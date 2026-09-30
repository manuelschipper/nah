//! Per-repository analyzer isolation.
//!
//! One repository analysis runs in one child process. A crash, timeout, or
//! garbage output becomes a first-class envelope; the parent continues. There
//! is no retry, including no retry under changed limits.

use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

#[cfg(target_os = "linux")]
pub const MEMORY_ENFORCEMENT: &str = "rlimit-as";
#[cfg(target_os = "macos")]
pub const MEMORY_ENFORCEMENT: &str = "resident-set-poll-20ms";

fn child_command(req: &IsolateRequest) -> Command {
    #[cfg(target_os = "linux")]
    if let Some(bytes) = req.max_memory_bytes {
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("ulimit -v \"$0\" && exec \"$@\"")
            .arg((bytes.saturating_add(1023) / 1024).to_string())
            .arg(&req.binary)
            .args(&req.args);
        return command;
    }
    let mut command = Command::new(&req.binary);
    command.args(&req.args);
    command
}

#[cfg(target_os = "linux")]
fn memory_exceeded(_pid: u32, _limit: u64) -> std::io::Result<bool> {
    // The kernel rejects allocations beyond the address-space limit.
    Ok(false)
}

#[cfg(target_os = "macos")]
fn memory_exceeded(pid: u32, limit: u64) -> std::io::Result<bool> {
    let mut info = std::mem::MaybeUninit::<libc::proc_taskinfo>::uninit();
    let size = std::mem::size_of::<libc::proc_taskinfo>() as libc::c_int;
    let read = unsafe {
        libc::proc_pidinfo(
            pid as libc::c_int,
            libc::PROC_PIDTASKINFO,
            0,
            info.as_mut_ptr().cast(),
            size,
        )
    };
    if read != size {
        return Err(if read <= 0 {
            std::io::Error::last_os_error()
        } else {
            std::io::Error::other("incomplete process memory information")
        });
    }
    Ok(unsafe { info.assume_init() }.pti_resident_size > limit)
}

/// Outcome of one isolated repository analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IsolateStatus {
    Analyzed,
    Crash,
    Timeout,
    InvalidPlan,
    ResourceExhaustion,
    Nonzero,
}

impl IsolateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            IsolateStatus::Analyzed => "analyzed",
            IsolateStatus::Crash => "crash",
            IsolateStatus::Timeout => "timeout",
            IsolateStatus::InvalidPlan => "invalid-plan",
            IsolateStatus::ResourceExhaustion => "resource-exhaustion",
            IsolateStatus::Nonzero => "nonzero",
        }
    }

    pub fn is_failure(self) -> bool {
        !matches!(self, IsolateStatus::Analyzed)
    }
}

/// Exact bits of the analyzer binary that ran the child.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinaryIdentity {
    pub path: String,
    pub size: u64,
    pub hash: String,
}

/// How the child process ended, plus bounded captured output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessCapture {
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub timed_out: bool,
    pub memory_limit_exceeded: bool,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub stdout: String,
    pub stderr: String,
}

/// Machine-readable per-repository result. Always produced by the parent;
/// a crash cannot prevent this envelope from existing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoEnvelope {
    pub status: IsolateStatus,
    pub analyzer: BinaryIdentity,
    pub cache_path: String,
    pub elapsed_ms: u64,
    pub process: ProcessCapture,
    /// Parsed child stdout when it was a JSON object.
    pub payload: Option<serde_json::Value>,
}

/// One attempt to run an analyzer child. A single spawn; never retried.
pub struct IsolateRequest {
    pub binary: PathBuf,
    pub args: Vec<String>,
    pub stdin: Vec<u8>,
    pub timeout: Duration,
    pub max_stdout: usize,
    pub max_stderr: usize,
    pub cache_path: PathBuf,
    pub extra_env: Vec<(String, String)>,
    /// Linux limits address space with RLIMIT_AS. macOS samples resident memory
    /// every 20 ms and kills the child above this budget; brief overshoot is possible.
    pub max_memory_bytes: Option<u64>,
}

/// Identity of `path`: size plus a content hash of the file as it sits on disk.
pub fn binary_identity(path: &Path) -> BinaryIdentity {
    match hash_file(path) {
        Ok((size, hash)) => BinaryIdentity {
            path: path.display().to_string(),
            size,
            hash,
        },
        Err(_) => BinaryIdentity {
            path: path.display().to_string(),
            size: 0,
            hash: "unreadable".to_string(),
        },
    }
}

fn hash_file(path: &Path) -> std::io::Result<(u64, String)> {
    let mut file = std::fs::File::open(path)?;
    let mut buf = [0u8; 64 * 1024];
    let mut hasher = blake3::Hasher::new();
    let mut size = 0u64;
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        size += n as u64;
        hasher.update(&buf[..n]);
    }
    Ok((size, format!("blake3:{}", hasher.finalize().to_hex())))
}

/// Classify a finished capture. Precedence is timeout, then memory/output
/// exhaustion, then signal, then nonzero exit, then JSON envelope shape.
pub fn classify_isolate_status(
    capture: &ProcessCapture,
    payload: Option<&serde_json::Value>,
) -> IsolateStatus {
    if capture.timed_out {
        return IsolateStatus::Timeout;
    }
    if capture.memory_limit_exceeded || capture.stdout_truncated || capture.stderr_truncated {
        return IsolateStatus::ResourceExhaustion;
    }
    if capture.signal.is_some() {
        return IsolateStatus::Crash;
    }
    if capture.exit_code.unwrap_or(1) != 0 {
        return IsolateStatus::Nonzero;
    }
    match payload
        .and_then(|v| v.get("status"))
        .and_then(|s| s.as_str())
    {
        Some("analyzed") => IsolateStatus::Analyzed,
        Some("crash") => IsolateStatus::Crash,
        Some("timeout") => IsolateStatus::Timeout,
        Some("invalid-plan") => IsolateStatus::InvalidPlan,
        Some("resource-exhaustion") => IsolateStatus::ResourceExhaustion,
        Some("nonzero") => IsolateStatus::Nonzero,
        _ => IsolateStatus::InvalidPlan,
    }
}

/// Spawn `req.binary` once, enforce the wall-clock timeout and output bounds,
/// and return a complete envelope. Never retries.
pub fn isolate_child_process(req: IsolateRequest) -> RepoEnvelope {
    let analyzer = binary_identity(&req.binary);
    let cache_path = req.cache_path.display().to_string();
    let start = Instant::now();
    let mut command = child_command(&req);
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in &req.extra_env {
        command.env(k, v);
    }
    let parent_pid = std::process::id() as libc::pid_t;
    // A killed measuring process releases its run lock. Its child must not
    // keep writing checkpoints while another process resumes that run.
    unsafe {
        command.pre_exec(move || guard_parent(parent_pid));
    }

    let mut child = match command.spawn() {
        Ok(c) => c,
        Err(e) => {
            let diagnostic = format!("spawn failed: {e}");
            return RepoEnvelope {
                status: IsolateStatus::Crash,
                analyzer,
                cache_path,
                elapsed_ms: start.elapsed().as_millis() as u64,
                process: ProcessCapture {
                    exit_code: None,
                    signal: None,
                    timed_out: false,
                    memory_limit_exceeded: false,
                    stdout_truncated: false,
                    stderr_truncated: false,
                    stdout: String::new(),
                    stderr: diagnostic,
                },
                payload: None,
            };
        }
    };

    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(&req.stdin);
    }

    let stdout = child.stdout.take().expect("piped stdout");
    let stderr = child.stderr.take().expect("piped stderr");
    let overflow = Arc::new(AtomicBool::new(false));
    let (tx_out, rx_out) = mpsc::channel();
    let (tx_err, rx_err) = mpsc::channel();
    spawn_reader(stdout, req.max_stdout, overflow.clone(), tx_out);
    spawn_reader(stderr, req.max_stderr, overflow.clone(), tx_err);

    let mut timed_out = false;
    let mut killed_for_output = false;
    let mut memory_limit_exceeded = false;
    let mut memory_diagnostic = None;
    let deadline = start + req.timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if overflow.load(Ordering::SeqCst) {
                    let _ = child.kill();
                    killed_for_output = true;
                    break child.wait().unwrap_or_else(|_| dummy_failure());
                }
                if let Some(limit) = req.max_memory_bytes {
                    match memory_exceeded(child.id(), limit) {
                        Ok(false) => {}
                        result => {
                            // The process may have exited between try_wait and the memory query.
                            if let Ok(Some(status)) = child.try_wait() {
                                break status;
                            }
                            memory_limit_exceeded = result.is_ok();
                            memory_diagnostic = Some(match result {
                                Ok(_) => format!("resident memory limit {limit} bytes exceeded"),
                                Err(error) => format!("memory monitor failed: {error}"),
                            });
                            let _ = child.kill();
                            break child.wait().unwrap_or_else(|_| dummy_failure());
                        }
                    }
                }
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    timed_out = true;
                    break child.wait().unwrap_or_else(|_| dummy_failure());
                }
                thread::sleep(Duration::from_millis(20));
            }
            Err(e) => {
                return RepoEnvelope {
                    status: IsolateStatus::Crash,
                    analyzer,
                    cache_path,
                    elapsed_ms: start.elapsed().as_millis() as u64,
                    process: ProcessCapture {
                        exit_code: None,
                        signal: None,
                        timed_out: false,
                        memory_limit_exceeded: false,
                        stdout_truncated: false,
                        stderr_truncated: false,
                        stdout: String::new(),
                        stderr: format!("wait failed: {e}"),
                    },
                    payload: None,
                };
            }
        }
    };

    let (stdout_bytes, stdout_truncated) = recv_pipe(rx_out);
    let (mut stderr_bytes, mut stderr_truncated) = recv_pipe(rx_err);
    if let Some(diagnostic) = memory_diagnostic {
        let mut bytes = format!("{diagnostic}\n").into_bytes();
        bytes.extend(stderr_bytes);
        stderr_truncated |= bytes.len() > req.max_stderr;
        bytes.truncate(req.max_stderr);
        stderr_bytes = bytes;
    }
    // A kill after overflow still counts as resource exhaustion, not a crash.
    let stdout_truncated = stdout_truncated || killed_for_output && overflow.load(Ordering::SeqCst);
    let capture = ProcessCapture {
        exit_code: status.code(),
        signal: signal_of(&status),
        timed_out,
        memory_limit_exceeded,
        stdout_truncated,
        stderr_truncated,
        stdout: String::from_utf8_lossy(&stdout_bytes).into_owned(),
        stderr: String::from_utf8_lossy(&stderr_bytes).into_owned(),
    };
    let payload = parse_payload(&capture.stdout);
    let status = classify_isolate_status(&capture, payload.as_ref());
    RepoEnvelope {
        status,
        analyzer,
        cache_path,
        elapsed_ms: start.elapsed().as_millis() as u64,
        process: capture,
        payload,
    }
}

fn spawn_reader(
    mut pipe: impl Read + Send + 'static,
    max: usize,
    overflow: Arc<AtomicBool>,
    tx: mpsc::Sender<(Vec<u8>, bool)>,
) {
    thread::spawn(move || {
        let mut buf = Vec::new();
        let mut tmp = [0u8; 8192];
        let mut truncated = false;
        loop {
            match pipe.read(&mut tmp) {
                Ok(0) => break,
                Ok(n) => {
                    if buf.len() + n > max {
                        let take = max.saturating_sub(buf.len());
                        buf.extend_from_slice(&tmp[..take]);
                        truncated = true;
                        overflow.store(true, Ordering::SeqCst);
                        break;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                }
                Err(_) => break,
            }
        }
        let _ = tx.send((buf, truncated));
    });
}

fn recv_pipe(rx: mpsc::Receiver<(Vec<u8>, bool)>) -> (Vec<u8>, bool) {
    rx.recv_timeout(Duration::from_secs(2))
        .unwrap_or_else(|_| (Vec::new(), false))
}

fn parse_payload(stdout: &str) -> Option<serde_json::Value> {
    let text = stdout.trim();
    if text.is_empty() {
        return None;
    }
    serde_json::from_str(text).ok()
}

fn signal_of(status: &std::process::ExitStatus) -> Option<i32> {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        status.signal()
    }
    #[cfg(not(unix))]
    {
        let _ = status;
        None
    }
}

fn dummy_failure() -> std::process::ExitStatus {
    std::os::unix::process::ExitStatusExt::from_raw(1 << 8)
}

#[cfg(target_os = "linux")]
fn guard_parent(parent: libc::pid_t) -> std::io::Result<()> {
    unsafe {
        if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if libc::getppid() != parent {
            libc::_exit(1);
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn guard_parent(parent: libc::pid_t) -> std::io::Result<()> {
    // Darwin has no parent-death signal. A guardian watches both processes;
    // the analyzer cannot exec until both exit notifications are registered.
    // This runs after fork: use only stack storage and libc, without locks.
    unsafe {
        let child = libc::getpid();
        let mut pipe = [0; 2];
        if libc::pipe(pipe.as_mut_ptr()) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let guardian = libc::fork();
        if guardian < 0 {
            let error = std::io::Error::last_os_error();
            libc::close(pipe[0]);
            libc::close(pipe[1]);
            return Err(error);
        }
        if guardian == 0 {
            // In particular, release Rust's spawn-error pipe and the run lock.
            for fd in 0..libc::getdtablesize() {
                if fd != pipe[1] {
                    libc::close(fd);
                }
            }
            let queue = libc::kqueue();
            let event = |pid| libc::kevent {
                ident: pid as libc::uintptr_t,
                filter: libc::EVFILT_PROC,
                flags: libc::EV_ADD | libc::EV_ENABLE,
                fflags: libc::NOTE_EXIT,
                data: 0,
                udata: std::ptr::null_mut(),
            };
            let changes = [event(parent), event(child)];
            if queue < 0
                || libc::kevent(
                    queue,
                    changes.as_ptr(),
                    2,
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null(),
                ) < 0
            {
                libc::_exit(1);
            }
            let ready: u8 = 1;
            if libc::write(pipe[1], (&ready as *const u8).cast(), 1) != 1 {
                libc::_exit(1);
            }
            libc::close(pipe[1]);
            loop {
                let mut events = [event(0), event(0)];
                let count = libc::kevent(
                    queue,
                    std::ptr::null(),
                    0,
                    events.as_mut_ptr(),
                    2,
                    std::ptr::null(),
                );
                if count < 0 && *libc::__error() == libc::EINTR {
                    continue;
                }
                // Our parent is the analyzer; checking it also avoids signaling
                // a reused PID after the analyzer has already exited.
                if libc::getppid() == child {
                    libc::kill(child, libc::SIGKILL);
                }
                libc::_exit(0);
            }
        }
        libc::close(pipe[1]);
        let mut ready: u8 = 0;
        let mut count;
        loop {
            count = libc::read(pipe[0], (&mut ready as *mut u8).cast(), 1);
            if count >= 0 || *libc::__error() != libc::EINTR {
                break;
            }
        }
        libc::close(pipe[0]);
        if count != 1 || ready != 1 || libc::getppid() != parent {
            libc::_exit(1);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capture(
        exit: Option<i32>,
        signal: Option<i32>,
        timed_out: bool,
        truncated: bool,
    ) -> ProcessCapture {
        ProcessCapture {
            exit_code: exit,
            signal,
            timed_out,
            memory_limit_exceeded: false,
            stdout_truncated: truncated,
            stderr_truncated: false,
            stdout: String::new(),
            stderr: String::new(),
        }
    }

    #[test]
    fn classify_precedence() {
        assert_eq!(
            classify_isolate_status(&capture(Some(0), None, true, false), None),
            IsolateStatus::Timeout
        );
        assert_eq!(
            classify_isolate_status(&capture(Some(0), None, false, true), None),
            IsolateStatus::ResourceExhaustion
        );
        assert_eq!(
            classify_isolate_status(&capture(None, Some(6), false, false), None),
            IsolateStatus::Crash
        );
        assert_eq!(
            classify_isolate_status(&capture(Some(7), None, false, false), None),
            IsolateStatus::Nonzero
        );
        assert_eq!(
            classify_isolate_status(&capture(Some(0), None, false, false), None),
            IsolateStatus::InvalidPlan
        );
        let ok = serde_json::json!({"status": "analyzed"});
        assert_eq!(
            classify_isolate_status(&capture(Some(0), None, false, false), Some(&ok)),
            IsolateStatus::Analyzed
        );
        let bad = serde_json::json!({"status": "nope"});
        assert_eq!(
            classify_isolate_status(&capture(Some(0), None, false, false), Some(&bad)),
            IsolateStatus::InvalidPlan
        );
        let child_plan = serde_json::json!({"status": "invalid-plan"});
        assert_eq!(
            classify_isolate_status(&capture(Some(0), None, false, false), Some(&child_plan)),
            IsolateStatus::InvalidPlan
        );
    }
}
