//! Runs the bounded exec/v1 process transport; it does not admit responses into policy.

use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

#[cfg(windows)]
use std::os::windows::{io::AsRawHandle, process::CommandExt};

use nah_proto::ctx::ActivationProjection;
use nah_proto::exec_v1::ExecV1Request;
use nah_proto::extension::{
    ConsultationOutcome, ExtensionConsultation, ExtensionResponse, TransportRejectionCode,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
#[cfg(not(target_arch = "wasm32"))]
use wait_timeout::ChildExt;

use crate::bundle::ExtensionBundle;

// wasm has no subprocesses: spawn fails before a wait can happen, so this
// shim exists only to satisfy the homepage demo's wasm32 build
#[cfg(target_arch = "wasm32")]
trait ChildExt {
    fn wait_timeout(
        &mut self,
        timeout: Duration,
    ) -> std::io::Result<Option<std::process::ExitStatus>>;
}
#[cfg(target_arch = "wasm32")]
impl ChildExt for std::process::Child {
    fn wait_timeout(
        &mut self,
        _timeout: Duration,
    ) -> std::io::Result<Option<std::process::ExitStatus>> {
        unreachable!("wasm cannot spawn the child this waits on")
    }
}

pub const EXEC_TIMEOUT: Duration = Duration::from_millis(750);
pub const OUTPUT_SIZE_CAP: usize = 64 * 1024;
const STDERR_SIZE_CAP: usize = 8 * 1024;
const CACHE_ENTRY_VERSION: u32 = 1;

pub(crate) struct ExecutionOutput {
    pub(crate) consultation: ExtensionConsultation,
    pub(crate) stderr: Option<String>,
}

pub(crate) fn execute(extension: &ExtensionBundle, request: &ExecV1Request) -> ExecutionOutput {
    let activation = extension.projection().clone();
    let mut command = Command::new(extension.run());
    command
        .current_dir(extension.directory())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    configure_process_group(&mut command);
    #[cfg(windows)]
    let job = match WindowsJob::create() {
        Ok(job) => job,
        Err(_) => return spawn_failure(activation),
    };
    #[cfg(windows)]
    command.creation_flags(windows_sys::Win32::System::Threading::CREATE_SUSPENDED);
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(_) => return spawn_failure(activation),
    };
    #[cfg(windows)]
    if job.assign_and_resume(&child).is_err() {
        let _ = child.kill();
        let _ = child.wait();
        return spawn_failure(activation);
    }
    let stdin = child.stdin.take();
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let request_bytes = serde_json::to_vec(request).expect("validated exec request serializes");
    let writer = thread::spawn(move || {
        if let Some(mut stdin) = stdin {
            let _ = stdin.write_all(&request_bytes);
            let _ = stdin.write_all(b"\n");
        }
    });
    let stdout_reader = thread::spawn(move || read_bounded(stdout, OUTPUT_SIZE_CAP));
    let stderr_reader = thread::spawn(move || read_bounded(stderr, STDERR_SIZE_CAP));
    let status = match child.wait_timeout(EXEC_TIMEOUT) {
        Ok(Some(status)) => {
            // A completed extension must not leave descendants holding the
            // captured pipes open beyond its one-shot consultation.
            kill_process_group(&child);
            Some(status)
        }
        Ok(None) | Err(_) => {
            kill_process_group(&child);
            let _ = child.kill();
            let _ = child.wait();
            None
        }
    };
    #[cfg(windows)]
    job.terminate();
    let _ = writer.join();
    let stdout = stdout_reader.join().unwrap_or_default();
    let stderr = stderr_reader.join().unwrap_or_default();
    let stderr = strip_terminal_sequences(&String::from_utf8_lossy(&stderr.bytes));
    let stderr = (!stderr.is_empty()).then_some(stderr);
    let outcome = match status {
        None => ConsultationOutcome::Timeout,
        Some(_) if stdout.oversize => ConsultationOutcome::RejectedTransport {
            code: TransportRejectionCode::Oversize,
        },
        Some(status) if !status.success() => ConsultationOutcome::Crash,
        Some(_) if stdout.bytes.is_empty() => ConsultationOutcome::Silence,
        Some(_) => match decode_response(&stdout.bytes) {
            Ok(response) => ConsultationOutcome::Response { response },
            Err(code) => ConsultationOutcome::RejectedTransport { code },
        },
    };
    ExecutionOutput {
        consultation: ExtensionConsultation {
            activation,
            outcome,
        },
        stderr,
    }
}

fn spawn_failure(activation: ActivationProjection) -> ExecutionOutput {
    ExecutionOutput {
        consultation: ExtensionConsultation {
            activation,
            outcome: ConsultationOutcome::SpawnFailure,
        },
        stderr: None,
    }
}

#[derive(Default)]
struct BoundedOutput {
    bytes: Vec<u8>,
    oversize: bool,
}

fn read_bounded<R: Read>(reader: Option<R>, cap: usize) -> BoundedOutput {
    let Some(mut reader) = reader else {
        return BoundedOutput::default();
    };
    let mut output = BoundedOutput::default();
    let mut buffer = [0_u8; 8192];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(count) => {
                let remaining = cap.saturating_sub(output.bytes.len());
                output
                    .bytes
                    .extend_from_slice(&buffer[..count.min(remaining)]);
                output.oversize |= count > remaining;
            }
        }
    }
    output
}

fn decode_response(bytes: &[u8]) -> Result<ExtensionResponse, TransportRejectionCode> {
    let text = std::str::from_utf8(bytes).map_err(|_| TransportRejectionCode::InvalidUtf8)?;
    let framed = if let Some(framed) = text.strip_suffix("\r\n") {
        if framed.contains('\r') {
            return Err(TransportRejectionCode::InvalidFraming);
        }
        framed
    } else {
        if text.contains('\r') {
            return Err(TransportRejectionCode::InvalidFraming);
        }
        text.strip_suffix('\n').unwrap_or(text)
    };
    if framed.is_empty()
        || framed.starts_with(char::is_whitespace)
        || framed.ends_with(char::is_whitespace)
    {
        return Err(TransportRejectionCode::InvalidFraming);
    }
    let mut values = serde_json::Deserializer::from_str(framed).into_iter::<Value>();
    let value = values
        .next()
        .ok_or(TransportRejectionCode::InvalidJson)?
        .map_err(|_| TransportRejectionCode::InvalidJson)?;
    if let Some(next) = values.next() {
        return match next {
            Ok(_) => Err(TransportRejectionCode::MultipleValues),
            Err(_) => Err(TransportRejectionCode::InvalidJson),
        };
    }
    let Some(object) = value.as_object() else {
        return Err(TransportRejectionCode::InvalidResponseFields);
    };
    if object
        .keys()
        .any(|key| !matches!(key.as_str(), "block" | "abstain" | "reason"))
    {
        return Err(TransportRejectionCode::InvalidResponseFields);
    }
    let mut response: ExtensionResponse =
        serde_json::from_value(value).map_err(|_| TransportRejectionCode::InvalidResponseFields)?;
    if let Some(reason) = &mut response.reason {
        *reason = strip_terminal_sequences(reason);
    }
    Ok(response)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CacheEntry {
    v: u32,
    key: String,
    activation: ActivationProjection,
    response: ExtensionResponse,
}

pub(crate) fn encode_cache_entry(
    key: &str,
    activation: &ActivationProjection,
    response: &ExtensionResponse,
) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(&CacheEntry {
        v: CACHE_ENTRY_VERSION,
        key: key.to_owned(),
        activation: activation.clone(),
        response: response.clone(),
    })
}

pub(crate) fn decode_cache_entry(
    bytes: &[u8],
    key: &str,
    activation: &ActivationProjection,
) -> Result<ExtensionResponse, ()> {
    if bytes.len() > OUTPUT_SIZE_CAP {
        return Err(());
    }
    let entry: CacheEntry = serde_json::from_slice(bytes).map_err(|_| ())?;
    if entry.v != CACHE_ENTRY_VERSION || entry.key != key || entry.activation != *activation {
        return Err(());
    }
    if serde_json::to_vec(&entry).map_err(|_| ())? != bytes {
        return Err(());
    }
    let mut response = entry.response;
    if let Some(reason) = &mut response.reason {
        *reason = strip_terminal_sequences(reason);
    }
    Ok(response)
}

#[cfg(unix)]
fn configure_process_group(command: &mut Command) {
    use std::os::unix::process::CommandExt;

    command.process_group(0);
}

#[cfg(not(unix))]
fn configure_process_group(_command: &mut Command) {}

#[cfg(unix)]
fn kill_process_group(child: &std::process::Child) {
    let _ = Command::new("kill")
        .args(["-KILL", "--", &format!("-{}", child.id())])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

#[cfg(not(unix))]
fn kill_process_group(_child: &std::process::Child) {}

#[cfg(windows)]
struct WindowsJob {
    handle: windows_sys::Win32::Foundation::HANDLE,
}

#[cfg(windows)]
impl WindowsJob {
    /// Creates a kill-on-close job before the suspended guard can run.
    fn create() -> std::io::Result<Self> {
        use std::mem::size_of;
        use std::ptr;

        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::JobObjects::{
            CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
            SetInformationJobObject,
        };

        let handle = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
        if handle.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let set = unsafe {
            SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if set != 0 {
            return Ok(Self { handle });
        }
        let error = std::io::Error::last_os_error();
        unsafe { CloseHandle(handle) };
        Err(error)
    }

    /// Assigns the suspended child before resuming its only runnable thread.
    fn assign_and_resume(&self, child: &std::process::Child) -> std::io::Result<()> {
        use windows_sys::Win32::System::JobObjects::AssignProcessToJobObject;

        let process = child.as_raw_handle().cast();
        if unsafe { AssignProcessToJobObject(self.handle, process) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        resume_suspended_process_threads(process)
    }

    fn terminate(&self) {
        use windows_sys::Win32::System::JobObjects::TerminateJobObject;

        unsafe { TerminateJobObject(self.handle, 1) };
    }
}

#[cfg(windows)]
impl Drop for WindowsJob {
    fn drop(&mut self) {
        use windows_sys::Win32::Foundation::CloseHandle;

        unsafe { CloseHandle(self.handle) };
    }
}

#[cfg(windows)]
fn resume_suspended_process_threads(
    process: windows_sys::Win32::Foundation::HANDLE,
) -> std::io::Result<()> {
    use std::mem::size_of;

    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
    };
    use windows_sys::Win32::System::Threading::{
        GetProcessId, OpenThread, ResumeThread, THREAD_SUSPEND_RESUME,
    };

    let child_id = unsafe { GetProcessId(process) };
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error());
    }
    let mut entry = THREADENTRY32 {
        dwSize: size_of::<THREADENTRY32>() as u32,
        ..Default::default()
    };
    let mut result = Ok(());
    let mut found = unsafe { Thread32First(snapshot, &mut entry) } != 0;
    while found {
        if entry.th32OwnerProcessID == child_id {
            let thread = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID) };
            if thread.is_null() {
                result = Err(std::io::Error::last_os_error());
                break;
            }
            if unsafe { ResumeThread(thread) } == u32::MAX {
                result = Err(std::io::Error::last_os_error());
            }
            unsafe { CloseHandle(thread) };
            if result.is_err() {
                break;
            }
        }
        found = unsafe { Thread32Next(snapshot, &mut entry) } != 0;
    }
    unsafe { CloseHandle(snapshot) };
    result
}

fn strip_terminal_sequences(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut characters = input.chars().peekable();
    while let Some(character) = characters.next() {
        if character == '\u{1b}' {
            match characters.next() {
                Some('[') => {
                    for next in characters.by_ref() {
                        if ('@'..='~').contains(&next) {
                            break;
                        }
                    }
                }
                Some(']') => {
                    while let Some(next) = characters.next() {
                        if next == '\u{7}' {
                            break;
                        }
                        if next == '\u{1b}' && characters.peek() == Some(&'\\') {
                            characters.next();
                            break;
                        }
                    }
                }
                Some(_) | None => {}
            }
        } else if character == '\u{9b}' {
            for next in characters.by_ref() {
                if ('@'..='~').contains(&next) {
                    break;
                }
            }
        } else {
            output.push(character);
        }
    }
    output
}

pub(crate) fn outcome_code(outcome: &ConsultationOutcome) -> &'static str {
    match outcome {
        ConsultationOutcome::Response { .. } => "response",
        ConsultationOutcome::Silence => "silence",
        ConsultationOutcome::Crash => "crash",
        ConsultationOutcome::Timeout => "timeout",
        ConsultationOutcome::SpawnFailure => "spawn-failure",
        ConsultationOutcome::RejectedTransport { code } => match code {
            TransportRejectionCode::Oversize => "rejected-transport:oversize",
            TransportRejectionCode::InvalidUtf8 => "rejected-transport:invalid-utf8",
            TransportRejectionCode::InvalidJson => "rejected-transport:invalid-json",
            TransportRejectionCode::MultipleValues => "rejected-transport:multiple-values",
            TransportRejectionCode::InvalidFraming => "rejected-transport:invalid-framing",
            TransportRejectionCode::InvalidResponseFields => {
                "rejected-transport:invalid-response-fields"
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::decode_response;
    use nah_proto::extension::TransportRejectionCode;

    #[test]
    fn response_framing_accepts_native_windows_line_endings() {
        assert!(decode_response(b"{\"abstain\":true}\r\n").is_ok());
        assert_eq!(
            decode_response(b"{\"abstain\":true}\r\r\n"),
            Err(TransportRejectionCode::InvalidFraming)
        );
    }
}
