//! Evaluator isolation self-tests. A fake analyzer child covers the harness
//! outcomes; a crash here must not abort the parent or silently retry.
#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

use std::path::PathBuf;
use std::time::Duration;

use effinterp_bench::repos::isolate::{
    IsolateRequest, IsolateStatus, binary_identity, isolate_child_process,
};

fn fake() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_fake_analyzer"))
}

fn run(
    mode: &str,
    timeout: Duration,
    max_stdout: usize,
) -> effinterp_bench::repos::isolate::RepoEnvelope {
    isolate_child_process(IsolateRequest {
        binary: fake(),
        args: vec![mode.to_string()],
        stdin: Vec::new(),
        timeout,
        max_stdout,
        max_stderr: 64 * 1024,
        cache_path: PathBuf::from("/tmp/ei-isolate-test-cache"),
        extra_env: Vec::new(),
        max_memory_bytes: None,
    })
}

#[test]
fn success_emits_analyzed_envelope() {
    let env = run("success", Duration::from_secs(5), 64 * 1024);
    assert_eq!(env.status, IsolateStatus::Analyzed);
    assert_eq!(env.process.exit_code, Some(0));
    assert!(env.process.signal.is_none());
    assert!(!env.process.timed_out);
    let payload = env.payload.expect("parsed payload");
    assert_eq!(payload["status"], "analyzed");
    assert_eq!(payload["ok"], true);
    assert_eq!(env.cache_path, "/tmp/ei-isolate-test-cache");
    assert!(!env.analyzer.hash.is_empty());
    assert_eq!(env.analyzer.hash, binary_identity(&fake()).hash);
}

#[test]
fn nonzero_exit_is_captured() {
    let env = run("nonzero", Duration::from_secs(5), 64 * 1024);
    assert_eq!(env.status, IsolateStatus::Nonzero);
    assert_eq!(env.process.exit_code, Some(7));
    assert!(env.process.signal.is_none());
    assert!(env.process.stderr.contains("exiting nonzero"));
}

#[test]
fn memory_cap_preserves_nonzero_exit() {
    let env = isolate_child_process(IsolateRequest {
        binary: fake(),
        args: vec!["nonzero".to_string()],
        stdin: Vec::new(),
        timeout: Duration::from_secs(5),
        max_stdout: 64 * 1024,
        max_stderr: 64 * 1024,
        cache_path: PathBuf::from("/tmp/ei-isolate-test-cache"),
        extra_env: Vec::new(),
        max_memory_bytes: Some(4 << 30),
    });
    assert_eq!(env.status, IsolateStatus::Nonzero);
    assert_eq!(env.process.exit_code, Some(7));
    assert!(env.process.signal.is_none());
}

#[test]
fn signal_abort_is_crash() {
    let env = run("signal", Duration::from_secs(5), 64 * 1024);
    assert_eq!(env.status, IsolateStatus::Crash);
    assert!(env.process.exit_code.is_none());
    assert_eq!(env.process.signal, Some(libc::SIGABRT));
}

#[test]
fn timeout_kills_the_child() {
    let env = run("timeout", Duration::from_millis(200), 64 * 1024);
    assert_eq!(env.status, IsolateStatus::Timeout);
    assert!(env.process.timed_out);
    assert!(env.elapsed_ms >= 200);
    // The fake child sleeps forever, so only the harness's kill ends it.
    assert_eq!(env.process.signal, Some(libc::SIGKILL));
}

// An interrupted run must not leave a child writing into a resumed run.
#[test]
fn killed_parent_does_not_leave_checkpoint_writer() {
    const CHILD_PID_FILE: &str = "EFFINTERP_TEST_CHILD_PID_FILE";
    // The guard kills the child as soon as its parent exits. The child would
    // otherwise live this long, so waiting half of it separates the two
    // without depending on machine load.
    const CHILD_LIFETIME: Duration = Duration::from_secs(60);
    if let Some(path) = std::env::var_os(CHILD_PID_FILE) {
        isolate_child_process(IsolateRequest {
            binary: "/bin/sh".into(),
            args: vec![
                "-c".into(),
                format!("echo $$ > \"$1\"; exec sleep {}", CHILD_LIFETIME.as_secs()),
                "checkpoint-writer".into(),
                path.to_string_lossy().into_owned(),
            ],
            stdin: Vec::new(),
            timeout: CHILD_LIFETIME,
            max_stdout: 1024,
            max_stderr: 1024,
            cache_path: PathBuf::new(),
            extra_env: Vec::new(),
            max_memory_bytes: Some(4 << 30),
        });
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let pid_file = dir.path().join("child.pid");
    let mut parent = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "isolate::killed_parent_does_not_leave_checkpoint_writer",
        ])
        .env(CHILD_PID_FILE, &pid_file)
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let start = std::time::Instant::now();
    let pid = loop {
        if let Ok(pid) = std::fs::read_to_string(&pid_file)
            && let Ok(pid) = pid.trim().parse::<i32>()
        {
            break pid;
        }
        if start.elapsed() > CHILD_LIFETIME / 2 {
            let _ = parent.kill();
            let _ = parent.wait();
            panic!("isolated child did not start");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    parent.kill().unwrap();
    parent.wait().unwrap();
    let start = std::time::Instant::now();
    loop {
        let state = std::process::Command::new("ps")
            .args(["-o", "stat=", "-p", &pid.to_string()])
            .output()
            .unwrap();
        let state = String::from_utf8(state.stdout).unwrap();
        if state.trim().is_empty() || state.trim().starts_with('Z') {
            break;
        }
        if start.elapsed() > CHILD_LIFETIME / 2 {
            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }
            panic!("child survived its measuring parent");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn malformed_json_is_invalid_plan() {
    let env = run("malformed", Duration::from_secs(5), 64 * 1024);
    assert_eq!(env.status, IsolateStatus::InvalidPlan);
    assert_eq!(env.process.exit_code, Some(0));
    assert!(env.payload.is_none());
    assert!(env.process.stdout.contains("not a json envelope"));
}

#[test]
fn oversized_output_is_resource_exhaustion() {
    let env = run("oversized", Duration::from_secs(5), 1024);
    assert_eq!(env.status, IsolateStatus::ResourceExhaustion);
    assert!(env.process.stdout_truncated);
    assert!(env.process.stdout.len() <= 1024);
}

#[test]
fn failure_does_not_abort_parent_or_retry() {
    // Sequential attempts: a crash then a success. The parent is still
    // running, and the crash stays a crash — no second spawn under new limits.
    let crash = run("signal", Duration::from_secs(5), 64 * 1024);
    assert_eq!(crash.status, IsolateStatus::Crash);
    let ok = run("success", Duration::from_secs(5), 64 * 1024);
    assert_eq!(ok.status, IsolateStatus::Analyzed);
}

#[test]
fn memory_cap_is_a_typed_child_failure() {
    let env = isolate_child_process(IsolateRequest {
        binary: fake(),
        args: vec!["allocate".to_string()],
        stdin: Vec::new(),
        timeout: Duration::from_secs(5),
        max_stdout: 64 * 1024,
        max_stderr: 64 * 1024,
        cache_path: PathBuf::from("/tmp/ei-isolate-test-cache"),
        extra_env: Vec::new(),
        max_memory_bytes: Some(64 << 20),
    });
    #[cfg(target_os = "macos")]
    {
        assert_eq!(env.status, IsolateStatus::ResourceExhaustion);
        assert!(env.process.memory_limit_exceeded);
        assert!(!env.process.timed_out);
        assert!(env.process.stderr.contains("resident memory limit"));
    }
    assert!(matches!(
        env.status,
        IsolateStatus::ResourceExhaustion | IsolateStatus::Crash
    ));
}
