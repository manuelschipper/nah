#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

mod support;

use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::json;
use support::repo;

fn run_hook(
    home: &std::path::Path,
    repo: &std::path::Path,
    file_path: &str,
) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_nah"));
    command.args(["hook", "claude", "run"]);
    let mut child = command
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env_remove("XDG_CONFIG_HOME")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let payload = json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": file_path},
        "cwd": repo,
        "session_id": "session-1",
    });
    child
        .stdin
        .take()
        .unwrap()
        .write_all(payload.to_string().as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn native_claude_adapter_maps_verdicts_without_leaking_warnings() {
    let temp = tempfile::tempdir().unwrap();
    let repo = repo(temp.path());
    std::fs::create_dir(repo.join(".nah")).unwrap();
    std::fs::write(
        repo.join(".nah/project.toml"),
        "enable-guards = [\"unknown-guard\"]\n",
    )
    .unwrap();

    // An ordinary project read is left to Claude's own approval flow.
    let delegated = run_hook(temp.path(), &repo, "src/lib.rs");
    assert!(delegated.status.success());
    assert!(delegated.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&delegated.stderr).contains("unknown project guard"));

    let blocked = run_hook(temp.path(), &repo, ".env");
    assert!(blocked.status.success());
    let blocked: serde_json::Value = serde_json::from_slice(&blocked.stdout).unwrap();
    assert_eq!(blocked["hookSpecificOutput"]["permissionDecision"], "deny");
    assert!(
        blocked["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .unwrap()
            .starts_with("nah - ")
    );

    let outside = temp.path().join("outside.txt");
    std::fs::write(&outside, "outside\n").unwrap();
    let delegated = run_hook(temp.path(), &repo, outside.to_str().unwrap());
    assert!(delegated.status.success());
    assert!(delegated.stdout.is_empty());
}

#[test]
fn native_claude_adapter_ignores_invalid_outer_input() {
    let output = Command::new(env!("CARGO_BIN_EXE_nah"))
        .args(["hook", "claude", "run"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
        .wait_with_output()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}
