#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

use crate::support;

use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::json;
use support::repo;

fn run_hook(
    home: &std::path::Path,
    repo: &std::path::Path,
    file_path: &str,
) -> std::process::Output {
    run_tool(home, repo, "Read", json!({"file_path": file_path}))
}

fn run_tool(
    home: &std::path::Path,
    repo: &std::path::Path,
    tool_name: &str,
    tool_input: serde_json::Value,
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
        "tool_name": tool_name,
        "tool_input": tool_input,
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
    // The secret file the read below must not disclose.
    std::fs::write(repo.join(".env"), "FAKE_KEY=not-a-real-secret\n").unwrap();

    // An ordinary project read is left to Claude's own approval flow.
    let delegated = run_hook(temp.path(), &repo, "src/lib.rs");
    assert!(delegated.status.success());
    assert!(delegated.stdout.is_empty());
    assert!(delegated.stderr.is_empty(), "{delegated:?}");

    let blocked = run_hook(temp.path(), &repo, ".env");
    assert!(blocked.status.success());
    let blocked: serde_json::Value = serde_json::from_slice(&blocked.stdout).unwrap();
    assert_eq!(blocked["hookSpecificOutput"]["permissionDecision"], "deny");
    assert!(
        blocked["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .unwrap()
            .starts_with("nah · ")
    );

    let outside = temp.path().join("outside.txt");
    std::fs::write(&outside, "outside\n").unwrap();
    let delegated = run_hook(temp.path(), &repo, outside.to_str().unwrap());
    assert!(delegated.status.success());
    assert!(delegated.stdout.is_empty());
}

#[test]
fn claude_hook_blocks_a_write_to_an_installed_cursor_hook() {
    let home_temp = tempfile::tempdir().unwrap();
    let home = support::test_temp_path(home_temp.path());
    let home = home.as_path();
    let repo = repo(home);
    let installed = Command::new(env!("CARGO_BIN_EXE_nah"))
        .args(["hook", "cursor", "install"])
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env_remove("XDG_CONFIG_HOME")
        .output()
        .unwrap();
    assert!(installed.status.success(), "{installed:?}");

    let hook = home.join(".cursor/hooks.json");
    let blocked = run_tool(
        home,
        &repo,
        "Write",
        json!({"file_path": hook, "content": "x"}),
    );
    assert!(blocked.status.success(), "{blocked:?}");
    let blocked: serde_json::Value = serde_json::from_slice(&blocked.stdout).unwrap();
    assert_eq!(blocked["hookSpecificOutput"]["permissionDecision"], "deny");
}

#[test]
fn native_claude_adapter_ignores_invalid_outer_input() {
    let temp = tempfile::tempdir().unwrap();
    let output = support::nah(temp.path(), temp.path(), &["hook", "claude", "run"], None);
    assert!(output.status.success());
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}
