#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

mod support;

use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::{Value, json};
use support::repo;

fn run_hook(home: &std::path::Path, payload: Value) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_nah"))
        .args(["hook", "copilot", "run"])
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("COPILOT_HOME")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(payload.to_string().as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn cli_payload(cwd: &std::path::Path, tool: &str, input: Value) -> Value {
    json!({
        "sessionId":"session-1",
        "timestamp":1,
        "cwd":cwd,
        "toolName":tool,
        "toolArgs":input.to_string()
    })
}

fn vscode_payload(cwd: &std::path::Path, tool: &str, input: Value) -> Value {
    json!({
        "hook_event_name":"PreToolUse",
        "session_id":"session-1",
        "timestamp":"2026-07-26T00:00:00Z",
        "cwd":cwd,
        "tool_name":tool,
        "tool_input":input
    })
}

#[test]
fn adapter_maps_cli_and_vscode_decisions() {
    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = support::test_temp_path(home_temp.path());
    let home = home.as_path();
    let project = repo(home);
    std::fs::write(project.join(".env"), "TOKEN=secret\n").unwrap();

    let delegated = run_hook(
        home,
        cli_payload(&project, "bash", json!({"command":"git status"})),
    );
    assert!(delegated.status.success(), "{delegated:?}");
    assert!(delegated.stdout.is_empty());

    let delegated = run_hook(
        home,
        cli_payload(&project, "web_fetch", json!({"url":"https://example.com"})),
    );
    assert!(delegated.status.success(), "{delegated:?}");
    assert!(delegated.stdout.is_empty());

    let runtime_lifecycle = run_hook(
        home,
        vscode_payload(
            &project,
            "runTerminalCommand",
            json!({"command":"nah hook copilot uninstall"}),
        ),
    );
    assert!(runtime_lifecycle.status.success(), "{runtime_lifecycle:?}");
    if cfg!(windows) {
        assert!(runtime_lifecycle.stdout.is_empty());
    } else {
        let output: Value = serde_json::from_slice(&runtime_lifecycle.stdout).unwrap();
        assert_eq!(output["hookSpecificOutput"]["permissionDecision"], "deny");
        assert!(
            output["hookSpecificOutput"]["permissionDecisionReason"]
                .as_str()
                .unwrap()
                .contains("do not retry")
        );
        assert_eq!(
            output["hookSpecificOutput"]["additionalContext"],
            output["hookSpecificOutput"]["permissionDecisionReason"],
            "VS Code's model must receive the same block guidance as the user"
        );
    }

    let bash_lifecycle = run_hook(
        home,
        cli_payload(
            &project,
            "bash",
            json!({"command":"nah hook copilot uninstall"}),
        ),
    );
    let output: Value = serde_json::from_slice(&bash_lifecycle.stdout).unwrap();
    assert_eq!(output["permissionDecision"], "deny");

    if cfg!(windows) {
        let powershell = run_hook(
            home,
            cli_payload(
                &project,
                "powershell",
                json!({"command":"Remove-Item -LiteralPath C:\\ -Recurse -Force"}),
            ),
        );
        assert!(!powershell.stdout.is_empty(), "{powershell:?}");
        let output: Value = serde_json::from_slice(&powershell.stdout).unwrap();
        assert_eq!(output["permissionDecision"], "deny");

        for tool in ["Bash", "run_in_terminal"] {
            let delegated = run_hook(
                home,
                vscode_payload(
                    &project,
                    tool,
                    json!({"command":"nah hook copilot uninstall"}),
                ),
            );
            assert!(delegated.status.success(), "{tool}: {delegated:?}");
            assert!(delegated.stdout.is_empty(), "{tool}: {delegated:?}");
        }
    }

    for path in [
        home.join(".copilot/hooks/nah.json"),
        home.join(".copilot/settings.json"),
    ] {
        let wiring = run_hook(
            home,
            vscode_payload(
                &project,
                "create_file",
                json!({"filePath":path,"content":"disabled"}),
            ),
        );
        let output: Value = serde_json::from_slice(&wiring.stdout).unwrap();
        assert_eq!(output["hookSpecificOutput"]["permissionDecision"], "deny");
    }

    let sensitive = run_hook(
        home,
        vscode_payload(
            &project,
            "read_file",
            json!({"filePath":project.join(".env")}),
        ),
    );
    let output: Value = serde_json::from_slice(&sensitive.stdout).unwrap();
    assert_eq!(output["hookSpecificOutput"]["permissionDecision"], "deny");

    let vscode_delegated = run_hook(
        home,
        vscode_payload(
            &project,
            "read_file",
            json!({"filePath":project.join("src/lib.rs")}),
        ),
    );
    assert!(vscode_delegated.status.success(), "{vscode_delegated:?}");
    assert!(vscode_delegated.stdout.is_empty());
}

#[test]
fn malformed_payloads_delegate_in_each_protocol() {
    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = support::test_temp_path(home_temp.path());
    let home = home.as_path();
    let project = repo(home);
    for payload in [
        json!({"sessionId":"session-1","cwd":project,"toolName":"bash","toolArgs":"not json"}),
        json!({
            "hook_event_name":"PreToolUse",
            "session_id":"session-1",
            "cwd":project,
            "tool_name":"read_file",
            "tool_input":{"filePath":7}
        }),
    ] {
        let output = run_hook(home, payload);
        assert!(output.status.success(), "{output:?}");
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn independent_guards_still_block_when_self_protection_is_unavailable() {
    let home_temp = tempfile::tempdir().unwrap();
    let home = support::test_temp_path(home_temp.path());
    let project = repo(&home);
    let (tool, command) = if cfg!(windows) {
        (
            "powershell",
            "Remove-Item -LiteralPath C:\\ -Recurse -Force",
        )
    } else {
        ("bash", "rm -rf /")
    };
    let payload = cli_payload(&project, tool, json!({"command":command}));
    let mut child = Command::new(env!("CARGO_BIN_EXE_nah"))
        .args(["hook", "copilot", "run"])
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env_remove("XDG_CONFIG_HOME")
        .env("COPILOT_HOME", home.join("elsewhere"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(payload.to_string().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "{output:?}");

    let responses = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert!(
        responses
            .iter()
            .any(|response| response["type"] == "progress")
    );
    assert!(
        responses
            .iter()
            .any(|response| response["permissionDecision"] == "deny")
    );

    let records = std::fs::read_to_string(home.join(".nah/audit.jsonl")).unwrap();
    let record: Value = serde_json::from_str(records.lines().last().unwrap()).unwrap();
    assert_eq!(record["core"]["verdict"], "block");
    assert!(
        record["failures"]
            .as_array()
            .unwrap()
            .iter()
            .any(|failure| {
                failure["source"] == "nah"
                    && failure["component"] == "runtime-self-protection"
                    && failure["code"] == "failed"
            })
    );
}
