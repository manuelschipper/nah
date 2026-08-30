#![cfg(not(windows))]
#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

mod support;

use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::{Value, json};
use support::repo;

fn run_adapter(
    home: &std::path::Path,
    project: &std::path::Path,
    tool_name: &str,
    tool_input: Value,
) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_nah"))
        .args(["hook", "amp", "run"])
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env_remove("XDG_CONFIG_HOME")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(
            json!({
                "tool_name": tool_name,
                "tool_input": tool_input,
                "cwd": project,
                "session_id": "T-subagent",
            })
            .to_string()
            .as_bytes(),
        )
        .unwrap();
    child.wait_with_output().unwrap()
}

fn decision(output: &std::process::Output) -> Value {
    assert!(output.status.success(), "{output:?}");
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn amp_adapter_maps_builtins_and_guards() {
    let temp = tempfile::tempdir().unwrap();
    // macOS hands out temp directories under symlinked /var, and a protected
    // path only matches the home nah resolves, so compare canonical paths
    let home = std::fs::canonicalize(temp.path()).unwrap();
    let home = home.as_path();
    let project = repo(home);
    std::fs::write(project.join(".env"), "TOKEN=secret\n").unwrap();

    for (tool, input) in [
        ("shell_command", json!({"command":"echo ok"})),
        (
            "create_file",
            json!({"path":project.join("src/new.rs"),"content":"pub fn new() {}\n"}),
        ),
        (
            "edit_file",
            json!({
                "path":project.join("src/lib.rs"),
                "old_str":"demo",
                "new_str":"example",
                "replace_all":false
            }),
        ),
        (
            "apply_patch",
            json!({
                "patchText":"*** Begin Patch\n*** Update File: src/lib.rs\n@@\n-old\n+new\n*** End Patch\n"
            }),
        ),
        (
            "upload_thread_file",
            json!({"thread":"T-other","path":"src/lib.rs"}),
        ),
        ("custom_tool", json!({"argument":7})),
    ] {
        let output = run_adapter(home, &project, tool, input);
        assert_eq!(
            decision(&output),
            json!({"block":false,"evaluation_failed":false}),
            "{tool}"
        );
    }

    let secret = run_adapter(
        home,
        &project,
        "shell_command",
        json!({"command":"cat .env"}),
    );
    let secret = decision(&secret);
    assert_eq!(secret["block"], true);
    assert!(secret["reason"].as_str().unwrap().starts_with("nah - "));

    let wiring_edit = run_adapter(
        home,
        &project,
        "edit_file",
        json!({
            "path":home.join(".config/amp/plugins/nah.ts"),
            "old_str":"enabled",
            "new_str":"disabled"
        }),
    );
    let wiring_edit = decision(&wiring_edit);
    assert_eq!(wiring_edit["block"], true);
    assert!(
        wiring_edit["reason"]
            .as_str()
            .unwrap()
            .contains("do not retry")
    );

    for command in [
        format!(
            "python -c 'import os; os.chmod(\"{}\", 0)'",
            home.join(".config/amp/plugins").display()
        ),
        format!(
            "python -c 'import os; os.chmod(\"{}\", 0)'",
            home.join(".local/bin").display()
        ),
    ] {
        let output = run_adapter(home, &project, "shell_command", json!({"command":command}));
        assert_eq!(decision(&output)["block"], true, "{command}");
    }

    let unrelated_chmod = run_adapter(
        home,
        &project,
        "shell_command",
        json!({"command":"python -c 'import os; os.chmod(\"/tmp/unrelated\", 0)'"}),
    );
    assert_eq!(
        decision(&unrelated_chmod),
        json!({"block":false,"evaluation_failed":false})
    );

    let upload_secret = run_adapter(
        home,
        &project,
        "upload_thread_file",
        json!({"thread":"T-other","path":".env"}),
    );
    assert_eq!(decision(&upload_secret)["block"], true);

    let wiring_download = run_adapter(
        home,
        &project,
        "download_thread_file",
        json!({
            "thread":"T-other",
            "path":"nah.ts",
            "destination":home.join(".config/amp/plugins/nah.ts"),
            "overwrite":true
        }),
    );
    assert_eq!(decision(&wiring_download)["block"], true);

    for command in [
        "nah hook amp uninstall",
        "amp plugins remove nah.ts --target system",
    ] {
        let output = run_adapter(home, &project, "shell_command", json!({"command":command}));
        assert_eq!(decision(&output)["block"], true, "{command}");
    }
    let unrelated_plugin = run_adapter(
        home,
        &project,
        "shell_command",
        json!({"command":"amp plugins add @owner/example"}),
    );
    assert_eq!(
        decision(&unrelated_plugin),
        json!({"block":false,"evaluation_failed":false})
    );
}

#[test]
fn malformed_amp_input_delegates_as_opaque() {
    let home = tempfile::tempdir().unwrap();
    let project = repo(home.path());
    for (tool, input) in [
        ("shell_command", json!({"command":7})),
        ("edit_file", json!({"path":"/repo/src/lib.rs"})),
        ("apply_patch", json!({"patchText":""})),
        ("create_file", json!({"path":"", "content":"x"})),
    ] {
        let output = run_adapter(home.path(), &project, tool, input);
        assert_eq!(
            decision(&output),
            json!({"block":false,"evaluation_failed":false}),
            "{tool}"
        );
    }
}
