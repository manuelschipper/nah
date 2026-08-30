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
        .args(["hook", "opencode", "run"])
        .env("HOME", home)
        .env("USERPROFILE", home)
        // an inherited XDG_CONFIG_HOME belongs to the real user, not this
        // fixture home, and the adapter refuses a custom one
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
                "session_id": "subagent-session",
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
fn opencode_adapter_maps_builtins_and_guards() {
    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = std::fs::canonicalize(home_temp.path()).unwrap();
    let home = home.as_path();
    let project = repo(home);
    std::fs::write(project.join(".env"), "TOKEN=secret\n").unwrap();

    for (tool, input) in [
        ("bash", json!({"command":"echo ok"})),
        ("read", json!({"filePath":"src/lib.rs","offset":1})),
        (
            "write",
            json!({"filePath":"src/new.rs","content":"pub fn new() {}\n"}),
        ),
        (
            "edit",
            json!({
                "filePath":"src/lib.rs",
                "oldString":"demo",
                "newString":"example",
                "replaceAll":false
            }),
        ),
        ("glob", json!({"pattern":"src","path":project})),
        ("grep", json!({"pattern":"demo","path":"src"})),
        (
            "apply_patch",
            json!({
                "patchText":"*** Begin Patch\n*** Update File: src/lib.rs\n@@\n-old\n+new\n*** End Patch\n"
            }),
        ),
        ("websearch", json!({"query":"example"})),
    ] {
        let output = run_adapter(home, &project, tool, input);
        assert_eq!(
            decision(&output),
            json!({"block":false,"evaluation_failed":false}),
            "{tool}"
        );
    }

    let secret = run_adapter(home, &project, "read", json!({"filePath":".env"}));
    let secret = decision(&secret);
    assert_eq!(secret["block"], true);
    assert!(secret["reason"].as_str().unwrap().starts_with("nah - "));

    let wiring_edit = run_adapter(
        home,
        &project,
        "write",
        json!({
            "filePath":home.join(".config/opencode/plugins/nah.js"),
            "content":"disabled"
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

    let lifecycle = run_adapter(
        home,
        &project,
        "bash",
        json!({"command":"nah hook opencode uninstall"}),
    );
    assert_eq!(decision(&lifecycle)["block"], true);
}

#[test]
fn malformed_opencode_input_delegates_as_opaque() {
    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = std::fs::canonicalize(home_temp.path()).unwrap();
    let home = home.as_path();
    let project = repo(home);
    for (tool, input) in [
        ("bash", json!({"command":7})),
        ("edit", json!({"filePath":"src/lib.rs"})),
        ("apply_patch", json!({"patchText":""})),
        ("grep", json!({"pattern":"x","path":7})),
    ] {
        let output = run_adapter(home, &project, tool, input);
        assert_eq!(
            decision(&output),
            json!({"block":false,"evaluation_failed":false}),
            "{tool}"
        );
    }
}
