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
        .args(["hook", "pi", "run"])
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env_remove("XDG_CONFIG_HOME")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let payload = json!({
        "tool_name": tool_name,
        "tool_input": tool_input,
        "cwd": project,
    });
    child
        .stdin
        .take()
        .unwrap()
        .write_all(payload.to_string().as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn decision(output: &std::process::Output) -> Value {
    assert!(output.status.success(), "{output:?}");
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn pi_adapter_maps_builtins_and_preserves_verdicts() {
    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = std::fs::canonicalize(home_temp.path()).unwrap();
    let home = home.as_path();
    let project = repo(home);
    std::fs::write(project.join(".env"), "TOKEN=secret\n").unwrap();

    for (tool, input) in [
        ("bash", json!({"command":"echo ok","timeout":10})),
        ("read", json!({"path":"src/lib.rs","offset":1})),
        (
            "write",
            json!({"path":"src/new.rs","content":"pub fn new() {}\n"}),
        ),
        (
            "edit",
            json!({"path":"src/lib.rs","edits":[
                {"oldText":"demo","newText":"example"},
                {"oldText":"pub","newText":"pub(crate)"}
            ]}),
        ),
        ("grep", json!({"pattern":"demo","path":"src"})),
        ("find", json!({"pattern":"**/*.rs","path":"src"})),
        ("ls", json!({"path":"src"})),
        ("custom_tool", json!({"argument":7})),
    ] {
        let output = run_adapter(home, &project, tool, input);
        assert_eq!(
            decision(&output),
            json!({"block":false,"evaluation_failed":false}),
            "{tool}"
        );
    }

    let secret = run_adapter(home, &project, "read", json!({"path":".env"}));
    let secret = decision(&secret);
    assert_eq!(secret["block"], true);
    assert!(secret["reason"].as_str().unwrap().starts_with("nah - "));

    let wiring_edit = run_adapter(
        home,
        &project,
        "write",
        json!({
            "path":home.join(".pi/agent/extensions/nah/index.js"),
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
}

#[test]
fn malformed_pi_input_delegates_as_opaque() {
    let home_temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah
    // resolves paths before matching them
    let home = std::fs::canonicalize(home_temp.path()).unwrap();
    let home = home.as_path();
    let project = repo(home);
    for (tool, input) in [
        ("bash", json!({"command":7})),
        ("edit", json!({"path":"src/lib.rs","edits":[]})),
        ("ls", json!({"path":7})),
    ] {
        let output = run_adapter(home, &project, tool, input);
        assert_eq!(
            decision(&output),
            json!({"block":false,"evaluation_failed":false})
        );
    }
}
