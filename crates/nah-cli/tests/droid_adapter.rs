#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

mod support;

use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::json;
use support::repo;

#[test]
fn malformed_hook_input_delegates() {
    let home = tempfile::tempdir().unwrap();
    let project = repo(home.path());
    for (tool, input) in [
        ("Execute", json!({"command":7})),
        ("Create", json!({"file_path":"","content":"x"})),
        ("Edit", json!({"file_path":"src/lib.rs"})),
        ("ApplyPatch", json!({"input":""})),
        ("Glob", json!({"patterns":"*.rs"})),
    ] {
        let mut child = Command::new(env!("CARGO_BIN_EXE_nah"))
            .args(["hook", "droid", "run"])
            .env("HOME", home.path())
            .env("USERPROFILE", home.path())
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
                    "hook_event_name":"PreToolUse",
                    "tool_name":tool,
                    "tool_input":input,
                    "cwd":project
                })
                .to_string()
                .as_bytes(),
            )
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success(), "{tool}: {output:?}");
        assert!(output.stdout.is_empty());
        assert!(output.stderr.is_empty(), "{tool}: {output:?}");
    }
}
