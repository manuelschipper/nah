#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

use crate::support;

use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::{Value, json};

/// Every runtime adapter reports a block in the one message format, naming
/// the rule that blocked. Each blocks corpus row `secrets-env.env-read`
/// (`cat .env`) through its own shell tool and hook payload; a runtime added
/// to `HOOK_RUNTIME_NAMES` fails here until it has a payload.
#[test]
fn every_adapter_names_the_blocking_rule_in_one_format() {
    let temp = tempfile::tempdir().unwrap();
    let home = support::test_temp_path(temp.path());
    let project = support::repo(&home);
    std::fs::write(project.join(".env"), "TOKEN=secret\n").unwrap();
    let command = "cat .env";
    let shell = |tool: &str| json!({"hook_event_name":"PreToolUse","tool_name":tool,"tool_input":{"command":command},"cwd":project,"session_id":"session-1"});
    let plugin = |tool: &str| json!({"tool_name":tool,"tool_input":{"command":command},"cwd":project,"session_id":"session-1"});
    let payloads: [(&str, Value); 8] = [
        (
            "antigravity",
            json!({
                "toolCall": {"name":"run_command","args":{"CommandLine":command,"Cwd":project}},
                "stepIdx": 1,
                "conversationId": "conversation-1",
                "workspacePaths": [project],
                "transcriptPath": home.join("transcript.jsonl"),
                "artifactDirectoryPath": home.join("artifacts")
            }),
        ),
        ("claude", shell("Bash")),
        ("codex", shell("Bash")),
        (
            "cursor",
            json!({
                "conversation_id": "conversation-1",
                "generation_id": "generation-1",
                "hook_event_name": "preToolUse",
                "tool_name": "Shell",
                "tool_input": {"command":command},
                "tool_use_id": "call-1",
                "cwd": project,
            }),
        ),
        (
            "hermes",
            json!({"hook_event_name":"pre_tool_call","tool_name":"terminal","tool_input":{"command":command},"session_id":"session-1","cwd":project}),
        ),
        ("openclaw", plugin("exec")),
        ("opencode", plugin("shell")),
        ("pi", plugin("bash")),
    ];
    for runtime in nah_proto::runtime::HOOK_RUNTIME_NAMES {
        let payload = &payloads
            .iter()
            .find(|(name, _)| name == runtime)
            .unwrap_or_else(|| panic!("no hook payload for {runtime}"))
            .1;
        let mut child = Command::new(env!("CARGO_BIN_EXE_nah"))
            .args(["hook", runtime, "run"])
            .current_dir(&project)
            .env("HOME", &home)
            .env("USERPROFILE", &home)
            .env_remove("XDG_CONFIG_HOME")
            .env_remove("HERMES_HOME")
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
        let reply = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            reply.contains("nah · secrets/env-files-read: "),
            "{runtime}: {reply}"
        );
        assert!(!reply.contains("nah - "), "{runtime}: {reply}");
    }
}
