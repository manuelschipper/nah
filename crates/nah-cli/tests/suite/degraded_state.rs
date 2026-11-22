#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

use crate::support;

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use nah_proto::decision::{DecisionOutput, Verdict};
use serde_json::json;
use support::repo;

/// The custom-guard state nah 1.x kept. Nah 2.0 runs no custom guard, so no
/// decision reads it, however damaged it is.
const LEGACY_CUSTOM_GUARD_STATE: [&str; 2] = ["trust.json", "activations.json"];

/// Unreadable bytes, then a state version from a future release. A downgrade —
/// or a stale hook pointing at an older binary — produces the second one.
const DAMAGE: [&str; 2] = ["GARBAGE{not json", r#"{"v":999}"#];

fn nah(home: &Path, args: &[&str], stdin: Option<&str>) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_nah"));
    command
        .args(args)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env_remove("XDG_CONFIG_HOME")
        .env("USER", "tester")
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if args.get(1) == Some(&"disable") {
        return support::operator_output(&mut command);
    }
    let mut child = command.spawn().unwrap();
    if let Some(input) = stdin {
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
    }
    child.wait_with_output().unwrap()
}

fn decide(
    home: &Path,
    cwd: &Path,
    tool: &str,
    input: serde_json::Value,
) -> (DecisionOutput, String, Option<i32>) {
    let payload = json!({"v": 1, "tool": tool, "input": input, "cwd": cwd}).to_string();
    let output = nah(home, &["decide"], Some(&payload));
    (
        serde_json::from_slice(&output.stdout).expect("decide always answers with a decision"),
        String::from_utf8(output.stderr).unwrap(),
        output.status.code(),
    )
}

fn damage(home: &Path, file: &str, contents: &str) {
    std::fs::create_dir_all(home.join(".nah")).unwrap();
    std::fs::write(home.join(".nah").join(file), contents).unwrap();
}

#[test]
fn damaged_state_decides_exactly_like_a_fresh_install() {
    let probes = [
        ("Bash", json!({"command":"rm -rf /"})),
        ("Bash", json!({"command":"git push --force"})),
        ("Read", json!({"file_path":"src/lib.rs"})),
        ("Read", json!({"file_path":".env"})),
    ];
    let answers = |home: &Path, project: &Path| {
        probes
            .iter()
            .map(|(tool, input)| {
                let (decision, _, code) = decide(home, project, tool, input.clone());
                (decision.verdict(), decision.reason().to_owned(), code)
            })
            .collect::<Vec<_>>()
    };

    let fresh = tempfile::tempdir().unwrap();
    let fresh_project = repo(fresh.path());
    assert!(!fresh.path().join(".nah").exists());
    let expected = answers(fresh.path(), &fresh_project);

    for file in LEGACY_CUSTOM_GUARD_STATE {
        for contents in DAMAGE {
            let temp = tempfile::tempdir().unwrap();
            // macOS temp directories sit under a symlinked /var, and nah resolves
            // paths before matching them
            let root = support::test_temp_path(temp.path());
            let project = repo(&root);
            damage(&root, file, contents);

            assert_eq!(answers(&root, &project), expected, "{file}: {contents}");
        }
    }
}

#[test]
fn invalid_shipped_state_keeps_defaults_and_reports_failure_under_both_policies() {
    for (contents, error) in [
        (Some(DAMAGE[0]), "invalid-shipped-state"),
        (Some(DAMAGE[1]), "unsupported-shipped-state-version"),
        (
            Some(
                "{\"v\":3,\"guards\":{},\"rules\":{\"infrastructure/database-drop\":\"enabled\",\"infrastructure/database-drop\":\"disabled\"}}\n",
            ),
            "invalid-shipped-state",
        ),
        (
            None,
            if cfg!(windows) {
                "shipped-state-io-failed"
            } else {
                "invalid-shipped-state"
            },
        ),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let root = support::test_temp_path(temp.path());
        let project = repo(&root);
        let command = "psql -c 'DROP TABLE users'";
        let input = json!({"command":command});
        assert_eq!(
            decide(&root, &project, "Bash", input.clone()).0.verdict(),
            Verdict::Delegate
        );
        for args in [
            ["rule", "enable", "infrastructure/database-drop"],
            ["rule", "disable", "persistence/auth-files-modify"],
        ] {
            let output = nah(&root, &args, None);
            assert!(output.status.success(), "{output:?}");
        }
        assert_eq!(
            decide(&root, &project, "Bash", input.clone()).0.verdict(),
            Verdict::Block
        );
        let payload = json!({
            "hook_event_name":"PreToolUse",
            "tool_name":"Bash",
            "tool_input":input,
            "cwd":project,
            "session_id":"session-1"
        })
        .to_string();
        let output = nah(
            &root,
            &["hook", "claude", "run", "--fail-closed"],
            Some(&payload),
        );
        assert!(output.status.success(), "{output:?}");
        let reply: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(reply["hookSpecificOutput"]["permissionDecision"], "deny");
        let write = json!({"file_path":root.join(".ssh/authorized_keys"),"content":"key"});
        assert_eq!(
            decide(&root, &project, "Write", write.clone()).0.verdict(),
            Verdict::Delegate
        );

        if let Some(contents) = contents {
            damage(&root, "built-ins.json", contents);
        } else {
            // A directory cannot be read as state on any supported platform.
            let path = root.join(".nah/built-ins.json");
            std::fs::remove_file(&path).unwrap();
            std::fs::create_dir(path).unwrap();
        }

        for (tool, input, verdict) in [
            ("Bash", input, Verdict::Delegate),
            ("Write", write, Verdict::Block),
            ("Bash", json!({"command":"rm -rf /"}), Verdict::Block),
            (
                "Write",
                json!({"file_path":root.join(".nah/trust.json"),"content":"{}"}),
                Verdict::Block,
            ),
        ] {
            let (decision, stderr, code) = decide(&root, &project, tool, input);
            assert_eq!(decision.verdict(), verdict, "{contents:?}");
            assert_eq!(code, Some(if verdict == Verdict::Block { 1 } else { 2 }));
            assert!(stderr.contains("~/.nah/built-ins.json"), "{stderr}");
            assert!(stderr.contains(error), "{stderr}");
        }

        for hook_command in [command, "rm -rf /"] {
            let payload = json!({
                "hook_event_name":"PreToolUse",
                "tool_name":"Bash",
                "tool_input":{"command":hook_command},
                "cwd":project,
                "session_id":"session-1"
            })
            .to_string();
            for fail_closed in [false, true] {
                let mut args = vec!["hook", "claude", "run"];
                if fail_closed {
                    args.push("--fail-closed");
                }
                let output = nah(&root, &args, Some(&payload));
                assert!(output.status.success(), "{contents:?}: {output:?}");
                let reply: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
                let guard_blocked = hook_command == "rm -rf /";
                if fail_closed || guard_blocked {
                    assert_eq!(reply["hookSpecificOutput"]["permissionDecision"], "deny");
                    if guard_blocked {
                        assert!(
                            reply["systemMessage"]
                                .as_str()
                                .unwrap()
                                .contains("evaluation was incomplete")
                        );
                    }
                } else {
                    assert!(
                        reply["systemMessage"]
                            .as_str()
                            .unwrap()
                            .contains("could not finish safety evaluation")
                    );
                    assert!(reply["hookSpecificOutput"].is_null());
                }
                let audit = std::fs::read_to_string(root.join(".nah/audit.jsonl")).unwrap();
                let record: serde_json::Value =
                    serde_json::from_str(audit.lines().last().unwrap()).unwrap();
                assert_eq!(record["status"], "decision");
                assert_eq!(record["failures"][0]["source"], "nah");
                assert_eq!(record["failures"][0]["component"], "built-ins.json");
                assert_eq!(record["failures"][0]["code"], error);
                let diagnostic = record["diagnostics"][0].as_str().unwrap();
                assert!(diagnostic.contains("~/.nah/built-ins.json"), "{diagnostic}");
                assert!(diagnostic.contains(error), "{diagnostic}");
                assert_eq!(
                    record["core"]["verdict"],
                    if fail_closed || guard_blocked {
                        "block"
                    } else {
                        "delegate"
                    }
                );
            }
        }

        let output = support::nah(&root, &project, &["test", "--json", command], None);
        assert!(output.status.success(), "{output:?}");
        let dry_run: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(dry_run["decision"]["verdict"], "delegate");
        assert_eq!(dry_run["failures"][0]["component"], "built-ins.json");
        assert_eq!(dry_run["failures"][0]["code"], error);

        if contents.is_none() {
            std::fs::remove_dir(root.join(".nah/built-ins.json")).unwrap();
        }
        damage(
            &root,
            "built-ins.json",
            "{\"v\":3,\"guards\":{},\"rules\":{\"infrastructure/database-drop\":\"enabled\",\"persistence/auth-files-modify\":\"disabled\"}}\n",
        );
        let output = support::nah(&root, &project, &["test", "--json", command], None);
        assert!(output.status.success(), "{output:?}");
        let repaired: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(repaired["decision"]["verdict"], "block");
        assert!(repaired["failures"].as_array().unwrap().is_empty());
    }
}
