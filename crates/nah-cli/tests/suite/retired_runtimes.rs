//! The runtimes Nah 2.0 dropped: a hook Nah 1.x installed for one keeps
//! letting calls go on after the upgrade, and `uninstall` removes it.
#![cfg(unix)]
#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use serde_json::{Value, json};

fn nah(home: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_nah"));
    command
        .args(args)
        .env("HOME", home)
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("KIRO_HOME")
        .env_remove("COPILOT_HOME")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

fn run_hook(home: &Path, runtime: &str, event: &Value) -> std::process::Output {
    let mut child = nah(home, &["hook", runtime, "run"])
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(event.to_string().as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

/// Copilot CLI denies a call whose hook exits nonzero, and Kiro and Droid
/// deny one that exits 2, as a usage error does; so each runtime's `run`
/// answers in that runtime's own "go on" shape, and says once per session
/// that Nah no longer checks it.
#[test]
fn a_retired_runtimes_hook_lets_every_call_go_on_and_says_so_once_per_session() {
    let notice = "Nah 2.0 no longer supports";
    for (runtime, pre_call, post_call, said_code) in [
        (
            "amp",
            json!({"tool_name":"shell_command","tool_input":{"command":"rm -rf /"},"cwd":"/repo","session_id":"T-1"}),
            json!({"tool_name":"shell_command","hook_event_name":"PostToolUse","session_id":"T-1"}),
            0,
        ),
        (
            "cline",
            json!({"hookName":"PreToolUse","taskId":"task-1","preToolUse":{"toolName":"execute_command","parameters":{"command":"rm -rf /"}}}),
            json!({"hookName":"PostToolUse","taskId":"task-1"}),
            0,
        ),
        (
            "copilot",
            json!({"sessionId":"s-1","toolName":"bash","toolArgs":"{\"command\":\"rm -rf /\"}","cwd":"/repo"}),
            json!({"sessionId":"s-1","toolName":"bash","toolResult":{"resultType":"success"}}),
            0,
        ),
        (
            "devin",
            json!({"hook_event_name":"PreToolUse","session_id":"s-1","tool_name":"exec","tool_input":{"command":"rm -rf /"}}),
            json!({"hook_event_name":"Stop","session_id":"s-1"}),
            0,
        ),
        (
            "droid",
            json!({"hook_event_name":"PreToolUse","session_id":"s-1","tool_name":"Execute","tool_input":{"command":"rm -rf /"}}),
            json!({"hook_event_name":"PostToolUse","session_id":"s-1"}),
            0,
        ),
        (
            "kiro",
            json!({"hook_event_name":"PreToolUse","session_id":"s-1","tool_name":"execute_bash","tool_input":{"command":"rm -rf /"},"cwd":"/repo"}),
            json!({"hook_event_name":"PostToolUse","session_id":"s-1"}),
            1,
        ),
    ] {
        let home = tempfile::tempdir().unwrap();
        // A post-call event says nothing, so the session's first pre-call
        // event still does.
        let after = run_hook(home.path(), runtime, &post_call);
        assert_eq!(after.status.code(), Some(0), "{runtime}: {after:?}");
        let first = run_hook(home.path(), runtime, &pre_call);
        let again = run_hook(home.path(), runtime, &pre_call);
        for output in [&after, &first, &again] {
            let printed = format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(
                printed.contains(notice),
                std::ptr::eq(output, &first),
                "{runtime}: {printed}"
            );
        }
        assert_eq!(first.status.code(), Some(said_code), "{runtime}: {first:?}");
        assert_eq!(again.status.code(), Some(0), "{runtime}: {again:?}");
        let reply = |output: &std::process::Output| {
            serde_json::from_slice::<Value>(&output.stdout).unwrap_or(Value::Null)
        };
        match runtime {
            "amp" => {
                assert_eq!(reply(&first)["block"], false, "{first:?}");
                assert_eq!(reply(&first)["evaluation_failed"], true, "{first:?}");
                assert_eq!(
                    reply(&again),
                    json!({"block":false,"evaluation_failed":false})
                );
            }
            "cline" => {
                assert_eq!(reply(&first)["cancel"], false, "{first:?}");
                assert_eq!(reply(&again), json!({"cancel":false}));
            }
            "copilot" => {
                assert_eq!(reply(&first)["type"], "progress", "{first:?}");
                assert!(again.stdout.is_empty(), "{again:?}");
            }
            _ => {}
        }
        // Another session is told once too, however the two interleave.
        let mut other = pre_call.clone();
        for field in ["session_id", "sessionId", "taskId"] {
            if other.get(field).is_some() {
                other[field] = json!("another");
            }
        }
        for (event, told) in [(&other, true), (&pre_call, false), (&other, false)] {
            let output = run_hook(home.path(), runtime, event);
            let printed = format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(printed.contains(notice), told, "{runtime}: {printed}");
        }
    }
}

/// Removing a runtime's 1.x hook by hand means finding it among the user's
/// own configuration, so `uninstall` still recognizes and removes exactly
/// the wiring 1.x wrote. Install refuses and status says no more than that
/// the runtime is no longer supported.
#[test]
fn uninstall_removes_the_1x_wiring_and_keeps_the_users() {
    let home = tempfile::tempdir().unwrap();
    let home = home.path();
    let write = |path: &str, contents: &str| {
        let path = home.join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    };
    let json_at = |path: &str| -> Value {
        serde_json::from_slice(&std::fs::read(home.join(path)).unwrap()).unwrap()
    };
    let user_handler = json!({"type":"command","command":"/usr/local/bin/audit-hook","timeout":5});
    write(
        ".config/amp/plugins/nah.ts",
        "// Managed by nah.\nconst child = spawn(nahExecutable, [\"hook\", \"amp\", \"run\"]);\n",
    );
    write(".config/amp/plugins/mine.ts", "export default () => {};\n");
    write(
        "Documents/Cline/Hooks/PreToolUse",
        "#!/bin/sh\n# Managed by nah: Cline PreToolUse\nexec '/usr/bin/nah' hook cline run\n",
    );
    // 1.x wrote only PreToolUse, so a PostToolUse is the user's, here a link
    // to a script of theirs, which uninstall must neither follow nor refuse.
    write("Documents/Cline/mine.sh", "#!/bin/sh\necho mine\n");
    std::os::unix::fs::symlink(
        home.join("Documents/Cline/mine.sh"),
        home.join("Documents/Cline/Hooks/PostToolUse"),
    )
    .unwrap();
    write(
        ".copilot/hooks/nah.json",
        &json!({"version":1,"hooks":{"preToolUse":[{"type":"command","command":"'/usr/bin/nah' hook copilot run","timeoutSec":5}]}}).to_string(),
    );
    write(
        ".config/devin/config.json",
        &json!({"version":1,"model":"mine","hooks":{"PreToolUse":[{"matcher":"","hooks":[
            {"type":"command","command":"'/usr/bin/nah' hook devin run --fail-closed","timeout":5},
            user_handler
        ]}]}})
        .to_string(),
    );
    write(
        ".factory/hooks.json",
        &json!({"PreToolUse":[
            {"matcher":"*","hooks":[{"type":"command","command":"'/usr/bin/nah' hook droid run","timeout":5}]},
            {"matcher":"Execute","hooks":[user_handler]}
        ]})
        .to_string(),
    );
    write(
        ".kiro/hooks/nah.json",
        &json!({"version":"v1","hooks":[{
            "name":"nah",
            "description":"Block tool calls that nah proves are disasters.",
            "trigger":"PreToolUse",
            "action":{"type":"command","command":"'/usr/bin/nah' hook kiro run || { status=$?; [ \"$status\" -eq 1 ] && exit 1; [ \"$status\" -eq 2 ] && exit 2; printf '%s\\n' 'nah - evaluation failed; this call was delegated to the runtime' >&2; exit 1; }"},
            "timeout":5,
            "enabled":true
        }]})
        .to_string(),
    );
    for runtime in ["amp", "cline", "copilot", "devin", "droid", "kiro"] {
        let status = nah(home, &["hook", runtime, "status"]).output().unwrap();
        assert!(status.status.success(), "{runtime}: {status:?}");
        assert!(
            String::from_utf8_lossy(&status.stdout).contains("no longer supported"),
            "{runtime}: {status:?}"
        );
        let install = nah(home, &["hook", runtime, "install"]).output().unwrap();
        assert!(!install.status.success(), "{runtime}: {install:?}");
        let uninstall =
            crate::support::operator_output(&mut nah(home, &["hook", runtime, "uninstall"]));
        assert!(uninstall.status.success(), "{runtime}: {uninstall:?}");
    }
    for removed in [
        ".config/amp/plugins/nah.ts",
        "Documents/Cline/Hooks/PreToolUse",
        ".copilot/hooks/nah.json",
        ".kiro/hooks/nah.json",
    ] {
        assert!(!home.join(removed).exists(), "{removed}");
    }
    for kept in [
        ".config/amp/plugins/mine.ts",
        "Documents/Cline/Hooks/PostToolUse",
        "Documents/Cline/mine.sh",
    ] {
        assert!(std::fs::symlink_metadata(home.join(kept)).is_ok(), "{kept}");
    }
    assert_eq!(
        json_at(".config/devin/config.json"),
        json!({"version":1,"model":"mine","hooks":{"PreToolUse":[{"matcher":"","hooks":[user_handler]}]}})
    );
    assert_eq!(
        json_at(".factory/hooks.json"),
        json!({"PreToolUse":[{"matcher":"Execute","hooks":[user_handler]}]})
    );

    // A Nah script someone edited is not removed, and uninstall says so
    // instead of reporting success.
    write(
        "Documents/Cline/Hooks/PreToolUse",
        "#!/bin/sh\n# Managed by nah: Cline PreToolUse\nexec '/usr/bin/nah' hook cline run\n# mine\n",
    );
    let uninstall =
        crate::support::operator_output(&mut nah(home, &["hook", "cline", "uninstall"]));
    assert!(!uninstall.status.success(), "{uninstall:?}");
    assert!(
        String::from_utf8_lossy(&uninstall.stderr).contains("cline-hook-file-conflict"),
        "{uninstall:?}"
    );
    assert!(home.join("Documents/Cline/Hooks/PreToolUse").exists());
}
