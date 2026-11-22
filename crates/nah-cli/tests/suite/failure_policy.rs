#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

use crate::support;

use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::{Value, json};
use support::repo;

/// Runs an adapter with no resolvable home directory, the reachable trigger for
/// "nah cannot build a decision context at all".
fn run_without_home(runtime: &str, payload: Value) -> Value {
    run_adapter(runtime, None, payload)
}

fn run_without_home_strict(runtime: &str, payload: Value) -> Value {
    run_adapter_mode(runtime, None, payload, true)
}

fn run_adapter(runtime: &str, home: Option<&std::path::Path>, payload: Value) -> Value {
    run_adapter_mode(runtime, home, payload, false)
}

fn run_adapter_mode(
    runtime: &str,
    home: Option<&std::path::Path>,
    payload: Value,
    fail_closed: bool,
) -> Value {
    let mut command = Command::new(env!("CARGO_BIN_EXE_nah"));
    command.args(["hook", runtime, "run"]);
    if fail_closed {
        command.arg("--fail-closed");
    }
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    match home {
        Some(home) => {
            // the hermes adapter resolves its home, so give the fixture the
            // standard one instead of inheriting the host's
            std::fs::create_dir_all(home.join(".hermes")).unwrap();
            command
                .env("HOME", home)
                .env("USERPROFILE", home)
                .env_remove("XDG_CONFIG_HOME")
                .env_remove("HERMES_HOME");
        }
        None => {
            command.env_remove("HOME").env_remove("USERPROFILE");
        }
    }
    let mut child = command.spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(payload.to_string().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let parsed_stdout = serde_json::from_str::<Value>(&stdout).unwrap_or(Value::Null);
    json!({
        "code": output.status.code(),
        "stdout": parsed_stdout,
        "stdout_raw": stdout,
        "stderr": String::from_utf8(output.stderr).unwrap(),
    })
}

fn assert_native_deny(runtime: &str, observed: &Value) {
    match runtime {
        "claude" | "codex" => assert_eq!(
            observed["stdout"]["hookSpecificOutput"]["permissionDecision"], "deny",
            "{runtime}: {observed}"
        ),
        "cursor" => {
            assert_eq!(observed["code"], 2, "{runtime}: {observed}");
            assert_eq!(observed["stdout"]["permission"], "deny");
        }
        "pi" | "opencode" | "openclaw" => {
            assert_eq!(observed["stdout"]["block"], true, "{runtime}: {observed}")
        }
        "antigravity" => {
            assert_eq!(
                observed["stdout"]["decision"], "deny",
                "{runtime}: {observed}"
            )
        }
        "hermes" => {
            assert_eq!(
                observed["stdout"]["decision"], "block",
                "{runtime}: {observed}"
            )
        }
        _ => unreachable!("{runtime}"),
    }
}

fn danger(project: &std::path::Path) -> Vec<(&'static str, Value)> {
    let cwd = project.to_str().unwrap();
    vec![
        (
            "claude",
            json!({
                "hook_event_name":"PreToolUse",
                "tool_name":"Bash",
                "tool_input":{"command":"rm -rf /"},
                "cwd":cwd,
                "session_id":"session-1"
            }),
        ),
        (
            "codex",
            json!({
                "hook_event_name":"PreToolUse",
                "tool_name":"Bash",
                "tool_input":{"command":"rm -rf /"},
                "cwd":cwd,
                "session_id":"session-1"
            }),
        ),
        (
            "cursor",
            json!({
                "hook_event_name":"preToolUse",
                "tool_name":"Shell",
                "tool_input":{"command":"rm -rf /"},
                "cwd":cwd,
                "conversation_id":"conversation-1"
            }),
        ),
        (
            "pi",
            json!({"tool_name":"bash","tool_input":{"command":"rm -rf /"},"cwd":cwd}),
        ),
        (
            "opencode",
            json!({
                "tool_name":"shell",
                "tool_input":{"command":"rm -rf /"},
                "cwd":cwd,
                "session_id":"session-1"
            }),
        ),
        (
            "openclaw",
            json!({
                "tool_name":"exec",
                "tool_input":{"command":"rm -rf /"},
                "cwd":cwd,
                "session_id":"session-1"
            }),
        ),
        (
            "antigravity",
            json!({
                "toolCall":{"name":"run_command","args":{"CommandLine":"rm -rf /","Cwd":cwd}},
                "conversationId":"conversation-1",
                "workspacePaths":[cwd]
            }),
        ),
        (
            "hermes",
            json!({
                "hook_event_name":"pre_tool_call",
                "tool_name":"terminal",
                "tool_input":{"command":"rm -rf /"},
                "cwd":cwd,
                "session_id":"session-1"
            }),
        ),
    ]
}

fn guard_blocking_danger(project: &std::path::Path) -> Vec<(&'static str, Value)> {
    danger(project)
}

fn with_ill_typed_command(runtime: &str, mut payload: Value) -> Value {
    match runtime {
        "antigravity" => payload["toolCall"]["args"]["CommandLine"] = json!(7),
        _ => payload["tool_input"]["command"] = json!(7),
    }
    payload
}

fn with_command(runtime: &str, mut payload: Value, command: &str) -> Value {
    match runtime {
        "antigravity" => payload["toolCall"]["args"]["CommandLine"] = json!(command),
        _ => payload["tool_input"]["command"] = json!(command),
    }
    payload
}

fn with_tool_input(runtime: &str, mut payload: Value, input: Value) -> Value {
    match runtime {
        "antigravity" => payload["toolCall"]["args"] = input,
        _ => payload["tool_input"] = input,
    }
    payload
}

fn with_unavailable_cwd(runtime: &str, mut payload: Value) -> Value {
    match runtime {
        "antigravity" => payload["workspacePaths"] = json!([]),
        _ => payload["cwd"] = json!(7),
    }
    payload
}

fn with_irrelevant_event(runtime: &str, mut payload: Value) -> Option<Value> {
    match runtime {
        "claude" | "codex" => payload["hook_event_name"] = json!("PostToolUse"),
        "cursor" => payload["hook_event_name"] = json!("postToolUse"),
        "hermes" => payload["hook_event_name"] = json!("post_tool_call"),
        _ => return None,
    }
    Some(payload)
}

fn minimal_irrelevant_event(runtime: &str) -> Option<Value> {
    match runtime {
        "claude" | "codex" => Some(json!({"hook_event_name":"PostToolUse"})),
        "cursor" => Some(json!({"hook_event_name":"postToolUse"})),
        "hermes" => Some(json!({"hook_event_name":"post_tool_call"})),
        _ => None,
    }
}

fn recovery_id(observed: &Value) -> &str {
    ["stdout_raw", "stderr"]
        .into_iter()
        .find_map(|channel| {
            let (_, command) = observed[channel].as_str()?.split_once("nah why ")?;
            let id = command.split('`').next()?;
            id.starts_with("decision-").then_some(id)
        })
        .expect("a failed decision exposes its recovery ID")
}

fn delegated(runtime: &str, evaluation_failed: bool, id: Option<&str>) -> Value {
    let message = id.map(|id| format!("nah · could not finish safety evaluation; this call was delegated to the runtime; run `nah why {id}` for details"));
    let native = |code: i64, stdout: Value| json!({"code":code,"stdout":stdout});
    match (runtime, evaluation_failed) {
        ("claude" | "codex", true) => native(0, json!({"systemMessage":message.as_ref().unwrap()})),
        // Cursor hands a call back with a reply, which its `failClosed`
        // does not take for a failed hook.
        ("cursor", _) => native(0, json!({})),
        ("pi" | "opencode" | "openclaw", failed) => {
            let mut response = json!({"block":false,"evaluation_failed":failed});
            if failed {
                response["reason"] = json!(message.as_ref().unwrap());
            }
            native(0, response)
        }
        ("antigravity", _) => native(0, json!({"decision":"ask"})),
        ("hermes", _) => native(0, json!({})),
        ("claude" | "codex", false) => native(0, Value::Null),
        _ => unreachable!("{runtime}"),
    }
}

#[test]
fn every_adapter_delegates_when_nah_cannot_decide() {
    let temp = tempfile::tempdir().unwrap();
    let project = repo(temp.path());

    for (runtime, payload) in danger(&project) {
        let observed = run_without_home(runtime, payload);
        let expected = delegated(runtime, true, Some(recovery_id(&observed)));
        assert_eq!(observed["code"], expected["code"], "{runtime}: {observed}");
        assert_eq!(
            observed["stdout"], expected["stdout"],
            "{runtime}: {observed}"
        );
        match runtime {
            "cursor" | "antigravity" | "hermes" => assert!(
                observed["stderr"]
                    .as_str()
                    .unwrap()
                    .contains("could not finish safety evaluation"),
                "{runtime}: {observed}"
            ),
            _ => {}
        }
    }
}

#[test]
fn every_adapter_denies_when_fail_closed_cannot_decide() {
    let temp = tempfile::tempdir().unwrap();
    let project = repo(temp.path());

    for (runtime, payload) in danger(&project) {
        let observed = run_without_home_strict(runtime, payload);
        assert_native_deny(runtime, &observed);
        let rendered = observed.to_string();
        assert!(
            rendered.contains("Ask the operator"),
            "{runtime}: {observed}"
        );
        assert!(!rendered.contains("rm -rf /"), "{runtime}: {observed}");
        assert!(
            !rendered.contains("context failed"),
            "{runtime}: {observed}"
        );
    }
}

#[test]
fn fail_closed_preserves_healthy_uncertainty() {
    let temp = tempfile::tempdir().unwrap();
    let project = repo(temp.path());

    for (runtime, payload) in danger(&project) {
        let observed = run_adapter_mode(
            runtime,
            Some(temp.path()),
            with_command(runtime, payload, "unknown-tool --dynamic"),
            true,
        );
        let expected = delegated(runtime, false, None);
        assert_eq!(observed["code"], expected["code"], "{runtime}: {observed}");
        assert_eq!(
            observed["stdout"], expected["stdout"],
            "{runtime}: {observed}"
        );
    }

    // OpenCode 2.x shell options that leave the command's effects unchanged.
    for options in [json!({"timeout":1000}), json!({"background":false})] {
        let mut input = json!({"command":"echo ok"});
        input
            .as_object_mut()
            .unwrap()
            .extend(options.as_object().unwrap().clone());
        let payload = json!({
            "tool_name":"shell",
            "tool_input":input,
            "cwd":project,
            "session_id":"session-1"
        });
        let observed = run_adapter_mode("opencode", Some(temp.path()), payload, true);
        assert_eq!(
            observed["stdout"],
            delegated("opencode", false, None)["stdout"],
            "{observed}"
        );
    }
}

#[test]
fn fail_closed_blocks_a_parser_refusal_in_json_and_exit_code_adapters() {
    let temp = tempfile::tempdir().unwrap();
    let project = repo(temp.path());
    let oversized = format!("echo {}", "a".repeat(1024 * 1024));

    for (runtime, payload) in danger(&project)
        .into_iter()
        .filter(|(runtime, _)| matches!(*runtime, "pi" | "cursor"))
    {
        let observed = run_adapter_mode(
            runtime,
            Some(temp.path()),
            with_command(runtime, payload, &oversized),
            true,
        );
        assert_native_deny(runtime, &observed);
        assert!(
            observed
                .to_string()
                .contains("split the intended operation")
        );
        assert!(!observed.to_string().contains(&oversized));
    }

    let records = std::fs::read_to_string(temp.path().join(".nah/audit.jsonl")).unwrap();
    for line in records.lines() {
        let record: Value = serde_json::from_str(line).unwrap();
        assert_eq!(record["status"], "decision");
        assert_eq!(record["core"]["verdict"], "block");
        assert!(
            record["failures"]
                .as_array()
                .unwrap()
                .iter()
                .any(|failure| {
                    failure["source"] == "analysis"
                        && failure["component"] == "effinterp"
                        && failure["code"] == "input-byte-limit"
                })
        );
    }
}

/// Step exhaustion must retain an explicit refusal when a nested interior or
/// function body is unread, so the hook's strict failure policy can deny it.
#[test]
fn fail_closed_blocks_unread_shell_nesting_but_keeps_shallow_partials() {
    let temp = tempfile::tempdir().unwrap();
    let project = repo(temp.path());
    let whiles = |n: usize, body: &str| {
        format!(
            "{}{}{}",
            "while true; do ".repeat(n),
            body,
            "; done".repeat(n)
        )
    };
    let commands = [
        format!(
            "f() {{ {}chmod 000 ~/.local/bin/nah; }}; f",
            "echo hi; ".repeat(20_000)
        ),
        format!(
            "f1() {{ {}; }}; f0() {{ {}; }}; f0",
            whiles(57, "chmod 000 ~/.local/bin/nah"),
            whiles(57, "f1")
        ),
        whiles(
            60,
            &format!("bash -c '{}'", whiles(60, "chmod 000 ~/.local/bin/nah")),
        ),
        whiles(
            110,
            &format!("eval '{}'", whiles(110, "chmod 000 ~/.local/bin/nah")),
        ),
        format!(
            "{}chmod 000 ~/.local/bin/nah{}",
            "while true; do :; :; :; :; :; :; ".repeat(60),
            "; done".repeat(60)
        ),
    ];
    let payload = |command: &str| {
        json!({
            "hook_event_name":"PreToolUse", "tool_name":"Bash",
            "tool_input":{"command":command}, "cwd":project, "session_id":"nesting-budget"
        })
    };
    for command in commands {
        for strict in [false, true] {
            let observed = run_adapter_mode("claude", Some(temp.path()), payload(&command), strict);
            if strict {
                assert_native_deny("claude", &observed);
            } else {
                assert_ne!(
                    observed["stdout"]["hookSpecificOutput"]["permissionDecision"], "deny",
                    "{observed}"
                );
            }
        }
    }
    // The parser's nesting refusal also blocks with the default policy,
    // including a harmless body whose contents cannot be inspected.
    for body in ["chmod 000 ~/.local/bin/nah", "echo nest-ok"] {
        let command = format!("{}{}{}", "( ".repeat(161), body, " )".repeat(161));
        for strict in [false, true] {
            let observed = run_adapter_mode("claude", Some(temp.path()), payload(&command), strict);
            assert_native_deny("claude", &observed);
        }
    }
    let flat = "echo hi; ".repeat(20_000);
    for command in [
        flat.clone(),
        "for i in {1..30}; do for j in {1..30}; do echo \"$i,$j\" >> /tmp/grid.csv; done; done"
            .into(),
        format!("while read l; do {flat} done < /tmp/input.txt"),
    ] {
        let observed = run_adapter_mode("claude", Some(temp.path()), payload(&command), true);
        assert_ne!(
            observed["stdout"]["hookSpecificOutput"]["permissionDecision"], "deny",
            "{observed}"
        );
    }
}

/// The engine bounds the environment names one invocation may read; past it
/// no partial evidence is offered, so a fail-closed hook blocks.
#[test]
fn fail_closed_blocks_environment_name_saturation() {
    let temp = tempfile::tempdir().unwrap();
    let project = repo(temp.path());
    let command = format!(
        "echo {}",
        (0..300)
            .map(|index| format!("$NAH_NAME_{index}"))
            .collect::<Vec<_>>()
            .join(" ")
    );

    for (runtime, payload) in danger(&project)
        .into_iter()
        .filter(|(runtime, _)| matches!(*runtime, "pi" | "cursor"))
    {
        let observed = run_adapter_mode(
            runtime,
            Some(temp.path()),
            with_command(runtime, payload, &command),
            true,
        );
        assert_native_deny(runtime, &observed);
        assert!(
            observed
                .to_string()
                .contains("split the intended operation")
        );
    }

    let records = std::fs::read_to_string(temp.path().join(".nah/audit.jsonl")).unwrap();
    for line in records.lines() {
        let record: Value = serde_json::from_str(line).unwrap();
        assert_eq!(record["status"], "decision");
        assert_eq!(record["core"]["verdict"], "block");
        assert!(
            record["failures"]
                .as_array()
                .unwrap()
                .iter()
                .any(|failure| {
                    failure["source"] == "analysis"
                        && failure["component"] == "effinterp"
                        && failure["code"] == "environment-names"
                })
        );
    }
}

/// Interpreter source past the engine's byte bound is refused the same way.
#[test]
fn fail_closed_blocks_source_byte_saturation() {
    let temp = tempfile::tempdir().unwrap();
    let project = repo(temp.path());
    let (runtime, mut payload) = danger(&project)
        .into_iter()
        .find(|(runtime, _)| *runtime == "hermes")
        .unwrap();
    payload["tool_name"] = json!("execute_code");
    payload["tool_input"] = json!({"code":format!("x = '{}'", "a".repeat(1024 * 1024))});
    let observed = run_adapter_mode(runtime, Some(temp.path()), payload, true);
    assert_native_deny(runtime, &observed);

    let records = std::fs::read_to_string(temp.path().join(".nah/audit.jsonl")).unwrap();
    let record: Value = serde_json::from_str(records.lines().next().unwrap()).unwrap();
    assert!(
        record["failures"]
            .as_array()
            .unwrap()
            .iter()
            .any(|failure| {
                failure["source"] == "analysis"
                    && failure["component"] == "effinterp"
                    && failure["code"] == "input-byte-limit"
            })
    );
}

#[test]
fn fail_closed_blocks_unknown_fields_on_known_claude_and_codex_tools() {
    let temp = tempfile::tempdir().unwrap();
    let project = repo(temp.path());

    for runtime in ["claude", "codex"] {
        let payload = json!({
            "hook_event_name":"PreToolUse",
            "tool_name":"Read",
            "tool_input":{"file_path":"src/lib.rs","futureBehavior":"execute"},
            "cwd":project,
            "session_id":"session-1"
        });
        let delegated = run_adapter_mode(runtime, Some(temp.path()), payload.clone(), false);
        assert_eq!(delegated["stdout"], Value::Null, "{runtime}: {delegated}");

        let blocked = run_adapter_mode(runtime, Some(temp.path()), payload, true);
        assert_native_deny(runtime, &blocked);

        let opaque = json!({
            "hook_event_name":"PreToolUse",
            "tool_name":"future_tool",
            "tool_input":{"futureBehavior":"execute"},
            "cwd":project,
            "session_id":"session-1"
        });
        let opaque = run_adapter_mode(runtime, Some(temp.path()), opaque, true);
        assert_eq!(opaque["stdout"], Value::Null, "{runtime}: {opaque}");
    }

    let records = std::fs::read_to_string(temp.path().join(".nah/audit.jsonl")).unwrap();
    assert!(records.lines().any(|line| {
        let record: Value = serde_json::from_str(line).unwrap();
        record["failures"].as_array().is_some_and(|failures| {
            failures.iter().any(|failure| {
                failure["source"] == "analysis"
                    && failure["component"] == "adapter-normalization"
                    && failure["code"] == "incomplete"
            })
        })
    }));
}

#[test]
fn fail_closed_denies_malformed_input_and_records_only_fixed_evidence() {
    let temp = tempfile::tempdir().unwrap();
    let project = repo(temp.path());
    let raw_secret = "malformed-secret-value";

    for (runtime, _) in danger(&project) {
        let observed = run_adapter_mode(
            runtime,
            Some(temp.path()),
            json!({"unexpected":raw_secret}),
            true,
        );
        assert_native_deny(runtime, &observed);
        assert!(
            !observed.to_string().contains(raw_secret),
            "{runtime}: {observed}"
        );
    }

    let records = std::fs::read_to_string(temp.path().join(".nah/audit.jsonl")).unwrap();
    assert!(!records.contains(raw_secret));
    for line in records.lines() {
        let record: Value = serde_json::from_str(line).unwrap();
        assert_eq!(record["status"], "unavailable");
        assert_eq!(record["command"], "[unavailable]");
        assert_eq!(record["failures"][0]["source"], "integration");
    }
}

#[test]
fn irrelevant_lifecycle_events_emit_no_policy_response() {
    let temp = tempfile::tempdir().unwrap();
    let project = repo(temp.path());

    for (runtime, payload) in danger(&project) {
        let Some(payload) = with_irrelevant_event(runtime, payload) else {
            continue;
        };
        for payload in [payload, minimal_irrelevant_event(runtime).unwrap()] {
            for fail_closed in [false, true] {
                let observed =
                    run_adapter_mode(runtime, Some(temp.path()), payload.clone(), fail_closed);
                assert_eq!(observed["code"], 0, "{runtime}: {observed}");
                assert_eq!(observed["stdout"], Value::Null, "{runtime}: {observed}");
                assert_eq!(observed["stderr"], "", "{runtime}: {observed}");
            }
        }
    }
    assert!(!temp.path().join(".nah/audit.jsonl").exists());
}

#[test]
fn every_guard_blocking_adapter_offers_the_guard_scoped_override() {
    let temp = tempfile::tempdir().unwrap();
    let project = repo(temp.path());

    // `rm -rf /` blocks with machine/home-folder-modify,
    // machine/outside-workspace-delete, machine/system-files-modify, and
    // persistence/auth-files-modify. The first three are nap-only, so
    // disabling the last alone would not clear the block.
    for (runtime, payload) in guard_blocking_danger(&project) {
        let observed = run_adapter(runtime, Some(temp.path()), payload);
        let feedback = observed.to_string();
        let nap = feedback
            .split("`nah nap ")
            .nth(1)
            .and_then(|rest| rest.split('`').next())
            .unwrap_or_else(|| panic!("{runtime}: {observed}"));
        let mut napped = nap.split(' ').collect::<Vec<_>>();
        napped.sort_unstable();
        assert_eq!(
            napped,
            [
                "machine/home-folder-modify",
                "machine/outside-workspace-delete",
                "machine/system-files-modify",
                "persistence/auth-files-modify"
            ],
            "{runtime}: {observed}"
        );
        assert!(
            !feedback.contains("nah rule disable"),
            "{runtime}: {observed}"
        );
        assert!(!feedback.contains("nah why"), "{runtime}: {observed}");
        assert!(!feedback.contains("rm -rf /"), "{runtime}: {observed}");
    }
}

#[test]
fn every_adapter_delegates_malformed_pre_tool_inputs() {
    let temp = tempfile::tempdir().unwrap();
    let project = repo(temp.path());

    for (runtime, payload) in danger(&project) {
        let cases = [
            ("command", with_ill_typed_command(runtime, payload.clone())),
            ("cwd", with_unavailable_cwd(runtime, payload)),
        ];
        for (field, payload) in cases {
            let observed = run_adapter(runtime, Some(temp.path()), payload);
            let expected = delegated(runtime, false, None);
            assert_eq!(
                observed["code"], expected["code"],
                "{runtime} {field}: {observed}"
            );
            assert_eq!(
                observed["stdout"], expected["stdout"],
                "{runtime} {field}: {observed}"
            );
        }
    }
}

#[test]
fn every_adapter_delegates_every_json_input_shape() {
    let temp = tempfile::tempdir().unwrap();
    let project = repo(temp.path());

    for (runtime, payload) in danger(&project) {
        for input in [
            json!({}),
            json!([]),
            json!("opaque"),
            json!(7),
            json!(true),
            Value::Null,
        ] {
            let observed = run_adapter(
                runtime,
                Some(temp.path()),
                with_tool_input(runtime, payload.clone(), input),
            );
            let expected = delegated(runtime, false, None);
            assert_eq!(observed["code"], expected["code"], "{runtime}: {observed}");
            assert_eq!(
                observed["stdout"], expected["stdout"],
                "{runtime}: {observed}"
            );
        }
    }
}

#[test]
fn decide_delegates_when_context_evaluation_fails() {
    let temp = tempfile::tempdir().unwrap();
    let project = repo(temp.path());
    let mut child = Command::new(env!("CARGO_BIN_EXE_nah"))
        .arg("decide")
        .env_remove("HOME")
        .env_remove("USERPROFILE")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let payload = json!({
        "v":1,
        "tool":"Bash",
        "input":{"command":"rm -rf /"},
        "cwd":project,
    });
    child
        .stdin
        .take()
        .unwrap()
        .write_all(payload.to_string().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();

    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap()["verdict"],
        "delegate"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("context failed"),
        "{output:?}"
    );
}

#[test]
fn decide_rejects_incomplete_normalization_without_original_input() {
    let temp = tempfile::tempdir().unwrap();
    let project = repo(temp.path());
    let mut child = Command::new(env!("CARGO_BIN_EXE_nah"))
        .arg("decide")
        .env("HOME", temp.path())
        .env("USERPROFILE", temp.path())
        .env_remove("XDG_CONFIG_HOME")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let payload = json!({
        "v":1,
        "tool":"Bash",
        "input":{"command":"echo ok"},
        "normalization_complete":false,
        "cwd":project,
    });
    child
        .stdin
        .take()
        .unwrap()
        .write_all(payload.to_string().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();

    assert_eq!(output.status.code(), Some(3), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("invalid input; no decision was produced"),
        "{output:?}"
    );
}

#[test]
fn healthy_decisions_keep_their_verdict_exit_codes_and_body() {
    let temp = tempfile::tempdir().unwrap();
    let project = repo(temp.path());
    let decide = |input: Value, cwd: &std::path::Path| {
        let mut child = Command::new(env!("CARGO_BIN_EXE_nah"))
            .arg("decide")
            .env("HOME", temp.path())
            .env("USERPROFILE", temp.path())
            .env_remove("XDG_CONFIG_HOME")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let payload = json!({"v":1,"tool":"Bash","input":input,"cwd":cwd});
        child
            .stdin
            .take()
            .unwrap()
            .write_all(payload.to_string().as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    };

    let blocked = decide(json!({"command":"rm -rf /"}), &project);
    assert_eq!(blocked.status.code(), Some(1), "{blocked:?}");
    let blocked: Value = serde_json::from_slice(&blocked.stdout).unwrap();
    assert_eq!(blocked["verdict"], "block");

    let delegated = decide(json!({"command":"unknown-tool --flag"}), &project);
    assert_eq!(delegated.status.code(), Some(2), "{delegated:?}");
    let delegated: Value = serde_json::from_slice(&delegated.stdout).unwrap();
    assert_eq!(delegated["verdict"], "delegate");

    // The adapters read the same seam, so a healthy verdict must still survive
    // the exit-code-to-verdict consistency check in the shared adapter.
    let mut child = Command::new(env!("CARGO_BIN_EXE_nah"))
        .args(["hook", "claude", "run"])
        .env("HOME", temp.path())
        .env("USERPROFILE", temp.path())
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
                "tool_name":"Bash",
                "tool_input":{"command":"rm -rf /"},
                "cwd":project,
                "session_id":"session-1"
            })
            .to_string()
            .as_bytes(),
        )
        .unwrap();
    let hooked = child.wait_with_output().unwrap();
    assert!(hooked.status.success(), "{hooked:?}");
    let hooked: Value = serde_json::from_slice(&hooked.stdout).unwrap();
    assert_eq!(
        hooked["hookSpecificOutput"]["permissionDecision"], "deny",
        "{hooked}"
    );
}
