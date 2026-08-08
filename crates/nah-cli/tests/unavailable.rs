#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

mod support;

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::{Value, json};
use support::repo;

/// Runs an adapter with no resolvable home directory, the reachable trigger for
/// "nah cannot build a decision context at all".
fn run_without_home(runtime: &str, project: &std::path::Path, payload: Value) -> Value {
    run_adapter(runtime, None, project, payload, true)
}

fn run_without_home_strict(runtime: &str, project: &std::path::Path, payload: Value) -> Value {
    run_adapter_mode(runtime, None, project, payload, true, true)
}

fn run_adapter(
    runtime: &str,
    home: Option<&std::path::Path>,
    project: &std::path::Path,
    payload: Value,
    devin_project: bool,
) -> Value {
    run_adapter_mode(runtime, home, project, payload, devin_project, false)
}

fn run_adapter_mode(
    runtime: &str,
    home: Option<&std::path::Path>,
    project: &std::path::Path,
    payload: Value,
    devin_project: bool,
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
                .env_remove("HERMES_HOME")
                .env_remove("PRIME_AGENT_CODING_AGENT_DIR");
        }
        None => {
            command.env_remove("HOME").env_remove("USERPROFILE");
        }
    }
    if devin_project {
        command.env("DEVIN_PROJECT_DIR", project);
    } else {
        command.env_remove("DEVIN_PROJECT_DIR");
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
        "copilot" => assert!(
            observed["stdout"]["permissionDecision"] == "deny"
                || observed["stdout"]["hookSpecificOutput"]["permissionDecision"] == "deny",
            "{runtime}: {observed}"
        ),
        "droid" | "kiro" => assert_eq!(observed["code"], 2, "{runtime}: {observed}"),
        "cursor" => {
            assert_eq!(observed["code"], 2, "{runtime}: {observed}");
            assert_eq!(observed["stdout"]["permission"], "deny");
        }
        "devin" => {
            assert_eq!(observed["code"], 2, "{runtime}: {observed}");
            assert_eq!(observed["stdout"]["decision"], "block");
        }
        "amp" | "pi" | "prime-agent" | "opencode" | "openclaw" => {
            assert_eq!(observed["stdout"]["block"], true, "{runtime}: {observed}")
        }
        "cline" => assert_eq!(observed["stdout"]["cancel"], true, "{runtime}: {observed}"),
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

fn configure_missing_guard(home: &std::path::Path) {
    for args in [["guard", "new", "broken"], ["guard", "enable", "broken"]] {
        let output = Command::new(env!("CARGO_BIN_EXE_nah"))
            .args(args)
            .env("HOME", home)
            .env("USERPROFILE", home)
            .env_remove("XDG_CONFIG_HOME")
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
    }
    std::fs::remove_dir_all(home.join(".nah/guards/broken")).unwrap();
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
            "droid",
            json!({
                "hook_event_name":"PreToolUse",
                "tool_name":"Execute",
                "tool_input":{"command":"rm -rf /"},
                "cwd":cwd,
                "session_id":"session-1"
            }),
        ),
        (
            "kiro",
            json!({
                "hook_event_name":"PreToolUse",
                "tool_name":"execute_bash",
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
            "devin",
            json!({
                "hook_event_name":"PreToolUse",
                "tool_name":"exec",
                "tool_input":{"command":"rm -rf /"},
                "session_id":"session-1",
                "prompt_id":"prompt-1"
            }),
        ),
        (
            "amp",
            json!({
                "tool_name":"shell_command",
                "tool_input":{"command":"rm -rf /"},
                "cwd":cwd,
                "session_id":"session-1"
            }),
        ),
        (
            "pi",
            json!({"tool_name":"bash","tool_input":{"command":"rm -rf /"},"cwd":cwd}),
        ),
        (
            "prime-agent",
            json!({
                "tool_name":"ipython",
                "tool_input":{"code":"import shutil; shutil.rmtree('/')"},
                "cwd":cwd,
                "tool_source":"builtin",
                "tool_path":"<builtin:ipython>"
            }),
        ),
        (
            "opencode",
            json!({
                "tool_name":"bash",
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
            "cline",
            json!({
                "taskId":"task-1",
                "hookName":"PreToolUse",
                "workspaceRoots":[cwd],
                "preToolUse":{
                    "toolName":"execute_command",
                    "parameters":{"command":"rm -rf /"}
                }
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
        (
            "copilot",
            json!({
                "hook_event_name":"PreToolUse",
                "session_id":"session-1",
                "timestamp":"2026-07-26T00:00:00Z",
                "cwd":cwd,
                "tool_name":"bash",
                "tool_input":{"command":"rm -rf /"}
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
        "cline" => payload["preToolUse"]["parameters"]["command"] = json!(7),
        "prime-agent" => payload["tool_input"]["code"] = json!(7),
        _ => payload["tool_input"]["command"] = json!(7),
    }
    payload
}

fn with_command(runtime: &str, mut payload: Value, command: &str) -> Value {
    match runtime {
        "antigravity" => payload["toolCall"]["args"]["CommandLine"] = json!(command),
        "cline" => payload["preToolUse"]["parameters"]["command"] = json!(command),
        "prime-agent" => payload["tool_input"]["code"] = json!("prior_callable()"),
        _ => payload["tool_input"]["command"] = json!(command),
    }
    payload
}

fn with_tool_input(runtime: &str, mut payload: Value, input: Value) -> Value {
    match runtime {
        "antigravity" => payload["toolCall"]["args"] = input,
        "cline" => payload["preToolUse"]["parameters"] = input,
        _ => payload["tool_input"] = input,
    }
    payload
}

fn with_unavailable_cwd(runtime: &str, mut payload: Value) -> (Value, bool) {
    match runtime {
        "antigravity" => payload["workspacePaths"] = json!([]),
        "cline" => payload["workspaceRoots"] = json!([]),
        "devin" => return (payload, false),
        _ => payload["cwd"] = json!(7),
    }
    (payload, true)
}

fn with_irrelevant_event(runtime: &str, mut payload: Value) -> Option<Value> {
    match runtime {
        "claude" | "codex" | "droid" | "devin" | "copilot" | "kiro" => {
            payload["hook_event_name"] = json!("PostToolUse")
        }
        "cursor" => payload["hook_event_name"] = json!("postToolUse"),
        "cline" => payload["hookName"] = json!("PostToolUse"),
        "hermes" => payload["hook_event_name"] = json!("post_tool_call"),
        _ => return None,
    }
    Some(payload)
}

fn minimal_irrelevant_event(runtime: &str) -> Option<Value> {
    match runtime {
        "claude" | "codex" | "droid" | "devin" | "copilot" | "kiro" => {
            Some(json!({"hook_event_name":"PostToolUse"}))
        }
        "cursor" => Some(json!({"hook_event_name":"postToolUse"})),
        "cline" => Some(json!({"hookName":"PostToolUse"})),
        "hermes" => Some(json!({"hook_event_name":"post_tool_call"})),
        _ => None,
    }
}

fn delegated(runtime: &str, evaluation_failed: bool) -> Value {
    let native = |code: i64, stdout: Value| json!({"code":code,"stdout":stdout});
    match (runtime, evaluation_failed) {
        ("claude" | "codex" | "copilot", true) => native(
            0,
            json!({"systemMessage":"nah - evaluation failed; this call was delegated to the runtime"}),
        ),
        ("kiro", true) => native(1, Value::Null),
        ("droid" | "cursor" | "devin", true) => native(0, Value::Null),
        ("amp" | "pi" | "prime-agent" | "opencode" | "openclaw", failed) => {
            native(0, json!({"block":false,"evaluation_failed":failed}))
        }
        ("cline", true) => native(
            0,
            json!({
                "cancel":false,
                "contextModification":"nah - evaluation failed; this call was delegated to the runtime"
            }),
        ),
        ("cline", false) => native(0, json!({"cancel":false})),
        ("antigravity", _) => native(0, json!({"decision":"ask"})),
        ("hermes", _) => native(0, json!({})),
        ("claude" | "codex" | "copilot" | "droid" | "kiro" | "cursor" | "devin", false) => {
            native(0, Value::Null)
        }
        _ => unreachable!("{runtime}"),
    }
}

#[test]
fn every_adapter_delegates_when_nah_cannot_decide() {
    let temp = tempfile::tempdir().unwrap();
    let project = repo(temp.path());

    for (runtime, payload) in danger(&project) {
        let observed = run_without_home(runtime, &project, payload);
        let expected = delegated(runtime, true);
        assert_eq!(observed["code"], expected["code"], "{runtime}: {observed}");
        assert_eq!(
            observed["stdout"], expected["stdout"],
            "{runtime}: {observed}"
        );
        match runtime {
            "kiro" | "cursor" | "devin" | "antigravity" | "hermes" => assert!(
                observed["stderr"]
                    .as_str()
                    .unwrap()
                    .contains("evaluation failed"),
                "{runtime}: {observed}"
            ),
            "droid" => assert!(
                observed["stdout_raw"]
                    .as_str()
                    .unwrap()
                    .contains("evaluation failed"),
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
        let observed = run_without_home_strict(runtime, &project, payload);
        assert_native_deny(runtime, &observed);
        let rendered = observed.to_string();
        assert!(
            rendered.contains("ask the operator"),
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
            &project,
            with_command(runtime, payload, "unknown-tool --dynamic"),
            true,
            true,
        );
        let expected = delegated(runtime, false);
        assert_eq!(observed["code"], expected["code"], "{runtime}: {observed}");
        assert_eq!(
            observed["stdout"], expected["stdout"],
            "{runtime}: {observed}"
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
        .filter(|(runtime, _)| matches!(*runtime, "amp" | "droid"))
    {
        let observed = run_adapter_mode(
            runtime,
            Some(temp.path()),
            &project,
            with_command(runtime, payload, &oversized),
            true,
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
                        && failure["component"] == "bash-parser"
                        && failure["code"] == "source-limit"
                })
        );
    }
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
        let delegated = run_adapter_mode(
            runtime,
            Some(temp.path()),
            &project,
            payload.clone(),
            true,
            false,
        );
        assert_eq!(delegated["stdout"], Value::Null, "{runtime}: {delegated}");

        let blocked = run_adapter_mode(runtime, Some(temp.path()), &project, payload, true, true);
        assert_native_deny(runtime, &blocked);

        let opaque = json!({
            "hook_event_name":"PreToolUse",
            "tool_name":"future_tool",
            "tool_input":{"futureBehavior":"execute"},
            "cwd":project,
            "session_id":"session-1"
        });
        let opaque = run_adapter_mode(runtime, Some(temp.path()), &project, opaque, true, true);
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
fn fail_closed_blocks_a_selected_custom_guard_failure_without_caching_a_verdict() {
    let temp = tempfile::tempdir().unwrap();
    let project = repo(temp.path());
    configure_missing_guard(temp.path());
    let (_, payload) = danger(&project)
        .into_iter()
        .find(|(runtime, _)| *runtime == "claude")
        .unwrap();

    for _ in 0..2 {
        let observed = run_adapter_mode(
            "claude",
            Some(temp.path()),
            &project,
            with_command("claude", payload.clone(), "unknown-tool --dynamic"),
            true,
            true,
        );
        assert_native_deny("claude", &observed);
        assert!(observed.to_string().contains("ask the operator"));
    }

    let records = std::fs::read_to_string(temp.path().join(".nah/audit.jsonl")).unwrap();
    assert_eq!(records.lines().count(), 2);
    for line in records.lines() {
        let record: Value = serde_json::from_str(line).unwrap();
        assert_eq!(record["core"]["verdict"], "block");
        assert!(
            record["failures"]
                .as_array()
                .unwrap()
                .iter()
                .any(|failure| {
                    failure["source"] == "nah" || failure["source"] == "custom-guard"
                })
        );
    }
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
            &project,
            json!({"unexpected":raw_secret}),
            false,
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
fn fail_closed_uses_copilot_hybrid_deny_and_denies_missing_devin_project() {
    let temp = tempfile::tempdir().unwrap();
    let project = repo(temp.path());

    let copilot = run_adapter_mode(
        "copilot",
        Some(temp.path()),
        &project,
        json!([]),
        true,
        true,
    );
    assert_eq!(copilot["stdout"]["permissionDecision"], "deny");
    assert_eq!(
        copilot["stdout"]["hookSpecificOutput"]["permissionDecision"],
        "deny"
    );

    let (_, payload) = danger(&project)
        .into_iter()
        .find(|(runtime, _)| *runtime == "devin")
        .unwrap();
    let devin = run_adapter_mode("devin", Some(temp.path()), &project, payload, false, true);
    assert_native_deny("devin", &devin);
    assert!(devin.to_string().contains("ask the operator"));
}

#[test]
fn every_guard_blocking_adapter_keeps_a_positive_block_when_another_guard_failed() {
    let temp = tempfile::tempdir().unwrap();
    let project = repo(temp.path());
    configure_missing_guard(temp.path());

    for (runtime, payload) in guard_blocking_danger(&project) {
        let observed = run_adapter(runtime, Some(temp.path()), &project, payload, true);
        match runtime {
            "claude" | "codex" | "copilot" => {
                assert_eq!(
                    observed["stdout"]["hookSpecificOutput"]["permissionDecision"], "deny",
                    "{runtime}: {observed}"
                );
                assert_eq!(
                    observed["stdout"]["systemMessage"],
                    "nah - evaluation was incomplete; another guard blocked this call",
                    "{runtime}: {observed}"
                );
                if runtime == "copilot" {
                    let context = observed["stdout"]["hookSpecificOutput"]["additionalContext"]
                        .as_str()
                        .unwrap();
                    assert!(
                        context.starts_with(
                            observed["stdout"]["hookSpecificOutput"]["permissionDecisionReason"]
                                .as_str()
                                .unwrap()
                        ),
                        "{runtime}: {observed}"
                    );
                    assert!(
                        context.ends_with(
                            "nah - evaluation was incomplete; another guard blocked this call"
                        ),
                        "{runtime}: {observed}"
                    );
                }
            }
            "droid" | "kiro" => {
                assert_eq!(observed["code"], 2, "{runtime}: {observed}");
                assert!(
                    observed["stderr"]
                        .as_str()
                        .unwrap()
                        .contains("evaluation was incomplete"),
                    "{runtime}: {observed}"
                );
            }
            "cursor" => {
                assert_eq!(observed["code"], 2, "{runtime}: {observed}");
                assert_eq!(observed["stdout"]["permission"], "deny");
                assert!(
                    observed["stderr"]
                        .as_str()
                        .unwrap()
                        .contains("evaluation was incomplete")
                );
            }
            "devin" => {
                assert_eq!(observed["code"], 2, "{runtime}: {observed}");
                assert_eq!(observed["stdout"]["decision"], "block");
                assert!(
                    observed["stderr"]
                        .as_str()
                        .unwrap()
                        .contains("evaluation was incomplete")
                );
            }
            "amp" | "pi" | "prime-agent" | "opencode" | "openclaw" => {
                assert_eq!(observed["stdout"]["block"], true, "{runtime}: {observed}");
                assert_eq!(
                    observed["stdout"]["evaluation_failed"], true,
                    "{runtime}: {observed}"
                );
            }
            "cline" => {
                assert_eq!(observed["stdout"]["cancel"], true, "{runtime}: {observed}");
                let context = observed["stdout"]["contextModification"].as_str().unwrap();
                assert!(
                    context.starts_with(observed["stdout"]["errorMessage"].as_str().unwrap()),
                    "{runtime}: {observed}"
                );
                assert!(
                    context.ends_with(
                        "nah - evaluation was incomplete; another guard blocked this call"
                    ),
                    "{runtime}: {observed}"
                );
            }
            "antigravity" => {
                assert_eq!(observed["stdout"]["decision"], "deny");
                assert!(
                    observed["stderr"]
                        .as_str()
                        .unwrap()
                        .contains("evaluation was incomplete")
                );
            }
            "hermes" => {
                assert_eq!(observed["stdout"]["decision"], "block");
                assert!(
                    observed["stderr"]
                        .as_str()
                        .unwrap()
                        .contains("evaluation was incomplete")
                );
            }
            _ => unreachable!("{runtime}"),
        }
        assert!(!observed.to_string().contains("activated bundle is missing"));
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
                let observed = run_adapter_mode(
                    runtime,
                    Some(temp.path()),
                    &project,
                    payload.clone(),
                    true,
                    fail_closed,
                );
                assert_eq!(observed["code"], 0, "{runtime}: {observed}");
                assert_eq!(observed["stdout"], Value::Null, "{runtime}: {observed}");
                assert_eq!(observed["stderr"], "", "{runtime}: {observed}");
            }
        }
    }
    assert!(!temp.path().join(".nah/audit.jsonl").exists());
}

#[test]
fn every_guard_blocking_adapter_links_its_redacted_decision() {
    let temp = tempfile::tempdir().unwrap();
    let project = repo(temp.path());
    let audit = temp.path().join(".nah/audit.jsonl");

    for (runtime, payload) in guard_blocking_danger(&project) {
        let observed = run_adapter(runtime, Some(temp.path()), &project, payload, true);
        let records = std::fs::read_to_string(&audit).unwrap();
        let record: Value = serde_json::from_str(records.lines().last().unwrap()).unwrap();
        let id = record["envelope"]["id"].as_str().unwrap();
        let feedback = observed.to_string();
        assert!(
            feedback.contains(&format!("if they want details, give them `nah why {id}`")),
            "{runtime}: {observed}"
        );
        assert!(
            !feedback.contains(&format!("id {id}")),
            "{runtime}: {observed}"
        );
        assert!(!feedback.contains("rm -rf /"), "{runtime}: {observed}");
    }
}

#[test]
fn guard_blocking_adapters_never_offer_why_for_an_unrecorded_decision() {
    let temp = tempfile::tempdir().unwrap();
    let project = repo(temp.path());
    let directory = temp.path().join(".nah");
    let audit = directory.join("audit.jsonl");
    std::fs::create_dir_all(&directory).unwrap();
    let held = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&audit)
        .unwrap();
    File::lock(&held).unwrap();

    for (runtime, payload) in guard_blocking_danger(&project) {
        let observed = run_adapter(runtime, Some(temp.path()), &project, payload, true);
        let feedback = observed.to_string();
        assert!(feedback.contains("id decision-"), "{runtime}: {observed}");
        assert!(!feedback.contains("nah why"), "{runtime}: {observed}");
        assert!(!feedback.contains("rm -rf /"), "{runtime}: {observed}");
    }

    assert_eq!(std::fs::metadata(audit).unwrap().len(), 0);
    File::unlock(&held).unwrap();
}

#[test]
fn every_adapter_delegates_malformed_pre_tool_inputs() {
    let temp = tempfile::tempdir().unwrap();
    let project = repo(temp.path());

    for (runtime, payload) in danger(&project) {
        let cases = [
            (
                "command",
                with_ill_typed_command(runtime, payload.clone()),
                true,
            ),
            {
                let (payload, devin_project) = with_unavailable_cwd(runtime, payload);
                ("cwd", payload, devin_project)
            },
        ];
        for (field, payload, devin_project) in cases {
            let observed =
                run_adapter(runtime, Some(temp.path()), &project, payload, devin_project);
            let expected = delegated(runtime, false);
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
                &project,
                with_tool_input(runtime, payload.clone(), input),
                true,
            );
            let expected = delegated(runtime, false);
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
