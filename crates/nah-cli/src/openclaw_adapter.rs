//! Native OpenClaw tool-call adapter over the shared `nah decide` seam.

use std::io::{Read, Write};

use nah_proto::ctx::SchemaVersion;
use nah_proto::decision::Verdict;
use nah_proto::tool::ToolCallInput;
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::hook_adapter::{self, HookOutcome};
use crate::runtime::{FailurePolicy, Runtime};

#[derive(Deserialize)]
struct OpenClawHookInput {
    tool_name: String,
    tool_input: Value,
    cwd: String,
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    tool_kind: Option<String>,
}

pub(crate) fn run<R: Read, W: Write, E: Write>(
    stdin: &mut R,
    stdout: &mut W,
    stderr: &mut E,
    failure_policy: FailurePolicy,
) -> u8 {
    let request = serde_json::from_reader::<_, OpenClawHookInput>(stdin)
        .map_err(|error| error.to_string())
        .and_then(normalize);
    let output = match request {
        Ok(request) => {
            match hook_adapter::decide_input(request, stderr, Runtime::OpenClaw, failure_policy) {
                HookOutcome::Decision(decision) if decision.verdict() == Verdict::Block => {
                    json!({
                        "block":true,
                        "reason":format!("nah - {}", hook_adapter::feedback(&decision)),
                        "evaluation_failed":decision.evaluation_failed()
                    })
                }
                HookOutcome::Decision(decision) => {
                    json!({"block":false,"evaluation_failed":decision.evaluation_failed()})
                }
                HookOutcome::IrrelevantEvent => return 0,
                HookOutcome::MalformedInput => unavailable(
                    failure_policy,
                    hook_adapter::IntegrationUnavailable::MalformedInput,
                )
                .unwrap_or_else(|| delegated(false)),
                HookOutcome::EvaluationUnavailable(kind) => {
                    { unavailable(failure_policy, kind) }.unwrap_or_else(|| delegated(true))
                }
            }
        }
        Err(_) => unavailable(
            failure_policy,
            hook_adapter::IntegrationUnavailable::MalformedInput,
        )
        .unwrap_or_else(|| delegated(false)),
    };
    let _ = serde_json::to_writer(&mut *stdout, &output);
    let _ = writeln!(stdout);
    0
}

fn unavailable(
    failure_policy: FailurePolicy,
    unavailable: hook_adapter::IntegrationUnavailable,
) -> Option<Value> {
    hook_adapter::unavailable_feedback(failure_policy, Runtime::OpenClaw, unavailable).map(
        |reason| json!({"block":true,"reason":format!("nah - {reason}"),"evaluation_failed":true}),
    )
}

fn normalize(input: OpenClawHookInput) -> Result<ToolCallInput, String> {
    let original_input = input.tool_input.clone();
    let lowered = if input.tool_kind.as_deref() == Some("code_mode_exec") {
        Ok(("OpenClawCodeModeExec", input.tool_input.clone()))
    } else {
        input
            .tool_input
            .as_object()
            .ok_or_else(|| "invalid-openclaw-tool-input".to_owned())
            .and_then(|object| lower(&input.tool_name, &input.tool_input, object))
    };
    let (tool, tool_input, normalization_complete) = match lowered {
        Ok((tool, tool_input)) => (
            tool,
            tool_input,
            input.tool_kind.as_deref() == Some("code_mode_exec")
                || crate::adapter_fields::complete("openclaw", &input.tool_name, &original_input),
        ),
        Err(_) => (input.tool_name.as_str(), original_input.clone(), false),
    };
    ToolCallInput::new(
        SchemaVersion::V1,
        tool,
        tool_input,
        input.cwd,
        input.session_id,
    )
    .map(|input| input.with_original_input(original_input, normalization_complete))
    .map_err(|error| error.to_string())
}

fn lower<'a>(
    tool_name: &'a str,
    tool_input: &Value,
    object: &Map<String, Value>,
) -> Result<(&'a str, Value), String> {
    Ok(match tool_name {
        "exec" => ("Bash", json!({"command": string(object, "command")?})),
        "read" => ("Read", json!({"file_path": non_empty(object, "path")?})),
        "write" => (
            "Write",
            json!({
                "file_path":non_empty(object, "path")?,
                "content":string(object, "content")?
            }),
        ),
        "edit" => (
            "Edit",
            json!({"file_path":non_empty(object, "path")?,"edits":edits(object)?}),
        ),
        "apply_patch" => (
            "apply_patch",
            json!({"command":non_empty(object, "input")?}),
        ),
        "grep" => ("Grep", search_input(object)?),
        "find" => ("Find", search_input(object)?),
        "ls" => (
            "Ls",
            json!({"path":optional_non_empty(object, "path")?.unwrap_or_else(|| ".".into())}),
        ),
        "process" => {
            reject_process_input(object)?;
            (tool_name, tool_input.clone())
        }
        _ => (tool_name, tool_input.clone()),
    })
}

fn search_input(object: &Map<String, Value>) -> Result<Value, String> {
    Ok(json!({
        "pattern":string(object, "pattern")?,
        "path":optional_non_empty(object, "path")?.unwrap_or_else(|| ".".into())
    }))
}

fn string(object: &Map<String, Value>, name: &str) -> Result<String, String> {
    object
        .get(name)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| "invalid-openclaw-tool-input".to_owned())
}

fn non_empty(object: &Map<String, Value>, name: &str) -> Result<String, String> {
    string(object, name).and_then(|value| {
        (!value.is_empty())
            .then_some(value)
            .ok_or_else(|| "invalid-openclaw-tool-input".to_owned())
    })
}

fn optional_non_empty(object: &Map<String, Value>, name: &str) -> Result<Option<String>, String> {
    match object.get(name) {
        Some(Value::String(value)) if !value.is_empty() => Ok(Some(value.clone())),
        Some(Value::String(_)) | None => Ok(None),
        Some(_) => Err("invalid-openclaw-tool-input".into()),
    }
}

fn edits(object: &Map<String, Value>) -> Result<Value, String> {
    let edits = object
        .get("edits")
        .and_then(Value::as_array)
        .filter(|edits| !edits.is_empty())
        .ok_or_else(|| "invalid-openclaw-tool-input".to_owned())?;
    edits
        .iter()
        .all(|edit| {
            edit.as_object().is_some_and(|edit| {
                edit.get("oldText").is_some_and(Value::is_string)
                    && edit.get("newText").is_some_and(Value::is_string)
            })
        })
        .then(|| Value::Array(edits.clone()))
        .ok_or_else(|| "invalid-openclaw-tool-input".to_owned())
}

fn reject_process_input(object: &Map<String, Value>) -> Result<(), String> {
    match object.get("action").and_then(Value::as_str) {
        Some("list" | "poll" | "log" | "kill" | "clear" | "remove") => Ok(()),
        Some("write" | "send-keys" | "submit" | "paste") => {
            Err("unsupported-openclaw-process-input".into())
        }
        _ => Err("invalid-openclaw-tool-input".into()),
    }
}

fn delegated(evaluation_failed: bool) -> Value {
    json!({"block":false,"evaluation_failed":evaluation_failed})
}

#[cfg(test)]
mod tests {
    use super::*;

    fn normalized(tool_name: &str, tool_input: Value) -> ToolCallInput {
        normalize(OpenClawHookInput {
            tool_name: tool_name.into(),
            tool_input,
            cwd: "/repo".into(),
            session_id: Some("session-1".into()),
            tool_kind: None,
        })
        .unwrap()
    }

    #[test]
    fn normalizes_verified_openclaw_builtins() {
        for (name, input, expected) in [
            ("exec", json!({"command":"echo ok"}), "Bash"),
            ("read", json!({"path":"src/lib.rs"}), "Read"),
            (
                "write",
                json!({"path":"src/new.rs","content":"new"}),
                "Write",
            ),
            (
                "edit",
                json!({"path":"src/lib.rs","edits":[{"oldText":"a","newText":"b"}]}),
                "Edit",
            ),
            (
                "apply_patch",
                json!({"input":"*** Begin Patch\n*** End Patch"}),
                "apply_patch",
            ),
            ("grep", json!({"pattern":"needle"}), "Grep"),
            ("find", json!({"pattern":"*.rs","path":"src"}), "Find"),
            ("ls", json!({}), "Ls"),
        ] {
            let call = normalized(name, input);
            assert_eq!(call.tool(), expected, "{name}");
            assert_eq!(call.session(), Some("session-1"));
        }
    }

    #[test]
    fn code_mode_exec_and_unknown_tools_stay_opaque() {
        let code = normalize(OpenClawHookInput {
            tool_name: "exec".into(),
            tool_input: json!({"code":"await tools.read({path:'x'})"}),
            cwd: "/repo".into(),
            session_id: None,
            tool_kind: Some("code_mode_exec".into()),
        })
        .unwrap();
        assert_eq!(code.tool(), "OpenClawCodeModeExec");

        let unknown = normalized("process", json!({"action":"poll","sessionId":"p1"}));
        assert_eq!(unknown.tool(), "process");
    }

    #[test]
    fn process_input_actions_stay_opaque() {
        for action in ["write", "send-keys", "submit", "paste"] {
            let input = json!({"action":action,"sessionId":"p1","data":"echo unsafe\n"});
            let call = normalize(OpenClawHookInput {
                tool_name: "process".into(),
                tool_input: input.clone(),
                cwd: "/repo".into(),
                session_id: None,
                tool_kind: None,
            })
            .unwrap();
            assert_eq!(call.tool(), "process");
            assert_eq!(call.input(), &input);
            assert!(!call.normalization_complete());
        }
    }

    #[test]
    fn malformed_known_tools_stay_opaque() {
        for (name, input) in [
            ("exec", json!({"command":7})),
            ("read", json!({"path":""})),
            ("write", json!({"path":"x"})),
            ("edit", json!({"path":"x","edits":[]})),
            ("apply_patch", json!({"input":""})),
            ("grep", json!({"pattern":7})),
            ("find", json!({"pattern":"x","path":7})),
            ("ls", json!({"path":7})),
        ] {
            let call = normalize(OpenClawHookInput {
                tool_name: name.into(),
                tool_input: input.clone(),
                cwd: "/repo".into(),
                session_id: None,
                tool_kind: None,
            })
            .unwrap();
            assert_eq!(call.tool(), name);
            assert_eq!(call.input(), &input);
            assert!(!call.normalization_complete());
        }
    }

    #[test]
    fn native_adapter_stays_thin() {
        let implementation = include_str!("openclaw_adapter.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        assert!(implementation.lines().count() <= 210);
    }
}
