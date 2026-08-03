//! Native Pi tool-call adapter over the shared `nah decide` seam.

use std::io::{Read, Write};

use nah_proto::ctx::SchemaVersion;
use nah_proto::decision::Verdict;
use nah_proto::tool::ToolCallInput;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    hook_adapter,
    runtime::{FailurePolicy, Runtime},
};

#[derive(Deserialize)]
struct PiHookInput {
    tool_name: String,
    tool_input: Value,
    cwd: String,
}

pub(crate) fn run<R: Read, W: Write, E: Write>(
    stdin: &mut R,
    stdout: &mut W,
    stderr: &mut E,
    failure_policy: FailurePolicy,
) -> u8 {
    let request = serde_json::from_reader::<_, PiHookInput>(stdin)
        .map_err(|error| error.to_string())
        .and_then(normalize);
    let output = match request {
        Ok(request) => {
            match hook_adapter::decide_input(request, stderr, Runtime::Pi, failure_policy) {
                hook_adapter::HookOutcome::Decision(decision)
                    if decision.verdict() == Verdict::Block =>
                {
                    json!({
                        "block": true,
                        "reason": format!("nah - {}", hook_adapter::feedback(&decision)),
                        "evaluation_failed":decision.evaluation_failed()
                    })
                }
                hook_adapter::HookOutcome::Decision(decision) => {
                    json!({"block": false, "evaluation_failed":decision.evaluation_failed()})
                }
                hook_adapter::HookOutcome::IrrelevantEvent => return 0,
                hook_adapter::HookOutcome::MalformedInput => unavailable(
                    failure_policy,
                    hook_adapter::IntegrationUnavailable::MalformedInput,
                )
                .unwrap_or_else(|| delegated(false)),
                hook_adapter::HookOutcome::EvaluationUnavailable(kind) => {
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
    hook_adapter::unavailable_feedback(failure_policy, Runtime::Pi, unavailable).map(
        |reason| json!({"block":true,"reason":format!("nah - {reason}"),"evaluation_failed":true}),
    )
}

fn normalize(input: PiHookInput) -> Result<ToolCallInput, String> {
    let original_input = input.tool_input.clone();
    let lowered = input
        .tool_input
        .as_object()
        .ok_or_else(|| "invalid-pi-tool-input".to_owned())
        .and_then(|object| lower(&input.tool_name, &input.tool_input, object));
    let (tool, tool_input, normalization_complete) = match lowered {
        Ok((tool, tool_input)) => (
            tool,
            tool_input,
            crate::adapter_fields::complete("pi", &input.tool_name, &original_input),
        ),
        Err(_) => (input.tool_name.as_str(), original_input.clone(), false),
    };
    ToolCallInput::new(SchemaVersion::V1, tool, tool_input, input.cwd, None)
        .map(|input| input.with_original_input(original_input, normalization_complete))
        .map_err(|error| error.to_string())
}

fn lower<'a>(
    tool_name: &'a str,
    tool_input: &Value,
    object: &serde_json::Map<String, Value>,
) -> Result<(&'a str, Value), String> {
    let string = |name: &str| {
        object
            .get(name)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .ok_or_else(|| "invalid-pi-tool-input".to_owned())
    };
    let optional_path = || match object.get("path") {
        Some(Value::String(path)) if !path.is_empty() => Ok(path.clone()),
        Some(Value::String(_)) | None => Ok(".".to_owned()),
        Some(_) => Err("invalid-pi-tool-input".to_owned()),
    };
    Ok(match tool_name {
        "bash" => ("Bash", json!({"command": string_value(object, "command")?})),
        "read" => ("Read", json!({"file_path": string("path")?})),
        "write" => (
            "Write",
            json!({"file_path": string("path")?, "content": string_value(object, "content")?}),
        ),
        "edit" => (
            "Edit",
            json!({"file_path": string("path")?, "edits": edits(object)?}),
        ),
        "grep" => (
            "Grep",
            json!({"pattern": string_value(object, "pattern")?, "path": optional_path()?}),
        ),
        "find" => (
            "Find",
            json!({"pattern": string_value(object, "pattern")?, "path": optional_path()?}),
        ),
        "ls" => ("Ls", json!({"path": optional_path()?})),
        _ => (tool_name, tool_input.clone()),
    })
}

fn string_value(object: &serde_json::Map<String, Value>, name: &str) -> Result<String, String> {
    object
        .get(name)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| "invalid-pi-tool-input".to_owned())
}

fn edits(object: &serde_json::Map<String, Value>) -> Result<Value, String> {
    let edits = object
        .get("edits")
        .and_then(Value::as_array)
        .filter(|edits| !edits.is_empty())
        .ok_or_else(|| "invalid-pi-tool-input".to_owned())?;
    if edits.iter().all(|edit| {
        edit.as_object().is_some_and(|edit| {
            edit.get("oldText").is_some_and(Value::is_string)
                && edit.get("newText").is_some_and(Value::is_string)
        })
    }) {
        Ok(Value::Array(edits.clone()))
    } else {
        Err("invalid-pi-tool-input".to_owned())
    }
}

fn delegated(evaluation_failed: bool) -> Value {
    json!({"block": false, "evaluation_failed":evaluation_failed})
}

#[cfg(test)]
mod tests {
    use super::*;

    fn normalized(tool_name: &str, tool_input: Value) -> ToolCallInput {
        normalize(PiHookInput {
            tool_name: tool_name.into(),
            tool_input,
            cwd: "/repo".into(),
        })
        .unwrap()
    }

    #[test]
    fn normalizes_pi_builtins_without_policy_logic() {
        let cases = [
            (
                "bash",
                json!({"command":"echo ok","timeout":10}),
                "Bash",
                json!({"command":"echo ok"}),
            ),
            (
                "read",
                json!({"path":"src/lib.rs","offset":2}),
                "Read",
                json!({"file_path":"src/lib.rs"}),
            ),
            (
                "write",
                json!({"path":"src/lib.rs","content":"x"}),
                "Write",
                json!({"file_path":"src/lib.rs","content":"x"}),
            ),
            (
                "grep",
                json!({"pattern":"needle"}),
                "Grep",
                json!({"pattern":"needle","path":"."}),
            ),
            (
                "find",
                json!({"pattern":"**/*.rs","path":"src"}),
                "Find",
                json!({"pattern":"**/*.rs","path":"src"}),
            ),
            ("ls", json!({}), "Ls", json!({"path":"."})),
        ];
        for (name, input, expected_tool, expected_input) in cases {
            let call = normalized(name, input);
            assert_eq!(call.tool(), expected_tool);
            assert_eq!(call.input(), &expected_input);
        }
    }

    #[test]
    fn preserves_multi_edit_and_unknown_tool_inputs() {
        let edits = json!([
            {"oldText":"old one","newText":"new one"},
            {"oldText":"old two","newText":"new two"}
        ]);
        let edit = normalized("edit", json!({"path":"src/lib.rs","edits":edits}));
        assert_eq!(edit.tool(), "Edit");
        assert_eq!(edit.input()["edits"], edits);

        let unknown = normalized("custom_tool", json!({"argument":7}));
        assert_eq!(unknown.tool(), "custom_tool");
        assert_eq!(unknown.input(), &json!({"argument":7}));
    }

    #[test]
    fn preserves_malformed_builtin_inputs_as_opaque_calls() {
        for (name, input) in [
            ("bash", json!({"command":7})),
            ("read", json!({"path":""})),
            ("write", json!({"path":"file"})),
            ("edit", json!({"path":"file","edits":[]})),
            ("grep", json!({"pattern":"x","path":7})),
            ("find", json!({"pattern":7})),
            ("ls", json!({"path":7})),
        ] {
            let call = normalize(PiHookInput {
                tool_name: name.into(),
                tool_input: input.clone(),
                cwd: "/repo".into(),
            })
            .unwrap();
            assert_eq!(call.tool(), name);
            assert_eq!(call.input(), &input);
            assert!(!call.normalization_complete());
        }
    }

    #[test]
    fn native_adapter_stays_thin() {
        let implementation = include_str!("pi_adapter.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        assert!(implementation.lines().count() <= 171);
    }
}
