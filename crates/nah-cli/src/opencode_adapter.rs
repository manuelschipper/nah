//! Native OpenCode tool adapter over the shared `nah decide` seam.

use std::io::{Read, Write};

use nah_proto::ctx::SchemaVersion;
use nah_proto::decision::Verdict;
use nah_proto::tool::ToolCallInput;
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::{
    hook_adapter,
    runtime::{FailurePolicy, Runtime},
};

#[derive(Deserialize)]
struct OpenCodeHookInput {
    tool_name: String,
    tool_input: Value,
    cwd: String,
    #[serde(default)]
    session_id: Option<String>,
}

pub(crate) fn run<R: Read, W: Write, E: Write>(
    stdin: &mut R,
    stdout: &mut W,
    stderr: &mut E,
    failure_policy: FailurePolicy,
) -> u8 {
    let request = serde_json::from_reader::<_, OpenCodeHookInput>(stdin)
        .map_err(|error| error.to_string())
        .and_then(normalize);
    let output = match request {
        Ok(request) => {
            match hook_adapter::decide_input(request, stderr, Runtime::OpenCode, failure_policy) {
                hook_adapter::HookOutcome::Decision(decision)
                    if decision.verdict() == Verdict::Block =>
                {
                    json!({
                        "block": true,
                        "reason": format!("nah - {}", hook_adapter::feedback(&decision)),
                        "evaluation_failed": decision.evaluation_failed()
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
    hook_adapter::unavailable_feedback(failure_policy, Runtime::OpenCode, unavailable).map(
        |reason| json!({"block":true,"reason":format!("nah - {reason}"),"evaluation_failed":true}),
    )
}

fn normalize(input: OpenCodeHookInput) -> Result<ToolCallInput, String> {
    let original_input = input.tool_input.clone();
    let lowered = input
        .tool_input
        .as_object()
        .ok_or_else(|| "invalid-opencode-tool-input".to_owned())
        .and_then(|object| lower(&input.tool_name, &input.tool_input, object));
    let (tool, tool_input, normalization_complete) = match lowered {
        Ok((tool, tool_input)) => (
            tool,
            tool_input,
            crate::adapter_fields::complete("opencode", &input.tool_name, &original_input),
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
        "bash" => ("Bash", json!({"command": string(object, "command")?})),
        "read" => ("Read", json!({"file_path": non_empty(object, "filePath")?})),
        "write" => (
            "Write",
            json!({
                "file_path": non_empty(object, "filePath")?,
                "content": string(object, "content")?
            }),
        ),
        "edit" => {
            let mut normalized = json!({
                "file_path": non_empty(object, "filePath")?,
                "old_string": string(object, "oldString")?,
                "new_string": string(object, "newString")?
            });
            if let Some(replace_all) = optional_bool(object, "replaceAll")? {
                normalized["replace_all"] = json!(replace_all);
            }
            ("Edit", normalized)
        }
        "apply_patch" => (
            "apply_patch",
            json!({"command": non_empty(object, "patchText")?}),
        ),
        "glob" => ("Glob", search_input(object)?),
        "grep" => ("Grep", search_input(object)?),
        _ => (tool_name, tool_input.clone()),
    })
}

fn search_input(object: &Map<String, Value>) -> Result<Value, String> {
    let mut input = json!({"pattern": string(object, "pattern")?});
    match object.get("path") {
        Some(Value::String(path)) if !path.is_empty() => input["path"] = json!(path),
        Some(Value::String(_)) | None => {}
        Some(_) => return Err("invalid-opencode-tool-input".into()),
    }
    Ok(input)
}

fn string(object: &Map<String, Value>, name: &str) -> Result<String, String> {
    object
        .get(name)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| "invalid-opencode-tool-input".to_owned())
}

fn non_empty(object: &Map<String, Value>, name: &str) -> Result<String, String> {
    string(object, name).and_then(|value| {
        if value.is_empty() {
            Err("invalid-opencode-tool-input".into())
        } else {
            Ok(value)
        }
    })
}

fn optional_bool(object: &Map<String, Value>, name: &str) -> Result<Option<bool>, String> {
    match object.get(name) {
        Some(Value::Bool(value)) => Ok(Some(*value)),
        None => Ok(None),
        Some(_) => Err("invalid-opencode-tool-input".into()),
    }
}

fn delegated(evaluation_failed: bool) -> Value {
    json!({"block": false, "evaluation_failed":evaluation_failed})
}

#[cfg(test)]
mod tests {
    use super::*;

    fn normalized(tool_name: &str, tool_input: Value) -> ToolCallInput {
        normalize(OpenCodeHookInput {
            tool_name: tool_name.into(),
            tool_input,
            cwd: "/repo".into(),
            session_id: Some("session-1".into()),
        })
        .unwrap()
    }

    #[test]
    fn normalizes_verified_opencode_builtins() {
        let cases = [
            (
                "bash",
                json!({"command":"echo ok","timeout":10,"workdir":"/repo"}),
                "Bash",
                json!({"command":"echo ok"}),
            ),
            (
                "read",
                json!({"filePath":"src/lib.rs","offset":2}),
                "Read",
                json!({"file_path":"src/lib.rs"}),
            ),
            (
                "write",
                json!({"filePath":"src/lib.rs","content":""}),
                "Write",
                json!({"file_path":"src/lib.rs","content":""}),
            ),
            (
                "edit",
                json!({
                    "filePath":"src/lib.rs",
                    "oldString":"old",
                    "newString":"new",
                    "replaceAll":true
                }),
                "Edit",
                json!({
                    "file_path":"src/lib.rs",
                    "old_string":"old",
                    "new_string":"new",
                    "replace_all":true
                }),
            ),
            (
                "apply_patch",
                json!({"patchText":"*** Begin Patch\n*** End Patch"}),
                "apply_patch",
                json!({"command":"*** Begin Patch\n*** End Patch"}),
            ),
            (
                "glob",
                json!({"pattern":"src","path":"/repo"}),
                "Glob",
                json!({"pattern":"src","path":"/repo"}),
            ),
            (
                "grep",
                json!({"pattern":"needle"}),
                "Grep",
                json!({"pattern":"needle"}),
            ),
        ];
        for (name, input, expected_tool, expected_input) in cases {
            let call = normalized(name, input);
            assert_eq!(call.tool(), expected_tool);
            assert_eq!(call.input(), &expected_input);
            assert_eq!(call.session(), Some("session-1"));
        }
    }

    #[test]
    fn preserves_unknown_tool_inputs() {
        let input = json!({"query":"example"});
        let call = normalized("websearch", input.clone());
        assert_eq!(call.tool(), "websearch");
        assert_eq!(call.input(), &input);
    }

    #[test]
    fn preserves_malformed_builtin_inputs_as_opaque_calls() {
        for (name, input) in [
            ("bash", json!({"command":7})),
            ("read", json!({"filePath":""})),
            ("write", json!({"filePath":"file"})),
            (
                "edit",
                json!({"filePath":"file","oldString":"a","newString":"b","replaceAll":"yes"}),
            ),
            ("apply_patch", json!({"patchText":""})),
            ("glob", json!({"pattern":"*","path":7})),
            ("grep", json!({"pattern":7})),
        ] {
            let call = normalize(OpenCodeHookInput {
                tool_name: name.into(),
                tool_input: input.clone(),
                cwd: "/repo".into(),
                session_id: None,
            })
            .unwrap();
            assert_eq!(call.tool(), name);
            assert_eq!(call.input(), &input);
            assert!(!call.normalization_complete());
        }
    }

    #[test]
    fn native_adapter_stays_thin() {
        let implementation = include_str!("opencode_adapter.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        assert!(implementation.lines().count() <= 183);
    }
}
