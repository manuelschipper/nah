//! Native OpenCode tool adapter over the shared `nah decide` seam.

use std::io::{Read, Write};
use std::path::Path;

use nah_proto::ctx::SchemaVersion;
use nah_proto::decision::Verdict;
use nah_proto::tool::ToolCallInput;
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::{
    adapter_fields::{
        runtime_field_names_covered, tool_input_non_empty_string, tool_input_optional_bool,
        tool_input_string,
    },
    hook_adapter,
    runtime::{FailurePolicy, Runtime},
};

const INVALID_OPENCODE_TOOL_INPUT: &str = "invalid-opencode-tool-input";

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
                hook_adapter::HookOutcome::MalformedInput => {
                    hook_adapter::unavailable_plugin_reply(
                        failure_policy,
                        Runtime::OpenCode,
                        hook_adapter::IntegrationUnavailable::MalformedInput,
                    )
                    .unwrap_or_else(|| hook_adapter::delegated_plugin_reply(false))
                }
                hook_adapter::HookOutcome::EvaluationUnavailable(kind) => {
                    hook_adapter::unavailable_plugin_reply(failure_policy, Runtime::OpenCode, kind)
                }
                .unwrap_or_else(|| hook_adapter::delegated_plugin_reply(true)),
            }
        }
        Err(_) => hook_adapter::unavailable_plugin_reply(
            failure_policy,
            Runtime::OpenCode,
            hook_adapter::IntegrationUnavailable::MalformedInput,
        )
        .unwrap_or_else(|| hook_adapter::delegated_plugin_reply(false)),
    };
    let _ = serde_json::to_writer(&mut *stdout, &output);
    let _ = writeln!(stdout);
    0
}

/// The tool call `run` hands the pipeline for this OpenCode tool call.
pub(crate) fn normalize_call(
    tool_name: &str,
    tool_input: Value,
    cwd: &str,
) -> Result<ToolCallInput, String> {
    normalize(OpenCodeHookInput {
        tool_name: tool_name.into(),
        tool_input,
        cwd: cwd.into(),
        session_id: None,
    })
}

fn normalize(input: OpenCodeHookInput) -> Result<ToolCallInput, String> {
    let original_input = input.tool_input.clone();
    let lowered = input
        .tool_input
        .as_object()
        .ok_or_else(|| INVALID_OPENCODE_TOOL_INPUT.to_owned())
        .and_then(|object| lower_opencode_tool(&input.tool_name, &input.tool_input, object));
    let (tool, tool_input, normalization_complete) = match lowered {
        Ok((tool, tool_input)) => (
            tool,
            tool_input,
            runtime_field_names_covered("opencode", &input.tool_name, &original_input),
        ),
        Err(_) => (input.tool_name.as_str(), original_input.clone(), false),
    };
    // A shell command runs in its workdir, resolved against the session directory.
    let cwd = match (input.tool_name.as_str(), original_input.get("workdir")) {
        ("shell", Some(Value::String(workdir))) if !workdir.is_empty() => Path::new(&input.cwd)
            .join(workdir)
            .to_string_lossy()
            .into_owned(),
        _ => input.cwd,
    };
    ToolCallInput::new(SchemaVersion::V1, tool, tool_input, cwd, input.session_id)
        .map(|input| input.with_original_input(original_input, normalization_complete))
        .map_err(|error| error.to_string())
}

fn lower_opencode_tool<'a>(
    tool_name: &'a str,
    tool_input: &Value,
    object: &Map<String, Value>,
) -> Result<(&'a str, Value), String> {
    Ok(match tool_name {
        "shell" if object.get("workdir").is_none_or(Value::is_string) => (
            "Bash",
            json!({"command": tool_input_string(object, "command", INVALID_OPENCODE_TOOL_INPUT)?}),
        ),
        "shell" => return Err(INVALID_OPENCODE_TOOL_INPUT.into()),
        "read" => (
            "Read",
            json!({"file_path": tool_input_non_empty_string(object, "path", INVALID_OPENCODE_TOOL_INPUT)?}),
        ),
        "write" => (
            "Write",
            json!({
                "file_path": tool_input_non_empty_string(object, "path", INVALID_OPENCODE_TOOL_INPUT)?,
                "content": tool_input_string(object, "content", INVALID_OPENCODE_TOOL_INPUT)?
            }),
        ),
        "edit" => {
            let mut normalized = json!({
                "file_path": tool_input_non_empty_string(object, "path", INVALID_OPENCODE_TOOL_INPUT)?,
                "old_string": tool_input_string(object, "oldString", INVALID_OPENCODE_TOOL_INPUT)?,
                "new_string": tool_input_string(object, "newString", INVALID_OPENCODE_TOOL_INPUT)?
            });
            if let Some(replace_all) =
                tool_input_optional_bool(object, "replaceAll", INVALID_OPENCODE_TOOL_INPUT)?
            {
                normalized["replace_all"] = json!(replace_all);
            }
            ("Edit", normalized)
        }
        "patch" => (
            "apply_patch",
            json!({"command": tool_input_non_empty_string(object, "patchText", INVALID_OPENCODE_TOOL_INPUT)?}),
        ),
        "glob" => ("Glob", search_input(object)?),
        "grep" => ("Grep", search_input(object)?),
        _ => (tool_name, tool_input.clone()),
    })
}

fn search_input(object: &Map<String, Value>) -> Result<Value, String> {
    let mut input =
        json!({"pattern": tool_input_string(object, "pattern", INVALID_OPENCODE_TOOL_INPUT)?});
    match object.get("path") {
        Some(Value::String(path)) if !path.is_empty() => input["path"] = json!(path),
        Some(Value::String(_)) | None => {}
        Some(_) => return Err(INVALID_OPENCODE_TOOL_INPUT.into()),
    }
    Ok(input)
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
        // Argument shapes captured from OpenCode 2.0.18 tool calls.
        let cases = [
            (
                "shell",
                json!({"command":"echo ok","workdir":"/repo"}),
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
                json!({"path":"src/lib.rs","content":""}),
                "Write",
                json!({"file_path":"src/lib.rs","content":""}),
            ),
            (
                "edit",
                json!({
                    "path":"src/lib.rs",
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
                "patch",
                json!({"patchText":"*** Begin Patch\n*** End Patch"}),
                "apply_patch",
                json!({"command":"*** Begin Patch\n*** End Patch"}),
            ),
            (
                "glob",
                json!({"pattern":"src","path":"/repo","hidden":false,"limit":5}),
                "Glob",
                json!({"pattern":"src","path":"/repo"}),
            ),
            (
                "grep",
                json!({
                    "pattern":"needle",
                    "include":"*.rs",
                    "literal":true,
                    "caseSensitive":false,
                    "limit":5
                }),
                "Grep",
                json!({"pattern":"needle"}),
            ),
        ];
        for (name, input, expected_tool, expected_input) in cases {
            let call = normalized(name, input);
            assert_eq!(call.tool(), expected_tool);
            assert_eq!(call.input(), &expected_input);
            assert_eq!(call.session(), Some("session-1"));
            assert!(call.normalization_complete(), "{name}");
        }
    }

    #[test]
    fn hidden_glob_is_incomplete() {
        let call = normalized("glob", json!({"pattern":"*","hidden":true}));
        assert_eq!(call.tool(), "Glob");
        assert!(!call.normalization_complete());
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
            ("shell", json!({"command":7})),
            ("shell", json!({"command":"pwd","workdir":7})),
            ("read", json!({"path":""})),
            ("write", json!({"path":"file"})),
            (
                "edit",
                json!({"path":"file","oldString":"a","newString":"b","replaceAll":"yes"}),
            ),
            ("patch", json!({"patchText":""})),
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
}
