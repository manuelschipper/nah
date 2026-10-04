//! Native Kiro CLI PreToolUse adapter over the shared decision seam.

use std::io::{Read, Write};

use nah_proto::ctx::SchemaVersion;
use nah_proto::decision::Verdict;
use nah_proto::tool::ToolCallInput;
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::adapter_fields::{runtime_field_names_covered, tool_input_non_empty_string};
use crate::hook_adapter::{self, HookOutcome};
use crate::runtime::{FailurePolicy, Runtime};

const INVALID_KIRO_TOOL_INPUT: &str = "invalid-kiro-tool-input";

#[derive(Deserialize)]
struct KiroHookInput {
    hook_event_name: String,
    tool_name: String,
    tool_input: Value,
    cwd: String,
    #[serde(default)]
    session_id: Option<String>,
}

pub(crate) fn run<R: Read, W: Write, E: Write>(
    stdin: &mut R,
    _stdout: &mut W,
    stderr: &mut E,
    failure_policy: FailurePolicy,
) -> u8 {
    let request = read_input(stdin).and_then(|value| {
        if value
            .get("hook_event_name")
            .and_then(Value::as_str)
            .is_some_and(|event| !matches!(event, "PreToolUse" | "preToolUse"))
        {
            return Ok(None);
        }
        serde_json::from_value::<KiroHookInput>(value)
            .map_err(|error| error.to_string())
            .and_then(normalize_kiro_hook_input)
    });
    match request {
        Ok(Some(requests)) => {
            match hook_adapter::decide_each(requests, stderr, Runtime::Kiro, failure_policy) {
                HookOutcome::Decision(decision) if decision.verdict() == Verdict::Block => {
                    let _ = writeln!(stderr, "nah - {}", hook_adapter::feedback(&decision));
                    if decision.guard_block_incomplete() {
                        let _ = writeln!(stderr, "{}", hook_adapter::BLOCK_FAILURE_MESSAGE);
                    }
                    2
                }
                HookOutcome::Decision(decision) => {
                    if decision.evaluation_failed() {
                        let _ = writeln!(stderr, "{}", hook_adapter::DELEGATED_FAILURE_MESSAGE);
                        1
                    } else {
                        0
                    }
                }
                HookOutcome::IrrelevantEvent => 0,
                HookOutcome::MalformedInput => hook_adapter::deny_unavailable_on_stderr(
                    stderr,
                    failure_policy,
                    Runtime::Kiro,
                    hook_adapter::IntegrationUnavailable::MalformedInput,
                )
                .unwrap_or(0),
                HookOutcome::EvaluationUnavailable(kind) => {
                    hook_adapter::deny_unavailable_on_stderr(
                        stderr,
                        failure_policy,
                        Runtime::Kiro,
                        kind,
                    )
                    .unwrap_or_else(|| {
                        let _ = writeln!(stderr, "{}", hook_adapter::DELEGATED_FAILURE_MESSAGE);
                        1
                    })
                }
            }
        }
        Ok(None) => 0,
        Err(_) => hook_adapter::deny_unavailable_on_stderr(
            stderr,
            failure_policy,
            Runtime::Kiro,
            hook_adapter::IntegrationUnavailable::MalformedInput,
        )
        .unwrap_or(0),
    }
}

fn read_input<R: Read>(stdin: &mut R) -> Result<Value, String> {
    let mut bytes = Vec::new();
    stdin
        .read_to_end(&mut bytes)
        .map_err(|_| "kiro-hook-input-read-failed".to_owned())?;
    serde_json::from_slice(&bytes).map_err(|error| error.to_string())
}

/// The tool calls `run` hands the pipeline for this Kiro tool call: one, or
/// one per operation of a filesystem batch.
pub(crate) fn normalize_call(
    tool_name: &str,
    tool_input: Value,
    cwd: &str,
) -> Result<Vec<ToolCallInput>, String> {
    normalize_kiro_hook_input(KiroHookInput {
        hook_event_name: "PreToolUse".into(),
        tool_name: tool_name.into(),
        tool_input,
        cwd: cwd.into(),
        session_id: None,
    })
    .map(|request| request.expect("a PreToolUse event always yields a tool call"))
}

fn normalize_kiro_hook_input(input: KiroHookInput) -> Result<Option<Vec<ToolCallInput>>, String> {
    if !matches!(input.hook_event_name.as_str(), "PreToolUse" | "preToolUse") {
        return Ok(None);
    }
    let original_input = input.tool_input.clone();
    let object = input.tool_input.as_object();
    let lowered = lower_kiro_tool(&input.tool_name, &original_input, object);
    let lowered =
        lowered.unwrap_or_else(|_| vec![(input.tool_name.as_str(), original_input.clone(), false)]);
    lowered
        .into_iter()
        .map(|(tool, tool_input, complete)| {
            ToolCallInput::new(
                SchemaVersion::V1,
                tool,
                tool_input,
                input.cwd.clone(),
                input.session_id.clone(),
            )
            .map(|input| input.with_original_input(original_input.clone(), complete))
            .map_err(|error| error.to_string())
        })
        .collect::<Result<_, _>>()
        .map(Some)
}

/// The calls a Kiro tool call stands for. A filesystem batch performs each of
/// its operations, so each becomes its own call and is judged on its own path.
fn lower_kiro_tool<'a>(
    tool_name: &'a str,
    original_input: &Value,
    object: Option<&Map<String, Value>>,
) -> Result<Vec<(&'a str, Value, bool)>, String> {
    Ok(vec![match tool_name {
        "shell" | "execute_bash" | "execute_cmd" => (
            "Bash",
            json!({"command": tool_input_non_empty_string(required_object(object)?, "command", INVALID_KIRO_TOOL_INPUT)?}),
            runtime_field_names_covered("kiro", tool_name, original_input),
        ),
        "read_file" => {
            let object = required_object(object)?;
            optional_u64(object, "offset")?;
            optional_u64(object, "limit")?;
            ("Read", json!({"file_path":required_path(object)?}), false)
        }
        "read" | "fs_read" | "fsRead" => {
            let (paths, every_operation_named_path) = operation_paths(required_object(object)?)?;
            let complete = every_operation_named_path
                && runtime_field_names_covered("kiro", tool_name, original_input);
            return Ok(paths
                .into_iter()
                .map(|path| ("Read", json!({"file_path":path}), complete))
                .collect());
        }
        "write" | "fs_write" | "fsWrite" => {
            let (paths, every_operation_named_path) = operation_paths(required_object(object)?)?;
            let complete = every_operation_named_path
                && runtime_field_names_covered("kiro", tool_name, original_input);
            return Ok(paths
                .into_iter()
                .map(|path| ("Write", json!({"file_path":path,"content":""}), complete))
                .collect());
        }
        "str_replace" => (
            "Write",
            json!({"file_path":required_path(required_object(object)?)?,"content":""}),
            false,
        ),
        _ => (tool_name, original_input.clone(), true),
    }])
}

fn required_object(object: Option<&Map<String, Value>>) -> Result<&Map<String, Value>, String> {
    object.ok_or_else(|| INVALID_KIRO_TOOL_INPUT.to_owned())
}

/// The path of every operation that names one, or of the call itself when it
/// carries no `operations` list, and whether every operation named one. An
/// operation without a usable path is skipped rather than refusing the call:
/// the paths beside it are still judged. A call that names no path at all is
/// invalid.
fn operation_paths(object: &Map<String, Value>) -> Result<(Vec<String>, bool), String> {
    let Some(operations) = object.get("operations") else {
        return required_path(object).map(|path| (vec![path], true));
    };
    let operations = operations
        .as_array()
        .ok_or_else(|| INVALID_KIRO_TOOL_INPUT.to_owned())?;
    let paths = operations
        .iter()
        .filter_map(|operation| required_path(operation.as_object()?).ok())
        .collect::<Vec<_>>();
    if paths.is_empty() {
        return Err(INVALID_KIRO_TOOL_INPUT.into());
    }
    let every_operation_named_path = paths.len() == operations.len();
    Ok((paths, every_operation_named_path))
}

fn required_path(object: &Map<String, Value>) -> Result<String, String> {
    match object.get("path") {
        Some(Value::String(path)) if !path.is_empty() => Ok(path.clone()),
        Some(Value::String(_)) => Err(INVALID_KIRO_TOOL_INPUT.into()),
        Some(_) => Err(INVALID_KIRO_TOOL_INPUT.into()),
        None => Err(INVALID_KIRO_TOOL_INPUT.into()),
    }
}

fn optional_u64(object: &Map<String, Value>, name: &str) -> Result<(), String> {
    match object.get(name) {
        None | Some(Value::Null) => Ok(()),
        Some(value) if value.as_u64().is_some() => Ok(()),
        Some(_) => Err(INVALID_KIRO_TOOL_INPUT.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn normalized_calls(tool_name: &str, tool_input: Value) -> Vec<ToolCallInput> {
        normalize_kiro_hook_input(KiroHookInput {
            hook_event_name: "PreToolUse".into(),
            tool_name: tool_name.into(),
            tool_input,
            cwd: "/repo".into(),
            session_id: Some("session-1".into()),
        })
        .unwrap()
        .unwrap()
    }

    fn normalized(tool_name: &str, tool_input: Value) -> ToolCallInput {
        let mut calls = normalized_calls(tool_name, tool_input);
        assert_eq!(calls.len(), 1);
        calls.remove(0)
    }

    #[test]
    fn normalizes_documented_shell_and_single_filesystem_operations() {
        let shell = normalized("execute_bash", json!({"command":"echo ok"}));
        assert_eq!(shell.tool(), "Bash");
        assert_eq!(shell.input(), &json!({"command":"echo ok"}));
        assert!(shell.normalization_complete());

        let read = normalized(
            "fs_read",
            json!({"operations":[{"mode":"Line","path":"/repo/src/lib.rs"}]}),
        );
        assert_eq!(read.tool(), "Read");
        assert_eq!(read.input(), &json!({"file_path":"/repo/src/lib.rs"}));
        assert!(read.normalization_complete());

        let read_file = normalized(
            "read_file",
            json!({"path":"/repo/.env","offset":null,"limit":null}),
        );
        assert_eq!(read_file.tool(), "Read");
        assert_eq!(read_file.input(), &json!({"file_path":"/repo/.env"}));
        assert!(!read_file.normalization_complete());

        let write = normalized(
            "fs_write",
            json!({"operations":[{"command":"create","path":"/repo/new.rs","file_text":"x"}]}),
        );
        assert_eq!(write.tool(), "Write");
        assert_eq!(
            write.input(),
            &json!({"file_path":"/repo/new.rs","content":""})
        );
        assert!(write.normalization_complete());
    }

    #[test]
    fn lowers_each_batch_operation_and_preserves_unknown_tools_opaque() {
        let batch = json!({"operations":[{"path":"a"},{"path":"b"}]});
        for (tool, lowered, inputs) in [
            (
                "fs_read",
                "Read",
                [json!({"file_path":"a"}), json!({"file_path":"b"})],
            ),
            (
                "fs_write",
                "Write",
                [
                    json!({"file_path":"a","content":""}),
                    json!({"file_path":"b","content":""}),
                ],
            ),
        ] {
            let calls = normalized_calls(tool, batch.clone());
            assert_eq!(calls.len(), 2, "{tool}");
            for (call, input) in calls.iter().zip(&inputs) {
                assert_eq!(call.tool(), lowered);
                assert_eq!(call.input(), input);
                assert!(call.normalization_complete());
            }

            // An operation without a usable path, or with a field the
            // lowering does not account for, leaves the call incomplete but
            // never hides the paths beside it.
            for unread in [
                json!({"operations":[{"path":"a"},{"path":""},{},{"path":7},{"path":"b"}]}),
                json!({"operations":[{"path":"a","unmodeled":true},{"path":"b"}]}),
            ] {
                let calls = normalized_calls(tool, unread);
                assert_eq!(calls.len(), 2, "{tool}");
                for (call, input) in calls.iter().zip(&inputs) {
                    assert_eq!(call.tool(), lowered);
                    assert_eq!(call.input(), input);
                    assert!(!call.normalization_complete());
                }
            }
        }

        let mcp = json!({"query":"select 1"});
        let call = normalized("@postgres/query", mcp.clone());
        assert_eq!(call.tool(), "@postgres/query");
        assert_eq!(call.input(), &mcp);

        let call = normalized("@postgres/query", Value::Null);
        assert_eq!(call.tool(), "@postgres/query");
        assert_eq!(call.input(), &Value::Null);
    }

    #[test]
    fn accepts_transition_event_case_and_keeps_malformed_tools_opaque() {
        let transition = normalize_kiro_hook_input(KiroHookInput {
            hook_event_name: "preToolUse".into(),
            tool_name: "shell".into(),
            tool_input: json!({"command":"pwd"}),
            cwd: "/repo".into(),
            session_id: None,
        })
        .unwrap();
        assert!(transition.is_some());

        for (tool, input) in [
            ("shell", json!({"command":7})),
            ("read_file", json!({"path":"/repo/.env","offset":"bad"})),
            ("read_file", json!({"path":"/repo/.env","limit":-1})),
            ("fs_read", json!({})),
            ("fs_read", json!({"operations":"bad"})),
            ("fs_read", json!({"operations":[]})),
            ("fs_write", json!({})),
            ("fs_write", json!({"operations":[{}]})),
            ("str_replace", json!({})),
            ("fs_write", json!({"operations":[{"path":7}]})),
            ("str_replace", json!({"path":""})),
        ] {
            let call = normalized(tool, input.clone());
            assert_eq!(call.tool(), tool);
            assert_eq!(call.input(), &input);
            assert!(!call.normalization_complete());
        }
    }

    #[test]
    fn hook_input_has_no_runtime_specific_size_rejection() {
        let value = json!({"payload":"x".repeat(8 * 1024 * 1024)});
        let input = serde_json::to_vec(&value).unwrap();
        assert_eq!(read_input(&mut input.as_slice()), Ok(value));
    }
}
