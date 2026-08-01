//! Native Kiro CLI PreToolUse adapter over the shared decision seam.

use std::io::{Read, Write};

use nah_proto::ctx::SchemaVersion;
use nah_proto::decision::Verdict;
use nah_proto::tool::ToolCallInput;
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::hook_adapter::{self, HookOutcome};
use crate::runtime::Runtime;

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
            .and_then(normalize)
    });
    match request {
        Ok(Some(request)) => match hook_adapter::decide_input(request, stderr, Runtime::Kiro) {
            HookOutcome::Decision(decision) if decision.verdict() == Verdict::Block => {
                let _ = writeln!(stderr, "nah - {}", hook_adapter::feedback(&decision));
                if decision.evaluation_failed() {
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
            HookOutcome::IrrelevantEvent | HookOutcome::MalformedInput => 0,
            HookOutcome::EvaluationUnavailable => {
                let _ = writeln!(stderr, "{}", hook_adapter::DELEGATED_FAILURE_MESSAGE);
                1
            }
        },
        Ok(None) => 0,
        Err(_) => 0,
    }
}

fn read_input<R: Read>(stdin: &mut R) -> Result<Value, String> {
    let mut bytes = Vec::new();
    stdin
        .read_to_end(&mut bytes)
        .map_err(|_| "kiro-hook-input-read-failed".to_owned())?;
    serde_json::from_slice(&bytes).map_err(|error| error.to_string())
}

fn normalize(input: KiroHookInput) -> Result<Option<ToolCallInput>, String> {
    if !matches!(input.hook_event_name.as_str(), "PreToolUse" | "preToolUse") {
        return Ok(None);
    }
    let original_input = input.tool_input.clone();
    let object = input.tool_input.as_object();
    let lowered = lower(&input.tool_name, &original_input, object);
    let (tool, tool_input, complete) =
        lowered.unwrap_or_else(|_| (input.tool_name.as_str(), original_input.clone(), false));
    ToolCallInput::new(
        SchemaVersion::V1,
        tool,
        tool_input,
        input.cwd,
        input.session_id,
    )
    .map(|input| Some(input.with_original_input(original_input, complete)))
    .map_err(|error| error.to_string())
}

fn lower<'a>(
    tool_name: &'a str,
    original_input: &Value,
    object: Option<&Map<String, Value>>,
) -> Result<(&'a str, Value, bool), String> {
    Ok(match tool_name {
        "shell" | "execute_bash" | "execute_cmd" => (
            "Bash",
            json!({"command": non_empty(required_object(object)?, "command")?}),
            crate::adapter_fields::complete("kiro", tool_name, original_input),
        ),
        "read_file" => {
            let object = required_object(object)?;
            optional_u64(object, "offset")?;
            optional_u64(object, "limit")?;
            ("Read", json!({"file_path":required_path(object)?}), false)
        }
        "read" | "fs_read" | "fsRead" => match single_operation_path(required_object(object)?)? {
            Some(path) => ("Read", json!({"file_path":path}), false),
            None => (tool_name, original_input.clone(), true),
        },
        "write" | "fs_write" | "fsWrite" => {
            match single_operation_path(required_object(object)?)? {
                Some(path) => ("Write", json!({"file_path":path,"content":""}), false),
                None => (tool_name, original_input.clone(), true),
            }
        }
        "str_replace" => (
            "Write",
            json!({"file_path":required_path(required_object(object)?)?,"content":""}),
            false,
        ),
        _ => (tool_name, original_input.clone(), true),
    })
}

fn required_object(object: Option<&Map<String, Value>>) -> Result<&Map<String, Value>, String> {
    object.ok_or_else(|| "invalid-kiro-tool-input".to_owned())
}

fn single_operation_path(object: &Map<String, Value>) -> Result<Option<String>, String> {
    let Some(operations) = object.get("operations") else {
        return required_path(object).map(Some);
    };
    let operations = operations
        .as_array()
        .ok_or_else(|| "invalid-kiro-tool-input".to_owned())?;
    match operations.len() {
        0 => return Err("invalid-kiro-tool-input".into()),
        1 => {}
        _ => return Ok(None),
    }
    operations[0]
        .as_object()
        .ok_or_else(|| "invalid-kiro-tool-input".to_owned())
        .and_then(required_path)
        .map(Some)
}

fn required_path(object: &Map<String, Value>) -> Result<String, String> {
    match object.get("path") {
        Some(Value::String(path)) if !path.is_empty() => Ok(path.clone()),
        Some(Value::String(_)) => Err("invalid-kiro-tool-input".into()),
        Some(_) => Err("invalid-kiro-tool-input".into()),
        None => Err("invalid-kiro-tool-input".into()),
    }
}

fn optional_u64(object: &Map<String, Value>, name: &str) -> Result<(), String> {
    match object.get(name) {
        None | Some(Value::Null) => Ok(()),
        Some(value) if value.as_u64().is_some() => Ok(()),
        Some(_) => Err("invalid-kiro-tool-input".into()),
    }
}

fn non_empty(object: &Map<String, Value>, name: &str) -> Result<String, String> {
    object
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| "invalid-kiro-tool-input".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn normalized(tool_name: &str, tool_input: Value) -> ToolCallInput {
        normalize(KiroHookInput {
            hook_event_name: "PreToolUse".into(),
            tool_name: tool_name.into(),
            tool_input,
            cwd: "/repo".into(),
            session_id: Some("session-1".into()),
        })
        .unwrap()
        .unwrap()
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
        assert!(!read.normalization_complete());

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
        assert!(!write.normalization_complete());
    }

    #[test]
    fn preserves_batches_and_unknown_tools_opaque() {
        let batch = json!({"operations":[{"path":"a"},{"path":"b"}]});
        let call = normalized("fs_read", batch.clone());
        assert_eq!(call.tool(), "fs_read");
        assert_eq!(call.input(), &batch);

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
        let transition = normalize(KiroHookInput {
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
            let call = normalize(KiroHookInput {
                hook_event_name: "PreToolUse".into(),
                tool_name: tool.into(),
                tool_input: input.clone(),
                cwd: "/repo".into(),
                session_id: None,
            })
            .unwrap()
            .unwrap();
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
