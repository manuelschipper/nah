//! Native Hermes pre-tool adapter over the shared `nah decide` seam.

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
struct HermesHookInput {
    hook_event_name: String,
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
    let request = match hook_adapter::read_event::<_, HermesHookInput>(
        stdin,
        "hook_event_name",
        "pre_tool_call",
    ) {
        Ok(Some(input)) => normalize(input),
        Ok(None) => return 0,
        Err(error) => Err(error.to_string()),
    };
    let output = match request {
        Ok(request) => {
            match hook_adapter::decide_input(request, stderr, Runtime::Hermes, failure_policy) {
                hook_adapter::HookOutcome::Decision(decision)
                    if decision.verdict() == Verdict::Block =>
                {
                    if decision.guard_block_incomplete() {
                        let _ = writeln!(stderr, "{}", hook_adapter::BLOCK_FAILURE_MESSAGE);
                    }
                    json!({"decision":"block","reason":format!("nah - {}", hook_adapter::feedback(&decision))})
                }
                hook_adapter::HookOutcome::Decision(decision) => {
                    if decision.evaluation_failed() {
                        let _ = writeln!(stderr, "{}", hook_adapter::DELEGATED_FAILURE_MESSAGE);
                    }
                    json!({})
                }
                hook_adapter::HookOutcome::IrrelevantEvent => return 0,
                hook_adapter::HookOutcome::MalformedInput => unavailable(
                    failure_policy,
                    hook_adapter::IntegrationUnavailable::MalformedInput,
                )
                .unwrap_or_else(|| json!({})),
                hook_adapter::HookOutcome::EvaluationUnavailable(kind) => {
                    { unavailable(failure_policy, kind) }.unwrap_or_else(|| {
                        let _ = writeln!(stderr, "{}", hook_adapter::DELEGATED_FAILURE_MESSAGE);
                        json!({})
                    })
                }
            }
        }
        Err(_) => unavailable(
            failure_policy,
            hook_adapter::IntegrationUnavailable::MalformedInput,
        )
        .unwrap_or_else(|| json!({})),
    };
    let _ = serde_json::to_writer(&mut *stdout, &output);
    let _ = writeln!(stdout);
    0
}

fn unavailable(
    failure_policy: FailurePolicy,
    unavailable: hook_adapter::IntegrationUnavailable,
) -> Option<Value> {
    hook_adapter::unavailable_feedback(failure_policy, Runtime::Hermes, unavailable)
        .map(|reason| json!({"decision":"block","reason":format!("nah - {reason}")}))
}

fn normalize(input: HermesHookInput) -> Result<ToolCallInput, String> {
    let original_input = input.tool_input.clone();
    if input.hook_event_name != "pre_tool_call" {
        return Err("invalid-hermes-hook-event".into());
    }
    let lowered = lower(&input.tool_name, &input.tool_input, input.cwd.as_str());
    let (tool, tool_input, cwd, normalization_complete) = match lowered {
        Ok((tool, tool_input, cwd)) => (
            tool,
            tool_input,
            cwd,
            crate::adapter_fields::complete("hermes", &input.tool_name, &original_input),
        ),
        Err(_) => (
            input.tool_name.as_str(),
            original_input.clone(),
            input.cwd,
            false,
        ),
    };
    ToolCallInput::new(SchemaVersion::V1, tool, tool_input, cwd, input.session_id)
        .map(|input| input.with_original_input(original_input, normalization_complete))
        .map_err(|error| error.to_string())
}

fn lower<'a>(
    tool_name: &'a str,
    tool_input: &Value,
    fallback_cwd: &str,
) -> Result<(&'a str, Value, String), String> {
    let object = tool_input
        .as_object()
        .ok_or_else(|| "invalid-hermes-tool-input".to_owned())?;
    let cwd = if tool_name == "terminal" {
        optional_non_empty(object, "workdir")?.unwrap_or_else(|| fallback_cwd.to_owned())
    } else {
        fallback_cwd.to_owned()
    };
    let (tool, input) = match tool_name {
        "terminal" => ("Bash", json!({"command": string(object, "command")?})),
        "read_file" => ("Read", json!({"file_path": non_empty(object, "path")?})),
        "write_file" => (
            "Write",
            json!({
                "file_path": non_empty(object, "path")?,
                "content": string(object, "content")?
            }),
        ),
        "patch" => patch_input(object)?,
        "search_files" => search_input(object)?,
        _ => (tool_name, tool_input.clone()),
    };
    Ok((tool, input, cwd))
}

fn patch_input(object: &Map<String, Value>) -> Result<(&'static str, Value), String> {
    match object.get("mode").and_then(Value::as_str) {
        Some("replace") => {
            let replace_all = optional_bool(object, "replace_all")?.unwrap_or(false);
            Ok((
                "Edit",
                json!({
                    "file_path":non_empty(object, "path")?,
                    "old_string":string(object, "old_string")?,
                    "new_string":string(object, "new_string")?,
                    "replace_all":replace_all
                }),
            ))
        }
        Some("patch") => Ok((
            "apply_patch",
            json!({"command":non_empty(object, "patch")?}),
        )),
        _ => Err("invalid-hermes-tool-input".into()),
    }
}

fn search_input(object: &Map<String, Value>) -> Result<(&'static str, Value), String> {
    let pattern = string(object, "pattern")?;
    let path = optional_non_empty(object, "path")?.unwrap_or_else(|| ".".into());
    match object
        .get("target")
        .and_then(Value::as_str)
        .unwrap_or("content")
    {
        "content" => Ok(("Grep", json!({"pattern":pattern,"path":path}))),
        "files" if literal_path(&pattern) => Ok(("Glob", json!({"pattern":pattern,"path":path}))),
        "files" => Ok(("HermesSearchFiles", Value::Object(object.clone()))),
        _ => Err("invalid-hermes-tool-input".into()),
    }
}

fn literal_path(path: &str) -> bool {
    !path.is_empty()
        && path.split('/').all(|part| {
            !part.is_empty()
                && !matches!(part, "." | "..")
                && part.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b' ')
                })
        })
}

fn string(object: &Map<String, Value>, name: &str) -> Result<String, String> {
    object
        .get(name)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| "invalid-hermes-tool-input".to_owned())
}

fn non_empty(object: &Map<String, Value>, name: &str) -> Result<String, String> {
    string(object, name).and_then(|value| {
        (!value.is_empty())
            .then_some(value)
            .ok_or_else(|| "invalid-hermes-tool-input".to_owned())
    })
}

fn optional_non_empty(object: &Map<String, Value>, name: &str) -> Result<Option<String>, String> {
    match object.get(name) {
        Some(Value::String(value)) if !value.is_empty() => Ok(Some(value.clone())),
        Some(Value::String(_)) | None => Ok(None),
        Some(_) => Err("invalid-hermes-tool-input".into()),
    }
}

fn optional_bool(object: &Map<String, Value>, name: &str) -> Result<Option<bool>, String> {
    match object.get(name) {
        Some(Value::Bool(value)) => Ok(Some(*value)),
        None => Ok(None),
        Some(_) => Err("invalid-hermes-tool-input".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn normalized(tool_name: &str, tool_input: Value) -> ToolCallInput {
        normalize(HermesHookInput {
            hook_event_name: "pre_tool_call".into(),
            tool_name: tool_name.into(),
            tool_input,
            cwd: "/repo".into(),
            session_id: Some("session-1".into()),
        })
        .unwrap()
    }

    #[test]
    fn normalizes_hermes_filesystem_and_terminal_tools() {
        let cases = [
            (
                "terminal",
                json!({"command":"echo ok","workdir":"/repo"}),
                "Bash",
                json!({"command":"echo ok"}),
            ),
            (
                "read_file",
                json!({"path":"src/lib.rs","offset":1}),
                "Read",
                json!({"file_path":"src/lib.rs"}),
            ),
            (
                "write_file",
                json!({"path":"src/new.rs","content":""}),
                "Write",
                json!({"file_path":"src/new.rs","content":""}),
            ),
            (
                "patch",
                json!({"mode":"replace","path":"src/lib.rs","old_string":"a","new_string":"b"}),
                "Edit",
                json!({"file_path":"src/lib.rs","old_string":"a","new_string":"b","replace_all":false}),
            ),
            (
                "search_files",
                json!({"target":"content","pattern":"needle","path":"src"}),
                "Grep",
                json!({"pattern":"needle","path":"src"}),
            ),
        ];
        for (name, input, expected_tool, expected_input) in cases {
            let call = normalized(name, input);
            assert_eq!(call.tool(), expected_tool);
            assert_eq!(call.input(), &expected_input);
            assert_eq!(call.session(), Some("session-1"));
        }
        assert_eq!(
            normalized(
                "terminal",
                json!({"command":"pwd","workdir":"/sandbox/project"})
            )
            .cwd(),
            "/sandbox/project"
        );
        assert_eq!(
            normalized("read_file", json!({"path":"src/lib.rs"})).cwd(),
            "/repo"
        );
    }

    #[test]
    fn preserves_tools_without_complete_effect_models() {
        for (name, input, expected) in [
            (
                "search_files",
                json!({"target":"files","pattern":"*.rs","path":"src"}),
                "HermesSearchFiles",
            ),
            (
                "execute_code",
                json!({"code":"open('.env').read()"}),
                "execute_code",
            ),
            (
                "browser_navigate",
                json!({"url":"https://example.com"}),
                "browser_navigate",
            ),
        ] {
            assert_eq!(normalized(name, input).tool(), expected);
        }
    }

    #[test]
    fn malformed_known_tools_stay_opaque() {
        for (name, input) in [
            ("terminal", json!({"command":7})),
            ("read_file", json!({"path":""})),
            ("write_file", json!({"path":"x"})),
            ("patch", json!({"mode":"patch","patch":""})),
            ("search_files", json!({"pattern":7})),
        ] {
            let call = normalize(HermesHookInput {
                hook_event_name: "pre_tool_call".into(),
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
