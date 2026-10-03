//! Native Devin PreToolUse adapter over the shared `nah decide` seam.

use std::io::{Read, Write};

use nah_proto::ctx::SchemaVersion;
use nah_proto::decision::Verdict;
use nah_proto::tool::ToolCallInput;
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::adapter_fields::{
    runtime_field_names_covered, tool_input_non_empty_string, tool_input_object, tool_input_string,
};
use crate::hook_adapter::{self, HookOutcome};
use crate::runtime::{FailurePolicy, Runtime};

const INVALID_DEVIN_TOOL_INPUT: &str = "invalid-devin-tool-input";

#[derive(Deserialize)]
struct DevinHookInput {
    hook_event_name: String,
    tool_name: String,
    tool_input: Value,
    #[serde(default)]
    session_id: Option<String>,
}

pub(crate) fn run<R: Read, W: Write, E: Write>(
    stdin: &mut R,
    stdout: &mut W,
    stderr: &mut E,
    project_dir: Option<&str>,
    failure_policy: FailurePolicy,
) -> u8 {
    let request =
        match hook_adapter::read_event::<_, DevinHookInput>(stdin, "hook_event_name", "PreToolUse")
        {
            Ok(Some(input)) => project_dir
                .ok_or_else(|| "devin-project-dir-unavailable".to_owned())
                .and_then(|cwd| normalize(input, cwd)),
            Ok(None) => return 0,
            Err(error) => Err(error.to_string()),
        };
    let decision = match request {
        Ok(request) => hook_adapter::decide_input(request, stderr, Runtime::Devin, failure_policy),
        Err(_) => HookOutcome::MalformedInput,
    };
    match decision {
        HookOutcome::Decision(decision) if decision.verdict() == Verdict::Block => {
            let feedback = hook_adapter::feedback(&decision);
            deny(stdout, &feedback);
            let _ = writeln!(stderr, "nah - {feedback}");
            if decision.guard_block_incomplete() {
                let _ = writeln!(stderr, "{}", hook_adapter::BLOCK_FAILURE_MESSAGE);
            }
            2
        }
        HookOutcome::Decision(decision) => {
            if decision.evaluation_failed() {
                let _ = writeln!(stderr, "{}", hook_adapter::DELEGATED_FAILURE_MESSAGE);
            }
            0
        }
        HookOutcome::IrrelevantEvent => 0,
        HookOutcome::MalformedInput => deny_unavailable(
            stdout,
            stderr,
            failure_policy,
            hook_adapter::IntegrationUnavailable::MalformedInput,
        )
        .unwrap_or(0),
        HookOutcome::EvaluationUnavailable(kind) => {
            deny_unavailable(stdout, stderr, failure_policy, kind).unwrap_or_else(|| {
                let _ = writeln!(stderr, "{}", hook_adapter::DELEGATED_FAILURE_MESSAGE);
                0
            })
        }
    }
}

fn deny_unavailable<W: Write, E: Write>(
    stdout: &mut W,
    stderr: &mut E,
    failure_policy: FailurePolicy,
    unavailable: hook_adapter::IntegrationUnavailable,
) -> Option<u8> {
    hook_adapter::unavailable_feedback(failure_policy, Runtime::Devin, unavailable).map(|reason| {
        deny(stdout, &reason);
        let _ = writeln!(stderr, "nah - {reason}");
        2
    })
}

/// The tool call `run` hands the pipeline for this Devin tool call.
/// `cwd` stands in for the project directory the hook reads from `DEVIN_PROJECT_DIR`.
pub(crate) fn normalize_call(
    tool_name: &str,
    tool_input: Value,
    cwd: &str,
) -> Result<ToolCallInput, String> {
    normalize(
        DevinHookInput {
            hook_event_name: "PreToolUse".into(),
            tool_name: tool_name.into(),
            tool_input,
            session_id: None,
        },
        cwd,
    )
}

fn normalize(input: DevinHookInput, cwd: &str) -> Result<ToolCallInput, String> {
    let original_input = input.tool_input.clone();
    if input.hook_event_name != "PreToolUse" {
        return Err("invalid-devin-hook-event".into());
    }
    let lowered = lower(&input.tool_name, &input.tool_input);
    let (tool, tool_input, normalization_complete) = match lowered {
        Ok((tool, tool_input)) => (
            tool,
            tool_input,
            runtime_field_names_covered("devin", &input.tool_name, &original_input),
        ),
        Err(_) => (input.tool_name.as_str(), original_input.clone(), false),
    };
    ToolCallInput::new(SchemaVersion::V1, tool, tool_input, cwd, input.session_id)
        .map(|input| input.with_original_input(original_input, normalization_complete))
        .map_err(|error| error.to_string())
}

fn lower<'a>(tool_name: &'a str, tool_input: &Value) -> Result<(&'a str, Value), String> {
    Ok(match tool_name {
        "exec" => {
            let object = tool_input_object(tool_input, INVALID_DEVIN_TOOL_INPUT)?;
            (
                "Bash",
                json!({"command": tool_input_string(object, "command", INVALID_DEVIN_TOOL_INPUT)?}),
            )
        }
        "read" => {
            let object = tool_input_object(tool_input, INVALID_DEVIN_TOOL_INPUT)?;
            (
                "Read",
                json!({"file_path": tool_input_non_empty_string(object, "file_path", INVALID_DEVIN_TOOL_INPUT)?}),
            )
        }
        "write" => {
            let object = tool_input_object(tool_input, INVALID_DEVIN_TOOL_INPUT)?;
            (
                "Write",
                json!({
                    "file_path": tool_input_non_empty_string(object, "file_path", INVALID_DEVIN_TOOL_INPUT)?,
                    "content": tool_input_string(object, "content", INVALID_DEVIN_TOOL_INPUT)?
                }),
            )
        }
        "edit" => {
            let object = tool_input_object(tool_input, INVALID_DEVIN_TOOL_INPUT)?;
            let mut normalized = json!({
                "file_path": tool_input_non_empty_string(object, "file_path", INVALID_DEVIN_TOOL_INPUT)?,
                "old_string": tool_input_string(object, "old_string", INVALID_DEVIN_TOOL_INPUT)?,
                "new_string": tool_input_string(object, "new_string", INVALID_DEVIN_TOOL_INPUT)?
            });
            if let Some(replace_all) = object.get("replace_all") {
                if !replace_all.is_boolean() {
                    return Err(INVALID_DEVIN_TOOL_INPUT.into());
                }
                normalized["replace_all"] = replace_all.clone();
            }
            ("Edit", normalized)
        }
        "grep" => {
            let object = tool_input_object(tool_input, INVALID_DEVIN_TOOL_INPUT)?;
            let mut normalized = json!({"pattern": aliased_string(object, "pattern", "query")?});
            if let Some(path) = aliased_optional(object, "path", "file_path")? {
                normalized["path"] = json!(path);
            }
            ("Grep", normalized)
        }
        "glob" => {
            let object = tool_input_object(tool_input, INVALID_DEVIN_TOOL_INPUT)?;
            let mut normalized = json!({"pattern": tool_input_non_empty_string(object, "pattern", INVALID_DEVIN_TOOL_INPUT)?});
            if let Some(path) = aliased_optional(object, "path", "file_path")? {
                normalized["path"] = json!(path);
            }
            ("Glob", normalized)
        }
        _ => (tool_name, tool_input.clone()),
    })
}

fn aliased_string(object: &Map<String, Value>, left: &str, right: &str) -> Result<String, String> {
    match (object.get(left), object.get(right)) {
        (Some(Value::String(left)), Some(Value::String(right)))
            if left == right && !left.is_empty() =>
        {
            Ok(left.clone())
        }
        (Some(Value::String(value)), None) | (None, Some(Value::String(value)))
            if !value.is_empty() =>
        {
            Ok(value.clone())
        }
        _ => Err(INVALID_DEVIN_TOOL_INPUT.into()),
    }
}

fn aliased_optional(
    object: &Map<String, Value>,
    left: &str,
    right: &str,
) -> Result<Option<String>, String> {
    match (object.get(left), object.get(right)) {
        (Some(Value::String(left)), Some(Value::String(right))) if left == right => {
            Ok((!left.is_empty()).then(|| left.clone()))
        }
        (Some(Value::String(value)), None) | (None, Some(Value::String(value))) => {
            Ok((!value.is_empty()).then(|| value.clone()))
        }
        (None, None) => Ok(None),
        _ => Err(INVALID_DEVIN_TOOL_INPUT.into()),
    }
}

fn deny<W: Write>(stdout: &mut W, reason: &str) {
    let _ = serde_json::to_writer(
        &mut *stdout,
        &json!({"decision":"block","reason":format!("nah - {reason}")}),
    );
    let _ = writeln!(stdout);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn normalized(tool_name: &str, tool_input: Value) -> ToolCallInput {
        normalize(
            DevinHookInput {
                hook_event_name: "PreToolUse".into(),
                tool_name: tool_name.into(),
                tool_input,
                session_id: Some("session-1".into()),
            },
            "/repo",
        )
        .unwrap()
    }

    #[test]
    fn normalizes_documented_devin_tools() {
        let cases = [
            (
                "exec",
                json!({"command":"echo ok","shell_id":"main"}),
                "Bash",
                json!({"command":"echo ok"}),
            ),
            (
                "read",
                json!({"file_path":"src/lib.rs","offset":1,"limit":2}),
                "Read",
                json!({"file_path":"src/lib.rs"}),
            ),
            (
                "write",
                json!({"file_path":"src/new.rs","content":"new"}),
                "Write",
                json!({"file_path":"src/new.rs","content":"new"}),
            ),
            (
                "edit",
                json!({"file_path":"src/lib.rs","old_string":"a","new_string":"b"}),
                "Edit",
                json!({"file_path":"src/lib.rs","old_string":"a","new_string":"b"}),
            ),
            (
                "grep",
                json!({"query":"needle","file_path":"src"}),
                "Grep",
                json!({"pattern":"needle","path":"src"}),
            ),
            (
                "glob",
                json!({"pattern":"*.rs","path":"src"}),
                "Glob",
                json!({"pattern":"*.rs","path":"src"}),
            ),
        ];
        for (name, input, expected_name, expected_input) in cases {
            let request = normalized(name, input);
            assert_eq!(request.tool(), expected_name);
            assert_eq!(request.input(), &expected_input);
            assert_eq!(request.cwd(), "/repo");
        }
    }

    #[test]
    fn keeps_unknown_tools_and_conflicting_aliases_opaque() {
        let opaque = normalized("mcp__github__create_issue", json!({"title":"bug"}));
        assert_eq!(opaque.tool(), "mcp__github__create_issue");
        assert_eq!(opaque.input(), &json!({"title":"bug"}));

        let input = json!({"pattern":"one","query":"two"});
        let call = normalize(
            DevinHookInput {
                hook_event_name: "PreToolUse".into(),
                tool_name: "grep".into(),
                tool_input: input.clone(),
                session_id: None,
            },
            "/repo",
        )
        .unwrap();
        assert_eq!(call.tool(), "grep");
        assert_eq!(call.input(), &input);
        assert!(!call.normalization_complete());
    }
}
