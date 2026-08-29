//! Native Cursor preToolUse adapter over the shared `nah decide` seam.

use std::io::{Read, Write};

use nah_proto::ctx::{Platform, SchemaVersion};
use nah_proto::decision::Verdict;
use nah_proto::tool::ToolCallInput;
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::hook_adapter::{self, HookOutcome};
use crate::live_state;
use crate::runtime::{FailurePolicy, Runtime};

#[derive(Deserialize)]
struct CursorHookInput {
    hook_event_name: String,
    tool_name: String,
    tool_input: Value,
    cwd: Option<String>,
    workspace_roots: Option<Vec<String>>,
    #[serde(default)]
    conversation_id: Option<String>,
}

pub(crate) fn run<R: Read, W: Write, E: Write>(
    stdin: &mut R,
    stdout: &mut W,
    stderr: &mut E,
    failure_policy: FailurePolicy,
) -> u8 {
    run_for_platform(
        stdin,
        stdout,
        stderr,
        live_state::host_platform(),
        failure_policy,
    )
}

fn run_for_platform<R: Read, W: Write, E: Write>(
    stdin: &mut R,
    stdout: &mut W,
    stderr: &mut E,
    platform: Platform,
    failure_policy: FailurePolicy,
) -> u8 {
    let request = match hook_adapter::read_event::<_, CursorHookInput>(
        stdin,
        "hook_event_name",
        "preToolUse",
    ) {
        Ok(Some(input)) => normalize_for_platform(input, platform),
        Ok(None) => return 0,
        Err(error) => Err(error.to_string()),
    };
    let decision = match request {
        Ok(request) => hook_adapter::decide_input(request, stderr, Runtime::Cursor, failure_policy),
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
    hook_adapter::unavailable_feedback(failure_policy, Runtime::Cursor, unavailable).map(|reason| {
        deny(stdout, &reason);
        let _ = writeln!(stderr, "nah - {reason}");
        2
    })
}

fn normalize_for_platform(
    input: CursorHookInput,
    platform: Platform,
) -> Result<ToolCallInput, String> {
    let original_input = input.tool_input.clone();
    if input.hook_event_name != "preToolUse" {
        return Err("invalid-cursor-hook-event".into());
    }
    let root = input.workspace_roots.as_ref().and_then(|r| r.first());
    let cwd = input.cwd.as_deref();
    let fallback_cwd = cwd
        .or(root.map(String::as_str))
        .filter(|cwd| !cwd.is_empty())
        .ok_or_else(|| "invalid-cursor-hook-input".to_owned())?
        .to_owned();
    if platform == Platform::Windows && input.tool_name == "Shell" {
        let cwd = input
            .tool_input
            .as_object()
            .and_then(|object| shell_cwd(object, &fallback_cwd).ok())
            .unwrap_or(fallback_cwd);
        return ToolCallInput::new(
            SchemaVersion::V1,
            "CursorWindowsShell",
            original_input.clone(),
            cwd,
            input.conversation_id,
        )
        .map(|input| input.with_original_input(original_input, false))
        .map_err(|error| error.to_string());
    }
    let lowered = lower(&input.tool_name, &input.tool_input, &fallback_cwd);
    let (tool, tool_input, cwd, normalization_complete) = match lowered {
        Ok((tool, tool_input, cwd)) => (
            tool,
            tool_input,
            cwd,
            crate::adapter_fields::complete("cursor", &input.tool_name, &original_input),
        ),
        Err(_) => (
            input.tool_name.as_str(),
            original_input.clone(),
            fallback_cwd,
            false,
        ),
    };
    ToolCallInput::new(
        SchemaVersion::V1,
        tool,
        tool_input,
        cwd,
        input.conversation_id,
    )
    .map(|input| input.with_original_input(original_input, normalization_complete))
    .map_err(|error| error.to_string())
}

fn lower<'a>(
    tool_name: &'a str,
    tool_input: &Value,
    fallback_cwd: &str,
) -> Result<(&'a str, Value, String), String> {
    Ok(match tool_name {
        "Shell" => {
            let object = object(tool_input)?;
            let cwd = shell_cwd(object, fallback_cwd)?;
            ("Bash", json!({"command": string(object, "command")?}), cwd)
        }
        "Read" => {
            let object = object(tool_input)?;
            (
                "Read",
                json!({"file_path": non_empty(object, "file_path")?}),
                fallback_cwd.to_owned(),
            )
        }
        "Write" => {
            let object = object(tool_input)?;
            (
                "Write",
                json!({
                    "file_path": non_empty(object, "file_path")?,
                    "content": string(object, "content")?
                }),
                fallback_cwd.to_owned(),
            )
        }
        "Delete" => {
            let object = object(tool_input)?;
            (
                "Delete",
                json!({"file_path": non_empty(object, "file_path")?}),
                fallback_cwd.to_owned(),
            )
        }
        "Grep" => {
            let object = object(tool_input)?;
            let mut normalized = json!({"pattern": string(object, "pattern")?});
            if let Some(path) = optional_non_empty(object, "file_path")? {
                normalized["path"] = json!(path);
            }
            ("Grep", normalized, fallback_cwd.to_owned())
        }
        "List" => {
            let object = object(tool_input)?;
            (
                "Ls",
                json!({"path": non_empty(object, "file_path")?}),
                fallback_cwd.to_owned(),
            )
        }
        _ => (tool_name, tool_input.clone(), fallback_cwd.to_owned()),
    })
}

fn shell_cwd(object: &Map<String, Value>, fallback: &str) -> Result<String, String> {
    let cwd = optional_non_empty(object, "cwd")?;
    let working_directory = optional_non_empty(object, "working_directory")?;
    match (cwd, working_directory) {
        (Some(left), Some(right)) if left != right => Err("invalid-cursor-tool-input".into()),
        (Some(cwd), _) | (_, Some(cwd)) => Ok(cwd),
        (None, None) => Ok(fallback.to_owned()),
    }
}

fn object(input: &Value) -> Result<&Map<String, Value>, String> {
    input
        .as_object()
        .ok_or_else(|| "invalid-cursor-tool-input".to_owned())
}

fn string(object: &Map<String, Value>, name: &str) -> Result<String, String> {
    object
        .get(name)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| "invalid-cursor-tool-input".to_owned())
}

fn non_empty(object: &Map<String, Value>, name: &str) -> Result<String, String> {
    string(object, name).and_then(|value| {
        if value.is_empty() {
            Err("invalid-cursor-tool-input".into())
        } else {
            Ok(value)
        }
    })
}

fn optional_non_empty(object: &Map<String, Value>, name: &str) -> Result<Option<String>, String> {
    match object.get(name) {
        Some(Value::String(value)) if !value.is_empty() => Ok(Some(value.clone())),
        Some(Value::String(_)) | None => Ok(None),
        Some(_) => Err("invalid-cursor-tool-input".into()),
    }
}

fn deny<W: Write>(stdout: &mut W, reason: &str) {
    let reason = format!("nah - {reason}");
    let _ = serde_json::to_writer(
        &mut *stdout,
        &json!({
            "permission": "deny",
            "user_message": reason,
            "agent_message": reason
        }),
    );
    let _ = writeln!(stdout);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn normalized(tool_name: &str, tool_input: Value) -> ToolCallInput {
        normalize_for_platform(
            CursorHookInput {
                hook_event_name: "preToolUse".into(),
                tool_name: tool_name.into(),
                tool_input,
                cwd: Some("/repo".into()),
                workspace_roots: None,
                conversation_id: Some("conversation-1".into()),
            },
            Platform::Linux,
        )
        .unwrap()
    }

    #[test]
    fn normalizes_verified_cursor_builtins() {
        let cases = [
            (
                "Read",
                json!({"file_path":"src/lib.rs"}),
                "Read",
                json!({"file_path":"src/lib.rs"}),
                "/repo",
            ),
            (
                "Write",
                json!({"file_path":"src/lib.rs","content":""}),
                "Write",
                json!({"file_path":"src/lib.rs","content":""}),
                "/repo",
            ),
            (
                "Delete",
                json!({"file_path":"src/old.rs"}),
                "Delete",
                json!({"file_path":"src/old.rs"}),
                "/repo",
            ),
            (
                "Grep",
                json!({"pattern":"needle","file_path":"src"}),
                "Grep",
                json!({"pattern":"needle","path":"src"}),
                "/repo",
            ),
            (
                "List",
                json!({"file_path":"src"}),
                "Ls",
                json!({"path":"src"}),
                "/repo",
            ),
            (
                "Shell",
                json!({"command":"echo ok","cwd":"/repo/sub"}),
                "Bash",
                json!({"command":"echo ok"}),
                "/repo/sub",
            ),
            (
                "Shell",
                json!({"command":"echo ok","working_directory":"/repo/other"}),
                "Bash",
                json!({"command":"echo ok"}),
                "/repo/other",
            ),
        ];
        for (name, input, expected_tool, expected_input, expected_cwd) in cases {
            let call = normalized(name, input);
            assert_eq!(call.tool(), expected_tool);
            assert_eq!(call.input(), &expected_input);
            assert_eq!(call.cwd(), expected_cwd);
            assert_eq!(call.session(), Some("conversation-1"));
        }
    }

    #[test]
    fn preserves_unknown_and_malformed_tools_as_opaque_calls() {
        let input = json!({"query":"example"});
        let call = normalized("WebSearch", input.clone());
        assert_eq!(call.tool(), "WebSearch");
        assert_eq!(call.input(), &input);

        for (name, input) in [
            ("Read", json!({"file_path":""})),
            ("Write", json!({"file_path":"file"})),
            ("Delete", json!({"file_path":7})),
            ("Grep", json!({"pattern":"x","file_path":7})),
            ("List", json!({})),
            (
                "Shell",
                json!({"command":"pwd","cwd":"/one","working_directory":"/two"}),
            ),
        ] {
            let call = normalize_for_platform(
                CursorHookInput {
                    hook_event_name: "preToolUse".into(),
                    tool_name: name.into(),
                    tool_input: input.clone(),
                    cwd: Some("/repo".into()),
                    workspace_roots: None,
                    conversation_id: None,
                },
                Platform::Linux,
            )
            .unwrap();
            assert_eq!(call.tool(), name);
            assert_eq!(call.input(), &input);
            assert!(!call.normalization_complete());
        }
    }

    #[test]
    fn native_windows_shell_calls_remain_opaque() {
        let original = json!({"command":"Remove-Item -Recurse -Force C:\\","cwd":"C:\\repo"});
        let call = normalize_for_platform(
            CursorHookInput {
                hook_event_name: "preToolUse".into(),
                tool_name: "Shell".into(),
                tool_input: original.clone(),
                cwd: Some("C:\\workspace".into()),
                workspace_roots: None,
                conversation_id: None,
            },
            Platform::Windows,
        )
        .unwrap();
        assert_eq!(call.tool(), "CursorWindowsShell");
        assert_eq!(call.input(), &original);
        assert_eq!(call.cwd(), "C:\\repo");
        assert!(!call.normalization_complete());
    }

    #[test]
    fn native_adapter_stays_thin() {
        let implementation = include_str!("cursor_adapter.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        assert!(implementation.lines().count() <= 280);
    }
}
