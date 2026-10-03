//! GitHub Copilot CLI and VS Code PreToolUse adapter.

use std::io::{Read, Write};

use nah_proto::ctx::SchemaVersion;
use nah_proto::decision::Verdict;
use nah_proto::tool::ToolCallInput;
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::{
    adapter_fields::{runtime_field_names_covered, tool_input_object},
    code_input::CodeInput,
    hook_adapter, live_state,
    runtime::{FailurePolicy, Runtime},
};

const INVALID_COPILOT_TOOL_INPUT: &str = "invalid-copilot-tool-input";

#[derive(Deserialize)]
#[serde(untagged)]
enum CopilotHookInput {
    Cli {
        #[serde(rename = "sessionId")]
        session_id: String,
        cwd: String,
        #[serde(rename = "toolName")]
        tool_name: String,
        #[serde(rename = "toolArgs")]
        tool_input: Value,
    },
    VsCode {
        hook_event_name: String,
        #[serde(default)]
        session_id: Option<String>,
        cwd: String,
        tool_name: String,
        tool_input: Value,
    },
}

#[derive(Clone, Copy)]
enum Surface {
    Cli,
    VsCode,
    Unknown,
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
    platform: nah_proto::ctx::Platform,
    failure_policy: FailurePolicy,
) -> u8 {
    let parsed = serde_json::from_reader::<_, Value>(stdin);
    if parsed
        .as_ref()
        .ok()
        .is_some_and(|value| hook_adapter::irrelevant_event(value, "hook_event_name", "PreToolUse"))
    {
        return 0;
    }
    let surface = match parsed.as_ref().ok().and_then(Value::as_object) {
        Some(object) if object.contains_key("hook_event_name") => Surface::VsCode,
        Some(_) => Surface::Cli,
        None => Surface::Unknown,
    };
    let request = parsed
        .map_err(|error| error.to_string())
        .and_then(|value| serde_json::from_value(value).map_err(|error| error.to_string()))
        .and_then(|input| normalize(input, platform));
    let (surface, decision) = match request {
        Ok((surface, request, code)) => {
            let decision = hook_adapter::decide_input(
                (request, code.as_ref()),
                stderr,
                Runtime::Copilot,
                failure_policy,
            );
            (surface, decision)
        }
        Err(_) => (surface, hook_adapter::HookOutcome::MalformedInput),
    };
    let output = match decision {
        hook_adapter::HookOutcome::Decision(decision) => match decision.verdict() {
            Verdict::Block => {
                let feedback = hook_adapter::feedback(&decision);
                if decision.guard_block_incomplete() && matches!(surface, Surface::Cli) {
                    emit_progress(stdout, hook_adapter::BLOCK_FAILURE_MESSAGE);
                }
                Some(response(
                    surface,
                    &feedback,
                    decision.guard_block_incomplete(),
                ))
            }
            Verdict::Delegate if decision.evaluation_failed() => match surface {
                Surface::Cli => {
                    emit_progress(stdout, hook_adapter::DELEGATED_FAILURE_MESSAGE);
                    None
                }
                Surface::VsCode => {
                    Some(json!({"systemMessage":hook_adapter::DELEGATED_FAILURE_MESSAGE}))
                }
                Surface::Unknown => None,
            },
            Verdict::Delegate => None,
        },
        hook_adapter::HookOutcome::IrrelevantEvent => return 0,
        hook_adapter::HookOutcome::MalformedInput => hook_adapter::unavailable_feedback(
            failure_policy,
            Runtime::Copilot,
            hook_adapter::IntegrationUnavailable::MalformedInput,
        )
        .map(|reason| response(surface, &reason, false)),
        hook_adapter::HookOutcome::EvaluationUnavailable(kind) => {
            match hook_adapter::unavailable_feedback(failure_policy, Runtime::Copilot, kind) {
                Some(reason) => Some(response(surface, &reason, false)),
                None => match surface {
                    Surface::Cli => {
                        emit_progress(stdout, hook_adapter::DELEGATED_FAILURE_MESSAGE);
                        None
                    }
                    Surface::VsCode => {
                        Some(json!({"systemMessage":hook_adapter::DELEGATED_FAILURE_MESSAGE}))
                    }
                    Surface::Unknown => None,
                },
            }
        }
    };
    if let Some(output) = output {
        let _ = serde_json::to_writer(&mut *stdout, &output);
        let _ = writeln!(stdout);
    }
    0
}

/// The tool call `run` hands the pipeline for this GitHub Copilot tool call.
/// It takes the VS Code payload shape, whose tool input is a JSON object.
pub(crate) fn normalize_call(
    tool_name: &str,
    tool_input: Value,
    cwd: &str,
) -> Result<(ToolCallInput, Option<CodeInput>), String> {
    normalize(
        CopilotHookInput::VsCode {
            hook_event_name: "PreToolUse".into(),
            session_id: None,
            cwd: cwd.into(),
            tool_name: tool_name.into(),
            tool_input,
        },
        live_state::host_platform(),
    )
    .map(|(_, request, code)| (request, code))
}

fn normalize(
    input: CopilotHookInput,
    platform: nah_proto::ctx::Platform,
) -> Result<(Surface, ToolCallInput, Option<CodeInput>), String> {
    let (surface, session, cwd, name, input, input_complete) = match input {
        CopilotHookInput::Cli {
            session_id,
            cwd,
            tool_name,
            tool_input,
        } => {
            let parsed = parse_cli_input(tool_input.clone());
            let complete = parsed.is_ok();
            (
                Surface::Cli,
                Some(session_id),
                cwd,
                tool_name,
                parsed.unwrap_or(tool_input),
                complete,
            )
        }
        CopilotHookInput::VsCode {
            hook_event_name,
            session_id,
            cwd,
            tool_name,
            tool_input,
        } => {
            if hook_event_name != "PreToolUse" {
                return Err("invalid-copilot-vscode-hook-event".into());
            }
            (
                Surface::VsCode,
                session_id,
                cwd,
                tool_name,
                tool_input,
                true,
            )
        }
    };
    let original_input = input.clone();
    if platform == nah_proto::ctx::Platform::Windows
        && matches!(
            name.as_str(),
            "Bash" | "runTerminalCommand" | "run_in_terminal"
        )
    {
        let request = ToolCallInput::new(
            SchemaVersion::V1,
            "CopilotWindowsShell",
            original_input.clone(),
            cwd,
            session,
        )
        .map(|call| call.with_original_input(original_input, false))
        .map_err(|error| error.to_string())?;
        return Ok((surface, request, None));
    }
    let lowered = lower_copilot_tool(&name, input.clone(), cwd.clone(), platform);
    let (tool, input, cwd, code, normalization_complete) = match lowered {
        Ok((tool, input, cwd, code)) => {
            let normalization_complete = input_complete
                && (code.is_some()
                    || runtime_field_names_covered("copilot", &name, &original_input));
            (tool, input, cwd, code, normalization_complete)
        }
        Err(_) => (name.as_str(), original_input.clone(), cwd, None, false),
    };
    ToolCallInput::new(SchemaVersion::V1, tool, input, cwd, session)
        .map(|call| call.with_original_input(original_input, normalization_complete))
        .map(|call| (surface, call, code))
        .map_err(|error| error.to_string())
}

fn parse_cli_input(input: Value) -> Result<Value, String> {
    match input {
        Value::String(value) if value.is_empty() => Ok(Value::Null),
        Value::String(value) => {
            serde_json::from_str(&value).map_err(|_| INVALID_COPILOT_TOOL_INPUT.into())
        }
        value => Ok(value),
    }
}

fn lower_copilot_tool(
    name: &str,
    input: Value,
    fallback_cwd: String,
    platform: nah_proto::ctx::Platform,
) -> Result<(&str, Value, String, Option<CodeInput>), String> {
    let lowered = match name {
        "bash" | "Bash" | "runTerminalCommand" | "run_in_terminal" => {
            let object = tool_input_object(&input, INVALID_COPILOT_TOOL_INPUT)?;
            let cwd = tool_input_optional_aliased_string(object, &["cwd"])?.unwrap_or(fallback_cwd);
            (
                "Bash",
                json!({"command": tool_input_aliased_string(object, &["command"])?}),
                cwd,
                None,
            )
        }
        "powershell" if platform == nah_proto::ctx::Platform::Windows => {
            let object = tool_input_object(&input, INVALID_COPILOT_TOOL_INPUT)?;
            let cwd = tool_input_optional_aliased_string(object, &["cwd"])?.unwrap_or(fallback_cwd);
            let code = CodeInput::PowerShell {
                source: tool_input_aliased_string(object, &["command"])?,
            };
            (name, code.canonical_input(), cwd, Some(code))
        }
        "view" | "Read" | "readFile" | "read_file" => {
            let object = tool_input_object(&input, INVALID_COPILOT_TOOL_INPUT)?;
            (
                "Read",
                json!({"file_path": tool_input_aliased_non_empty_string(object, &["path", "filePath", "file_path"])?}),
                fallback_cwd,
                None,
            )
        }
        "create" | "Write" | "createFile" | "create_file" => {
            let object = tool_input_object(&input, INVALID_COPILOT_TOOL_INPUT)?;
            (
                "Write",
                json!({
                    "file_path":tool_input_aliased_non_empty_string(object, &["path", "filePath", "file_path"])?,
                    "content":tool_input_aliased_string(object, &["file_text", "content"])?
                }),
                fallback_cwd,
                None,
            )
        }
        "edit" | "str_replace_editor" | "replaceString" | "replace_string_in_file" => {
            let object = tool_input_object(&input, INVALID_COPILOT_TOOL_INPUT)?;
            (
                "Edit",
                json!({
                    "file_path":tool_input_aliased_non_empty_string(object, &["path", "filePath", "file_path"])?,
                    "old_string":tool_input_aliased_non_empty_string(object, &["old_str", "oldString", "old_string"])?,
                    "new_string":tool_input_aliased_string(object, &["new_str", "newString", "new_string"])?
                }),
                fallback_cwd,
                None,
            )
        }
        "grep" | "rg" | "Grep" | "grepSearch" | "grep_search" => {
            let object = tool_input_object(&input, INVALID_COPILOT_TOOL_INPUT)?;
            let mut lowered =
                json!({"pattern":tool_input_aliased_string(object, &["pattern", "query"])?});
            if let Some(path) =
                tool_input_optional_aliased_string(object, &["path", "filePath", "file_path"])?
            {
                lowered["path"] = json!(path);
            }
            ("Grep", lowered, fallback_cwd, None)
        }
        "glob" | "Glob" | "fileSearch" | "file_search" => {
            let object = tool_input_object(&input, INVALID_COPILOT_TOOL_INPUT)?;
            (
                "Glob",
                json!({"pattern":tool_input_aliased_string(object, &["pattern", "query"])?}),
                fallback_cwd,
                None,
            )
        }
        _ => (name, input, fallback_cwd, None),
    };
    Ok(lowered)
}

/// Reads a required string tool input field that Copilot spells under several
/// alias names. Only the first alias present is read; it may be empty.
fn tool_input_aliased_string(
    object: &Map<String, Value>,
    names: &[&str],
) -> Result<String, String> {
    names
        .iter()
        .find_map(|name| object.get(*name))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| INVALID_COPILOT_TOOL_INPUT.into())
}

/// Reads a required aliased tool input field that must be a non-empty string.
fn tool_input_aliased_non_empty_string(
    object: &Map<String, Value>,
    names: &[&str],
) -> Result<String, String> {
    tool_input_aliased_string(object, names).and_then(|value| {
        if value.is_empty() {
            Err(INVALID_COPILOT_TOOL_INPUT.into())
        } else {
            Ok(value)
        }
    })
}

/// Reads an optional aliased tool input field. No alias present is `None`; the
/// first alias present must be a non-empty string.
fn tool_input_optional_aliased_string(
    object: &Map<String, Value>,
    names: &[&str],
) -> Result<Option<String>, String> {
    let Some(value) = names.iter().find_map(|name| object.get(*name)) else {
        return Ok(None);
    };
    match value {
        Value::String(value) if !value.is_empty() => Ok(Some(value.clone())),
        _ => Err(INVALID_COPILOT_TOOL_INPUT.into()),
    }
}

fn emit_progress<W: Write>(stdout: &mut W, message: &str) {
    let _ = serde_json::to_writer(&mut *stdout, &json!({"type":"progress","message":message}));
    let _ = writeln!(stdout);
}

fn response(surface: Surface, reason: &str, incomplete: bool) -> Value {
    let reason = format!("nah - {reason}");
    let context = if incomplete {
        format!("{reason}; {}", hook_adapter::BLOCK_FAILURE_MESSAGE)
    } else {
        reason.clone()
    };
    match surface {
        Surface::Cli => {
            json!({"permissionDecision":"deny","permissionDecisionReason":reason})
        }
        Surface::VsCode => {
            let mut result = json!({
                "hookSpecificOutput":{
                    "hookEventName":"PreToolUse",
                    "permissionDecision":"deny",
                    "permissionDecisionReason":reason,
                    "additionalContext":context
                }
            });
            if incomplete {
                result["systemMessage"] = json!(hook_adapter::BLOCK_FAILURE_MESSAGE);
            }
            result
        }
        Surface::Unknown => {
            json!({
                "permissionDecision":"deny",
                "permissionDecisionReason":reason,
                "hookSpecificOutput":{
                    "hookEventName":"PreToolUse",
                    "permissionDecision":"deny",
                    "permissionDecisionReason":reason,
                    "additionalContext":context
                }
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lowers_cli_and_vscode_tools() {
        let cases = [
            ("bash", json!({"command":"pwd"}), "Bash"),
            ("view", json!({"path":"src/lib.rs"}), "Read"),
            (
                "create_file",
                json!({"filePath":"src/new.rs","content":""}),
                "Write",
            ),
            (
                "replace_string_in_file",
                json!({"filePath":"src/lib.rs","oldString":"old","newString":"new"}),
                "Edit",
            ),
            (
                "grep_search",
                json!({"query":"needle","path":"src"}),
                "Grep",
            ),
            ("file_search", json!({"query":"**/*.rs"}), "Glob"),
        ];
        for (name, input, expected) in cases {
            let (tool, _, _, _) =
                lower_copilot_tool(name, input, "/repo".into(), nah_proto::ctx::Platform::Linux)
                    .unwrap();
            assert_eq!(tool, expected);
        }
    }

    #[test]
    fn preserves_unknown_tools() {
        let input = json!({"query":"example"});
        let (tool, lowered, _, _) = lower_copilot_tool(
            "web_fetch",
            input.clone(),
            "/repo".into(),
            nah_proto::ctx::Platform::Linux,
        )
        .unwrap();
        assert_eq!(tool, "web_fetch");
        assert_eq!(lowered, input);
    }

    #[test]
    fn unknown_protocol_blocks_emit_both_decision_shapes() {
        let output = response(Surface::Unknown, "blocked", false);
        assert_eq!(output["permissionDecision"], "deny");
        assert_eq!(output["hookSpecificOutput"]["permissionDecision"], "deny");
        assert_eq!(
            output["hookSpecificOutput"]["permissionDecisionReason"],
            "nah - blocked"
        );
        assert_eq!(
            output["hookSpecificOutput"]["additionalContext"],
            "nah - blocked"
        );
    }

    #[test]
    fn windows_shell_routing_uses_only_proven_dialects() {
        let cli = |tool: &str| CopilotHookInput::Cli {
            session_id: "session-1".into(),
            cwd: "C:\\repo".into(),
            tool_name: tool.into(),
            tool_input: json!({"command":"echo ok"}),
        };

        let (_, bash, code) = normalize(cli("bash"), nah_proto::ctx::Platform::Windows).unwrap();
        assert_eq!(bash.tool(), "Bash");
        assert!(code.is_none());

        let (_, powershell, code) =
            normalize(cli("powershell"), nah_proto::ctx::Platform::Windows).unwrap();
        assert_eq!(powershell.tool(), "powershell");
        assert!(powershell.normalization_complete());
        assert!(matches!(code, Some(CodeInput::PowerShell { .. })));

        let (_, powershell, code) =
            normalize(cli("powershell"), nah_proto::ctx::Platform::Linux).unwrap();
        assert_eq!(powershell.tool(), "powershell");
        assert!(code.is_none());

        for tool in ["Bash", "runTerminalCommand", "run_in_terminal"] {
            let (_, call, code) = normalize(cli(tool), nah_proto::ctx::Platform::Windows).unwrap();
            assert_eq!(call.tool(), "CopilotWindowsShell", "{tool}");
            assert!(!call.normalization_complete(), "{tool}");
            assert!(code.is_none(), "{tool}");
        }
    }
}
