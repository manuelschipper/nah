//! Native Cursor preToolUse adapter over the shared `nah decide` seam.

use std::io::{Read, Write};

use nah_proto::ctx::{Platform, SchemaVersion};
use nah_proto::decision::Verdict;
use nah_proto::tool::ToolCallInput;
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::adapter_fields::{
    runtime_field_names_covered, tool_input_non_empty_string, tool_input_object,
    tool_input_optional_non_empty_string, tool_input_string,
};
use crate::hook_adapter::{self, HookOutcome};
use crate::live_state;
use crate::runtime::{FailurePolicy, Runtime};

const INVALID_CURSOR_TOOL_INPUT: &str = "invalid-cursor-tool-input";

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
    run_cursor_for_platform(
        stdin,
        stdout,
        stderr,
        live_state::host_platform(),
        failure_policy,
    )
}

fn run_cursor_for_platform<R: Read, W: Write, E: Write>(
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
        Ok(Some(input)) => normalize_cursor_hook_input_for_platform(input, platform),
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
            write_cursor_deny_reply(stdout, &feedback);
            let _ = writeln!(stderr, "nah - {feedback}");
            if decision.guard_block_incomplete() {
                let _ = writeln!(stderr, "{}", hook_adapter::BLOCK_FAILURE_MESSAGE);
            }
            2
        }
        HookOutcome::Decision(decision) => {
            if decision.evaluation_failed() {
                let _ = writeln!(stderr, "{}", decision.delegated_failure_message());
            }
            0
        }
        HookOutcome::IrrelevantEvent => 0,
        HookOutcome::MalformedInput => deny_unavailable_on_cursor_stdout(
            stdout,
            stderr,
            failure_policy,
            hook_adapter::IntegrationUnavailable::MalformedInput,
        )
        .unwrap_or_else(|| {
            // Fail-open lets the call run unchecked; the record keeps it visible in `nah log`.
            hook_adapter::record_unavailable(
                Runtime::Cursor,
                hook_adapter::IntegrationUnavailable::MalformedInput,
            );
            0
        }),
        HookOutcome::EvaluationUnavailable(kind) => {
            deny_unavailable_on_cursor_stdout(stdout, stderr, failure_policy, kind).unwrap_or_else(
                || {
                    let _ = writeln!(stderr, "{}", hook_adapter::DELEGATED_FAILURE_MESSAGE);
                    0
                },
            )
        }
    }
}

fn deny_unavailable_on_cursor_stdout<W: Write, E: Write>(
    stdout: &mut W,
    stderr: &mut E,
    failure_policy: FailurePolicy,
    unavailable: hook_adapter::IntegrationUnavailable,
) -> Option<u8> {
    hook_adapter::unavailable_feedback(failure_policy, Runtime::Cursor, unavailable).map(|reason| {
        write_cursor_deny_reply(stdout, &reason);
        let _ = writeln!(stderr, "nah - {reason}");
        2
    })
}

/// The tool call `run` hands the pipeline for this Cursor tool call.
/// `cwd` is also the one workspace root.
pub(crate) fn normalize_call(
    tool_name: &str,
    tool_input: Value,
    cwd: &str,
) -> Result<ToolCallInput, String> {
    normalize_cursor_hook_input_for_platform(
        CursorHookInput {
            hook_event_name: "preToolUse".into(),
            tool_name: tool_name.into(),
            tool_input,
            cwd: Some(cwd.into()),
            workspace_roots: Some(vec![cwd.into()]),
            conversation_id: None,
        },
        live_state::host_platform(),
    )
}

fn normalize_cursor_hook_input_for_platform(
    input: CursorHookInput,
    platform: Platform,
) -> Result<ToolCallInput, String> {
    let original_input = input.tool_input.clone();
    if input.hook_event_name != "preToolUse" {
        return Err("invalid-cursor-hook-event".into());
    }
    let explicit_shell_cwd = input
        .tool_input
        .as_object()
        .filter(|_| input.tool_name == "Shell")
        .and_then(|object| shell_cwd(object).ok().flatten());
    // Cursor sends an empty `cwd` for a Shell call made without its own
    // directory, so empty means absent here. A Shell call's own directory
    // comes first, so it needs neither a top-level `cwd` nor a workspace root.
    let reported_cwd = input.cwd.as_deref().filter(|cwd| !cwd.is_empty());
    let fallback_cwd = explicit_shell_cwd
        .as_deref()
        .or(reported_cwd)
        .or_else(|| {
            input
                .workspace_roots
                .iter()
                .flatten()
                .map(String::as_str)
                .find(|root| !root.is_empty())
        })
        .ok_or_else(|| "invalid-cursor-hook-input".to_owned())?
        .to_owned();
    // Cursor's shell keeps its directory across calls, so after an earlier
    // `cd` a Shell call with no directory of its own runs wherever that left
    // it, which Cursor does not report. A workspace root is then only a guess:
    // the call is still decided there, but marked as incompletely normalized.
    let shell_location_guessed =
        input.tool_name == "Shell" && reported_cwd.is_none() && explicit_shell_cwd.is_none();
    if platform == Platform::Windows && input.tool_name == "Shell" {
        return ToolCallInput::new(
            SchemaVersion::V1,
            "CursorWindowsShell",
            original_input.clone(),
            fallback_cwd,
            input.conversation_id,
        )
        .map(|input| input.with_original_input(original_input, false))
        .map_err(|error| error.to_string());
    }
    let lowered = lower_cursor_tool(&input.tool_name, &input.tool_input, &fallback_cwd);
    let (tool, tool_input, cwd, normalization_complete) = match lowered {
        Ok((tool, tool_input, cwd)) => (
            tool,
            tool_input,
            cwd,
            runtime_field_names_covered("cursor", &input.tool_name, &original_input)
                && !shell_location_guessed,
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

fn lower_cursor_tool<'a>(
    tool_name: &'a str,
    tool_input: &Value,
    fallback_cwd: &str,
) -> Result<(&'a str, Value, String), String> {
    Ok(match tool_name {
        "Shell" => {
            let object = tool_input_object(tool_input, INVALID_CURSOR_TOOL_INPUT)?;
            let cwd = shell_cwd(object)?.unwrap_or_else(|| fallback_cwd.to_owned());
            (
                "Bash",
                json!({"command": tool_input_string(object, "command", INVALID_CURSOR_TOOL_INPUT)?}),
                cwd,
            )
        }
        "Read" => {
            let object = tool_input_object(tool_input, INVALID_CURSOR_TOOL_INPUT)?;
            (
                "Read",
                json!({"file_path": tool_input_non_empty_string(object, "file_path", INVALID_CURSOR_TOOL_INPUT)?}),
                fallback_cwd.to_owned(),
            )
        }
        "Write" => {
            let object = tool_input_object(tool_input, INVALID_CURSOR_TOOL_INPUT)?;
            (
                "Write",
                json!({
                    "file_path": tool_input_non_empty_string(object, "file_path", INVALID_CURSOR_TOOL_INPUT)?,
                    "content": tool_input_string(object, "content", INVALID_CURSOR_TOOL_INPUT)?
                }),
                fallback_cwd.to_owned(),
            )
        }
        "Delete" => {
            let object = tool_input_object(tool_input, INVALID_CURSOR_TOOL_INPUT)?;
            (
                "Delete",
                json!({"file_path": tool_input_non_empty_string(object, "file_path", INVALID_CURSOR_TOOL_INPUT)?}),
                fallback_cwd.to_owned(),
            )
        }
        "Grep" => {
            let object = tool_input_object(tool_input, INVALID_CURSOR_TOOL_INPUT)?;
            let mut normalized = json!({"pattern": tool_input_string(object, "pattern", INVALID_CURSOR_TOOL_INPUT)?});
            if let Some(path) = tool_input_optional_non_empty_string(
                object,
                "file_path",
                INVALID_CURSOR_TOOL_INPUT,
            )? {
                normalized["path"] = json!(path);
            }
            // Cursor runs its search with ripgrep's `--follow`.
            normalized["follow"] = json!(true);
            // It passes no `--no-ignore`, so ignore files apply.
            normalized["ignore_files"] = json!(true);
            ("Grep", normalized, fallback_cwd.to_owned())
        }
        "List" => {
            let object = tool_input_object(tool_input, INVALID_CURSOR_TOOL_INPUT)?;
            (
                "Ls",
                json!({"path": tool_input_non_empty_string(object, "file_path", INVALID_CURSOR_TOOL_INPUT)?}),
                fallback_cwd.to_owned(),
            )
        }
        _ => (tool_name, tool_input.clone(), fallback_cwd.to_owned()),
    })
}

/// The directory a Shell call names itself, if any.
fn shell_cwd(object: &Map<String, Value>) -> Result<Option<String>, String> {
    let cwd = tool_input_optional_non_empty_string(object, "cwd", INVALID_CURSOR_TOOL_INPUT)?;
    let working_directory = tool_input_optional_non_empty_string(
        object,
        "working_directory",
        INVALID_CURSOR_TOOL_INPUT,
    )?;
    match (cwd, working_directory) {
        (Some(left), Some(right)) if left != right => Err(INVALID_CURSOR_TOOL_INPUT.into()),
        (Some(cwd), _) | (_, Some(cwd)) => Ok(Some(cwd)),
        (None, None) => Ok(None),
    }
}

fn write_cursor_deny_reply<W: Write>(stdout: &mut W, reason: &str) {
    let reason = format!("nah - {reason}");
    hook_adapter::write_hook_reply_line(
        stdout,
        json!({
            "permission": "deny",
            "user_message": reason,
            "agent_message": reason
        }),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn normalized(tool_name: &str, tool_input: Value) -> ToolCallInput {
        normalize_cursor_hook_input_for_platform(
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
                json!({"pattern":"needle","path":"src","follow":true,"ignore_files":true}),
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
            let call = normalize_cursor_hook_input_for_platform(
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
    fn empty_cursor_directories_fall_through_to_the_next_source() {
        let cli_shell = |cwd: &str, inner_cwd: &str, roots: &[&str]| {
            normalize_cursor_hook_input_for_platform(
                CursorHookInput {
                    hook_event_name: "preToolUse".into(),
                    tool_name: "Shell".into(),
                    tool_input: json!({"command":"pwd","cwd":inner_cwd,"timeout":30000}),
                    cwd: Some(cwd.into()),
                    workspace_roots: Some(roots.iter().map(|root| (*root).into()).collect()),
                    conversation_id: None,
                },
                Platform::Linux,
            )
        };

        for roots in [&["/repo"][..], &[""], &[]] {
            let explicit = cli_shell("", "/repo/sub", roots).unwrap();
            assert_eq!(explicit.cwd(), "/repo/sub");
            assert!(explicit.normalization_complete());
        }
        let working_directory = normalize_cursor_hook_input_for_platform(
            CursorHookInput {
                hook_event_name: "preToolUse".into(),
                tool_name: "Shell".into(),
                tool_input: json!({"command":"pwd","working_directory":"/repo/other"}),
                cwd: Some(String::new()),
                workspace_roots: None,
                conversation_id: None,
            },
            Platform::Linux,
        )
        .unwrap();
        assert_eq!(working_directory.cwd(), "/repo/other");
        assert!(working_directory.normalization_complete());

        let reported = cli_shell("/repo/top", "", &["/repo"]).unwrap();
        assert_eq!(reported.cwd(), "/repo/top");
        assert!(reported.normalization_complete());

        let guessed = cli_shell("", "", &["", "/repo"]).unwrap();
        assert_eq!(guessed.cwd(), "/repo");
        assert!(!guessed.normalization_complete());

        assert!(cli_shell("", "", &[""]).is_err());

        let read = normalize_cursor_hook_input_for_platform(
            CursorHookInput {
                hook_event_name: "preToolUse".into(),
                tool_name: "Read".into(),
                tool_input: json!({"file_path":"/repo/src/lib.rs"}),
                cwd: None,
                workspace_roots: Some(vec!["/repo".into()]),
                conversation_id: None,
            },
            Platform::Linux,
        )
        .unwrap();
        assert!(read.normalization_complete());
    }

    #[test]
    fn native_windows_shell_calls_remain_opaque() {
        let original = json!({"command":"Remove-Item -Recurse -Force C:\\","cwd":"C:\\repo"});
        let call = normalize_cursor_hook_input_for_platform(
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
}
