//! Native Hermes pre-tool adapter over the shared `nah decide` seam, and its
//! `post_tool_call` event: save-then-run's refresh and session memory's
//! account of how the call ended.

use std::io::{Read, Write};

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
    code_input::{CodeInput, CodeIntake},
    hook_adapter,
    runtime::{FailurePolicy, Runtime},
    session_memory,
};

const INVALID_HERMES_TOOL_INPUT: &str = "invalid-hermes-tool-input";

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
    let request = match serde_json::from_reader::<_, Value>(stdin) {
        Ok(event) if event["hook_event_name"] == "post_tool_call" => {
            post_call(event);
            return 0;
        }
        Ok(event) if hook_adapter::irrelevant_event(&event, "hook_event_name", "pre_tool_call") => {
            return 0;
        }
        Ok(event) => {
            if let Some(call) = call_id(&event) {
                session_memory::set_call(call, None);
            }
            serde_json::from_value(keyed_by_conversation(event))
                .map_err(|error| error.to_string())
                .and_then(normalize_hermes_hook_input)
        }
        Err(error) => Err(error.to_string()),
    };
    let output = match request {
        Ok((request, code)) => {
            match hook_adapter::decide_input(
                (request, code.as_ref()),
                stderr,
                Runtime::Hermes,
                failure_policy,
            ) {
                hook_adapter::HookOutcome::Decision(decision)
                    if decision.verdict() == Verdict::Block =>
                {
                    if decision.guard_block_incomplete() {
                        let _ = writeln!(stderr, "{}", hook_adapter::BLOCK_FAILURE_MESSAGE);
                    }
                    let unfinished = hook_adapter::once_report(&decision);
                    let reason = hook_adapter::block_reason(&decision, unfinished.as_deref());
                    json!({"decision":"block","reason":reason})
                }
                hook_adapter::HookOutcome::Decision(decision) => {
                    if decision.evaluation_failed() {
                        let _ = writeln!(stderr, "{}", decision.delegated_failure_message());
                    }
                    // A shell hook has no channel to the model on an allowed
                    // call, so the notes reach only Hermes's log.
                    if let Some(notes) = hook_adapter::delegate_note(
                        &decision,
                        hook_adapter::once_report(&decision).as_deref(),
                    ) {
                        let _ = writeln!(stderr, "{notes}");
                    }
                    json!({})
                }
                hook_adapter::HookOutcome::IrrelevantEvent => return 0,
                hook_adapter::HookOutcome::MalformedInput => hermes_unavailable_reply(
                    failure_policy,
                    hook_adapter::IntegrationUnavailable::MalformedInput,
                )
                .unwrap_or_else(|| json!({})),
                hook_adapter::HookOutcome::EvaluationUnavailable(kind) => {
                    { hermes_unavailable_reply(failure_policy, kind) }.unwrap_or_else(|| {
                        let _ = writeln!(stderr, "{}", hook_adapter::DELEGATED_FAILURE_MESSAGE);
                        json!({})
                    })
                }
            }
        }
        Err(_) => hermes_unavailable_reply(
            failure_policy,
            hook_adapter::IntegrationUnavailable::MalformedInput,
        )
        .unwrap_or_else(|| json!({})),
    };
    hook_adapter::write_hook_reply_line(stdout, output);
    0
}

/// Reports a finished call: Hermes emits `post_tool_call` after every
/// dispatch, with `extra.status` `ok`, or `error` or `blocked` for a call
/// that failed or never ran.
fn post_call(mut event: Value) {
    let failed = event["extra"]["status"] != "ok";
    let call = call_id(&event)
        .filter(|_| event["tool_name"] != "terminal" || command_ended(&event["extra"]["result"]))
        .map(str::to_owned);
    // Normalized as the call its pre-call hook decided.
    event["hook_event_name"] = json!("pre_tool_call");
    let Ok((request, _)) = serde_json::from_value(keyed_by_conversation(event))
        .map_err(|error| error.to_string())
        .and_then(normalize_hermes_hook_input)
    else {
        return;
    };
    let finished = hook_adapter::finished_call(&request, failed, call.as_deref());
    hook_adapter::post_call_detached(&finished, Runtime::Hermes);
}

/// Whether a `terminal` call's `result` says its command ended. Hermes
/// returns a background command, or one it moved to the background while
/// it ran, with the `session_id` of its tracked process before it ends; a
/// foreground result has none. A call whose command may still run settles
/// nothing, so what it proposed keeps counting as run.
fn command_ended(result: &Value) -> bool {
    result
        .as_str()
        .and_then(|result| serde_json::from_str::<Value>(result).ok())
        .is_some_and(|result| result.is_object() && result.get("session_id").is_none())
}

/// The call's `tool_call_id`, which Hermes puts under `extra`.
fn call_id(event: &Value) -> Option<&str> {
    event["extra"]["tool_call_id"]
        .as_str()
        .filter(|call| !call.is_empty())
}

/// `event` with its session id replaced by `extra.conversation_id` where it
/// has one: Hermes rotates `session_id` when it compresses a conversation,
/// while the conversation id stays, and a delegated subagent shares it.
fn keyed_by_conversation(mut event: Value) -> Value {
    if let Some(conversation) = event["extra"]["conversation_id"]
        .as_str()
        .filter(|conversation| !conversation.is_empty())
    {
        event["session_id"] = json!(conversation);
    }
    event
}

fn hermes_unavailable_reply(
    failure_policy: FailurePolicy,
    unavailable: hook_adapter::IntegrationUnavailable,
) -> Option<Value> {
    hook_adapter::unavailable_feedback(failure_policy, Runtime::Hermes, unavailable)
        .map(|reason| json!({"decision":"block","reason":reason}))
}

/// The tool call `run` hands the pipeline for this Hermes tool call.
pub(crate) fn normalize_call(
    tool_name: &str,
    tool_input: Value,
    cwd: &str,
) -> Result<(ToolCallInput, Option<CodeInput>), String> {
    normalize_hermes_hook_input(HermesHookInput {
        hook_event_name: "pre_tool_call".into(),
        tool_name: tool_name.into(),
        tool_input,
        cwd: cwd.into(),
        session_id: None,
    })
}

fn normalize_hermes_hook_input(
    input: HermesHookInput,
) -> Result<(ToolCallInput, Option<CodeInput>), String> {
    let original_input = input.tool_input.clone();
    if input.hook_event_name != "pre_tool_call" {
        return Err("invalid-hermes-hook-event".into());
    }
    let (lowered, code) = match crate::code_input::hermes(&input.tool_name, &input.tool_input) {
        CodeIntake::Code(code) => (
            Ok((
                input.tool_name.as_str(),
                code.canonical_input(),
                input.cwd.clone(),
            )),
            Some(code),
        ),
        CodeIntake::NotCode => (
            lower_hermes_tool(&input.tool_name, &input.tool_input, input.cwd.as_str()),
            None,
        ),
        CodeIntake::Invalid => (Err(INVALID_HERMES_TOOL_INPUT.into()), None),
    };
    let (tool, tool_input, cwd, normalization_complete) = match lowered {
        Ok((tool, tool_input, cwd)) => (
            tool,
            tool_input,
            cwd,
            runtime_field_names_covered("hermes", &input.tool_name, &original_input),
        ),
        Err(_) => (
            input.tool_name.as_str(),
            original_input.clone(),
            input.cwd,
            false,
        ),
    };
    // Calls made through `hermes_tools` inside `execute_code` carry an empty
    // session id.
    let session = input.session_id.filter(|session| !session.is_empty());
    ToolCallInput::new(SchemaVersion::V1, tool, tool_input, cwd, session)
        .map(|input| input.with_original_input(original_input, normalization_complete))
        .map(|input| (input, code))
        .map_err(|error| error.to_string())
}

fn lower_hermes_tool<'a>(
    tool_name: &'a str,
    tool_input: &Value,
    fallback_cwd: &str,
) -> Result<(&'a str, Value, String), String> {
    let object = tool_input
        .as_object()
        .ok_or_else(|| INVALID_HERMES_TOOL_INPUT.to_owned())?;
    let cwd = if tool_name == "terminal" {
        tool_input_nullable_non_empty_string(object, "workdir")?
            .unwrap_or_else(|| fallback_cwd.to_owned())
    } else {
        fallback_cwd.to_owned()
    };
    let (tool, input) = match tool_name {
        "terminal" => (
            "Bash",
            json!({"command": tool_input_string(object, "command", INVALID_HERMES_TOOL_INPUT)?}),
        ),
        "read_file" => (
            "Read",
            json!({"file_path": tool_input_non_empty_string(object, "path", INVALID_HERMES_TOOL_INPUT)?}),
        ),
        "write_file" => (
            "Write",
            json!({
                "file_path": tool_input_non_empty_string(object, "path", INVALID_HERMES_TOOL_INPUT)?,
                "content": tool_input_string(object, "content", INVALID_HERMES_TOOL_INPUT)?
            }),
        ),
        "patch" => patch_input(object)?,
        "search_files" => hermes_search_input(object)?,
        _ => (tool_name, tool_input.clone()),
    };
    Ok((tool, input, cwd))
}

fn patch_input(object: &Map<String, Value>) -> Result<(&'static str, Value), String> {
    // Hermes advertises `mode` only to OpenAI-family models; its handler
    // treats an omitted mode as `replace`.
    match object.get("mode").map(Value::as_str) {
        None | Some(Some("replace")) => {
            let replace_all =
                tool_input_optional_bool(object, "replace_all", INVALID_HERMES_TOOL_INPUT)?
                    .unwrap_or(false);
            Ok((
                "Edit",
                json!({
                    "file_path":tool_input_non_empty_string(object, "path", INVALID_HERMES_TOOL_INPUT)?,
                    "old_string":tool_input_string(object, "old_string", INVALID_HERMES_TOOL_INPUT)?,
                    "new_string":tool_input_string(object, "new_string", INVALID_HERMES_TOOL_INPUT)?,
                    "replace_all":replace_all
                }),
            ))
        }
        Some(Some("patch")) => Ok((
            "apply_patch",
            json!({"command":tool_input_non_empty_string(object, "patch", INVALID_HERMES_TOOL_INPUT)?}),
        )),
        _ => Err(INVALID_HERMES_TOOL_INPUT.into()),
    }
}

fn hermes_search_input(object: &Map<String, Value>) -> Result<(&'static str, Value), String> {
    let pattern = tool_input_string(object, "pattern", INVALID_HERMES_TOOL_INPUT)?;
    let path = tool_input_nullable_non_empty_string(object, "path")?.unwrap_or_else(|| ".".into());
    // Hermes applies `file_glob` as a filter inside `path` (`rg --glob`,
    // `grep --include`, `find -name`), so it only narrows the search; the
    // lowered search keeps the whole of `path` as its bound.
    tool_input_nullable_non_empty_string(object, "file_glob")?;
    match object
        .get("target")
        .and_then(Value::as_str)
        .unwrap_or("content")
    {
        // Hermes can probe with `--hidden --no-ignore` after zero matches,
        // or use recursive grep, so it cannot claim `ignore_files`.
        "content" => Ok(("Grep", json!({"pattern":pattern,"path":path}))),
        "files" if literal_path(&pattern) => Ok(("Glob", json!({"pattern":pattern,"path":path}))),
        "files" => Ok(("HermesSearchFiles", Value::Object(object.clone()))),
        _ => Err(INVALID_HERMES_TOOL_INPUT.into()),
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

/// Reads an optional string tool input field that Hermes may send as null. A
/// missing field, null and an empty string are all `None`.
fn tool_input_nullable_non_empty_string(
    object: &Map<String, Value>,
    name: &str,
) -> Result<Option<String>, String> {
    match object.get(name) {
        Some(Value::String(value)) if !value.is_empty() => Ok(Some(value.clone())),
        // Hermes treats null like an omitted field, and its `hermes_tools`
        // stubs send null for every unset optional argument.
        Some(Value::String(_) | Value::Null) | None => Ok(None),
        Some(_) => Err(INVALID_HERMES_TOOL_INPUT.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn normalized(tool_name: &str, tool_input: Value) -> ToolCallInput {
        normalize_hermes_hook_input(HermesHookInput {
            hook_event_name: "pre_tool_call".into(),
            tool_name: tool_name.into(),
            tool_input,
            cwd: "/repo".into(),
            session_id: Some("session-1".into()),
        })
        .unwrap()
        .0
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
            // The `hermes_tools.search_files` stub sends every argument.
            (
                "search_files",
                json!({"pattern":"needle","target":"content","path":".","file_glob":null,"limit":50,"offset":0,"output_mode":"content","context":0,"order":"discovery"}),
                "Grep",
                json!({"pattern":"needle","path":"."}),
            ),
            // A glob only filters files under `path`, which stays the bound.
            (
                "search_files",
                json!({"pattern":"needle","target":"content","path":"src","file_glob":"*.rs","limit":50,"offset":0,"output_mode":"files_only","context":0,"order":"discovery"}),
                "Grep",
                json!({"pattern":"needle","path":"src"}),
            ),
        ];
        for (name, input, expected_tool, expected_input) in cases {
            let call = normalized(name, input);
            assert_eq!(call.tool(), expected_tool);
            assert_eq!(call.input(), &expected_input);
            assert!(call.normalization_complete(), "{name}");
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
        // `hermes_tools` stubs send every argument; an uncovered field would
        // make a fail-closed install block these calls.
        for (name, input) in [
            (
                "terminal",
                json!({"command":"echo ok","timeout":null,"workdir":null}),
            ),
            (
                "write_file",
                json!({"path":"src/new.rs","content":"","cross_profile":false}),
            ),
            (
                "patch",
                json!({"path":"src/lib.rs","old_string":"a","new_string":"b","replace_all":false,"mode":"replace","patch":null,"cross_profile":false}),
            ),
        ] {
            assert!(normalized(name, input).normalization_complete(), "{name}");
        }
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
                "browser_navigate",
                json!({"url":"https://example.com"}),
                "browser_navigate",
            ),
        ] {
            assert_eq!(normalized(name, input).tool(), expected);
        }
    }

    #[test]
    fn normalizes_verified_execute_code_for_later_analysis() {
        let source = "open('.env').read()";
        let original = json!({"code":source});
        let code = normalize_hermes_hook_input(HermesHookInput {
            hook_event_name: "pre_tool_call".into(),
            tool_name: "execute_code".into(),
            tool_input: original.clone(),
            cwd: "/repo".into(),
            session_id: None,
        })
        .unwrap();
        assert_eq!(code.0.tool(), "execute_code");
        assert_eq!(code.0.input(), &json!({"code":source,"language":"python"}));
        assert_eq!(code.0.invocation_input(), &original);
        assert!(code.0.normalization_complete());
        assert_eq!(
            code.1,
            Some(CodeInput::Python {
                source: source.into()
            })
        );
    }

    #[test]
    fn malformed_execute_code_stays_incomplete() {
        for input in [
            json!({}),
            json!({"code":7}),
            json!({"code":" \n"}),
            json!({"code":"print('ok')","futureBehavior":"execute"}),
        ] {
            let code = normalize_hermes_hook_input(HermesHookInput {
                hook_event_name: "pre_tool_call".into(),
                tool_name: "execute_code".into(),
                tool_input: input.clone(),
                cwd: "/repo".into(),
                session_id: None,
            })
            .unwrap();
            assert_eq!(code.0.tool(), "execute_code");
            assert_eq!(code.0.input(), &input);
            assert!(!code.0.normalization_complete());
            assert_eq!(code.1, None);
        }
    }

    #[test]
    fn malformed_known_tools_stay_opaque() {
        for (name, input) in [
            ("terminal", json!({"command":7})),
            ("read_file", json!({"path":""})),
            ("write_file", json!({"path":"x"})),
            ("patch", json!({"mode":"patch","patch":""})),
            (
                "patch",
                json!({"mode":"append","path":"x","old_string":"a","new_string":"b"}),
            ),
            ("search_files", json!({"pattern":7})),
            (
                "search_files",
                json!({"pattern":"needle","target":"content","file_glob":7}),
            ),
        ] {
            let call = normalize_hermes_hook_input(HermesHookInput {
                hook_event_name: "pre_tool_call".into(),
                tool_name: name.into(),
                tool_input: input.clone(),
                cwd: "/repo".into(),
                session_id: None,
            })
            .unwrap()
            .0;
            assert_eq!(call.tool(), name);
            assert_eq!(call.input(), &input);
            assert!(!call.normalization_complete());
        }
    }
}
