//! Native Hermes pre-tool adapter over the shared `nah decide` seam.

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

/// The tool call `run` hands the pipeline for this Hermes tool call.
pub(crate) fn normalize_call(
    tool_name: &str,
    tool_input: Value,
    cwd: &str,
) -> Result<(ToolCallInput, Option<CodeInput>), String> {
    normalize(HermesHookInput {
        hook_event_name: "pre_tool_call".into(),
        tool_name: tool_name.into(),
        tool_input,
        cwd: cwd.into(),
        session_id: None,
    })
}

fn normalize(input: HermesHookInput) -> Result<(ToolCallInput, Option<CodeInput>), String> {
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
            lower(&input.tool_name, &input.tool_input, input.cwd.as_str()),
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

fn lower<'a>(
    tool_name: &'a str,
    tool_input: &Value,
    fallback_cwd: &str,
) -> Result<(&'a str, Value, String), String> {
    let object = tool_input
        .as_object()
        .ok_or_else(|| INVALID_HERMES_TOOL_INPUT.to_owned())?;
    let cwd = if tool_name == "terminal" {
        optional_non_empty(object, "workdir")?.unwrap_or_else(|| fallback_cwd.to_owned())
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
        "search_files" => search_input(object)?,
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

fn search_input(object: &Map<String, Value>) -> Result<(&'static str, Value), String> {
    let pattern = tool_input_string(object, "pattern", INVALID_HERMES_TOOL_INPUT)?;
    let path = optional_non_empty(object, "path")?.unwrap_or_else(|| ".".into());
    // Hermes applies `file_glob` as a filter inside `path` (`rg --glob`,
    // `grep --include`, `find -name`), so it only narrows the search; the
    // lowered search keeps the whole of `path` as its bound.
    optional_non_empty(object, "file_glob")?;
    match object
        .get("target")
        .and_then(Value::as_str)
        .unwrap_or("content")
    {
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

fn optional_non_empty(object: &Map<String, Value>, name: &str) -> Result<Option<String>, String> {
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
        normalize(HermesHookInput {
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
        let code = normalize(HermesHookInput {
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
            let code = normalize(HermesHookInput {
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
            let call = normalize(HermesHookInput {
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
