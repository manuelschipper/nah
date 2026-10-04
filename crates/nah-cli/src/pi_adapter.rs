//! Native Pi tool-call adapter over the shared `nah decide` seam.

use std::io::{Read, Write};

use nah_proto::ctx::SchemaVersion;
use nah_proto::decision::Verdict;
use nah_proto::tool::ToolCallInput;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    adapter_fields::{
        runtime_field_names_covered, tool_input_non_empty_string, tool_input_object,
        tool_input_optional_non_empty_string, tool_input_string, tool_input_text_edits,
    },
    hook_adapter,
    runtime::{FailurePolicy, Runtime},
};

const INVALID_PI_TOOL_INPUT: &str = "invalid-pi-tool-input";

#[derive(Deserialize)]
struct PiHookInput {
    tool_name: String,
    tool_input: Value,
    cwd: String,
}

pub(crate) fn run<R: Read, W: Write, E: Write>(
    stdin: &mut R,
    stdout: &mut W,
    stderr: &mut E,
    failure_policy: FailurePolicy,
) -> u8 {
    let request = serde_json::from_reader::<_, PiHookInput>(stdin)
        .map_err(|error| error.to_string())
        .and_then(normalize_pi_hook_input);
    let output = match request {
        Ok(request) => {
            match hook_adapter::decide_input(request, stderr, Runtime::Pi, failure_policy) {
                hook_adapter::HookOutcome::Decision(decision)
                    if decision.verdict() == Verdict::Block =>
                {
                    json!({
                        "block": true,
                        "reason": format!("nah - {}", hook_adapter::feedback(&decision)),
                        "evaluation_failed":decision.evaluation_failed()
                    })
                }
                hook_adapter::HookOutcome::Decision(decision) => {
                    json!({"block": false, "evaluation_failed":decision.evaluation_failed()})
                }
                hook_adapter::HookOutcome::IrrelevantEvent => return 0,
                hook_adapter::HookOutcome::MalformedInput => {
                    hook_adapter::unavailable_plugin_reply(
                        failure_policy,
                        Runtime::Pi,
                        hook_adapter::IntegrationUnavailable::MalformedInput,
                    )
                    .unwrap_or_else(|| hook_adapter::delegated_plugin_reply(false))
                }
                hook_adapter::HookOutcome::EvaluationUnavailable(kind) => {
                    { hook_adapter::unavailable_plugin_reply(failure_policy, Runtime::Pi, kind) }
                        .unwrap_or_else(|| hook_adapter::delegated_plugin_reply(true))
                }
            }
        }
        Err(_) => hook_adapter::unavailable_plugin_reply(
            failure_policy,
            Runtime::Pi,
            hook_adapter::IntegrationUnavailable::MalformedInput,
        )
        .unwrap_or_else(|| hook_adapter::delegated_plugin_reply(false)),
    };
    hook_adapter::write_hook_reply_line(stdout, output);
    0
}

/// The tool call `run` hands the pipeline for this Pi tool call.
pub(crate) fn normalize_call(
    tool_name: &str,
    tool_input: Value,
    cwd: &str,
) -> Result<ToolCallInput, String> {
    normalize_pi_hook_input(PiHookInput {
        tool_name: tool_name.into(),
        tool_input,
        cwd: cwd.into(),
    })
}

fn normalize_pi_hook_input(input: PiHookInput) -> Result<ToolCallInput, String> {
    let original_input = input.tool_input.clone();
    let lowered = tool_input_object(&input.tool_input, INVALID_PI_TOOL_INPUT)
        .and_then(|object| lower_pi_tool(&input.tool_name, &input.tool_input, object));
    let (tool, tool_input, normalization_complete) = match lowered {
        Ok((tool, tool_input)) => (
            tool,
            tool_input,
            runtime_field_names_covered("pi", &input.tool_name, &original_input),
        ),
        Err(_) => (input.tool_name.as_str(), original_input.clone(), false),
    };
    ToolCallInput::new(SchemaVersion::V1, tool, tool_input, input.cwd, None)
        .map(|input| input.with_original_input(original_input, normalization_complete))
        .map_err(|error| error.to_string())
}

fn lower_pi_tool<'a>(
    tool_name: &'a str,
    tool_input: &Value,
    object: &serde_json::Map<String, Value>,
) -> Result<(&'a str, Value), String> {
    let string = |name: &str| tool_input_non_empty_string(object, name, INVALID_PI_TOOL_INPUT);
    let string_value = |name: &str| tool_input_string(object, name, INVALID_PI_TOOL_INPUT);
    let optional_path = || {
        tool_input_optional_non_empty_string(object, "path", INVALID_PI_TOOL_INPUT)
            .map(|path| path.unwrap_or_else(|| ".".into()))
    };
    Ok(match tool_name {
        "bash" => ("Bash", json!({"command": string_value("command")?})),
        "read" => ("Read", json!({"file_path": string("path")?})),
        "write" => (
            "Write",
            json!({"file_path": string("path")?, "content": string_value("content")?}),
        ),
        "edit" => (
            "Edit",
            json!({"file_path": string("path")?, "edits": tool_input_text_edits(object, INVALID_PI_TOOL_INPUT)?}),
        ),
        "grep" => (
            "Grep",
            json!({"pattern": string_value("pattern")?, "path": optional_path()?}),
        ),
        "find" => (
            "Find",
            json!({"pattern": string_value("pattern")?, "path": optional_path()?}),
        ),
        "ls" => ("Ls", json!({"path": optional_path()?})),
        _ => (tool_name, tool_input.clone()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn normalized(tool_name: &str, tool_input: Value) -> ToolCallInput {
        normalize_pi_hook_input(PiHookInput {
            tool_name: tool_name.into(),
            tool_input,
            cwd: "/repo".into(),
        })
        .unwrap()
    }

    #[test]
    fn normalizes_pi_builtins_without_policy_logic() {
        let cases = [
            (
                "bash",
                json!({"command":"echo ok","timeout":10}),
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
                json!({"path":"src/lib.rs","content":"x"}),
                "Write",
                json!({"file_path":"src/lib.rs","content":"x"}),
            ),
            (
                "grep",
                json!({"pattern":"needle"}),
                "Grep",
                json!({"pattern":"needle","path":"."}),
            ),
            (
                "find",
                json!({"pattern":"**/*.rs","path":"src"}),
                "Find",
                json!({"pattern":"**/*.rs","path":"src"}),
            ),
            ("ls", json!({}), "Ls", json!({"path":"."})),
        ];
        for (name, input, expected_tool, expected_input) in cases {
            let call = normalized(name, input);
            assert_eq!(call.tool(), expected_tool);
            assert_eq!(call.input(), &expected_input);
            // An incomplete normalization is a refusal that a fail-closed
            // hook blocks, so a builtin's documented fields must not cause one.
            assert!(call.normalization_complete(), "{name}");
        }
    }

    #[test]
    fn preserves_multi_edit_and_unknown_tool_inputs() {
        let edits = json!([
            {"oldText":"old one","newText":"new one"},
            {"oldText":"old two","newText":"new two"}
        ]);
        let edit = normalized("edit", json!({"path":"src/lib.rs","edits":edits}));
        assert_eq!(edit.tool(), "Edit");
        assert_eq!(edit.input()["edits"], edits);

        let unknown = normalized("custom_tool", json!({"argument":7}));
        assert_eq!(unknown.tool(), "custom_tool");
        assert_eq!(unknown.input(), &json!({"argument":7}));
    }

    #[test]
    fn preserves_malformed_builtin_inputs_as_opaque_calls() {
        for (name, input) in [
            ("bash", json!({"command":7})),
            ("read", json!({"path":""})),
            ("write", json!({"path":"file"})),
            ("edit", json!({"path":"file","edits":[]})),
            ("grep", json!({"pattern":"x","path":7})),
            ("find", json!({"pattern":7})),
            ("ls", json!({"path":7})),
        ] {
            let call = normalize_pi_hook_input(PiHookInput {
                tool_name: name.into(),
                tool_input: input.clone(),
                cwd: "/repo".into(),
            })
            .unwrap();
            assert_eq!(call.tool(), name);
            assert_eq!(call.input(), &input);
            assert!(!call.normalization_complete());
        }
    }
}
