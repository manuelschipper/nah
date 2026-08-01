//! Native Amp tool-call adapter over the shared `nah decide` seam.

use std::io::{Read, Write};

use nah_proto::ctx::SchemaVersion;
use nah_proto::decision::Verdict;
use nah_proto::tool::ToolCallInput;
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::hook_adapter::{self, HookOutcome};
use crate::runtime::Runtime;

#[derive(Deserialize)]
struct AmpHookInput {
    tool_name: String,
    tool_input: Value,
    cwd: String,
    session_id: Option<String>,
}

pub(crate) fn run<R: Read, W: Write, E: Write>(
    stdin: &mut R,
    stdout: &mut W,
    stderr: &mut E,
) -> u8 {
    let request = serde_json::from_reader::<_, AmpHookInput>(stdin)
        .map_err(|error| error.to_string())
        .and_then(normalize);
    let output = match request {
        Ok(request) => match hook_adapter::decide_input(request, stderr, Runtime::Amp) {
            HookOutcome::Decision(decision) if decision.verdict() == Verdict::Block => {
                json!({
                    "block": true,
                    "reason": format!("nah - {}", hook_adapter::feedback(&decision)),
                    "evaluation_failed": decision.evaluation_failed()
                })
            }
            HookOutcome::Decision(decision) => {
                json!({"block": false, "evaluation_failed": decision.evaluation_failed()})
            }
            HookOutcome::IrrelevantEvent => return 0,
            HookOutcome::MalformedInput => delegated(false),
            HookOutcome::EvaluationUnavailable => delegated(true),
        },
        Err(_) => delegated(false),
    };
    let _ = serde_json::to_writer(&mut *stdout, &output);
    let _ = writeln!(stdout);
    0
}

fn normalize(input: AmpHookInput) -> Result<ToolCallInput, String> {
    let original_input = input.tool_input.clone();
    let lowered = input
        .tool_input
        .as_object()
        .ok_or_else(|| "invalid-amp-tool-input".to_owned())
        .and_then(|object| lower(&input.tool_name, &input.tool_input, object));
    let (tool, tool_input, normalization_complete) = match lowered {
        Ok((tool, tool_input)) => (
            tool,
            tool_input,
            crate::adapter_fields::complete("amp", &input.tool_name, &original_input),
        ),
        Err(_) => (input.tool_name.as_str(), original_input.clone(), false),
    };
    ToolCallInput::new(
        SchemaVersion::V1,
        tool,
        tool_input,
        input.cwd,
        input.session_id,
    )
    .map(|input| input.with_original_input(original_input, normalization_complete))
    .map_err(|error| error.to_string())
}

fn lower<'a>(
    tool_name: &'a str,
    tool_input: &Value,
    object: &Map<String, Value>,
) -> Result<(&'a str, Value), String> {
    Ok(match tool_name {
        "shell_command" => ("Bash", json!({"command": string(object, "command")?})),
        "apply_patch" => (
            "apply_patch",
            json!({"command": non_empty(object, "patchText")?}),
        ),
        "create_file" => (
            "Write",
            json!({
                "file_path": non_empty(object, "path")?,
                "content": string(object, "content")?
            }),
        ),
        "edit_file" => {
            let mut normalized = json!({
                "file_path": non_empty(object, "path")?,
                "old_string": string(object, "old_str")?,
                "new_string": string(object, "new_str")?
            });
            if let Some(replace_all) = optional_bool(object, "replace_all")? {
                normalized["replace_all"] = json!(replace_all);
            }
            ("Edit", normalized)
        }
        "upload_thread_file" => (
            "AmpUpload",
            json!({"file_path": non_empty(object, "path")?}),
        ),
        "download_thread_file" => (
            "AmpDownload",
            json!({"file_path": non_empty(object, "destination")?}),
        ),
        _ => (tool_name, tool_input.clone()),
    })
}

fn string(object: &Map<String, Value>, name: &str) -> Result<String, String> {
    object
        .get(name)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| "invalid-amp-tool-input".to_owned())
}

fn non_empty(object: &Map<String, Value>, name: &str) -> Result<String, String> {
    string(object, name).and_then(|value| {
        if value.is_empty() {
            Err("invalid-amp-tool-input".into())
        } else {
            Ok(value)
        }
    })
}

fn optional_bool(object: &Map<String, Value>, name: &str) -> Result<Option<bool>, String> {
    match object.get(name) {
        Some(Value::Bool(value)) => Ok(Some(*value)),
        None => Ok(None),
        Some(_) => Err("invalid-amp-tool-input".into()),
    }
}

fn delegated(evaluation_failed: bool) -> Value {
    json!({"block": false, "evaluation_failed": evaluation_failed})
}

#[cfg(test)]
mod tests {
    use super::*;

    fn normalized(tool_name: &str, tool_input: Value) -> ToolCallInput {
        normalize(AmpHookInput {
            tool_name: tool_name.into(),
            tool_input,
            cwd: "/repo".into(),
            session_id: Some("T-thread".into()),
        })
        .unwrap()
    }

    #[test]
    fn normalizes_verified_amp_builtins() {
        let cases = [
            (
                "shell_command",
                json!({"command":"echo ok","workdir":"/repo","timeout_ms":10}),
                "Bash",
                json!({"command":"echo ok"}),
            ),
            (
                "apply_patch",
                json!({"patchText":"*** Begin Patch\n*** End Patch"}),
                "apply_patch",
                json!({"command":"*** Begin Patch\n*** End Patch"}),
            ),
            (
                "create_file",
                json!({"path":"/repo/src/lib.rs","content":""}),
                "Write",
                json!({"file_path":"/repo/src/lib.rs","content":""}),
            ),
            (
                "edit_file",
                json!({
                    "path":"/repo/src/lib.rs",
                    "old_str":"old",
                    "new_str":"new",
                    "replace_all":true
                }),
                "Edit",
                json!({
                    "file_path":"/repo/src/lib.rs",
                    "old_string":"old",
                    "new_string":"new",
                    "replace_all":true
                }),
            ),
        ];
        for (name, input, expected_tool, expected_input) in cases {
            let call = normalized(name, input);
            assert_eq!(call.tool(), expected_tool);
            assert_eq!(call.input(), &expected_input);
            assert_eq!(call.session(), Some("T-thread"));
        }
    }

    #[test]
    fn preserves_opaque_amp_tools() {
        for (name, input) in [
            ("load_plugin", json!({"path":".amp/plugins/example.ts"})),
            ("custom_tool", json!({"argument":7})),
        ] {
            let call = normalized(name, input.clone());
            assert_eq!(call.tool(), name);
            assert_eq!(call.input(), &input);
        }
    }

    #[test]
    fn incomplete_normalization_preserves_the_original_runtime_input() {
        let original = json!({"command":"echo ok","futureBehavior":"execute"});

        let call = normalized("shell_command", original.clone());

        assert!(!call.normalization_complete());
        assert_eq!(call.invocation_input(), &original);
        let serialized = serde_json::to_value(&call).unwrap();
        assert_eq!(serialized["original_input"], original);
    }

    #[test]
    fn normalizes_visible_thread_transfer_paths() {
        let upload = normalized("upload_thread_file", json!({"path":"src/lib.rs"}));
        assert_eq!(upload.tool(), "AmpUpload");
        assert_eq!(upload.input(), &json!({"file_path":"src/lib.rs"}));

        let download = normalized(
            "download_thread_file",
            json!({"path":"artifact","destination":"/repo/artifact"}),
        );
        assert_eq!(download.tool(), "AmpDownload");
        assert_eq!(download.input(), &json!({"file_path":"/repo/artifact"}));
    }

    #[test]
    fn preserves_malformed_builtin_inputs_as_opaque_calls() {
        for (name, input) in [
            ("shell_command", json!({"command":7})),
            ("apply_patch", json!({"patchText":""})),
            ("create_file", json!({"path":"", "content":"x"})),
            ("download_thread_file", json!({"path":"artifact.txt"})),
            (
                "edit_file",
                json!({"path":"/repo/file","old_str":"a","new_str":"b","replace_all":"yes"}),
            ),
        ] {
            let call = normalize(AmpHookInput {
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

    #[test]
    fn native_adapter_stays_thin() {
        let implementation = include_str!("amp_adapter.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        assert!(implementation.lines().count() <= 149);
    }
}
