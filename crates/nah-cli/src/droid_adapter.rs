//! Native Factory Droid PreToolUse adapter over the shared decision seam.

use std::io::{Read, Write};

use nah_proto::ctx::SchemaVersion;
use nah_proto::decision::Verdict;
use nah_proto::tool::ToolCallInput;
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::hook_adapter::{self, HookOutcome};
use crate::runtime::Runtime;

#[derive(Deserialize)]
struct DroidHookInput {
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
) -> u8 {
    let request =
        match hook_adapter::read_event::<_, DroidHookInput>(stdin, "hook_event_name", "PreToolUse")
        {
            Ok(Some(input)) => normalize(input),
            Ok(None) => return 0,
            Err(error) => Err(error.to_string()),
        };
    match request {
        Ok(request) => match hook_adapter::decide_input(request, stderr, Runtime::Droid) {
            HookOutcome::Decision(decision) if decision.verdict() == Verdict::Block => {
                let _ = writeln!(stderr, "nah - {}", hook_adapter::feedback(&decision));
                if decision.evaluation_failed() {
                    let _ = writeln!(stderr, "{}", hook_adapter::BLOCK_FAILURE_MESSAGE);
                }
                2
            }
            HookOutcome::Decision(decision) => {
                if decision.evaluation_failed() {
                    let _ = writeln!(stdout, "{}", hook_adapter::DELEGATED_FAILURE_MESSAGE);
                }
                0
            }
            HookOutcome::IrrelevantEvent | HookOutcome::MalformedInput => 0,
            HookOutcome::EvaluationUnavailable => {
                let _ = writeln!(stdout, "{}", hook_adapter::DELEGATED_FAILURE_MESSAGE);
                0
            }
        },
        Err(_) => 0,
    }
}

fn normalize(input: DroidHookInput) -> Result<ToolCallInput, String> {
    let original_input = input.tool_input.clone();
    if input.hook_event_name != "PreToolUse" {
        return Err("invalid-droid-hook-event".into());
    }
    let lowered = input
        .tool_input
        .as_object()
        .ok_or_else(|| "invalid-droid-tool-input".to_owned())
        .and_then(|object| lower(&input.tool_name, &input.tool_input, object, &input.cwd));
    let (tool, tool_input, normalization_complete) = match lowered {
        Ok((tool, tool_input)) => (
            tool,
            tool_input,
            crate::adapter_fields::complete("droid", &input.tool_name, &original_input),
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
    cwd: &str,
) -> Result<(&'a str, Value), String> {
    Ok(match tool_name {
        "Execute" => ("Bash", json!({"command": string(object, "command")?})),
        "Read" => (
            "Read",
            json!({"file_path": non_empty(object, "file_path")?}),
        ),
        "Create" => (
            "Write",
            json!({
                "file_path": non_empty(object, "file_path")?,
                "content": string(object, "content")?
            }),
        ),
        "Edit" => ("Edit", edit_input(object)?),
        "ApplyPatch" => (
            "apply_patch",
            json!({"command": non_empty(object, "input")?}),
        ),
        "Grep" => {
            let mut normalized = json!({"pattern": string(object, "pattern")?});
            if let Some(path) = optional_non_empty(object, "path")? {
                normalized["path"] = json!(path);
            }
            ("Grep", normalized)
        }
        "Glob" => glob_input(object)?,
        "LS" => (
            "Ls",
            json!({"path": optional_non_empty(object, "directory_path")?
                .unwrap_or_else(|| cwd.to_owned())}),
        ),
        _ => (tool_name, tool_input.clone()),
    })
}

fn edit_input(object: &Map<String, Value>) -> Result<Value, String> {
    let path = non_empty(object, "file_path")?;
    if let Some(changes) = object.get("changes") {
        let changes = changes
            .as_array()
            .filter(|changes| !changes.is_empty())
            .ok_or_else(|| "invalid-droid-tool-input".to_owned())?;
        let edits = changes
            .iter()
            .map(|change| {
                let change = change
                    .as_object()
                    .ok_or_else(|| "invalid-droid-tool-input".to_owned())?;
                optional_bool(change, "change_all")?;
                Ok(json!({
                    "oldText": string(change, "old_str")?,
                    "newText": string(change, "new_str")?
                }))
            })
            .collect::<Result<Vec<_>, String>>()?;
        return Ok(json!({"file_path":path,"edits":edits}));
    }
    let mut normalized = json!({
        "file_path": path,
        "old_string": string(object, "old_str")?,
        "new_string": string(object, "new_str")?
    });
    if let Some(change_all) = optional_bool(object, "change_all")? {
        normalized["replace_all"] = json!(change_all);
    }
    Ok(normalized)
}

fn glob_input(object: &Map<String, Value>) -> Result<(&'static str, Value), String> {
    optional_strings(object, "excludePatterns")?;
    let folder = optional_non_empty(object, "folder")?;
    let Some(patterns) = optional_strings(object, "patterns")? else {
        return Ok(("DroidGlob", Value::Object(object.clone())));
    };
    if patterns.len() != 1 || patterns[0].is_empty() {
        return Ok(("DroidGlob", Value::Object(object.clone())));
    }
    let mut normalized = json!({"pattern":patterns[0]});
    if let Some(folder) = folder {
        normalized["path"] = json!(folder);
    }
    Ok(("Glob", normalized))
}

fn string(object: &Map<String, Value>, name: &str) -> Result<String, String> {
    object
        .get(name)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| "invalid-droid-tool-input".to_owned())
}

fn non_empty(object: &Map<String, Value>, name: &str) -> Result<String, String> {
    string(object, name).and_then(|value| {
        (!value.is_empty())
            .then_some(value)
            .ok_or_else(|| "invalid-droid-tool-input".to_owned())
    })
}

fn optional_non_empty(object: &Map<String, Value>, name: &str) -> Result<Option<String>, String> {
    match object.get(name) {
        Some(Value::String(value)) if !value.is_empty() => Ok(Some(value.clone())),
        Some(Value::String(_)) | None => Ok(None),
        Some(_) => Err("invalid-droid-tool-input".into()),
    }
}

fn optional_bool(object: &Map<String, Value>, name: &str) -> Result<Option<bool>, String> {
    match object.get(name) {
        Some(Value::Bool(value)) => Ok(Some(*value)),
        None => Ok(None),
        Some(_) => Err("invalid-droid-tool-input".into()),
    }
}

fn optional_strings(
    object: &Map<String, Value>,
    name: &str,
) -> Result<Option<Vec<String>>, String> {
    match object.get(name) {
        Some(Value::Array(values)) if values.iter().all(Value::is_string) => Ok(Some(
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect(),
        )),
        None => Ok(None),
        Some(_) => Err("invalid-droid-tool-input".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn normalized(tool_name: &str, tool_input: Value) -> ToolCallInput {
        normalize(DroidHookInput {
            hook_event_name: "PreToolUse".into(),
            tool_name: tool_name.into(),
            tool_input,
            cwd: "/repo".into(),
            session_id: Some("session-1".into()),
        })
        .unwrap()
    }

    #[test]
    fn normalizes_current_droid_tools() {
        let cases = [
            (
                "Execute",
                json!({"command":"echo ok","riskLevel":"low"}),
                "Bash",
                json!({"command":"echo ok"}),
            ),
            (
                "Create",
                json!({"file_path":"src/new.rs","content":"new"}),
                "Write",
                json!({"file_path":"src/new.rs","content":"new"}),
            ),
            (
                "ApplyPatch",
                json!({"input":"*** Begin Patch\n*** End Patch"}),
                "apply_patch",
                json!({"command":"*** Begin Patch\n*** End Patch"}),
            ),
            (
                "Grep",
                json!({"pattern":"needle","path":"src","output_mode":"files_with_matches"}),
                "Grep",
                json!({"pattern":"needle","path":"src"}),
            ),
            (
                "Glob",
                json!({"patterns":["lib.rs"],"folder":"src"}),
                "Glob",
                json!({"pattern":"lib.rs","path":"src"}),
            ),
            (
                "LS",
                json!({"directory_path":"src","ignorePatterns":["target"]}),
                "Ls",
                json!({"path":"src"}),
            ),
        ];
        for (name, input, expected_tool, expected_input) in cases {
            let call = normalized(name, input);
            assert_eq!(call.tool(), expected_tool);
            assert_eq!(call.input(), &expected_input);
            assert_eq!(call.session(), Some("session-1"));
        }
    }

    #[test]
    fn normalizes_single_and_multi_edit_shapes() {
        assert_eq!(
            normalized(
                "Edit",
                json!({
                    "file_path":"src/lib.rs",
                    "old_str":"old",
                    "new_str":"new",
                    "change_all":true
                })
            )
            .input(),
            &json!({
                "file_path":"src/lib.rs",
                "old_string":"old",
                "new_string":"new",
                "replace_all":true
            })
        );
        assert_eq!(
            normalized(
                "Edit",
                json!({
                    "file_path":"src/lib.rs",
                    "changes":[
                        {"old_str":"a","new_str":"b"},
                        {"old_str":"c","new_str":"d","change_all":false}
                    ]
                })
            )
            .input(),
            &json!({
                "file_path":"src/lib.rs",
                "edits":[
                    {"oldText":"a","newText":"b"},
                    {"oldText":"c","newText":"d"}
                ]
            })
        );
    }

    #[test]
    fn preserves_unmapped_and_non_exact_glob_tools() {
        let task = normalized("Task", json!({"prompt":"inspect"}));
        assert_eq!(task.tool(), "Task");
        let glob = normalized("Glob", json!({"patterns":["a","b"],"folder":"src"}));
        assert_eq!(glob.tool(), "DroidGlob");
    }

    #[test]
    fn preserves_malformed_known_tools_as_opaque_calls() {
        for (name, input) in [
            ("Execute", json!({"command":7})),
            ("Create", json!({"file_path":"","content":"x"})),
            ("ApplyPatch", json!({"input":""})),
            (
                "Edit",
                json!({"file_path":"x","old_str":"a","new_str":"b","change_all":"yes"}),
            ),
            ("Grep", json!({"pattern":7})),
            ("Glob", json!({"patterns":"*.rs"})),
            ("LS", json!({"directory_path":7})),
        ] {
            let call = normalize(DroidHookInput {
                hook_event_name: "PreToolUse".into(),
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
    fn native_adapter_stays_contained() {
        let implementation = include_str!("droid_adapter.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        assert!(implementation.lines().count() <= 228);
    }
}
