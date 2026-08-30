//! Native Antigravity PreToolUse adapter over the shared decision seam.

use std::io::{Read, Write};

use nah_proto::ctx::{AbsolutePath, Platform, SchemaVersion};
use nah_proto::decision::Verdict;
use nah_proto::tool::ToolCallInput;
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::{
    hook_adapter, live_state,
    runtime::{FailurePolicy, Runtime},
};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AntigravityHookInput {
    tool_call: AntigravityToolCall,
    conversation_id: String,
    workspace_paths: Vec<String>,
}

#[derive(Deserialize)]
struct AntigravityToolCall {
    name: String,
    args: Value,
}

type LoweredTool<'a> = (&'a str, Value, Option<String>, Option<String>);

pub(crate) fn run<R: Read, W: Write, E: Write>(
    stdin: &mut R,
    stdout: &mut W,
    stderr: &mut E,
    failure_policy: FailurePolicy,
) -> u8 {
    let request = serde_json::from_reader::<_, AntigravityHookInput>(stdin)
        .map_err(|error| error.to_string())
        .and_then(normalize);
    let output = match request {
        Ok(request) => {
            match hook_adapter::decide_input(request, stderr, Runtime::Antigravity, failure_policy)
            {
                hook_adapter::HookOutcome::Decision(decision) => match decision.verdict() {
                    Verdict::Block => {
                        if decision.guard_block_incomplete() {
                            let _ = writeln!(stderr, "{}", hook_adapter::BLOCK_FAILURE_MESSAGE);
                        }
                        deny(&hook_adapter::feedback(&decision))
                    }
                    Verdict::Delegate => {
                        if decision.evaluation_failed() {
                            let _ = writeln!(stderr, "{}", hook_adapter::DELEGATED_FAILURE_MESSAGE);
                        }
                        json!({"decision":"ask"})
                    }
                },
                hook_adapter::HookOutcome::IrrelevantEvent => return 0,
                hook_adapter::HookOutcome::MalformedInput => hook_adapter::unavailable_feedback(
                    failure_policy,
                    Runtime::Antigravity,
                    hook_adapter::IntegrationUnavailable::MalformedInput,
                )
                .map_or_else(|| json!({"decision":"ask"}), |reason| deny(&reason)),
                hook_adapter::HookOutcome::EvaluationUnavailable(kind) => {
                    match hook_adapter::unavailable_feedback(
                        failure_policy,
                        Runtime::Antigravity,
                        kind,
                    ) {
                        Some(reason) => deny(&reason),
                        None => {
                            let _ = writeln!(stderr, "{}", hook_adapter::DELEGATED_FAILURE_MESSAGE);
                            json!({"decision":"ask"})
                        }
                    }
                }
            }
        }
        Err(_) => hook_adapter::unavailable_feedback(
            failure_policy,
            Runtime::Antigravity,
            hook_adapter::IntegrationUnavailable::MalformedInput,
        )
        .map_or_else(|| json!({"decision":"ask"}), |reason| deny(&reason)),
    };
    let _ = serde_json::to_writer(&mut *stdout, &output);
    let _ = writeln!(stdout);
    0
}

fn normalize(input: AntigravityHookInput) -> Result<ToolCallInput, String> {
    let original_input = input.tool_call.args.clone();
    let platform = live_state::host_platform();
    let workspaces = validate_workspaces(input.workspace_paths, platform)?;
    let lowered = input
        .tool_call
        .args
        .as_object()
        .ok_or_else(|| "invalid-antigravity-tool-input".to_owned())
        .and_then(|object| {
            lower(
                &input.tool_call.name,
                &input.tool_call.args,
                object,
                platform,
            )
        });
    let (tool, tool_input, path, cwd, normalization_complete) = match lowered {
        Ok((tool, tool_input, path, cwd)) => (
            tool,
            tool_input,
            path,
            cwd,
            crate::adapter_fields::complete("antigravity", &input.tool_call.name, &original_input),
        ),
        Err(_) => (
            input.tool_call.name.as_str(),
            original_input.clone(),
            None,
            None,
            false,
        ),
    };
    let cwd = cwd.unwrap_or_else(|| workspace_for(path.as_deref(), &workspaces, platform));
    ToolCallInput::new(
        SchemaVersion::V1,
        tool,
        tool_input,
        cwd,
        Some(input.conversation_id),
    )
    .map(|input| input.with_original_input(original_input, normalization_complete))
    .map_err(|error| error.to_string())
}

fn lower<'a>(
    tool_name: &'a str,
    tool_input: &Value,
    object: &Map<String, Value>,
    platform: Platform,
) -> Result<LoweredTool<'a>, String> {
    Ok(match tool_name {
        "run_command" => (
            "Bash",
            json!({"command": string(object, "CommandLine")?}),
            None,
            Some(absolute(object, "Cwd", platform)?),
        ),
        "view_file" => {
            let path = absolute(object, "AbsolutePath", platform)?;
            ("Read", json!({"file_path":path.clone()}), Some(path), None)
        }
        "write_to_file" => {
            let path = absolute(object, "TargetFile", platform)?;
            (
                "Write",
                json!({
                    "file_path":path.clone(),
                    "content":string(object, "CodeContent")?
                }),
                Some(path),
                None,
            )
        }
        "replace_file_content" => {
            let path = absolute(object, "TargetFile", platform)?;
            let mut edit = json!({
                "file_path":path.clone(),
                "old_string":non_empty(object, "TargetContent")?,
                "new_string":string(object, "ReplacementContent")?
            });
            if let Some(replace_all) = optional_bool(object, "AllowMultiple")? {
                edit["replace_all"] = json!(replace_all);
            }
            ("Edit", edit, Some(path), None)
        }
        "multi_replace_file_content" => {
            let path = absolute(object, "TargetFile", platform)?;
            (
                "Edit",
                json!({"file_path":path.clone(),"edits":replacement_chunks(object)?}),
                Some(path),
                None,
            )
        }
        "list_dir" => {
            let path = absolute(object, "DirectoryPath", platform)?;
            ("Ls", json!({"path":path.clone()}), Some(path), None)
        }
        "find_by_name" => {
            let path = absolute(object, "SearchDirectory", platform)?;
            (
                "Find",
                json!({"path":path.clone(),"pattern":string(object, "Pattern")?}),
                Some(path),
                None,
            )
        }
        "grep_search" => {
            let path = absolute(object, "SearchPath", platform)?;
            (
                "Grep",
                json!({"path":path.clone(),"pattern":string(object, "Query")?}),
                Some(path),
                None,
            )
        }
        "manage_task" => {
            match string(object, "Action")?.as_str() {
                "send_input" => return Err("unsupported-antigravity-task-input".into()),
                "list" | "kill" | "status" => {}
                _ => return Err("invalid-antigravity-tool-input".into()),
            }
            (tool_name, tool_input.clone(), None, None)
        }
        _ => (tool_name, tool_input.clone(), None, None),
    })
}

fn validate_workspaces(workspaces: Vec<String>, platform: Platform) -> Result<Vec<String>, String> {
    if workspaces.is_empty()
        || workspaces
            .iter()
            .any(|path| AbsolutePath::new(platform, path.clone()).is_err())
    {
        return Err("invalid-antigravity-workspaces".into());
    }
    Ok(workspaces)
}

fn workspace_for(path: Option<&str>, workspaces: &[String], platform: Platform) -> String {
    path.and_then(|path| {
        workspaces
            .iter()
            .filter(|workspace| contains(workspace, path, platform))
            .max_by_key(|workspace| workspace.len())
    })
    .unwrap_or(&workspaces[0])
    .clone()
}

fn contains(root: &str, path: &str, platform: Platform) -> bool {
    let normalize = |value: &str| {
        let value = value.replace('\\', "/");
        let value = value.trim_end_matches('/').to_owned();
        if platform == Platform::Windows {
            value.to_ascii_lowercase()
        } else {
            value
        }
    };
    let root = normalize(root);
    let path = normalize(path);
    path == root
        || path
            .strip_prefix(&root)
            .is_some_and(|rest| rest.starts_with('/'))
}

fn replacement_chunks(object: &Map<String, Value>) -> Result<Vec<Value>, String> {
    object
        .get("ReplacementChunks")
        .and_then(Value::as_array)
        .filter(|chunks| !chunks.is_empty())
        .ok_or_else(|| "invalid-antigravity-tool-input".to_owned())?
        .iter()
        .map(|chunk| {
            let chunk = chunk
                .as_object()
                .ok_or_else(|| "invalid-antigravity-tool-input".to_owned())?;
            optional_bool(chunk, "AllowMultiple")?;
            Ok(json!({
                "oldText":non_empty(chunk, "TargetContent")?,
                "newText":string(chunk, "ReplacementContent")?
            }))
        })
        .collect()
}

fn string(object: &Map<String, Value>, name: &str) -> Result<String, String> {
    object
        .get(name)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| "invalid-antigravity-tool-input".to_owned())
}

fn non_empty(object: &Map<String, Value>, name: &str) -> Result<String, String> {
    object
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| "invalid-antigravity-tool-input".to_owned())
}

fn absolute(object: &Map<String, Value>, name: &str, platform: Platform) -> Result<String, String> {
    let path = non_empty(object, name)?;
    AbsolutePath::new(platform, path.clone())
        .map(|_| path)
        .map_err(|_| "invalid-antigravity-tool-input".into())
}

fn optional_bool(object: &Map<String, Value>, name: &str) -> Result<Option<bool>, String> {
    match object.get(name) {
        Some(Value::Bool(value)) => Ok(Some(*value)),
        None => Ok(None),
        Some(_) => Err("invalid-antigravity-tool-input".into()),
    }
}

fn deny(reason: &str) -> Value {
    json!({"decision":"deny","reason":format!("nah - {reason}")})
}

#[cfg(test)]
mod tests {
    use super::*;

    fn native_path(path: &str) -> String {
        if cfg!(windows) {
            format!("C:{path}")
        } else {
            path.to_owned()
        }
    }

    fn native_paths(value: &mut Value) {
        match value {
            Value::String(path) if path.starts_with('/') => *path = native_path(path),
            Value::Array(values) => values.iter_mut().for_each(native_paths),
            Value::Object(object) => object.values_mut().for_each(native_paths),
            _ => {}
        }
    }

    fn normalized(name: &str, mut args: Value) -> ToolCallInput {
        native_paths(&mut args);
        normalize(AntigravityHookInput {
            tool_call: AntigravityToolCall {
                name: name.into(),
                args,
            },
            conversation_id: "conversation-1".into(),
            workspace_paths: vec![native_path("/repo"), native_path("/other")],
        })
        .unwrap()
    }

    #[test]
    fn normalizes_documented_antigravity_tools() {
        for (name, args, expected, cwd) in [
            (
                "run_command",
                json!({"CommandLine":"echo ok","Cwd":"/other"}),
                "Bash",
                "/other",
            ),
            (
                "view_file",
                json!({"AbsolutePath":"/other/src/lib.rs"}),
                "Read",
                "/other",
            ),
            (
                "write_to_file",
                json!({"TargetFile":"/repo/new.rs","CodeContent":"new"}),
                "Write",
                "/repo",
            ),
            (
                "replace_file_content",
                json!({
                    "TargetFile":"/repo/lib.rs",
                    "TargetContent":"old",
                    "ReplacementContent":"new",
                    "AllowMultiple":false
                }),
                "Edit",
                "/repo",
            ),
            (
                "multi_replace_file_content",
                json!({
                    "TargetFile":"/repo/lib.rs",
                    "ReplacementChunks":[
                        {"TargetContent":"a","ReplacementContent":"b"},
                        {"TargetContent":"c","ReplacementContent":"d","AllowMultiple":false}
                    ]
                }),
                "Edit",
                "/repo",
            ),
            (
                "list_dir",
                json!({"DirectoryPath":"/repo/src"}),
                "Ls",
                "/repo",
            ),
            (
                "find_by_name",
                json!({"SearchDirectory":"/repo","Pattern":"*.rs"}),
                "Find",
                "/repo",
            ),
            (
                "grep_search",
                json!({"SearchPath":"/repo","Query":"needle"}),
                "Grep",
                "/repo",
            ),
        ] {
            let call = normalized(name, args);
            assert_eq!(call.tool(), expected, "{name}");
            assert_eq!(call.cwd(), native_path(cwd), "{name}");
            assert_eq!(call.session(), Some("conversation-1"));
        }
    }

    #[test]
    fn unknown_tools_and_unsupported_task_actions_stay_opaque() {
        let unknown = normalized("call_mcp_tool", json!({"server":"db","tool":"query"}));
        assert_eq!(unknown.tool(), "call_mcp_tool");
        let task_input = json!({"Action":"send_input","TaskId":"task-1","Input":"rm -rf /"});
        let task = normalized("manage_task", task_input.clone());
        assert_eq!(task.tool(), "manage_task");
        assert_eq!(task.input(), &task_input);
        assert!(!task.normalization_complete());
    }

    #[test]
    fn malformed_known_tools_stay_opaque() {
        for (name, args) in [
            ("run_command", json!({"CommandLine":7,"Cwd":"/repo"})),
            ("view_file", json!({"AbsolutePath":"relative"})),
            (
                "write_to_file",
                json!({"TargetFile":"relative","CodeContent":"x"}),
            ),
            ("write_to_file", json!({"TargetFile":"","CodeContent":"x"})),
            (
                "replace_file_content",
                json!({"TargetFile":"/repo/x","TargetContent":"","ReplacementContent":"x"}),
            ),
            (
                "multi_replace_file_content",
                json!({"TargetFile":"/repo/x","ReplacementChunks":[]}),
            ),
            ("list_dir", json!({"DirectoryPath":7})),
            ("find_by_name", json!({"SearchDirectory":"/repo"})),
            ("grep_search", json!({"SearchPath":"/repo","Query":7})),
        ] {
            let mut expected = args.clone();
            native_paths(&mut expected);
            let call = normalized(name, args);
            assert_eq!(call.tool(), name);
            assert_eq!(call.input(), &expected);
            assert!(!call.normalization_complete());
        }
    }

    #[test]
    fn native_adapter_stays_contained() {
        let implementation = include_str!("antigravity_adapter.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        assert!(implementation.lines().count() <= 317);
    }
}
