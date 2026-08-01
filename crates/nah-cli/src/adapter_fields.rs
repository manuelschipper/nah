//! Declares the runtime fields preserved by each documented tool adapter.

use serde_json::Value;

pub(crate) fn complete(runtime: &str, tool: &str, input: &Value) -> bool {
    let allowed: &[&str] = match (runtime, tool) {
        ("amp", "shell_command") => &["command", "workdir", "timeout_ms"],
        ("amp", "apply_patch") => &["patchText"],
        ("amp", "create_file") => &["path", "content"],
        ("amp", "edit_file") => &["path", "old_str", "new_str", "replace_all"],
        ("amp", "upload_thread_file") => &["path"],
        ("amp", "download_thread_file") => &["destination"],
        ("antigravity", "run_command") => &["CommandLine", "Cwd"],
        ("antigravity", "view_file") => &["AbsolutePath"],
        ("antigravity", "write_to_file") => &["TargetFile", "CodeContent"],
        ("antigravity", "replace_file_content") => &[
            "TargetFile",
            "TargetContent",
            "ReplacementContent",
            "AllowMultiple",
        ],
        ("antigravity", "multi_replace_file_content") => &["TargetFile", "ReplacementChunks"],
        ("antigravity", "list_dir") => &["DirectoryPath"],
        ("antigravity", "find_by_name") => &["SearchDirectory", "Pattern"],
        ("antigravity", "grep_search") => &["SearchPath", "Query"],
        ("cline", "execute_command") => &["command"],
        ("cline", "run_commands") => &["commands", "command", "cmd", "args"],
        ("cline", "read_file") => &["path", "file_path"],
        ("cline", "read_files") => &["files", "paths", "file_paths"],
        ("cline", "write_to_file") => &["path", "file_path", "content"],
        ("cline", "replace_in_file") => &["path", "file_path", "diff"],
        ("cline", "editor") => &["path", "old_text", "new_text"],
        ("cline", "apply_patch") => &["input"],
        ("cline", "search_files") => &["path", "regex", "pattern"],
        ("cline", "search_codebase") => &["queries"],
        ("cline", "list_files" | "list_code_definition_names") => &["path"],
        ("copilot", "bash" | "Bash" | "runTerminalCommand" | "run_in_terminal") => {
            &["command", "cwd"]
        }
        ("copilot", "view" | "Read" | "readFile" | "read_file") => {
            &["path", "filePath", "file_path", "offset", "limit"]
        }
        ("copilot", "create" | "Write" | "createFile" | "create_file") => {
            &["path", "filePath", "file_path", "file_text", "content"]
        }
        ("copilot", "edit" | "str_replace_editor" | "replaceString" | "replace_string_in_file") => {
            &[
                "path",
                "filePath",
                "file_path",
                "old_str",
                "oldString",
                "old_string",
                "new_str",
                "newString",
                "new_string",
            ]
        }
        ("copilot", "grep" | "rg" | "Grep" | "grepSearch" | "grep_search") => {
            &["pattern", "query", "path", "filePath", "file_path"]
        }
        ("copilot", "glob" | "Glob" | "fileSearch" | "file_search") => &["pattern", "query"],
        ("cursor", "Shell") => &["command", "cwd", "working_directory"],
        ("cursor", "Read" | "Delete" | "List") => &["file_path"],
        ("cursor", "Write") => &["file_path", "content"],
        ("cursor", "Grep") => &["pattern", "file_path"],
        ("devin", "exec") => &["command"],
        ("devin", "read") => &["file_path"],
        ("devin", "write") => &["file_path", "content"],
        ("devin", "edit") => &["file_path", "old_string", "new_string", "replace_all"],
        ("devin", "grep" | "glob") => &["pattern", "query", "path", "file_path"],
        ("droid", "Execute") => &["command", "riskLevel"],
        ("droid", "Read") => &["file_path", "offset", "limit"],
        ("droid", "Create") => &["file_path", "content"],
        ("droid", "Edit") => &["file_path", "old_str", "new_str", "change_all", "changes"],
        ("droid", "ApplyPatch") => &["input"],
        ("droid", "Grep") => &["pattern", "path", "output_mode"],
        ("droid", "Glob") => &["patterns", "folder", "excludePatterns"],
        ("droid", "LS") => &["directory_path", "ignorePatterns"],
        ("hermes", "terminal") => &["command", "workdir"],
        ("hermes", "read_file") => &["path", "offset", "limit"],
        ("hermes", "write_file") => &["path", "content"],
        ("hermes", "patch") => &[
            "mode",
            "path",
            "old_string",
            "new_string",
            "replace_all",
            "patch",
        ],
        ("hermes", "search_files") => &["target", "pattern", "path"],
        ("kiro", "shell" | "execute_bash" | "execute_cmd") => &["command"],
        ("openclaw", "exec") => &["command"],
        ("openclaw", "read") => &["path", "offset", "limit"],
        ("openclaw", "write") => &["path", "content"],
        ("openclaw", "edit") => &["path", "edits"],
        ("openclaw", "apply_patch") => &["input"],
        ("openclaw", "grep" | "find") => &["pattern", "path"],
        ("openclaw", "ls") => &["path", "depth"],
        ("opencode", "bash") => &["command"],
        ("opencode", "read") => &["filePath", "offset", "limit"],
        ("opencode", "write") => &["filePath", "content"],
        ("opencode", "edit") => &["filePath", "oldString", "newString", "replaceAll"],
        ("opencode", "apply_patch") => &["patchText"],
        ("opencode", "glob" | "grep") => &["pattern", "path"],
        ("pi", "bash") => &["command"],
        ("pi", "read") => &["path", "offset", "limit"],
        ("pi", "write") => &["path", "content"],
        ("pi", "edit") => &["path", "edits"],
        ("pi", "grep") => &["pattern", "path", "glob", "limit"],
        ("pi", "find") => &["pattern", "path", "limit"],
        ("pi", "ls") => &["path", "depth"],
        _ => return true,
    };
    only_fields(input, allowed)
        && match (runtime, tool) {
            ("antigravity", "multi_replace_file_content") => array_fields(
                input.get("ReplacementChunks"),
                &["TargetContent", "ReplacementContent", "AllowMultiple"],
            ),
            ("droid", "Edit") => {
                array_fields(input.get("changes"), &["old_str", "new_str", "change_all"])
            }
            ("openclaw" | "pi", "edit") => {
                array_fields(input.get("edits"), &["oldText", "newText"])
            }
            _ => true,
        }
}

fn only_fields(input: &Value, allowed: &[&str]) -> bool {
    input
        .as_object()
        .is_some_and(|object| object.keys().all(|field| allowed.contains(&field.as_str())))
}

fn array_fields(input: Option<&Value>, allowed: &[&str]) -> bool {
    input.is_none_or(|input| {
        input
            .as_array()
            .is_some_and(|items| items.iter().all(|item| only_fields(item, allowed)))
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::complete;

    #[test]
    fn every_runtime_rejects_an_unknown_field_for_a_documented_tool() {
        for (runtime, tool, input) in [
            ("amp", "shell_command", json!({"command":"pwd"})),
            (
                "antigravity",
                "run_command",
                json!({"CommandLine":"pwd","Cwd":"/repo"}),
            ),
            ("cline", "execute_command", json!({"command":"pwd"})),
            ("copilot", "bash", json!({"command":"pwd"})),
            ("cursor", "Shell", json!({"command":"pwd"})),
            ("devin", "exec", json!({"command":"pwd"})),
            ("droid", "Execute", json!({"command":"pwd"})),
            ("hermes", "terminal", json!({"command":"pwd"})),
            ("kiro", "execute_bash", json!({"command":"pwd"})),
            ("openclaw", "exec", json!({"command":"pwd"})),
            ("opencode", "bash", json!({"command":"pwd"})),
            ("pi", "bash", json!({"command":"pwd"})),
        ] {
            assert!(complete(runtime, tool, &input), "{runtime}");
            let mut unknown = input;
            unknown["futureBehavior"] = json!("execute");
            assert!(!complete(runtime, tool, &unknown), "{runtime}");
        }
    }
}
