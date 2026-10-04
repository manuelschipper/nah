//! Declares the runtime fields preserved by each documented tool adapter, and
//! the tool input field readers the adapters share. Each reader returns the
//! calling adapter's `invalid-<runtime>-tool-input` error code as `invalid`.

use serde_json::{Map, Value};

/// Checks field-name coverage for listed runtime/tool pairs, including modeled
/// nested fields. Missing known fields are permitted; unlisted pairs return true.
/// Adapters separately validate required fields and value types. This result alone
/// does not establish that the input is a valid tool invocation.
pub(crate) fn runtime_field_names_covered(runtime: &str, tool: &str, input: &Value) -> bool {
    let allowed: &[&str] = match (runtime, tool) {
        ("claude" | "codex", "Bash") => &["command", "description", "timeout", "run_in_background"],
        ("claude" | "codex", "Read") => &["file_path", "offset", "limit", "pages"],
        ("claude" | "codex", "Write") => &["file_path", "content"],
        ("claude" | "codex", "Delete") => &["file_path"],
        ("claude" | "codex", "Edit") => &[
            "file_path",
            "old_string",
            "new_string",
            "replace_all",
            "edits",
        ],
        ("claude" | "codex", "Find") => &["pattern", "path", "limit"],
        ("claude" | "codex", "Ls") => &["path", "depth"],
        ("claude" | "codex", "Glob") => &["pattern", "path"],
        ("claude" | "codex", "Grep") => &[
            "pattern",
            "path",
            "glob",
            "output_mode",
            "-A",
            "-B",
            "-C",
            "context",
            "line_numbers",
            "case_insensitive",
            "type",
            "head_limit",
            "offset",
            "multiline",
        ],
        ("claude" | "codex", "apply_patch") => &["command"],
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
        ("hermes", "terminal") => &["command", "timeout", "workdir"],
        ("hermes", "read_file") => &["path", "offset", "limit"],
        ("hermes", "write_file") => &["path", "content", "cross_profile"],
        ("hermes", "patch") => &[
            "mode",
            "path",
            "old_string",
            "new_string",
            "replace_all",
            "patch",
            "cross_profile",
        ],
        ("hermes", "search_files") => &[
            "target",
            "pattern",
            "path",
            "file_glob",
            "limit",
            "offset",
            "output_mode",
            "context",
            "order",
        ],
        ("hermes", "execute_code") => &["code"],
        ("kiro", "shell" | "execute_bash" | "execute_cmd") => &["command"],
        ("openclaw", "exec") => &["command"],
        ("openclaw", "read") => &["path", "offset", "limit"],
        ("openclaw", "write") => &["path", "content"],
        ("openclaw", "edit") => &["path", "edits"],
        ("openclaw", "apply_patch") => &["input"],
        ("openclaw", "grep" | "find") => &["pattern", "path"],
        ("openclaw", "ls") => &["path", "depth"],
        ("opencode", "shell") => &["command", "workdir", "timeout", "background"],
        ("opencode", "read") => &["path", "offset", "limit"],
        ("opencode", "write") => &["path", "content"],
        ("opencode", "edit") => &["path", "oldString", "newString", "replaceAll"],
        ("opencode", "patch") => &["patchText"],
        // The lowering keeps only `pattern` and `path`. Dropping `include`
        // widens the read, and the rest select matches or output, not files.
        ("opencode", "glob") => &["pattern", "path", "hidden", "limit"],
        ("opencode", "grep") => &[
            "pattern",
            "path",
            "include",
            "literal",
            "caseSensitive",
            "limit",
        ],
        ("pi", "bash") => &["command", "timeout"],
        ("pi", "read") => &["path", "offset", "limit"],
        ("pi", "write") => &["path", "content"],
        ("pi", "edit") => &["path", "edits"],
        ("pi", "grep") => &["pattern", "path", "glob", "limit"],
        ("pi", "find") => &["pattern", "path", "limit"],
        ("pi", "ls") => &["path", "depth"],
        ("prime-agent", "ipython") => &["code"],
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
            // Nah reads a glob's leading `*` as skipping hidden entries, so
            // `hidden: true` would select files Nah does not model.
            // Neither option changes what the command does.
            ("opencode", "shell") => {
                input.get("timeout").is_none_or(Value::is_u64)
                    && input.get("background").is_none_or(Value::is_boolean)
            }
            ("opencode", "glob") => matches!(input.get("hidden"), None | Some(Value::Bool(false))),
            // Pi's time limit in seconds does not change what the command does.
            ("pi", "bash") => input.get("timeout").is_none_or(Value::is_number),
            ("openclaw" | "pi", "edit") => {
                array_fields(input.get("edits"), &["oldText", "newText"])
            }
            _ => true,
        }
}

/// Reads a runtime tool input as a JSON object.
pub(crate) fn tool_input_object<'a>(
    input: &'a Value,
    invalid: &str,
) -> Result<&'a Map<String, Value>, String> {
    input.as_object().ok_or_else(|| invalid.to_owned())
}

/// Reads a required tool input field that must be a string; it may be empty.
pub(crate) fn tool_input_string(
    object: &Map<String, Value>,
    name: &str,
    invalid: &str,
) -> Result<String, String> {
    object
        .get(name)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| invalid.to_owned())
}

/// Reads a required tool input field that must be a non-empty string.
pub(crate) fn tool_input_non_empty_string(
    object: &Map<String, Value>,
    name: &str,
    invalid: &str,
) -> Result<String, String> {
    tool_input_string(object, name, invalid).and_then(|value| {
        if value.is_empty() {
            Err(invalid.into())
        } else {
            Ok(value)
        }
    })
}

/// Reads an optional string tool input field. A missing field and an empty
/// string are both `None`; any other type, including null, is invalid.
pub(crate) fn tool_input_optional_non_empty_string(
    object: &Map<String, Value>,
    name: &str,
    invalid: &str,
) -> Result<Option<String>, String> {
    match object.get(name) {
        Some(Value::String(value)) if !value.is_empty() => Ok(Some(value.clone())),
        Some(Value::String(_)) | None => Ok(None),
        Some(_) => Err(invalid.into()),
    }
}

/// Reads an optional boolean tool input field. A missing field is `None`; any
/// other type, including null, is invalid.
pub(crate) fn tool_input_optional_bool(
    object: &Map<String, Value>,
    name: &str,
    invalid: &str,
) -> Result<Option<bool>, String> {
    match object.get(name) {
        Some(Value::Bool(value)) => Ok(Some(*value)),
        None => Ok(None),
        Some(_) => Err(invalid.into()),
    }
}

/// Reads the required `edits` tool input field that OpenClaw and Pi send: a
/// non-empty array of text edits, each an object whose `oldText` and `newText`
/// are strings. Returns the array unchanged.
pub(crate) fn tool_input_text_edits(
    object: &Map<String, Value>,
    invalid: &str,
) -> Result<Value, String> {
    let edits = object
        .get("edits")
        .and_then(Value::as_array)
        .filter(|edits| !edits.is_empty())
        .ok_or_else(|| invalid.to_owned())?;
    edits
        .iter()
        .all(|edit| {
            edit.as_object().is_some_and(|edit| {
                edit.get("oldText").is_some_and(Value::is_string)
                    && edit.get("newText").is_some_and(Value::is_string)
            })
        })
        .then(|| Value::Array(edits.clone()))
        .ok_or_else(|| invalid.to_owned())
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

    use super::runtime_field_names_covered;

    #[test]
    fn every_runtime_rejects_an_unknown_field_for_a_documented_tool() {
        for (runtime, tool, input) in [
            ("claude", "Read", json!({"file_path":"file"})),
            ("codex", "Read", json!({"file_path":"file"})),
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
            ("opencode", "shell", json!({"command":"pwd"})),
            ("pi", "bash", json!({"command":"pwd"})),
            ("prime-agent", "ipython", json!({"code":"print('ok')"})),
        ] {
            assert!(
                runtime_field_names_covered(runtime, tool, &input),
                "{runtime}"
            );
            let mut unknown = input;
            unknown["futureBehavior"] = json!("execute");
            assert!(
                !runtime_field_names_covered(runtime, tool, &unknown),
                "{runtime}"
            );
        }
    }
}
