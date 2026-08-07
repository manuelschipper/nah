//! Lowers typed native tool calls into planned effects; it performs no host I/O.

use nah_proto::action::{FilesystemOperation, InvocationInput};
use nah_proto::ctx::Platform;
use nah_proto::tool::{CallSite, ToolCallInput};

use crate::INVOCATION_EVIDENCE_CAP;
use crate::codex_patch;
use crate::paths::{join, literal_relative_path};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Draft {
    Native {
        tool: String,
        operation: &'static str,
        filesystem_operation: FilesystemOperation,
        requested_path: String,
        recursive: bool,
        requires_file: bool,
        complete: bool,
        network: bool,
        input: InvocationInput,
    },
    Patch {
        effects: Vec<codex_patch::PatchEffect>,
        input: InvocationInput,
        complete: bool,
    },
    Opaque {
        tool: String,
        input: InvocationInput,
        complete: bool,
    },
    Unsupported,
}

pub(crate) fn draft(input: &ToolCallInput, call_site: &CallSite, platform: Platform) -> Draft {
    let Some(object) = input.input().as_object() else {
        return Draft::Unsupported;
    };
    let string = |name: &str| object.get(name).and_then(|value| value.as_str());
    let file_path = || string("file_path").filter(|value| !value.is_empty());
    let native = |operation,
                  filesystem_operation,
                  requested_path: &str,
                  recursive,
                  requires_file,
                  allowed_fields: &[&str]| {
        let invocation_input = invocation_input(input);
        Draft::Native {
            tool: input.tool().into(),
            operation,
            filesystem_operation,
            requested_path: requested_path.into(),
            recursive,
            requires_file,
            complete: input.normalization_complete()
                && only_fields(input, allowed_fields)
                && invocation_input.complete(),
            network: false,
            input: invocation_input,
        }
    };

    match input.tool() {
        "Read" => match file_path() {
            Some(path) => native(
                "read",
                FilesystemOperation::Read,
                path,
                false,
                false,
                &["file_path", "offset", "limit"],
            ),
            None => Draft::Unsupported,
        },
        "Write" => match (file_path(), string("content")) {
            (Some(path), Some(_)) => native(
                "write",
                FilesystemOperation::Write,
                path,
                false,
                false,
                &["file_path", "content"],
            ),
            _ => Draft::Unsupported,
        },
        "Delete" => match file_path() {
            Some(path) => native(
                "delete",
                FilesystemOperation::Delete,
                path,
                false,
                false,
                &["file_path"],
            ),
            None => Draft::Unsupported,
        },
        "Edit" => {
            let replace_all_valid = object
                .get("replace_all")
                .is_none_or(|value| value.is_boolean());
            let claude_input = matches!(
                (
                    file_path(),
                    string("old_string"),
                    string("new_string"),
                    replace_all_valid,
                ),
                (Some(_), Some(_), Some(_), true)
            );
            let pi_input = object
                .get("edits")
                .and_then(|value| value.as_array())
                .is_some_and(|edits| {
                    !edits.is_empty()
                        && edits.iter().all(|edit| {
                            edit.as_object().is_some_and(|edit| {
                                edit.get("oldText").is_some_and(|value| value.is_string())
                                    && edit.get("newText").is_some_and(|value| value.is_string())
                            })
                        })
                });
            match (file_path(), claude_input || pi_input) {
                (Some(path), true) => native(
                    "edit",
                    FilesystemOperation::Write,
                    path,
                    false,
                    false,
                    &[
                        "file_path",
                        "old_string",
                        "new_string",
                        "replace_all",
                        "edits",
                    ],
                ),
                _ => Draft::Unsupported,
            }
        }
        "Find" => {
            if string("pattern").is_none() {
                return Draft::Unsupported;
            }
            match string("path").filter(|path| !path.is_empty()) {
                Some(path) => native(
                    "find",
                    FilesystemOperation::Read,
                    path,
                    true,
                    false,
                    &["pattern", "path", "limit"],
                ),
                None => Draft::Unsupported,
            }
        }
        "Ls" => match string("path").filter(|path| !path.is_empty()) {
            Some(path) => native(
                "ls",
                FilesystemOperation::Read,
                path,
                false,
                false,
                &["path", "depth"],
            ),
            None => Draft::Unsupported,
        },
        "Glob" => {
            let Some(pattern) = string("pattern") else {
                return Draft::Unsupported;
            };
            if !literal_relative_path(pattern, platform) {
                return Draft::Unsupported;
            }
            let base = match object.get("path") {
                None => call_site.requested_cwd().as_str(),
                Some(value) => match value.as_str().filter(|path| !path.is_empty()) {
                    Some(path) => path,
                    None => return Draft::Unsupported,
                },
            };
            native(
                "glob",
                FilesystemOperation::Read,
                &join(base, pattern, platform),
                false,
                true,
                &["pattern", "path"],
            )
        }
        "Grep" => {
            let Some(_pattern) = string("pattern") else {
                return Draft::Unsupported;
            };
            let path = match object.get("path") {
                None => call_site.requested_cwd().as_str(),
                Some(value) => match value.as_str().filter(|path| !path.is_empty()) {
                    Some(path) => path,
                    None => return Draft::Unsupported,
                },
            };
            native(
                "grep",
                FilesystemOperation::Read,
                path,
                false,
                true,
                &[
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
            )
        }
        "apply_patch" => match string("command").and_then(codex_patch::effects) {
            Some(effects) => {
                let invocation_input = invocation_input(input);
                Draft::Patch {
                    effects,
                    complete: input.normalization_complete()
                        && only_fields(input, &["command"])
                        && invocation_input.complete(),
                    input: invocation_input,
                }
            }
            None => Draft::Unsupported,
        },
        "AmpUpload" => match file_path() {
            Some(path) => Draft::Native {
                tool: input.tool().into(),
                operation: "network-transfer",
                filesystem_operation: FilesystemOperation::Read,
                requested_path: path.into(),
                recursive: false,
                requires_file: true,
                complete: false,
                network: true,
                input: invocation_input(input),
            },
            None => Draft::Unsupported,
        },
        "AmpDownload" => match file_path() {
            Some(path) => Draft::Native {
                tool: input.tool().into(),
                operation: "network-transfer",
                filesystem_operation: FilesystemOperation::Write,
                requested_path: path.into(),
                recursive: false,
                requires_file: false,
                complete: false,
                network: true,
                input: invocation_input(input),
            },
            None => Draft::Unsupported,
        },
        _ => Draft::Opaque {
            tool: input.tool().into(),
            input: invocation_input(input),
            complete: input.normalization_complete(),
        },
    }
}

pub(crate) fn invocation_input(input: &ToolCallInput) -> InvocationInput {
    let value = input.invocation_input();
    if value.to_string().len() <= INVOCATION_EVIDENCE_CAP {
        InvocationInput::native(value.clone(), true)
    } else {
        let mut omitted = input.input().clone();
        omitted
            .as_object_mut()
            .expect("native drafts require object input")
            .clear();
        InvocationInput::native(omitted, false)
    }
}

fn only_fields(input: &ToolCallInput, allowed: &[&str]) -> bool {
    input
        .input()
        .as_object()
        .expect("native drafts require object input")
        .keys()
        .all(|field| allowed.contains(&field.as_str()))
}
