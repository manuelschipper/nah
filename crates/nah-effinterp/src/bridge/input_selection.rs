//! Which validated tool input the bridge analyzes, and as what engine subject:
//! a shell command, visible source in a supported language, or a native tool
//! call whose typed fields the engine models.

use effinterp_proto as p;
use nah_proto::effects as e;
use nah_proto::tool::ToolCallInput;

use super::{AdapterRefusal, RefusalKind, refusal};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceLanguage {
    Python,
    JavaScript,
    TypeScript,
    Ipython,
    PowerShell,
    Pwsh,
    Cmd,
}

/// Validated runtime identity is retained independently of model support.
#[derive(Clone, Copy)]
pub enum SelectedInput<'a> {
    Shell(&'a ToolCallInput),
    Source {
        input: &'a ToolCallInput,
        source: &'a str,
        language: SourceLanguage,
    },
    Native(&'a ToolCallInput),
}
impl SelectedInput<'_> {
    pub fn input(&self) -> &ToolCallInput {
        match self {
            Self::Shell(input) | Self::Native(input) | Self::Source { input, .. } => input,
        }
    }
}

/// The command text the operator approves for a shell or PowerShell tool call,
/// as `plan_evidence` gave it to the engine; other subjects carry none.
pub(super) fn command_text(subject: &p::Subject) -> Option<&str> {
    match subject {
        p::Subject::Shell { source, .. } => Some(source),
        p::Subject::Source {
            source, language, ..
        } if language == "powershell" => Some(source),
        _ => None,
    }
}

/// The engine's typed tool call for a native tool's input, refusing fields the model does not know.
pub(super) fn native_subject(root: &ToolCallInput) -> Result<p::ToolCall, AdapterRefusal> {
    let unsupported = |code| refusal(root, RefusalKind::UnsupportedInput, code);
    let invalid = || refusal(root, RefusalKind::InvalidInput, "native-fields");
    let object = root.input().as_object().ok_or_else(invalid)?;
    let string = |key: &str| {
        object
            .get(key)
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .ok_or_else(invalid)
    };
    let allowed: Option<&[&str]> = match root.tool() {
        "Read" => Some(&["file_path", "offset", "limit"]),
        "Write" => Some(&["file_path", "content"]),
        "Delete" => Some(&["file_path"]),
        "Edit" => Some(&[
            "file_path",
            "old_string",
            "new_string",
            "replace_all",
            "edits",
        ]),
        "Glob" => Some(&["pattern", "path"]),
        "Grep" => Some(&["pattern", "path"]),
        "Find" => Some(&["pattern", "path", "limit"]),
        "AmpUpload" | "AmpDownload" => Some(&["file_path"]),
        "apply_patch" => Some(&["command"]),
        "Ls" => Some(&["path"]),
        _ => None,
    };
    if allowed.is_some_and(|allowed| object.keys().any(|key| !allowed.contains(&key.as_str()))) {
        return Err(unsupported("native-options"));
    }
    Ok(match root.tool() {
        "Delete" => p::ToolCall::FileDelete(p::FileDeleteArgs {
            path: string("file_path")?,
        }),
        "AmpUpload" => p::ToolCall::FileTransfer(p::FileTransferArgs {
            path: string("file_path")?,
            direction: p::TransferDirection::Upload,
        }),
        "AmpDownload" => p::ToolCall::FileTransfer(p::FileTransferArgs {
            path: string("file_path")?,
            direction: p::TransferDirection::Download,
        }),
        "process" | "OpenClawProcess" => return Err(unsupported("process-control")),
        "Read" => {
            let offset = object
                .get("offset")
                .map(|v| {
                    v.as_u64()
                        .and_then(|n| u32::try_from(n).ok())
                        .ok_or_else(invalid)
                })
                .transpose()?;
            let limit = object
                .get("limit")
                .map(|v| {
                    v.as_u64()
                        .and_then(|n| u32::try_from(n).ok())
                        .ok_or_else(invalid)
                })
                .transpose()?;
            let range = if offset.is_some() || limit.is_some() {
                let start_line = offset.unwrap_or(1);
                let end_line = limit
                    .map(|n| {
                        n.checked_sub(1)
                            .and_then(|n| start_line.checked_add(n))
                            .ok_or_else(invalid)
                    })
                    .transpose()?;
                Some(p::LineRange {
                    start_line,
                    end_line,
                })
            } else {
                None
            };
            p::ToolCall::FileRead(p::FileReadArgs {
                path: string("file_path")?,
                range,
            })
        }
        "Write" => p::ToolCall::FileWrite(p::FileWriteArgs {
            path: string("file_path")?,
            content: string("content")?,
        }),
        "Edit" => {
            if let Some(edits) = object.get("edits") {
                if object
                    .keys()
                    .any(|key| matches!(key.as_str(), "old_string" | "new_string" | "replace_all"))
                {
                    return Err(unsupported("native-batch-edit-mixed-fields"));
                }
                let edits = edits.as_array().ok_or_else(invalid)?;
                if edits.is_empty() {
                    return Err(invalid());
                }
                let edits = edits
                    .iter()
                    .map(|edit| {
                        let edit = edit.as_object().ok_or_else(invalid)?;
                        if edit
                            .keys()
                            .any(|key| !matches!(key.as_str(), "oldText" | "newText"))
                        {
                            return Err(unsupported("native-batch-edit-entry-options"));
                        }
                        Ok(p::FileEditEntry {
                            old: edit
                                .get("oldText")
                                .and_then(|value| value.as_str())
                                .map(str::to_owned)
                                .ok_or_else(invalid)?,
                            new: edit
                                .get("newText")
                                .and_then(|value| value.as_str())
                                .map(str::to_owned)
                                .ok_or_else(invalid)?,
                        })
                    })
                    .collect::<Result<Vec<_>, AdapterRefusal>>()?;
                p::ToolCall::FileEditBatch(p::FileEditBatchArgs {
                    path: string("file_path")?,
                    edits,
                })
            } else {
                let count = match object.get("replace_all") {
                    None | Some(serde_json::Value::Bool(false)) => Some(1),
                    Some(serde_json::Value::Bool(true)) => None,
                    _ => return Err(invalid()),
                };
                p::ToolCall::FileEdit(p::FileEditArgs {
                    path: string("file_path")?,
                    old: string("old_string")?,
                    new: string("new_string")?,
                    count,
                })
            }
        }
        "apply_patch" => p::ToolCall::FilePatch(p::FilePatchArgs {
            format: p::PatchFormat::ApplyPatch,
            text: string("command")?,
        }),
        "Ls" => p::ToolCall::FsList(p::FsListArgs {
            path: string("path")?,
        }),
        "Glob" => p::ToolCall::FsGlob(p::FsGlobArgs {
            pattern: string("pattern")
                .and_then(|pattern| (!pattern.is_empty()).then_some(pattern).ok_or_else(invalid))?,
            root: object
                .get("path")
                .map(|value| {
                    value
                        .as_str()
                        .filter(|path| !path.is_empty())
                        .map(str::to_owned)
                        .ok_or_else(invalid)
                })
                .transpose()?,
        }),
        "Grep" => {
            let path = object
                .get("path")
                .map(|value| {
                    value
                        .as_str()
                        .filter(|path| !path.is_empty())
                        .map(str::to_owned)
                        .ok_or_else(invalid)
                })
                .transpose()?;
            p::ToolCall::FsGrep(p::FsGrepArgs {
                pattern: string("pattern").and_then(|pattern| {
                    (!pattern.is_empty()).then_some(pattern).ok_or_else(invalid)
                })?,
                paths: path.map(|path| vec![path]),
                root: None,
            })
        }
        "Find" => p::ToolCall::FsFind(p::FsFindArgs {
            pattern: string("pattern")
                .and_then(|pattern| (!pattern.is_empty()).then_some(pattern).ok_or_else(invalid))?,
            root: string("path")
                .and_then(|path| (!path.is_empty()).then_some(path).ok_or_else(invalid))?,
            limit: object
                .get("limit")
                .map(|value| {
                    value
                        .as_u64()
                        .and_then(|value| u32::try_from(value).ok())
                        .ok_or_else(invalid)
                })
                .transpose()?,
        }),
        _ => p::ToolCall::Unknown(p::UnknownToolArgs {
            name: root.tool().to_owned(),
            args: root.input().clone(),
        }),
    })
}

/// Native filesystem tools are explicit user requests. Search tools expose a
/// selected filesystem resource; they do not establish that file contents were
/// consumed by another program, so they remain filesystem access facts rather
/// than `ProgramInput` facts.
pub(super) fn native_access_purpose(subject: &p::Subject) -> e::AccessPurpose {
    match subject {
        p::Subject::ToolCall {
            call:
                p::ToolCall::FileRead(_)
                | p::ToolCall::FileWrite(_)
                | p::ToolCall::FileTransfer(_)
                | p::ToolCall::FileEdit(_)
                | p::ToolCall::FilePatch(_)
                | p::ToolCall::FsGlob(_)
                | p::ToolCall::FsGrep(_)
                | p::ToolCall::FsList(_),
            ..
        } => e::AccessPurpose::Explicit,
        _ => e::AccessPurpose::Unknown,
    }
}
