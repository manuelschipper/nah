//! Which validated tool input the bridge analyzes, and as what engine subject:
//! a shell command, visible source in a supported language, or a native tool
//! call whose typed fields the engine models.

use nah_proto::effects;
use nah_proto::tool::ToolCallInput;

use super::{AdapterRefusal, RefusalKind, adapter_refusal};

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
pub(super) fn command_text(subject: &effinterp_proto::Subject) -> Option<&str> {
    match subject {
        effinterp_proto::Subject::Shell { source, .. } => Some(source),
        effinterp_proto::Subject::Source {
            source, language, ..
        } if language == "powershell" => Some(source),
        _ => None,
    }
}

/// The engine's typed tool call for a native tool's input, refusing fields the model does not know.
pub(super) fn native_subject(
    root: &ToolCallInput,
) -> Result<effinterp_proto::ToolCall, AdapterRefusal> {
    let unsupported = |code| adapter_refusal(root, RefusalKind::UnsupportedInput, code);
    let invalid = || adapter_refusal(root, RefusalKind::InvalidInput, "native-fields");
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
        "Delete" => effinterp_proto::ToolCall::FileDelete(effinterp_proto::FileDeleteArgs {
            path: string("file_path")?,
        }),
        "AmpUpload" => effinterp_proto::ToolCall::FileTransfer(effinterp_proto::FileTransferArgs {
            path: string("file_path")?,
            direction: effinterp_proto::TransferDirection::Upload,
        }),
        "AmpDownload" => {
            effinterp_proto::ToolCall::FileTransfer(effinterp_proto::FileTransferArgs {
                path: string("file_path")?,
                direction: effinterp_proto::TransferDirection::Download,
            })
        }
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
                Some(effinterp_proto::LineRange {
                    start_line,
                    end_line,
                })
            } else {
                None
            };
            effinterp_proto::ToolCall::FileRead(effinterp_proto::FileReadArgs {
                path: string("file_path")?,
                range,
            })
        }
        "Write" => effinterp_proto::ToolCall::FileWrite(effinterp_proto::FileWriteArgs {
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
                        Ok(effinterp_proto::FileEditEntry {
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
                effinterp_proto::ToolCall::FileEditBatch(effinterp_proto::FileEditBatchArgs {
                    path: string("file_path")?,
                    edits,
                })
            } else {
                let count = match object.get("replace_all") {
                    None | Some(serde_json::Value::Bool(false)) => Some(1),
                    Some(serde_json::Value::Bool(true)) => None,
                    _ => return Err(invalid()),
                };
                effinterp_proto::ToolCall::FileEdit(effinterp_proto::FileEditArgs {
                    path: string("file_path")?,
                    old: string("old_string")?,
                    new: string("new_string")?,
                    count,
                })
            }
        }
        "apply_patch" => effinterp_proto::ToolCall::FilePatch(effinterp_proto::FilePatchArgs {
            format: effinterp_proto::PatchFormat::ApplyPatch,
            text: string("command")?,
        }),
        "Ls" => effinterp_proto::ToolCall::FsList(effinterp_proto::FsListArgs {
            path: string("path")?,
        }),
        "Glob" => effinterp_proto::ToolCall::FsGlob(effinterp_proto::FsGlobArgs {
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
            effinterp_proto::ToolCall::FsGrep(effinterp_proto::FsGrepArgs {
                pattern: string("pattern").and_then(|pattern| {
                    (!pattern.is_empty()).then_some(pattern).ok_or_else(invalid)
                })?,
                paths: path.map(|path| vec![path]),
                root: None,
            })
        }
        "Find" => effinterp_proto::ToolCall::FsFind(effinterp_proto::FsFindArgs {
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
        _ => effinterp_proto::ToolCall::Unknown(effinterp_proto::UnknownToolArgs {
            name: root.tool().to_owned(),
            args: root.input().clone(),
        }),
    })
}

/// Native filesystem tools are explicit user requests. Search tools expose a
/// selected filesystem resource; they do not establish that file contents were
/// consumed by another program, so they remain filesystem access facts rather
/// than `ProgramInput` facts.
pub(super) fn native_access_purpose(subject: &effinterp_proto::Subject) -> effects::AccessPurpose {
    match subject {
        effinterp_proto::Subject::ToolCall {
            call:
                effinterp_proto::ToolCall::FileRead(_)
                | effinterp_proto::ToolCall::FileWrite(_)
                | effinterp_proto::ToolCall::FileTransfer(_)
                | effinterp_proto::ToolCall::FileEdit(_)
                | effinterp_proto::ToolCall::FilePatch(_)
                | effinterp_proto::ToolCall::FsGlob(_)
                | effinterp_proto::ToolCall::FsGrep(_)
                | effinterp_proto::ToolCall::FsList(_),
            ..
        } => effects::AccessPurpose::Explicit,
        _ => effects::AccessPurpose::Unknown,
    }
}
