//! Parses Codex's apply_patch envelope into filesystem operations; it does not apply patches.

use nah_proto::action::FilesystemOperation;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PatchEffect {
    pub(crate) operation: FilesystemOperation,
    pub(crate) requested_path: String,
}

enum Mode {
    Started,
    Add(String),
    Delete(String),
    Update {
        path: String,
        move_path: Option<String>,
        has_lines: bool,
        current_chunk_has_lines: Option<bool>,
        after_eof: bool,
    },
    Ended,
}

enum Header<'a> {
    End,
    Add(&'a str),
    Delete(&'a str),
    Update(&'a str),
    Move(&'a str, &'a str),
}

pub(crate) fn effects(command: &str) -> Option<Vec<PatchEffect>> {
    let lines = patch_lines(command)?;
    let mut mode = Mode::Started;
    let mut effects = Vec::new();

    for line in &lines[1..] {
        let header_line = match mode {
            Mode::Update { .. } => line.trim_end(),
            _ => line.trim(),
        };
        if let Some(header) = header(header_line) {
            finish(mode, &mut effects)?;
            mode = match header {
                Header::End => Mode::Ended,
                Header::Add(path) => Mode::Add(owned_path(path)?),
                Header::Delete(path) => Mode::Delete(owned_path(path)?),
                Header::Move(path, destination) => {
                    effects.push(PatchEffect {
                        operation: FilesystemOperation::Delete,
                        requested_path: owned_path(path)?,
                    });
                    effects.push(PatchEffect {
                        operation: FilesystemOperation::Write,
                        requested_path: owned_path(destination)?,
                    });
                    Mode::Started
                }
                Header::Update(path) => Mode::Update {
                    path: owned_path(path)?,
                    move_path: None,
                    has_lines: false,
                    current_chunk_has_lines: None,
                    after_eof: false,
                },
            };
            continue;
        }

        mode = match mode {
            Mode::Started if line.trim().starts_with("*** Environment ID:") => return None,
            Mode::Started | Mode::Delete(_) | Mode::Ended => return None,
            Mode::Add(path) if line.starts_with('+') => Mode::Add(path),
            Mode::Add(_) => return None,
            Mode::Update {
                path,
                mut move_path,
                mut has_lines,
                mut current_chunk_has_lines,
                mut after_eof,
            } => {
                let line = line.trim_end();
                if !has_lines
                    && current_chunk_has_lines.is_none()
                    && move_path.is_none()
                    && let Some(destination) = line.strip_prefix("*** Move to: ")
                {
                    move_path = Some(owned_path(destination)?);
                } else if line == "@@" || line.starts_with("@@ ") {
                    if current_chunk_has_lines == Some(false) {
                        return None;
                    }
                    current_chunk_has_lines = Some(false);
                    after_eof = false;
                } else if line == "*** End of File" {
                    if current_chunk_has_lines != Some(true) {
                        return None;
                    }
                    after_eof = true;
                } else if after_eof && line.is_empty() {
                } else if line.is_empty()
                    || line.starts_with(' ')
                    || line.starts_with('+')
                    || line.starts_with('-')
                {
                    has_lines = true;
                    current_chunk_has_lines = Some(true);
                    after_eof = false;
                } else {
                    return None;
                }
                Mode::Update {
                    path,
                    move_path,
                    has_lines,
                    current_chunk_has_lines,
                    after_eof,
                }
            }
        };
    }

    matches!(mode, Mode::Ended).then_some(effects)
}

fn patch_lines(command: &str) -> Option<Vec<&str>> {
    let lines = command.trim().lines().collect::<Vec<_>>();
    let lines = match lines.as_slice() {
        [first, .., last]
            if matches!(first.trim(), "<<EOF" | "<<'EOF'" | "<<\"EOF\"")
                && last.trim_end().ends_with("EOF")
                && lines.len() >= 4 =>
        {
            &lines[1..lines.len() - 1]
        }
        _ => lines.as_slice(),
    };
    (lines.first()?.trim() == "*** Begin Patch").then(|| lines.to_vec())
}

fn header(line: &str) -> Option<Header<'_>> {
    if line == "*** End Patch" {
        Some(Header::End)
    } else if let Some(path) = line.strip_prefix("*** Add File: ") {
        Some(Header::Add(path))
    } else if let Some(path) = line.strip_prefix("*** Delete File: ") {
        Some(Header::Delete(path))
    } else if let Some(paths) = line.strip_prefix("*** Move File: ") {
        paths
            .split_once(" -> ")
            .map(|(path, destination)| Header::Move(path, destination))
    } else {
        line.strip_prefix("*** Update File: ").map(Header::Update)
    }
}

fn owned_path(path: &str) -> Option<String> {
    (!path.is_empty()).then(|| path.to_owned())
}

fn finish(mode: Mode, effects: &mut Vec<PatchEffect>) -> Option<()> {
    let mut push = |operation, requested_path| {
        effects.push(PatchEffect {
            operation,
            requested_path,
        });
    };
    match mode {
        Mode::Started => {}
        Mode::Add(path) => push(FilesystemOperation::Write, path),
        Mode::Delete(path) => push(FilesystemOperation::Delete, path),
        Mode::Update {
            path,
            move_path,
            has_lines: true,
            current_chunk_has_lines: Some(true),
            ..
        } => match move_path {
            Some(destination) => {
                push(FilesystemOperation::Delete, path);
                push(FilesystemOperation::Write, destination);
            }
            None => push(FilesystemOperation::Write, path),
        },
        Mode::Update { .. } | Mode::Ended => return None,
    }
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_every_filesystem_operation_without_mistaking_content_for_headers() {
        let patch = "\
*** Begin Patch
*** Add File: added
+*** Delete File: only-content
*** Update File: old
*** Move to: moved
@@
-old
+new
 *** Add File: also-content
*** Delete File: deleted
*** Move File: moved-again -> final
*** End Patch";
        assert_eq!(
            effects(patch),
            Some(vec![
                PatchEffect {
                    operation: FilesystemOperation::Write,
                    requested_path: "added".into(),
                },
                PatchEffect {
                    operation: FilesystemOperation::Delete,
                    requested_path: "old".into(),
                },
                PatchEffect {
                    operation: FilesystemOperation::Write,
                    requested_path: "moved".into(),
                },
                PatchEffect {
                    operation: FilesystemOperation::Delete,
                    requested_path: "deleted".into(),
                },
                PatchEffect {
                    operation: FilesystemOperation::Delete,
                    requested_path: "moved-again".into(),
                },
                PatchEffect {
                    operation: FilesystemOperation::Write,
                    requested_path: "final".into(),
                },
            ])
        );
    }

    #[test]
    fn accepts_codex_line_endings_and_legacy_heredoc_but_rejects_unknown_contexts() {
        assert!(effects(
            "<<'EOF'\r\n*** Begin Patch\r\n*** Add File: file\r\n+line\r\n*** End Patch\r\nEOF\r\n"
        )
        .is_some());
        for patch in [
            "*** Begin Patch\n*** Environment ID: remote\n*** Add File: file\n+x\n*** End Patch",
            "*** Begin Patch\n*** Update File: file\n@@\n*** End Patch",
            "*** Begin Patch\n*** Frobnicate File: file\n*** End Patch",
            "*** Begin Patch\n*** Add File: file\n+x\n*** End Patch\nextra",
        ] {
            assert_eq!(effects(patch), None, "{patch}");
        }
    }
}
