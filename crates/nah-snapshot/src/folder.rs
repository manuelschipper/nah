//! Lists a folder that is not a git work tree: every file, outside skip-list
//! folders and repositories nested in it.

use crate::manifest::{NotSaved, NotSavedReason, Origin};
use crate::{Candidate, Context, Refusal, SKIP_LIST, Scan};
use std::fs;
use std::path::Path;
use std::time::Instant;

pub(crate) fn scan(context: &Context, root: &Path, deadline: Instant) -> Result<Scan, Refusal> {
    let mut scan = Scan::default();
    let mut not_saved = Vec::new();
    walk(
        root,
        deadline,
        &mut |path| {
            scan.candidates
                .push(Candidate::untracked(&path, Origin::Folder))
        },
        &mut |skipped| not_saved.push(skipped),
    )?;
    scan.not_saved = not_saved;
    scan.leave_out_secrets(context, root)?;
    Ok(scan)
}

/// [`scan`] of only what lies under `subtrees`, relative to `root`: a file
/// or link among them is listed itself, and a missing one holds nothing.
pub(crate) fn scan_subtrees(
    context: &Context,
    root: &Path,
    subtrees: &[String],
    deadline: Instant,
) -> Result<Scan, Refusal> {
    let mut scan = Scan::default();
    let mut not_saved = Vec::new();
    for subtree in subtrees {
        let path = root.join(subtree);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(Refusal::Unreadable {
                    path: path.display().to_string(),
                    detail: error.to_string(),
                });
            }
        };
        if !metadata.is_dir() {
            scan.candidates
                .push(Candidate::untracked(subtree, Origin::Folder));
            continue;
        }
        let name = subtree.rsplit('/').next().unwrap_or_default();
        let reason = if SKIP_LIST.contains(&name) {
            Some(NotSavedReason::SkipList)
        } else if fs::symlink_metadata(path.join(".git")).is_ok() {
            Some(NotSavedReason::NestedRepository)
        } else {
            None
        };
        if let Some(reason) = reason {
            not_saved.push(NotSaved {
                path: format!("{subtree}/"),
                reason,
                origin: None,
            });
            continue;
        }
        walk(
            &path,
            deadline,
            &mut |file| {
                scan.candidates.push(Candidate::untracked(
                    &format!("{subtree}/{file}"),
                    Origin::Folder,
                ))
            },
            &mut |skipped| {
                not_saved.push(NotSaved {
                    path: format!("{subtree}/{}", skipped.path),
                    ..skipped
                })
            },
        )?;
    }
    scan.not_saved = not_saved;
    scan.leave_out_secrets(context, root)?;
    Ok(scan)
}

/// Calls `file` with the path, relative to `root`, of every file and link
/// under it, and `skipped` with every entry it does not descend into: a
/// skip-list folder, a folder holding `.git`, or a special file.
pub(crate) fn walk(
    root: &Path,
    deadline: Instant,
    file: &mut dyn FnMut(String),
    skipped: &mut dyn FnMut(NotSaved),
) -> Result<(), Refusal> {
    let mut folders = vec![String::new()];
    let mut visited = 0usize;
    while let Some(folder) = folders.pop() {
        let unreadable = |path: &str, error: std::io::Error| Refusal::Unreadable {
            path: root.join(path).display().to_string(),
            detail: error.to_string(),
        };
        let entries =
            fs::read_dir(root.join(&folder)).map_err(|error| unreadable(&folder, error))?;
        for entry in entries {
            visited += 1;
            if visited.is_multiple_of(1024) && Instant::now() >= deadline {
                return Err(Refusal::OverDeadline);
            }
            let entry = entry.map_err(|error| unreadable(&folder, error))?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                return Err(Refusal::Unreadable {
                    path: entry.path().display().to_string(),
                    detail: "its name is not UTF-8".to_owned(),
                });
            };
            let path = if folder.is_empty() {
                name.to_owned()
            } else {
                format!("{folder}/{name}")
            };
            let kind = entry
                .file_type()
                .map_err(|error| unreadable(&path, error))?;
            if kind.is_dir() {
                let reason = if SKIP_LIST.contains(&name) {
                    Some(NotSavedReason::SkipList)
                } else if name == ".git" || fs::symlink_metadata(entry.path().join(".git")).is_ok()
                {
                    Some(NotSavedReason::NestedRepository)
                } else {
                    None
                };
                match reason {
                    Some(reason) => skipped(NotSaved {
                        path: format!("{path}/"),
                        reason,
                        origin: None,
                    }),
                    None => folders.push(path),
                }
            } else if kind.is_file() || kind.is_symlink() {
                file(path);
            } else {
                skipped(NotSaved {
                    path,
                    reason: NotSavedReason::Special,
                    origin: None,
                });
            }
        }
    }
    Ok(())
}
