//! Bounded descendant snapshots for recursive reads that can reach the network.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use nah_proto::ctx::AbsolutePath;
use nah_proto::observation::{
    DescendantObservation, MAX_DESCENDANT_DEPTH, MAX_DESCENDANT_ENTRIES, MAX_DESCENDANT_PATH_BYTES,
    MAX_DESCENDANT_PATHS, PathKind, PathObservation, SymlinkTraversal,
};

use crate::io_paths::{absolute_from_path, is_reparse_point};
use crate::path_facts::has_multiple_links;

/// The descendant entry and path-byte budget that every recursive read in one
/// observation request draws from.
pub(crate) struct DescendantBudget {
    entries: usize,
    path_bytes: usize,
}

impl Default for DescendantBudget {
    fn default() -> Self {
        Self {
            entries: MAX_DESCENDANT_ENTRIES,
            path_bytes: MAX_DESCENDANT_PATH_BYTES,
        }
    }
}

impl DescendantBudget {
    pub(crate) const fn exhausted(&self) -> bool {
        self.entries == 0 || self.path_bytes == 0
    }
}

#[cfg(test)]
impl DescendantBudget {
    pub(crate) fn limited(entries: usize) -> Self {
        Self {
            entries,
            path_bytes: MAX_DESCENDANT_PATH_BYTES,
        }
    }

    pub(crate) fn limited_path_bytes(path_bytes: usize) -> Self {
        Self {
            entries: MAX_DESCENDANT_ENTRIES,
            path_bytes,
        }
    }
}

/// Snapshots the descendants below `path`; a snapshot cut short by the budget or
/// an unreadable entry is marked incomplete rather than failing.
pub(crate) fn observe_descendants(
    path: &PathObservation,
    symlink_traversal: SymlinkTraversal,
    budget: &mut DescendantBudget,
) -> DescendantObservation {
    let mut complete = true;
    // An entry beneath the root that the snapshot omits: a link left
    // unfollowed, an empty directory, a special file, or an entry it could
    // not read or reach within its budget.
    let mut unlisted = false;
    let mut paths = BTreeSet::new();
    let mut links = Vec::new();
    let mut pending = Vec::new();
    let visible_root = PathBuf::from(path.resolved().as_str());
    let physical_root = PathBuf::from(path.realpath().unwrap_or_else(|| path.resolved()).as_str());

    if budget.entries == 0 {
        return DescendantObservation::new(Vec::new(), false)
            .expect("bounded descendant snapshot")
            .with_unlisted_entries();
    }
    budget.entries -= 1;

    if fs::symlink_metadata(&physical_root).is_ok_and(|metadata| is_reparse_point(&metadata)) {
        complete = false;
        unlisted = true;
    } else {
        match path.kind() {
            PathKind::Directory => {
                pending.push((physical_root.clone(), visible_root.clone(), Vec::new()));
            }
            PathKind::Symlink if symlink_traversal != SymlinkTraversal::None => {
                record_link(&visible_root, &physical_root, &mut links, &mut complete);
                match fs::metadata(&physical_root) {
                    Ok(metadata) if metadata.is_dir() => {
                        pending.push((physical_root.clone(), visible_root.clone(), Vec::new()));
                    }
                    Ok(metadata) if metadata.is_file() => {
                        inspect_file(
                            &physical_root,
                            &visible_root,
                            &metadata,
                            budget,
                            &mut paths,
                            &mut complete,
                            &mut unlisted,
                        );
                    }
                    Ok(_) | Err(_) => {
                        complete = false;
                        unlisted = true;
                    }
                }
            }
            PathKind::Symlink => unlisted = true,
            PathKind::Other => complete = false,
            PathKind::Missing | PathKind::File | PathKind::Fifo => {}
        }
    }

    // Each directory is walked under every spelling that reaches it, so a
    // second link to the same directory still lists what lies below it. A
    // link back to a directory the walk is inside is a loop, which following
    // walks do not descend, so each walk carries the directories above it.
    'walk: while let Some((physical_directory, visible_directory, ancestors)) = pending.pop() {
        let depth = ancestors.len();
        let entries = match fs::read_dir(&physical_directory) {
            Ok(entries) => entries,
            Err(_) => {
                complete = false;
                unlisted = true;
                continue;
            }
        };
        if depth >= MAX_DESCENDANT_DEPTH {
            if entries.into_iter().next().is_some() {
                complete = false;
                unlisted = true;
            }
            continue;
        }
        let mut entries = entries.peekable();
        if depth > 0 && entries.peek().is_none() {
            unlisted = true;
        }
        for entry in entries {
            if budget.entries == 0 {
                complete = false;
                unlisted = true;
                break 'walk;
            }
            budget.entries -= 1;
            let entry = match entry {
                Ok(entry) => entry,
                Err(_) => {
                    complete = false;
                    unlisted = true;
                    continue;
                }
            };
            let physical_path = entry.path();
            let visible_path = visible_directory.join(entry.file_name());
            let metadata = match fs::symlink_metadata(&physical_path) {
                Ok(metadata) => metadata,
                Err(_) => {
                    complete = false;
                    unlisted = true;
                    continue;
                }
            };
            if is_reparse_point(&metadata) {
                complete = false;
                unlisted = true;
                continue;
            }
            let file_type = metadata.file_type();
            if file_type.is_file() {
                match entry.metadata() {
                    Ok(metadata) => {
                        if !inspect_file(
                            &physical_path,
                            &visible_path,
                            &metadata,
                            budget,
                            &mut paths,
                            &mut complete,
                            &mut unlisted,
                        ) {
                            break 'walk;
                        }
                    }
                    Err(_) => {
                        complete = false;
                        unlisted = true;
                    }
                }
            } else if file_type.is_dir() {
                let mut ancestors = ancestors.clone();
                ancestors.push(physical_directory.clone());
                pending.push((physical_path, visible_path, ancestors));
            } else if file_type.is_symlink() && symlink_traversal == SymlinkTraversal::All {
                let target = match fs::canonicalize(&physical_path) {
                    Ok(target) => target,
                    Err(_) => {
                        complete = false;
                        unlisted = true;
                        continue;
                    }
                };
                record_link(&visible_path, &target, &mut links, &mut complete);
                match fs::metadata(&target) {
                    Ok(metadata) if metadata.is_file() => {
                        if !inspect_file(
                            &target,
                            &visible_path,
                            &metadata,
                            budget,
                            &mut paths,
                            &mut complete,
                            &mut unlisted,
                        ) {
                            break 'walk;
                        }
                    }
                    Ok(metadata) if metadata.is_dir() => {
                        if target != physical_directory && !ancestors.contains(&target) {
                            let mut ancestors = ancestors.clone();
                            ancestors.push(physical_directory.clone());
                            pending.push((target, visible_path, ancestors));
                        } else {
                            // A loop: what lies below this link is not listed.
                            unlisted = true;
                        }
                    }
                    Ok(_) | Err(_) => {
                        complete = false;
                        unlisted = true;
                    }
                }
            } else if file_type.is_symlink() {
                unlisted = true;
            } else {
                complete = false;
                unlisted = true;
            }
        }
    }

    let snapshot = DescendantObservation::new(paths.into_iter().collect(), complete)
        .and_then(|descendants| descendants.with_links(links))
        .expect("bounded descendant snapshot");
    if unlisted {
        snapshot.with_unlisted_entries()
    } else {
        snapshot
    }
}

/// Keeps the link a walk followed at `visible` to `target`, so what the walk
/// reached through it can be named by the path it leads to.
fn record_link(
    visible: &Path,
    target: &Path,
    links: &mut Vec<(AbsolutePath, AbsolutePath)>,
    complete: &mut bool,
) {
    match (absolute_from_path(visible), absolute_from_path(target)) {
        (Ok(visible), Ok(target)) if links.len() < MAX_DESCENDANT_PATHS => {
            links.push((visible, target));
        }
        _ => *complete = false,
    }
}

fn inspect_file(
    physical_path: &Path,
    visible_path: &Path,
    metadata: &fs::Metadata,
    budget: &mut DescendantBudget,
    paths: &mut BTreeSet<AbsolutePath>,
    complete: &mut bool,
    unlisted: &mut bool,
) -> bool {
    match has_multiple_links(physical_path, metadata) {
        Ok(true) | Err(_) => *complete = false,
        Ok(false) => {}
    }
    record(physical_path, budget, paths, complete, unlisted)
        && (physical_path == visible_path
            || record(visible_path, budget, paths, complete, unlisted))
}

fn record(
    path: &Path,
    budget: &mut DescendantBudget,
    paths: &mut BTreeSet<AbsolutePath>,
    complete: &mut bool,
    unlisted: &mut bool,
) -> bool {
    let path = match absolute_from_path(path) {
        Ok(path) => path,
        Err(_) => {
            *complete = false;
            *unlisted = true;
            return true;
        }
    };
    if paths.contains(&path) {
        return true;
    }
    let bytes = path.as_str().len();
    if paths.len() == MAX_DESCENDANT_PATHS || bytes > budget.path_bytes {
        *complete = false;
        *unlisted = true;
        return false;
    }
    budget.path_bytes -= bytes;
    paths.insert(path);
    true
}
