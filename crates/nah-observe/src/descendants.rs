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

pub(crate) struct Budget {
    entries: usize,
    path_bytes: usize,
}

impl Default for Budget {
    fn default() -> Self {
        Self {
            entries: MAX_DESCENDANT_ENTRIES,
            path_bytes: MAX_DESCENDANT_PATH_BYTES,
        }
    }
}

impl Budget {
    pub(crate) const fn exhausted(&self) -> bool {
        self.entries == 0 || self.path_bytes == 0
    }
}

#[cfg(test)]
impl Budget {
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

pub(crate) fn observe(
    path: &PathObservation,
    symlink_traversal: SymlinkTraversal,
    budget: &mut Budget,
) -> DescendantObservation {
    let mut complete = true;
    let mut paths = BTreeSet::new();
    let mut pending = Vec::new();
    let visible_root = PathBuf::from(path.resolved().as_str());
    let physical_root = PathBuf::from(path.realpath().unwrap_or_else(|| path.resolved()).as_str());

    if budget.entries == 0 {
        return DescendantObservation::new(Vec::new(), false).expect("bounded descendant snapshot");
    }
    budget.entries -= 1;

    if fs::symlink_metadata(&physical_root).is_ok_and(|metadata| is_reparse_point(&metadata)) {
        complete = false;
    } else {
        match path.kind() {
            PathKind::Directory => pending.push((physical_root.clone(), visible_root.clone(), 0)),
            PathKind::Symlink if symlink_traversal != SymlinkTraversal::None => {
                match fs::metadata(&physical_root) {
                    Ok(metadata) if metadata.is_dir() => {
                        pending.push((physical_root.clone(), visible_root.clone(), 0));
                    }
                    Ok(metadata) if metadata.is_file() => {
                        inspect_file(
                            &physical_root,
                            &visible_root,
                            &metadata,
                            budget,
                            &mut paths,
                            &mut complete,
                        );
                    }
                    Ok(_) => complete = false,
                    Err(_) => complete = false,
                }
            }
            PathKind::Other => complete = false,
            PathKind::Missing | PathKind::File | PathKind::Symlink | PathKind::Fifo => {}
        }
    }

    let mut visited = BTreeSet::new();
    if !pending.is_empty() {
        visited.insert(physical_root);
    }
    'walk: while let Some((physical_directory, visible_directory, depth)) = pending.pop() {
        let entries = match fs::read_dir(&physical_directory) {
            Ok(entries) => entries,
            Err(_) => {
                complete = false;
                continue;
            }
        };
        if depth >= MAX_DESCENDANT_DEPTH {
            if entries.into_iter().next().is_some() {
                complete = false;
            }
            continue;
        }
        for entry in entries {
            if budget.entries == 0 {
                complete = false;
                break 'walk;
            }
            budget.entries -= 1;
            let entry = match entry {
                Ok(entry) => entry,
                Err(_) => {
                    complete = false;
                    continue;
                }
            };
            let physical_path = entry.path();
            let visible_path = visible_directory.join(entry.file_name());
            let metadata = match fs::symlink_metadata(&physical_path) {
                Ok(metadata) => metadata,
                Err(_) => {
                    complete = false;
                    continue;
                }
            };
            if is_reparse_point(&metadata) {
                complete = false;
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
                        ) {
                            break 'walk;
                        }
                    }
                    Err(_) => complete = false,
                }
            } else if file_type.is_dir() {
                if visited.insert(physical_path.clone()) {
                    pending.push((physical_path, visible_path, depth + 1));
                }
            } else if file_type.is_symlink() && symlink_traversal == SymlinkTraversal::All {
                let target = match fs::canonicalize(&physical_path) {
                    Ok(target) => target,
                    Err(_) => {
                        complete = false;
                        continue;
                    }
                };
                match fs::metadata(&target) {
                    Ok(metadata) if metadata.is_file() => {
                        if !inspect_file(
                            &target,
                            &visible_path,
                            &metadata,
                            budget,
                            &mut paths,
                            &mut complete,
                        ) {
                            break 'walk;
                        }
                    }
                    Ok(metadata) if metadata.is_dir() => {
                        if visited.insert(target.clone()) {
                            pending.push((target, visible_path, depth + 1));
                        }
                    }
                    Ok(_) => complete = false,
                    Err(_) => complete = false,
                }
            } else if !file_type.is_symlink() {
                complete = false;
            }
        }
    }

    DescendantObservation::new(paths.into_iter().collect(), complete)
        .expect("bounded descendant snapshot")
}

fn inspect_file(
    physical_path: &Path,
    visible_path: &Path,
    metadata: &fs::Metadata,
    budget: &mut Budget,
    paths: &mut BTreeSet<AbsolutePath>,
    complete: &mut bool,
) -> bool {
    match has_multiple_links(physical_path, metadata) {
        Ok(true) | Err(_) => *complete = false,
        Ok(false) => {}
    }
    record(physical_path, budget, paths, complete)
        && (physical_path == visible_path || record(visible_path, budget, paths, complete))
}

fn record(
    path: &Path,
    budget: &mut Budget,
    paths: &mut BTreeSet<AbsolutePath>,
    complete: &mut bool,
) -> bool {
    let path = match absolute_from_path(path) {
        Ok(path) => path,
        Err(_) => {
            *complete = false;
            return true;
        }
    };
    if paths.contains(&path) {
        return true;
    }
    let bytes = path.as_str().len();
    if paths.len() == MAX_DESCENDANT_PATHS || bytes > budget.path_bytes {
        *complete = false;
        return false;
    }
    budget.path_bytes -= bytes;
    paths.insert(path);
    true
}
