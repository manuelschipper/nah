//! Complete, bounded listings of a directory's entries for the engine's
//! selection expansion.

use std::fs;
use std::path::PathBuf;

use nah_proto::ctx::AbsolutePath;
use nah_proto::effinterp_proto::{
    ListedEntry, ListingFact, MAX_LISTING_DEPTH, MAX_LISTING_ENTRIES, MAX_OBSERVATION_PATH_BYTES,
    ObservationRefusal, PathKind,
};
use nah_proto::observation::{Observed, PathKind as HostKind};

use crate::io_paths::is_reparse_point;
use crate::path_facts::observe_path;

/// Every entry beneath the directory `requested` names, down to `depth`
/// components below it, following its final component and nothing beneath
/// it. The answer is complete or refused: an
/// entry the walk cannot read or name, or a tree past the listing bounds,
/// refuses the whole listing rather than omitting what it could not see.
pub fn observe_listing(
    cwd: &AbsolutePath,
    requested: &str,
    depth: Option<u32>,
) -> Result<ListingFact, ObservationRefusal> {
    let root = match observe_path(cwd, requested) {
        Observed::Ok { value } => value,
        Observed::Error { .. } => return Err(ObservationRefusal::Unobserved),
    };
    let directory = match (root.kind(), root.target_kind(), root.realpath()) {
        (HostKind::Directory, _, Some(realpath))
        | (HostKind::Symlink, Some(HostKind::Directory), Some(realpath)) => realpath.clone(),
        (_, _, None) => return Err(ObservationRefusal::Unobserved),
        _ => return Err(ObservationRefusal::Unsupported),
    };
    let mut entries = Vec::new();
    let mut pending = vec![(PathBuf::from(directory.as_str()), String::new(), 0)];
    let asked = depth;
    while let Some((physical, relative, depth)) = pending.pop() {
        let listed = fs::read_dir(&physical).map_err(|_| ObservationRefusal::Unobserved)?;
        for entry in listed {
            let entry = entry.map_err(|_| ObservationRefusal::Unobserved)?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| ObservationRefusal::Unobserved)?;
            let path = if relative.is_empty() {
                name
            } else {
                format!("{relative}/{name}")
            };
            if depth + 1 > MAX_LISTING_DEPTH {
                return Err(limit("max_listing_depth"));
            }
            if entries.len() == MAX_LISTING_ENTRIES {
                return Err(limit("max_listing_entries"));
            }
            if directory.as_str().len() + 1 + path.len() > MAX_OBSERVATION_PATH_BYTES {
                return Err(limit("max_observation_path_bytes"));
            }
            let metadata =
                fs::symlink_metadata(entry.path()).map_err(|_| ObservationRefusal::Unobserved)?;
            // A reparse point can redirect beneath the directory to anywhere.
            if is_reparse_point(&metadata) {
                return Err(ObservationRefusal::Ambiguous);
            }
            let kind = entry_kind(&metadata.file_type());
            // An unbounded walk descends everywhere, so a tree past the
            // depth limit is refused above rather than cut short.
            if kind == PathKind::Directory && asked.is_none_or(|asked| depth + 1 < asked as usize) {
                pending.push((entry.path(), path.clone(), depth + 1));
            }
            entries.push(ListedEntry { path, kind });
        }
    }
    entries.sort();
    Ok(ListingFact {
        directory: directory.as_str().to_owned(),
        entries,
    })
}

fn limit(name: &str) -> ObservationRefusal {
    ObservationRefusal::Limit { limit: name.into() }
}

fn entry_kind(file_type: &fs::FileType) -> PathKind {
    if file_type.is_symlink() {
        return PathKind::Symlink;
    }
    if file_type.is_file() {
        return PathKind::File;
    }
    if file_type.is_dir() {
        return PathKind::Directory;
    }
    #[cfg(unix)]
    if std::os::unix::fs::FileTypeExt::is_fifo(file_type) {
        return PathKind::Fifo;
    }
    PathKind::Other
}
