//! Whether a Git repository lies below a directory a recursive delete takes.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use nah_proto::observation::{
    NestedRepositoryObservation, ObservationFailure, Observed, PathKind, PathObservation,
};

use crate::descendants::DescendantBudget;
use crate::directory_entries::{EntryKind, Listed, passed, read_directory};

/// Searches below the directory `path`, at any depth, for an entry named
/// `.git` in any letter case, of any kind, without following links, as
/// `rm -r` does not. Every entry listed is charged to `budget`, which also
/// bounds how deep the search goes: each level takes an entry. The search
/// answers `Absent` only once it has listed every directory below `path`:
/// running out of budget, reaching `deadline`, or an entry or directory it
/// cannot read (on macOS, a dataless File Provider item, which
/// `read_directory` refuses to open) leaves it unavailable unless a marker
/// turned up anyway.
pub(crate) fn observe_nested_repository(
    path: &Observed<PathObservation>,
    budget: &mut DescendantBudget,
    deadline: Option<Instant>,
) -> Observed<NestedRepositoryObservation> {
    let unavailable = Observed::Error {
        error: ObservationFailure::Unavailable,
    };
    let path = match path {
        Observed::Ok { value } => value,
        Observed::Error { error } => return Observed::Error { error: *error },
    };
    match path.kind() {
        PathKind::Directory => {}
        // `rm -r link/` empties the directory the link leads to.
        PathKind::Symlink => return unavailable,
        PathKind::Missing | PathKind::File | PathKind::Fifo | PathKind::Other => {
            return Observed::Ok {
                value: NestedRepositoryObservation::Absent,
            };
        }
    }
    let root = PathBuf::from(path.realpath().unwrap_or_else(|| path.resolved()).as_str());
    let remaining = AtomicUsize::new(budget.entries);
    let expired = || passed(deadline);
    let mut complete = true;
    let mut pending = vec![root];
    let found = 'search: loop {
        let Some(directory) = pending.pop() else {
            break false;
        };
        let entries = match read_directory(&directory, &remaining, &expired, deadline) {
            Ok(Listed { entries, whole }) => {
                complete &= whole;
                entries
            }
            Err(_) => {
                complete = false;
                continue;
            }
        };
        for entry in entries {
            match entry {
                // A case-insensitive filesystem, macOS's and Windows'
                // default, gives Git `.GIT` when it opens `.git`.
                Ok(entry) if entry.name.eq_ignore_ascii_case(".git") => {
                    break 'search true;
                }
                Ok(entry) if entry.kind == EntryKind::Directory => {
                    pending.push(directory.join(&entry.name));
                }
                Ok(_) => {}
                Err(_) => complete = false,
            }
        }
        // A listing cut short by the budget or the deadline leaves no
        // budget or time for the rest of the search either.
        if !complete && (remaining.load(Ordering::Relaxed) == 0 || expired()) {
            break false;
        }
    };
    budget.entries = remaining.load(Ordering::Relaxed);
    if found {
        Observed::Ok {
            value: NestedRepositoryObservation::Found,
        }
    } else if complete {
        Observed::Ok {
            value: NestedRepositoryObservation::Absent,
        }
    } else {
        unavailable
    }
}
