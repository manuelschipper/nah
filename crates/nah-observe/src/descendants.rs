//! Bounded descendant snapshots for recursive reads that can reach the network.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use nah_proto::ctx::AbsolutePath;
use nah_proto::observation::{
    DescendantObservation, IgnoredEntriesObservation, MAX_DESCENDANT_DEPTH, MAX_DESCENDANT_ENTRIES,
    MAX_DESCENDANT_PATH_BYTES, MAX_DESCENDANT_PATHS, ObservationFailure, PathKind, PathObservation,
    SymlinkTraversal,
};

use crate::directory_entries::{
    ENTRIES_PER_DEADLINE_CHECK, EntryKind, Listed, passed, read_directory,
};
use crate::ignored_entries::Listings;
use crate::io_paths::{absolute_from_path, is_reparse_point};
use crate::path_facts::has_multiple_links;
use crate::read_ahead::ReadAhead;

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

/// When a walk stops: once the time left before the decision's deadline no
/// longer covers the work its observation owes after the walk and handling
/// what the walk holds, the paths it found, in `held`, or the entries its
/// listings took, in `listed`, whichever are more. The threads reading ahead
/// for the walk count what they list, and stop with it.
pub(crate) struct Cutoff {
    deadline: Option<Instant>,
    owed: Duration,
    per_path: Duration,
    held: AtomicUsize,
    listed: AtomicUsize,
}

impl Cutoff {
    pub(crate) fn new(deadline: Option<Instant>, owed: Duration, per_path: Duration) -> Self {
        Self {
            deadline,
            owed,
            per_path,
            held: AtomicUsize::new(0),
            listed: AtomicUsize::new(0),
        }
    }

    /// The moment the walk, holding what it holds now, must stop.
    fn at(&self) -> Option<Instant> {
        crate::brought_forward(
            self.deadline,
            self.owed
                + crate::times(
                    self.per_path,
                    self.held
                        .load(Ordering::Relaxed)
                        .max(self.listed.load(Ordering::Relaxed)),
                ),
        )
    }
}

/// Snapshots the descendants below `path`; a snapshot cut short by the budget or
/// an unreadable entry is marked incomplete rather than failing. A directory
/// `ignored` lists below `path` is not entered but named among the
/// snapshot's ignored directories. A directory `listings` holds is not read
/// again. A walk still under way at its `cutoff` stops there, incomplete.
pub(crate) fn observe_descendants(
    path: &PathObservation,
    symlink_traversal: SymlinkTraversal,
    ignored: Option<&IgnoredEntriesObservation>,
    listings: &Listings,
    budget: &mut DescendantBudget,
    cutoff: &Cutoff,
) -> DescendantObservation {
    let ignored_directories = ignored
        .into_iter()
        .flat_map(|ignored| ignored.entries())
        .map(|entry| entry.path())
        .filter(|entry| entry.ends_with('/'))
        .collect::<BTreeSet<_>>();
    let mut skipped = Vec::new();
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
                            has_multiple_links(&physical_root, &metadata),
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

    // Directories are read ahead of the walk no further than its entry
    // budget reaches; the walk reads any other itself. One walk, even of a
    // mid-size repository's root (some 4,400 entries), fits the decision's
    // time budget on a host's slow cores, and scoped walks fit it in bursts
    // on its fast cores and, crate-sized, on its slow ones. A walk that
    // would run past the deadline, such as one of a whole drive on a host
    // where each entry costs a file open, stops at it: the walk looks at the
    // deadline at each directory and every few entries, and each listing,
    // the walk's own or a thread's reading ahead, at each entry it reads, so
    // the walk never waits on a listing past it. Its snapshot is then
    // incomplete, and its decision ends, as any observation out of time
    // does, with partial coverage.
    let ahead = AtomicUsize::new(budget.entries);
    let out_of_time = |complete: &mut bool, unlisted: &mut bool, held: usize| {
        cutoff.held.store(held, Ordering::Relaxed);
        let expired = passed(cutoff.at());
        if expired {
            *complete = false;
            *unlisted = true;
        }
        expired
    };
    ReadAhead::run(
        |directory| read_entries(directory, listings, &ahead, cutoff),
        |read_ahead| {
            for (physical_directory, _, ancestors) in &pending {
                if ancestors.len() < MAX_DESCENDANT_DEPTH {
                    read_ahead.ask(physical_directory);
                }
            }
            // Each directory is walked under every spelling that reaches it, so a
            // second link to the same directory still lists what lies below it. A
            // link back to a directory the walk is inside is a loop, which following
            // walks do not descend, so each walk carries the directories above it.
            'walk: while let Some((physical_directory, visible_directory, ancestors)) =
                pending.pop()
            {
                if out_of_time(
                    &mut complete,
                    &mut unlisted,
                    paths.len() + links.len() + skipped.len(),
                ) {
                    break 'walk;
                }
                let depth = ancestors.len();
                if depth >= MAX_DESCENDANT_DEPTH {
                    if fs::read_dir(&physical_directory)
                        .map_or(true, |mut entries| entries.next().is_some())
                    {
                        complete = false;
                        unlisted = true;
                    }
                    continue;
                }
                // A directory read ahead only in part, or not at all, is read
                // here no further than one entry past the walk's budget, which
                // is enough for the walk to find its budget spent. A read that
                // stops short of the directory's end leaves its listing
                // incomplete, whatever the budget left.
                let entries = match read_ahead.take(&physical_directory) {
                    Some(Ok((entries, true))) => Ok(entries),
                    Some(Err(error)) => Err(error),
                    Some(Ok((_, false))) | None => read_entries(
                        &physical_directory,
                        listings,
                        &AtomicUsize::new(budget.entries.saturating_add(1)),
                        cutoff,
                    )
                    .map(|(entries, whole)| {
                        if !whole {
                            complete = false;
                            unlisted = true;
                        }
                        entries
                    }),
                };
                let entries = match entries {
                    Ok(entries) => entries,
                    Err(_) => {
                        complete = false;
                        unlisted = true;
                        continue;
                    }
                };
                if depth > 0 && entries.is_empty() {
                    unlisted = true;
                }
                for (index, entry) in entries.into_iter().enumerate() {
                    if index % ENTRIES_PER_DEADLINE_CHECK == ENTRIES_PER_DEADLINE_CHECK - 1
                        && out_of_time(
                            &mut complete,
                            &mut unlisted,
                            paths.len() + links.len() + skipped.len(),
                        )
                    {
                        break 'walk;
                    }
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
                    let Entry {
                        name,
                        kind,
                        multiple_links,
                    } = entry;
                    let physical_path = physical_directory.join(&name);
                    let visible_path = visible_directory.join(&name);
                    if kind == EntryKind::File {
                        match multiple_links.expect("a file's links are read with its entry") {
                            Ok(multiple_links) => {
                                if !inspect_file(
                                    &physical_path,
                                    &visible_path,
                                    multiple_links,
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
                    } else if kind == EntryKind::Directory {
                        // The ignored entries name a directory by its path below the
                        // root, which a walk through a followed link never matches.
                        let ignored = !ignored_directories.is_empty()
                            && visible_path
                                .strip_prefix(&visible_root)
                                .ok()
                                .and_then(|below| {
                                    below
                                        .components()
                                        .map(|component| component.as_os_str().to_str())
                                        .collect::<Option<Vec<_>>>()
                                })
                                .is_some_and(|components| {
                                    ignored_directories
                                        .contains(format!("{}/", components.join("/")).as_str())
                                });
                        if ignored {
                            let Ok(directory) = absolute_from_path(&visible_path) else {
                                complete = false;
                                unlisted = true;
                                continue;
                            };
                            let bytes = directory.as_str().len();
                            if skipped.len() == MAX_DESCENDANT_PATHS || bytes > budget.path_bytes {
                                complete = false;
                                unlisted = true;
                                break 'walk;
                            }
                            budget.path_bytes -= bytes;
                            skipped.push(directory);
                            continue;
                        }
                        let mut ancestors = ancestors.clone();
                        ancestors.push(physical_directory.clone());
                        if ancestors.len() < MAX_DESCENDANT_DEPTH {
                            read_ahead.ask(&physical_path);
                        }
                        pending.push((physical_path, visible_path, ancestors));
                    } else if kind == EntryKind::Symlink
                        && symlink_traversal == SymlinkTraversal::All
                    {
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
                                    has_multiple_links(&target, &metadata),
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
                                    if ancestors.len() < MAX_DESCENDANT_DEPTH {
                                        read_ahead.ask(&target);
                                    }
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
                    } else if kind == EntryKind::Symlink {
                        unlisted = true;
                    } else {
                        complete = false;
                        unlisted = true;
                    }
                }
            }
            // Listings still under way when the walk stops end at their next
            // entry rather than at their own cutoff.
            ahead.store(0, Ordering::Relaxed);
        },
    );

    let snapshot = DescendantObservation::new(paths.into_iter().collect(), complete)
        .and_then(|descendants| descendants.with_links(links))
        .and_then(|descendants| descendants.with_ignored_directories(skipped))
        .expect("bounded descendant snapshot");
    if unlisted {
        snapshot.with_unlisted_entries()
    } else {
        snapshot
    }
}

/// One entry of a directory a walk reads, and, for a file, whether it has
/// other names, or the error reading its metadata gave.
struct Entry {
    name: OsString,
    kind: EntryKind,
    multiple_links: Option<io::Result<Result<bool, ObservationFailure>>>,
}

/// The entries of `directory`, from `listings` where a walk already read it,
/// each taken from `remaining` up to where that runs out, and whether they
/// are all of them. On Windows, where only an entry's own metadata tells a
/// reparse point, every entry's is read, and a reparse point is an entry
/// that could not be read. Entries `cutoff` leaves no time to list, or to
/// read the metadata of, are left out, as the end of a read cut short.
fn read_entries(
    directory: &Path,
    listings: &Listings,
    remaining: &AtomicUsize,
    cutoff: &Cutoff,
) -> io::Result<(Vec<io::Result<Entry>>, bool)> {
    if passed(cutoff.at()) {
        return Ok((Vec::new(), false));
    }
    let expired = || {
        let expired = passed(cutoff.at());
        if !expired {
            cutoff.listed.fetch_add(1, Ordering::Relaxed);
        }
        expired
    };
    let Listed { entries, mut whole } = match listings.get(directory) {
        Some(listed) => {
            let taken = listed
                .iter()
                .take_while(|_| {
                    !expired()
                        && remaining
                            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |left| {
                                left.checked_sub(1)
                            })
                            .is_ok()
                })
                .cloned()
                .map(Ok)
                .collect::<Vec<_>>();
            Listed {
                whole: taken.len() == listed.len(),
                entries: taken,
            }
        }
        None => read_directory(directory, remaining, &expired)?,
    };
    let mut read = Vec::with_capacity(entries.len());
    for (index, entry) in entries.into_iter().enumerate() {
        if index % ENTRIES_PER_DEADLINE_CHECK == 0 && passed(cutoff.at()) {
            whole = false;
            break;
        }
        read.push(entry.and_then(|entry| {
            let path = directory.join(&entry.name);
            if cfg!(windows) {
                let metadata = fs::symlink_metadata(&path)?;
                if is_reparse_point(&metadata) {
                    return Err(io::Error::other("a reparse point"));
                }
                let kind = EntryKind::from(metadata.file_type());
                Ok(Entry {
                    name: entry.name,
                    kind,
                    multiple_links: (kind == EntryKind::File)
                        .then(|| Ok(has_multiple_links(&path, &metadata))),
                })
            } else {
                Ok(Entry {
                    multiple_links: (entry.kind == EntryKind::File).then(|| match entry.links {
                        Some(links) => Ok(Ok(links > 1)),
                        None => fs::symlink_metadata(&path)
                            .map(|metadata| has_multiple_links(&path, &metadata)),
                    }),
                    name: entry.name,
                    kind: entry.kind,
                })
            }
        }));
    }
    Ok((read, whole))
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
    multiple_links: Result<bool, ObservationFailure>,
    budget: &mut DescendantBudget,
    paths: &mut BTreeSet<AbsolutePath>,
    complete: &mut bool,
    unlisted: &mut bool,
) -> bool {
    match multiple_links {
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
