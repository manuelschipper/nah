#![cfg(unix)]
#![allow(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types
)]

//! Saves a project's unsaved work to a store outside the project and
//! restores it byte for byte. A save either publishes a complete snapshot or
//! refuses and leaves none: no copy, no run.
//!
//! For a git work tree it saves HEAD's commit and branch, the staged state,
//! tracked files that differ from the index or were deleted, untracked files
//! git does not ignore, and ignored files the caller names. For any other
//! folder it saves every file. Secret files and skip-list folders are never
//! saved; the manifest names what was left out and why. Before a command
//! deletes refs or stash entries, it saves the commits only they reach
//! instead ([`save_commits`]). What a discard would reach or write, which
//! the save-then-run hook asks before it saves, is [`discard_reach`].
//!
//! A save never writes to the project's repository, and nothing here starts
//! a program the repository's configuration names. `undo` writes the work
//! tree and the index, or, for a snapshot of commits, adds the saved objects
//! to the repository's object store and recreates the refs and stash
//! entries that are missing.
//!
//! Snapshots expire: [`prune`] removes those retention no longer keeps, and
//! the content no remaining snapshot refers to.
//!
//! Unsupported: snapshots on Windows. The crate is Unix only, so elsewhere
//! nothing saves before a discard runs (`save_then_run::available` in
//! nah-cli).

mod capture;
mod commits;
pub mod discard_reach;
mod folder;
mod git;
mod journal;
mod manifest;
mod retention;
mod store;
mod undo;
mod work_tree;

pub use commits::{Deleting, save_commits};
pub use manifest::{
    Commits, Content, DiscardResult, Entry, FileKind, Listed, Manifest, NotSaved, NotSavedReason,
    Origin, RepositoryState, Saved, SavedRef, Stage, StashEntry, Stat, Summary, Undoing, Written,
};
pub use retention::{Prune, Pruned, RETENTION, Retention, Unfinished, prune};
pub use undo::{Conflict, UndoOutcome, undo, undo_refusing};

use capture::Capture;
use nah_proto::ctx::{AbsolutePath, Platform};
use nah_proto::labels::Sensitivity;
use nah_proto::labels::sensitivity::sensitivity;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use store::{Store, hex, now_ns};
use work_tree::Repository;

/// How many new bytes a save made before a command may read and store.
pub const DEFAULT_BUDGET_BYTES: u64 = 50 * 1024 * 1024;

/// How long a save made before a command may take.
pub const DEFAULT_DEADLINE: Duration = Duration::from_secs(2);

/// What a save no hook waits for may cost: a refresh after a command, or the
/// save an undo makes first.
pub const BACKGROUND_BUDGET_BYTES: u64 = 500 * 1024 * 1024;
pub const BACKGROUND_DEADLINE: Duration = Duration::from_secs(30);

/// Files larger than this are stored as plain copies, not git objects:
/// copying is far cheaper than compressing them.
pub(crate) const PLAIN_COPY_BYTES: u64 = 10 * 1024 * 1024;

/// Dependency and build folders, which can be regenerated. Untracked files in
/// them are not saved; tracked ones are.
pub const SKIP_LIST: [&str; 15] = nah_proto::labels::build_output::SNAPSHOT_SKIP_LIST;

/// Where snapshots live and what the host looks like.
pub struct Context {
    /// `~/.nah/snapshots`: each project's store is a folder in it.
    pub snapshots_dir: PathBuf,
    /// The user's home, which secret classification reads.
    pub home: AbsolutePath,
    /// The git executable.
    pub git: PathBuf,
    /// Lets git consult its built-in fsmonitor daemon in a repository whose
    /// own configuration sets `core.fsmonitor=true`, which spares status
    /// most of its walk of a large tree. A `core.fsmonitor` naming a hook
    /// program is never run.
    pub builtin_fsmonitor: bool,
    /// Reads the files the agents' sessions label as holding secret bytes, by
    /// absolute path: never saved, like the files the secret classification
    /// names. A save reads them before its scan and again before it
    /// publishes, so a file labelled while it was being saved is never kept.
    /// A save whose read of them fails is refused.
    pub labelled: Box<dyn Fn() -> Result<Vec<PathBuf>, String> + Send + Sync>,
    /// Asked right before a save makes a snapshot visible, with the folder
    /// it is about to take. A save it answers false refuses as over its
    /// deadline and leaves nothing a listing or an undo can see: the hook's
    /// save child asks the hook, which allows none once it stopped waiting.
    pub may_publish: Box<dyn Fn(&Path) -> bool + Send + Sync>,
    /// The command a snapshot this context saves or names as an undo point
    /// is the undo for, as the agent was told it (`nah snapshots` shows it);
    /// `None` where Nah names no command.
    pub undo_for: Option<String>,
}

/// What one save may cost.
#[derive(Clone, Copy, Debug)]
pub struct Budget {
    /// Most bytes it may read and store that the store does not already hold.
    pub bytes: u64,
    pub deadline: Instant,
}

impl Budget {
    /// The defaults for a save made before a command.
    pub fn pre_call() -> Self {
        Budget {
            bytes: DEFAULT_BUDGET_BYTES,
            deadline: Instant::now() + DEFAULT_DEADLINE,
        }
    }
}

/// Why a save, or an undo, did nothing. Each leaves no snapshot behind.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "reason", rename_all = "kebab-case")]
pub enum Refusal {
    OverBudget {
        bytes: u64,
        budget_bytes: u64,
    },
    OverDeadline,
    Unreadable {
        path: String,
        detail: String,
    },
    IndexLocked {
        path: String,
    },
    DiskFull,
    RepositoryUnreadable {
        detail: String,
    },
    StoreUnwritable {
        detail: String,
    },
    LabelsUnreadable {
        detail: String,
    },
    /// The request itself cannot be carried out, such as an unknown snapshot.
    Invalid {
        detail: String,
    },
}

impl fmt::Display for Refusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::OverBudget {
                bytes,
                budget_bytes,
            } => write!(
                formatter,
                "{} to save is over the {} budget",
                megabytes(*bytes),
                megabytes(*budget_bytes)
            ),
            Refusal::OverDeadline => write!(formatter, "saving would take longer than allowed"),
            Refusal::Unreadable { path, detail } => {
                write!(formatter, "{path} cannot be read: {detail}")
            }
            Refusal::IndexLocked { path } => write!(
                formatter,
                "another git process holds the index lock ({path})"
            ),
            Refusal::DiskFull => write!(formatter, "the snapshot store's disk is full"),
            Refusal::RepositoryUnreadable { detail } => {
                write!(formatter, "the repository cannot be read: {detail}")
            }
            Refusal::StoreUnwritable { detail } => {
                write!(formatter, "the snapshot store cannot be written: {detail}")
            }
            Refusal::LabelsUnreadable { detail } => write!(
                formatter,
                "the files nah's sessions label secret cannot be read: {detail}"
            ),
            Refusal::Invalid { detail } => write!(formatter, "{detail}"),
        }
    }
}

fn megabytes(bytes: u64) -> String {
    format!("{:.1} MB", bytes as f64 / 1_000_000.0)
}

/// The refusal a failed write to the store becomes.
pub(crate) fn store_failure(error: io::Error) -> Refusal {
    match error.raw_os_error() {
        Some(libc::ENOSPC | libc::EDQUOT) => Refusal::DiskFull,
        _ => Refusal::StoreUnwritable {
            detail: error.to_string(),
        },
    }
}

/// Whether the latest snapshot still holds the project's unsaved work.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum Freshness {
    /// It does; nothing was saved.
    Current { snapshot: Manifest },
    /// It did not, so a new snapshot was saved.
    Saved { snapshot: Manifest },
}

/// Saves `project`'s unsaved work, and the `named` files besides, as a new
/// snapshot.
pub fn save(
    context: &Context,
    project: &Path,
    named: &[PathBuf],
    budget: Budget,
) -> Result<Manifest, Refusal> {
    let project = locate(context, project, budget.deadline)?;
    let store = store::open(&context.snapshots_dir, &project.id, budget.deadline)?;
    snapshot(context, &store, &project, named, None, &budget, false).map(|(manifest, _)| manifest)
}

/// Publishes a discard snapshot, adding selected paths the rolling snapshot
/// did not need to save. A clean file refers to Git's blob, which undo
/// writes back, only once its kind, executable bit and bytes on disk prove
/// they are the blob's (`git hash-object --no-filters`); any other file's
/// own bytes and kind are copied first. Paths Git will create are recorded
/// as absent.
pub fn save_discard(
    context: &Context,
    mut snapshot: Manifest,
    results: BTreeMap<String, DiscardResult>,
    mut index: BTreeMap<String, Vec<Stage>>,
    deadline: Instant,
) -> Result<Manifest, Refusal> {
    let project = locate(context, Path::new(&snapshot.root), deadline)?;
    let store = store::open(&context.snapshots_dir, &project.id, deadline)?;
    // The caller read `snapshot` under an earlier hold of the lock. A prune
    // since may have removed it and the content only it referred to, which
    // this save would then name. While it is still published, its content
    // stays: a prune deletes content only once it moved out every snapshot
    // it removes, and reads this save's snapshot before its next deletion.
    if store.find(&snapshot.id)?.is_none() {
        return Err(Refusal::Invalid {
            detail: format!(
                "snapshot {}, which this save builds on, expired while it was being made",
                snapshot.id
            ),
        });
    }
    let clean = results
        .keys()
        .filter(|path| {
            !snapshot.entries.iter().any(|entry| &entry.path == *path)
                && matches!(index.get(*path).map(Vec::as_slice), Some([stage]) if stage.stage == 0)
        })
        .map(String::as_str)
        .collect::<Vec<_>>();
    let unproven = match &project.repository {
        Some(repository) => {
            work_tree::unproven_by_index(context, &repository.top, &clean, deadline)?
        }
        None => Vec::new(),
    };
    let mut new_bytes = 0;
    if !unproven.is_empty() {
        // The new save also names what `snapshot` holds, such as ignored
        // files a caller had it copy, which the rolling scan leaves out.
        let named = unproven
            .iter()
            .chain(
                snapshot
                    .entries
                    .iter()
                    .filter(|entry| entry.worktree.is_some())
                    .map(|entry| &entry.path),
            )
            .map(|path| project.root.join(path))
            .collect::<Vec<_>>();
        let budget = Budget {
            bytes: DEFAULT_BUDGET_BYTES,
            deadline,
        };
        let (mut copied, _) =
            self::snapshot(context, &store, &project, &named, None, &budget, false)?;
        let held = copied
            .entries
            .iter()
            .map(|entry| entry.path.as_str())
            .collect::<BTreeSet<_>>();
        if let Some(missing) = unproven.iter().find(|path| !held.contains(path.as_str())) {
            return Err(Refusal::Unreadable {
                path: missing.clone(),
                detail: "its bytes differ from the Git blob it would be restored from, and the save could not copy it".to_owned(),
            });
        }
        for left_out in snapshot.not_saved {
            if !copied.not_saved.contains(&left_out) {
                copied.not_saved.push(left_out);
            }
        }
        new_bytes = copied.summary.new_bytes;
        snapshot = copied;
    }
    let pending = store.begin()?;
    let held = snapshot
        .entries
        .iter()
        .map(|entry| entry.path.as_str())
        .collect::<BTreeSet<_>>();
    let mut lookup = Lookup::new(&project.root);
    let candidates = results
        .keys()
        .map(String::as_str)
        .filter(|path| !held.contains(path) && undo::safe_path(path))
        .filter_map(|path| {
            let index = index.remove(path).unwrap_or_default();
            let mut candidate = Candidate::restored(path, index);
            match candidate.index.as_slice() {
                [] => {}
                [stage] if stage.stage == 0 && stage.file_kind().is_some() => {
                    match lookup.metadata(path) {
                        Ok(Some(metadata)) if metadata.is_file() || metadata.is_symlink() => {
                            candidate.origin = Origin::Clean;
                        }
                        // A sparse work tree may have the index entry only.
                        Ok(None) => {}
                        Ok(Some(metadata)) if metadata.is_dir() => {}
                        _ => return None,
                    }
                }
                _ => return None,
            }
            Some(candidate)
        })
        .collect::<Vec<_>>();
    snapshot.summary.new_bytes = new_bytes;
    if !candidates.is_empty() {
        let mut scan = Scan {
            candidates,
            ..Scan::default()
        };
        scan.leave_out_secrets(context, &project.root)?;
        snapshot
            .entries
            .extend(scan.candidates.into_iter().map(|candidate| Entry {
                path: candidate.path,
                origin: candidate.origin,
                worktree: None,
                head: candidate.head,
                index: candidate.index,
                staged: false,
                intent_to_add: false,
                gone_since_ms: None,
            }));
        snapshot
            .entries
            .sort_by(|left, right| left.path.cmp(&right.path));
        snapshot.summary.files = snapshot.entries.len() as u64;
        snapshot.not_saved.extend(scan.not_saved);
    }
    snapshot.discard_results = results;
    snapshot.undo_of = None;
    store.publish(
        pending,
        snapshot,
        context.may_publish.as_ref(),
        false,
        true,
        context.undo_for.as_deref(),
    )
}

/// Records that Nah names `snapshot` as an undo point, so retention keeps it
/// for its full age from now, as it would a snapshot saved now, and as the
/// newest promise never removes it for the store's size. A save that reuses
/// the latest snapshot names one that may have been saved long ago. Refuses
/// once retention removed it.
pub fn name_undo(context: &Context, snapshot: &Manifest, deadline: Instant) -> Result<(), Refusal> {
    let project = locate(context, Path::new(&snapshot.root), deadline)?;
    let store = store::open(&context.snapshots_dir, &project.id, deadline)?;
    // The caller read `snapshot` under an earlier hold of the lock, and a
    // prune may have removed it since.
    if store.find(&snapshot.id)?.is_none() {
        return Err(Refusal::Invalid {
            detail: format!(
                "snapshot {}, which would undo this call, expired while it was being named",
                snapshot.id
            ),
        });
    }
    store.set_named(&snapshot.id, context.undo_for.as_deref())
}

/// Checks that the latest snapshot holds `project`'s unsaved work, and saves
/// a new one, reusing the unchanged content, when it does not. Where the
/// filesystem keeps a change journal, it also records the journal's position
/// from before the check, which [`unchanged`] reads.
pub fn fresh(context: &Context, project: &Path, budget: Budget) -> Result<Freshness, Refusal> {
    let project = locate(context, project, budget.deadline)?;
    let store = store::open(&context.snapshots_dir, &project.id, budget.deadline)?;
    fresh_in(context, &store, &project, budget)
}

fn fresh_in(
    context: &Context,
    store: &Store,
    project: &Project,
    budget: Budget,
) -> Result<Freshness, Refusal> {
    // A check that fails leaves no mark, so the copy counts as stale until
    // one succeeds.
    store.set_mark(None)?;
    let position = journal::position(watched(project));
    let (snapshot, saved) = snapshot(context, store, project, &[], None, &budget, true)?;
    if let Some(position) = position {
        store.set_mark(Some(&journal::Mark {
            snapshot: snapshot.id.clone(),
            position,
        }))?;
    }
    Ok(if saved {
        Freshness::Saved { snapshot }
    } else {
        Freshness::Current { snapshot }
    })
}

/// The latest snapshot, when the filesystem's change journal shows that
/// nothing under the work tree or its git directories changed since the
/// freshness check that left it as the latest began: it then still holds the
/// unsaved work, with no walk of the tree. `None` when that cannot be shown,
/// and always on a system without a journal. Refuses when the files the
/// sessions label secret cannot be read.
pub fn unchanged(
    context: &Context,
    project: &Path,
    deadline: Instant,
) -> Result<Option<Manifest>, Refusal> {
    let project = locate(context, project, deadline)?;
    let store = store::open(&context.snapshots_dir, &project.id, deadline)?;
    let (Some(mark), Some(latest)) = (store.mark(), store.latest()?) else {
        return Ok(None);
    };
    // A file labelled secret since it was saved is copied in it; a new save
    // leaves it out.
    let labelled = labelled(context)?;
    if latest
        .entries
        .iter()
        .any(|entry| entry.worktree.is_some() && labelled.contains(&project.root.join(&entry.path)))
    {
        return Ok(None);
    }
    Ok((mark.snapshot == latest.id
        && mark.position.paths == watched(&project)
        && journal::unchanged_since(&mark.position, &store.root, &[], deadline))
    .then_some(latest))
}

/// [`fresh`] after a call that wrote only `file`, an absolute path: only
/// `file` is looked at again, and its entry replaces the latest snapshot's,
/// with no walk of the tree. Where the filesystem keeps a change journal,
/// that happens only when the latest snapshot held the work tree as of the
/// last freshness check and the journal shows nothing but `file` changed
/// since; [`unchanged`] then trusts the result as it would a full check's,
/// and otherwise this is a full check, which keeps the next discard's check
/// cheap. Elsewhere no check is ever trusted, so the latest snapshot with
/// `file` refreshed is as current as the latest snapshot was; a full check
/// runs only for the first snapshot, or over one an undo or a discard's
/// save of named files left.
pub fn refresh_file(context: &Context, file: &Path, budget: Budget) -> Result<Freshness, Refusal> {
    let unreadable = |error: io::Error| Refusal::Unreadable {
        path: file.display().to_string(),
        detail: error.to_string(),
    };
    let (Some(parent), Some(name)) = (file.parent(), file.file_name()) else {
        return Err(Refusal::Invalid {
            detail: format!("{} names no file", file.display()),
        });
    };
    let project = locate(context, parent, budget.deadline)?;
    let store = store::open(&context.snapshots_dir, &project.id, budget.deadline)?;
    // The journal names a file by its real folder.
    let file = fs::canonicalize(parent).map_err(unreadable)?.join(name);
    let relative = file
        .strip_prefix(&project.root)
        .ok()
        .and_then(Path::to_str)
        .map(str::to_owned);
    let (Some(repository), Some(latest), Some(relative)) =
        (&project.repository, store.latest()?, relative)
    else {
        return fresh_in(context, &store, &project, budget);
    };
    let mark = store.mark();
    store.set_mark(None)?;
    // Taken before `file` is read, so a later change to it is after the mark.
    let position = journal::position(watched(&project));
    match (&position, mark) {
        (Some(_), Some(mark))
            if mark.snapshot == latest.id
                && mark.position.paths == watched(&project)
                && journal::unchanged_since(
                    &mark.position,
                    &store.root,
                    std::slice::from_ref(&file),
                    budget.deadline,
                ) => {}
        (Some(_), _) => return fresh_in(context, &store, &project, budget),
        // Saved paths an undo or a discard's save adds are no part of the
        // rolling copy.
        (None, _)
            if latest.undo_of.is_some()
                || latest
                    .entries
                    .iter()
                    .any(|entry| matches!(entry.origin, Origin::Named | Origin::Restored)) =>
        {
            return fresh_in(context, &store, &project, budget);
        }
        (None, _) => {}
    }
    let started_ns = now_ns();
    let filters = work_tree::filters(context, repository, budget.deadline)?;
    let looked = work_tree::scan(
        context,
        repository,
        &filters,
        &[],
        Some(&relative),
        budget.deadline,
    )?;
    let mut scan = Scan {
        repository: looked.repository,
        candidates: latest
            .entries
            .iter()
            .filter(|entry| entry.path != relative)
            .map(Candidate::of_entry)
            .collect(),
        not_saved: latest
            .not_saved
            .iter()
            .filter(|left_out| left_out.path != relative)
            .cloned()
            .collect(),
    };
    scan.candidates.extend(looked.candidates);
    scan.not_saved.extend(looked.not_saved);
    let (snapshot, saved) = capture(
        context,
        &store,
        &project,
        scan,
        &filters,
        Some(latest),
        None,
        &budget,
        true,
        started_ns,
    )?;
    if let Some(position) = position {
        store.set_mark(Some(&journal::Mark {
            snapshot: snapshot.id.clone(),
            position,
        }))?;
    }
    Ok(if saved {
        Freshness::Saved { snapshot }
    } else {
        Freshness::Current { snapshot }
    })
}

/// Saves every file under `subtrees`, paths relative to `project`, a folder
/// no git work tree holds, as a new snapshot of `project`: what a delete of
/// those subtrees destroys, which [`undo`] run in `project` puts back. As
/// for a snapshot of the whole folder, skip-list folders, repositories
/// nested in it and secret files are left out, and the manifest names them.
pub fn save_folder(
    context: &Context,
    project: &Path,
    subtrees: &[String],
    budget: Budget,
) -> Result<Manifest, Refusal> {
    let project = locate(context, project, budget.deadline)?;
    if project.repository.is_some() {
        return Err(Refusal::Invalid {
            detail: format!("{} is in a git work tree", project.root.display()),
        });
    }
    let store = store::open(&context.snapshots_dir, &project.id, budget.deadline)?;
    let latest = store.latest()?;
    let started_ns = now_ns();
    let scan = folder::scan_subtrees(context, &project.root, subtrees, budget.deadline)?;
    capture(
        context,
        &store,
        &project,
        scan,
        &[],
        latest,
        None,
        &budget,
        false,
        started_ns,
    )
    .map(|(manifest, _)| manifest)
}

/// The folders whose change can change a snapshot of `project`: its root and
/// the git directories outside it, which hold its index and HEAD.
fn watched(project: &Project) -> Vec<PathBuf> {
    let mut paths = vec![project.root.clone()];
    if let Some(repository) = &project.repository {
        for dir in [&repository.git_dir, &repository.common_dir] {
            if !paths.iter().any(|path| dir.starts_with(path)) {
                paths.push(dir.clone());
            }
        }
    }
    paths
}

/// Refuses a save of the repository Git finds from `dir` that would refuse
/// before reading anything: another Git process holds its index lock.
pub fn index_unlocked(context: &Context, dir: &Path, deadline: Instant) -> Result<(), Refusal> {
    match locate(context, dir, deadline)?.repository {
        Some(repository) => work_tree::index_unlocked(&repository),
        None => Ok(()),
    }
}

/// One snapshot [`list`] returns.
#[derive(Clone, Debug)]
pub struct Listing {
    pub snapshot: Manifest,
    /// Whether Nah gave it as an undo point; `None` for a rolling copy of
    /// the project's work that no undo named.
    pub undo: Option<UndoPoint>,
}

/// When and for what Nah last gave a snapshot as an undo point.
#[derive(Clone, Debug, Serialize)]
pub struct UndoPoint {
    /// Milliseconds since the Unix epoch.
    pub named_ms: u64,
    /// The command it was saved before, where Nah knew it.
    pub command: Option<String>,
}

/// `project`'s snapshots, newest first.
pub fn list(context: &Context, project: &Path, deadline: Instant) -> Result<Vec<Listing>, Refusal> {
    let project = locate(context, project, deadline)?;
    let store = store::open(&context.snapshots_dir, &project.id, deadline)?;
    // A store written before snapshots were named at their save holds
    // undo points without `named`: the last one Nah gave, which `promised`
    // names, and every snapshot only an undo point's save makes, of a
    // discard's results, of commits, or of what an undo replaced.
    let promised = store.promised()?;
    store
        .manifests()?
        .into_iter()
        .map(|snapshot| {
            let saved_as_undo = promised.as_deref() == Some(snapshot.id.as_str())
                || !snapshot.discard_results.is_empty()
                || snapshot.commits.is_some()
                || snapshot.undo_of.is_some();
            let named_ms = match store.named_ms(&snapshot.id)? {
                Some(named_ms) => Some(named_ms),
                None => saved_as_undo.then_some(snapshot.created_ms),
            };
            let undo = match named_ms {
                Some(named_ms) => Some(UndoPoint {
                    named_ms,
                    command: store.undo_for(&snapshot.id)?,
                }),
                None => None,
            };
            Ok(Listing { snapshot, undo })
        })
        .collect()
}

/// The id of every snapshot any project's store in `snapshots_dir` still
/// holds, reading no manifest: a snapshot an earlier note named and
/// retention has since removed is not among them.
pub fn kept_ids(snapshots_dir: &Path) -> io::Result<BTreeSet<String>> {
    let mut ids = BTreeSet::new();
    let stores = match fs::read_dir(snapshots_dir) {
        Ok(stores) => stores,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(ids),
        Err(error) => return Err(error),
    };
    for store in stores {
        let snapshots = match fs::read_dir(store?.path().join("snapshots")) {
            Ok(snapshots) => snapshots,
            // Not a store, such as a stray file, or one that has published
            // nothing yet.
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                ) =>
            {
                continue;
            }
            Err(error) => return Err(error),
        };
        for snapshot in snapshots {
            if let Some(id) = snapshot?.file_name().to_str() {
                ids.insert(id.to_owned());
            }
        }
    }
    Ok(ids)
}

/// A project as the store knows it.
pub(crate) struct Project {
    /// The work tree top level, or the folder.
    pub(crate) root: PathBuf,
    pub(crate) repository: Option<Repository>,
    /// Names the project's store: one per work tree, so linked worktrees of
    /// one repository get separate stores.
    pub(crate) id: String,
}

pub(crate) fn locate(context: &Context, dir: &Path, deadline: Instant) -> Result<Project, Refusal> {
    let dir = fs::canonicalize(dir).map_err(|error| Refusal::Unreadable {
        path: dir.display().to_string(),
        detail: error.to_string(),
    })?;
    let in_repository = dir
        .ancestors()
        .any(|ancestor| fs::symlink_metadata(ancestor.join(".git")).is_ok());
    if !in_repository {
        let id = hex(&Sha256::digest(format!("folder\0{}", dir.display()))[..8]);
        return Ok(Project {
            root: dir,
            repository: None,
            id,
        });
    }
    let repository = work_tree::locate(context, &dir, deadline)?;
    let id = hex(&Sha256::digest(format!(
        "git\0{}\0{}",
        repository.top.display(),
        repository.common_dir.display()
    ))[..8]);
    Ok(Project {
        root: repository.top.clone(),
        repository: Some(repository),
        id,
    })
}

/// Saves `project` into `store`. Before an undo of `restoring`, it also saves
/// every path that snapshot holds as it stands, so undoing the undo puts each
/// back. With `reuse_current`, returns the latest snapshot instead when it
/// holds the same work, and says whether it saved.
pub(crate) fn snapshot(
    context: &Context,
    store: &Store,
    project: &Project,
    named: &[PathBuf],
    restoring: Option<&Manifest>,
    budget: &Budget,
    reuse_current: bool,
) -> Result<(Manifest, bool), Refusal> {
    let latest = store.latest()?;
    let started_ns = now_ns();
    let (scan, filters) = match &project.repository {
        Some(repository) => {
            let filters = work_tree::filters(context, repository, budget.deadline)?;
            let scan =
                work_tree::scan(context, repository, &filters, named, None, budget.deadline)?;
            (scan, filters)
        }
        None => (
            folder::scan(context, &project.root, budget.deadline)?,
            Vec::new(),
        ),
    };
    let mut scan = scan;
    if let Some(restoring) = restoring {
        // Paths the scan already considered, a secret it left out included.
        let listed = scan
            .candidates
            .iter()
            .map(|candidate| candidate.path.as_str())
            .chain(
                scan.not_saved
                    .iter()
                    .filter(|left_out| left_out.reason == NotSavedReason::Secret)
                    .map(|left_out| left_out.path.as_str()),
            )
            .collect::<BTreeSet<_>>();
        // The undo may also replace what stands on a path's way or under
        // it: a file where it writes a folder, or a folder where it writes a
        // file, and their index entries.
        let paths = restoring
            .entries
            .iter()
            .map(|entry| entry.path.as_str())
            .collect::<BTreeSet<_>>();
        let folders = paths
            .iter()
            .flat_map(|path| path.match_indices('/').map(|(slash, _)| &path[..slash]))
            .collect::<BTreeSet<_>>();
        let queried = paths.union(&folders).copied().collect::<Vec<_>>();
        // A path status does not list has the same index entry as HEAD, if
        // any; recording it lets undoing this undo restage what it was.
        let mut indexed = match &project.repository {
            Some(repository) => work_tree::index_entries(
                context,
                &repository.top,
                &filters,
                &queried,
                budget.deadline,
            )?,
            None => BTreeMap::new(),
        };
        let reached = |indexed: &str| {
            paths.contains(indexed)
                || folders.contains(indexed)
                || paths.iter().any(|path| {
                    indexed
                        .strip_prefix(path)
                        .is_some_and(|rest| rest.starts_with('/'))
                })
        };
        let unlisted = paths
            .iter()
            .copied()
            .chain(
                indexed
                    .keys()
                    .map(String::as_str)
                    .filter(|path| reached(path)),
            )
            .filter(|path| !listed.contains(path))
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();
        let mut restored = Vec::with_capacity(unlisted.len());
        for path in &unlisted {
            let index = indexed.remove(path).unwrap_or_default();
            restored.push(Candidate::restored(path, index));
        }
        scan.candidates.extend(restored);
        // What the undo may replace beyond the snapshot's own paths is
        // classified like any other file: a secret there is never copied.
        scan.leave_out_secrets(context, &project.root)?;
    }
    capture(
        context,
        store,
        project,
        scan,
        &filters,
        latest,
        restoring,
        budget,
        reuse_current,
        started_ns,
    )
}

/// Copies what `scan` found into `store` and publishes it, as a snapshot
/// begun at `started_ns` that reuses `latest`'s content; with
/// `reuse_current`, a freshness check whose snapshot Nah gives as no undo
/// unless it names it, returns `latest` instead when it holds the same work.
#[allow(clippy::too_many_arguments)]
fn capture(
    context: &Context,
    store: &Store,
    project: &Project,
    scan: Scan,
    filters: &[String],
    latest: Option<Manifest>,
    restoring: Option<&Manifest>,
    budget: &Budget,
    reuse_current: bool,
    started_ns: u64,
) -> Result<(Manifest, bool), Refusal> {
    let saving = scan
        .candidates
        .iter()
        .map(|candidate| project.root.join(&candidate.path))
        .collect::<Vec<_>>();
    let pending = store.begin()?;
    let mut manifest = Capture {
        context,
        store,
        pending: &pending,
        root: &project.root,
        repository: project
            .repository
            .as_ref()
            .map(|repository| (repository, filters)),
        latest: latest.as_ref(),
        budget,
        started_ns,
    }
    .run(scan)?;
    manifest.undo_of = restoring.map(|restoring| restoring.id.clone());
    if reuse_current && let Some(latest) = latest.filter(|latest| latest.same_state(&manifest)) {
        return Ok((latest, false));
    }
    if Instant::now() >= budget.deadline {
        return Err(Refusal::OverDeadline);
    }
    // A label is recorded before the call that writes its secret runs, so a
    // file whose secret this save read is labelled by now; dropping
    // `pending` discards what the save copied.
    if let Some(labelled) = labelled(context)?
        .into_iter()
        .find(|labelled| saving.contains(labelled))
    {
        return Err(Refusal::Unreadable {
            path: labelled.display().to_string(),
            detail: "it was labelled secret while it was being saved".to_owned(),
        });
    }
    Ok((
        store.publish(
            pending,
            manifest,
            context.may_publish.as_ref(),
            true,
            !reuse_current,
            context.undo_for.as_deref(),
        )?,
        true,
    ))
}

/// The files the sessions label as secret.
fn labelled(context: &Context) -> Result<Vec<PathBuf>, Refusal> {
    (context.labelled)().map_err(|detail| Refusal::LabelsUnreadable { detail })
}

/// Looks up paths in a work tree as git does: a path below a link or a file
/// is absent. Following such a link would read, or delete, files outside the
/// project or under another name.
pub(crate) struct Lookup<'a> {
    root: &'a Path,
    /// Folders already looked up, and whether each is a real folder.
    folders: HashMap<String, bool>,
}

impl<'a> Lookup<'a> {
    pub(crate) fn new(root: &'a Path) -> Self {
        Lookup {
            root,
            folders: HashMap::new(),
        }
    }

    /// The metadata of `path`, relative to the root, without following a
    /// link; `None` where it is absent.
    pub(crate) fn metadata(&mut self, path: &str) -> io::Result<Option<fs::Metadata>> {
        let mut end = 0;
        while let Some(slash) = path[end..].find('/') {
            let folder = &path[..end + slash];
            let real = match self.folders.get(folder) {
                Some(real) => *real,
                None => {
                    let real = absent_as_none(fs::symlink_metadata(self.root.join(folder)))?
                        .is_some_and(|metadata| metadata.is_dir());
                    self.folders.insert(folder.to_owned(), real);
                    real
                }
            };
            if !real {
                return Ok(None);
            }
            end += slash + 1;
        }
        absent_as_none(fs::symlink_metadata(self.root.join(path)))
    }
}

fn absent_as_none(result: io::Result<fs::Metadata>) -> io::Result<Option<fs::Metadata>> {
    match result {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// What a scan found: the paths a save considers and those it leaves out.
#[derive(Default)]
pub(crate) struct Scan {
    pub(crate) repository: Option<RepositoryState>,
    pub(crate) candidates: Vec<Candidate>,
    pub(crate) not_saved: Vec<NotSaved>,
}

impl Scan {
    /// Moves every secret file among the candidates to the paths left out,
    /// and gives a secret file git ignores that reason.
    pub(crate) fn leave_out_secrets(
        &mut self,
        context: &Context,
        root: &Path,
    ) -> Result<(), Refusal> {
        let platform = if cfg!(target_os = "macos") {
            Platform::Macos
        } else {
            Platform::Linux
        };
        let labelled = labelled(context)?;
        let secret = |path: &str| {
            let absolute = format!("{}/{path}", root.display());
            if labelled
                .iter()
                .any(|labelled| labelled.as_os_str() == absolute.as_str())
            {
                return Ok(true);
            }
            let target =
                AbsolutePath::new(platform, &absolute).map_err(|_| Refusal::Unreadable {
                    path: absolute.clone(),
                    detail: "its path cannot be classified".to_owned(),
                })?;
            Ok::<_, Refusal>(matches!(
                sensitivity(&absolute, &target, &context.home, platform, false),
                Sensitivity::EnvironmentSecret
                    | Sensitivity::CredentialSecret
                    | Sensitivity::KeyMaterial
            ))
        };
        let mut kept = Vec::with_capacity(self.candidates.len());
        for candidate in std::mem::take(&mut self.candidates) {
            if secret(&candidate.path)? {
                self.not_saved.push(NotSaved {
                    path: candidate.path,
                    reason: NotSavedReason::Secret,
                    origin: Some(candidate.origin),
                });
            } else {
                kept.push(candidate);
            }
        }
        self.candidates = kept;
        for left_out in &mut self.not_saved {
            if left_out.reason == NotSavedReason::Ignored
                && !left_out.path.ends_with('/')
                && secret(&left_out.path)?
            {
                left_out.reason = NotSavedReason::Secret;
            }
        }
        Ok(())
    }
}

/// One path a save considers.
pub(crate) struct Candidate {
    pub(crate) path: String,
    pub(crate) origin: Origin,
    pub(crate) head: Option<Stage>,
    pub(crate) index: Vec<Stage>,
    pub(crate) staged: bool,
    /// Git found the work tree file the same as the index entry.
    pub(crate) worktree_matches_index: bool,
    /// The index marks the path intent-to-add (`git add -N`), with no
    /// staged version.
    pub(crate) intent_to_add: bool,
}

impl Candidate {
    fn restored(path: &str, index: Vec<Stage>) -> Self {
        Self {
            head: match index.as_slice() {
                [stage] if stage.stage == 0 => Some(stage.clone()),
                _ => None,
            },
            index,
            ..Self::untracked(path, Origin::Restored)
        }
    }

    /// The path `entry` saved, to be looked at again.
    fn of_entry(entry: &Entry) -> Self {
        Candidate {
            path: entry.path.clone(),
            origin: entry.origin,
            head: entry.head.clone(),
            index: entry.index.clone(),
            staged: entry.staged,
            worktree_matches_index: false,
            intent_to_add: entry.intent_to_add,
        }
    }

    pub(crate) fn untracked(path: &str, origin: Origin) -> Self {
        Candidate {
            path: path.to_owned(),
            origin,
            head: None,
            index: Vec::new(),
            staged: false,
            worktree_matches_index: false,
            intent_to_add: false,
        }
    }
}
