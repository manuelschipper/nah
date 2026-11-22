//! Undo, which `nah undo` runs: restores a snapshot into the work tree and
//! index, or into a separate folder. A snapshot of commits is undone by
//! `commits::undo`.

use crate::capture::sha256_of;
use crate::commits;
use crate::git::{self, GitFailure};
use crate::manifest::{Content, Entry, FileKind, Manifest, NotSavedReason, Origin, Saved, Stage};
use crate::store::{Pending, Store, hex};
use crate::work_tree::{self, GITLINK};
use crate::{Budget, Context, Lookup, Project, Refusal, locate, snapshot, store, store_failure};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs::{self, File};
use std::io;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

/// How long the restore itself may run once the state before it is saved:
/// stopping halfway would leave a mix of both.
const RESTORE_TIME: Duration = Duration::from_secs(3600);

/// The name of the empty blob, which an intent-to-add entry holds.
const EMPTY_BLOB: &str = "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391";

/// Most blob bytes read from the store at once.
const FETCH_BYTES: u64 = 256 * 1024 * 1024;

/// Folder of a restore `--into` that holds the saved index versions, under
/// one folder per stage: `0/` for a staged version differing from the work
/// tree's, `1/` to `3/` for an unmerged path's base, ours and theirs. Where
/// the snapshot itself holds a path there, the first of `.nah-index-2`,
/// `.nah-index-3`, ... it does not hold is used instead.
const INDEX_FOLDER: &str = ".nah-index";

#[derive(Clone, Debug, Serialize)]
pub struct UndoOutcome {
    pub snapshot: String,
    /// The snapshot of the state the undo replaced, which undoes it; `None`
    /// for a restore into a separate folder.
    pub before_undo: Option<String>,
    /// Absolute paths of the files, links and folders it wrote.
    pub written: Vec<String>,
    /// Absolute paths of the files it removed.
    pub removed: Vec<String>,
    /// Paths, relative to the work tree, whose staged state it restored.
    pub staged: Vec<String>,
    /// Clean paths restored from Git, by relative path and destination.
    #[serde(skip)]
    pub clean_restored: BTreeMap<String, String>,
    /// The refs and stash entries it restored or took away.
    pub refs: Vec<String>,
    /// Paths it left alone.
    pub conflicts: Vec<Conflict>,
}

/// A path the undo did not overwrite, with the reason.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Conflict {
    pub path: String,
    pub reason: String,
}

/// Restores snapshot `id` of `project`. In place, it first saves the current
/// state within `budget`, and stops if that save is refused; a path changed
/// since the snapshot in a way a discard does not explain is left alone and
/// reported. With `into`, it writes the whole snapshot into that empty or
/// missing folder instead and touches nothing else.
pub fn undo(
    context: &Context,
    project: &Path,
    id: &str,
    into: Option<&Path>,
    budget: Budget,
) -> Result<UndoOutcome, Refusal> {
    undo_refusing(context, project, id, into, budget, |_, _| BTreeMap::new())
}

/// As [`undo`], leaving out the paths `refuse` names. It is given the folder
/// the restore writes into and every path, relative to it, the snapshot
/// holds, and returns the paths not to write, each with the reason, which
/// the outcome reports as conflicts.
pub fn undo_refusing(
    context: &Context,
    project: &Path,
    id: &str,
    into: Option<&Path>,
    budget: Budget,
    refuse: impl FnOnce(&Path, &[&str]) -> BTreeMap<String, String>,
) -> Result<UndoOutcome, Refusal> {
    let located = locate(context, project, budget.deadline)?;
    let store = store::open(&context.snapshots_dir, &located.id, budget.deadline)?;
    let mut manifest = store.find(id)?.ok_or_else(|| Refusal::Invalid {
        detail: format!("this project has no snapshot `{id}`; `nah snapshots` lists them"),
    })?;
    if let Some(commits) = &manifest.commits {
        return commits::undo(context, &store, &located, &manifest, commits, into, budget);
    }
    // A separate folder also gets the files deleted since, which an undo in
    // place leaves deleted.
    if into.is_some() {
        for deleted in std::mem::take(&mut manifest.deleted) {
            match manifest
                .entries
                .iter_mut()
                .find(|entry| entry.path == deleted.path)
            {
                Some(entry) => entry.worktree = entry.worktree.take().or(deleted.worktree),
                None => manifest.entries.push(deleted),
            }
        }
        manifest
            .entries
            .sort_by(|left, right| left.path.cmp(&right.path));
    }
    if let Some(entry) = manifest
        .entries
        .iter()
        .find(|entry| !safe_path(&entry.path))
    {
        return Err(Refusal::Invalid {
            detail: format!("snapshot `{id}` names an unsafe path: {}", entry.path),
        });
    }
    let paths = manifest
        .entries
        .iter()
        .map(|entry| entry.path.as_str())
        .collect::<Vec<_>>();
    let missing = if into.is_none() {
        let saved = paths.iter().copied().collect::<HashSet<_>>();
        manifest
            .discard_results
            .keys()
            .filter(|path| !saved.contains(path.as_str()))
            .map(|path| Conflict {
                path: path.clone(),
                reason: "its pre-discard state was not saved".to_owned(),
            })
            .collect()
    } else {
        Vec::new()
    };
    let refused = refuse(into.unwrap_or(&located.root), &paths);
    manifest
        .entries
        .retain(|entry| !refused.contains_key(&entry.path));
    let restorer = Restorer {
        context,
        store: &store,
        manifest: &manifest,
        deadline: Instant::now() + RESTORE_TIME,
    };
    let mut outcome = match into {
        Some(into) => restorer.to_folder(into, located.repository.as_ref())?,
        None => {
            let (before, _) = snapshot(
                context,
                &store,
                &located,
                &[],
                Some(&manifest),
                &budget,
                false,
            )?;
            // A secret the save before the undo left out could not be put
            // back by undoing the undo, so the undo leaves it in place.
            let secrets = before
                .not_saved
                .iter()
                .filter(|left_out| left_out.reason == NotSavedReason::Secret)
                .map(|left_out| left_out.path.clone())
                .collect::<HashSet<_>>();
            let mut outcome = restorer.in_place(&located, &secrets)?;
            outcome.before_undo = Some(before.id);
            outcome
        }
    };
    outcome.conflicts.extend(
        refused
            .into_iter()
            .map(|(path, reason)| Conflict { path, reason }),
    );
    outcome.conflicts.extend(missing);
    Ok(outcome)
}

/// A relative path with no empty, `.`, `..` or `.git` component.
pub(crate) fn safe_path(path: &str) -> bool {
    !path.is_empty()
        && path.split('/').all(|component| {
            !matches!(component, "" | "." | "..") && !component.eq_ignore_ascii_case(".git")
        })
}

/// What stands at a snapshot's path now.
enum Current {
    /// Nothing, or nothing git would see: the path is below a link or a file.
    Absent,
    /// A file or link, with its blob name and, for comparing with a plain
    /// copy, its SHA-256.
    Present {
        kind: FileKind,
        oid: String,
        sha256: Option<String>,
    },
    Folder,
    /// Neither a file, a link nor a folder.
    Special,
}

#[derive(Clone, Copy)]
enum WorktreeVersion<'a> {
    Saved(&'a Saved),
    Head(&'a Stage, FileKind),
}

impl Entry {
    fn worktree_version(&self) -> Option<WorktreeVersion<'_>> {
        if self.origin == Origin::Clean {
            let head = self.head.as_ref()?;
            return Some(WorktreeVersion::Head(head, head.file_kind()?));
        }
        self.worktree.as_ref().map(WorktreeVersion::Saved)
    }
}

impl<'a> WorktreeVersion<'a> {
    /// The permission bits the saved file had; a clean file's come from its
    /// kind, as Git's checkout gives them.
    fn permissions(self) -> Option<u32> {
        match self {
            Self::Saved(saved) => Some(saved.stat.mode & 0o7777).filter(|mode| *mode != 0),
            Self::Head(..) => None,
        }
    }

    fn kind(self) -> FileKind {
        match self {
            Self::Saved(saved) => saved.kind,
            Self::Head(_, kind) => kind,
        }
    }

    fn oid(self) -> Option<&'a str> {
        match self {
            Self::Saved(Saved {
                content: Content::Blob { oid },
                ..
            })
            | Self::Head(Stage { oid, .. }, _) => Some(oid),
            Self::Saved(_) => None,
        }
    }

    fn matches(self, current: &Current) -> bool {
        let Current::Present { kind, oid, sha256 } = current else {
            return false;
        };
        *kind == self.kind()
            && match self {
                Self::Saved(Saved {
                    content: Content::File { sha256: saved },
                    ..
                }) => sha256.as_ref() == Some(saved),
                _ => self.oid() == Some(oid),
            }
    }
}

struct Restorer<'a> {
    context: &'a Context,
    store: &'a Store,
    manifest: &'a Manifest,
    deadline: Instant,
}

impl Restorer<'_> {
    fn in_place(
        &self,
        project: &Project,
        secrets: &HashSet<String>,
    ) -> Result<UndoOutcome, Refusal> {
        let root = &project.root;
        let pending = self.store.begin()?;
        // Undoing an undo overwrites what that undo wrote.
        let undone = match &self.manifest.undo_of {
            Some(id) => self.store.find(id)?,
            None => None,
        };
        let undone = undone
            .iter()
            .flat_map(|undone| &undone.entries)
            .map(|entry| (entry.path.as_str(), entry))
            .collect::<HashMap<_, _>>();
        let current = self.current(root, &pending, |entry| {
            [Some(entry), undone.get(entry.path.as_str()).copied()]
                .into_iter()
                .flatten()
                .filter_map(|entry| entry.worktree.as_ref())
                .any(|saved| matches!(saved.content, Content::File { .. }))
        })?;
        let mut outcome = UndoOutcome {
            snapshot: self.manifest.id.clone(),
            before_undo: None,
            written: Vec::new(),
            removed: Vec::new(),
            staged: Vec::new(),
            clean_restored: BTreeMap::new(),
            refs: Vec::new(),
            conflicts: Vec::new(),
        };
        let mut writes = Vec::new();
        let mut suspects = Vec::new();
        // Snapshot files where a folder stands now, which removing the files
        // the snapshot lacks may empty; an empty folder is replaced.
        let mut folders = Vec::new();
        for (entry, current) in self.manifest.entries.iter().zip(current) {
            let result = self.manifest.discard_results.get(&entry.path);
            match (entry.worktree_version(), &current, result) {
                (_, Current::Special, _) => outcome.conflicts.push(Conflict {
                    path: entry.path.clone(),
                    reason: "a special file stands there now".to_owned(),
                }),
                // The snapshot had no file there either: a folder's files are
                // entries of their own, and a submodule's are not saved.
                (None, Current::Absent | Current::Folder, _) => {}
                (Some(saved), _, _) if saved.matches(&current) => {}
                (_, current, Some(result)) => {
                    let matches = match (current, &result.worktree) {
                        (Current::Absent, None) => true,
                        (Current::Present { kind, oid, .. }, Some(stage)) => {
                            stage.oid == *oid && stage.mode == kind.mode()
                        }
                        _ => false,
                    };
                    if matches {
                        writes.push(entry);
                    } else {
                        outcome.conflicts.push(Conflict {
                            path: entry.path.clone(),
                            reason: "it changed since the snapshot was taken".to_owned(),
                        });
                    }
                }
                (Some(_), Current::Folder, None) => folders.push(entry),
                (_, current, None)
                    if replaceable(entry, current)
                        || undone
                            .get(entry.path.as_str())
                            .and_then(|entry| entry.worktree_version())
                            .is_some_and(|saved| saved.matches(current)) =>
                {
                    writes.push(entry);
                }
                _ => suspects.push(entry),
            }
        }
        let checked_out = match &project.repository {
            Some(repository) => self.checked_out(repository, root, &suspects, &pending)?,
            None => HashSet::new(),
        };
        suspects.retain(|entry| {
            let explained = checked_out.contains(entry.path.as_str());
            if explained {
                writes.push(entry);
            }
            !explained
        });
        let committed = match &project.repository {
            Some(repository) => {
                let paths = suspects
                    .iter()
                    .map(|entry| entry.path.as_str())
                    .collect::<Vec<_>>();
                self.committed(repository, &paths, secrets)?
            }
            None => HashSet::new(),
        };
        for entry in suspects {
            if committed.contains(entry.path.as_str()) {
                writes.push(entry);
            } else {
                outcome.conflicts.push(Conflict {
                    path: entry.path.clone(),
                    reason: "it changed since the snapshot was taken".to_owned(),
                });
            }
        }
        let entries = writes.iter().chain(&folders).copied();
        let mut fetched = self.fetch(entries.clone(), &pending)?;
        self.fetch_repository(project.repository.as_ref(), entries, &pending, &mut fetched)?;
        // Removals first: a file the snapshot lacks may stand where it has a
        // folder.
        for entry in writes
            .iter()
            .filter(|entry| entry.worktree_version().is_none())
        {
            let target = root.join(&entry.path);
            match fs::remove_file(&target) {
                Ok(()) => {
                    outcome.removed.push(target.display().to_string());
                    // As git does, a folder the removal empties goes too.
                    for folder in target.ancestors().skip(1) {
                        if folder == root.as_path() || fs::remove_dir(folder).is_err() {
                            break;
                        }
                        outcome.removed.push(folder.display().to_string());
                    }
                }
                Err(error) => outcome.conflicts.push(Conflict {
                    path: entry.path.clone(),
                    reason: format!("it could not be removed: {error}"),
                }),
            }
        }
        let mut filled = Vec::new();
        for entry in folders {
            // An empty folder holds no work: a checkout leaves one where a
            // submodule was.
            let folder = root.join(&entry.path);
            match fs::remove_dir(&folder) {
                Ok(()) => {
                    outcome.removed.push(folder.display().to_string());
                    writes.push(entry);
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => writes.push(entry),
                Err(_) => filled.push(entry),
            }
        }
        // A folder a discard checked out from another commit, all of it
        // committed and clean: git still holds it, so it makes way.
        let committed = match &project.repository {
            Some(repository) => {
                let paths = filled
                    .iter()
                    .map(|entry| entry.path.as_str())
                    .collect::<Vec<_>>();
                self.committed(repository, &paths, secrets)?
            }
            None => HashSet::new(),
        };
        for entry in filled {
            let folder = root.join(&entry.path);
            if committed.contains(&entry.path) && fs::remove_dir_all(&folder).is_ok() {
                outcome.removed.push(folder.display().to_string());
                writes.push(entry);
            } else {
                outcome.conflicts.push(Conflict {
                    path: entry.path.clone(),
                    reason: "a folder stands there now".to_owned(),
                });
            }
        }
        // A file where the snapshot has a folder, which a discard checked
        // out from another commit: git still holds it, so it makes way.
        let in_the_way = writes
            .iter()
            .filter(|entry| entry.worktree_version().is_some())
            .filter_map(|entry| {
                entry
                    .path
                    .match_indices('/')
                    .map(|(slash, _)| &entry.path[..slash])
                    .find(|folder| {
                        fs::symlink_metadata(root.join(folder)).is_ok_and(|found| !found.is_dir())
                    })
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        if let Some(repository) = &project.repository {
            for file in self.committed(repository, &in_the_way, secrets)? {
                let file = root.join(file);
                if fs::remove_file(&file).is_ok() {
                    outcome.removed.push(file.display().to_string());
                }
            }
        }
        for entry in writes {
            let Some(saved) = entry.worktree_version() else {
                continue;
            };
            let written = self.source(saved, &fetched).and_then(|source| {
                place(
                    root,
                    &entry.path,
                    saved.kind(),
                    saved.permissions(),
                    &source,
                    &mut outcome.written,
                )
            });
            match written {
                Ok(()) => outcome
                    .written
                    .push(root.join(&entry.path).display().to_string()),
                Err(reason) => outcome.conflicts.push(Conflict {
                    path: entry.path.clone(),
                    reason,
                }),
            }
        }
        if let Some(repository) = &project.repository {
            self.restore_index(repository, &undone, &mut outcome)?;
        }
        self.summarize_clean(root, &mut outcome);
        Ok(outcome)
    }

    fn summarize_clean(&self, root: &Path, outcome: &mut UndoOutcome) {
        let left = outcome
            .conflicts
            .iter()
            .map(|conflict| conflict.path.as_str())
            .collect::<HashSet<_>>();
        let restored = outcome
            .staged
            .iter()
            .map(String::as_str)
            .chain(
                outcome
                    .written
                    .iter()
                    .filter_map(|path| Path::new(path).strip_prefix(root).ok()?.to_str()),
            )
            .collect::<HashSet<_>>();
        outcome.clean_restored = self
            .manifest
            .entries
            .iter()
            .filter(|entry| {
                entry.origin == Origin::Clean
                    && restored.contains(entry.path.as_str())
                    && !left.contains(entry.path.as_str())
            })
            .map(|entry| {
                (
                    entry.path.clone(),
                    root.join(&entry.path).display().to_string(),
                )
            })
            .collect();
    }

    /// The paths among `entries` whose work tree file is what a checkout
    /// writes for their HEAD or index version, where a filter makes those
    /// bytes differ from the blob: a Git LFS file smudged from its pointer, or
    /// a text file given CRLF line endings. A discard such as `reset --hard`
    /// leaves exactly that, which undo may then overwrite.
    fn checked_out(
        &self,
        repository: &work_tree::Repository,
        root: &Path,
        entries: &[&Entry],
        pending: &Pending,
    ) -> Result<HashSet<String>, Refusal> {
        let mut explained = HashSet::new();
        if entries.is_empty() {
            return Ok(explained);
        }
        let blobs = entries
            .iter()
            .flat_map(|entry| entry.head.iter().chain(&entry.index))
            .filter(|stage| stage.mode != GITLINK)
            .map(|stage| stage.oid.as_str())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let filters = work_tree::filters(self.context, repository, self.deadline)?;
        let repository_git = || git::repository(&self.context.git, &repository.top, &filters);
        let sizes = work_tree::object_sizes(repository_git(), &blobs, self.deadline)
            .map_err(GitFailure::repository)?;
        // A pointer is a small text blob naming its content's SHA-256.
        let small = blobs
            .iter()
            .zip(sizes)
            .filter(|(_, size)| size.is_some_and(|size| size <= 1024))
            .map(|(oid, _)| *oid)
            .collect::<Vec<_>>();
        let pointers = work_tree::read_objects(repository_git(), &small, self.deadline)?
            .into_iter()
            .zip(&small)
            .filter_map(|(blob, oid)| {
                let text = String::from_utf8(blob).ok()?;
                let content = text
                    .strip_prefix("version https://git-lfs.github.com/spec/v1\n")?
                    .lines()
                    .find_map(|line| line.strip_prefix("oid sha256:"))?
                    .to_owned();
                Some((*oid, content))
            })
            .collect::<HashMap<_, _>>();
        let mut normalized = Vec::new();
        for (position, entry) in entries.iter().enumerate() {
            let path = root.join(&entry.path);
            // A checkout writes a regular file in its stage's mode.
            let Ok(metadata) = fs::symlink_metadata(&path) else {
                continue;
            };
            if !metadata.is_file() {
                continue;
            }
            let mode = if metadata.permissions().mode() & 0o100 != 0 {
                FileKind::Executable.mode()
            } else {
                FileKind::File.mode()
            };
            let Ok(bytes) = fs::read(&path) else {
                continue;
            };
            let base = || {
                entry
                    .head
                    .iter()
                    .chain(&entry.index)
                    .filter(move |stage| stage.mode == mode)
            };
            let sha256 = hex(&Sha256::digest(&bytes));
            if base().any(|stage| pointers.get(stage.oid.as_str()) == Some(&sha256)) {
                explained.insert(entry.path.clone());
            } else if bytes.windows(2).any(|pair| pair == b"\r\n") {
                let lf = String::from_utf8_lossy(&bytes).replace("\r\n", "\n");
                let copy = pending.scratch().join(format!("lf-{position}"));
                fs::write(&copy, lf).map_err(store_failure)?;
                normalized.push((*entry, copy, mode));
            }
        }
        if !normalized.is_empty() {
            let mut command = git::store(&self.context.git, &self.store.git_dir(), None);
            command.args(["hash-object", "--no-filters", "--stdin-paths"]);
            let mut input = Vec::new();
            for (_, copy, _) in &normalized {
                input.extend_from_slice(copy.as_os_str().as_bytes());
                input.push(b'\n');
            }
            let output = git::output(command, input, self.deadline).map_err(GitFailure::store)?;
            for ((entry, _, mode), oid) in normalized
                .iter()
                .zip(String::from_utf8_lossy(&output).lines())
            {
                if entry
                    .head
                    .iter()
                    .chain(&entry.index)
                    .any(|stage| stage.oid == oid && stage.mode == *mode)
                {
                    explained.insert(entry.path.clone());
                }
            }
        }
        Ok(explained)
    }

    /// The paths among `paths` whose file, or every file under the folder, is
    /// exactly the version HEAD and the index hold now. A discard that lands on another commit (`reset
    /// --hard origin/main`, `checkout -f other`) leaves that; git still
    /// holds it, so undo may overwrite it. Anything git status lists there,
    /// changed, staged, untracked or ignored, is newer work and stays.
    fn committed(
        &self,
        repository: &work_tree::Repository,
        paths: &[&str],
        secrets: &HashSet<String>,
    ) -> Result<HashSet<String>, Refusal> {
        if paths.is_empty() {
            return Ok(HashSet::new());
        }
        let filters = work_tree::filters(self.context, repository, self.deadline)?;
        let mut listed = HashSet::new();
        for chunk in paths.chunks(500) {
            let mut command = git::repository(&self.context.git, &repository.top, &filters);
            command.args([
                "status",
                "--porcelain=v1",
                "-z",
                "--untracked-files=all",
                "--ignored=matching",
                "--no-renames",
                "--",
            ]);
            command.args(chunk.iter().map(|path| format!(":(literal){path}")));
            let output =
                git::output(command, Vec::new(), self.deadline).map_err(GitFailure::repository)?;
            listed.extend(
                output
                    .split(|byte| *byte == 0)
                    .filter_map(|record| record.get(3..))
                    .filter(|path| !path.is_empty())
                    .map(|path| String::from_utf8_lossy(path).into_owned()),
            );
        }
        // Status says nothing of a file marked assume-unchanged or
        // skip-worktree, nor of a submodule's or a nested repository's own
        // history: every file there must be an ordinary index entry, which
        // git can write back.
        let mut tracked = HashMap::new();
        for chunk in paths.chunks(500) {
            let mut command = git::repository(&self.context.git, &repository.top, &filters);
            command.args(["ls-files", "-s", "-v", "-z", "--"]);
            command.args(chunk.iter().map(|path| format!(":(literal){path}")));
            let output =
                git::output(command, Vec::new(), self.deadline).map_err(GitFailure::repository)?;
            for record in output.split(|byte| *byte == 0) {
                let record = String::from_utf8_lossy(record);
                if let Some((fields, path)) = record.split_once('\t') {
                    let mut fields = fields.split(' ');
                    let ordinary = fields.next() == Some("H") && fields.next() != Some(GITLINK);
                    tracked.insert(path.to_owned(), ordinary);
                }
            }
        }
        let mut committed = HashSet::new();
        for path in paths {
            let below = format!("{path}/");
            let changed = listed
                .iter()
                .any(|listed| listed == *path || listed.starts_with(&below));
            let hidden = tracked.iter().any(|(entry, ordinary)| {
                !ordinary && (entry == *path || entry.starts_with(&below))
            });
            let secret = secrets
                .iter()
                .any(|secret| secret == *path || secret.starts_with(&below));
            if changed || hidden || secret {
                continue;
            }
            let files = files_under(&repository.top, path)?;
            if files.is_some_and(|files| files.iter().all(|file| tracked.get(file) == Some(&true)))
            {
                committed.insert((*path).to_owned());
            }
        }
        Ok(committed)
    }

    /// What stands at each entry's path under `root`, in entry order, with
    /// its SHA-256 where `compares_plain` says a plain copy may match it.
    fn current(
        &self,
        root: &Path,
        pending: &Pending,
        compares_plain: impl Fn(&Entry) -> bool,
    ) -> Result<Vec<Current>, Refusal> {
        let scratch = pending.scratch();
        let mut lookup = Lookup::new(root);
        let mut states = Vec::new();
        let mut hashed = Vec::new();
        for (position, entry) in self.manifest.entries.iter().enumerate() {
            let path = root.join(&entry.path);
            let unreadable = |error: io::Error| Refusal::Unreadable {
                path: path.display().to_string(),
                detail: error.to_string(),
            };
            let Some(metadata) = lookup.metadata(&entry.path).map_err(unreadable)? else {
                states.push(Current::Absent);
                continue;
            };
            let (kind, hashed_path) = if metadata.file_type().is_symlink() {
                let link = scratch.join(format!("link-{position}"));
                let target = fs::read_link(&path).map_err(unreadable)?;
                fs::write(&link, target.into_os_string().into_vec()).map_err(store_failure)?;
                (FileKind::Symlink, link)
            } else if metadata.is_file() {
                let kind = if metadata.permissions().mode() & 0o100 != 0 {
                    FileKind::Executable
                } else {
                    FileKind::File
                };
                if entry.path.contains(['\n', '\r']) {
                    let copy = scratch.join(format!("copy-{position}"));
                    fs::copy(&path, &copy).map_err(unreadable)?;
                    (kind, copy)
                } else {
                    (kind, path.clone())
                }
            } else {
                states.push(if metadata.is_dir() {
                    Current::Folder
                } else {
                    Current::Special
                });
                continue;
            };
            let sha256 = if compares_plain(entry) {
                Some(sha256_of(&hashed_path).map_err(unreadable)?.0)
            } else {
                None
            };
            hashed.push(hashed_path);
            states.push(Current::Present {
                kind,
                oid: String::new(),
                sha256,
            });
        }
        if hashed.is_empty() {
            return Ok(states);
        }
        let mut command = git::store(&self.context.git, &self.store.git_dir(), None);
        command.args(["hash-object", "--no-filters", "--stdin-paths"]);
        let mut input = Vec::new();
        for path in &hashed {
            input.extend_from_slice(path.as_os_str().as_bytes());
            input.push(b'\n');
        }
        let output = git::output(command, input, self.deadline).map_err(GitFailure::store)?;
        let mut oids = String::from_utf8_lossy(&output)
            .lines()
            .map(str::to_owned)
            .collect::<Vec<_>>()
            .into_iter();
        for state in &mut states {
            if let Current::Present { oid, .. } = state {
                *oid = oids.next().ok_or_else(|| Refusal::StoreUnwritable {
                    detail: "git hashed fewer files than it was given".to_owned(),
                })?;
            }
        }
        Ok(states)
    }

    /// Reads every blob the `entries` restore out of the store into scratch
    /// files, by blob name.
    fn fetch<'e>(
        &self,
        entries: impl Iterator<Item = &'e Entry>,
        pending: &Pending,
    ) -> Result<HashMap<String, PathBuf>, Refusal> {
        let mut wanted = BTreeMap::new();
        for entry in entries {
            if let Some(saved) = &entry.worktree
                && let Content::Blob { oid } = &saved.content
            {
                wanted.insert(oid.clone(), saved.size);
            }
        }
        self.fetch_store_blobs(wanted, pending)
    }

    fn fetch_store_blobs(
        &self,
        wanted: BTreeMap<String, u64>,
        pending: &Pending,
    ) -> Result<HashMap<String, PathBuf>, Refusal> {
        let mut fetched = HashMap::new();
        self.fetch_blobs(
            wanted,
            pending,
            || git::store(&self.context.git, &self.store.git_dir(), None),
            &mut fetched,
        )
        .map_err(|error| match error {
            Refusal::RepositoryUnreadable { .. } => Refusal::StoreUnwritable {
                detail: "a saved blob is missing from the store".to_owned(),
            },
            error => error,
        })?;
        Ok(fetched)
    }

    fn fetch_repository<'e>(
        &self,
        repository: Option<&work_tree::Repository>,
        entries: impl Iterator<Item = &'e Entry>,
        pending: &Pending,
        fetched: &mut HashMap<String, PathBuf>,
    ) -> Result<(), Refusal> {
        let oids = entries
            .filter_map(|entry| match entry.worktree_version()? {
                WorktreeVersion::Head(stage, _) if !fetched.contains_key(&stage.oid) => {
                    Some(stage.oid.as_str())
                }
                _ => None,
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let Some(repository) = repository.filter(|_| !oids.is_empty()) else {
            return Ok(());
        };
        let command = || git::repository(&self.context.git, &repository.top, &[]);
        let sizes = work_tree::object_sizes(command(), &oids, self.deadline)
            .map_err(GitFailure::repository)?;
        let wanted = oids
            .into_iter()
            .zip(sizes)
            .filter_map(|(oid, size)| Some((oid.to_owned(), size?)))
            .collect();
        self.fetch_blobs(wanted, pending, command, fetched)
    }

    fn fetch_blobs(
        &self,
        wanted: BTreeMap<String, u64>,
        pending: &Pending,
        command: impl Fn() -> Command,
        fetched: &mut HashMap<String, PathBuf>,
    ) -> Result<(), Refusal> {
        let mut batch = Vec::new();
        let mut batch_bytes = 0;
        let mut wanted = wanted.into_iter().peekable();
        while let Some((oid, size)) = wanted.next() {
            batch_bytes += size;
            batch.push(oid);
            if batch_bytes >= FETCH_BYTES || wanted.peek().is_none() {
                let oids = batch.iter().map(String::as_str).collect::<Vec<_>>();
                let blobs = work_tree::read_objects(command(), &oids, self.deadline)?;
                for (oid, blob) in batch.drain(..).zip(blobs) {
                    let file = pending.scratch().join(format!("blob-{}", fetched.len()));
                    fs::write(&file, blob).map_err(store_failure)?;
                    fetched.insert(oid, file);
                }
                batch_bytes = 0;
            }
        }
        Ok(())
    }

    /// The store file holding `content`.
    fn source(
        &self,
        version: WorktreeVersion<'_>,
        fetched: &HashMap<String, PathBuf>,
    ) -> Result<PathBuf, String> {
        match version {
            WorktreeVersion::Saved(Saved {
                content: Content::File { sha256 },
                ..
            }) => Ok(self.store.plain_file(sha256)),
            WorktreeVersion::Saved(Saved {
                content: Content::Blob { oid },
                ..
            })
            | WorktreeVersion::Head(Stage { oid, .. }, _) => fetched
                .get(oid)
                .cloned()
                .ok_or_else(|| "its saved Git blob is unavailable".to_owned()),
        }
    }

    /// Restores the index entries of every staged path whose entries are
    /// still what the discard left, or, undoing an undo, still what that
    /// undo staged.
    fn restore_index(
        &self,
        repository: &work_tree::Repository,
        undone: &HashMap<&str, &Entry>,
        outcome: &mut UndoOutcome,
    ) -> Result<(), Refusal> {
        // Staging a path replaces the staged entries on its way and under
        // it, so the undo being undone may have unstaged those too.
        let displaced = |path: &str| {
            let below = format!("{path}/");
            undone.iter().any(|(staged, entry)| {
                (entry.staged || entry.intent_to_add)
                    && (path.starts_with(&format!("{staged}/")) || staged.starts_with(&below))
            })
        };
        let staged = self
            .manifest
            .entries
            .iter()
            .filter(|entry| {
                entry.staged
                    || entry.intent_to_add
                    || self
                        .manifest
                        .discard_results
                        .get(&entry.path)
                        .is_some_and(|result| result.index.is_some())
                    || undone
                        .get(entry.path.as_str())
                        .is_some_and(|undone| undone.staged || undone.intent_to_add)
                    || (!entry.index.is_empty() && displaced(&entry.path))
            })
            .collect::<Vec<_>>();
        if staged.is_empty() {
            return Ok(());
        }
        let filters = work_tree::filters(self.context, repository, self.deadline)?;
        // Each path, and the folders on its way: a staged file at one of them,
        // or under the path itself, is replaced by staging the path.
        let paths = staged
            .iter()
            .flat_map(|entry| {
                entry
                    .path
                    .match_indices('/')
                    .map(|(slash, _)| &entry.path[..slash])
                    .chain([entry.path.as_str()])
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let current = work_tree::index_entries(
            self.context,
            &repository.top,
            &filters,
            &paths,
            self.deadline,
        )?;
        // HEAD's version of each staged path and of each index entry staging
        // one would displace.
        let head_paths = staged
            .iter()
            .map(|entry| entry.path.as_str())
            .chain(current.keys().map(String::as_str))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let head = work_tree::head_entries(
            self.context,
            repository,
            &filters,
            &head_paths,
            self.deadline,
        )?;
        let at_head = |path: &str, stages: &[crate::Stage]| {
            head.get(path)
                .is_some_and(|version| stages == std::slice::from_ref(version))
        };
        let blobs = staged
            .iter()
            .flat_map(|entry| &entry.index)
            .filter(|stage| stage.mode != GITLINK)
            .map(|stage| stage.oid.as_str())
            .collect::<Vec<_>>();
        let command = git::repository(&self.context.git, &repository.top, &filters);
        let present = if blobs.is_empty() {
            Vec::new()
        } else {
            work_tree::object_sizes(command, &blobs, self.deadline)
                .map_err(GitFailure::repository)?
        };
        let present = blobs
            .into_iter()
            .zip(present)
            .filter_map(|(oid, size)| size.map(|_| oid))
            .collect::<HashSet<_>>();
        let mut planned = Vec::new();
        for entry in staged {
            let now = current.get(&entry.path).cloned().unwrap_or_default();
            let result = self.manifest.discard_results.get(&entry.path);
            let matches_discard = result.is_some_and(|result| result.index.as_ref() == Some(&now));
            if entry.intent_to_add {
                if matches_discard || (result.is_none() && now.is_empty()) {
                    planned.push(entry);
                } else if !intent_to_add_entry(&now) {
                    outcome.conflicts.push(Conflict {
                        path: entry.path.clone(),
                        reason: "its staged state changed since the snapshot was taken".to_owned(),
                    });
                }
                continue;
            }
            if now == entry.index {
                continue;
            }
            let discarded = entry.head.iter().cloned().collect::<Vec<_>>();
            // A discard onto another commit stages that commit's version,
            // which git keeps; anything else staged there is newer work.
            let landed = head
                .get(&entry.path)
                .cloned()
                .into_iter()
                .collect::<Vec<_>>();
            let restaged = undone.get(entry.path.as_str()).is_some_and(|undone| {
                undone.index == now || (undone.intent_to_add && intent_to_add_entry(&now))
            }) || (now.is_empty() && displaced(&entry.path));
            let newer = if result.is_some() {
                !matches_discard
            } else {
                now != discarded && now != landed && !restaged
            };
            let reason = if newer {
                Some("its staged state changed since the snapshot was taken")
            } else if entry
                .index
                .iter()
                .any(|stage| stage.mode != GITLINK && !present.contains(stage.oid.as_str()))
            {
                Some("its staged content is no longer in the repository; restore it with --into")
            } else {
                None
            };
            match reason {
                Some(reason) => outcome.conflicts.push(Conflict {
                    path: entry.path.clone(),
                    reason: reason.to_owned(),
                }),
                None => planned.push(entry),
            }
        }
        let restaging = planned
            .iter()
            .map(|entry| entry.path.as_str())
            .collect::<HashSet<_>>();
        let mut input = Vec::new();
        let mut intents = Vec::new();
        for entry in planned {
            // Git replaces a staged file at a folder on this path, or staged
            // files under it, without asking; one this undo does not restore
            // itself is newer work.
            let below = format!("{}/", entry.path);
            let displaced = entry
                .path
                .match_indices('/')
                .map(|(slash, _)| &entry.path[..slash])
                .filter(|folder| current.contains_key(*folder))
                .chain(
                    current
                        .range(below.clone()..)
                        .map(|(path, _)| path.as_str())
                        .take_while(|path| path.starts_with(&below)),
                )
                // One HEAD holds as it is, which a discard onto another
                // commit staged, makes way; any other is newer work.
                .find(|path| !restaging.contains(path) && !at_head(path, &current[*path]));
            if (!entry.index.is_empty() || entry.intent_to_add)
                && let Some(displaced) = displaced
            {
                outcome.conflicts.push(Conflict {
                    path: entry.path.clone(),
                    reason: format!("staging it would replace the staged {displaced}"),
                });
                continue;
            }
            if entry.intent_to_add {
                // Git marks only a file that is there.
                if fs::symlink_metadata(repository.top.join(&entry.path))
                    .is_ok_and(|metadata| !metadata.is_dir())
                {
                    intents.push(format!(":(literal){}", entry.path));
                    outcome.staged.push(entry.path.clone());
                } else {
                    outcome.conflicts.push(Conflict {
                        path: entry.path.clone(),
                        reason: "its file is not there to mark intent-to-add".to_owned(),
                    });
                }
                continue;
            }
            // Removing the path first clears every stage it had.
            input.extend_from_slice(b"0 0000000000000000000000000000000000000000\t");
            input.extend_from_slice(entry.path.as_bytes());
            input.push(0);
            for stage in &entry.index {
                input.extend_from_slice(
                    format!(
                        "{} {} {}\t{}",
                        stage.mode, stage.oid, stage.stage, entry.path
                    )
                    .as_bytes(),
                );
                input.push(0);
            }
            outcome.staged.push(entry.path.clone());
        }
        if !input.is_empty() {
            let mut command = git::repository(&self.context.git, &repository.top, &filters);
            command.args(["update-index", "-z", "--index-info"]);
            git::output(command, input, self.deadline).map_err(GitFailure::repository)?;
        }
        // `add -N` records the mark alone: it reads no content and runs no
        // filter.
        for chunk in intents.chunks(500) {
            let mut command = git::repository(&self.context.git, &repository.top, &filters);
            command.args(["add", "--force", "--intent-to-add", "--"]);
            command.args(chunk);
            git::output(command, Vec::new(), self.deadline).map_err(GitFailure::repository)?;
        }
        Ok(())
    }

    fn to_folder(
        &self,
        into: &Path,
        repository: Option<&work_tree::Repository>,
    ) -> Result<UndoOutcome, Refusal> {
        let empty = match fs::read_dir(into) {
            Ok(mut entries) => entries.next().is_none(),
            Err(error) if error.kind() == io::ErrorKind::NotFound => true,
            Err(error) => return Err(store_failure(error)),
        };
        if !empty {
            return Err(Refusal::Invalid {
                detail: format!("{} is not an empty folder", into.display()),
            });
        }
        fs::create_dir_all(into).map_err(store_failure)?;
        let into = fs::canonicalize(into).map_err(store_failure)?;
        let pending = self.store.begin()?;
        let mut wanted = BTreeMap::new();
        let mut staged = Vec::new();
        for entry in &self.manifest.entries {
            if let Some(saved) = &entry.worktree
                && let Content::Blob { oid } = &saved.content
            {
                wanted.insert(oid.clone(), saved.size);
            }
            let version = entry.worktree_version();
            let worktree_oid = version.and_then(WorktreeVersion::oid);
            let worktree_mode = version.map(|saved| saved.kind().mode());
            if !entry.staged {
                continue;
            }
            for stage in &entry.index {
                // A staged version the work tree file shows, bytes and mode,
                // adds nothing.
                if stage.stage == 0
                    && Some(stage.oid.as_str()) == worktree_oid
                    && Some(stage.mode.as_str()) == worktree_mode
                {
                    continue;
                }
                if stage.mode != GITLINK {
                    wanted.insert(stage.oid.clone(), 0);
                }
                staged.push((entry, stage));
            }
        }
        let mut fetched = self.fetch_store_blobs(wanted, &pending)?;
        self.fetch_repository(
            repository,
            self.manifest.entries.iter(),
            &pending,
            &mut fetched,
        )?;
        let mut outcome = UndoOutcome {
            snapshot: self.manifest.id.clone(),
            before_undo: None,
            written: Vec::new(),
            removed: Vec::new(),
            staged: Vec::new(),
            clean_restored: BTreeMap::new(),
            refs: Vec::new(),
            conflicts: Vec::new(),
        };
        let place_into = |path: &str,
                          kind: FileKind,
                          permissions: Option<u32>,
                          source: &Path,
                          outcome: &mut UndoOutcome| match place(
            &into,
            path,
            kind,
            permissions,
            source,
            &mut outcome.written,
        ) {
            Ok(()) => outcome.written.push(into.join(path).display().to_string()),
            Err(reason) => outcome.conflicts.push(Conflict {
                path: path.to_owned(),
                reason,
            }),
        };
        for entry in &self.manifest.entries {
            if let Some(saved) = entry.worktree_version() {
                match self.source(saved, &fetched) {
                    Ok(source) => place_into(
                        &entry.path,
                        saved.kind(),
                        saved.permissions(),
                        &source,
                        &mut outcome,
                    ),
                    Err(reason) => outcome.conflicts.push(Conflict {
                        path: entry.path.clone(),
                        reason,
                    }),
                }
            }
        }
        let index_folder = (1..)
            .map(|number| match number {
                1 => INDEX_FOLDER.to_owned(),
                number => format!("{INDEX_FOLDER}-{number}"),
            })
            .find(|folder| {
                let below = format!("{folder}/");
                !self
                    .manifest
                    .entries
                    .iter()
                    .any(|entry| entry.path == *folder || entry.path.starts_with(&below))
            })
            .expect("some folder name is free");
        for (position, (entry, stage)) in staged.into_iter().enumerate() {
            let path = format!("{index_folder}/{}/{}", stage.stage, entry.path);
            if stage.mode == GITLINK {
                // A submodule's staged commit is no blob: its id stands in.
                let id = pending.scratch().join(format!("gitlink-{position}"));
                fs::write(&id, format!("{}\n", stage.oid)).map_err(store_failure)?;
                place_into(&path, FileKind::File, None, &id, &mut outcome);
            } else {
                let kind = match stage.mode.as_str() {
                    "120000" => FileKind::Symlink,
                    "100755" => FileKind::Executable,
                    _ => FileKind::File,
                };
                place_into(&path, kind, None, &fetched[&stage.oid], &mut outcome);
            }
            if outcome.staged.last() != Some(&entry.path) {
                outcome.staged.push(entry.path.clone());
            }
        }
        self.summarize_clean(&into, &mut outcome);
        Ok(outcome)
    }
}

/// The files and links at or under `path` in `top`, relative to it; `None`
/// when a repository's `.git` is among them.
fn files_under(top: &Path, path: &str) -> Result<Option<Vec<String>>, Refusal> {
    let mut files = Vec::new();
    let mut pending = vec![path.to_owned()];
    while let Some(path) = pending.pop() {
        let absolute = top.join(&path);
        let metadata = match fs::symlink_metadata(&absolute) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(store_failure(error)),
        };
        if !metadata.is_dir() {
            files.push(path);
            continue;
        }
        for entry in fs::read_dir(&absolute).map_err(store_failure)? {
            let name = entry.map_err(store_failure)?.file_name();
            if name == ".git" {
                return Ok(None);
            }
            pending.push(format!("{path}/{}", name.to_string_lossy()));
        }
    }
    Ok(Some(files))
}

/// Whether `stages` is the one entry `git add -N` makes: stage 0 holding the
/// empty blob. A staged empty file looks the same, and is left alone too.
fn intent_to_add_entry(stages: &[crate::Stage]) -> bool {
    matches!(stages, [stage] if stage.stage == 0 && stage.oid == EMPTY_BLOB)
}

/// Whether the current state at `entry`'s path may be overwritten with the
/// snapshot's: nothing is there, or it holds the version a discard restores,
/// HEAD's or the index's, in content and in mode. A newer `chmod` is a change
/// like any other.
fn replaceable(entry: &Entry, current: &Current) -> bool {
    match current {
        Current::Absent => true,
        Current::Folder | Current::Special => false,
        Current::Present { kind, oid, .. } => entry
            .head
            .iter()
            .chain(&entry.index)
            .any(|stage| stage.oid == *oid && stage.mode == kind.mode()),
    }
}

/// Writes `source`, a store file holding the content, to `root/path` as
/// `kind` with the saved `permissions` (else 0644, or 0755 for an
/// executable), through a temporary file renamed into place. Missing folders on
/// the way are created and added to `written`; a link or file where a folder
/// should be is the reason it returns.
fn place(
    root: &Path,
    path: &str,
    kind: FileKind,
    permissions: Option<u32>,
    source: &Path,
    written: &mut Vec<String>,
) -> Result<(), String> {
    let components = path.split('/').collect::<Vec<_>>();
    let (name, folders) = components.split_last().expect("a path has a name");
    let mut dir = root.to_path_buf();
    for folder in folders {
        dir.push(folder);
        match fs::symlink_metadata(&dir) {
            Ok(metadata) if metadata.is_dir() => {}
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err("a folder on its path is now a link".to_owned());
            }
            Ok(_) => return Err("a file stands where a folder on its path was".to_owned()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                fs::create_dir(&dir).map_err(|error| error.to_string())?;
                written.push(dir.display().to_string());
            }
            Err(error) => return Err(error.to_string()),
        }
    }
    // A temporary name of this call's own: an existing file is never
    // replaced, and only the file created here is ever removed.
    let mut attempt = 0u32;
    let (temporary, file) = loop {
        let temporary = dir.join(format!(".{name}.nah-undo-{attempt}"));
        let created = match kind {
            FileKind::Symlink => fs::read(source).and_then(|target| {
                std::os::unix::fs::symlink(std::ffi::OsString::from_vec(target), &temporary)
                    .map(|()| None)
            }),
            FileKind::File | FileKind::Executable => File::create_new(&temporary).map(Some),
        };
        match created {
            Ok(file) => break (temporary, file),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => attempt += 1,
            Err(error) => return Err(error.to_string()),
        }
    };
    let result = (|| -> io::Result<()> {
        if let Some(mut file) = file {
            io::copy(&mut File::open(source)?, &mut file)?;
            let mode = permissions.unwrap_or(if kind == FileKind::Executable {
                0o755
            } else {
                0o644
            });
            file.set_permissions(fs::Permissions::from_mode(mode))?;
        }
        fs::rename(&temporary, dir.join(name))
    })();
    result.map_err(|error| {
        let _ = fs::remove_file(&temporary);
        error.to_string()
    })
}
