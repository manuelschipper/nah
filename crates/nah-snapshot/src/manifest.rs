//! What one snapshot records: the manifest published beside its content.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The manifest layout this build writes and reads.
pub(crate) const MANIFEST_FORMAT: u32 = 1;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Manifest {
    pub format: u32,
    pub id: String,
    /// Milliseconds since the Unix epoch when the save published it.
    pub created_ms: u64,
    /// Nanoseconds since the Unix epoch before the save read any file. A file
    /// whose change and modification times both precede it, and whose
    /// metadata is unchanged, still holds the content recorded here.
    pub started_ns: u64,
    /// The canonical work tree or folder the snapshot was taken of.
    pub root: String,
    /// `None` for a folder that is not a git work tree, and for a snapshot
    /// of commits.
    pub repository: Option<RepositoryState>,
    /// Every saved path, sorted by path.
    pub entries: Vec<Entry>,
    /// Paths deliberately left out, sorted by path. A path ending in `/` is a
    /// whole folder.
    pub not_saved: Vec<NotSaved>,
    /// The last saved copy of each file with unsaved content deleted since
    /// an earlier snapshot, sorted by path. Each later snapshot carries it
    /// until it is as old as the retention age (`gone_since_ms`); an undo in
    /// place never writes it back, and an undo into a separate folder does.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deleted: Vec<Entry>,
    pub summary: Summary,
    /// For the snapshot an undo saves first, the snapshot it was about to
    /// restore: undoing this one may overwrite what that restore wrote.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub undo_of: Option<String>,
    /// What a revision discard is expected to leave at each saved path.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) discard_results: BTreeMap<String, DiscardResult>,
    /// For a snapshot of commits a command was about to make unreachable,
    /// such as dropped stash entries, what it holds; it then holds no files.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commits: Option<Commits>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DiscardResult {
    /// The source revision's blob and mode, or a deletion.
    pub worktree: Option<Stage>,
    /// The result in the index if the discard writes it. An empty list is
    /// a staged deletion, while `None` means the index was left alone.
    pub index: Option<Vec<Stage>>,
}

impl Manifest {
    /// Whether two manifests hold the same unsaved work, whatever their ids,
    /// times and recorded file metadata.
    pub(crate) fn same_state(&self, other: &Manifest) -> bool {
        let state = |entry: &Entry| {
            (
                entry.path.clone(),
                entry.origin,
                entry
                    .worktree
                    .as_ref()
                    .map(|saved| (saved.kind, saved.content.clone())),
                entry.head.clone(),
                entry.index.clone(),
                entry.staged,
                entry.intent_to_add,
            )
        };
        self.root == other.root
            && self.repository == other.repository
            && self.not_saved == other.not_saved
            && self.deleted.len() == other.deleted.len()
            && self
                .deleted
                .iter()
                .zip(&other.deleted)
                .all(|(left, right)| state(left) == state(right))
            && self.entries.len() == other.entries.len()
            && self
                .entries
                .iter()
                .zip(&other.entries)
                .all(|(left, right)| state(left) == state(right))
    }
}

/// The commits a snapshot holds, and the refs that named them.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Commits {
    /// Each saved ref and stash entry, stash entries newest first.
    pub refs: Vec<SavedRef>,
    /// The pack, `pack-<hash>` in the store's `git/objects/pack/`, holding
    /// the objects of these refs that no ref kept by the command reached;
    /// `None` when there were none.
    pub pack: Option<String>,
    /// How many commits it holds.
    pub count: u64,
    /// The stash's entries, newest first, when the snapshot saved any: the
    /// list each saved entry's `older` counts in, which an undo matches
    /// against the stash it finds.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stash: Vec<Listed>,
    /// For the snapshot an undo saves before it writes: what that undo
    /// writes, which undoing this snapshot takes back.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub undoing: Option<Undoing>,
}

/// One entry of the stash's reflog. Two entries alike in every field are
/// the same entry as far as Git or anyone can tell.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Listed {
    pub oid: String,
    /// What `git stash list` shows after `stash@{n}: `.
    pub message: String,
    /// Who wrote the entry and when, `<seconds> <zone>`: an undo writes an
    /// entry back with them, so it is told apart from one stored since.
    pub name: String,
    pub email: String,
    pub date: String,
}

/// What an undo of commits writes. The refs it deletes are the plain refs
/// of the snapshot it saved first.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Undoing {
    /// The refs it creates, each with the commit it names.
    pub created: Vec<SavedRef>,
    /// The stash it writes, newest first, when it rewrites the stash: each
    /// entry with its position in the snapshot's `stash`, the list before,
    /// or `None` for one the undo puts back.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stash: Option<Vec<Written>>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Written {
    #[serde(flatten)]
    pub entry: Listed,
    pub before: Option<usize>,
}

/// A ref as it stood when saved.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SavedRef {
    /// The full ref name, such as `refs/heads/topic` or `refs/stash`.
    pub name: String,
    /// The commit it named.
    pub oid: String,
    /// For a stash entry, one of the entries in `refs/stash`'s reflog; a
    /// plain `refs/stash` is a stash ref with no reflog.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stash: Option<StashEntry>,
    /// The command moves it from this commit, or may: an undo recreates the
    /// commit under its recovery ref (`recovery_ref`) and leaves the ref
    /// itself as it finds it. `HEAD`, and a commit only a reflog records
    /// (`reflog/<commit>`), are among them.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub moved: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StashEntry {
    /// What `git stash list` shows after `stash@{n}: `.
    pub message: String,
    /// How many entries were older: its position, counted from the oldest,
    /// in the snapshot's `stash`. An undo puts it back above the entries
    /// that were older and remain.
    pub older: usize,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RepositoryState {
    /// HEAD's commit, `None` on an unborn branch.
    pub head: Option<String>,
    /// The checked-out branch, `None` when HEAD is detached.
    pub branch: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Origin {
    /// A tracked file whose work tree or staged state differs from HEAD.
    Tracked,
    /// An untracked file git does not ignore.
    Untracked,
    /// A path the caller named, usually an ignored file.
    Named,
    /// A file in a folder that is not a git work tree.
    Folder,
    /// A path saved before a restore or discard would write it, absent included.
    Restored,
    /// A clean tracked file whose working version is the HEAD blob.
    Clean,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Entry {
    /// Relative to the root, `/`-separated.
    pub path: String,
    pub origin: Origin,
    /// The work tree's copied version. A clean file uses `head` instead.
    pub worktree: Option<Saved>,
    /// HEAD's version of a tracked path, `None` where HEAD lacks it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head: Option<Stage>,
    /// The index's entries for the path; empty where the index lacks it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub index: Vec<Stage>,
    /// Whether the index differs from HEAD for this path, which undo then
    /// restores.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub staged: bool,
    /// Whether the index marks the path intent-to-add (`git add -N`): it
    /// holds no staged version, yet git tracks the path.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub intent_to_add: bool,
    /// For an entry of a manifest's `deleted`, milliseconds since the Unix
    /// epoch when a save first found its file gone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gone_since_ms: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Saved {
    pub kind: FileKind,
    pub content: Content,
    pub size: u64,
    pub stat: Stat,
    /// Lines in a text file no HEAD version exists for; `None` for a binary,
    /// large or tracked file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lines: Option<u64>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum FileKind {
    File,
    Executable,
    /// The content is the link's target, not what it points at.
    Symlink,
}

impl FileKind {
    /// Git's index mode for this kind.
    pub(crate) fn mode(self) -> &'static str {
        match self {
            FileKind::File => "100644",
            FileKind::Executable => "100755",
            FileKind::Symlink => "120000",
        }
    }
}

/// Where a saved version's bytes live in the store.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "store", rename_all = "kebab-case")]
pub enum Content {
    /// A git blob in the store's object directory.
    Blob { oid: String },
    /// A plain copy under `files/`, named by its SHA-256.
    File { sha256: String },
}

/// One index entry, or HEAD's version of a path.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Stage {
    /// Git's octal mode, such as `100644`.
    pub mode: String,
    pub oid: String,
    /// 0, or 1 to 3 for an unmerged path.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub stage: u8,
}

impl Stage {
    pub(crate) fn file_kind(&self) -> Option<FileKind> {
        match self.mode.as_str() {
            "100644" => Some(FileKind::File),
            "100755" => Some(FileKind::Executable),
            "120000" => Some(FileKind::Symlink),
            _ => None,
        }
    }
}

fn is_zero(stage: &u8) -> bool {
    *stage == 0
}

/// The file metadata a later save compares to reuse saved content without
/// reading the file again.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Stat {
    pub size: u64,
    pub mtime_ns: i64,
    pub ctime_ns: i64,
    pub inode: u64,
    pub device: u64,
    pub mode: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct NotSaved {
    pub path: String,
    pub reason: NotSavedReason,
    /// For a secret file status listed, whether it was tracked or untracked;
    /// `None` for an ignored one and for every other reason. Which discards
    /// destroy a secret file depends on it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<Origin>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum NotSavedReason {
    /// A file Nah's secret classification recognizes. Never saved.
    Secret,
    /// Ignored by git and not named by the caller.
    Ignored,
    /// Inside a dependency or build folder on the skip list.
    SkipList,
    /// A repository of its own inside the project.
    NestedRepository,
    /// A submodule; its own work tree is not saved.
    Submodule,
    /// Neither a file, a link nor a folder.
    Special,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Summary {
    /// Saved paths, deletions included.
    pub files: u64,
    /// Bytes of every saved version.
    pub bytes: u64,
    /// Bytes this save read and stored; the rest was already in the store.
    pub new_bytes: u64,
    /// Lines added and removed against HEAD, or the lines of a new text file;
    /// `None` where too many tracked files changed to count cheaply.
    pub lines_changed: Option<u64>,
}
