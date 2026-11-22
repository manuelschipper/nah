//! Turns the paths a scan found into saved content in a pending snapshot:
//! content an earlier snapshot already holds is reused by file metadata,
//! small files and link targets become git blobs, large files plain copies.

use crate::git::{self, GitFailure};
use crate::manifest::{
    Content, Entry, FileKind, MANIFEST_FORMAT, Manifest, NotSaved, NotSavedReason, Origin, Saved,
    Stat, Summary,
};
use crate::retention::RETENTION;
use crate::store::{Pending, Store, free_bytes, hex};
use crate::work_tree::{self, GITLINK, Repository};
use crate::{Budget, Context, Lookup, PLAIN_COPY_BYTES, Refusal, Scan, store_failure};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Instant;

/// Most bytes of a new text file whose lines a save counts.
const LINE_COUNT_BYTES: u64 = 1024 * 1024;

/// Fewest new bytes, or files, worth a git process of their own when
/// storing blobs.
const BYTES_PER_PROCESS: u64 = 8 * 1024 * 1024;
const FILES_PER_PROCESS: usize = 2048;

/// Most git processes storing blobs at once.
const STORE_PROCESSES: u64 = 8;

/// The bytes one new blob is made of.
enum Source {
    /// A work tree file and the size it had when planned. Its lines are
    /// counted where `count_lines` holds.
    File {
        path: PathBuf,
        size: u64,
        count_lines: bool,
    },
    Bytes(Vec<u8>),
}

impl Source {
    fn size(&self) -> u64 {
        match self {
            Source::File { size, .. } => *size,
            Source::Bytes(bytes) => bytes.len() as u64,
        }
    }
}

/// A blob a save stored, and the lines of a text file it counted.
struct Stored {
    oid: String,
    lines: Option<u64>,
}

/// What a save does for one path.
enum Plan {
    Absent,
    Reuse(Saved),
    Blob(FileKind, Stat),
    Plain(FileKind, Stat),
    Link(Vec<u8>, Stat),
}

pub(crate) struct Capture<'a> {
    pub(crate) context: &'a Context,
    pub(crate) store: &'a Store,
    pub(crate) pending: &'a Pending,
    pub(crate) root: &'a Path,
    /// The repository and its filter-disabling options, for a work tree.
    pub(crate) repository: Option<(&'a Repository, &'a [String])>,
    pub(crate) latest: Option<&'a Manifest>,
    pub(crate) budget: &'a Budget,
    pub(crate) started_ns: u64,
}

impl Capture<'_> {
    pub(crate) fn run(&self, scan: Scan) -> Result<Manifest, Refusal> {
        let deadline = self.budget.deadline;
        let previous = self
            .latest
            .map(|latest| {
                latest
                    .entries
                    .iter()
                    .filter_map(|entry| Some((entry.path.as_str(), entry.worktree.as_ref()?)))
                    .collect::<HashMap<_, _>>()
            })
            .unwrap_or_default();
        let reusable = |path: &str, kind: FileKind, stat: &Stat| {
            let latest = self.latest?;
            previous.get(path).filter(|saved| {
                saved.kind == kind
                    && saved.stat == *stat
                    && stat.mtime_ns < latest.started_ns as i64
                    && stat.ctime_ns < latest.started_ns as i64
            })
        };
        let mut not_saved = scan.not_saved;
        let mut candidates = Vec::new();
        let mut plans = Vec::new();
        let mut new_bytes = 0u64;
        let mut lookup = Lookup::new(self.root);
        for (position, candidate) in scan.candidates.into_iter().enumerate() {
            if position.is_multiple_of(512) && Instant::now() >= deadline {
                return Err(Refusal::OverDeadline);
            }
            let path = self.root.join(&candidate.path);
            let unreadable = |error: io::Error| Refusal::Unreadable {
                path: path.display().to_string(),
                detail: error.to_string(),
            };
            let plan = match lookup.metadata(&candidate.path).map_err(unreadable)? {
                None => {
                    // An untracked file gone since it was listed has nothing to lose.
                    if !matches!(candidate.origin, Origin::Tracked | Origin::Restored) {
                        continue;
                    }
                    Plan::Absent
                }
                Some(metadata) => {
                    let stat = stat_of(&metadata);
                    if metadata.file_type().is_symlink() {
                        match reusable(&candidate.path, FileKind::Symlink, &stat) {
                            Some(saved) => Plan::Reuse((*saved).clone()),
                            None => {
                                let target = fs::read_link(&path).map_err(unreadable)?;
                                let target = target.as_os_str().as_bytes().to_vec();
                                new_bytes += target.len() as u64;
                                Plan::Link(target, stat)
                            }
                        }
                    } else if metadata.is_file() {
                        let kind = if metadata.mode() & 0o100 != 0 {
                            FileKind::Executable
                        } else {
                            FileKind::File
                        };
                        match reusable(&candidate.path, kind, &stat) {
                            Some(saved) => Plan::Reuse((*saved).clone()),
                            None => {
                                new_bytes += stat.size;
                                if stat.size > PLAIN_COPY_BYTES {
                                    Plan::Plain(kind, stat)
                                } else {
                                    Plan::Blob(kind, stat)
                                }
                            }
                        }
                    } else if metadata.is_dir() {
                        // A folder now stands where a tracked file was; its
                        // files are listed on their own.
                        Plan::Absent
                    } else {
                        not_saved.push(NotSaved {
                            path: candidate.path,
                            reason: NotSavedReason::Special,
                            origin: None,
                        });
                        continue;
                    }
                }
            };
            candidates.push(candidate);
            plans.push(plan);
        }

        // Staged blobs the store lacks are copied from the repository. One
        // whose work tree file git finds equal to the index is usually that
        // file's blob, stored below, so this first check leaves it out; the
        // check after storing counts every blob that is still to copy.
        let staged = candidates
            .iter()
            .filter(|candidate| candidate.staged)
            .flat_map(|candidate| {
                candidate
                    .index
                    .iter()
                    .filter(|stage| stage.mode != GITLINK)
                    .map(move |stage| (stage.oid.as_str(), candidate.worktree_matches_index))
            })
            .collect::<Vec<_>>();
        let staged_oids = staged.iter().map(|(oid, _)| *oid).collect::<BTreeSet<_>>();
        let staged_oids = staged_oids.into_iter().collect::<Vec<_>>();
        let git_dir = self.store.git_dir();
        let in_store = if staged_oids.is_empty() {
            Vec::new()
        } else {
            work_tree::object_sizes(
                git::store(&self.context.git, &git_dir, None),
                &staged_oids,
                deadline,
            )
            .map_err(GitFailure::store)?
        };
        let in_store = staged_oids
            .iter()
            .zip(&in_store)
            .filter_map(|(oid, size)| size.map(|_| *oid))
            .collect::<BTreeSet<_>>();
        let to_copy = staged_oids
            .iter()
            .filter(|oid| !in_store.contains(*oid))
            .copied()
            .collect::<Vec<_>>();
        let staged_sizes = match (to_copy.is_empty(), self.repository) {
            (false, Some((repository, filters))) => {
                let command = git::repository(&self.context.git, &repository.top, filters);
                let sizes = work_tree::object_sizes(command, &to_copy, deadline)
                    .map_err(GitFailure::repository)?;
                to_copy
                    .into_iter()
                    .zip(sizes)
                    .map(|(oid, size)| (oid, size.unwrap_or(0)))
                    .collect::<HashMap<_, _>>()
            }
            _ => HashMap::new(),
        };
        let unlike_worktree = staged
            .iter()
            .filter(|(_, matches)| !matches)
            .filter_map(|(oid, _)| staged_sizes.get(oid).map(|size| (*oid, *size)))
            .collect::<HashMap<_, _>>();
        let planned = new_bytes + unlike_worktree.values().sum::<u64>();
        self.check_space(planned, planned)?;

        // Store every new small file and link target as blobs.
        let mut sources = Vec::new();
        let mut blob_plans = Vec::new();
        for (position, (candidate, plan)) in candidates.iter().zip(&plans).enumerate() {
            match plan {
                Plan::Blob(_, stat) => sources.push(Source::File {
                    path: self.root.join(&candidate.path),
                    size: stat.size,
                    count_lines: candidate.head.is_none()
                        && candidate.origin != Origin::Folder
                        && stat.size <= LINE_COUNT_BYTES,
                }),
                Plan::Link(target, _) => sources.push(Source::Bytes(target.clone())),
                _ => continue,
            }
            blob_plans.push(position);
        }
        let mut contents = HashMap::new();
        let mut lines = HashMap::new();
        for (position, stored) in blob_plans
            .into_iter()
            .zip(self.store_blobs(sources, deadline)?)
        {
            contents.insert(position, Content::Blob { oid: stored.oid });
            lines.insert(position, stored.lines);
        }
        for (position, (candidate, plan)) in candidates.iter().zip(&plans).enumerate() {
            if let Plan::Plain(_, stat) = plan {
                let sha256 =
                    self.copy_plain(&self.root.join(&candidate.path), stat.size, deadline)?;
                contents.insert(position, Content::File { sha256 });
            }
        }

        // Staged blobs neither stored above nor already in the store.
        let stored = contents
            .values()
            .filter_map(|content| match content {
                Content::Blob { oid } => Some(oid.as_str()),
                Content::File { .. } => None,
            })
            .collect::<BTreeSet<_>>();
        let missing = staged_oids
            .iter()
            .filter(|oid| !in_store.contains(*oid) && !stored.contains(*oid))
            .copied()
            .collect::<Vec<_>>();
        // A text conversion, for one, makes the staged blob differ from the
        // work tree bytes even where git finds the file unchanged.
        let missing_bytes = missing
            .iter()
            .map(|oid| staged_sizes.get(oid).copied().unwrap_or(0))
            .sum::<u64>();
        new_bytes += missing_bytes;
        self.check_space(new_bytes, missing_bytes)?;
        if let (false, Some((repository, filters))) = (missing.is_empty(), self.repository) {
            let command = git::repository(&self.context.git, &repository.top, filters);
            let blobs = work_tree::read_objects(command, &missing, deadline)?;
            let copied =
                self.store_blobs(blobs.into_iter().map(Source::Bytes).collect(), deadline)?;
            if copied
                .iter()
                .zip(&missing)
                .any(|(copied, oid)| copied.oid != *oid)
            {
                return Err(Refusal::RepositoryUnreadable {
                    detail: "a staged blob did not hash to its name".to_owned(),
                });
            }
        }

        // A file that changed while it was read may be saved torn.
        for (candidate, plan) in candidates.iter().zip(&plans) {
            if let Plan::Blob(_, stat) | Plan::Plain(_, stat) | Plan::Link(_, stat) = plan {
                let path = self.root.join(&candidate.path);
                let now = fs::symlink_metadata(&path).map(|metadata| stat_of(&metadata));
                if now.ok().as_ref() != Some(stat) {
                    return Err(Refusal::Unreadable {
                        path: path.display().to_string(),
                        detail: "it changed while it was being saved".to_owned(),
                    });
                }
            }
        }

        let mut entries = Vec::with_capacity(candidates.len());
        let mut tracked_with_head = Vec::new();
        let mut new_lines = 0u64;
        for (position, (candidate, plan)) in candidates.iter().zip(plans).enumerate() {
            let worktree = match plan {
                Plan::Absent => None,
                Plan::Reuse(saved) => Some(saved),
                Plan::Blob(kind, stat) | Plan::Plain(kind, stat) => Some(Saved {
                    kind,
                    content: contents
                        .remove(&position)
                        .expect("every new file was stored"),
                    size: stat.size,
                    stat,
                    lines: lines.remove(&position).flatten(),
                }),
                Plan::Link(target, stat) => Some(Saved {
                    kind: FileKind::Symlink,
                    content: contents.remove(&position).expect("every link was stored"),
                    size: target.len() as u64,
                    stat,
                    lines: None,
                }),
            };
            if candidate
                .head
                .as_ref()
                .is_some_and(|head| head.mode == GITLINK)
            {
                // A submodule's commit has no lines.
            } else if candidate.head.is_some() {
                tracked_with_head.push(candidate.path.as_str());
            } else {
                new_lines += worktree.as_ref().and_then(|saved| saved.lines).unwrap_or(0);
            }
            entries.push(Entry {
                path: candidate.path.clone(),
                origin: candidate.origin,
                worktree,
                head: candidate.head.clone(),
                index: candidate.index.clone(),
                staged: candidate.staged,
                intent_to_add: candidate.intent_to_add,
                gone_since_ms: None,
            });
        }
        let lines_changed = match self.repository {
            Some((repository, filters)) => work_tree::lines_against_head(
                self.context,
                repository,
                filters,
                &tracked_with_head,
                deadline,
            )?
            .map(|lines| lines + new_lines),
            None => None,
        };
        entries.sort_by(|left, right| left.path.cmp(&right.path));
        not_saved.sort();
        not_saved.dedup();
        let summary = Summary {
            files: entries.len() as u64,
            bytes: entries
                .iter()
                .filter_map(|entry| entry.worktree.as_ref())
                .map(|saved| saved.size)
                .sum(),
            new_bytes,
            lines_changed,
        };
        let deleted = self.deleted(&entries, &not_saved, &mut lookup)?;
        Ok(Manifest {
            format: MANIFEST_FORMAT,
            id: String::new(),
            created_ms: 0,
            started_ns: self.started_ns,
            root: self.root.display().to_string(),
            repository: scan.repository,
            entries,
            not_saved,
            deleted,
            summary,
            undo_of: None,
            discard_results: Default::default(),
            commits: None,
        })
    }

    /// The last saved copy of every file with unsaved content that was
    /// deleted since an earlier snapshot: those the latest snapshot carries,
    /// and those it holds that are gone now. A file deleted one call at a
    /// time leaves no discard to save before, so this is its only copy, kept
    /// for the retention age from when a save first found it gone. A path
    /// that exists again, or that this snapshot holds, drops out.
    fn deleted(
        &self,
        entries: &[Entry],
        not_saved: &[NotSaved],
        lookup: &mut Lookup<'_>,
    ) -> Result<Vec<Entry>, Refusal> {
        let Some(latest) = self.latest else {
            return Ok(Vec::new());
        };
        let held = |path: &str| {
            entries
                .iter()
                .any(|entry| entry.path == path && entry.worktree.is_some())
                || not_saved.iter().any(|left_out| left_out.path == path)
        };
        let now_ms = self.started_ns / 1_000_000;
        let expired = now_ms.saturating_sub(RETENTION.age.as_millis() as u64);
        let mut deleted = Vec::new();
        for entry in latest.deleted.iter().chain(&latest.entries) {
            if entry.worktree.is_none()
                || entry.gone_since_ms.is_some_and(|gone| gone < expired)
                || entry.origin == Origin::Restored
                || held(&entry.path)
                || deleted.iter().any(|known: &Entry| known.path == entry.path)
            {
                continue;
            }
            let gone = lookup
                .metadata(&entry.path)
                .map_err(|error| Refusal::Unreadable {
                    path: self.root.join(&entry.path).display().to_string(),
                    detail: error.to_string(),
                })?
                .is_none();
            if gone {
                deleted.push(Entry {
                    staged: false,
                    index: Vec::new(),
                    intent_to_add: false,
                    gone_since_ms: entry.gone_since_ms.or(Some(now_ms)),
                    ..entry.clone()
                });
            }
        }
        deleted.sort_by(|left, right| left.path.cmp(&right.path));
        Ok(deleted)
    }

    /// Refuses a save whose `new_bytes` exceed the budget, or whose `to_write`
    /// bytes not yet written exceed the store's free space.
    fn check_space(&self, new_bytes: u64, to_write: u64) -> Result<(), Refusal> {
        if new_bytes > self.budget.bytes {
            return Err(Refusal::OverBudget {
                bytes: new_bytes,
                budget_bytes: self.budget.bytes,
            });
        }
        if free_bytes(&self.store.root).is_some_and(|free| free < to_write + (1 << 20)) {
            return Err(Refusal::DiskFull);
        }
        Ok(())
    }

    /// Writes `sources` as blobs to packs in the pending snapshot's objects,
    /// and returns their names in order. `git fast-import` stores the bytes
    /// it is given, raw: no filter or line-ending conversion runs, and a blob
    /// the store already packs is not written again. Large saves are split
    /// across several processes, since compressing is their cost.
    fn store_blobs(&self, sources: Vec<Source>, deadline: Instant) -> Result<Vec<Stored>, Refusal> {
        if sources.is_empty() {
            return Ok(Vec::new());
        }
        let total = sources.iter().map(Source::size).sum::<u64>();
        let processes = total
            .div_ceil(BYTES_PER_PROCESS)
            .max(sources.len().div_ceil(FILES_PER_PROCESS) as u64)
            .clamp(1, STORE_PROCESSES);
        let (bytes_share, files_share) =
            (total / processes + 1, sources.len() as u64 / processes + 1);
        let mut chunks = vec![Vec::new()];
        let mut chunk_bytes = 0;
        for source in sources {
            let chunk = chunks.last().expect("a chunk");
            if (chunk_bytes >= bytes_share || chunk.len() as u64 >= files_share)
                && (chunks.len() as u64) < processes
            {
                chunks.push(Vec::new());
                chunk_bytes = 0;
            }
            chunk_bytes += source.size();
            chunks.last_mut().expect("a chunk").push(source);
        }
        let results = std::thread::scope(|scope| {
            let workers = chunks
                .iter()
                .enumerate()
                .map(|(number, chunk)| {
                    scope.spawn(move || self.fast_import(number, chunk, deadline))
                })
                .collect::<Vec<_>>();
            workers
                .into_iter()
                .map(|worker| worker.join().expect("store thread"))
                .collect::<Vec<_>>()
        });
        let mut stored = Vec::new();
        for result in results {
            // Git names a short write to a full disk in words of its own.
            stored.extend(result.map_err(|refusal| match refusal {
                Refusal::StoreUnwritable { .. }
                    if free_bytes(&self.store.root).is_some_and(|free| free < 1 << 20) =>
                {
                    Refusal::DiskFull
                }
                refusal => refusal,
            })?);
        }
        Ok(stored)
    }

    /// One `git fast-import` storing `sources` as blobs.
    fn fast_import(
        &self,
        number: usize,
        sources: &[Source],
        deadline: Instant,
    ) -> Result<Vec<Stored>, Refusal> {
        let marks = self.pending.dir.join(format!("marks-{number}"));
        let mut command = git::store(
            &self.context.git,
            &self.store.git_dir(),
            Some(&self.pending.objects()),
        );
        command
            .args(["fast-import", "--quiet", "--done"])
            .arg(format!("--export-marks={}", marks.display()));
        let mut lines = Vec::with_capacity(sources.len());
        git::feed(command, deadline, |input| {
            for (mark, source) in sources.iter().enumerate() {
                if Instant::now() >= deadline {
                    return Err(Refusal::OverDeadline.into());
                }
                let bytes = match source {
                    Source::File {
                        path,
                        size,
                        count_lines,
                    } => {
                        let bytes = fs::read(path).map_err(|error| Refusal::Unreadable {
                            path: path.display().to_string(),
                            detail: error.to_string(),
                        })?;
                        if bytes.len() as u64 != *size {
                            return Err(Refusal::Unreadable {
                                path: path.display().to_string(),
                                detail: "it changed while it was being saved".to_owned(),
                            }
                            .into());
                        }
                        lines.push(count_lines.then(|| text_lines(&bytes)).flatten());
                        std::borrow::Cow::Owned(bytes)
                    }
                    Source::Bytes(bytes) => {
                        lines.push(None);
                        std::borrow::Cow::Borrowed(bytes)
                    }
                };
                let header = format!("blob\nmark :{}\ndata {}\n", mark + 1, bytes.len());
                input.write_all(header.as_bytes())?;
                input.write_all(&bytes)?;
                input.write_all(b"\n")?;
            }
            input.write_all(b"done\n")?;
            Ok(())
        })?;
        let marks = fs::read_to_string(&marks).map_err(store_failure)?;
        let mut oids = vec![None; sources.len()];
        for line in marks.lines() {
            if let Some((mark, oid)) = line.strip_prefix(':').and_then(|line| line.split_once(' '))
                && let Some(slot) = mark
                    .parse::<usize>()
                    .ok()
                    .and_then(|mark| oids.get_mut(mark - 1))
            {
                *slot = Some(oid.to_owned());
            }
        }
        oids.into_iter()
            .zip(lines)
            .map(|(oid, lines)| {
                Ok(Stored {
                    oid: oid.ok_or_else(|| Refusal::StoreUnwritable {
                        detail: "git stored fewer blobs than it was given".to_owned(),
                    })?,
                    lines,
                })
            })
            .collect()
    }

    /// Copies `source` into the pending snapshot's plain files, named by its
    /// SHA-256, which it returns. It hashes while it copies, a megabyte at a
    /// time, so a large file cannot carry the save past its deadline.
    fn copy_plain(&self, source: &Path, size: u64, deadline: Instant) -> Result<String, Refusal> {
        let unreadable = |error: io::Error| Refusal::Unreadable {
            path: source.display().to_string(),
            detail: error.to_string(),
        };
        let partial = self.pending.files().join("partial");
        let mut input = File::open(source).map_err(unreadable)?;
        let mut output = File::create_new(&partial).map_err(store_failure)?;
        let mut hasher = Sha256::new();
        let mut buffer = vec![0; 1 << 20];
        let mut copied = 0u64;
        loop {
            if Instant::now() >= deadline {
                return Err(Refusal::OverDeadline);
            }
            let read = input.read(&mut buffer).map_err(unreadable)?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
            output.write_all(&buffer[..read]).map_err(store_failure)?;
            copied += read as u64;
        }
        let sha256 = hex(&hasher.finalize());
        if copied != size {
            return Err(Refusal::Unreadable {
                path: source.display().to_string(),
                detail: "it changed while it was being saved".to_owned(),
            });
        }
        fs::rename(&partial, self.pending.files().join(&sha256)).map_err(store_failure)?;
        Ok(sha256)
    }
}

/// The SHA-256 of a file's bytes, and how many there were.
pub(crate) fn sha256_of(path: &Path) -> io::Result<(String, u64)> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0; 1 << 20];
    let mut total = 0u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        total += read as u64;
    }
    Ok((hex(&hasher.finalize()), total))
}

/// The lines in text with no NUL byte, `None` for binary content.
fn text_lines(bytes: &[u8]) -> Option<u64> {
    if bytes.contains(&0) {
        return None;
    }
    let breaks = bytes.iter().filter(|byte| **byte == b'\n').count() as u64;
    Some(breaks + u64::from(bytes.last().is_some_and(|byte| *byte != b'\n')))
}

pub(crate) fn stat_of(metadata: &fs::Metadata) -> Stat {
    Stat {
        size: metadata.size(),
        mtime_ns: metadata.mtime() * 1_000_000_000 + metadata.mtime_nsec(),
        ctime_ns: metadata.ctime() * 1_000_000_000 + metadata.ctime_nsec(),
        inode: metadata.ino(),
        device: metadata.dev(),
        mode: metadata.mode(),
    }
}
