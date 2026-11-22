//! The session ledger store, under `~/.nah/sessions/`, which self-protection
//! already covers as Nah state. Each session has two files:
//!
//! - `<key>.jsonl`, an append-only log of what each call proposed, how the
//!   post-call hook settled it, and every block. `nah session` prints it; no
//!   hook reads it, so its length costs nothing.
//! - `<key>.json`, the session's state: the facts the rules read, folded from
//!   the log as it is written. It holds one entry per flagged content, path
//!   or launch, never one per call, so a long session's lookups stay bounded.
//!
//! Beside them, `labels.json` holds every file any session labels as
//! secret, with the sessions that label it: snapshots are shared by every
//! session of a project, so each leaves out what any of them labels.
//!
//! Rows and state hold structure only (paths, content digests, guard names,
//! hosts), never the content they describe.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use nah_proto::ctx::{AbsolutePath, Platform};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::world::World;
use crate::state_protection::nah_state_file_path;

/// How long one hook waits for the hooks of the same session ahead of it to
/// release the ledger. Each holds it only to read the state, apply the rules
/// and record one call (content is judged before), so a longer wait means a
/// stuck or hostile holder.
const LOCK_BUDGET: Duration = Duration::from_millis(500);
/// A state past this size is refused rather than parsed on every call.
const MAX_STATE_BYTES: u64 = 16 * 1024 * 1024;
/// A log past this size is no longer printed whole.
const MAX_LOG_BYTES: u64 = 64 * 1024 * 1024;
/// Calls proposed and not yet settled. Past this many, the oldest is taken
/// as having run as proposed: a session without the post-call hook would
/// otherwise grow its state with every call.
const MAX_IN_FLIGHT: usize = 256;

/// The facts the rules read, as the calls settled so far left them.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub(crate) struct SessionState {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) session: Option<Session>,
    /// Content judged unsafe to run, by digest. A judgment depends only on
    /// the content and where it is written, so a digest stays flagged even
    /// when the write that carried it never ran.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) flagged: BTreeMap<String, ContentVerdict>,
    /// The digest of flagged content each path last held, for a later run
    /// whose program cannot be hashed. Clean content leaves no entry, so the
    /// state grows with flagged writes, not with every script written.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) written: BTreeMap<String, String>,
    /// Paths a launch will run later, by path.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) pending: BTreeMap<String, Pending>,
    /// Files secret bytes flowed into, with the digest found after the call
    /// that labelled them.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) labels: BTreeMap<String, Option<String>>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub(crate) label_digests: BTreeSet<String>,
    /// Files a download wrote and folders a clone or extraction filled.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) fetched: BTreeMap<String, Fetched>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub(crate) fetched_digests: BTreeSet<String>,
    /// Calls whose changes wait for the post-call hook, oldest first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) in_flight: Vec<Intent>,
    /// The labelled files this session last put in the shared label index.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub(crate) indexed: BTreeSet<String>,
}

impl SessionState {
    /// The files this session labels, counting labels still in flight.
    fn labelled(&self) -> BTreeSet<String> {
        self.labels
            .keys()
            .cloned()
            .chain(self.in_flight.iter().flat_map(|intent| {
                intent.changes.iter().filter_map(|change| match change {
                    Change::Label { path, .. } => Some(path.clone()),
                    _ => None,
                })
            }))
            .collect()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct Session {
    pub(crate) runtime: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) session_id: Option<String>,
    pub(crate) workspace: String,
}

/// How written content judges when run: the guards a run of it blocks on.
/// Not a decision verdict (`nah_proto::decision::Verdict`), which is one
/// call's block or delegate.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct ContentVerdict {
    /// The guards a run of the whole file blocks on.
    pub(crate) guards: Vec<String>,
    /// For a Makefile or `package.json`, each target or script in file
    /// order with the guards a run of it blocks on: a run selects some of
    /// them, and only those decide. Empty for any other program.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) entries: Vec<(String, Vec<String>)>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct Pending {
    /// The program, scheduler or job that will run the path.
    pub(crate) via: String,
    /// A crontab or launch agent entry, which runs outside any session.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(crate) scheduled: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct Fetched {
    /// `download`, `clone`, `extract`, or `copy` of a fetched file.
    pub(crate) source: String,
    /// A folder: everything under it came from outside.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(crate) tree: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) digest: Option<String>,
}

/// One call's proposed changes, keyed by the runtime's tool use id.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct Intent {
    pub(crate) call: String,
    /// The subagent that made the call; `None` for the main agent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) agent: Option<String>,
    /// The call may leave a launch running after it returns.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(crate) background: bool,
    /// A file tool that writes one file, so nothing when it fails.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(crate) file_tool: bool,
    pub(crate) changes: Vec<Change>,
}

/// What a call proposes to leave behind. The post-call hook keeps each one
/// the disk confirms.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "change", rename_all = "kebab-case")]
pub(crate) enum Change {
    /// Judged content the call leaves at `path`.
    Wrote { path: String, digest: String },
    /// A launch of `path` that may run it after the call.
    Launch {
        path: String,
        via: String,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        scheduled: bool,
    },
    /// Secret bytes flow into `path`.
    Label {
        path: String,
        /// What the file held before the call and when it last changed. A
        /// call that failed counts only if it changed them.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        found: Option<String>,
    },
    /// A stated overwrite no secret flowed into replaces a labelled file.
    Unlabel { path: String, digest: String },
    Fetched {
        path: String,
        source: String,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        tree: bool,
        /// What the path held before the call: a file's digest, or a
        /// folder's modification time. A call that failed counts only if it
        /// changed it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        found: Option<String>,
    },
}

/// One log row: when it was written and what it records.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct Row {
    pub(crate) at: String,
    #[serde(flatten)]
    pub(crate) record: Record,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub(crate) enum Record {
    Session(Session),
    /// Content judged unsafe to run, written to `path`.
    Flagged {
        path: String,
        digest: String,
        verdict: ContentVerdict,
    },
    /// A call's proposed changes.
    Proposed {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        call: Option<String>,
        changes: Vec<Change>,
    },
    /// The post-call hook's account of a call: what the disk confirmed.
    Settled {
        call: String,
        outcome: Outcome,
        kept: Vec<Change>,
    },
    /// A call Nah blocked, by a stateless guard or a session rule, with the
    /// guards it reports and the resources the call touches.
    Blocked {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        rule: Option<String>,
        guards: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        resources: Vec<String>,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Outcome {
    Succeeded,
    Failed,
    /// The batch ended without the call reporting: it was denied or never
    /// started.
    NotRun,
    /// The call ended, but its event does not say whether it succeeded:
    /// every runtime but Claude Code reports a shell command's end without
    /// its exit status.
    Ended,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LedgerError {
    /// Another hook held the ledger past the lock budget.
    Contended,
    Io,
    /// The state does not parse, or is past its size bound.
    Damaged,
}

impl LedgerError {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::Contended => "contended",
            Self::Io => "io",
            Self::Damaged => "damaged",
        }
    }
}

/// The ledger key of a session: a digest of the runtime's session id, or,
/// without one, of the workspace and the agent process that ran the hook.
pub(crate) fn session_key(runtime: &str, session_id: Option<&str>, workspace: &str) -> String {
    let identity = match session_id {
        Some(id) => format!("{runtime}\0session\0{id}"),
        None => format!("{runtime}\0workspace\0{workspace}\0{}", parent_process()),
    };
    format!("{:x}", Sha256::digest(identity.as_bytes()))[..32].to_owned()
}

#[cfg(unix)]
fn parent_process() -> u32 {
    std::os::unix::process::parent_id()
}

#[cfg(not(unix))]
fn parent_process() -> u32 {
    0
}

pub(crate) fn sessions_directory(home: &AbsolutePath, platform: Platform) -> PathBuf {
    nah_state_file_path(home, platform, "sessions")
}

/// The log of the session `key`; its state sits beside it.
pub(crate) fn log_path(home: &AbsolutePath, platform: Platform, key: &str) -> PathBuf {
    sessions_directory(home, platform).join(format!("{key}.jsonl"))
}

fn state_path(log: &Path) -> PathBuf {
    log.with_extension("json")
}

/// The session's state under a shared lock, for a reader that records
/// nothing; a session not yet started is empty.
pub(crate) fn read_state(log: &Path) -> Result<SessionState, LedgerError> {
    let file = match File::open(log) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(SessionState::default());
        }
        Err(_) => return Err(LedgerError::Io),
    };
    lock(&file, true)?;
    let state = load_state(&state_path(log));
    let unlocked = file.unlock().map_err(|_| LedgerError::Io);
    let state = state?;
    unlocked.map(|()| state)
}

/// Every row of the log at `log`, under a shared lock.
pub(crate) fn read_log(log: &Path) -> Result<Vec<Row>, LedgerError> {
    let mut file = match File::open(log) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => return Err(LedgerError::Io),
    };
    lock(&file, true)?;
    let rows = (|| {
        if file.metadata().map_err(|_| LedgerError::Io)?.len() > MAX_LOG_BYTES {
            return Err(LedgerError::Damaged);
        }
        let mut text = String::new();
        file.read_to_string(&mut text)
            .map_err(|_| LedgerError::Io)?;
        text.lines()
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_str(line).map_err(|_| LedgerError::Damaged))
            .collect()
    })();
    let unlocked = file.unlock().map_err(|_| LedgerError::Io);
    let rows = rows?;
    unlocked.map(|()| rows)
}

/// A session's ledger held under its exclusive lock from the state its rules
/// read through the write that records the call, so a parallel call of the
/// same session decides on a state that includes this one, or this one on a
/// state that includes it. Dropping it releases the lock.
pub(crate) struct Locked {
    log: File,
    state_path: PathBuf,
    pub(crate) state: SessionState,
}

impl Locked {
    pub(crate) fn open(log: &Path) -> Result<Self, LedgerError> {
        let directory = log.parent().ok_or(LedgerError::Io)?;
        create_private_directory(directory)?;
        let file = private_options()
            .append(true)
            .read(true)
            .open(log)
            .map_err(|_| LedgerError::Io)?;
        lock(&file, false)?;
        let state_path = state_path(log);
        let state = load_state(&state_path)?;
        Ok(Self {
            log: file,
            state_path,
            state,
        })
    }

    /// Appends `rows` to the log as one write, then replaces the state file
    /// with the state as it stands.
    pub(crate) fn record(&mut self, rows: &[Row], world: &dyn World) -> Result<(), LedgerError> {
        while self.state.in_flight.len() > MAX_IN_FLIGHT {
            let oldest = self.state.in_flight.remove(0);
            for change in &oldest.changes {
                self.state.apply(change, world);
            }
        }
        if !rows.is_empty() {
            let mut bytes = Vec::new();
            for row in rows {
                serde_json::to_writer(&mut bytes, row).map_err(|_| LedgerError::Io)?;
                bytes.push(b'\n');
            }
            self.log.write_all(&bytes).map_err(|_| LedgerError::Io)?;
        }
        let labelled = self.state.labelled();
        if labelled != self.state.indexed {
            let directory = self.state_path.parent().ok_or(LedgerError::Io)?;
            let key = self
                .state_path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .ok_or(LedgerError::Io)?;
            index_labels(directory, key, &labelled)?;
            self.state.indexed = labelled;
        }
        let bytes = serde_json::to_vec(&self.state).map_err(|_| LedgerError::Io)?;
        replace_file(&self.state_path, &bytes)
    }
}

/// Every file any session labels as secret, as far as it can be read: the
/// shared index (none when it is missing), or, where the index cannot be
/// read, every session state that can. The pre-call hook reads this one;
/// `labelled_paths`, on Unix, is the strict reader a snapshot needs.
pub(crate) fn readable_labelled_paths(home: &AbsolutePath, platform: Platform) -> BTreeSet<String> {
    let directory = sessions_directory(home, platform);
    match read_index(&directory.join(LABELS)) {
        Ok(index) => index.into_keys().collect(),
        Err(_) => std::fs::read_dir(&directory)
            .into_iter()
            .flatten()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "jsonl"))
            .filter_map(|log| read_state(&log).ok())
            .flat_map(|state| state.labelled())
            .collect(),
    }
}

/// Like [`readable_labelled_paths`], or why some session's labels cannot be
/// read: a snapshot must never copy a file one of them names.
#[cfg(unix)]
pub(crate) fn labelled_paths(
    home: &AbsolutePath,
    platform: Platform,
) -> Result<BTreeSet<String>, LedgerError> {
    let directory = sessions_directory(home, platform);
    // Only an index that is there vouches for the ledgers; without one, each
    // ledger is read.
    if std::fs::symlink_metadata(directory.join(LABELS)).is_ok()
        && let Ok(index) = read_index(&directory.join(LABELS))
    {
        return Ok(index.into_keys().collect());
    }
    let entries = match std::fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeSet::new()),
        Err(_) => return Err(LedgerError::Io),
    };
    let mut labels = BTreeSet::new();
    for entry in entries {
        let log = entry.map_err(|_| LedgerError::Io)?.path();
        if log.extension().is_some_and(|ext| ext == "jsonl") {
            labels.extend(read_state(&log)?.labelled());
        }
    }
    Ok(labels)
}

/// The shared label index, under `~/.nah/sessions/`.
const LABELS: &str = "labels.json";

/// The labelled files of every session, with the sessions labelling each.
type LabelIndex = BTreeMap<String, BTreeSet<String>>;

fn read_index(path: &Path) -> Result<LabelIndex, LedgerError> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|_| LedgerError::Damaged),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(LabelIndex::new()),
        Err(_) => Err(LedgerError::Io),
    }
}

/// Makes `labelled` the files the session `key` holds in the shared index.
fn index_labels(
    directory: &Path,
    key: &str,
    labelled: &BTreeSet<String>,
) -> Result<(), LedgerError> {
    let lock_file = private_options()
        .write(true)
        .truncate(false)
        .open(directory.join("labels.lock"))
        .map_err(|_| LedgerError::Io)?;
    lock(&lock_file, false)?;
    let path = directory.join(LABELS);
    // A damaged index is rebuilt from this session's labels; the others
    // add theirs back on their next change, and readers meanwhile read
    // every session's state.
    let mut index = read_index(&path).unwrap_or_default();
    index.retain(|_, sessions| {
        sessions.remove(key);
        !sessions.is_empty()
    });
    for file in labelled {
        index
            .entry(file.clone())
            .or_default()
            .insert(key.to_owned());
    }
    let bytes = serde_json::to_vec(&index).map_err(|_| LedgerError::Io)?;
    let written = replace_file(&path, &bytes);
    let _ = lock_file.unlock();
    written
}

/// Writes `bytes` to `path` through a rename, so a reader never sees half.
pub(super) fn replace_file(path: &Path, bytes: &[u8]) -> Result<(), LedgerError> {
    let mut partial = path.as_os_str().to_owned();
    partial.push(".partial");
    let partial = PathBuf::from(partial);
    let mut file = private_options()
        .write(true)
        .truncate(true)
        .open(&partial)
        .map_err(|_| LedgerError::Io)?;
    file.write_all(bytes).map_err(|_| LedgerError::Io)?;
    std::fs::rename(&partial, path).map_err(|_| LedgerError::Io)
}

impl Drop for Locked {
    fn drop(&mut self) {
        let _ = self.log.unlock();
    }
}

impl SessionState {
    /// The state without the background launches of `paths` that have
    /// ended: such a launch waits to run its file only while a running
    /// process names it. A crontab or launch agent entry waits until it is
    /// removed. Applied before the calls in flight are counted, whose
    /// launches may not have started yet.
    pub(crate) fn without_ended_launches(mut self, paths: &[&str], world: &dyn World) -> Self {
        self.pending.retain(|path, pending| {
            pending.scheduled
                || !paths.contains(&path.as_str())
                || super::post_call::still_running(path, world)
        });
        self
    }

    /// The state with every call still in flight counted as having run: what
    /// the rules read, since a call that has not reported may be running.
    pub(crate) fn counting_in_flight(mut self, world: &dyn World) -> Self {
        for intent in std::mem::take(&mut self.in_flight) {
            for change in &intent.changes {
                self.apply(change, world);
            }
        }
        self
    }

    /// Applies one change as having happened, as the disk confirmed it or,
    /// for a call that never reports, as it was proposed.
    pub(crate) fn apply(&mut self, change: &Change, world: &dyn World) {
        match change {
            Change::Wrote { path, digest } => {
                if self.flagged.contains_key(digest) {
                    self.written.insert(path.clone(), digest.clone());
                } else {
                    self.written.remove(path);
                }
            }
            Change::Launch {
                path,
                via,
                scheduled,
            } => {
                self.pending.insert(
                    path.clone(),
                    Pending {
                        via: via.clone(),
                        scheduled: *scheduled,
                    },
                );
            }
            Change::Label { path, .. } => {
                let digest = world.digest(path);
                if let Some(digest) = &digest {
                    self.label_digests.insert(digest.clone());
                }
                self.labels.insert(path.clone(), digest);
            }
            Change::Unlabel { path, .. } => {
                self.labels.remove(path);
            }
            Change::Fetched {
                path, source, tree, ..
            } => {
                let digest = (!tree).then(|| world.digest(path)).flatten();
                if let Some(digest) = &digest {
                    self.fetched_digests.insert(digest.clone());
                }
                self.fetched.insert(
                    path.clone(),
                    Fetched {
                        source: source.clone(),
                        tree: *tree,
                        digest,
                    },
                );
            }
        }
    }
}

fn load_state(path: &Path) -> Result<SessionState, LedgerError> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(SessionState::default());
        }
        Err(_) => return Err(LedgerError::Io),
    };
    if file.metadata().map_err(|_| LedgerError::Io)?.len() > MAX_STATE_BYTES {
        return Err(LedgerError::Damaged);
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(|_| LedgerError::Io)?;
    serde_json::from_slice(&bytes).map_err(|_| LedgerError::Damaged)
}

fn private_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
}

pub(super) fn create_private_directory(directory: &Path) -> Result<(), LedgerError> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(directory).map_err(|_| LedgerError::Io)
}

fn lock(file: &File, shared: bool) -> Result<(), LedgerError> {
    let give_up = Instant::now() + LOCK_BUDGET;
    loop {
        let attempt = if shared {
            file.try_lock_shared()
        } else {
            file.try_lock()
        };
        match attempt {
            Ok(()) => return Ok(()),
            Err(std::fs::TryLockError::WouldBlock) if Instant::now() < give_up => {
                std::thread::sleep(Duration::from_millis(2));
            }
            Err(std::fs::TryLockError::WouldBlock) => return Err(LedgerError::Contended),
            Err(std::fs::TryLockError::Error(_)) => return Err(LedgerError::Io),
        }
    }
}
