//! One project's snapshot store under Nah's state directory, readable only by
//! the user:
//!
//! - `git/`: a bare repository whose `objects/` holds every saved blob, shared
//!   by all snapshots, and in `objects/pack/` the commits snapshots of
//!   commits saved;
//! - `files/<sha256>`: plain copies of large files, shared the same way;
//! - `snapshots/<id>/manifest.json`: one published snapshot each,
//!   `snapshots/<id>/named`: when Nah last named that snapshot as an undo
//!   point, at its save or since, and `snapshots/<id>/undo-for`: the
//!   command it was last named an undo for, where Nah knew it;
//! - `latest`: the id of the last rolling snapshot;
//! - `promised`: the id of the snapshot Nah last gave as an undo;
//! - `journal-mark`: the change journal position the last successful
//!   freshness check began at, and the snapshot it left as the latest;
//! - `tmp/`: snapshots being built, removed by the next save;
//! - `lock`: held by the one process using the store;
//! - `retention-lock`, `removed/` and `repack/`: held and used by the one
//!   process removing what the store no longer keeps (`retention`).
//!
//! A snapshot is built in `tmp/` and renamed into `snapshots/` only once its
//! content is in place, so a save that fails or is killed leaves nothing
//! `list` or `undo` can see.

use crate::journal::Mark;
use crate::manifest::{MANIFEST_FORMAT, Manifest};
use crate::{Refusal, store_failure};
use sha2::{Digest, Sha256};
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// An open store: its lock, if it took one, is held until it is dropped.
pub(crate) struct Store {
    pub(crate) root: PathBuf,
    _lock: Option<File>,
}

/// A snapshot being built in `tmp/`, removed on drop unless published.
pub(crate) struct Pending {
    pub(crate) dir: PathBuf,
    published: bool,
}

impl Drop for Pending {
    fn drop(&mut self) {
        if !self.published {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }
}

impl Pending {
    /// New git objects; the store's shared ones are found as alternates.
    pub(crate) fn objects(&self) -> PathBuf {
        self.dir.join("objects")
    }

    /// New plain copies of large files.
    pub(crate) fn files(&self) -> PathBuf {
        self.dir.join("files")
    }

    /// Files written only to be hashed, such as a link's target.
    pub(crate) fn scratch(&self) -> PathBuf {
        self.dir.join("scratch")
    }
}

/// The store of the project `id` under `snapshots_dir`, created if missing,
/// with its lock taken and any snapshot an earlier process left unfinished
/// removed. Waits for another process's lock until `deadline`.
pub(crate) fn open(snapshots_dir: &Path, id: &str, deadline: Instant) -> Result<Store, Refusal> {
    let root = snapshots_dir.join(id);
    for dir in [
        root.join("git/objects"),
        root.join("git/refs"),
        root.join("files"),
        root.join("snapshots"),
        root.join("tmp"),
    ] {
        private_dir(&dir).map_err(store_failure)?;
    }
    let head = root.join("git/HEAD");
    if !head.exists() {
        fs::write(
            root.join("git/config"),
            "[core]\n\trepositoryformatversion = 0\n\tbare = true\n",
        )
        .map_err(store_failure)?;
        fs::write(&head, "ref: refs/heads/main\n").map_err(store_failure)?;
    }
    let lock = lock(&root.join("lock"), deadline)?;
    // Whatever is in tmp/ belongs to a save that ended without publishing:
    // no other process holds the lock.
    for entry in fs::read_dir(root.join("tmp")).map_err(store_failure)? {
        let path = entry.map_err(store_failure)?.path();
        let _ = fs::remove_dir_all(&path);
    }
    Ok(Store {
        root,
        _lock: Some(lock),
    })
}

/// The store at `root` to read without its lock: published snapshots never
/// change, and only a prune, which holds the retention lock, removes them.
pub(crate) fn unlocked(root: PathBuf) -> Store {
    Store { root, _lock: None }
}

/// Records in the snapshot folder `dir` that Nah names it as an undo point
/// now, for the command `undo_for` where it is known, replacing what an
/// earlier naming recorded.
fn write_named(dir: &Path, undo_for: Option<&str>) -> Result<(), Refusal> {
    let undo_for_path = dir.join("undo-for");
    match undo_for {
        Some(command) => {
            let partial = dir.join("undo-for.partial");
            fs::write(&partial, command).map_err(store_failure)?;
            fs::rename(&partial, &undo_for_path).map_err(store_failure)?;
        }
        None => match fs::remove_file(&undo_for_path) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => {
                return Err(store_failure(error));
            }
            _ => {}
        },
    }
    let partial = dir.join("named.partial");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis());
    fs::write(&partial, now.to_string()).map_err(store_failure)?;
    fs::rename(&partial, dir.join("named")).map_err(store_failure)
}

/// The lock file `path`, created if missing and held until the file is
/// dropped. Waits for another process's lock until `deadline`.
pub(crate) fn lock(path: &Path, deadline: Instant) -> Result<File, Refusal> {
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .open(path)
        .map_err(store_failure)?;
    loop {
        // SAFETY: `lock` is an open descriptor for the duration of the call.
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Ok(lock);
        }
        if Instant::now() >= deadline {
            return Err(Refusal::OverDeadline);
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Creates `dir` and its missing parents readable only by the user.
pub(crate) fn private_dir(dir: &Path) -> io::Result<()> {
    DirBuilder::new().recursive(true).mode(0o700).create(dir)
}

impl Store {
    pub(crate) fn git_dir(&self) -> PathBuf {
        self.root.join("git")
    }

    pub(crate) fn plain_file(&self, sha256: &str) -> PathBuf {
        self.root.join("files").join(sha256)
    }

    pub(crate) fn begin(&self) -> Result<Pending, Refusal> {
        let dir = self.root.join("tmp").join(unique_name());
        let pending = Pending {
            dir,
            published: false,
        };
        for dir in [
            pending.objects().join("pack"),
            pending.files(),
            pending.scratch(),
        ] {
            private_dir(&dir).map_err(store_failure)?;
        }
        Ok(pending)
    }

    /// The ids of every published snapshot, reading no manifest.
    pub(crate) fn ids(&self) -> Result<Vec<String>, Refusal> {
        let mut ids = Vec::new();
        for entry in fs::read_dir(self.root.join("snapshots")).map_err(store_failure)? {
            let entry = entry.map_err(store_failure)?;
            if let Some(id) = entry.file_name().to_str() {
                ids.push(id.to_owned());
            }
        }
        Ok(ids)
    }

    /// Every published manifest, newest first.
    pub(crate) fn manifests(&self) -> Result<Vec<Manifest>, Refusal> {
        let mut manifests = self
            .ids()?
            .iter()
            .map(|id| self.manifest(id))
            .collect::<Result<Vec<_>, _>>()?;
        manifests
            .sort_by(|left, right| (right.started_ns, &right.id).cmp(&(left.started_ns, &left.id)));
        Ok(manifests)
    }

    /// The published snapshot `id`, `None` when there is none.
    pub(crate) fn find(&self, id: &str) -> Result<Option<Manifest>, Refusal> {
        let valid = !id.is_empty() && id.bytes().all(|byte| byte.is_ascii_hexdigit());
        if !valid || !self.root.join("snapshots").join(id).is_dir() {
            return Ok(None);
        }
        self.manifest(id).map(Some)
    }

    fn manifest(&self, id: &str) -> Result<Manifest, Refusal> {
        let path = self.root.join("snapshots").join(id).join("manifest.json");
        let bytes = fs::read(&path).map_err(store_failure)?;
        let manifest: Manifest =
            serde_json::from_slice(&bytes).map_err(|error| Refusal::StoreUnwritable {
                detail: format!("{} is unreadable: {error}", path.display()),
            })?;
        if manifest.format != MANIFEST_FORMAT || manifest.id != id {
            return Err(Refusal::StoreUnwritable {
                detail: format!("{} is not a snapshot this nah reads", path.display()),
            });
        }
        Ok(manifest)
    }

    /// Moves `pending`'s new content into the shared store and publishes its
    /// manifest under a fresh id, which it returns, once `may_publish`
    /// allows the snapshot's folder. Only rolling snapshots set `latest`,
    /// which later saves compare with; a discard's or commits' does not.
    /// A save whose snapshot Nah gives as an undo (`promise`), every save
    /// but a freshness check, sets `promised` and publishes the snapshot
    /// named, for the command `undo_for` where it is known.
    pub(crate) fn publish(
        &self,
        mut pending: Pending,
        mut manifest: Manifest,
        may_publish: &dyn Fn(&Path) -> bool,
        make_latest: bool,
        promise: bool,
        undo_for: Option<&str>,
    ) -> Result<Manifest, Refusal> {
        move_objects(&pending.objects(), &self.git_dir().join("objects")).map_err(store_failure)?;
        for entry in fs::read_dir(pending.files()).map_err(store_failure)? {
            let entry = entry.map_err(store_failure)?;
            let target = self.root.join("files").join(entry.file_name());
            if target.exists() {
                fs::remove_file(entry.path()).map_err(store_failure)?;
            } else {
                fs::rename(entry.path(), target).map_err(store_failure)?;
            }
        }
        fs::remove_dir_all(pending.scratch()).map_err(store_failure)?;
        let snapshots = self.root.join("snapshots");
        let id = (0u32..)
            .map(|attempt| {
                let digest = Sha256::digest(format!(
                    "{}\0{}\0{attempt}",
                    pending.dir.display(),
                    manifest.started_ns
                ));
                hex(&digest[..4])
            })
            .find(|id| !snapshots.join(id).exists())
            .expect("some id is free");
        manifest.id = id.clone();
        manifest.created_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_millis() as u64);
        let bytes = serde_json::to_vec(&manifest).expect("a manifest serializes");
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(pending.dir.join("manifest.json"))
            .map_err(store_failure)?;
        file.write_all(&bytes).map_err(store_failure)?;
        file.sync_all().map_err(store_failure)?;
        if promise {
            write_named(&pending.dir, undo_for)?;
        }
        // Content in the shared store is not visible on its own; dropping
        // `pending` removes the rest.
        if !may_publish(&snapshots.join(&id)) {
            return Err(Refusal::OverDeadline);
        }
        // `latest` and `promised` name the snapshot before it is visible, so
        // nothing that can fail follows the rename that publishes it. Until
        // then, or if the rename fails, they name no snapshot, and the next
        // save reuses no content.
        if promise {
            self.set_promised(&id)?;
        }
        if make_latest {
            let latest = self.root.join("latest.partial");
            fs::write(&latest, &id).map_err(store_failure)?;
            fs::rename(&latest, self.root.join("latest")).map_err(store_failure)?;
        }
        fs::rename(&pending.dir, snapshots.join(&id)).map_err(store_failure)?;
        pending.published = true;
        Ok(manifest)
    }

    /// When Nah last named the published snapshot `id` as an undo point, in
    /// milliseconds since the Unix epoch, `None` when it never did after the
    /// save.
    pub(crate) fn named_ms(&self, id: &str) -> Result<Option<u64>, Refusal> {
        let path = self.root.join("snapshots").join(id).join("named");
        match fs::read_to_string(&path) {
            Ok(named) => named
                .parse()
                .map(Some)
                .map_err(|error| Refusal::StoreUnwritable {
                    detail: format!("{} is unreadable: {error}", path.display()),
                }),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(store_failure(error)),
        }
    }

    /// The command Nah last named the published snapshot `id` an undo for,
    /// `None` when it never did or did not know the command.
    pub(crate) fn undo_for(&self, id: &str) -> Result<Option<String>, Refusal> {
        match fs::read_to_string(self.root.join("snapshots").join(id).join("undo-for")) {
            Ok(command) => Ok(Some(command)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(store_failure(error)),
        }
    }

    /// Records that Nah names the published snapshot `id` as an undo point
    /// now, for `undo_for` where it is known, making it the newest promise.
    pub(crate) fn set_named(&self, id: &str, undo_for: Option<&str>) -> Result<(), Refusal> {
        write_named(&self.root.join("snapshots").join(id), undo_for)?;
        self.set_promised(id)
    }

    fn set_promised(&self, id: &str) -> Result<(), Refusal> {
        let partial = self.root.join("promised.partial");
        fs::write(&partial, id).map_err(store_failure)?;
        fs::rename(&partial, self.root.join("promised")).map_err(store_failure)
    }

    /// The id of the snapshot Nah last gave as an undo, `None` when there
    /// is none. It may name a snapshot retention removed since.
    pub(crate) fn promised(&self) -> Result<Option<String>, Refusal> {
        match fs::read_to_string(self.root.join("promised")) {
            Ok(id) => Ok(Some(id)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(store_failure(error)),
        }
    }

    /// The change journal mark the last successful freshness check left,
    /// `None` when there is none or it cannot be read.
    pub(crate) fn mark(&self) -> Option<Mark> {
        let bytes = fs::read(self.root.join("journal-mark")).ok()?;
        serde_json::from_slice(&bytes).ok()
    }

    /// Records `mark`, or with `None` removes the one recorded.
    pub(crate) fn set_mark(&self, mark: Option<&Mark>) -> Result<(), Refusal> {
        let path = self.root.join("journal-mark");
        match mark {
            Some(mark) => {
                let partial = self.root.join("journal-mark.partial");
                let bytes = serde_json::to_vec(mark).expect("a mark serializes");
                fs::write(&partial, bytes).map_err(store_failure)?;
                fs::rename(&partial, &path).map_err(store_failure)
            }
            None => match fs::remove_file(&path) {
                Err(error) if error.kind() != io::ErrorKind::NotFound => Err(store_failure(error)),
                _ => Ok(()),
            },
        }
    }

    /// The last rolling snapshot, which a save compares with and reuses
    /// content from.
    pub(crate) fn latest(&self) -> Result<Option<Manifest>, Refusal> {
        match fs::read_to_string(self.root.join("latest")) {
            Ok(id) => self.find(&id),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(store_failure(error)),
        }
    }
}

/// Moves every loose object and pack under `from` into `to`, keeping one
/// already there and dropping its copy.
fn move_objects(from: &Path, to: &Path) -> io::Result<()> {
    for fanout in fs::read_dir(from)? {
        let fanout = fanout?;
        if !fanout.file_type()?.is_dir() {
            continue;
        }
        let target = to.join(fanout.file_name());
        private_dir(&target)?;
        for object in fs::read_dir(fanout.path())? {
            let object = object?;
            let destination = target.join(object.file_name());
            if destination.exists() {
                fs::remove_file(object.path())?;
            } else {
                fs::rename(object.path(), destination)?;
            }
        }
    }
    Ok(())
}

/// A name no other pending snapshot of this store uses.
fn unique_name() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{}-{now}", std::process::id())
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Nanoseconds since the Unix epoch.
pub(crate) fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos() as u64)
}

/// Bytes free to the user on the filesystem holding `dir`.
pub(crate) fn free_bytes(dir: &Path) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(dir.as_os_str().as_bytes()).ok()?;
    let mut stats = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: `path` is NUL-terminated and `stats` is large enough for the call
    // to fill.
    if unsafe { libc::statvfs(path.as_ptr(), stats.as_mut_ptr()) } != 0 {
        return None;
    }
    // SAFETY: statvfs succeeded, so it filled `stats`.
    let stats = unsafe { stats.assume_init() };
    #[allow(clippy::unnecessary_cast)]
    Some(stats.f_bavail as u64 * stats.f_frsize as u64)
}
