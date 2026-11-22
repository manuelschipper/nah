//! Persists the global, operator-started enforcement pause.

use std::error::Error;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use nah_proto::ctx::{AbsolutePath, Platform};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::private_files::{
    HOOK_LOCK_WAIT, lock_until, restrict_file_to_owner, sync_parent_directory,
};
use crate::state_protection::nah_state_file_path;
use crate::state_protection::validate_private_file;

/// Version 2 is nah 1.x's nap, which names 1.x guards; `import_legacy`
/// converts it once.
const VERSION: u32 = 3;
const LEGACY_VERSION: u32 = 2;
const DURATION_SECONDS: u64 = 10 * 60;
const KEY_BYTES: usize = 32;
/// The MAC framing, unchanged since nah 1.x signed version 2; the version
/// itself is part of every MAC.
const MAC_DOMAIN: &[u8] = b"nah nap state v2\0";

/// What a command says when the nap file holds a version this build neither
/// reads nor converts: another Nah build, older or newer, wrote it, and it
/// pauses nothing here. It fits two rows of the narrowest TUI.
pub(crate) const OTHER_VERSION_NOTICE: &str =
    "A nap from another Nah version is ignored; run `nah nap` again with this Nah.";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum NapMode {
    SelfProtection,
    All,
    /// Only these guards and rules (`guard/rule`) pause, named as
    /// `nah guards` lists them; sorted and unique.
    Guards(Vec<String>),
}

impl NapMode {
    /// What the nap pauses, in the words `nah nap` confirms it with.
    pub(crate) fn scope(&self) -> String {
        match self {
            Self::SelfProtection => "self-protection".to_owned(),
            Self::All => "all enforcement".to_owned(),
            // Names are guards or `guard/rule` IDs, so they carry no noun of
            // their own.
            Self::Guards(names) => names.join(", "),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ActiveNap {
    mode: NapMode,
    expires_at: u64,
}

impl ActiveNap {
    pub(crate) const fn mode(&self) -> &NapMode {
        &self.mode
    }

    pub(crate) const fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// Seconds before the nap expires on its own, for a live countdown.
    pub(crate) fn remaining(&self) -> u64 {
        self.expires_at.saturating_sub(unix_seconds())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredNap {
    v: u32,
    mode: NapMode,
    started_at: u64,
    expires_at: u64,
    mac: [u8; 32],
}

pub(crate) fn load(home: &AbsolutePath, platform: Platform) -> Result<Option<ActiveNap>, NapError> {
    load_at(&nap_path(home, platform), unix_seconds())
}

/// Starts a nap, and says whether it replaced a nap another Nah version
/// wrote.
pub(crate) fn start(
    home: &AbsolutePath,
    platform: Platform,
    mode: NapMode,
) -> Result<(ActiveNap, bool), NapError> {
    start_at(&nap_path(home, platform), mode, unix_seconds())
}

/// Ends the nap, and says whether the nap it removed was written by another
/// Nah version.
pub(crate) fn wake(home: &AbsolutePath, platform: Platform) -> Result<bool, NapError> {
    wake_path(&nap_path(home, platform))
}

pub(crate) fn nap_path(home: &AbsolutePath, platform: Platform) -> PathBuf {
    nah_state_file_path(home, platform, "nap.json")
}

fn load_at(path: &Path, now: u64) -> Result<Option<ActiveNap>, NapError> {
    reject_symlink(path)?;
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(NapError::Io),
    };
    // The version is read before the format, which another version may
    // change. Its nap pauses nothing here, and the error lets each command
    // say so.
    if written_by_other_version(&bytes) {
        return Err(NapError::UnsupportedVersion);
    }
    let stored: StoredNap = serde_json::from_slice(&bytes).map_err(|_| NapError::InvalidState)?;
    // A 1.x nap names 1.x guards and pauses nothing until `import_legacy`
    // converts it.
    if stored.v == LEGACY_VERSION {
        return Ok(None);
    }
    verified(path, stored, now)
}

/// Whether nap file `bytes` hold a version this build neither reads nor
/// converts.
fn written_by_other_version(bytes: &[u8]) -> bool {
    stored_version(bytes).is_some_and(|v| v != u64::from(VERSION) && v != u64::from(LEGACY_VERSION))
}

/// Whether the nap file at `path` holds a version this build neither reads
/// nor converts; the caller holds the lock.
fn holds_other_version(path: &Path) -> bool {
    std::fs::read(path).is_ok_and(|bytes| written_by_other_version(&bytes))
}

fn stored_version(bytes: &[u8]) -> Option<u64> {
    serde_json::from_slice::<serde_json::Value>(bytes)
        .ok()?
        .get("v")?
        .as_u64()
}

/// The nap `stored` grants at `now` once its MAC and timing verify.
fn verified(path: &Path, stored: StoredNap, now: u64) -> Result<Option<ActiveNap>, NapError> {
    let key = load_key(&key_path(path))?.ok_or(NapError::InvalidState)?;
    verify_mac(&stored, &key)?;
    if stored.started_at > now
        || stored
            .expires_at
            .checked_sub(stored.started_at)
            .filter(|duration| *duration == DURATION_SECONDS)
            .is_none()
    {
        return Err(NapError::InvalidState);
    }
    if stored.expires_at <= now {
        return Ok(None);
    }
    Ok(Some(ActiveNap {
        mode: stored.mode,
        expires_at: stored.expires_at,
    }))
}

/// Whether `path` holds a nah 1.x nap for `import_legacy` to convert.
pub(crate) fn is_legacy(path: &Path) -> bool {
    std::fs::read(path)
        .ok()
        .and_then(|bytes| stored_version(&bytes))
        == Some(u64::from(LEGACY_VERSION))
}

/// Converts an active, verified nah 1.x nap in place, once: the same mode
/// and expiry, re-signed as the current version. `convert` maps the 1.x
/// names of a nap of named guards to the 2.0 names to pause; when none
/// remain, the nap ends, as an expired one does, and with `None` the nap is
/// left for a later call to convert. A 1.x nap that does not verify is left
/// as it is, which reads as awake, and is reported. The hook runs this, so
/// it waits for another process's lock only briefly and then fails with
/// `Contended`, leaving the 1.x nap for a later call.
pub(crate) fn import_legacy(
    path: &Path,
    convert: impl FnOnce(&[String]) -> Option<Vec<String>>,
) -> Result<(), NapError> {
    import_legacy_at(path, unix_seconds(), convert)
}

fn import_legacy_at(
    path: &Path,
    now: u64,
    convert: impl FnOnce(&[String]) -> Option<Vec<String>>,
) -> Result<(), NapError> {
    with_lock(path, Some(Instant::now() + HOOK_LOCK_WAIT), || {
        let file = match File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(_) => return Err(NapError::Io),
        };
        let stored: StoredNap =
            serde_json::from_reader(file).map_err(|_| NapError::InvalidState)?;
        if stored.v != LEGACY_VERSION {
            return Ok(());
        }
        let (started_at, expires_at) = (stored.started_at, stored.expires_at);
        let Some(active) = verified(path, stored, now)? else {
            return remove_nap(path);
        };
        let mode = match active.mode {
            NapMode::Guards(names) => {
                let Some(mut names) = convert(&names) else {
                    return Ok(());
                };
                if names.is_empty() {
                    return remove_nap(path);
                }
                names.sort();
                names.dedup();
                NapMode::Guards(names)
            }
            mode => mode,
        };
        let key = load_key(&key_path(path))?.ok_or(NapError::InvalidState)?;
        let mut converted = StoredNap {
            v: VERSION,
            mode,
            started_at,
            expires_at,
            mac: [0; 32],
        };
        converted.mac = sign(&converted, &key)?;
        save(path, &converted)
    })
}

fn start_at(path: &Path, mode: NapMode, now: u64) -> Result<(ActiveNap, bool), NapError> {
    let expires_at = now
        .checked_add(DURATION_SECONDS)
        .ok_or(NapError::InvalidState)?;
    let replaced_other_version = with_lock(path, None, || {
        let key = load_or_create_key(&key_path(path))?;
        let mut stored = StoredNap {
            v: VERSION,
            mode: mode.clone(),
            started_at: now,
            expires_at,
            mac: [0; 32],
        };
        stored.mac = sign(&stored, &key)?;
        let replaced_other_version = holds_other_version(path);
        save(path, &stored)?;
        Ok(replaced_other_version)
    })?;
    Ok((ActiveNap { mode, expires_at }, replaced_other_version))
}

fn wake_path(path: &Path) -> Result<bool, NapError> {
    with_lock(path, None, || {
        let other_version = holds_other_version(path);
        remove_nap(path)?;
        Ok(other_version)
    })
}

/// Removes the nap file; the caller holds the lock.
fn remove_nap(path: &Path) -> Result<(), NapError> {
    reject_symlink(path)?;
    match std::fs::remove_file(path) {
        Ok(()) => sync_parent_directory(path.parent().ok_or(NapError::InvalidPath)?)
            .map_err(|_| NapError::Io),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(NapError::Io),
    }
}

/// Runs `operation` under the nap lock. A command a person runs waits for it
/// as long as another process holds it (`None`); a hook's wait ends at
/// `give_up` with `Contended`.
fn with_lock<T>(
    path: &Path,
    give_up: Option<Instant>,
    operation: impl FnOnce() -> Result<T, NapError>,
) -> Result<T, NapError> {
    let parent = path.parent().ok_or(NapError::InvalidPath)?;
    std::fs::create_dir_all(parent).map_err(|_| NapError::Io)?;
    let lock_path = path.with_extension("lock");
    reject_symlink(&lock_path)?;
    let mut options = OpenOptions::new();
    options.create(true).truncate(false).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let lock = options.open(lock_path).map_err(|_| NapError::Io)?;
    restrict_file_to_owner(&lock).map_err(|_| NapError::Io)?;
    match give_up {
        None => lock.lock().map_err(|_| NapError::Io)?,
        Some(give_up) => lock_until(&lock, give_up).map_err(|error| match error {
            std::fs::TryLockError::WouldBlock => NapError::Contended,
            std::fs::TryLockError::Error(_) => NapError::Io,
        })?,
    }
    reject_symlink(path)?;
    operation()
}

fn save(path: &Path, state: &StoredNap) -> Result<(), NapError> {
    let parent = path.parent().ok_or(NapError::InvalidPath)?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent).map_err(|_| NapError::Io)?;
    restrict_file_to_owner(temporary.as_file()).map_err(|_| NapError::Io)?;
    serde_json::to_writer(&mut temporary, state).map_err(|_| NapError::Io)?;
    temporary.write_all(b"\n").map_err(|_| NapError::Io)?;
    temporary.as_file().sync_all().map_err(|_| NapError::Io)?;
    temporary.persist(path).map_err(|_| NapError::Io)?;
    sync_parent_directory(parent).map_err(|_| NapError::Io)
}

fn key_path(path: &Path) -> PathBuf {
    path.with_extension("key")
}

fn load_or_create_key(path: &Path) -> Result<[u8; KEY_BYTES], NapError> {
    if let Some(key) = load_key(path)? {
        return Ok(key);
    }

    let parent = path.parent().ok_or(NapError::InvalidPath)?;
    let mut key = [0; KEY_BYTES];
    getrandom::fill(&mut key).map_err(|_| NapError::Io)?;
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return load_key(path)?.ok_or(NapError::InvalidState);
        }
        Err(_) => return Err(NapError::Io),
    };
    restrict_file_to_owner(&file).map_err(|_| NapError::Io)?;
    if file.write_all(&key).and_then(|()| file.sync_all()).is_err() {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(NapError::Io);
    }
    sync_parent_directory(parent).map_err(|_| NapError::Io)?;
    Ok(key)
}

fn load_key(path: &Path) -> Result<Option<[u8; KEY_BYTES]>, NapError> {
    reject_symlink(path)?;
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(NapError::Io),
    };
    validate_private_key(&file)?;
    let mut key = [0; KEY_BYTES];
    file.read_exact(&mut key)
        .map_err(|_| NapError::InvalidState)?;
    let mut extra = [0];
    if file.read(&mut extra).map_err(|_| NapError::Io)? != 0 {
        return Err(NapError::InvalidState);
    }
    Ok(Some(key))
}

fn validate_private_key(file: &File) -> Result<(), NapError> {
    let metadata = file.metadata().map_err(|_| NapError::Io)?;
    if !metadata.is_file() {
        return Err(NapError::InvalidState);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(NapError::InvalidState);
        }
    }
    validate_private_file(file).map_err(|_| NapError::InvalidState)?;
    Ok(())
}

fn sign(state: &StoredNap, key: &[u8; KEY_BYTES]) -> Result<[u8; 32], NapError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| NapError::InvalidState)?;
    update_mac(&mut mac, state);
    let bytes = mac.finalize().into_bytes();
    let mut signed = [0; 32];
    signed.copy_from_slice(&bytes);
    Ok(signed)
}

fn verify_mac(state: &StoredNap, key: &[u8; KEY_BYTES]) -> Result<(), NapError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| NapError::InvalidState)?;
    update_mac(&mut mac, state);
    mac.verify_slice(&state.mac)
        .map_err(|_| NapError::InvalidState)
}

/// Fixed-width framing covers every semantic field without trusting JSON formatting.
fn update_mac(mac: &mut Hmac<Sha256>, state: &StoredNap) {
    mac.update(MAC_DOMAIN);
    mac.update(&state.v.to_be_bytes());
    match &state.mode {
        NapMode::SelfProtection => mac.update(&[0]),
        NapMode::All => mac.update(&[1]),
        NapMode::Guards(names) => {
            mac.update(&[2]);
            mac.update(&(names.len() as u64).to_be_bytes());
            for name in names {
                mac.update(&(name.len() as u64).to_be_bytes());
                mac.update(name.as_bytes());
            }
        }
    }
    mac.update(&state.started_at.to_be_bytes());
    mac.update(&state.expires_at.to_be_bytes());
}

fn reject_symlink(path: &Path) -> Result<(), NapError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(NapError::Symlink),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(NapError::Io),
    }
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NapError {
    /// Another Nah process held the nap lock past a hook's wait.
    Contended,
    InvalidPath,
    InvalidState,
    Io,
    Symlink,
    UnsupportedVersion,
}

impl NapError {
    const fn code(self) -> &'static str {
        match self {
            Self::Contended => "nap-state-busy",
            Self::InvalidPath => "invalid-nap-path",
            Self::InvalidState => "invalid-nap-state",
            Self::Io => "nap-state-io-failed",
            Self::Symlink => "nap-state-symlink-unsupported",
            Self::UnsupportedVersion => "unsupported-nap-state-version",
        }
    }
}

impl fmt::Display for NapError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Error for NapError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_path(temporary: &tempfile::TempDir) -> PathBuf {
        #[cfg(windows)]
        {
            let home = AbsolutePath::new(
                Platform::Windows,
                temporary.path().to_str().expect("Windows temp path"),
            )
            .unwrap();
            crate::state_protection::ensure_nah_state_directory(&home, Platform::Windows).unwrap();
            temporary.path().join(".nah/nap.json")
        }
        #[cfg(not(windows))]
        temporary.path().join("nap.json")
    }

    fn signed_state(
        v: u32,
        mode: NapMode,
        started_at: u64,
        expires_at: u64,
        key: &[u8; KEY_BYTES],
    ) -> StoredNap {
        let mut state = StoredNap {
            v,
            mode,
            started_at,
            expires_at,
            mac: [0; 32],
        };
        state.mac = sign(&state, key).unwrap();
        state
    }

    fn write_state(path: &Path, state: &StoredNap) {
        std::fs::write(path, serde_json::to_vec(state).unwrap()).unwrap();
    }

    #[test]
    fn state_is_global_fixed_duration_and_expires_without_a_write() {
        let temp = tempfile::tempdir().unwrap();
        let path = test_path(&temp);
        let active = start_at(&path, NapMode::SelfProtection, 100).unwrap().0;
        assert_eq!(active.mode(), &NapMode::SelfProtection);
        assert_eq!(active.expires_at(), 700);
        assert_eq!(load_at(&path, 699).unwrap(), Some(active));
        assert_eq!(load_at(&path, 700).unwrap(), None);
        // A new nap replaces the paused set and restarts the timer.
        let guards = NapMode::Guards(vec!["work".into(), "machine/system-halt".into()]);
        start_at(&path, NapMode::All, 100).unwrap();
        let replaced = start_at(&path, guards.clone(), 300).unwrap().0;
        assert_eq!(load_at(&path, 899).unwrap(), Some(replaced));
        assert_eq!(load_at(&path, 899).unwrap().unwrap().mode(), &guards);
        assert!(path.is_file());
        assert!(key_path(&path).is_file());
        wake_path(&path).unwrap();
        assert_eq!(load_at(&path, 101).unwrap(), None);
        assert!(key_path(&path).is_file());
    }

    /// A verified 1.x nap pauses nothing until it converts, then keeps its
    /// mode and expiry under the current version with the converted names.
    /// A nap with nothing left to pause ends, as an expired one does.
    #[test]
    fn a_1x_nap_converts_once_with_its_expiry() {
        let temp = tempfile::tempdir().unwrap();
        let path = test_path(&temp);
        start_at(&path, NapMode::All, 100).unwrap();
        let key = load_key(&key_path(&path)).unwrap().unwrap();
        let legacy = |mode| signed_state(LEGACY_VERSION, mode, 100, 700, &key);

        write_state(
            &path,
            &legacy(NapMode::Guards(vec!["corp".into(), "db-destroy".into()])),
        );
        assert!(is_legacy(&path));
        assert_eq!(load_at(&path, 101), Ok(None));
        import_legacy_at(&path, 101, |names| {
            assert_eq!(names, ["corp", "db-destroy"]);
            Some(vec![
                "work/stash-drop".into(),
                "infrastructure/database-drop".into(),
            ])
        })
        .unwrap();
        assert!(!is_legacy(&path));
        let converted = load_at(&path, 101).unwrap().unwrap();
        assert_eq!(
            converted.mode(),
            &NapMode::Guards(vec![
                "infrastructure/database-drop".into(),
                "work/stash-drop".into()
            ])
        );
        assert_eq!(converted.expires_at(), 700);

        write_state(&path, &legacy(NapMode::All));
        import_legacy_at(&path, 101, |_| unreachable!()).unwrap();
        assert_eq!(load_at(&path, 101).unwrap().unwrap().mode(), &NapMode::All);

        write_state(
            &path,
            &legacy(NapMode::Guards(vec!["git-hard-reset".into()])),
        );
        import_legacy_at(&path, 101, |_| None).unwrap();
        assert!(is_legacy(&path));
        import_legacy_at(&path, 101, |_| Some(vec![])).unwrap();
        assert!(!path.exists());
        write_state(&path, &legacy(NapMode::All));
        import_legacy_at(&path, 700, |_| unreachable!()).unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn unsigned_tampered_and_invalid_state_fail_awake() {
        let temp = tempfile::tempdir().unwrap();
        let path = test_path(&temp);
        std::fs::write(
            &path,
            r#"{"v":2,"mode":"all","started_at":100,"expires_at":700}"#,
        )
        .unwrap();
        assert_eq!(load_at(&path, 101), Err(NapError::InvalidState));

        start_at(&path, NapMode::SelfProtection, 100).unwrap();
        let key = load_key(&key_path(&path)).unwrap().unwrap();
        let valid = signed_state(VERSION, NapMode::SelfProtection, 100, 700, &key);
        let guards = signed_state(
            VERSION,
            NapMode::Guards(vec!["work".into()]),
            100,
            700,
            &key,
        );

        let mut mode = valid.clone();
        mode.mode = NapMode::All;
        let mut started_at = valid.clone();
        started_at.started_at += 1;
        let mut expires_at = valid.clone();
        expires_at.expires_at += 1;
        let mut mac = valid;
        mac.mac[0] ^= 1;
        let mut added_guard = guards.clone();
        added_guard.mode = NapMode::Guards(vec!["work".into(), "machine/system-halt".into()]);
        let mut renamed_guard = guards.clone();
        renamed_guard.mode = NapMode::Guards(vec!["machine/system-halt".into()]);
        let mut widened = guards;
        widened.mode = NapMode::All;
        for state in [
            mode,
            started_at,
            expires_at,
            mac,
            added_guard,
            renamed_guard,
            widened,
        ] {
            write_state(&path, &state);
            assert_eq!(load_at(&path, 101), Err(NapError::InvalidState));
        }

        write_state(&path, &signed_state(VERSION, NapMode::All, 100, 701, &key));
        assert_eq!(load_at(&path, 101), Err(NapError::InvalidState));
        write_state(&path, &signed_state(VERSION, NapMode::All, 200, 800, &key));
        assert_eq!(load_at(&path, 101), Err(NapError::InvalidState));
        for v in [1, VERSION + 1] {
            write_state(&path, &signed_state(v, NapMode::All, 100, 700, &key));
            assert_eq!(load_at(&path, 101), Err(NapError::UnsupportedVersion));
        }
        std::fs::write(
            &path,
            r#"{"v":2,"mode":"unknown","started_at":100,"expires_at":700,"mac":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}"#,
        )
        .unwrap();
        assert_eq!(load_at(&path, 101), Err(NapError::InvalidState));
    }

    #[test]
    fn replacing_only_the_key_or_signing_with_the_wrong_key_fails_awake() {
        let temp = tempfile::tempdir().unwrap();
        let path = test_path(&temp);
        start_at(&path, NapMode::All, 100).unwrap();
        let key_path = key_path(&path);
        let real_key = load_key(&key_path).unwrap().unwrap();
        let attacker_key = [0x5a; KEY_BYTES];

        std::fs::write(&key_path, [0; KEY_BYTES - 1]).unwrap();
        assert_eq!(load_at(&path, 101), Err(NapError::InvalidState));

        std::fs::write(&key_path, [0; KEY_BYTES + 1]).unwrap();
        assert_eq!(load_at(&path, 101), Err(NapError::InvalidState));

        std::fs::write(&key_path, attacker_key).unwrap();
        assert_eq!(load_at(&path, 101), Err(NapError::InvalidState));

        std::fs::write(&key_path, real_key).unwrap();
        write_state(
            &path,
            &signed_state(VERSION, NapMode::All, 100, 700, &attacker_key),
        );
        assert_eq!(load_at(&path, 101), Err(NapError::InvalidState));
    }

    #[cfg(unix)]
    #[test]
    fn state_key_and_lock_are_private_and_symlinks_are_rejected() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("nap.json");
        start_at(&path, NapMode::All, 100).unwrap();
        for private in [&path, &key_path(&path), &path.with_extension("lock")] {
            assert_eq!(
                std::fs::metadata(private).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }

        wake_path(&path).unwrap();
        symlink(temp.path().join("elsewhere"), &path).unwrap();
        assert_eq!(load_at(&path, 101), Err(NapError::Symlink));
        assert_eq!(start_at(&path, NapMode::All, 101), Err(NapError::Symlink));

        let key_temp = tempfile::tempdir().unwrap();
        let key_state = key_temp.path().join("nap.json");
        symlink(key_temp.path().join("elsewhere"), key_path(&key_state)).unwrap();
        assert_eq!(
            start_at(&key_state, NapMode::All, 101),
            Err(NapError::Symlink)
        );

        let lock_temp = tempfile::tempdir().unwrap();
        let lock_state = lock_temp.path().join("nap.json");
        symlink(
            lock_temp.path().join("elsewhere"),
            lock_state.with_extension("lock"),
        )
        .unwrap();
        assert_eq!(
            start_at(&lock_state, NapMode::All, 101),
            Err(NapError::Symlink)
        );

        let private_temp = tempfile::tempdir().unwrap();
        let private_state = private_temp.path().join("nap.json");
        start_at(&private_state, NapMode::All, 100).unwrap();
        let private_key = key_path(&private_state);
        std::fs::set_permissions(&private_key, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(load_at(&private_state, 101), Err(NapError::InvalidState));
    }

    #[cfg(windows)]
    #[test]
    fn windows_state_dacl_keeps_keys_locks_and_replacements_usable() {
        let temporary = tempfile::tempdir().unwrap();
        let home = AbsolutePath::new(
            Platform::Windows,
            temporary.path().to_str().expect("Windows temp path"),
        )
        .unwrap();
        crate::state_protection::ensure_nah_state_directory(&home, Platform::Windows).unwrap();
        let path = temporary.path().join(".nah/nap.json");

        start_at(&path, NapMode::SelfProtection, 100).unwrap();
        let first = std::fs::read(&path).unwrap();
        start_at(&path, NapMode::All, 101).unwrap();
        assert_ne!(std::fs::read(&path).unwrap(), first);
        assert_eq!(load_at(&path, 102).unwrap().unwrap().mode(), &NapMode::All);

        for path in [&key_path(&path), &path.with_extension("lock")] {
            let file = File::open(path).unwrap();
            crate::state_protection::validate_private_file(&file).unwrap();
        }
    }
}
