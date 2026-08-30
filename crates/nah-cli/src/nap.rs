//! Persists the global, operator-started enforcement pause.

use std::error::Error;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use nah_proto::ctx::{AbsolutePath, Platform};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::state_protection::validate_private_file;

const VERSION: u32 = 1;
const DURATION_SECONDS: u64 = 10 * 60;
const KEY_BYTES: usize = 32;
const MAC_DOMAIN: &[u8] = b"nah nap state v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum NapMode {
    SelfProtection,
    All,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ActiveNap {
    mode: NapMode,
    expires_at: u64,
}

impl ActiveNap {
    pub(crate) const fn mode(self) -> NapMode {
        self.mode
    }

    pub(crate) const fn expires_at(self) -> u64 {
        self.expires_at
    }

    /// Seconds before the nap expires on its own, for a live countdown.
    pub(crate) fn remaining(self) -> u64 {
        self.expires_at.saturating_sub(unix_seconds())
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
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

pub(crate) fn start(
    home: &AbsolutePath,
    platform: Platform,
    mode: NapMode,
) -> Result<ActiveNap, NapError> {
    start_at(&nap_path(home, platform), mode, unix_seconds())
}

pub(crate) fn wake(home: &AbsolutePath, platform: Platform) -> Result<(), NapError> {
    wake_path(&nap_path(home, platform))
}

pub(crate) fn nap_path(home: &AbsolutePath, platform: Platform) -> PathBuf {
    let separator = if platform == Platform::Windows {
        '\\'
    } else {
        '/'
    };
    PathBuf::from(format!(
        "{}{separator}.nah{separator}nap.json",
        home.as_str().trim_end_matches(['/', '\\'])
    ))
}

fn load_at(path: &Path, now: u64) -> Result<Option<ActiveNap>, NapError> {
    reject_symlink(path)?;
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(NapError::Io),
    };
    let stored: StoredNap = serde_json::from_reader(file).map_err(|_| NapError::InvalidState)?;
    if stored.v != VERSION {
        return Err(NapError::UnsupportedVersion);
    }
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

fn start_at(path: &Path, mode: NapMode, now: u64) -> Result<ActiveNap, NapError> {
    let expires_at = now
        .checked_add(DURATION_SECONDS)
        .ok_or(NapError::InvalidState)?;
    with_lock(path, || {
        let key = load_or_create_key(&key_path(path))?;
        let mut stored = StoredNap {
            v: VERSION,
            mode,
            started_at: now,
            expires_at,
            mac: [0; 32],
        };
        stored.mac = sign(&stored, &key)?;
        save(path, &stored)
    })?;
    Ok(ActiveNap { mode, expires_at })
}

fn wake_path(path: &Path) -> Result<(), NapError> {
    with_lock(path, || {
        reject_symlink(path)?;
        match std::fs::remove_file(path) {
            Ok(()) => sync_parent(path.parent().ok_or(NapError::InvalidPath)?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(NapError::Io),
        }
    })
}

fn with_lock<T>(
    path: &Path,
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
    protect_file(&lock)?;
    lock.lock().map_err(|_| NapError::Io)?;
    reject_symlink(path)?;
    operation()
}

fn save(path: &Path, state: &StoredNap) -> Result<(), NapError> {
    let parent = path.parent().ok_or(NapError::InvalidPath)?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent).map_err(|_| NapError::Io)?;
    protect_file(temporary.as_file())?;
    serde_json::to_writer(&mut temporary, state).map_err(|_| NapError::Io)?;
    temporary.write_all(b"\n").map_err(|_| NapError::Io)?;
    temporary.as_file().sync_all().map_err(|_| NapError::Io)?;
    temporary.persist(path).map_err(|_| NapError::Io)?;
    sync_parent(parent)
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
    protect_file(&file)?;
    if file.write_all(&key).and_then(|()| file.sync_all()).is_err() {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(NapError::Io);
    }
    sync_parent(parent)?;
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
    mac.update(&[match state.mode {
        NapMode::SelfProtection => 0,
        NapMode::All => 1,
    }]);
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

#[cfg(unix)]
fn protect_file(file: &File) -> Result<(), NapError> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|_| NapError::Io)
}

#[cfg(not(unix))]
fn protect_file(_file: &File) -> Result<(), NapError> {
    Ok(())
}

#[cfg(unix)]
fn sync_parent(parent: &Path) -> Result<(), NapError> {
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| NapError::Io)
}

#[cfg(not(unix))]
fn sync_parent(_parent: &Path) -> Result<(), NapError> {
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NapError {
    InvalidPath,
    InvalidState,
    Io,
    Symlink,
    UnsupportedVersion,
}

impl NapError {
    const fn code(self) -> &'static str {
        match self {
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
        let active = start_at(&path, NapMode::SelfProtection, 100).unwrap();
        assert_eq!(active.mode(), NapMode::SelfProtection);
        assert_eq!(active.expires_at(), 700);
        assert_eq!(load_at(&path, 699).unwrap(), Some(active));
        assert_eq!(load_at(&path, 700).unwrap(), None);
        assert!(path.is_file());
        assert!(key_path(&path).is_file());
        wake_path(&path).unwrap();
        assert_eq!(load_at(&path, 101).unwrap(), None);
        assert!(key_path(&path).is_file());
    }

    #[test]
    fn unsigned_tampered_and_invalid_state_fail_awake() {
        let temp = tempfile::tempdir().unwrap();
        let path = test_path(&temp);
        std::fs::write(
            &path,
            r#"{"v":1,"mode":"all","started_at":100,"expires_at":700}"#,
        )
        .unwrap();
        assert_eq!(load_at(&path, 101), Err(NapError::InvalidState));

        start_at(&path, NapMode::SelfProtection, 100).unwrap();
        let key = load_key(&key_path(&path)).unwrap().unwrap();
        let valid = signed_state(VERSION, NapMode::SelfProtection, 100, 700, &key);

        let mut mode = valid;
        mode.mode = NapMode::All;
        let mut started_at = valid;
        started_at.started_at += 1;
        let mut expires_at = valid;
        expires_at.expires_at += 1;
        let mut mac = valid;
        mac.mac[0] ^= 1;
        for state in [mode, started_at, expires_at, mac] {
            write_state(&path, &state);
            assert_eq!(load_at(&path, 101), Err(NapError::InvalidState));
        }

        write_state(&path, &signed_state(VERSION, NapMode::All, 100, 701, &key));
        assert_eq!(load_at(&path, 101), Err(NapError::InvalidState));
        write_state(&path, &signed_state(VERSION, NapMode::All, 200, 800, &key));
        assert_eq!(load_at(&path, 101), Err(NapError::InvalidState));
        write_state(&path, &signed_state(2, NapMode::All, 100, 700, &key));
        assert_eq!(load_at(&path, 101), Err(NapError::UnsupportedVersion));
        std::fs::write(
            &path,
            r#"{"v":1,"mode":"unknown","started_at":100,"expires_at":700,"mac":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}"#,
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
        assert_eq!(load_at(&path, 102).unwrap().unwrap().mode(), NapMode::All);

        for path in [&key_path(&path), &path.with_extension("lock")] {
            let file = File::open(path).unwrap();
            crate::state_protection::validate_private_file(&file).unwrap();
        }
    }
}
