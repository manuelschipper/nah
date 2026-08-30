//! Stores validated memo responses by content identity; it does not validate raw responses.

use std::error::Error;
use std::fmt;
use std::fs::{File, FileTimes, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use nah_proto::ctx::{AbsolutePath, Platform};

pub const CACHE_SIZE_CAP: u64 = 16 * 1024 * 1024;

pub struct MemoCache {
    directory: PathBuf,
}

impl MemoCache {
    pub fn new(directory: PathBuf) -> Self {
        Self { directory }
    }

    pub fn get(&self, key: &str) -> Result<Option<Vec<u8>>, CacheError> {
        validate_key(key)?;
        std::fs::create_dir_all(&self.directory).map_err(|_| CacheError::Io)?;
        let lock = self.lock()?;
        let path = self.directory.join(format!("{key}.json"));
        let file = match OpenOptions::new().read(true).write(true).open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(CacheError::Io),
        };
        let mut bytes = Vec::new();
        (&file)
            .take(CACHE_SIZE_CAP + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| CacheError::Io)?;
        if bytes.len() as u64 > CACHE_SIZE_CAP {
            std::fs::remove_file(path).map_err(|_| CacheError::Io)?;
            return Ok(None);
        }
        file.set_times(FileTimes::new().set_modified(std::time::SystemTime::now()))
            .map_err(|_| CacheError::Io)?;
        drop(lock);
        Ok(Some(bytes))
    }

    pub fn put(&self, key: &str, bytes: &[u8]) -> Result<(), CacheError> {
        validate_key(key)?;
        if bytes.len() as u64 > CACHE_SIZE_CAP {
            return Err(CacheError::EntryTooLarge);
        }
        std::fs::create_dir_all(&self.directory).map_err(|_| CacheError::Io)?;
        let lock = self.lock()?;
        atomic_write(&self.directory.join(format!("{key}.json")), bytes)?;
        self.evict()?;
        drop(lock);
        Ok(())
    }

    pub fn discard(&self, key: &str) -> Result<(), CacheError> {
        validate_key(key)?;
        std::fs::create_dir_all(&self.directory).map_err(|_| CacheError::Io)?;
        let lock = self.lock()?;
        match std::fs::remove_file(self.directory.join(format!("{key}.json"))) {
            Ok(()) => {
                sync_parent(&self.directory)?;
                drop(lock);
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(CacheError::Io),
        }
    }

    fn lock(&self) -> Result<File, CacheError> {
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(self.directory.join(".lock"))
            .map_err(|_| CacheError::Io)?;
        lock.lock().map_err(|_| CacheError::Io)?;
        Ok(lock)
    }

    fn evict(&self) -> Result<(), CacheError> {
        let mut entries = Vec::new();
        let mut total = 0_u64;
        for entry in std::fs::read_dir(&self.directory).map_err(|_| CacheError::Io)? {
            let entry = entry.map_err(|_| CacheError::Io)?;
            if entry.file_name() == ".lock"
                || !entry.file_type().map_err(|_| CacheError::Io)?.is_file()
            {
                continue;
            }
            let metadata = entry.metadata().map_err(|_| CacheError::Io)?;
            total = total.saturating_add(metadata.len());
            entries.push((
                metadata.modified().unwrap_or(std::time::UNIX_EPOCH),
                entry.path(),
                metadata.len(),
            ));
        }
        entries.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
        for (_, path, size) in entries {
            if total <= CACHE_SIZE_CAP {
                break;
            }
            std::fs::remove_file(path).map_err(|_| CacheError::Io)?;
            total = total.saturating_sub(size);
        }
        sync_parent(&self.directory)
    }
}

fn validate_key(key: &str) -> Result<(), CacheError> {
    (key.len() == 64
        && key
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
    .then_some(())
    .ok_or(CacheError::InvalidKey)
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), CacheError> {
    let parent = path.parent().ok_or(CacheError::InvalidPath)?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent).map_err(|_| CacheError::Io)?;
    temporary.write_all(bytes).map_err(|_| CacheError::Io)?;
    temporary.as_file().sync_all().map_err(|_| CacheError::Io)?;
    temporary.persist(path).map_err(|_| CacheError::Io)?;
    sync_parent(parent)
}

pub fn memo_cache_path(home: &AbsolutePath, platform: Platform) -> PathBuf {
    let separator = if platform == Platform::Windows {
        '\\'
    } else {
        '/'
    };
    PathBuf::from(format!(
        "{}{separator}.nah{separator}cache{separator}exec-v1",
        home.as_str().trim_end_matches(['/', '\\'])
    ))
}

#[cfg(unix)]
fn sync_parent(parent: &Path) -> Result<(), CacheError> {
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| CacheError::Io)
}

#[cfg(not(unix))]
fn sync_parent(_parent: &Path) -> Result<(), CacheError> {
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CacheError {
    EntryTooLarge,
    InvalidKey,
    InvalidPath,
    Io,
}

impl CacheError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::EntryTooLarge => "cache-entry-too-large",
            Self::InvalidKey => "invalid-cache-key",
            Self::InvalidPath => "invalid-path",
            Self::Io => "cache-io-failed",
        }
    }
}

impl fmt::Display for CacheError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Error for CacheError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(character: char) -> String {
        character.to_string().repeat(64)
    }

    #[test]
    fn cache_round_trips_and_rejects_invalid_keys() {
        let temp = tempfile::tempdir().unwrap();
        let cache = MemoCache::new(temp.path().join("cache"));
        assert_eq!(cache.get(&key('a')).unwrap(), None);
        cache.put(&key('a'), b"response").unwrap();
        assert_eq!(cache.get(&key('a')).unwrap(), Some(b"response".to_vec()));
        assert_eq!(cache.get("not-a-key").unwrap_err(), CacheError::InvalidKey);
    }

    #[test]
    fn lru_cap_evicts_oldest_entries() {
        let temp = tempfile::tempdir().unwrap();
        let cache = MemoCache::new(temp.path().join("cache"));
        let bytes = vec![0_u8; 9 * 1024 * 1024];
        cache.put(&key('a'), &bytes).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));
        cache.put(&key('b'), &bytes).unwrap();
        assert_eq!(cache.get(&key('a')).unwrap(), None);
        assert_eq!(cache.get(&key('b')).unwrap(), Some(bytes));
    }
}
