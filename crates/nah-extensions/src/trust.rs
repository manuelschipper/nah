//! Persists canonical trusted project roots; it does not infer additional trust.

use std::error::Error;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use nah_proto::ctx::{
    AbsolutePath, ActivationProjection, Platform, TrustProjection, TrustedRoot, TrustedRootId,
};
use serde::{Deserialize, Serialize};

const TRUST_DATABASE_VERSION: u32 = 1;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustDatabase {
    v: u32,
    trusted_roots: Vec<TrustedRoot>,
}

impl TrustDatabase {
    fn empty() -> Self {
        Self {
            v: TRUST_DATABASE_VERSION,
            trusted_roots: vec![],
        }
    }

    pub fn load(path: &Path, platform: Platform) -> Result<Self, TrustError> {
        let file = match File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Self::empty()),
            Err(_) => return Err(TrustError::Io),
        };
        let database: Self =
            serde_json::from_reader(file).map_err(|_| TrustError::InvalidDatabase)?;
        if database.v != TRUST_DATABASE_VERSION {
            return Err(TrustError::UnsupportedVersion);
        }
        for root in &database.trusted_roots {
            AbsolutePath::new(platform, root.path().as_str())
                .map_err(|_| TrustError::InvalidDatabase)?;
        }
        TrustProjection::new(database.trusted_roots.clone())
            .map_err(|_| TrustError::InvalidDatabase)?;
        Ok(database)
    }

    fn trust(&mut self, path: AbsolutePath) -> Result<&TrustedRoot, TrustError> {
        if let Some(index) = self
            .trusted_roots
            .iter()
            .position(|root| root.path() == &path)
        {
            return Ok(&self.trusted_roots[index]);
        }
        let identity = TrustedRootId::new(format!("root:{}", path.as_str()))
            .map_err(|_| TrustError::InvalidPath)?;
        self.trusted_roots
            .push(TrustedRoot::new(identity.clone(), path));
        self.trusted_roots
            .sort_by(|left, right| left.identity().cmp(right.identity()));
        let index = self
            .trusted_roots
            .iter()
            .position(|root| root.identity() == &identity)
            .expect("the inserted trusted root remains present");
        Ok(&self.trusted_roots[index])
    }

    fn untrust(&mut self, path: &AbsolutePath) -> Result<TrustedRootId, TrustError> {
        let index = self
            .trusted_roots
            .iter()
            .position(|root| root.path() == path)
            .ok_or(TrustError::RootNotFound)?;
        Ok(self.trusted_roots.remove(index).identity().clone())
    }

    pub fn projection(&self) -> Result<TrustProjection, TrustError> {
        TrustProjection::new(self.trusted_roots.clone()).map_err(|_| TrustError::InvalidDatabase)
    }

    fn save(&self, path: &Path) -> Result<(), TrustError> {
        let parent = path.parent().ok_or(TrustError::InvalidPath)?;
        std::fs::create_dir_all(parent).map_err(|_| TrustError::Io)?;
        let mut temporary = tempfile::NamedTempFile::new_in(parent).map_err(|_| TrustError::Io)?;
        serde_json::to_writer(&mut temporary, self).map_err(|_| TrustError::Io)?;
        temporary.write_all(b"\n").map_err(|_| TrustError::Io)?;
        temporary.as_file().sync_all().map_err(|_| TrustError::Io)?;
        temporary.persist(path).map_err(|_| TrustError::Io)?;
        sync_parent(parent)?;
        Ok(())
    }
}

pub fn record_trusted_root(
    path: &Path,
    platform: Platform,
    root: AbsolutePath,
) -> Result<(), TrustError> {
    let parent = path.parent().ok_or(TrustError::InvalidPath)?;
    std::fs::create_dir_all(parent).map_err(|_| TrustError::Io)?;
    let lock_path = path.with_extension("lock");
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(lock_path)
        .map_err(|_| TrustError::Io)?;
    lock.lock().map_err(|_| TrustError::Io)?;

    let mut database = TrustDatabase::load(path, platform)?;
    database.trust(root)?;
    database.save(path)
}

pub fn record_project_activation(
    trust_path: &Path,
    activation_path: &Path,
    platform: Platform,
    projection: ActivationProjection,
    actor: String,
    activated_unix_ms: u64,
) -> Result<(), TrustError> {
    let parent = trust_path.parent().ok_or(TrustError::InvalidPath)?;
    std::fs::create_dir_all(parent).map_err(|_| TrustError::Io)?;
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(trust_path.with_extension("lock"))
        .map_err(|_| TrustError::Io)?;
    lock.lock().map_err(|_| TrustError::Io)?;

    let database = TrustDatabase::load(trust_path, platform)?;
    let trusted_root = projection
        .identity()
        .trusted_root()
        .ok_or(TrustError::InvalidPath)?;
    if !database
        .trusted_roots
        .iter()
        .any(|root| root.identity() == trusted_root)
    {
        return Err(TrustError::RootNotFound);
    }
    crate::activation::record_activation(activation_path, projection, actor, activated_unix_ms)
        .map_err(|_| TrustError::Activation)
}

pub fn revoke_trusted_root(
    trust_path: &Path,
    activation_path: &Path,
    platform: Platform,
    root: &AbsolutePath,
) -> Result<usize, TrustError> {
    let parent = trust_path.parent().ok_or(TrustError::InvalidPath)?;
    std::fs::create_dir_all(parent).map_err(|_| TrustError::Io)?;
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(trust_path.with_extension("lock"))
        .map_err(|_| TrustError::Io)?;
    lock.lock().map_err(|_| TrustError::Io)?;

    let mut database = TrustDatabase::load(trust_path, platform)?;
    let identity = database.untrust(root)?;
    let removed = crate::activation::remove_project_activations(activation_path, &identity)
        .map_err(|_| TrustError::Activation)?;
    database.save(trust_path)?;
    Ok(removed)
}

pub fn trust_database_path(home: &AbsolutePath, platform: Platform) -> PathBuf {
    let separator = if platform == Platform::Windows {
        '\\'
    } else {
        '/'
    };
    PathBuf::from(format!(
        "{}{separator}.nah{separator}trust.json",
        home.as_str().trim_end_matches(['/', '\\'])
    ))
}

#[cfg(unix)]
fn sync_parent(parent: &Path) -> Result<(), TrustError> {
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| TrustError::Io)
}

#[cfg(not(unix))]
fn sync_parent(_parent: &Path) -> Result<(), TrustError> {
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustError {
    Activation,
    InvalidDatabase,
    InvalidPath,
    Io,
    RootNotFound,
    UnsupportedVersion,
}

impl TrustError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Activation => "trust-activation-update-failed",
            Self::InvalidDatabase => "invalid-trust-database",
            Self::InvalidPath => "invalid-path",
            Self::Io => "trust-io-failed",
            Self::RootNotFound => "trusted-root-not-found",
            Self::UnsupportedVersion => "unsupported-trust-version",
        }
    }
}

impl fmt::Display for TrustError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Error for TrustError {}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};

    use super::*;

    #[test]
    fn trust_database_round_trips_and_is_idempotent() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("trust.json");
        let root = AbsolutePath::new(Platform::Linux, "/repo").unwrap();
        let mut database = TrustDatabase::empty();
        let first = database.trust(root.clone()).unwrap().identity().clone();
        let second = database.trust(root).unwrap().identity().clone();
        assert_eq!(first, second);
        database.save(&path).unwrap();
        database
            .trust(AbsolutePath::new(Platform::Linux, "/other").unwrap())
            .unwrap();
        database.save(&path).unwrap();

        let loaded = TrustDatabase::load(&path, Platform::Linux).unwrap();
        assert_eq!(loaded, database);
        assert_eq!(loaded.projection().unwrap().trusted_roots().len(), 2);
    }

    #[test]
    fn concurrent_trust_updates_are_serialized() {
        const ROOTS: usize = 12;

        let temp = tempfile::tempdir().unwrap();
        let path = Arc::new(temp.path().join("trust.json"));
        let barrier = Arc::new(Barrier::new(ROOTS));
        let workers = (0..ROOTS)
            .map(|index| {
                let path = Arc::clone(&path);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    let root =
                        AbsolutePath::new(Platform::Linux, format!("/repo-{index}")).unwrap();
                    barrier.wait();
                    record_trusted_root(&path, Platform::Linux, root).unwrap();
                })
            })
            .collect::<Vec<_>>();
        for worker in workers {
            worker.join().unwrap();
        }

        let database = TrustDatabase::load(&path, Platform::Linux).unwrap();
        assert_eq!(database.projection().unwrap().trusted_roots().len(), ROOTS);
    }

    #[test]
    fn malformed_or_future_trust_state_fails_closed() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("trust.json");
        std::fs::write(&path, r#"{"v":2,"trusted_roots":[]}"#).unwrap();
        assert_eq!(
            TrustDatabase::load(&path, Platform::Linux).unwrap_err(),
            TrustError::UnsupportedVersion
        );
        std::fs::write(&path, r#"{"v":1,"trusted_roots":"wrong"}"#).unwrap();
        assert_eq!(
            TrustDatabase::load(&path, Platform::Linux).unwrap_err(),
            TrustError::InvalidDatabase
        );
    }
}
