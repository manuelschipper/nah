//! Persists byte-pinned extension activations; it does not discover or execute bundles.

use std::error::Error;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use nah_proto::ctx::{
    AbsolutePath, ActivationProjection, GuardIdentity, GuardScope, Platform, TrustedRootId,
};
use serde::{Deserialize, Serialize};

const ACTIVATION_DATABASE_VERSION: u32 = 1;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationRecord {
    projection: ActivationProjection,
    actor: String,
    activated_unix_ms: u64,
}

impl ActivationRecord {
    pub fn projection(&self) -> &ActivationProjection {
        &self.projection
    }

    pub fn actor(&self) -> &str {
        &self.actor
    }

    pub const fn activated_unix_ms(&self) -> u64 {
        self.activated_unix_ms
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationDatabase {
    v: u32,
    records: Vec<ActivationRecord>,
}

impl ActivationDatabase {
    pub fn empty() -> Self {
        Self {
            v: ACTIVATION_DATABASE_VERSION,
            records: vec![],
        }
    }

    pub fn load(path: &Path) -> Result<Self, ActivationError> {
        let file = match File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::empty());
            }
            Err(_) => return Err(ActivationError::Io),
        };
        let database: Self =
            serde_json::from_reader(file).map_err(|_| ActivationError::InvalidDatabase)?;
        if database.v != ACTIVATION_DATABASE_VERSION {
            return Err(ActivationError::UnsupportedVersion);
        }
        if database
            .records
            .iter()
            .any(|record| !valid_actor(&record.actor))
            || database
                .records
                .windows(2)
                .any(|pair| pair[0].projection.identity() >= pair[1].projection.identity())
        {
            return Err(ActivationError::InvalidDatabase);
        }
        Ok(database)
    }

    pub fn records(&self) -> &[ActivationRecord] {
        &self.records
    }

    fn activate(
        &mut self,
        projection: ActivationProjection,
        actor: String,
        activated_unix_ms: u64,
    ) -> Result<(), ActivationError> {
        if !valid_actor(&actor) {
            return Err(ActivationError::InvalidActor);
        }
        self.records
            .retain(|record| record.projection.identity() != projection.identity());
        self.records.push(ActivationRecord {
            projection,
            actor,
            activated_unix_ms,
        });
        self.records
            .sort_by(|left, right| left.projection.identity().cmp(right.projection.identity()));
        Ok(())
    }

    fn deactivate_identity(&mut self, identity: &GuardIdentity) -> Result<(), ActivationError> {
        let before = self.records.len();
        self.records
            .retain(|record| record.projection.identity() != identity);
        if self.records.len() == before {
            return Err(ActivationError::GuardNotFound);
        }
        Ok(())
    }

    fn deactivate_project_root(&mut self, trusted_root: &TrustedRootId) -> usize {
        let before = self.records.len();
        self.records.retain(|record| {
            let identity = record.projection.identity();
            identity.scope() != GuardScope::Project || identity.trusted_root() != Some(trusted_root)
        });
        before - self.records.len()
    }

    fn save(&self, path: &Path) -> Result<(), ActivationError> {
        let parent = path.parent().ok_or(ActivationError::InvalidPath)?;
        std::fs::create_dir_all(parent).map_err(|_| ActivationError::Io)?;
        let mut temporary =
            tempfile::NamedTempFile::new_in(parent).map_err(|_| ActivationError::Io)?;
        serde_json::to_writer(&mut temporary, self).map_err(|_| ActivationError::Io)?;
        temporary
            .write_all(b"\n")
            .map_err(|_| ActivationError::Io)?;
        temporary
            .as_file()
            .sync_all()
            .map_err(|_| ActivationError::Io)?;
        temporary.persist(path).map_err(|_| ActivationError::Io)?;
        sync_parent(parent)
    }
}

fn valid_actor(actor: &str) -> bool {
    !actor.is_empty()
        && actor.len() <= 128
        && !actor.chars().any(|character| character.is_control())
}

pub fn record_activation(
    path: &Path,
    projection: ActivationProjection,
    actor: String,
    activated_unix_ms: u64,
) -> Result<(), ActivationError> {
    let parent = path.parent().ok_or(ActivationError::InvalidPath)?;
    std::fs::create_dir_all(parent).map_err(|_| ActivationError::Io)?;
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path.with_extension("lock"))
        .map_err(|_| ActivationError::Io)?;
    lock.lock().map_err(|_| ActivationError::Io)?;
    let mut database = ActivationDatabase::load(path)?;
    database.activate(projection, actor, activated_unix_ms)?;
    database.save(path)
}

pub fn remove_activation_by_identity(
    path: &Path,
    identity: &GuardIdentity,
) -> Result<(), ActivationError> {
    let parent = path.parent().ok_or(ActivationError::InvalidPath)?;
    std::fs::create_dir_all(parent).map_err(|_| ActivationError::Io)?;
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path.with_extension("lock"))
        .map_err(|_| ActivationError::Io)?;
    lock.lock().map_err(|_| ActivationError::Io)?;
    let mut database = ActivationDatabase::load(path)?;
    database.deactivate_identity(identity)?;
    database.save(path)
}

pub(crate) fn remove_project_activations(
    path: &Path,
    trusted_root: &TrustedRootId,
) -> Result<usize, ActivationError> {
    let parent = path.parent().ok_or(ActivationError::InvalidPath)?;
    std::fs::create_dir_all(parent).map_err(|_| ActivationError::Io)?;
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path.with_extension("lock"))
        .map_err(|_| ActivationError::Io)?;
    lock.lock().map_err(|_| ActivationError::Io)?;
    let mut database = ActivationDatabase::load(path)?;
    let removed = database.deactivate_project_root(trusted_root);
    database.save(path)?;
    Ok(removed)
}

pub fn activation_database_path(home: &AbsolutePath, platform: Platform) -> PathBuf {
    let separator = if platform == Platform::Windows {
        '\\'
    } else {
        '/'
    };
    PathBuf::from(format!(
        "{}{separator}.nah{separator}activations.json",
        home.as_str().trim_end_matches(['/', '\\'])
    ))
}

#[cfg(unix)]
fn sync_parent(parent: &Path) -> Result<(), ActivationError> {
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| ActivationError::Io)
}

#[cfg(not(unix))]
fn sync_parent(_parent: &Path) -> Result<(), ActivationError> {
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActivationError {
    InvalidActor,
    InvalidDatabase,
    InvalidPath,
    Io,
    GuardNotFound,
    UnsupportedVersion,
}

impl ActivationError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidActor => "invalid-activation-actor",
            Self::InvalidDatabase => "invalid-activation-database",
            Self::InvalidPath => "invalid-path",
            Self::Io => "activation-io-failed",
            Self::GuardNotFound => "policy-not-found",
            Self::UnsupportedVersion => "unsupported-activation-version",
        }
    }
}

impl fmt::Display for ActivationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Error for ActivationError {}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};

    use nah_proto::ctx::{ContentHash, ExecProtocolVersion, GuardIdentity};

    use super::*;

    fn projection(name: &str, hash: char) -> ActivationProjection {
        ActivationProjection::new(
            GuardIdentity::user(name).unwrap(),
            ContentHash::new(hash.to_string().repeat(64)).unwrap(),
            ExecProtocolVersion::V1,
            vec!["tool".into()],
        )
        .unwrap()
    }

    fn project_projection(root: &str, name: &str, hash: char) -> ActivationProjection {
        ActivationProjection::new(
            GuardIdentity::project(TrustedRootId::new(root).unwrap(), name).unwrap(),
            ContentHash::new(hash.to_string().repeat(64)).unwrap(),
            ExecProtocolVersion::V1,
            vec!["tool".into()],
        )
        .unwrap()
    }

    #[test]
    fn activation_round_trips_exact_projection_and_audit_metadata() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("activations.json");
        record_activation(&path, projection("one", 'a'), "alice".into(), 42).unwrap();
        let database = ActivationDatabase::load(&path).unwrap();
        assert_eq!(database.records().len(), 1);
        assert_eq!(database.records()[0].actor(), "alice");
        assert_eq!(database.records()[0].activated_unix_ms(), 42);
        assert_eq!(
            database.records()[0].projection().bundle_hash().as_str(),
            "a".repeat(64)
        );
    }

    #[test]
    fn reactivation_replaces_the_same_structural_identity() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("activations.json");
        record_activation(&path, projection("one", 'a'), "alice".into(), 1).unwrap();
        record_activation(&path, projection("one", 'b'), "bob".into(), 2).unwrap();
        let database = ActivationDatabase::load(&path).unwrap();
        assert_eq!(database.records().len(), 1);
        assert_eq!(database.records()[0].actor(), "bob");
        assert_eq!(
            database.records()[0].projection().bundle_hash().as_str(),
            "b".repeat(64)
        );
    }

    #[test]
    fn identity_deactivation_preserves_same_named_other_scope() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("activations.json");
        let user = projection("one", 'a');
        let project = project_projection("root:one", "one", 'b');
        record_activation(&path, user.clone(), "alice".into(), 1).unwrap();
        record_activation(&path, project.clone(), "alice".into(), 2).unwrap();

        remove_activation_by_identity(&path, user.identity()).unwrap();

        let database = ActivationDatabase::load(&path).unwrap();
        assert_eq!(database.records().len(), 1);
        assert_eq!(database.records()[0].projection(), &project);
    }

    #[test]
    fn project_revocation_preserves_other_roots_and_user_guards() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("activations.json");
        record_activation(&path, projection("user", 'a'), "alice".into(), 1).unwrap();
        record_activation(
            &path,
            project_projection("root:one", "one", 'b'),
            "alice".into(),
            2,
        )
        .unwrap();
        record_activation(
            &path,
            project_projection("root:two", "two", 'c'),
            "alice".into(),
            3,
        )
        .unwrap();

        let removed =
            remove_project_activations(&path, &TrustedRootId::new("root:one").unwrap()).unwrap();
        assert_eq!(removed, 1);
        let database = ActivationDatabase::load(&path).unwrap();
        let mut names = database
            .records()
            .iter()
            .map(|record| record.projection().identity().name())
            .collect::<Vec<_>>();
        names.sort_unstable();
        assert_eq!(names, ["two", "user"]);
    }

    #[test]
    fn concurrent_activations_do_not_lose_updates() {
        const COUNT: usize = 10;

        let temp = tempfile::tempdir().unwrap();
        let path = Arc::new(temp.path().join("activations.json"));
        let barrier = Arc::new(Barrier::new(COUNT));
        let workers = (0..COUNT)
            .map(|index| {
                let path = Arc::clone(&path);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    record_activation(
                        &path,
                        projection(&format!("extension-{index}"), 'a'),
                        "tester".into(),
                        index as u64,
                    )
                    .unwrap();
                })
            })
            .collect::<Vec<_>>();
        for worker in workers {
            worker.join().unwrap();
        }
        assert_eq!(
            ActivationDatabase::load(&path).unwrap().records().len(),
            COUNT
        );
    }

    #[test]
    fn malformed_and_future_state_fail_closed() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("activations.json");
        std::fs::write(&path, r#"{"v":2,"records":[]}"#).unwrap();
        assert_eq!(
            ActivationDatabase::load(&path).unwrap_err(),
            ActivationError::UnsupportedVersion
        );
        std::fs::write(&path, r#"{"v":1,"records":"wrong"}"#).unwrap();
        assert_eq!(
            ActivationDatabase::load(&path).unwrap_err(),
            ActivationError::InvalidDatabase
        );
    }
}
