//! Persists global enablement for shipped guards.

use std::error::Error;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use nah_proto::ctx::{AbsolutePath, Platform};
use serde::{Deserialize, Serialize};

const VERSION: u32 = 1;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ShippedState {
    v: u32,
    disabled: Vec<String>,
}

impl ShippedState {
    /// What a fresh install runs on: every shipped guard at its own default.
    pub(crate) fn defaults() -> Self {
        Self {
            v: VERSION,
            disabled: vec![],
        }
    }

    pub(crate) fn load(path: &Path, known: &[&str]) -> Result<Self, ShippedStateError> {
        let file = match File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::defaults());
            }
            Err(_) => return Err(ShippedStateError::Io),
        };
        let state: Self =
            serde_json::from_reader(file).map_err(|_| ShippedStateError::InvalidState)?;
        if state.v != VERSION {
            return Err(ShippedStateError::UnsupportedVersion);
        }
        if state.disabled.windows(2).any(|pair| pair[0] >= pair[1])
            || state
                .disabled
                .iter()
                .any(|name| !known.contains(&name.as_str()))
        {
            return Err(ShippedStateError::InvalidState);
        }
        Ok(state)
    }

    pub(crate) fn is_enabled(&self, name: &str) -> bool {
        !self.disabled.iter().any(|disabled| disabled == name)
    }

    fn set_enabled(&mut self, name: &str, enabled: bool) {
        self.disabled.retain(|disabled| disabled != name);
        if !enabled {
            self.disabled.push(name.to_owned());
            self.disabled.sort();
        }
    }

    fn save(&self, path: &Path) -> Result<(), ShippedStateError> {
        let parent = path.parent().ok_or(ShippedStateError::InvalidPath)?;
        std::fs::create_dir_all(parent).map_err(|_| ShippedStateError::Io)?;
        let mut temporary =
            tempfile::NamedTempFile::new_in(parent).map_err(|_| ShippedStateError::Io)?;
        protect_file(temporary.as_file())?;
        serde_json::to_writer(&mut temporary, self).map_err(|_| ShippedStateError::Io)?;
        temporary
            .write_all(b"\n")
            .map_err(|_| ShippedStateError::Io)?;
        temporary
            .as_file()
            .sync_all()
            .map_err(|_| ShippedStateError::Io)?;
        temporary.persist(path).map_err(|_| ShippedStateError::Io)?;
        sync_parent(parent)
    }
}

pub(crate) fn set_enabled(
    path: &Path,
    known: &[&str],
    name: &str,
    enabled: bool,
) -> Result<(), ShippedStateError> {
    if !known.contains(&name) {
        return Err(ShippedStateError::UnknownGuard);
    }
    let parent = path.parent().ok_or(ShippedStateError::InvalidPath)?;
    std::fs::create_dir_all(parent).map_err(|_| ShippedStateError::Io)?;
    let mut options = OpenOptions::new();
    options.create(true).truncate(false).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let lock = options
        .open(path.with_extension("lock"))
        .map_err(|_| ShippedStateError::Io)?;
    protect_file(&lock)?;
    lock.lock().map_err(|_| ShippedStateError::Io)?;
    let mut state = ShippedState::load(path, known)?;
    state.set_enabled(name, enabled);
    state.save(path)
}

pub(crate) fn state_path(home: &AbsolutePath, platform: Platform) -> PathBuf {
    let separator = if platform == Platform::Windows {
        '\\'
    } else {
        '/'
    };
    PathBuf::from(format!(
        "{}{separator}.nah{separator}built-ins.json",
        home.as_str().trim_end_matches(['/', '\\'])
    ))
}

#[cfg(unix)]
fn protect_file(file: &File) -> Result<(), ShippedStateError> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|_| ShippedStateError::Io)
}

#[cfg(not(unix))]
fn protect_file(_file: &File) -> Result<(), ShippedStateError> {
    Ok(())
}

#[cfg(unix)]
fn sync_parent(parent: &Path) -> Result<(), ShippedStateError> {
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| ShippedStateError::Io)
}

#[cfg(not(unix))]
fn sync_parent(_parent: &Path) -> Result<(), ShippedStateError> {
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ShippedStateError {
    InvalidPath,
    InvalidState,
    Io,
    UnknownGuard,
    UnsupportedVersion,
}

impl ShippedStateError {
    const fn code(self) -> &'static str {
        match self {
            Self::InvalidPath => "invalid-shipped-state-path",
            Self::InvalidState => "invalid-shipped-state",
            Self::Io => "shipped-state-io-failed",
            Self::UnknownGuard => "unknown-built-in-policy",
            Self::UnsupportedVersion => "unsupported-shipped-state-version",
        }
    }
}

impl fmt::Display for ShippedStateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Error for ShippedStateError {}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};

    use super::*;

    #[test]
    fn concurrent_mutations_preserve_each_disabled_guard() {
        let known = [
            "exec-decoded",
            "exec-obfuscated",
            "exec-remote",
            "exfil-pipe",
        ];
        let temp = tempfile::tempdir().unwrap();
        let path = Arc::new(temp.path().join("built-ins.json"));
        let barrier = Arc::new(Barrier::new(known.len()));
        let workers = known
            .iter()
            .copied()
            .map(|name| {
                let path = Arc::clone(&path);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    set_enabled(&path, &known, name, false).unwrap();
                })
            })
            .collect::<Vec<_>>();
        for worker in workers {
            worker.join().unwrap();
        }
        let state = ShippedState::load(&path, &known).unwrap();
        assert!(known.iter().all(|name| !state.is_enabled(name)));
    }

    #[test]
    fn malformed_unknown_and_future_state_fail_loudly() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("built-ins.json");
        std::fs::write(&path, r#"{"v":2,"disabled":[]}"#).unwrap();
        assert_eq!(
            ShippedState::load(&path, &["fs-root"]).unwrap_err(),
            ShippedStateError::UnsupportedVersion
        );
        std::fs::write(&path, r#"{"v":1,"disabled":["unknown"]}"#).unwrap();
        assert_eq!(
            ShippedState::load(&path, &["fs-root"]).unwrap_err(),
            ShippedStateError::InvalidState
        );
        std::fs::write(&path, r#"{"v":1,"disabled":[],"enabled":["fs-root"]}"#).unwrap();
        assert_eq!(
            ShippedState::load(&path, &["fs-root"]).unwrap_err(),
            ShippedStateError::InvalidState
        );
    }

    #[test]
    fn guards_default_on_and_can_be_disabled_then_restored() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("built-ins.json");
        let known = ["exec-remote", "fs-root"];

        let state = ShippedState::load(&path, &known).unwrap();
        assert!(state.is_enabled("fs-root"));
        assert!(state.is_enabled("exec-remote"));

        set_enabled(&path, &known, "exec-remote", false).unwrap();
        set_enabled(&path, &known, "fs-root", false).unwrap();
        let state = ShippedState::load(&path, &known).unwrap();
        assert!(!state.is_enabled("exec-remote"));
        assert!(!state.is_enabled("fs-root"));

        set_enabled(&path, &known, "exec-remote", true).unwrap();
        set_enabled(&path, &known, "fs-root", true).unwrap();
        let state = ShippedState::load(&path, &known).unwrap();
        assert!(state.is_enabled("exec-remote"));
        assert!(state.is_enabled("fs-root"));
    }
}
