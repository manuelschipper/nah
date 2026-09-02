//! Persists global enablement for shipped guards.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use nah_proto::ctx::{AbsolutePath, Platform};
use serde::{Deserialize, Serialize};

use crate::catalog::resolve_shipped_guard_from;

const VERSION: u32 = 2;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ShippedState {
    overrides: BTreeMap<String, bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ShippedStateV1 {
    v: u32,
    disabled: Vec<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ShippedStateV2 {
    v: u32,
    overrides: BTreeMap<String, bool>,
}

impl ShippedState {
    /// What a fresh install runs on: every shipped guard at its own default.
    pub(crate) fn defaults() -> Self {
        Self {
            overrides: BTreeMap::new(),
        }
    }

    /// Validates raw state before returning canonical overrides and sorted diagnostics.
    pub(crate) fn load(
        path: &Path,
        defaults: &[(&str, bool)],
        aliases: &[(&str, &str)],
    ) -> Result<(Self, Vec<String>), ShippedStateError> {
        let mut file = match File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok((Self::defaults(), vec![]));
            }
            Err(_) => return Err(ShippedStateError::Io),
        };
        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .map_err(|_| ShippedStateError::InvalidState)?;
        let value: serde_json::Value =
            serde_json::from_str(&contents).map_err(|_| ShippedStateError::InvalidState)?;
        let version = value
            .get("v")
            .and_then(serde_json::Value::as_u64)
            .ok_or(ShippedStateError::InvalidState)?;
        match version {
            1 => {
                let state: ShippedStateV1 =
                    serde_json::from_value(value).map_err(|_| ShippedStateError::InvalidState)?;
                if state.v != 1 || state.disabled.windows(2).any(|pair| pair[0] >= pair[1]) {
                    return Err(ShippedStateError::InvalidState);
                }
                canonicalize_overrides(
                    state.disabled.into_iter().map(|name| (name, false)),
                    defaults,
                    aliases,
                )
            }
            version if version == u64::from(VERSION) => {
                let state: ShippedStateV2 =
                    serde_json::from_value(value).map_err(|_| ShippedStateError::InvalidState)?;
                if state.v != VERSION
                    || serde_json::to_string(&state)
                        .map(|canonical| contents != format!("{canonical}\n"))
                        .unwrap_or(true)
                {
                    return Err(ShippedStateError::InvalidState);
                }
                canonicalize_overrides(state.overrides, defaults, aliases)
            }
            _ => Err(ShippedStateError::UnsupportedVersion),
        }
    }

    pub(crate) fn is_enabled(&self, name: &str, default_enabled: bool) -> bool {
        self.overrides.get(name).copied().unwrap_or(default_enabled)
    }

    pub(crate) fn is_explicitly_disabled(&self, name: &str) -> bool {
        self.overrides.get(name) == Some(&false)
    }

    pub(crate) fn operator_override(&self, name: &str) -> Option<bool> {
        self.overrides.get(name).copied()
    }

    fn set_enabled(&mut self, name: &str, enabled: bool, default_enabled: bool) {
        if enabled && default_enabled {
            self.overrides.remove(name);
        } else {
            self.overrides.insert(name.to_owned(), enabled);
        }
    }

    fn reset(&mut self, name: &str) {
        self.overrides.remove(name);
    }

    fn save(&self, path: &Path) -> Result<(), ShippedStateError> {
        let parent = path.parent().ok_or(ShippedStateError::InvalidPath)?;
        std::fs::create_dir_all(parent).map_err(|_| ShippedStateError::Io)?;
        let mut temporary =
            tempfile::NamedTempFile::new_in(parent).map_err(|_| ShippedStateError::Io)?;
        protect_file(temporary.as_file())?;
        serde_json::to_writer(
            &mut temporary,
            &ShippedStateV2 {
                v: VERSION,
                overrides: self.overrides.clone(),
            },
        )
        .map_err(|_| ShippedStateError::Io)?;
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
    defaults: &[(&str, bool)],
    aliases: &[(&str, &str)],
    name: &str,
    enabled: bool,
) -> Result<Vec<String>, ShippedStateError> {
    let default_enabled = factory_default(defaults, name).ok_or(ShippedStateError::UnknownGuard)?;
    mutate(path, defaults, aliases, |state| {
        state.set_enabled(name, enabled, default_enabled)
    })
}

pub(crate) fn reset(
    path: &Path,
    defaults: &[(&str, bool)],
    aliases: &[(&str, &str)],
    name: &str,
) -> Result<Vec<String>, ShippedStateError> {
    factory_default(defaults, name).ok_or(ShippedStateError::UnknownGuard)?;
    mutate(path, defaults, aliases, |state| state.reset(name))
}

fn mutate(
    path: &Path,
    defaults: &[(&str, bool)],
    aliases: &[(&str, &str)],
    update: impl FnOnce(&mut ShippedState),
) -> Result<Vec<String>, ShippedStateError> {
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
    let (mut state, diagnostics) = ShippedState::load(path, defaults, aliases)?;
    update(&mut state);
    state.save(path)?;
    Ok(diagnostics)
}

#[derive(Default)]
struct CanonicalCandidates {
    canonical: Option<bool>,
    aliases: Vec<(String, bool)>,
}

fn canonicalize_overrides(
    overrides: impl IntoIterator<Item = (String, bool)>,
    defaults: &[(&str, bool)],
    aliases: &[(&str, &str)],
) -> Result<(ShippedState, Vec<String>), ShippedStateError> {
    let canonical_names = defaults.iter().map(|(name, _)| *name).collect::<Vec<_>>();
    let mut candidates = BTreeMap::<String, CanonicalCandidates>::new();
    let mut diagnostics = Vec::new();
    for (name, enabled) in overrides {
        match resolve_shipped_guard_from(&canonical_names, aliases, &name) {
            Some(resolved) if resolved.renamed => {
                candidates
                    .entry(resolved.canonical_name.to_owned())
                    .or_default()
                    .aliases
                    .push((name, enabled));
            }
            Some(resolved) => {
                candidates
                    .entry(resolved.canonical_name.to_owned())
                    .or_default()
                    .canonical = Some(enabled);
            }
            None => diagnostics.push(format!("unknown built-in guard `{name}` was ignored")),
        }
    }

    let mut canonical = BTreeMap::new();
    for (name, candidate) in candidates {
        let enabled = if let Some(enabled) = candidate.canonical {
            for (alias, _) in candidate.aliases {
                diagnostics.push(format!(
                    "saved setting for renamed built-in guard `{alias}` was ignored because `{name}` is also set"
                ));
            }
            enabled
        } else {
            let Some(enabled) = candidate.aliases.first().map(|(_, enabled)| *enabled) else {
                continue;
            };
            if candidate
                .aliases
                .iter()
                .any(|(_, candidate_enabled)| *candidate_enabled != enabled)
            {
                return Err(ShippedStateError::InvalidState);
            }
            for (alias, _) in candidate.aliases {
                diagnostics.push(format!("built-in guard `{alias}` was renamed to `{name}`"));
            }
            enabled
        };
        let default = factory_default(defaults, &name).ok_or(ShippedStateError::InvalidState)?;
        if default && enabled {
            return Err(ShippedStateError::InvalidState);
        }
        canonical.insert(name, enabled);
    }
    diagnostics.sort();
    Ok((
        ShippedState {
            overrides: canonical,
        },
        diagnostics,
    ))
}

fn factory_default(defaults: &[(&str, bool)], name: &str) -> Option<bool> {
    defaults
        .iter()
        .find_map(|(known, enabled)| (*known == name).then_some(*enabled))
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
        let defaults = [
            ("exec-decoded", true),
            ("exec-obfuscated", true),
            ("exec-remote", true),
            ("secrets-exfil", true),
        ];
        let temp = tempfile::tempdir().unwrap();
        let path = Arc::new(temp.path().join("built-ins.json"));
        let barrier = Arc::new(Barrier::new(defaults.len()));
        let workers = defaults
            .iter()
            .map(|(name, _)| *name)
            .map(|name| {
                let path = Arc::clone(&path);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    set_enabled(&path, &defaults, &[], name, false).unwrap();
                })
            })
            .collect::<Vec<_>>();
        for worker in workers {
            worker.join().unwrap();
        }
        let (state, diagnostics) = ShippedState::load(&path, &defaults, &[]).unwrap();
        assert!(diagnostics.is_empty());
        assert!(
            defaults
                .iter()
                .all(|(name, default)| !state.is_enabled(name, *default))
        );
    }

    #[test]
    fn malformed_and_future_state_fail_while_unknown_names_are_diagnostic() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("built-ins.json");
        let defaults = [
            ("fs-shell-profile", false),
            ("fs-startup-persistence", true),
            ("fs-system-tree", true),
        ];
        std::fs::write(&path, r#"{"v":3,"overrides":{}}"#).unwrap();
        assert_eq!(
            ShippedState::load(&path, &defaults, &[]).unwrap_err(),
            ShippedStateError::UnsupportedVersion
        );
        std::fs::write(&path, r#"{"v":1,"disabled":["unknown"]}"#).unwrap();
        assert_eq!(
            ShippedState::load(&path, &defaults, &[]).unwrap().1,
            ["unknown built-in guard `unknown` was ignored"]
        );
        std::fs::write(
            &path,
            "{\"v\":2,\"overrides\":{\"fs-startup-persistence\":true}}\n",
        )
        .unwrap();
        assert_eq!(
            ShippedState::load(&path, &defaults, &[]).unwrap_err(),
            ShippedStateError::InvalidState
        );
        std::fs::write(
            &path,
            r#"{"v":1,"disabled":[],"enabled":["fs-system-tree"]}"#,
        )
        .unwrap();
        assert_eq!(
            ShippedState::load(&path, &defaults, &[]).unwrap_err(),
            ShippedStateError::InvalidState
        );
        std::fs::write(&path, r#"{"v":2,"overrides":{"fs-system-tree":true}}"#).unwrap();
        assert_eq!(
            ShippedState::load(&path, &defaults, &[]).unwrap_err(),
            ShippedStateError::InvalidState
        );
    }

    #[test]
    fn mixed_defaults_store_operator_choices_and_reset_removes_them() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("built-ins.json");
        let defaults = [
            ("fs-shell-profile", false),
            ("fs-startup-persistence", true),
            ("fs-system-tree", true),
        ];

        let (state, diagnostics) = ShippedState::load(&path, &defaults, &[]).unwrap();
        assert!(diagnostics.is_empty());
        assert!(state.is_enabled("fs-system-tree", true));
        assert!(state.is_enabled("fs-startup-persistence", true));
        assert!(!state.is_enabled("fs-shell-profile", false));

        set_enabled(&path, &defaults, &[], "fs-shell-profile", true).unwrap();
        set_enabled(&path, &defaults, &[], "fs-startup-persistence", false).unwrap();
        set_enabled(&path, &defaults, &[], "fs-system-tree", false).unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "{\"v\":2,\"overrides\":{\"fs-shell-profile\":true,\"fs-startup-persistence\":false,\"fs-system-tree\":false}}\n"
        );
        let (state, diagnostics) = ShippedState::load(&path, &defaults, &[]).unwrap();
        assert!(diagnostics.is_empty());
        assert!(state.is_enabled("fs-shell-profile", false));
        assert!(!state.is_enabled("fs-startup-persistence", true));
        assert!(!state.is_enabled("fs-system-tree", true));
        assert!(state.is_explicitly_disabled("fs-startup-persistence"));
        assert!(state.is_explicitly_disabled("fs-system-tree"));

        set_enabled(&path, &defaults, &[], "fs-startup-persistence", true).unwrap();
        reset(&path, &defaults, &[], "fs-shell-profile").unwrap();
        reset(&path, &defaults, &[], "fs-system-tree").unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "{\"v\":2,\"overrides\":{}}\n"
        );
    }

    #[test]
    fn explicitly_disabling_a_default_off_guard_is_a_project_veto() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("built-ins.json");
        let defaults = [("fs-shell-profile", false)];

        set_enabled(&path, &defaults, &[], "fs-shell-profile", false).unwrap();

        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "{\"v\":2,\"overrides\":{\"fs-shell-profile\":false}}\n"
        );
        let (state, diagnostics) = ShippedState::load(&path, &defaults, &[]).unwrap();
        assert!(diagnostics.is_empty());
        assert!(state.is_explicitly_disabled("fs-shell-profile"));
    }

    #[test]
    fn v1_choices_survive_without_rewriting_until_the_next_mutation() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("built-ins.json");
        let defaults = [
            ("fs-shell-profile", false),
            ("fs-startup-persistence", true),
            ("git-clean-force", true),
            ("git-hard-reset", true),
        ];
        std::fs::write(&path, r#"{"v":1,"disabled":["git-hard-reset"]}"#).unwrap();

        let (state, diagnostics) = ShippedState::load(&path, &defaults, &[]).unwrap();
        assert!(diagnostics.is_empty());
        assert!(state.is_enabled("git-clean-force", true));
        assert!(!state.is_enabled("git-hard-reset", true));
        assert!(!state.is_enabled("fs-shell-profile", false));
        assert!(state.is_enabled("fs-startup-persistence", true));
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            r#"{"v":1,"disabled":["git-hard-reset"]}"#
        );

        set_enabled(&path, &defaults, &[], "fs-shell-profile", true).unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "{\"v\":2,\"overrides\":{\"fs-shell-profile\":true,\"git-hard-reset\":false}}\n"
        );
    }

    #[test]
    fn aliases_canonicalize_v1_and_v2_state_with_sorted_diagnostics() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("built-ins.json");
        let defaults = [("current", true), ("other", true)];
        let aliases = [("old-current", "current"), ("older-current", "current")];

        std::fs::write(&path, r#"{"v":1,"disabled":["old-current","other"]}"#).unwrap();
        let (state, diagnostics) = ShippedState::load(&path, &defaults, &aliases).unwrap();
        assert!(!state.is_enabled("current", true));
        assert!(!state.is_enabled("other", true));
        assert_eq!(diagnostics.len(), 1);

        std::fs::write(
            &path,
            "{\"v\":2,\"overrides\":{\"current\":false,\"old-current\":true,\"unknown\":false}}\n",
        )
        .unwrap();
        let (state, diagnostics) = ShippedState::load(&path, &defaults, &aliases).unwrap();
        assert!(!state.is_enabled("current", true));
        assert_eq!(state.overrides.len(), 1);
        assert_eq!(diagnostics.len(), 2);
        assert!(diagnostics.windows(2).all(|pair| pair[0] < pair[1]));

        std::fs::write(&path, r#"{"v":1,"disabled":["other","old-current"]}"#).unwrap();
        assert_eq!(
            ShippedState::load(&path, &defaults, &aliases).unwrap_err(),
            ShippedStateError::InvalidState
        );
        std::fs::write(
            &path,
            "{\"v\":2,\"overrides\":{\"older-current\":false,\"old-current\":false}}\n",
        )
        .unwrap();
        assert_eq!(
            ShippedState::load(&path, &defaults, &aliases).unwrap_err(),
            ShippedStateError::InvalidState
        );
    }

    #[test]
    fn historical_aliases_deduplicate_equal_values_and_reject_conflicts() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("built-ins.json");
        let defaults = [("current", true)];
        let aliases = [("old-current", "current"), ("older-current", "current")];

        std::fs::write(
            &path,
            "{\"v\":2,\"overrides\":{\"old-current\":false,\"older-current\":false}}\n",
        )
        .unwrap();
        let (state, diagnostics) = ShippedState::load(&path, &defaults, &aliases).unwrap();
        assert_eq!(state.overrides, BTreeMap::from([("current".into(), false)]));
        assert_eq!(diagnostics.len(), 2);

        std::fs::write(
            &path,
            "{\"v\":2,\"overrides\":{\"old-current\":false,\"older-current\":true}}\n",
        )
        .unwrap();
        assert_eq!(
            ShippedState::load(&path, &defaults, &aliases).unwrap_err(),
            ShippedStateError::InvalidState
        );
    }

    #[test]
    fn explicit_mutation_rewrites_aliases_and_drops_unknown_names() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("built-ins.json");
        let defaults = [("current", true), ("default-off", false)];
        let aliases = [("old-current", "current")];
        std::fs::write(
            &path,
            "{\"v\":2,\"overrides\":{\"old-current\":false,\"unknown\":false}}\n",
        )
        .unwrap();

        let diagnostics = set_enabled(&path, &defaults, &aliases, "default-off", true).unwrap();
        assert_eq!(diagnostics.len(), 2);
        let saved: ShippedStateV2 =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(
            saved.overrides,
            BTreeMap::from([("current".into(), false), ("default-off".into(), true)])
        );
    }
}
