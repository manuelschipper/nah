//! Live HOME-derived context construction.

use nah_proto::ctx::{AbsolutePath, Ctx, Guard, Platform};

use crate::catalog::{rule_ids, rules_of};
use crate::nap::{self, ActiveNap, NapMode};
use crate::shipped_state::{ShippedState, ShippedStateError, state_path};
use crate::state_protection::ensure_nah_state_directory;

pub(crate) struct LiveState {
    pub(crate) ctx: Ctx,
    pub(crate) nap: Option<ActiveNap>,
    pub(crate) shipped_state_error: Option<ShippedStateError>,
    pub(crate) warnings: Vec<String>,
    /// What the 1.x import asks the converting command to print. A decision
    /// records these from the pending file instead, so two first decisions
    /// cannot each record them.
    pub(crate) import_reports: Vec<String>,
    /// The warnings of settings `load` could not read and replaced with safe
    /// defaults.
    pub(crate) unread: Vec<String>,
}

/// Damaged state must never be treated better than absent state: guards keep
/// running on safe defaults, with state failures reported on each decision.
pub(crate) fn load() -> Result<LiveState, String> {
    let platform = host_platform();
    let home = home(platform)?;
    let mut warnings = Vec::new();
    let (import_error, import_reports) = match crate::legacy_import::import_once(&home, platform) {
        Ok(reports) => (None, reports),
        Err(error) => (Some(error), Vec::new()),
    };
    let nap = match nap::load(&home, platform) {
        Ok(nap) => nap,
        Err(error) => {
            warnings.push(format!("{error}; self-protection remains awake"));
            None
        }
    };
    // A guard nap removes exactly the named guards and rules before
    // evaluation; every other rule, self-protection, and the permanent layers
    // still run.
    let napped = match nap.as_ref().map(ActiveNap::mode) {
        Some(NapMode::Guards(names)) => names.as_slice(),
        _ => &[],
    };
    let mut diagnostics = Vec::new();
    let settings_path = state_path(&home, platform);
    let loaded = match import_error {
        None => ShippedState::load(&settings_path, rule_ids()),
        // Another Nah process holds the state, so the 1.x import waits for a
        // later call. This call still enforces the settings as they stand,
        // which no reader needs the lock for.
        Some(ShippedStateError::Contended) => {
            diagnostics.push(
                "~/.nah/built-ins.json: another Nah process holds it, so the nah 1.x import finishes on a later call".to_owned(),
            );
            ShippedState::load_deferring_import(&settings_path, rule_ids())
        }
        Some(error) => Err(error),
    };
    let (shipped_state, shipped_state_error) = match loaded {
        Ok((shipped_state, ignored)) => {
            diagnostics.extend(ignored);
            (shipped_state, None)
        }
        Err(error) => {
            let import = if import_error.is_some() {
                "; the nah 1.x configuration was not imported"
            } else {
                ""
            };
            warnings.push(format!(
                "~/.nah/built-ins.json: {error}{import}; shipped defaults apply"
            ));
            (ShippedState::defaults(), Some(error))
        }
    };
    // Every warning so far is a setting that could not be read. Unknown
    // rule names and import reports are notices.
    let unread = warnings.clone();
    warnings.extend(diagnostics);
    let mut settings = shipped_state.settings().clone();
    for name in napped {
        // A napped rule is paused, so its override cannot re-enable it.
        let napped_rules = match Guard::from_name(name) {
            Some(guard) => rules_of(guard).collect(),
            None => rule_ids()
                .iter()
                .copied()
                .filter(|rule| rule == name)
                .collect::<Vec<_>>(),
        };
        for rule in napped_rules {
            settings.pause(rule);
        }
    }
    let ctx = Ctx::new(platform, home, settings).map_err(|error| error.to_string())?;
    Ok(LiveState {
        ctx,
        nap,
        shipped_state_error,
        warnings,
        import_reports,
        unread,
    })
}

/// Every setting at its shipped default, with no nap,
/// under the filesystem root in place of a home: what save-then-run judges a
/// call by when `load` fails, only to find what it discards.
#[cfg(unix)]
pub(crate) fn defaults() -> LiveState {
    let platform = host_platform();
    let home = AbsolutePath::new(platform, "/").expect("the root is absolute");
    let ctx = Ctx::new(platform, home, ShippedState::defaults().settings().clone())
        .expect("the shipped defaults are a valid context");
    LiveState {
        ctx,
        nap: None,
        shipped_state_error: None,
        warnings: Vec::new(),
        import_reports: Vec::new(),
        unread: Vec::new(),
    }
}

/// Resolves and canonicalizes the configured home directory. On Windows, also
/// creates and protects the Nah state directory through
/// [`crate::state_protection::ensure_nah_state_directory`].
pub(crate) fn home(platform: Platform) -> Result<AbsolutePath, String> {
    let home = configured_home(platform, |name| std::env::var_os(name))?;
    let home =
        std::fs::canonicalize(home).map_err(|_| "home directory cannot be resolved".to_owned())?;
    // Unit tests run inside the developer's session: one that resolved their
    // real home would read their guard configuration and append to their
    // audit log. A test that reaches live state starts with
    // `reran_in_temporary_home`.
    #[cfg(test)]
    assert!(
        home.starts_with(std::fs::canonicalize(std::env::temp_dir()).unwrap()),
        "a unit test resolved a home outside the temporary directory; start it with `live_state::reran_in_temporary_home`"
    );
    let home = home
        .to_str()
        .ok_or_else(|| "home directory is not UTF-8".to_owned())?;
    let home = if platform == Platform::Windows {
        nah_observe::normalize_windows_observed_path(home)
    } else {
        home.to_owned()
    };
    let home = AbsolutePath::new(platform, home).map_err(|error| error.to_string())?;
    if platform == Platform::Windows {
        ensure_nah_state_directory(&home, platform)
            .map_err(|_| "nah-state-protection-failed".to_owned())?;
    }
    Ok(home)
}

/// The running nah executable's paths, as launched and with links resolved,
/// so a call that runs this same binary is recognized as nah wherever it is
/// installed.
pub(crate) fn nah_executable_paths(platform: Platform) -> Vec<AbsolutePath> {
    let Ok(executable) = std::env::current_exe() else {
        return Vec::new();
    };
    let canonical = std::fs::canonicalize(&executable).ok();
    [Some(executable), canonical]
        .into_iter()
        .flatten()
        .filter_map(|path| {
            let path = path.to_str()?;
            let path = if platform == Platform::Windows {
                nah_observe::normalize_windows_observed_path(path)
            } else {
                path.to_owned()
            };
            AbsolutePath::new(platform, path).ok()
        })
        .collect()
}

pub(crate) fn configured_home<F>(
    platform: Platform,
    mut get: F,
) -> Result<std::ffi::OsString, String>
where
    F: FnMut(&str) -> Option<std::ffi::OsString>,
{
    if platform == Platform::Windows {
        get("USERPROFILE").or_else(|| get("HOME"))
    } else {
        get("HOME")
    }
    .ok_or_else(|| "home directory is unavailable".to_owned())
}

/// Reruns the calling unit test in a child test process whose only home,
/// through `HOME` and `USERPROFILE`, is a temporary directory, the way the
/// integration tests run `nah`. Returns `true` in the parent once the child
/// passed, so the test returns at once, and `false` in the child, which runs
/// the test's body.
#[cfg(test)]
pub(crate) fn reran_in_temporary_home() -> bool {
    const CHILD: &str = "NAH_UNIT_TEST_TEMPORARY_HOME";
    if std::env::var_os(CHILD).is_some() {
        return false;
    }
    let current = std::thread::current();
    let test = current.name().expect("libtest names each test's thread");
    let home = tempfile::tempdir().unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([test, "--exact"])
        .env(CHILD, "1")
        .env("HOME", home.path())
        .env("USERPROFILE", home.path())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("1 passed"),
        "{test} failed in its temporary home:\n{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    true
}

pub(crate) const fn host_platform() -> Platform {
    if cfg!(target_os = "windows") {
        Platform::Windows
    } else if cfg!(target_os = "macos") {
        Platform::Macos
    } else {
        Platform::Linux
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};

    use super::*;

    /// Two first loads of one 1.x state file must leave the import notice
    /// where exactly one decision can record it. The loads themselves must
    /// not carry the notice: the pending file is the only channel, and a
    /// failed audit puts the lines back for the next decision.
    #[test]
    fn concurrent_first_loads_leave_the_import_notice_for_one_decision() {
        if reran_in_temporary_home() {
            return;
        }
        let home = std::env::var("HOME").unwrap();
        let directory = std::path::Path::new(&home).join(".nah");
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(
            directory.join("built-ins.json"),
            "{\"v\":2,\"overrides\":{\"git-hard-reset\":false}}\n",
        )
        .unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let workers = (0..2)
            .map(|_| {
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    load().unwrap()
                })
            })
            .collect::<Vec<_>>();
        let states = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>();
        for state in &states {
            assert!(
                !state
                    .warnings
                    .iter()
                    .any(|warning| { warning.contains("imported the nah 1.x configuration") }),
                "{:?}",
                state.warnings
            );
            assert!(
                state.import_reports.is_empty()
                    || state
                        .import_reports
                        .iter()
                        .any(|report| report.contains("imported the nah 1.x configuration")),
                "{:?}",
                state.import_reports
            );
        }
        let path = crate::shipped_state::state_path(states[0].ctx.home(), states[0].ctx.platform());
        let first = crate::shipped_state::take_pending_reports(&path);
        let second = crate::shipped_state::take_pending_reports(&path);
        assert!(
            first
                .iter()
                .any(|line| line.contains("imported the nah 1.x configuration")),
            "{first:?}"
        );
        assert!(second.is_empty(), "{second:?}");
        crate::shipped_state::restore_pending_reports(&path, &first);
        assert_eq!(crate::shipped_state::take_pending_reports(&path), first);
        // Reports restored while another process holds the state still reach
        // a later decision.
        let held = std::fs::File::open(path.with_extension("lock")).unwrap();
        held.lock().unwrap();
        crate::shipped_state::restore_pending_reports(&path, &first);
        // A file Nah did not write under a pending report's name is not one.
        let lookalike = path.with_file_name("1x-import-pending-backup.txt");
        std::fs::write(&lookalike, "not a report\n").unwrap();
        assert_eq!(crate::shipped_state::take_pending_reports(&path), first);
        assert!(lookalike.is_file());
    }

    #[test]
    fn windows_home_prefers_userprofile_and_falls_back_to_home() {
        let selected = configured_home(Platform::Windows, |name| match name {
            "USERPROFILE" => Some(r"C:\Users\test".into()),
            "HOME" => Some(r"C:\fallback".into()),
            _ => None,
        })
        .unwrap();
        assert_eq!(selected, std::ffi::OsString::from(r"C:\Users\test"));

        let fallback = configured_home(Platform::Windows, |name| {
            (name == "HOME").then(|| r"C:\fallback".into())
        })
        .unwrap();
        assert_eq!(fallback, std::ffi::OsString::from(r"C:\fallback"));
    }
}
