//! Persists the operator's global guard settings and rule overrides.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use nah_proto::ctx::{AbsolutePath, Guard, GuardLevel, GuardSettings, Platform, RuleOverride};
use serde::{Deserialize, Serialize};

use crate::private_files::{
    HOOK_LOCK_WAIT, lock_until, restrict_file_to_owner, sync_parent_directory,
};
use crate::state_protection::nah_state_file_path;

/// Versions 1 and 2 are nah 1.x's, keyed by 1.x guard names;
/// `import_legacy` converts them once.
const VERSION: u32 = 3;

/// nah 1.x's first format: the shipped guards turned off.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyStateV1 {
    v: u32,
    disabled: Vec<String>,
}

/// nah 1.x's second format: each 1.x guard set away from its default.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyStateV2 {
    v: u32,
    overrides: BTreeMap<String, bool>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ShippedState {
    settings: GuardSettings,
}

/// `~/.nah/built-ins.json`: only the guard settings and rule overrides that
/// differ from the factory defaults, written canonically.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredState {
    v: u32,
    guards: BTreeMap<Guard, GuardLevel>,
    rules: BTreeMap<String, RuleOverride>,
}

impl ShippedState {
    /// What a fresh install runs on: every guard at `core`, no override.
    pub(crate) fn defaults() -> Self {
        Self {
            settings: GuardSettings::default(),
        }
    }

    /// Validates raw state before returning its settings and sorted
    /// diagnostics. `rules` are the shipped rule IDs.
    pub(crate) fn load(
        path: &Path,
        rules: &[&str],
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
        if version != u64::from(VERSION) {
            return Err(ShippedStateError::UnsupportedVersion);
        }
        let state: StoredState =
            serde_json::from_value(value).map_err(|_| ShippedStateError::InvalidState)?;
        if serde_json::to_string(&state)
            .map(|canonical| contents != format!("{canonical}\n"))
            .unwrap_or(true)
        {
            return Err(ShippedStateError::InvalidState);
        }
        let mut diagnostics = Vec::new();
        let mut overrides = BTreeMap::new();
        for (rule, value) in state.rules {
            if rules.contains(&rule.as_str()) {
                overrides.insert(rule, value);
            } else {
                diagnostics.push(format!("unknown built-in rule `{rule}` was ignored"));
            }
        }
        let settings = GuardSettings::new(state.guards, overrides)
            .map_err(|_| ShippedStateError::InvalidState)?;
        Ok((Self { settings }, diagnostics))
    }

    /// The settings at `path` while their 1.x import waits for a later call:
    /// a 1.x file reads as the settings its import would write, and any
    /// other file as `load` reads it. Nothing is written.
    pub(crate) fn load_deferring_import(
        path: &Path,
        rules: &[&str],
    ) -> Result<(Self, Vec<String>), ShippedStateError> {
        match std::fs::read_to_string(path) {
            Ok(contents) if legacy_version(&contents).is_some() => {
                let (overrides, diagnostics) = legacy_overrides(&contents)?;
                let settings = crate::legacy_import::import_settings(&overrides).settings;
                Ok((Self { settings }, diagnostics))
            }
            _ => Self::load(path, rules),
        }
    }

    pub(crate) fn settings(&self) -> &GuardSettings {
        &self.settings
    }

    fn save(&self, path: &Path) -> Result<(), ShippedStateError> {
        let parent = path.parent().ok_or(ShippedStateError::InvalidPath)?;
        std::fs::create_dir_all(parent).map_err(|_| ShippedStateError::Io)?;
        let mut temporary =
            tempfile::NamedTempFile::new_in(parent).map_err(|_| ShippedStateError::Io)?;
        restrict_file_to_owner(temporary.as_file()).map_err(|_| ShippedStateError::Io)?;
        serde_json::to_writer(
            &mut temporary,
            &StoredState {
                v: VERSION,
                guards: self.settings.guards().clone(),
                rules: self.settings.rules().clone(),
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
        sync_parent_directory(parent).map_err(|_| ShippedStateError::Io)
    }
}

/// Sets `guard`; `core` removes the stored setting. `self` has no setting.
pub(crate) fn set_guard_level(
    path: &Path,
    rules: &[&str],
    operator: bool,
    guard: Guard,
    level: GuardLevel,
) -> Result<Vec<String>, ShippedStateError> {
    if !guard.configurable() {
        return Err(ShippedStateError::UnknownGuard);
    }
    mutate(path, rules, operator, |settings| {
        settings.set_guard(guard, level)
    })
}

/// Sets or, with `None`, removes the override of the shipped rule `rule`.
pub(crate) fn set_rule_override(
    path: &Path,
    rules: &[&str],
    operator: bool,
    rule: &str,
    value: Option<RuleOverride>,
) -> Result<Vec<String>, ShippedStateError> {
    if !rules.contains(&rule) {
        return Err(ShippedStateError::UnknownGuard);
    }
    mutate(path, rules, operator, |settings| {
        settings.set_rule(rule, value)
    })
}

/// Applies `update` under the state lock. Without an `operator`, a change
/// that lowers the level any rule runs at is refused before anything is
/// written.
fn mutate(
    path: &Path,
    rules: &[&str],
    operator: bool,
    update: impl FnOnce(&mut GuardSettings),
) -> Result<Vec<String>, ShippedStateError> {
    let _lock = lock(path, None)?;
    let (mut state, diagnostics) = ShippedState::load(path, rules)?;
    let before = state.settings.clone();
    update(&mut state.settings);
    let lowers = rules
        .iter()
        .any(|rule| state.settings.rule_level(rule) < before.rule_level(rule));
    if lowers && !operator {
        return Err(ShippedStateError::OperatorRequired);
    }
    state.save(path)?;
    Ok(diagnostics)
}

/// Takes the state lock, held until the returned file drops. A command a
/// person runs waits for it as long as another process holds it (`None`); a
/// hook's wait ends at `give_up` with `Contended`, so a stopped holder cannot
/// hold the hook until its runtime kills it.
fn lock(path: &Path, give_up: Option<Instant>) -> Result<File, ShippedStateError> {
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
    restrict_file_to_owner(&lock).map_err(|_| ShippedStateError::Io)?;
    match give_up {
        None => lock.lock().map_err(|_| ShippedStateError::Io)?,
        Some(give_up) => lock_until(&lock, give_up).map_err(|error| match error {
            std::fs::TryLockError::WouldBlock => ShippedStateError::Contended,
            std::fs::TryLockError::Error(_) => ShippedStateError::Io,
        })?,
    }
    Ok(lock)
}

/// The state lock as a hook takes it, waiting at most `HOOK_LOCK_WAIT`.
fn hook_lock(path: &Path) -> Result<File, ShippedStateError> {
    lock(path, Some(Instant::now() + HOOK_LOCK_WAIT))
}

/// Whether `path` holds a nah 1.x state file for `import_legacy`.
pub(crate) fn is_legacy(path: &Path) -> bool {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|contents| legacy_version(&contents))
        .is_some()
}

fn legacy_version(contents: &str) -> Option<u64> {
    serde_json::from_str::<serde_json::Value>(contents)
        .ok()?
        .get("v")?
        .as_u64()
        .filter(|version| matches!(version, 1 | 2))
}

/// The 1.x choices a nah 1.x state file holds, validated as 1.x validated
/// them, with a diagnostic for each name that is no 1.x guard, which 1.x
/// ignored too.
fn legacy_overrides(
    contents: &str,
) -> Result<(BTreeMap<String, bool>, Vec<String>), ShippedStateError> {
    let value: serde_json::Value =
        serde_json::from_str(contents).map_err(|_| ShippedStateError::InvalidState)?;
    let overrides = match legacy_version(contents) {
        Some(1) => {
            let state: LegacyStateV1 =
                serde_json::from_value(value).map_err(|_| ShippedStateError::InvalidState)?;
            if state.v != 1 || state.disabled.windows(2).any(|pair| pair[0] >= pair[1]) {
                return Err(ShippedStateError::InvalidState);
            }
            state
                .disabled
                .into_iter()
                .map(|name| (name, false))
                .collect()
        }
        Some(_) => {
            let state: LegacyStateV2 =
                serde_json::from_value(value).map_err(|_| ShippedStateError::InvalidState)?;
            if serde_json::to_string(&state)
                .map(|canonical| contents != format!("{canonical}\n"))
                .unwrap_or(true)
            {
                return Err(ShippedStateError::InvalidState);
            }
            state.overrides
        }
        None => return Err(ShippedStateError::InvalidState),
    };
    let mut known = BTreeMap::new();
    let mut diagnostics = Vec::new();
    for (name, enabled) in overrides {
        let Some((_, default)) = nah_policy::LEGACY_GUARDS
            .iter()
            .find(|(legacy, _)| *legacy == name)
        else {
            diagnostics.push(format!("unknown nah 1.x guard `{name}` was ignored"));
            continue;
        };
        // 1.x never stored a guard that ships on as enabled.
        if *default && enabled {
            return Err(ShippedStateError::InvalidState);
        }
        known.insert(name, enabled);
    }
    Ok((known, diagnostics))
}

/// Converts a nah 1.x state file at `path` to the current version in place,
/// once, under the state lock. The 1.x bytes are first written to
/// `built-ins.json.1x` beside it, an existing different backup is never
/// overwritten, and the converted file replaces the 1.x one atomically. The
/// import's notices are kept in `1x-import.txt` beside it for `nah guards`.
/// Returns the 1.x choices, read from the 1.x file or from the backup of an
/// earlier import (none without either), for a 1.x nap's import, and the
/// warnings and notices this call's conversion produced. On failure the 1.x
/// file is untouched, and `Contended` means another process holds the
/// state, so the import waits for a later call.
pub(crate) fn import_legacy(
    path: &Path,
) -> Result<(BTreeMap<String, bool>, Vec<String>), ShippedStateError> {
    let _lock = hook_lock(path)?;
    let backup = legacy_backup_path(path);
    let contents = match std::fs::read_to_string(path) {
        Ok(contents) if legacy_version(&contents).is_some() => contents,
        Ok(_) => return Ok((earlier_import(&backup)?, vec![])),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok((earlier_import(&backup)?, vec![]));
        }
        Err(_) => return Err(ShippedStateError::Io),
    };
    let (overrides, mut warnings) = legacy_overrides(&contents)?;
    let imported = crate::legacy_import::import_settings(&overrides);
    write_new(&backup, contents.as_bytes())?;
    let notices = imported
        .notices
        .iter()
        .map(|notice| notice.text.clone())
        .collect::<Vec<_>>();
    warnings.push(format!(
        "imported the nah 1.x configuration; the 1.x file is kept at {}",
        backup.display()
    ));
    warnings.extend(notices.iter().cloned());
    add_lines(&import_notice_path(path), &notices)?;
    add_lines(&pending_report_path(path), &warnings)?;
    ShippedState {
        settings: imported.settings,
    }
    .save(path)?;
    Ok((overrides, warnings))
}

/// Adds lines to the reports the next decision records. Lines already
/// stored are left as they are, so repeating a line does not give it to a
/// second decision. While another process holds the state lock, the lines go
/// to a report file of their own instead, which `take_pending_reports` takes
/// as well.
pub(crate) fn append_pending_reports(
    path: &Path,
    lines: &[String],
) -> Result<(), ShippedStateError> {
    match hook_lock(path) {
        Ok(_lock) => add_lines(&pending_report_path(path), lines),
        Err(ShippedStateError::Contended) => {
            let mut contents = lines.join("\n");
            contents.push('\n');
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_nanos());
            write_private(
                &path.with_file_name(format!(
                    "{PENDING_REPORTS}-{}-{unique}.txt",
                    std::process::id()
                )),
                contents.as_bytes(),
            )
        }
        Err(error) => Err(error),
    }
}

/// Adds notices of the 1.x nap import to the file `nah guards` lists and to
/// the reports the next decision records, as `import_legacy` does for the
/// settings file's own.
pub(crate) fn record_import_notices(
    path: &Path,
    notices: &[String],
) -> Result<(), ShippedStateError> {
    let _lock = hook_lock(path)?;
    add_lines(&import_notice_path(path), notices)?;
    add_lines(&pending_report_path(path), notices)
}

/// Takes the import reports no decision has recorded yet, so that one
/// decision's audit row carries them. Whichever decision renames the file
/// away first takes them; the rest find none. A report that cannot be read
/// waits for the next decision. The pending file and every report file
/// `append_pending_reports` wrote beside it are taken.
pub(crate) fn take_pending_reports(path: &Path) -> Vec<String> {
    let Some(entries) = path
        .parent()
        .and_then(|parent| std::fs::read_dir(parent).ok())
    else {
        return vec![];
    };
    let mut reports = Vec::new();
    for entry in entries.flatten() {
        if !entry.file_type().is_ok_and(|kind| kind.is_file())
            || !entry.file_name().to_str().is_some_and(is_pending_report)
        {
            continue;
        }
        let pending = entry.path();
        let taken = pending.with_extension(format!("taken-{}", std::process::id()));
        if std::fs::rename(&pending, &taken).is_err() {
            continue;
        }
        let taken_reports = std::fs::read_to_string(&taken).unwrap_or_default();
        let _ = std::fs::remove_file(&taken);
        reports.extend(taken_reports.lines().map(str::to_owned));
    }
    reports
}

/// Puts back reports `take_pending_reports` took for a decision whose audit
/// row could not be written, so the next decision records them instead.
pub(crate) fn restore_pending_reports(path: &Path, reports: &[String]) {
    if !reports.is_empty() {
        let _ = append_pending_reports(path, reports);
    }
}

/// Adds the lines `path` does not hold yet, so an interrupted import that
/// runs again repeats nothing.
fn add_lines(path: &Path, lines: &[String]) -> Result<(), ShippedStateError> {
    let mut contents = match std::fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(_) => return Err(ShippedStateError::Io),
    };
    let mut held = contents.lines().map(str::to_owned).collect::<BTreeSet<_>>();
    let before = contents.len();
    for line in lines {
        if held.insert(line.clone()) {
            contents.push_str(line);
            contents.push('\n');
        }
    }
    if contents.len() == before {
        return Ok(());
    }
    write_private(path, contents.as_bytes())
}

/// The 1.x choices an earlier import kept in its backup.
fn earlier_import(backup: &Path) -> Result<BTreeMap<String, bool>, ShippedStateError> {
    match std::fs::read_to_string(backup) {
        Ok(contents) => Ok(legacy_overrides(&contents)?.0),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
        Err(_) => Err(ShippedStateError::Io),
    }
}

/// Creates `path` with `bytes`; an existing file is accepted only when it
/// already holds exactly these bytes, as an interrupted import leaves it.
fn write_new(path: &Path, bytes: &[u8]) -> Result<(), ShippedStateError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            return if metadata.is_file()
                && std::fs::read(path).map_err(|_| ShippedStateError::Io)? == bytes
            {
                Ok(())
            } else {
                Err(ShippedStateError::BackupExists)
            };
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(ShippedStateError::Io),
    }
    write_private(path, bytes)
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), ShippedStateError> {
    let parent = path.parent().ok_or(ShippedStateError::InvalidPath)?;
    let mut temporary =
        tempfile::NamedTempFile::new_in(parent).map_err(|_| ShippedStateError::Io)?;
    restrict_file_to_owner(temporary.as_file()).map_err(|_| ShippedStateError::Io)?;
    temporary
        .write_all(bytes)
        .and_then(|()| temporary.as_file().sync_all())
        .map_err(|_| ShippedStateError::Io)?;
    temporary.persist(path).map_err(|_| ShippedStateError::Io)?;
    sync_parent_directory(parent).map_err(|_| ShippedStateError::Io)
}

/// What the 1.x import could not carry exactly, one notice per line, or
/// `None` when it carried everything or no import ran.
pub(crate) fn import_notices(path: &Path) -> Result<Option<String>, ShippedStateError> {
    match std::fs::read_to_string(import_notice_path(path)) {
        Ok(notices) => Ok(Some(notices)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(ShippedStateError::Io),
    }
}

fn legacy_backup_path(path: &Path) -> PathBuf {
    path.with_file_name("built-ins.json.1x")
}

fn import_notice_path(path: &Path) -> PathBuf {
    path.with_file_name("1x-import.txt")
}

/// The name every pending report file starts with.
const PENDING_REPORTS: &str = "1x-import-pending";

/// Whether `name` is the pending file or a report file
/// `append_pending_reports` writes, `<PENDING_REPORTS>-<pid>-<nanos>.txt`.
fn is_pending_report(name: &str) -> bool {
    let Some(rest) = name.strip_prefix(PENDING_REPORTS) else {
        return false;
    };
    rest == ".txt"
        || rest
            .strip_prefix('-')
            .and_then(|rest| rest.strip_suffix(".txt"))
            .and_then(|rest| rest.split_once('-'))
            .is_some_and(|(pid, unique)| {
                [pid, unique]
                    .iter()
                    .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
            })
}

fn pending_report_path(path: &Path) -> PathBuf {
    path.with_file_name(format!("{PENDING_REPORTS}.txt"))
}

pub(crate) fn state_path(home: &AbsolutePath, platform: Platform) -> PathBuf {
    nah_state_file_path(home, platform, "built-ins.json")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ShippedStateError {
    /// A different `built-ins.json.1x` already exists, so the 1.x import
    /// stops rather than overwrite it.
    BackupExists,
    /// Another Nah process held the state lock past a hook's wait.
    Contended,
    InvalidPath,
    InvalidState,
    Io,
    OperatorRequired,
    UnknownGuard,
    UnsupportedVersion,
}

impl ShippedStateError {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::BackupExists => "shipped-state-1x-backup-exists",
            Self::Contended => "shipped-state-busy",
            Self::InvalidPath => "invalid-shipped-state-path",
            Self::InvalidState => "invalid-shipped-state",
            Self::Io => "shipped-state-io-failed",
            Self::OperatorRequired => "operator-required",
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

    const RULES: [&str; 4] = [
        "persistence/shell-profile-write",
        "persistence/startup-item-add",
        "untrusted-code/hidden-payload-run",
        "untrusted-code/remote-script-run",
    ];

    #[test]
    fn concurrent_mutations_preserve_each_disabled_rule() {
        let temp = tempfile::tempdir().unwrap();
        let path = Arc::new(temp.path().join("built-ins.json"));
        let barrier = Arc::new(Barrier::new(RULES.len()));
        let workers = RULES
            .iter()
            .map(|rule| {
                let path = Arc::clone(&path);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    set_rule_override(&path, &RULES, true, rule, Some(RuleOverride::Disabled))
                        .unwrap();
                })
            })
            .collect::<Vec<_>>();
        for worker in workers {
            worker.join().unwrap();
        }
        let (state, diagnostics) = ShippedState::load(&path, &RULES).unwrap();
        assert!(diagnostics.is_empty());
        assert!(
            RULES.iter().all(|rule| {
                state.settings().rule_override(rule) == Some(RuleOverride::Disabled)
            })
        );
    }

    /// A 1.x file converts once, in place: its bytes become the backup, the
    /// converted settings replace it, and a later import reads the 1.x
    /// choices back from the backup and changes nothing. A different backup,
    /// or a 1.x file 1.x itself would reject, stops the import and leaves
    /// the 1.x file as it was.
    #[test]
    fn a_1x_state_file_converts_once_beside_its_backup() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("built-ins.json");
        let legacy = "{\"v\":2,\"overrides\":{\"db-destroy\":true,\"git-hard-reset\":false,\"retired\":false}}\n";
        std::fs::write(&path, legacy).unwrap();
        let (overrides, warnings) = import_legacy(&path).unwrap();
        assert_eq!(
            overrides,
            BTreeMap::from([
                ("db-destroy".to_owned(), true),
                ("git-hard-reset".to_owned(), false)
            ])
        );
        assert_eq!(
            std::fs::read_to_string(legacy_backup_path(&path)).unwrap(),
            legacy
        );
        let (state, _) = ShippedState::load(&path, crate::catalog::rule_ids()).unwrap();
        assert_eq!(
            state.settings(),
            &crate::legacy_import::import_settings(&overrides).settings
        );
        assert!(warnings.iter().any(|warning| warning.contains("`retired`")));
        // `git-hard-reset` shares its rule with a guard 1.x kept on.
        let notices = import_notices(&path).unwrap().unwrap();
        assert!(notices.contains("work/changes-discard"), "{notices}");
        assert!(
            warnings
                .iter()
                .any(|warning| notices.contains(warning.as_str()))
        );

        let converted = std::fs::read(&path).unwrap();
        assert_eq!(import_legacy(&path).unwrap(), (overrides, vec![]));
        assert_eq!(std::fs::read(&path).unwrap(), converted);

        for (legacy, backup, error) in [
            (
                r#"{"v":1,"disabled":["fs-home"]}"#,
                Some("other bytes"),
                ShippedStateError::BackupExists,
            ),
            // 1.x never stored a guard that ships on as enabled.
            (
                "{\"v\":2,\"overrides\":{\"fs-home\":true}}\n",
                None,
                ShippedStateError::InvalidState,
            ),
        ] {
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join("built-ins.json");
            std::fs::write(&path, legacy).unwrap();
            if let Some(backup) = backup {
                std::fs::write(legacy_backup_path(&path), backup).unwrap();
            }
            assert_eq!(import_legacy(&path).unwrap_err(), error);
            assert_eq!(std::fs::read_to_string(&path).unwrap(), legacy);
            assert_eq!(
                std::fs::read_to_string(legacy_backup_path(&path))
                    .ok()
                    .as_deref(),
                backup
            );
        }
    }

    #[test]
    fn older_malformed_and_noncanonical_state_fail_while_unknown_rules_are_diagnostic() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("built-ins.json");
        // A 1.x file is unsupported until the import converts it.
        for older in [
            r#"{"v":1,"disabled":["fs-home"]}"#,
            "{\"v\":2,\"overrides\":{\"fs-home\":false}}\n",
            r#"{"v":4,"guards":{},"rules":{}}"#,
        ] {
            std::fs::write(&path, older).unwrap();
            assert_eq!(
                ShippedState::load(&path, &RULES).unwrap_err(),
                ShippedStateError::UnsupportedVersion
            );
        }
        std::fs::write(
            &path,
            "{\"v\":3,\"guards\":{},\"rules\":{\"retired/rule\":\"disabled\"}}\n",
        )
        .unwrap();
        let (state, diagnostics) = ShippedState::load(&path, &RULES).unwrap();
        assert!(state.settings().rules().is_empty());
        assert_eq!(diagnostics.len(), 1);
        assert!(diagnostics[0].contains("retired/rule"));
        for invalid in [
            // Not canonical: no trailing newline.
            r#"{"v":3,"guards":{},"rules":{}}"#,
            // `core` is the default and never stored; `self` has no setting.
            "{\"v\":3,\"guards\":{\"work\":\"core\"},\"rules\":{}}\n",
            "{\"v\":3,\"guards\":{\"self\":\"off\"},\"rules\":{}}\n",
            "{\"v\":3,\"guards\":{\"nope\":\"off\"},\"rules\":{}}\n",
            "{\"v\":3,\"guards\":{},\"rules\":{},\"overrides\":{}}\n",
        ] {
            std::fs::write(&path, invalid).unwrap();
            assert_eq!(
                ShippedState::load(&path, &RULES).unwrap_err(),
                ShippedStateError::InvalidState,
                "{invalid}"
            );
        }
    }

    #[test]
    fn choices_are_stored_canonically_and_reset_removes_them() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("built-ins.json");

        let (state, diagnostics) = ShippedState::load(&path, &RULES).unwrap();
        assert!(diagnostics.is_empty());
        assert_eq!(state.settings(), &GuardSettings::default());

        set_guard_level(&path, &RULES, true, Guard::Persistence, GuardLevel::Strict).unwrap();
        set_guard_level(&path, &RULES, true, Guard::Work, GuardLevel::Off).unwrap();
        set_rule_override(
            &path,
            &RULES,
            true,
            "untrusted-code/remote-script-run",
            Some(RuleOverride::Disabled),
        )
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "{\"v\":3,\"guards\":{\"work\":\"off\",\"persistence\":\"strict\"},\"rules\":{\"untrusted-code/remote-script-run\":\"disabled\"}}\n"
        );
        let (state, diagnostics) = ShippedState::load(&path, &RULES).unwrap();
        assert!(diagnostics.is_empty());
        assert_eq!(
            state.settings().guard_level(Guard::Persistence),
            GuardLevel::Strict
        );

        set_guard_level(&path, &RULES, true, Guard::Work, GuardLevel::Core).unwrap();
        set_guard_level(&path, &RULES, true, Guard::Persistence, GuardLevel::Core).unwrap();
        set_rule_override(
            &path,
            &RULES,
            true,
            "untrusted-code/remote-script-run",
            None,
        )
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "{\"v\":3,\"guards\":{},\"rules\":{}}\n"
        );
        assert_eq!(
            set_guard_level(&path, &RULES, true, Guard::SelfProtection, GuardLevel::Off)
                .unwrap_err(),
            ShippedStateError::UnknownGuard
        );
        assert_eq!(
            set_rule_override(&path, &RULES, true, "work/nope", None).unwrap_err(),
            ShippedStateError::UnknownGuard
        );
    }
}
