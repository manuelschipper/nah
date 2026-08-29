//! Installs and removes nah's user-level Factory Droid PreToolUse hook.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use nah_proto::ctx::AbsolutePath;
use serde_json::{Map, Value, json};

use crate::{live_state, runtime::FailurePolicy};

use super::hook_config;
use super::runtime::reject_unsupported_windows_runtime;
use super::{RuntimeHookStatus, RuntimeMutation};

pub(crate) fn mutate_droid_hook(
    install: bool,
    policy: FailurePolicy,
) -> Result<RuntimeMutation, String> {
    let platform = live_state::host_platform();
    reject_unsupported_windows_runtime(platform)?;
    let path = live_state::home(platform).and_then(|home| {
        if install {
            let executable = std::env::current_exe()
                .map_err(|_| "nah-executable-path-unavailable".to_owned())?;
            install_hook(&home, &executable, policy)
        } else {
            uninstall_hook(&home)
        }
    })?;
    Ok(RuntimeMutation::new(
        install,
        "Factory Droid hook",
        path,
        Some("Restart Droid, then review the hook in /hooks."),
    ))
}

pub(crate) fn droid_hook_status() -> Result<RuntimeHookStatus, String> {
    let platform = live_state::host_platform();
    if reject_unsupported_windows_runtime(platform).is_err() {
        return Ok(RuntimeHookStatus::NotConfigured);
    }
    let home = live_state::home(platform)?;
    let paths = DroidHookPaths::new(&home);
    reject_symlinks(&paths)?;
    let hooks = load(&paths.hooks)?;
    let executable =
        std::env::current_exe().map_err(|_| "nah-executable-path-unavailable".to_owned())?;
    let desired = desired_handler(&executable, FailurePolicy::Delegate)?;
    let strict_desired = desired_handler(&executable, FailurePolicy::Block)?;
    let current = inspect_standalone(&hooks, &desired)?;
    let strict_current = inspect_standalone(&hooks, &strict_desired)?;
    let old_current =
        hook_config::inspect(&hooks, &desired, is_owned_handler, "invalid-droid-settings")?;
    let legacy_config = load(&paths.legacy_settings)?;
    let legacy = hook_config::inspect(
        &legacy_config,
        &desired,
        is_owned_handler,
        "invalid-droid-settings",
    )?;
    let nested_config = load(&paths.legacy_nested_hooks)?;
    let nested = inspect_standalone(&nested_config, &desired)?;
    let old_nested = hook_config::inspect(
        &nested_config,
        &desired,
        is_owned_handler,
        "invalid-droid-settings",
    )?;
    let status = match (current, old_current, legacy, nested, old_nested) {
        (
            RuntimeHookStatus::NotConfigured,
            RuntimeHookStatus::NotConfigured,
            RuntimeHookStatus::NotConfigured,
            RuntimeHookStatus::NotConfigured,
            RuntimeHookStatus::NotConfigured,
        ) => RuntimeHookStatus::NotConfigured,
        (
            RuntimeHookStatus::WiringCurrent,
            RuntimeHookStatus::NotConfigured,
            RuntimeHookStatus::NotConfigured,
            RuntimeHookStatus::NotConfigured,
            RuntimeHookStatus::NotConfigured,
        ) => RuntimeHookStatus::WiringCurrent,
        _ => RuntimeHookStatus::NeedsReinstall,
    };
    let modes = [&hooks, &legacy_config, &nested_config]
        .into_iter()
        .flat_map(owned_fail_closed_modes)
        .collect::<Vec<_>>();
    if status == RuntimeHookStatus::NeedsReinstall
        && strict_current == RuntimeHookStatus::WiringCurrent
        && modes == [true]
    {
        Ok(RuntimeHookStatus::WiringCurrentFailClosed)
    } else if status == RuntimeHookStatus::NeedsReinstall
        && !modes.is_empty()
        && modes.iter().all(|strict| *strict)
    {
        Ok(RuntimeHookStatus::NeedsReinstallFailClosed)
    } else {
        Ok(status)
    }
}

pub(crate) fn droid_self_protection_paths() -> Result<Vec<PathBuf>, String> {
    let platform = live_state::host_platform();
    let home = live_state::home(platform)?;
    let paths = DroidHookPaths::new(&home);
    Ok(vec![
        paths.hooks,
        paths.legacy_settings,
        paths.legacy_nested_hooks,
    ])
}

fn install_hook(
    home: &AbsolutePath,
    executable: &Path,
    policy: FailurePolicy,
) -> Result<PathBuf, String> {
    let paths = DroidHookPaths::new(home);
    let lock = lock(&paths)?;
    reject_symlinks(&paths)?;
    let mut hooks = load(&paths.hooks)?;
    let mut legacy_configs = [&paths.legacy_settings, &paths.legacy_nested_hooks]
        .into_iter()
        .filter(|path| path.exists())
        .map(|path| load(path).map(|config| (path, config)))
        .collect::<Result<Vec<_>, _>>()?;
    let desired = desired_handler(executable, policy)?;
    let mut hooks_changed = migrate_nested_hooks(&mut hooks)?;
    hooks_changed |= add_standalone(&mut hooks, desired)?;
    if hooks_changed {
        save(&paths.hooks, &hooks)?;
    }
    for (path, config) in &mut legacy_configs {
        let mut changed = hook_config::remove(config, is_owned_handler, "invalid-droid-settings")?;
        if path.as_path() == paths.legacy_nested_hooks.as_path() {
            changed |= remove_standalone(config)?;
        }
        if changed {
            save(path, config)?;
        }
    }
    drop(lock);
    Ok(paths.hooks)
}

fn uninstall_hook(home: &AbsolutePath) -> Result<PathBuf, String> {
    let paths = DroidHookPaths::new(home);
    let lock = lock(&paths)?;
    reject_symlinks(&paths)?;
    let mut configs = [
        &paths.hooks,
        &paths.legacy_settings,
        &paths.legacy_nested_hooks,
    ]
    .into_iter()
    .filter(|path| path.exists())
    .map(|path| load(path).map(|config| (path, config)))
    .collect::<Result<Vec<_>, _>>()?;
    for (path, config) in &mut configs {
        let mut changed = hook_config::remove(config, is_owned_handler, "invalid-droid-settings")?;
        if path.as_path() != paths.legacy_settings.as_path() {
            changed |= remove_standalone(config)?;
        }
        if changed {
            save(path, config)?;
        }
    }
    drop(lock);
    Ok(paths.hooks)
}

struct DroidHookPaths {
    hooks: PathBuf,
    legacy_settings: PathBuf,
    legacy_nested_hooks: PathBuf,
    lock: PathBuf,
    directories: Vec<PathBuf>,
}

impl DroidHookPaths {
    fn new(home: &AbsolutePath) -> Self {
        let home = PathBuf::from(home.as_str());
        let factory = home.join(".factory");
        Self {
            hooks: factory.join("hooks.json"),
            legacy_settings: factory.join("settings.json"),
            legacy_nested_hooks: factory.join("hooks/hooks.json"),
            lock: home.join(".nah/droid-hook.lock"),
            directories: vec![factory.clone(), factory.join("hooks")],
        }
    }
}

fn lock(paths: &DroidHookPaths) -> Result<File, String> {
    let parent = paths
        .lock
        .parent()
        .ok_or_else(|| "invalid-droid-hook-lock-path".to_owned())?;
    std::fs::create_dir_all(parent).map_err(|_| "droid-hook-lock-failed")?;
    reject_symlink(&paths.lock, "droid-hook-lock-failed")?;
    let mut options = OpenOptions::new();
    options.create(true).truncate(false).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(&paths.lock)
        .map_err(|_| "droid-hook-lock-failed")?;
    protect_private(&file)?;
    file.lock().map_err(|_| "droid-hook-lock-failed")?;
    Ok(file)
}

fn load(path: &Path) -> Result<Value, String> {
    reject_symlink(path, "droid-settings-symlink-unsupported")?;
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Value::Object(Map::new()));
        }
        Err(_) => return Err("droid-settings-read-failed".into()),
    };
    let value: Value =
        serde_json::from_reader(file).map_err(|_| "invalid-droid-settings".to_owned())?;
    if !value.is_object() {
        return Err("invalid-droid-settings".into());
    }
    Ok(value)
}

fn desired_handler(executable: &Path, policy: FailurePolicy) -> Result<Value, String> {
    let executable = executable
        .to_str()
        .ok_or_else(|| "invalid-nah-executable-path".to_owned())?;
    let run = format!(
        "{} hook droid run{}",
        shell_quote(executable),
        policy.command_suffix()
    );
    let command = format!(
        "{run} || {{ status=$?; [ \"$status\" -eq 2 ] && exit 2; printf '%s\\n' \
         'nah - evaluation failed; this call was delegated to the runtime'; exit 0; }}"
    );
    Ok(json!({"type":"command","command":command,"timeout":5}))
}

fn inspect_standalone(config: &Value, desired: &Value) -> Result<RuntimeHookStatus, String> {
    hook_config::inspect(
        &json!({"hooks": config}),
        desired,
        is_owned_handler,
        "invalid-droid-settings",
    )
}

fn add_standalone(config: &mut Value, desired: Value) -> Result<bool, String> {
    let mut wrapped = json!({"hooks": config.clone()});
    let changed = hook_config::add(
        &mut wrapped,
        desired,
        is_owned_handler,
        "invalid-droid-settings",
    )?;
    if changed {
        *config = wrapped
            .as_object_mut()
            .and_then(|root| root.remove("hooks"))
            .ok_or_else(|| "invalid-droid-settings".to_owned())?;
    }
    Ok(changed)
}

fn remove_standalone(config: &mut Value) -> Result<bool, String> {
    let mut wrapped = json!({"hooks": config.clone()});
    let changed = hook_config::remove(&mut wrapped, is_owned_handler, "invalid-droid-settings")?;
    if changed {
        *config = wrapped
            .as_object_mut()
            .and_then(|root| root.remove("hooks"))
            .unwrap_or_else(|| Value::Object(Map::new()));
    }
    Ok(changed)
}

fn migrate_nested_hooks(config: &mut Value) -> Result<bool, String> {
    let root = config
        .as_object_mut()
        .ok_or_else(|| "invalid-droid-settings".to_owned())?;
    if let Some(nested) = root.get("hooks") {
        let nested = nested
            .as_object()
            .ok_or_else(|| "invalid-droid-settings".to_owned())?;
        if nested.values().any(|groups| !groups.is_array()) {
            return Err("invalid-droid-settings".into());
        }
    }
    let Some(nested) = root.remove("hooks") else {
        return Ok(false);
    };
    let nested = nested
        .as_object()
        .ok_or_else(|| "invalid-droid-settings".to_owned())?;
    for (event, groups) in nested {
        match root.get_mut(event) {
            Some(existing) => {
                let existing = existing
                    .as_array_mut()
                    .ok_or_else(|| "invalid-droid-settings".to_owned())?;
                let groups = groups
                    .as_array()
                    .ok_or_else(|| "invalid-droid-settings".to_owned())?;
                existing.extend(groups.iter().cloned());
            }
            None => {
                root.insert(event.clone(), groups.clone());
            }
        }
    }
    Ok(true)
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn is_owned_handler(handler: &Value) -> bool {
    let Some(command) = handler
        .as_object()
        .filter(|handler| handler.get("type").and_then(Value::as_str) == Some("command"))
        .and_then(|handler| handler.get("command"))
        .and_then(Value::as_str)
    else {
        return false;
    };
    command
        .split_once(" hook droid run")
        .is_some_and(|(executable, suffix)| {
            is_nah_executable(executable)
                && (suffix.is_empty()
                    || suffix == " --fail-closed"
                    || suffix.starts_with(" --fail-closed || { ")
                    || suffix.starts_with(" || { "))
        })
}

fn owned_fail_closed_modes(config: &Value) -> Vec<bool> {
    let mut handlers = Vec::new();
    for event in ["PreToolUse", "PermissionRequest", "PostToolUse"] {
        if let Some(groups) = config.get(event).and_then(Value::as_array) {
            handlers.extend(
                groups
                    .iter()
                    .flat_map(|group| group["hooks"].as_array().into_iter().flatten()),
            );
        }
        if let Some(groups) = config["hooks"].get(event).and_then(Value::as_array) {
            handlers.extend(
                groups
                    .iter()
                    .flat_map(|group| group["hooks"].as_array().into_iter().flatten()),
            );
        }
    }
    handlers
        .into_iter()
        .filter(|handler| is_owned_handler(handler))
        .map(|handler| {
            handler["command"]
                .as_str()
                .is_some_and(|command| command.contains(" hook droid run --fail-closed"))
        })
        .collect()
}

fn is_nah_executable(executable: &str) -> bool {
    let executable = executable.to_ascii_lowercase();
    (executable.starts_with('\'') && executable.ends_with("/nah'"))
        || (executable.starts_with('"')
            && (executable.ends_with("/nah\"")
                || executable.ends_with("\\nah.exe\"")
                || executable.ends_with("/nah.exe\"")))
}

fn save(path: &Path, settings: &Value) -> Result<(), String> {
    reject_symlink(path, "droid-settings-symlink-unsupported")?;
    let parent = path
        .parent()
        .ok_or_else(|| "invalid-droid-settings-path".to_owned())?;
    std::fs::create_dir_all(parent).map_err(|_| "droid-settings-write-failed")?;
    let mut temporary =
        tempfile::NamedTempFile::new_in(parent).map_err(|_| "droid-settings-write-failed")?;
    protect_private(temporary.as_file())?;
    serde_json::to_writer_pretty(&mut temporary, settings)
        .map_err(|_| "droid-settings-write-failed")?;
    temporary
        .write_all(b"\n")
        .map_err(|_| "droid-settings-write-failed")?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|_| "droid-settings-write-failed")?;
    temporary
        .persist(path)
        .map_err(|_| "droid-settings-write-failed")?;
    sync_parent(parent)
}

fn reject_symlink(path: &Path, error: &'static str) -> Result<(), String> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(error.into()),
        Ok(_) => Ok(()),
        Err(found) if found.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(error.into()),
    }
}

fn reject_symlinks(paths: &DroidHookPaths) -> Result<(), String> {
    for directory in &paths.directories {
        reject_symlink(directory, "droid-settings-symlink-unsupported")?;
    }
    for path in [
        &paths.hooks,
        &paths.legacy_settings,
        &paths.legacy_nested_hooks,
    ] {
        reject_symlink(path, "droid-settings-symlink-unsupported")?;
    }
    Ok(())
}

#[cfg(unix)]
fn protect_private(file: &File) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|_| "droid-hook-permissions-failed".into())
}

#[cfg(not(unix))]
fn protect_private(_file: &File) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn sync_parent(parent: &Path) -> Result<(), String> {
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| "droid-hook-sync-failed".into())
}

#[cfg(not(unix))]
fn sync_parent(_parent: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mixed_owned_handler_modes_are_not_reliably_strict() {
        let strict = desired_handler(Path::new("/old/nah"), FailurePolicy::Block).unwrap();
        let delegate = desired_handler(Path::new("/old/nah"), FailurePolicy::Delegate).unwrap();
        let config = json!({"PreToolUse":[{"matcher":"*","hooks":[strict,delegate]}]});
        assert_eq!(owned_fail_closed_modes(&config), [true, false]);
    }
}
