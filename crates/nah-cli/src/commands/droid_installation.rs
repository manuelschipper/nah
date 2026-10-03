//! Installs and removes nah's user-level Factory Droid PreToolUse hook.

use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

use nah_proto::ctx::AbsolutePath;
use serde_json::{Map, Value, json};

use crate::{live_state, runtime::FailurePolicy};

use super::hook_config;
use super::hook_paths::{HookLockErrorCodes, acquire_hook_lock, reject_hook_path_symlink};
use super::runtime::reject_unsupported_windows_runtime;
use super::shell_word::quote_posix_shell_word;
use super::{RuntimeHookStatus, RuntimeMutation};
use crate::private_files::{restrict_file_to_owner, sync_parent_directory};

/// The events where status counts Nah's handlers, so install and uninstall
/// remove owned handlers from each of them.
const EVENTS: [&str; 3] = ["PreToolUse", "PermissionRequest", "PostToolUse"];

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
    // Install removes any other owned handler, so the wiring is not current
    let status = if status == RuntimeHookStatus::WiringCurrent && modes.len() != 1 {
        RuntimeHookStatus::NeedsReinstall
    } else {
        status
    };
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
    let lock = acquire_hook_lock(&paths.lock, &DROID_HOOK_LOCK_ERRORS)?;
    reject_symlinks(&paths)?;
    let mut hooks = load(&paths.hooks)?;
    let mut legacy_configs = [&paths.legacy_settings, &paths.legacy_nested_hooks]
        .into_iter()
        .filter(|path| path.exists())
        .map(|path| load(path).map(|config| (path, config)))
        .collect::<Result<Vec<_>, _>>()?;
    let desired = desired_handler(executable, policy)?;
    let mut hooks_changed = migrate_nested_hooks(&mut hooks)?;
    hooks_changed |= remove_owned(&mut hooks, &EVENTS[1..])?;
    hooks_changed |= add_standalone(&mut hooks, desired)?;
    if hooks_changed {
        save(&paths.hooks, &hooks)?;
    }
    for (path, config) in &mut legacy_configs {
        if remove_owned(config, &EVENTS)? {
            save(path, config)?;
        }
    }
    drop(lock);
    Ok(paths.hooks)
}

fn uninstall_hook(home: &AbsolutePath) -> Result<PathBuf, String> {
    let paths = DroidHookPaths::new(home);
    let lock = acquire_hook_lock(&paths.lock, &DROID_HOOK_LOCK_ERRORS)?;
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
        if remove_owned(config, &EVENTS)? {
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

const DROID_HOOK_LOCK_ERRORS: HookLockErrorCodes = HookLockErrorCodes {
    invalid_path: "invalid-droid-hook-lock-path",
    failed: "droid-hook-lock-failed",
    permissions: "droid-hook-permissions-failed",
};

fn load(path: &Path) -> Result<Value, String> {
    reject_hook_path_symlink(path, "droid-settings-symlink-unsupported")?;
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
        quote_posix_shell_word(executable),
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

/// Removes owned handlers from `events`, at the top level and under a nested
/// `hooks` object, dropping only the groups, events and `hooks` object that
/// removal empties.
fn remove_owned(config: &mut Value, events: &[&str]) -> Result<bool, String> {
    let mut changed = false;
    for event in events {
        changed |= remove_owned_groups(config, event)?;
    }
    let root = config
        .as_object_mut()
        .ok_or_else(|| "invalid-droid-settings".to_owned())?;
    if let Some(nested) = root.get_mut("hooks") {
        let mut nested_changed = false;
        for event in events {
            nested_changed |= remove_owned_groups(nested, event)?;
        }
        if nested_changed && nested.as_object().is_some_and(Map::is_empty) {
            root.remove("hooks");
        }
        changed |= nested_changed;
    }
    Ok(changed)
}

fn remove_owned_groups(container: &mut Value, event: &str) -> Result<bool, String> {
    let container = container
        .as_object_mut()
        .ok_or_else(|| "invalid-droid-settings".to_owned())?;
    let Some(groups_value) = container.get_mut(event) else {
        return Ok(false);
    };
    let groups = groups_value
        .as_array_mut()
        .ok_or_else(|| "invalid-droid-settings".to_owned())?;
    if groups.iter().any(|group| {
        group
            .get("hooks")
            .is_some_and(|handlers| !handlers.is_array())
    }) {
        return Err("invalid-droid-settings".into());
    }
    let mut changed = false;
    groups.retain_mut(|group| {
        let Some(handlers) = group.get_mut("hooks").and_then(Value::as_array_mut) else {
            return true;
        };
        let before = handlers.len();
        handlers.retain(|handler| !is_owned_handler(handler));
        let dropped = handlers.len() != before;
        changed |= dropped;
        !dropped || !handlers.is_empty()
    });
    if changed && groups.is_empty() {
        container.remove(event);
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
            hook_config::is_quoted_nah_hook_executable(executable)
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

fn save(path: &Path, settings: &Value) -> Result<(), String> {
    reject_hook_path_symlink(path, "droid-settings-symlink-unsupported")?;
    let parent = path
        .parent()
        .ok_or_else(|| "invalid-droid-settings-path".to_owned())?;
    std::fs::create_dir_all(parent).map_err(|_| "droid-settings-write-failed")?;
    let mut temporary =
        tempfile::NamedTempFile::new_in(parent).map_err(|_| "droid-settings-write-failed")?;
    restrict_file_to_owner(temporary.as_file())
        .map_err(|_| "droid-hook-permissions-failed".to_owned())?;
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
    sync_parent_directory(parent).map_err(|_| "droid-hook-sync-failed".to_owned())
}

fn reject_symlinks(paths: &DroidHookPaths) -> Result<(), String> {
    for directory in &paths.directories {
        reject_hook_path_symlink(directory, "droid-settings-symlink-unsupported")?;
    }
    for path in [
        &paths.hooks,
        &paths.legacy_settings,
        &paths.legacy_nested_hooks,
    ] {
        reject_hook_path_symlink(path, "droid-settings-symlink-unsupported")?;
    }
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
