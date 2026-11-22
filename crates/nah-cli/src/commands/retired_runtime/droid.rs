//! Removes the Factory Droid hook handlers of Nah 1.x from each Factory
//! file they may be in.

use std::path::{Path, PathBuf};

use nah_proto::ctx::AbsolutePath;
use serde_json::{Map, Value};

use crate::live_state;

use super::super::RuntimeMutation;
use super::super::hook_config;
use super::super::hook_paths::{
    HookFileWriteErrorCodes, HookJsonReadErrorCodes, HookLockErrorCodes, acquire_hook_lock,
    read_hook_json_object, reject_hook_path_symlink, write_hook_json_atomically,
};
use super::super::runtime::reject_unsupported_windows_runtime;

/// The events Nah's handlers may be in.
const EVENTS: [&str; 3] = ["PreToolUse", "PermissionRequest", "PostToolUse"];

pub(super) fn uninstall() -> Result<RuntimeMutation, String> {
    let platform = live_state::host_platform();
    reject_unsupported_windows_runtime(platform)?;
    let path = live_state::home(platform).and_then(|home| uninstall_droid_hook(&home))?;
    Ok(RuntimeMutation::new(
        false,
        "Factory Droid hook",
        path,
        None,
    ))
}

fn uninstall_droid_hook(home: &AbsolutePath) -> Result<PathBuf, String> {
    let paths = DroidHookPaths::new(home);
    let lock = acquire_hook_lock(&paths.lock, &DROID_HOOK_LOCK_ERRORS)?;
    reject_droid_hook_symlinks(&paths)?;
    let mut configs = [
        &paths.hooks,
        &paths.legacy_settings,
        &paths.legacy_nested_hooks,
    ]
    .into_iter()
    .filter(|path| path.exists())
    .map(|path| load_droid_settings(path).map(|config| (path, config)))
    .collect::<Result<Vec<_>, _>>()?;
    for (path, config) in &mut configs {
        if remove_owned_droid_handlers(config, &EVENTS)? {
            save_droid_settings(path, config)?;
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

const DROID_SETTINGS_READ_ERRORS: HookJsonReadErrorCodes = HookJsonReadErrorCodes {
    read_failed: "droid-settings-read-failed",
    invalid: "invalid-droid-settings",
};

fn load_droid_settings(path: &Path) -> Result<Value, String> {
    reject_hook_path_symlink(path, "droid-settings-symlink-unsupported")?;
    read_hook_json_object(path, &DROID_SETTINGS_READ_ERRORS)
}

/// Removes owned handlers from `events`, at the top level and under a nested
/// `hooks` object, dropping only the groups, events and `hooks` object that
/// removal empties.
fn remove_owned_droid_handlers(config: &mut Value, events: &[&str]) -> Result<bool, String> {
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
        handlers.retain(|handler| !is_owned_droid_handler(handler));
        let dropped = handlers.len() != before;
        changed |= dropped;
        !dropped || !handlers.is_empty()
    });
    if changed && groups.is_empty() {
        container.remove(event);
    }
    Ok(changed)
}

fn is_owned_droid_handler(handler: &Value) -> bool {
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

const DROID_SETTINGS_WRITE_ERRORS: HookFileWriteErrorCodes = HookFileWriteErrorCodes {
    invalid_path: "invalid-droid-settings-path",
    write_failed: "droid-settings-write-failed",
    permissions: "droid-hook-permissions-failed",
    sync_failed: "droid-hook-sync-failed",
};

fn save_droid_settings(path: &Path, settings: &Value) -> Result<(), String> {
    reject_hook_path_symlink(path, "droid-settings-symlink-unsupported")?;
    write_hook_json_atomically(path, settings, &DROID_SETTINGS_WRITE_ERRORS)
}

fn reject_droid_hook_symlinks(paths: &DroidHookPaths) -> Result<(), String> {
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
