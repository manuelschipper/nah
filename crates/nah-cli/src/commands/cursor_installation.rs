//! Installs and removes nah's user-level Cursor preToolUse hook.

use std::path::{Path, PathBuf};

use nah_proto::ctx::AbsolutePath;
use serde_json::{Map, Value, json};

use crate::{live_state, runtime::FailurePolicy};

use super::hook_config;
use super::hook_paths::{
    HookFileWriteErrorCodes, HookJsonReadErrorCodes, HookLockErrorCodes, acquire_hook_lock,
    read_hook_json_object, reject_hook_path_symlink, write_hook_json_atomically,
};
use super::shell_word::quote_posix_shell_word;
use super::{RuntimeHookStatus, RuntimeMutation};

pub(crate) fn mutate_cursor_hook(
    install: bool,
    policy: FailurePolicy,
) -> Result<RuntimeMutation, String> {
    let platform = live_state::host_platform();
    let path = live_state::home(platform).and_then(|home| {
        if install {
            let executable = std::env::current_exe()
                .map_err(|_| "nah-executable-path-unavailable".to_owned())?;
            install_cursor_hook(&home, &executable, policy)
        } else {
            uninstall_cursor_hook(&home)
        }
    })?;
    Ok(RuntimeMutation::new(install, "Cursor hook", path, None))
}

pub(crate) fn cursor_hook_status() -> Result<RuntimeHookStatus, String> {
    let platform = live_state::host_platform();
    let home = live_state::home(platform)?;
    let paths = CursorHookPaths::new(&home);
    reject_cursor_hook_symlinks(&paths)?;
    let mut config = load_cursor_hooks(&paths.hooks)?;
    validate_version(&mut config)?;
    if !remove(&mut config.clone())? {
        return Ok(RuntimeHookStatus::NotConfigured);
    }
    let executable =
        std::env::current_exe().map_err(|_| "nah-executable-path-unavailable".to_owned())?;
    // Wiring is current exactly when install would leave the file alone, so
    // Nah's entry may sit anywhere among the user's other preToolUse hooks
    Ok(
        if !add(
            &mut config.clone(),
            desired_hook(&executable, FailurePolicy::Delegate)?,
        )? {
            RuntimeHookStatus::WiringCurrent
        } else if !add(
            &mut config.clone(),
            desired_hook(&executable, FailurePolicy::Block)?,
        )? {
            RuntimeHookStatus::WiringCurrentFailClosed
        } else {
            let mut hooks = config["hooks"]["preToolUse"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|hook| is_nah_hook(hook));
            let strict = hooks.next().is_some_and(|hook| {
                hook["command"]
                    .as_str()
                    .is_some_and(|command| command.ends_with(" hook cursor run --fail-closed"))
            }) && hooks.all(|hook| {
                hook["command"]
                    .as_str()
                    .is_some_and(|command| command.ends_with(" hook cursor run --fail-closed"))
            });
            RuntimeHookStatus::stale(if strict {
                FailurePolicy::Block
            } else {
                FailurePolicy::Delegate
            })
        },
    )
}

pub(crate) fn cursor_self_protection_paths() -> Result<Vec<PathBuf>, String> {
    let platform = live_state::host_platform();
    let home = live_state::home(platform)?;
    Ok(vec![CursorHookPaths::new(&home).hooks])
}

fn install_cursor_hook(
    home: &AbsolutePath,
    executable: &Path,
    policy: FailurePolicy,
) -> Result<PathBuf, String> {
    let paths = CursorHookPaths::new(home);
    let lock = acquire_hook_lock(&paths.lock, &CURSOR_HOOK_LOCK_ERRORS)?;
    reject_cursor_hook_symlinks(&paths)?;
    let mut config = load_cursor_hooks(&paths.hooks)?;
    validate_version(&mut config)?;
    let desired = desired_hook(executable, policy)?;
    if add(&mut config, desired)? {
        save_cursor_hooks(&paths.hooks, &config)?;
    }
    drop(lock);
    Ok(paths.hooks)
}

fn uninstall_cursor_hook(home: &AbsolutePath) -> Result<PathBuf, String> {
    let paths = CursorHookPaths::new(home);
    let lock = acquire_hook_lock(&paths.lock, &CURSOR_HOOK_LOCK_ERRORS)?;
    reject_cursor_hook_symlinks(&paths)?;
    if paths.hooks.exists() {
        let mut config = load_cursor_hooks(&paths.hooks)?;
        validate_version(&mut config)?;
        if remove(&mut config)? {
            save_cursor_hooks(&paths.hooks, &config)?;
        }
    }
    drop(lock);
    Ok(paths.hooks)
}

struct CursorHookPaths {
    hooks: PathBuf,
    lock: PathBuf,
    directories: Vec<PathBuf>,
}

impl CursorHookPaths {
    fn new(home: &AbsolutePath) -> Self {
        let home = PathBuf::from(home.as_str());
        let cursor = home.join(".cursor");
        Self {
            hooks: cursor.join("hooks.json"),
            lock: home.join(".nah/cursor-hook.lock"),
            directories: vec![cursor],
        }
    }
}

const CURSOR_HOOK_LOCK_ERRORS: HookLockErrorCodes = HookLockErrorCodes {
    invalid_path: "invalid-cursor-hook-lock-path",
    failed: "cursor-hook-lock-failed",
    permissions: "cursor-hook-permissions-failed",
};

const CURSOR_HOOKS_READ_ERRORS: HookJsonReadErrorCodes = HookJsonReadErrorCodes {
    read_failed: "cursor-hooks-read-failed",
    invalid: "invalid-cursor-hooks",
};

fn load_cursor_hooks(path: &Path) -> Result<Value, String> {
    reject_hook_path_symlink(path, "cursor-hooks-symlink-unsupported")?;
    read_hook_json_object(path, &CURSOR_HOOKS_READ_ERRORS)
}

fn validate_version(config: &mut Value) -> Result<(), String> {
    let root = config
        .as_object_mut()
        .ok_or_else(|| "invalid-cursor-hooks".to_owned())?;
    match root.get("version") {
        Some(Value::Number(version)) if version.as_u64() == Some(1) => Ok(()),
        None => {
            root.insert("version".into(), json!(1));
            Ok(())
        }
        _ => Err("invalid-cursor-hooks".into()),
    }
}

fn add(config: &mut Value, desired: Value) -> Result<bool, String> {
    let hooks = pre_tool_hooks(config)?;
    if hooks.iter().filter(|hook| is_nah_hook(hook)).count() == 1
        && hooks.iter().any(|hook| hook == &desired)
    {
        return Ok(false);
    }
    hooks.retain(|hook| !is_nah_hook(hook));
    hooks.push(desired);
    Ok(true)
}

fn remove(config: &mut Value) -> Result<bool, String> {
    let root = config
        .as_object_mut()
        .ok_or_else(|| "invalid-cursor-hooks".to_owned())?;
    let Some(hooks_value) = root.get_mut("hooks") else {
        return Ok(false);
    };
    let hooks = hooks_value
        .as_object_mut()
        .ok_or_else(|| "invalid-cursor-hooks".to_owned())?;
    let Some(pre_tool_use) = hooks.get_mut("preToolUse") else {
        return Ok(false);
    };
    let pre_tool_use = pre_tool_use
        .as_array_mut()
        .ok_or_else(|| "invalid-cursor-hooks".to_owned())?;
    if pre_tool_use.iter().any(|hook| !hook.is_object()) {
        return Err("invalid-cursor-hooks".into());
    }
    let before = pre_tool_use.len();
    pre_tool_use.retain(|hook| !is_nah_hook(hook));
    let changed = pre_tool_use.len() != before;
    if changed && pre_tool_use.is_empty() {
        hooks.remove("preToolUse");
    }
    if changed && hooks.is_empty() {
        root.remove("hooks");
    }
    Ok(changed)
}

fn pre_tool_hooks(config: &mut Value) -> Result<&mut Vec<Value>, String> {
    let root = config
        .as_object_mut()
        .ok_or_else(|| "invalid-cursor-hooks".to_owned())?;
    let hooks = root
        .entry("hooks")
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
        .ok_or_else(|| "invalid-cursor-hooks".to_owned())?;
    let pre_tool_use = hooks
        .entry("preToolUse")
        .or_insert_with(|| Value::Array(vec![]))
        .as_array_mut()
        .ok_or_else(|| "invalid-cursor-hooks".to_owned())?;
    if pre_tool_use.iter().any(|hook| !hook.is_object()) {
        return Err("invalid-cursor-hooks".into());
    }
    Ok(pre_tool_use)
}

fn desired_hook(executable: &Path, policy: FailurePolicy) -> Result<Value, String> {
    let executable = executable
        .to_str()
        .ok_or_else(|| "invalid-nah-executable-path".to_owned())?;
    let command = if cfg!(windows) {
        format!(
            "\"{executable}\" hook cursor run{}",
            policy.command_suffix()
        )
    } else {
        format!(
            "{} hook cursor run{}",
            quote_posix_shell_word(executable),
            policy.command_suffix()
        )
    };
    Ok(json!({
        "command": command,
        "matcher": "*",
        "timeout": 5
    }))
}

fn is_nah_hook(hook: &Value) -> bool {
    let Some(command) = hook.get("command").and_then(Value::as_str) else {
        return false;
    };
    let command = command.strip_suffix(" --fail-closed").unwrap_or(command);
    let Some(executable) = command.strip_suffix(" hook cursor run") else {
        return false;
    };
    let executable = executable.to_ascii_lowercase();
    hook_config::is_one_quoted_word(&executable)
        && ((executable.starts_with('\'') && executable.ends_with("/nah'"))
            || (executable.starts_with('"')
                && (executable.ends_with("\\nah.exe\"") || executable.ends_with("/nah.exe\""))))
}

const CURSOR_HOOKS_WRITE_ERRORS: HookFileWriteErrorCodes = HookFileWriteErrorCodes {
    invalid_path: "invalid-cursor-hooks-path",
    write_failed: "cursor-hooks-write-failed",
    permissions: "cursor-hook-permissions-failed",
    sync_failed: "cursor-hook-sync-failed",
};

fn save_cursor_hooks(path: &Path, config: &Value) -> Result<(), String> {
    reject_hook_path_symlink(path, "cursor-hooks-symlink-unsupported")?;
    write_hook_json_atomically(path, config, &CURSOR_HOOKS_WRITE_ERRORS)
}

fn reject_cursor_hook_symlinks(paths: &CursorHookPaths) -> Result<(), String> {
    for directory in &paths.directories {
        reject_hook_path_symlink(directory, "cursor-hooks-symlink-unsupported")?;
    }
    reject_hook_path_symlink(&paths.hooks, "cursor-hooks-symlink-unsupported")
}
