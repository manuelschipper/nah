//! Installs and removes nah's user-level Cursor hooks: the preToolUse one
//! that decides, and the postToolUse and postToolUseFailure ones that
//! refresh save-then-run's rolling copy and settle session memory.

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
    validate_cursor_hooks_version(&mut config)?;
    if !remove_cursor_hooks(&mut config.clone())? {
        return Ok(RuntimeHookStatus::NotConfigured);
    }
    let executable =
        std::env::current_exe().map_err(|_| "nah-executable-path-unavailable".to_owned())?;
    // Wiring is current exactly when install would leave the file alone, so
    // Nah's entries may sit anywhere among the user's other hooks
    Ok(
        if !set_cursor_hooks(&mut config.clone(), &executable, FailurePolicy::Delegate)? {
            RuntimeHookStatus::WiringCurrent
        } else if !set_cursor_hooks(&mut config.clone(), &executable, FailurePolicy::Block)? {
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
    validate_cursor_hooks_version(&mut config)?;
    if set_cursor_hooks(&mut config, executable, policy)? {
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
        validate_cursor_hooks_version(&mut config)?;
        if remove_cursor_hooks(&mut config)? {
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

/// The events of Nah's post-call handler.
const POST_EVENTS: [&str; 2] = ["postToolUse", "postToolUseFailure"];

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

fn validate_cursor_hooks_version(config: &mut Value) -> Result<(), String> {
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

/// Makes Nah's entries the ones `policy` installs, the pre-call one and
/// the post-call ones, and reports whether that changed `config`.
fn set_cursor_hooks(
    config: &mut Value,
    executable: &Path,
    policy: FailurePolicy,
) -> Result<bool, String> {
    let mut changed = add_cursor_hook(
        config,
        "preToolUse",
        desired_cursor_hook(executable, policy)?,
    )?;
    for event in POST_EVENTS {
        changed |= add_cursor_hook(config, event, desired_cursor_post_hook(executable)?)?;
    }
    Ok(changed)
}

fn add_cursor_hook(config: &mut Value, event: &str, desired: Value) -> Result<bool, String> {
    let hooks = cursor_event_hooks(config, event)?;
    if hooks.iter().filter(|hook| is_nah_hook(hook)).count() == 1
        && hooks.iter().any(|hook| hook == &desired)
    {
        return Ok(false);
    }
    hooks.retain(|hook| !is_nah_hook(hook));
    hooks.push(desired);
    Ok(true)
}

/// Removes Nah's entries from every event it installs one under, and
/// reports whether there were any.
fn remove_cursor_hooks(config: &mut Value) -> Result<bool, String> {
    let mut changed = false;
    for event in ["preToolUse"].into_iter().chain(POST_EVENTS) {
        changed |= remove_cursor_hook(config, event)?;
    }
    Ok(changed)
}

fn remove_cursor_hook(config: &mut Value, event: &str) -> Result<bool, String> {
    let root = config
        .as_object_mut()
        .ok_or_else(|| "invalid-cursor-hooks".to_owned())?;
    let Some(hooks_value) = root.get_mut("hooks") else {
        return Ok(false);
    };
    let hooks = hooks_value
        .as_object_mut()
        .ok_or_else(|| "invalid-cursor-hooks".to_owned())?;
    let Some(entries) = hooks.get_mut(event) else {
        return Ok(false);
    };
    let entries = entries
        .as_array_mut()
        .ok_or_else(|| "invalid-cursor-hooks".to_owned())?;
    if entries.iter().any(|hook| !hook.is_object()) {
        return Err("invalid-cursor-hooks".into());
    }
    let before = entries.len();
    entries.retain(|hook| !is_nah_hook(hook));
    let changed = entries.len() != before;
    if changed && entries.is_empty() {
        hooks.remove(event);
    }
    if changed && hooks.is_empty() {
        root.remove("hooks");
    }
    Ok(changed)
}

fn cursor_event_hooks<'a>(
    config: &'a mut Value,
    event: &str,
) -> Result<&'a mut Vec<Value>, String> {
    let root = config
        .as_object_mut()
        .ok_or_else(|| "invalid-cursor-hooks".to_owned())?;
    let hooks = root
        .entry("hooks")
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
        .ok_or_else(|| "invalid-cursor-hooks".to_owned())?;
    let entries = hooks
        .entry(event)
        .or_insert_with(|| Value::Array(vec![]))
        .as_array_mut()
        .ok_or_else(|| "invalid-cursor-hooks".to_owned())?;
    if entries.iter().any(|hook| !hook.is_object()) {
        return Err("invalid-cursor-hooks".into());
    }
    Ok(entries)
}

/// What Cursor does when the hook crashes, times out or prints nothing
/// follows the policy. Fail-open lets the call run, as in 1.x, so a discard
/// save-then-run would have saved may run without a fresh copy; fail-closed
/// sets Cursor's own `failClosed` to block it. The adapter answers every
/// call it hands back with `{}`, so `failClosed` never mistakes a delegate
/// for a failure.
fn desired_cursor_hook(executable: &Path, policy: FailurePolicy) -> Result<Value, String> {
    let mut hook = json!({
        "command": cursor_command(executable, policy.command_suffix())?,
        "matcher": "*",
        "timeout": 5
    });
    if policy == FailurePolicy::Block {
        hook["failClosed"] = json!(true);
    }
    Ok(hook)
}

/// The post-call entry. Cursor documents no background option, so the
/// refresh runs while Cursor may wait; it stops at its own deadline.
fn desired_cursor_post_hook(executable: &Path) -> Result<Value, String> {
    Ok(json!({
        "command": cursor_command(executable, "")?,
        "matcher": "*",
        "timeout": 60
    }))
}

/// The shell command Cursor runs for a Nah hook: `nah hook cursor run` and
/// `suffix`.
fn cursor_command(executable: &Path, suffix: &str) -> Result<String, String> {
    let executable = executable
        .to_str()
        .ok_or_else(|| "invalid-nah-executable-path".to_owned())?;
    Ok(if cfg!(windows) {
        format!("\"{executable}\" hook cursor run{suffix}")
    } else {
        format!(
            "{} hook cursor run{suffix}",
            quote_posix_shell_word(executable)
        )
    })
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
