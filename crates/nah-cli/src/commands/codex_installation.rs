//! Installs and removes nah's user-level Codex PreToolUse hook.

use std::path::{Path, PathBuf};

use nah_proto::ctx::AbsolutePath;
use serde_json::{Value, json};

use crate::{live_state, runtime::FailurePolicy};

use super::hook_config;
use super::hook_paths::{
    HookFileWriteErrorCodes, HookJsonReadErrorCodes, HookLockErrorCodes, acquire_hook_lock,
    read_hook_json_object, write_hook_json_atomically,
};
use super::shell_word::quote_posix_shell_word;
use super::{RuntimeHookStatus, RuntimeMutation};

pub(crate) fn mutate_codex_hook(
    install: bool,
    policy: FailurePolicy,
) -> Result<RuntimeMutation, String> {
    reject_custom_home()?;
    let platform = live_state::host_platform();
    let path = live_state::home(platform).and_then(|home| {
        if install {
            let executable = std::env::current_exe()
                .map_err(|_| "nah-executable-path-unavailable".to_owned())?;
            install_codex_hook(&home, &executable, policy)
        } else {
            uninstall_codex_hook(&home)
        }
    })?;
    Ok(RuntimeMutation::new(
        install,
        "Codex hook",
        path,
        Some("Open Codex, run /hooks, and trust the new hook before use."),
    ))
}

pub(crate) fn codex_hook_status() -> Result<RuntimeHookStatus, String> {
    reject_custom_home()?;
    let platform = live_state::host_platform();
    let home = live_state::home(platform)?;
    let paths = CodexHookPaths::new(&home);
    reject_codex_hook_symlinks(&paths)?;
    let hooks = load_codex_hooks(&paths.hooks)?;
    let executable =
        std::env::current_exe().map_err(|_| "nah-executable-path-unavailable".to_owned())?;
    hook_config::inspect_modes(
        &hooks,
        &desired_handler(&executable, FailurePolicy::Delegate)?,
        &desired_handler(&executable, FailurePolicy::Block)?,
        is_nah_handler,
        is_fail_closed_handler,
        "invalid-codex-hooks",
    )
}

pub(crate) fn codex_self_protection_paths() -> Result<Vec<PathBuf>, String> {
    reject_custom_home()?;
    let platform = live_state::host_platform();
    let home = live_state::home(platform)?;
    let paths = CodexHookPaths::new(&home);
    Ok(vec![
        paths.hooks,
        PathBuf::from(home.as_str()).join(".codex/config.toml"),
    ])
}

fn reject_custom_home() -> Result<(), String> {
    if std::env::var_os("CODEX_HOME").is_some() {
        Err("custom-CODEX_HOME-unsupported".into())
    } else {
        Ok(())
    }
}

fn install_codex_hook(
    home: &AbsolutePath,
    executable: &Path,
    policy: FailurePolicy,
) -> Result<PathBuf, String> {
    let paths = CodexHookPaths::new(home);
    let lock = acquire_hook_lock(&paths.lock, &CODEX_HOOK_LOCK_ERRORS)?;
    reject_codex_hook_symlinks(&paths)?;
    let mut hooks = load_codex_hooks(&paths.hooks)?;
    let desired = desired_handler(executable, policy)?;
    if hook_config::add(&mut hooks, desired, is_nah_handler, "invalid-codex-hooks")? {
        save_codex_hooks(&paths.hooks, &hooks)?;
    }
    drop(lock);
    Ok(paths.hooks)
}

fn uninstall_codex_hook(home: &AbsolutePath) -> Result<PathBuf, String> {
    let paths = CodexHookPaths::new(home);
    let lock = acquire_hook_lock(&paths.lock, &CODEX_HOOK_LOCK_ERRORS)?;
    reject_codex_hook_symlinks(&paths)?;
    if paths.hooks.exists() {
        let mut hooks = load_codex_hooks(&paths.hooks)?;
        if hook_config::remove(&mut hooks, is_nah_handler, "invalid-codex-hooks")? {
            save_codex_hooks(&paths.hooks, &hooks)?;
        }
    }
    drop(lock);
    Ok(paths.hooks)
}

struct CodexHookPaths {
    hooks: PathBuf,
    lock: PathBuf,
    directories: Vec<PathBuf>,
}

impl CodexHookPaths {
    fn new(home: &AbsolutePath) -> Self {
        let home = PathBuf::from(home.as_str());
        let codex = home.join(".codex");
        Self {
            hooks: codex.join("hooks.json"),
            lock: home.join(".nah/codex-hook.lock"),
            directories: vec![codex],
        }
    }
}

const CODEX_HOOK_LOCK_ERRORS: HookLockErrorCodes = HookLockErrorCodes {
    invalid_path: "invalid-codex-hook-lock-path",
    failed: "codex-hook-lock-failed",
    permissions: "codex-hook-permissions-failed",
};

const CODEX_HOOKS_READ_ERRORS: HookJsonReadErrorCodes = HookJsonReadErrorCodes {
    read_failed: "codex-hooks-read-failed",
    invalid: "invalid-codex-hooks",
};

fn load_codex_hooks(path: &Path) -> Result<Value, String> {
    reject_codex_hooks_symlink(path)?;
    read_hook_json_object(path, &CODEX_HOOKS_READ_ERRORS)
}

const CODEX_HOOKS_WRITE_ERRORS: HookFileWriteErrorCodes = HookFileWriteErrorCodes {
    invalid_path: "invalid-codex-hooks-path",
    write_failed: "codex-hooks-write-failed",
    permissions: "codex-hook-permissions-failed",
    sync_failed: "codex-hook-sync-failed",
};

fn save_codex_hooks(path: &Path, hooks: &Value) -> Result<(), String> {
    reject_codex_hooks_symlink(path)?;
    write_hook_json_atomically(path, hooks, &CODEX_HOOKS_WRITE_ERRORS)
}

fn reject_codex_hooks_symlink(path: &Path) -> Result<(), String> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err("codex-hooks-symlink-unsupported".into())
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err("codex-hooks-read-failed".into()),
    }
}

fn reject_codex_hook_symlinks(paths: &CodexHookPaths) -> Result<(), String> {
    for directory in &paths.directories {
        reject_codex_hooks_symlink(directory)?;
    }
    reject_codex_hooks_symlink(&paths.hooks)
}

fn desired_handler(executable: &Path, policy: FailurePolicy) -> Result<Value, String> {
    let executable = executable
        .to_str()
        .ok_or_else(|| "invalid-nah-executable-path".to_owned())?;
    let command = if cfg!(windows) {
        format!("\"{executable}\" hook codex run{}", policy.command_suffix())
    } else {
        format!(
            "{} hook codex run{}",
            quote_posix_shell_word(executable),
            policy.command_suffix()
        )
    };
    Ok(json!({
        "type": "command",
        "command": command,
        "timeout": 5
    }))
}

fn is_nah_handler(handler: &Value) -> bool {
    let Some(handler) = handler.as_object() else {
        return false;
    };
    if handler.get("type").and_then(Value::as_str) != Some("command") {
        return false;
    }
    let Some(command) = handler.get("command").and_then(Value::as_str) else {
        return false;
    };
    let command = command.strip_suffix(" --fail-closed").unwrap_or(command);
    let Some(executable) = command.strip_suffix(" hook codex run") else {
        return false;
    };
    let executable = executable.to_ascii_lowercase();
    hook_config::is_one_quoted_word(&executable)
        && ((executable.starts_with('\'') && executable.ends_with("/nah'"))
            || (executable.starts_with('"')
                && (executable.ends_with("\\nah.exe\"") || executable.ends_with("/nah.exe\""))))
}

fn is_fail_closed_handler(handler: &Value) -> bool {
    handler
        .get("command")
        .and_then(Value::as_str)
        .is_some_and(|command| command.ends_with(" hook codex run --fail-closed"))
}
