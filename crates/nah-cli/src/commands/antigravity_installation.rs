//! Installs and removes nah's shared Antigravity PreToolUse hook.

use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

use nah_proto::ctx::AbsolutePath;
use serde_json::{Map, Value, json};

use crate::{live_state, runtime::FailurePolicy};

use super::hook_config;
use super::hook_paths::{
    HookLockErrorCodes, acquire_hook_lock_in_unlinked_directory, reject_hook_path_symlink,
};
use super::shell_word::quote_posix_shell_word;
use super::{RuntimeHookStatus, RuntimeMutation};
use crate::private_files::{restrict_file_to_owner, sync_parent_directory};

const HOOK_NAME: &str = "nah";
const HOOK_MATCHER: &str = "run_command|view_file|write_to_file|replace_file_content|multi_replace_file_content|list_dir|find_by_name|grep_search";

pub(crate) fn mutate_antigravity_hook(
    install: bool,
    policy: FailurePolicy,
) -> Result<RuntimeMutation, String> {
    let platform = live_state::host_platform();
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
        "Antigravity hook",
        path,
        Some("Restart Antigravity, then review the hook in /hooks."),
    ))
}

pub(crate) fn antigravity_hook_status() -> Result<RuntimeHookStatus, String> {
    let platform = live_state::host_platform();
    let home = live_state::home(platform)?;
    let paths = AntigravityHookPaths::new(&home);
    reject_hook_symlinks(&paths)?;
    let config = load(&paths.hooks)?;
    let Some(configured) = config.get(HOOK_NAME) else {
        return Ok(RuntimeHookStatus::NotConfigured);
    };
    let executable =
        std::env::current_exe().map_err(|_| "nah-executable-path-unavailable".to_owned())?;
    if configured == &desired_hook(&executable, FailurePolicy::Delegate)? {
        Ok(RuntimeHookStatus::WiringCurrent)
    } else if configured == &desired_hook(&executable, FailurePolicy::Block)? {
        Ok(RuntimeHookStatus::WiringCurrentFailClosed)
    } else if is_owned(configured) {
        Ok(RuntimeHookStatus::stale(if is_fail_closed(configured) {
            FailurePolicy::Block
        } else {
            FailurePolicy::Delegate
        }))
    } else {
        Err("antigravity-hook-name-conflict".into())
    }
}

pub(crate) fn antigravity_self_protection_paths() -> Result<Vec<PathBuf>, String> {
    let platform = live_state::host_platform();
    let home = live_state::home(platform)?;
    Ok(vec![AntigravityHookPaths::new(&home).hooks])
}

fn install_hook(
    home: &AbsolutePath,
    executable: &Path,
    policy: FailurePolicy,
) -> Result<PathBuf, String> {
    let paths = AntigravityHookPaths::new(home);
    let lock = acquire_hook_lock_in_unlinked_directory(&paths.lock, &ANTIGRAVITY_HOOK_LOCK_ERRORS)?;
    reject_hook_symlinks(&paths)?;
    let mut config = load(&paths.hooks)?;
    let desired = desired_hook(executable, policy)?;
    let root = config
        .as_object_mut()
        .ok_or_else(|| "invalid-antigravity-hooks".to_owned())?;
    match root.get(HOOK_NAME) {
        Some(configured) if configured == &desired => {}
        Some(configured) if !is_owned(configured) => {
            return Err("antigravity-hook-name-conflict".into());
        }
        _ => {
            root.insert(HOOK_NAME.into(), desired);
            save(&paths.hooks, &config)?;
        }
    }
    drop(lock);
    Ok(paths.hooks)
}

fn uninstall_hook(home: &AbsolutePath) -> Result<PathBuf, String> {
    let paths = AntigravityHookPaths::new(home);
    let lock = acquire_hook_lock_in_unlinked_directory(&paths.lock, &ANTIGRAVITY_HOOK_LOCK_ERRORS)?;
    reject_hook_symlinks(&paths)?;
    if paths.hooks.exists() {
        let mut config = load(&paths.hooks)?;
        let root = config
            .as_object_mut()
            .ok_or_else(|| "invalid-antigravity-hooks".to_owned())?;
        match root.get(HOOK_NAME) {
            Some(configured) if is_owned(configured) => {
                root.remove(HOOK_NAME);
                save(&paths.hooks, &config)?;
            }
            Some(_) => return Err("antigravity-hook-name-conflict".into()),
            None => {}
        }
    }
    drop(lock);
    Ok(paths.hooks)
}

struct AntigravityHookPaths {
    hooks: PathBuf,
    lock: PathBuf,
    hook_directories: Vec<PathBuf>,
}

impl AntigravityHookPaths {
    fn new(home: &AbsolutePath) -> Self {
        let home = PathBuf::from(home.as_str());
        let gemini = home.join(".gemini");
        let config = gemini.join("config");
        Self {
            hooks: config.join("hooks.json"),
            lock: home.join(".nah/antigravity-hook.lock"),
            hook_directories: vec![gemini, config],
        }
    }
}

const ANTIGRAVITY_HOOK_LOCK_ERRORS: HookLockErrorCodes = HookLockErrorCodes {
    invalid_path: "invalid-antigravity-hook-lock-path",
    failed: "antigravity-hook-lock-failed",
    permissions: "antigravity-hook-permissions-failed",
};

fn reject_hook_symlinks(paths: &AntigravityHookPaths) -> Result<(), String> {
    for directory in &paths.hook_directories {
        reject_hook_path_symlink(directory, "antigravity-hooks-symlink-unsupported")?;
    }
    reject_hook_path_symlink(&paths.hooks, "antigravity-hooks-symlink-unsupported")
}

fn load(path: &Path) -> Result<Value, String> {
    reject_hook_path_symlink(path, "antigravity-hooks-symlink-unsupported")?;
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Value::Object(Map::new()));
        }
        Err(_) => return Err("antigravity-hooks-read-failed".into()),
    };
    let value: Value =
        serde_json::from_reader(file).map_err(|_| "invalid-antigravity-hooks".to_owned())?;
    if !value.is_object() {
        return Err("invalid-antigravity-hooks".into());
    }
    Ok(value)
}

fn desired_hook(executable: &Path, policy: FailurePolicy) -> Result<Value, String> {
    let executable = executable
        .to_str()
        .ok_or_else(|| "invalid-nah-executable-path".to_owned())?;
    let command = if cfg!(windows) {
        format!(
            "\"{executable}\" hook antigravity run{}",
            policy.command_suffix()
        )
    } else {
        format!(
            "{} hook antigravity run{}",
            quote_posix_shell_word(executable),
            policy.command_suffix()
        )
    };
    Ok(json!({
        "enabled": true,
        "PreToolUse": [{
            "matcher": HOOK_MATCHER,
            "hooks": [{
                "type": "command",
                "command": command,
                "timeout": 5
            }]
        }]
    }))
}

fn is_owned(definition: &Value) -> bool {
    definition["PreToolUse"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|group| group["hooks"].as_array().into_iter().flatten())
        .filter_map(|handler| handler["command"].as_str())
        .any(is_owned_command)
}

fn is_fail_closed(definition: &Value) -> bool {
    let mut commands = definition["PreToolUse"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|group| group["hooks"].as_array().into_iter().flatten())
        .filter_map(|handler| handler["command"].as_str())
        .filter(|command| is_owned_command(command));
    commands
        .next()
        .is_some_and(|command| command.ends_with(" hook antigravity run --fail-closed"))
        && commands.all(|command| command.ends_with(" hook antigravity run --fail-closed"))
}

fn is_owned_command(command: &str) -> bool {
    let command = command.strip_suffix(" --fail-closed").unwrap_or(command);
    let Some(executable) = command.strip_suffix(" hook antigravity run") else {
        return false;
    };
    let executable = executable.to_ascii_lowercase();
    hook_config::is_one_quoted_word(&executable)
        && ((executable.starts_with('\'') && executable.ends_with("/nah'"))
            || (executable.starts_with('"')
                && (executable.ends_with("\\nah.exe\"") || executable.ends_with("/nah.exe\""))))
}

fn save(path: &Path, config: &Value) -> Result<(), String> {
    reject_hook_path_symlink(path, "antigravity-hooks-symlink-unsupported")?;
    let parent = path
        .parent()
        .ok_or_else(|| "invalid-antigravity-hooks-path".to_owned())?;
    std::fs::create_dir_all(parent).map_err(|_| "antigravity-hooks-write-failed")?;
    let mut temporary =
        tempfile::NamedTempFile::new_in(parent).map_err(|_| "antigravity-hooks-write-failed")?;
    restrict_file_to_owner(temporary.as_file())
        .map_err(|_| "antigravity-hook-permissions-failed".to_owned())?;
    serde_json::to_writer_pretty(&mut temporary, config)
        .map_err(|_| "antigravity-hooks-write-failed")?;
    temporary
        .write_all(b"\n")
        .map_err(|_| "antigravity-hooks-write-failed")?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|_| "antigravity-hooks-write-failed")?;
    temporary
        .persist(path)
        .map_err(|_| "antigravity-hooks-write-failed")?;
    sync_parent_directory(parent).map_err(|_| "antigravity-hook-sync-failed".to_owned())
}
