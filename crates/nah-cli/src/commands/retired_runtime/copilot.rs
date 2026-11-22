//! Removes the GitHub Copilot hook file of Nah 1.x.

use std::fs::File;
use std::path::{Path, PathBuf};

use nah_proto::ctx::AbsolutePath;
use serde_json::Value;

use crate::live_state;

use super::super::RuntimeMutation;
use super::super::hook_config;
use super::super::hook_paths::{
    HookLockErrorCodes, acquire_hook_lock_in_unlinked_directory, reject_hook_path_symlink,
};

pub(super) fn uninstall() -> Result<RuntimeMutation, String> {
    reject_custom_copilot_home()?;
    let platform = live_state::host_platform();
    let path = live_state::home(platform).and_then(|home| uninstall_copilot_hook(&home))?;
    Ok(RuntimeMutation::new(false, "Copilot hook", path, None))
}

fn uninstall_copilot_hook(home: &AbsolutePath) -> Result<PathBuf, String> {
    let paths = CopilotHookPaths::new(home);
    let lock = acquire_hook_lock_in_unlinked_directory(&paths.lock, &COPILOT_HOOK_LOCK_ERRORS)?;
    reject_copilot_hook_symlinks(&paths)?;
    if paths.hook.exists() {
        let configured = load_copilot_hook(&paths.hook)?;
        if !is_owned_copilot_hook(&configured) {
            return Err("copilot-hook-file-conflict".into());
        }
        std::fs::remove_file(&paths.hook).map_err(|_| "copilot-hook-remove-failed")?;
    }
    drop(lock);
    Ok(paths.hook)
}

struct CopilotHookPaths {
    hook: PathBuf,
    lock: PathBuf,
    directories: Vec<PathBuf>,
}

impl CopilotHookPaths {
    fn new(home: &AbsolutePath) -> Self {
        let home = PathBuf::from(home.as_str());
        let copilot = home.join(".copilot");
        Self {
            hook: copilot.join("hooks/nah.json"),
            lock: home.join(".nah/copilot-hook.lock"),
            directories: vec![copilot.clone(), copilot.join("hooks")],
        }
    }
}

fn reject_custom_copilot_home() -> Result<(), String> {
    if std::env::var_os("COPILOT_HOME").is_some() {
        Err("custom-copilot-home-unsupported".into())
    } else {
        Ok(())
    }
}

/// The events of Nah's post-call hook.
const POST_EVENTS: [&str; 2] = ["postToolUse", "postToolUseFailure"];

fn load_copilot_hook(path: &Path) -> Result<Value, String> {
    reject_hook_path_symlink(path, "copilot-hook-symlink-unsupported")?;
    let file = File::open(path).map_err(|_| "copilot-hook-read-failed")?;
    serde_json::from_reader(file).map_err(|_| "invalid-copilot-hook".into())
}

fn is_owned_copilot_hook(config: &Value) -> bool {
    let Some(root) = config.as_object() else {
        return false;
    };
    let Some(hooks) = config["hooks"].as_object() else {
        return false;
    };
    let owned_entry = |entries: &Value| {
        entries.as_array().is_some_and(|entries| {
            entries.len() == 1
                && entries[0].as_object().is_some_and(|entry| {
                    entry
                        .keys()
                        .all(|key| matches!(key.as_str(), "type" | "command" | "timeoutSec"))
                })
                && entries[0]["type"] == "command"
                && entries[0]["command"]
                    .as_str()
                    .is_some_and(is_owned_copilot_command)
        })
    };
    root.keys()
        .all(|key| matches!(key.as_str(), "version" | "hooks"))
        && hooks.contains_key("preToolUse")
        && hooks.iter().all(|(event, entries)| {
            (event == "preToolUse" || POST_EVENTS.contains(&event.as_str())) && owned_entry(entries)
        })
}

fn is_owned_copilot_command(command: &str) -> bool {
    let command = command.strip_suffix(" --fail-closed").unwrap_or(command);
    let Some(executable) = command.strip_suffix(" hook copilot run") else {
        return false;
    };
    let executable = executable.to_ascii_lowercase();
    hook_config::is_one_quoted_word(&executable)
        && ((executable.starts_with('\'') && executable.ends_with("/nah'"))
            || (executable.starts_with('"')
                && (executable.ends_with("\\nah.exe\"") || executable.ends_with("/nah.exe\""))))
}

const COPILOT_HOOK_LOCK_ERRORS: HookLockErrorCodes = HookLockErrorCodes {
    invalid_path: "invalid-copilot-hook-lock-path",
    failed: "copilot-hook-lock-failed",
    permissions: "copilot-hook-permissions-failed",
};

fn reject_copilot_hook_symlinks(paths: &CopilotHookPaths) -> Result<(), String> {
    for directory in &paths.directories {
        reject_hook_path_symlink(directory, "copilot-hook-symlink-unsupported")?;
    }
    reject_hook_path_symlink(&paths.hook, "copilot-hook-symlink-unsupported")
}
