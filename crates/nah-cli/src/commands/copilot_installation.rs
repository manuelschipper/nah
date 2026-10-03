//! Installs and removes nah's shared GitHub Copilot hook.

use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

use nah_proto::ctx::AbsolutePath;
use serde_json::{Value, json};

use crate::{live_state, runtime::FailurePolicy};

use super::hook_config;
use super::hook_paths::{
    HookLockErrorCodes, acquire_hook_lock_in_unlinked_directory, reject_hook_path_symlink,
};
use super::shell_word::quote_posix_shell_word;
use super::{RuntimeHookStatus, RuntimeMutation};
use crate::private_files::{restrict_file_to_owner, sync_parent_directory};

pub(crate) fn mutate_copilot_hook(
    install: bool,
    policy: FailurePolicy,
) -> Result<RuntimeMutation, String> {
    reject_custom_home()?;
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
        "Copilot hook",
        path,
        Some("Restart Copilot CLI or reload VS Code, then inspect the loaded hooks."),
    ))
}

pub(crate) fn copilot_hook_status() -> Result<RuntimeHookStatus, String> {
    reject_custom_home()?;
    let platform = live_state::host_platform();
    let home = live_state::home(platform)?;
    let paths = CopilotHookPaths::new(&home);
    reject_symlinks(&paths)?;
    if !paths.hook.exists() {
        return Ok(RuntimeHookStatus::NotConfigured);
    }
    let configured = load(&paths.hook)?;
    let executable =
        std::env::current_exe().map_err(|_| "nah-executable-path-unavailable".to_owned())?;
    if configured == desired_hook(&executable, FailurePolicy::Delegate)? {
        Ok(RuntimeHookStatus::WiringCurrent)
    } else if configured == desired_hook(&executable, FailurePolicy::Block)? {
        Ok(RuntimeHookStatus::WiringCurrentFailClosed)
    } else if is_owned(&configured) {
        Ok(RuntimeHookStatus::stale(
            if configured.to_string().contains("run --fail-closed") {
                FailurePolicy::Block
            } else {
                FailurePolicy::Delegate
            },
        ))
    } else {
        Err("copilot-hook-file-conflict".into())
    }
}

pub(crate) fn copilot_self_protection_paths() -> Result<Vec<PathBuf>, String> {
    reject_custom_home()?;
    let platform = live_state::host_platform();
    let home = live_state::home(platform)?;
    Ok(vec![
        CopilotHookPaths::new(&home).hook,
        PathBuf::from(home.as_str()).join(".copilot/settings.json"),
    ])
}

fn install_hook(
    home: &AbsolutePath,
    executable: &Path,
    policy: FailurePolicy,
) -> Result<PathBuf, String> {
    let paths = CopilotHookPaths::new(home);
    let lock = acquire_hook_lock_in_unlinked_directory(&paths.lock, &COPILOT_HOOK_LOCK_ERRORS)?;
    reject_symlinks(&paths)?;
    let desired = desired_hook(executable, policy)?;
    if paths.hook.exists() {
        let configured = load(&paths.hook)?;
        if configured == desired {
            drop(lock);
            return Ok(paths.hook);
        }
        if !is_owned(&configured) {
            return Err("copilot-hook-file-conflict".into());
        }
    }
    save(&paths.hook, &desired)?;
    drop(lock);
    Ok(paths.hook)
}

fn uninstall_hook(home: &AbsolutePath) -> Result<PathBuf, String> {
    let paths = CopilotHookPaths::new(home);
    let lock = acquire_hook_lock_in_unlinked_directory(&paths.lock, &COPILOT_HOOK_LOCK_ERRORS)?;
    reject_symlinks(&paths)?;
    if paths.hook.exists() {
        let configured = load(&paths.hook)?;
        if !is_owned(&configured) {
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

fn reject_custom_home() -> Result<(), String> {
    if std::env::var_os("COPILOT_HOME").is_some() {
        Err("custom-copilot-home-unsupported".into())
    } else {
        Ok(())
    }
}

fn desired_hook(executable: &Path, policy: FailurePolicy) -> Result<Value, String> {
    let executable = executable
        .to_str()
        .ok_or_else(|| "invalid-nah-executable-path".to_owned())?;
    let command = if cfg!(windows) {
        format!(
            "\"{executable}\" hook copilot run{}",
            policy.command_suffix()
        )
    } else {
        format!(
            "{} hook copilot run{}",
            quote_posix_shell_word(executable),
            policy.command_suffix()
        )
    };
    Ok(json!({
        "version":1,
        "hooks":{
            "preToolUse":[{
                "type":"command",
                "command":command,
                "timeoutSec":5
            }]
        }
    }))
}

fn load(path: &Path) -> Result<Value, String> {
    reject_hook_path_symlink(path, "copilot-hook-symlink-unsupported")?;
    let file = File::open(path).map_err(|_| "copilot-hook-read-failed")?;
    serde_json::from_reader(file).map_err(|_| "invalid-copilot-hook".into())
}

fn is_owned(config: &Value) -> bool {
    let Some(root) = config.as_object() else {
        return false;
    };
    let Some(hooks) = config["hooks"].as_object() else {
        return false;
    };
    let Some(entries) = hooks["preToolUse"].as_array() else {
        return false;
    };
    root.keys()
        .all(|key| matches!(key.as_str(), "version" | "hooks"))
        && hooks.keys().all(|key| key == "preToolUse")
        && entries.len() == 1
        && entries[0].as_object().is_some_and(|entry| {
            entry
                .keys()
                .all(|key| matches!(key.as_str(), "type" | "command" | "timeoutSec"))
        })
        && entries[0]["type"] == "command"
        && entries[0]["command"].as_str().is_some_and(is_owned_command)
}

fn is_owned_command(command: &str) -> bool {
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

fn reject_symlinks(paths: &CopilotHookPaths) -> Result<(), String> {
    for directory in &paths.directories {
        reject_hook_path_symlink(directory, "copilot-hook-symlink-unsupported")?;
    }
    reject_hook_path_symlink(&paths.hook, "copilot-hook-symlink-unsupported")
}

fn save(path: &Path, config: &Value) -> Result<(), String> {
    reject_hook_path_symlink(path, "copilot-hook-symlink-unsupported")?;
    let parent = path
        .parent()
        .ok_or_else(|| "invalid-copilot-hook-path".to_owned())?;
    std::fs::create_dir_all(parent).map_err(|_| "copilot-hook-write-failed")?;
    let mut temporary =
        tempfile::NamedTempFile::new_in(parent).map_err(|_| "copilot-hook-write-failed")?;
    restrict_file_to_owner(temporary.as_file())
        .map_err(|_| "copilot-hook-permissions-failed".to_owned())?;
    serde_json::to_writer_pretty(&mut temporary, config)
        .map_err(|_| "copilot-hook-write-failed")?;
    temporary
        .write_all(b"\n")
        .map_err(|_| "copilot-hook-write-failed")?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|_| "copilot-hook-write-failed")?;
    temporary
        .persist(path)
        .map_err(|_| "copilot-hook-write-failed")?;
    sync_parent_directory(parent).map_err(|_| "copilot-hook-sync-failed".to_owned())
}
