//! Installs and removes nah's user-level Devin PreToolUse hook.

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

const EVENTS: [&str; 3] = ["PreToolUse", "PermissionRequest", "PostToolUse"];

pub(crate) fn mutate_devin_hook(
    install: bool,
    policy: FailurePolicy,
) -> Result<RuntimeMutation, String> {
    let platform = live_state::host_platform();
    let path = live_state::home(platform).and_then(|home| {
        if install {
            let executable = std::env::current_exe()
                .map_err(|_| "nah-executable-path-unavailable".to_owned())?;
            install_devin_hook(&home, &executable, policy)
        } else {
            uninstall_devin_hook(&home)
        }
    })?;
    Ok(RuntimeMutation::new(
        install,
        "Devin hook",
        path,
        Some("Restart Devin, then run /hooks to verify the hook."),
    ))
}

pub(crate) fn devin_hook_status() -> Result<RuntimeHookStatus, String> {
    let platform = live_state::host_platform();
    let home = live_state::home(platform)?;
    let paths = DevinHookPaths::new(&home);
    reject_devin_hook_symlinks(&paths)?;
    let mut config = load_devin_config(&paths.config)?;
    validate_devin_config_version(&mut config)?;
    let mut base = config.clone();
    if !remove_owned_devin_handlers(&mut base)? {
        return Ok(RuntimeHookStatus::NotConfigured);
    }
    let executable =
        std::env::current_exe().map_err(|_| "nah-executable-path-unavailable".to_owned())?;
    let mut delegate = base.clone();
    devin_pre_tool_hooks(&mut delegate)?.push(json!({
        "matcher": "",
        "hooks": [desired_devin_handler(&executable, FailurePolicy::Delegate)?]
    }));
    let mut strict = base;
    devin_pre_tool_hooks(&mut strict)?.push(json!({
        "matcher": "",
        "hooks": [desired_devin_handler(&executable, FailurePolicy::Block)?]
    }));
    Ok(if delegate == config {
        RuntimeHookStatus::WiringCurrent
    } else if strict == config {
        RuntimeHookStatus::WiringCurrentFailClosed
    } else {
        let mut handlers = config["hooks"]["PreToolUse"]
            .as_array()
            .into_iter()
            .flatten()
            .flat_map(|group| group["hooks"].as_array().into_iter().flatten())
            .filter(|handler| is_owned_devin_handler(handler));
        let strict = handlers.next().is_some_and(|handler| {
            handler["command"]
                .as_str()
                .is_some_and(|command| command.ends_with(" hook devin run --fail-closed"))
        }) && handlers.all(|handler| {
            handler["command"]
                .as_str()
                .is_some_and(|command| command.ends_with(" hook devin run --fail-closed"))
        });
        RuntimeHookStatus::stale(if strict {
            FailurePolicy::Block
        } else {
            FailurePolicy::Delegate
        })
    })
}

pub(crate) fn devin_self_protection_paths() -> Result<Vec<PathBuf>, String> {
    let platform = live_state::host_platform();
    let home = live_state::home(platform)?;
    Ok(vec![DevinHookPaths::new(&home).config])
}

fn install_devin_hook(
    home: &AbsolutePath,
    executable: &Path,
    policy: FailurePolicy,
) -> Result<PathBuf, String> {
    let paths = DevinHookPaths::new(home);
    let lock = acquire_hook_lock(&paths.lock, &DEVIN_HOOK_LOCK_ERRORS)?;
    reject_devin_hook_symlinks(&paths)?;
    let mut config = load_devin_config(&paths.config)?;
    validate_devin_config_version(&mut config)?;
    let original = config.clone();
    remove_owned_devin_handlers(&mut config)?;
    devin_pre_tool_hooks(&mut config)?.push(json!({
        "matcher": "",
        "hooks": [desired_devin_handler(executable, policy)?]
    }));
    if config != original {
        save_devin_config(&paths.config, &config)?;
    }
    drop(lock);
    Ok(paths.config)
}

fn uninstall_devin_hook(home: &AbsolutePath) -> Result<PathBuf, String> {
    let paths = DevinHookPaths::new(home);
    let lock = acquire_hook_lock(&paths.lock, &DEVIN_HOOK_LOCK_ERRORS)?;
    reject_devin_hook_symlinks(&paths)?;
    if paths.config.exists() {
        let mut config = load_devin_config(&paths.config)?;
        validate_devin_config_version(&mut config)?;
        if remove_owned_devin_handlers(&mut config)? {
            save_devin_config(&paths.config, &config)?;
        }
    }
    drop(lock);
    Ok(paths.config)
}

struct DevinHookPaths {
    config: PathBuf,
    lock: PathBuf,
    directories: Vec<PathBuf>,
}

impl DevinHookPaths {
    fn new(home: &AbsolutePath) -> Self {
        let home = PathBuf::from(home.as_str());
        if cfg!(windows) {
            let devin = home.join("AppData/Roaming/devin");
            Self {
                config: devin.join("config.json"),
                lock: home.join(".nah/devin-hook.lock"),
                directories: vec![devin],
            }
        } else {
            let devin = home.join(".config/devin");
            Self {
                config: devin.join("config.json"),
                lock: home.join(".nah/devin-hook.lock"),
                directories: vec![devin],
            }
        }
    }
}

const DEVIN_HOOK_LOCK_ERRORS: HookLockErrorCodes = HookLockErrorCodes {
    invalid_path: "invalid-devin-hook-lock-path",
    failed: "devin-hook-lock-failed",
    permissions: "devin-hook-permissions-failed",
};

const DEVIN_CONFIG_READ_ERRORS: HookJsonReadErrorCodes = HookJsonReadErrorCodes {
    read_failed: "devin-config-read-failed",
    invalid: "invalid-devin-config",
};

fn load_devin_config(path: &Path) -> Result<Value, String> {
    reject_hook_path_symlink(path, "devin-config-symlink-unsupported")?;
    read_hook_json_object(path, &DEVIN_CONFIG_READ_ERRORS)
}

fn validate_devin_config_version(config: &mut Value) -> Result<(), String> {
    let root = config
        .as_object_mut()
        .ok_or_else(|| "invalid-devin-config".to_owned())?;
    match root.get("version") {
        Some(Value::Number(version)) if version.as_u64() == Some(1) => Ok(()),
        None => {
            root.insert("version".into(), json!(1));
            Ok(())
        }
        _ => Err("invalid-devin-config".into()),
    }
}

fn remove_owned_devin_handlers(config: &mut Value) -> Result<bool, String> {
    let root = config
        .as_object_mut()
        .ok_or_else(|| "invalid-devin-config".to_owned())?;
    let Some(hooks_value) = root.get_mut("hooks") else {
        return Ok(false);
    };
    let hooks = hooks_value
        .as_object_mut()
        .ok_or_else(|| "invalid-devin-config".to_owned())?;
    let mut changed = false;
    let mut empty_events = Vec::new();
    for event in EVENTS {
        let Some(groups_value) = hooks.get_mut(event) else {
            continue;
        };
        let groups = groups_value
            .as_array_mut()
            .ok_or_else(|| "invalid-devin-config".to_owned())?;
        for group in groups.iter() {
            let group = group
                .as_object()
                .ok_or_else(|| "invalid-devin-config".to_owned())?;
            if group.get("hooks").is_some_and(|value| !value.is_array()) {
                return Err("invalid-devin-config".into());
            }
        }
        groups.retain_mut(|group| {
            let Some(handlers) = group
                .as_object_mut()
                .and_then(|group| group.get_mut("hooks"))
                .and_then(Value::as_array_mut)
            else {
                return true;
            };
            let before = handlers.len();
            handlers.retain(|handler| !is_owned_devin_handler(handler));
            let removed = handlers.len() != before;
            changed |= removed;
            !removed || !handlers.is_empty()
        });
        if groups.is_empty() {
            empty_events.push(event);
        }
    }
    for event in empty_events {
        hooks.remove(event);
    }
    if changed && hooks.is_empty() {
        root.remove("hooks");
    }
    Ok(changed)
}

fn devin_pre_tool_hooks(config: &mut Value) -> Result<&mut Vec<Value>, String> {
    let root = config
        .as_object_mut()
        .ok_or_else(|| "invalid-devin-config".to_owned())?;
    let hooks = root
        .entry("hooks")
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
        .ok_or_else(|| "invalid-devin-config".to_owned())?;
    hooks
        .entry("PreToolUse")
        .or_insert_with(|| Value::Array(vec![]))
        .as_array_mut()
        .ok_or_else(|| "invalid-devin-config".to_owned())
}

fn desired_devin_handler(executable: &Path, policy: FailurePolicy) -> Result<Value, String> {
    let executable = executable
        .to_str()
        .ok_or_else(|| "invalid-nah-executable-path".to_owned())?;
    let command = if cfg!(windows) {
        format!("\"{executable}\" hook devin run{}", policy.command_suffix())
    } else {
        format!(
            "{} hook devin run{}",
            quote_posix_shell_word(executable),
            policy.command_suffix()
        )
    };
    Ok(json!({"type":"command","command":command,"timeout":5}))
}

fn is_owned_devin_handler(handler: &Value) -> bool {
    let Some(command) = handler
        .as_object()
        .filter(|handler| handler.get("type").and_then(Value::as_str) == Some("command"))
        .and_then(|handler| handler.get("command"))
        .and_then(Value::as_str)
    else {
        return false;
    };
    let command = command.strip_suffix(" --fail-closed").unwrap_or(command);
    command
        .strip_suffix(" hook devin run")
        .is_some_and(hook_config::is_quoted_nah_hook_executable)
        || command
            .strip_suffix(" \"_devin-hook\"")
            .or_else(|| command.strip_suffix(" '_devin-hook'"))
            .is_some_and(hook_config::is_quoted_nah_hook_executable)
}

const DEVIN_CONFIG_WRITE_ERRORS: HookFileWriteErrorCodes = HookFileWriteErrorCodes {
    invalid_path: "invalid-devin-config-path",
    write_failed: "devin-config-write-failed",
    permissions: "devin-hook-permissions-failed",
    sync_failed: "devin-hook-sync-failed",
};

fn save_devin_config(path: &Path, config: &Value) -> Result<(), String> {
    reject_hook_path_symlink(path, "devin-config-symlink-unsupported")?;
    write_hook_json_atomically(path, config, &DEVIN_CONFIG_WRITE_ERRORS)
}

fn reject_devin_hook_symlinks(paths: &DevinHookPaths) -> Result<(), String> {
    for directory in &paths.directories {
        reject_hook_path_symlink(directory, "devin-config-symlink-unsupported")?;
    }
    reject_hook_path_symlink(&paths.config, "devin-config-symlink-unsupported")
}
