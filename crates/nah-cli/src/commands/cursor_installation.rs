//! Installs and removes nah's user-level Cursor preToolUse hook.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use nah_proto::ctx::AbsolutePath;
use serde_json::{Map, Value, json};

use crate::{live_state, runtime::FailurePolicy};

use super::hook_paths::reject_hook_path_symlink;
use super::shell_word::quote_posix_shell_word;
use super::{RuntimeHookStatus, RuntimeMutation};
use crate::private_files::{restrict_file_to_owner, sync_parent_directory};

pub(crate) fn mutate_cursor_hook(
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
    Ok(RuntimeMutation::new(install, "Cursor hook", path, None))
}

pub(crate) fn cursor_hook_status() -> Result<RuntimeHookStatus, String> {
    let platform = live_state::host_platform();
    let home = live_state::home(platform)?;
    let paths = CursorHookPaths::new(&home);
    reject_symlinks(&paths)?;
    let mut config = load(&paths.hooks)?;
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

fn install_hook(
    home: &AbsolutePath,
    executable: &Path,
    policy: FailurePolicy,
) -> Result<PathBuf, String> {
    let paths = CursorHookPaths::new(home);
    let lock = lock(&paths)?;
    reject_symlinks(&paths)?;
    let mut config = load(&paths.hooks)?;
    validate_version(&mut config)?;
    let desired = desired_hook(executable, policy)?;
    if add(&mut config, desired)? {
        save(&paths.hooks, &config)?;
    }
    drop(lock);
    Ok(paths.hooks)
}

fn uninstall_hook(home: &AbsolutePath) -> Result<PathBuf, String> {
    let paths = CursorHookPaths::new(home);
    let lock = lock(&paths)?;
    reject_symlinks(&paths)?;
    if paths.hooks.exists() {
        let mut config = load(&paths.hooks)?;
        validate_version(&mut config)?;
        if remove(&mut config)? {
            save(&paths.hooks, &config)?;
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

fn lock(paths: &CursorHookPaths) -> Result<File, String> {
    let parent = paths
        .lock
        .parent()
        .ok_or_else(|| "invalid-cursor-hook-lock-path".to_owned())?;
    std::fs::create_dir_all(parent).map_err(|_| "cursor-hook-lock-failed")?;
    reject_hook_path_symlink(&paths.lock, "cursor-hook-lock-failed")?;
    let mut options = OpenOptions::new();
    options.create(true).truncate(false).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(&paths.lock)
        .map_err(|_| "cursor-hook-lock-failed")?;
    restrict_file_to_owner(&file).map_err(|_| "cursor-hook-permissions-failed".to_owned())?;
    file.lock().map_err(|_| "cursor-hook-lock-failed")?;
    Ok(file)
}

fn load(path: &Path) -> Result<Value, String> {
    reject_hook_path_symlink(path, "cursor-hooks-symlink-unsupported")?;
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Value::Object(Map::new()));
        }
        Err(_) => return Err("cursor-hooks-read-failed".into()),
    };
    let value: Value =
        serde_json::from_reader(file).map_err(|_| "invalid-cursor-hooks".to_owned())?;
    if !value.is_object() {
        return Err("invalid-cursor-hooks".into());
    }
    Ok(value)
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
    (executable.starts_with('\'') && executable.ends_with("/nah'"))
        || (executable.starts_with('"')
            && (executable.ends_with("\\nah.exe\"") || executable.ends_with("/nah.exe\"")))
}

fn save(path: &Path, config: &Value) -> Result<(), String> {
    reject_hook_path_symlink(path, "cursor-hooks-symlink-unsupported")?;
    let parent = path
        .parent()
        .ok_or_else(|| "invalid-cursor-hooks-path".to_owned())?;
    std::fs::create_dir_all(parent).map_err(|_| "cursor-hooks-write-failed")?;
    let mut temporary =
        tempfile::NamedTempFile::new_in(parent).map_err(|_| "cursor-hooks-write-failed")?;
    restrict_file_to_owner(temporary.as_file())
        .map_err(|_| "cursor-hook-permissions-failed".to_owned())?;
    serde_json::to_writer_pretty(&mut temporary, config)
        .map_err(|_| "cursor-hooks-write-failed")?;
    temporary
        .write_all(b"\n")
        .map_err(|_| "cursor-hooks-write-failed")?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|_| "cursor-hooks-write-failed")?;
    temporary
        .persist(path)
        .map_err(|_| "cursor-hooks-write-failed")?;
    sync_parent_directory(parent).map_err(|_| "cursor-hook-sync-failed".to_owned())
}

fn reject_symlinks(paths: &CursorHookPaths) -> Result<(), String> {
    for directory in &paths.directories {
        reject_hook_path_symlink(directory, "cursor-hooks-symlink-unsupported")?;
    }
    reject_hook_path_symlink(&paths.hooks, "cursor-hooks-symlink-unsupported")
}
