//! Installs and removes nah's user-level Cursor preToolUse hook.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use nah_proto::ctx::AbsolutePath;
use serde_json::{Map, Value, json};

use crate::live_state;

use super::{RuntimeHookStatus, RuntimeMutation};

pub(crate) fn mutate_cursor_hook(install: bool) -> Result<RuntimeMutation, String> {
    let platform = live_state::host_platform();
    let path = live_state::home(platform).and_then(|home| {
        if install {
            let executable = std::env::current_exe()
                .map_err(|_| "nah-executable-path-unavailable".to_owned())?;
            install_hook(&home, &executable)
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
    let mut without_owned = config.clone();
    if !remove(&mut without_owned)? {
        return Ok(RuntimeHookStatus::NotConfigured);
    }
    let executable =
        std::env::current_exe().map_err(|_| "nah-executable-path-unavailable".to_owned())?;
    add(&mut without_owned, desired_hook(&executable)?)?;
    Ok(if without_owned == config {
        RuntimeHookStatus::WiringCurrent
    } else {
        RuntimeHookStatus::NeedsReinstall
    })
}

pub(crate) fn cursor_self_protection_paths() -> Result<Vec<PathBuf>, String> {
    let platform = live_state::host_platform();
    let home = live_state::home(platform)?;
    Ok(vec![CursorHookPaths::new(&home).hooks])
}

fn install_hook(home: &AbsolutePath, executable: &Path) -> Result<PathBuf, String> {
    let paths = CursorHookPaths::new(home);
    let lock = lock(&paths)?;
    reject_symlinks(&paths)?;
    let mut config = load(&paths.hooks)?;
    validate_version(&mut config)?;
    let desired = desired_hook(executable)?;
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
    reject_symlink(&paths.lock, "cursor-hook-lock-failed")?;
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
    protect_private(&file)?;
    file.lock().map_err(|_| "cursor-hook-lock-failed")?;
    Ok(file)
}

fn load(path: &Path) -> Result<Value, String> {
    reject_symlink(path, "cursor-hooks-symlink-unsupported")?;
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

fn desired_hook(executable: &Path) -> Result<Value, String> {
    let executable = executable
        .to_str()
        .ok_or_else(|| "invalid-nah-executable-path".to_owned())?;
    let command = if cfg!(windows) {
        format!("\"{executable}\" hook cursor run")
    } else {
        format!("{} hook cursor run", shell_quote(executable))
    };
    Ok(json!({
        "command": command,
        "matcher": "*",
        "timeout": 5
    }))
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn is_nah_hook(hook: &Value) -> bool {
    let Some(executable) = hook
        .get("command")
        .and_then(Value::as_str)
        .and_then(|command| command.strip_suffix(" hook cursor run"))
    else {
        return false;
    };
    let executable = executable.to_ascii_lowercase();
    (executable.starts_with('\'') && executable.ends_with("/nah'"))
        || (executable.starts_with('"')
            && (executable.ends_with("\\nah.exe\"") || executable.ends_with("/nah.exe\"")))
}

fn save(path: &Path, config: &Value) -> Result<(), String> {
    reject_symlink(path, "cursor-hooks-symlink-unsupported")?;
    let parent = path
        .parent()
        .ok_or_else(|| "invalid-cursor-hooks-path".to_owned())?;
    std::fs::create_dir_all(parent).map_err(|_| "cursor-hooks-write-failed")?;
    let mut temporary =
        tempfile::NamedTempFile::new_in(parent).map_err(|_| "cursor-hooks-write-failed")?;
    protect_private(temporary.as_file())?;
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
    sync_parent(parent)
}

fn reject_symlink(path: &Path, error: &'static str) -> Result<(), String> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(error.into()),
        Ok(_) => Ok(()),
        Err(found) if found.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(error.into()),
    }
}

fn reject_symlinks(paths: &CursorHookPaths) -> Result<(), String> {
    for directory in &paths.directories {
        reject_symlink(directory, "cursor-hooks-symlink-unsupported")?;
    }
    reject_symlink(&paths.hooks, "cursor-hooks-symlink-unsupported")
}

#[cfg(unix)]
fn protect_private(file: &File) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|_| "cursor-hook-permissions-failed".into())
}

#[cfg(not(unix))]
fn protect_private(_file: &File) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn sync_parent(parent: &Path) -> Result<(), String> {
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| "cursor-hook-sync-failed".into())
}

#[cfg(not(unix))]
fn sync_parent(_parent: &Path) -> Result<(), String> {
    Ok(())
}
