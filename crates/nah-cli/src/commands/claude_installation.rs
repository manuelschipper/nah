//! Installs and removes nah's user-level Claude Code PreToolUse hook.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use nah_proto::ctx::AbsolutePath;
use serde_json::{Map, Value, json};

use crate::live_state;

use super::hook_config;
use super::{RuntimeHookStatus, RuntimeMutation};

pub(crate) fn mutate_claude_hook(install: bool) -> Result<RuntimeMutation, String> {
    let platform = live_state::host_platform();
    let path = live_state::home(platform).and_then(|home| {
        if install {
            let executable = std::env::current_exe()
                .map_err(|_| "nah-executable-path-unavailable".to_owned())?;
            install_claude_hook(&home, &executable)
        } else {
            uninstall_claude_hook(&home)
        }
    })?;
    Ok(RuntimeMutation::new(install, "Claude hook", path, None))
}

pub(crate) fn claude_hook_status() -> Result<RuntimeHookStatus, String> {
    let platform = live_state::host_platform();
    let home = live_state::home(platform)?;
    let paths = ClaudeHookPaths::new(&home);
    reject_symlinks(&paths)?;
    let settings = load_settings(&paths.settings)?;
    let executable =
        std::env::current_exe().map_err(|_| "nah-executable-path-unavailable".to_owned())?;
    hook_config::inspect(
        &settings,
        &desired_handler(&executable)?,
        is_nah_handler,
        "invalid-claude-hooks",
    )
}

pub(crate) fn claude_self_protection_paths() -> Result<Vec<PathBuf>, String> {
    let platform = live_state::host_platform();
    let home = live_state::home(platform)?;
    Ok(vec![ClaudeHookPaths::new(&home).settings])
}

fn install_claude_hook(home: &AbsolutePath, executable: &Path) -> Result<PathBuf, String> {
    let paths = ClaudeHookPaths::new(home);
    let lock = lock(&paths)?;
    reject_symlinks(&paths)?;
    let mut settings = load_settings(&paths.settings)?;
    let desired = desired_handler(executable)?;
    if hook_config::add(
        &mut settings,
        desired,
        is_nah_handler,
        "invalid-claude-hooks",
    )? {
        save_settings(&paths.settings, &settings)?;
    }
    drop(lock);
    Ok(paths.settings)
}

fn uninstall_claude_hook(home: &AbsolutePath) -> Result<PathBuf, String> {
    let paths = ClaudeHookPaths::new(home);
    let lock = lock(&paths)?;
    reject_symlinks(&paths)?;
    if paths.settings.exists() {
        let mut settings = load_settings(&paths.settings)?;
        if hook_config::remove(&mut settings, is_nah_handler, "invalid-claude-hooks")? {
            save_settings(&paths.settings, &settings)?;
        }
    }
    drop(lock);
    Ok(paths.settings)
}

struct ClaudeHookPaths {
    settings: PathBuf,
    lock: PathBuf,
    directories: Vec<PathBuf>,
}

impl ClaudeHookPaths {
    fn new(home: &AbsolutePath) -> Self {
        let home = PathBuf::from(home.as_str());
        let claude = home.join(".claude");
        Self {
            settings: claude.join("settings.json"),
            lock: home.join(".nah/claude-hook.lock"),
            directories: vec![claude],
        }
    }
}

fn lock(paths: &ClaudeHookPaths) -> Result<File, String> {
    let parent = paths
        .lock
        .parent()
        .ok_or_else(|| "invalid-claude-hook-lock-path".to_owned())?;
    std::fs::create_dir_all(parent).map_err(|_| "claude-hook-lock-failed")?;
    match std::fs::symlink_metadata(&paths.lock) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err("claude-hook-lock-failed".into());
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err("claude-hook-lock-failed".into()),
    }
    let mut options = OpenOptions::new();
    options.create(true).truncate(false).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(&paths.lock)
        .map_err(|_| "claude-hook-lock-failed")?;
    protect_private(&file)?;
    file.lock().map_err(|_| "claude-hook-lock-failed")?;
    Ok(file)
}

fn load_settings(path: &Path) -> Result<Value, String> {
    reject_symlink(path)?;
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Value::Object(Map::new()));
        }
        Err(_) => return Err("claude-settings-read-failed".into()),
    };
    let value: Value =
        serde_json::from_reader(file).map_err(|_| "invalid-claude-settings".to_owned())?;
    if !value.is_object() {
        return Err("invalid-claude-settings".into());
    }
    Ok(value)
}

fn save_settings(path: &Path, settings: &Value) -> Result<(), String> {
    reject_symlink(path)?;
    let parent = path
        .parent()
        .ok_or_else(|| "invalid-claude-settings-path".to_owned())?;
    std::fs::create_dir_all(parent).map_err(|_| "claude-settings-write-failed")?;
    let mut temporary =
        tempfile::NamedTempFile::new_in(parent).map_err(|_| "claude-settings-write-failed")?;
    protect_private(temporary.as_file())?;
    serde_json::to_writer_pretty(&mut temporary, settings)
        .map_err(|_| "claude-settings-write-failed")?;
    temporary
        .write_all(b"\n")
        .map_err(|_| "claude-settings-write-failed")?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|_| "claude-settings-write-failed")?;
    temporary
        .persist(path)
        .map_err(|_| "claude-settings-write-failed")?;
    sync_parent(parent)
}

fn reject_symlink(path: &Path) -> Result<(), String> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err("claude-settings-symlink-unsupported".into())
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err("claude-settings-read-failed".into()),
    }
}

fn reject_symlinks(paths: &ClaudeHookPaths) -> Result<(), String> {
    for directory in &paths.directories {
        reject_symlink(directory)?;
    }
    reject_symlink(&paths.settings)
}

fn desired_handler(executable: &Path) -> Result<Value, String> {
    let command = executable
        .to_str()
        .ok_or_else(|| "invalid-nah-executable-path".to_owned())?;
    Ok(json!({
        "type": "command",
        "command": command,
        "args": ["hook", "claude", "run"],
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
    let command_name = handler
        .get("command")
        .and_then(Value::as_str)
        .and_then(|command| Path::new(command).file_name())
        .and_then(|name| name.to_str());
    if !matches!(command_name, Some("nah" | "nah.exe")) {
        return false;
    }
    let Some(args) = handler.get("args").and_then(Value::as_array) else {
        return false;
    };
    let args = args.iter().map(Value::as_str).collect::<Option<Vec<_>>>();
    // Keep recognizing the removed form so reinstall and uninstall clean up old entries.
    matches!(
        args.as_deref(),
        Some(["hook", "claude", "run"]) | Some(["hook", "claude", "run", "--strict"])
    )
}

#[cfg(unix)]
fn protect_private(file: &File) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|_| "claude-hook-permissions-failed".into())
}

#[cfg(not(unix))]
fn protect_private(_file: &File) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn sync_parent(parent: &Path) -> Result<(), String> {
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| "claude-hook-sync-failed".into())
}

#[cfg(not(unix))]
fn sync_parent(_parent: &Path) -> Result<(), String> {
    Ok(())
}
