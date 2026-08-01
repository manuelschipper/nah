//! Installs and removes nah's shared Antigravity PreToolUse hook.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use nah_proto::ctx::AbsolutePath;
use serde_json::{Map, Value, json};

use crate::live_state;

use super::{RuntimeHookStatus, RuntimeMutation};

const HOOK_NAME: &str = "nah";
const HOOK_MATCHER: &str = "run_command|view_file|write_to_file|replace_file_content|multi_replace_file_content|list_dir|find_by_name|grep_search";

pub(crate) fn mutate_antigravity_hook(install: bool) -> Result<RuntimeMutation, String> {
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
    let desired = desired_hook(&executable)?;
    if configured == &desired {
        Ok(RuntimeHookStatus::WiringCurrent)
    } else if is_owned(configured) {
        Ok(RuntimeHookStatus::NeedsReinstall)
    } else {
        Err("antigravity-hook-name-conflict".into())
    }
}

pub(crate) fn antigravity_self_protection_paths() -> Result<Vec<PathBuf>, String> {
    let platform = live_state::host_platform();
    let home = live_state::home(platform)?;
    Ok(vec![AntigravityHookPaths::new(&home).hooks])
}

fn install_hook(home: &AbsolutePath, executable: &Path) -> Result<PathBuf, String> {
    let paths = AntigravityHookPaths::new(home);
    let lock = lock(&paths)?;
    reject_hook_symlinks(&paths)?;
    let mut config = load(&paths.hooks)?;
    let desired = desired_hook(executable)?;
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
    let lock = lock(&paths)?;
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

fn lock(paths: &AntigravityHookPaths) -> Result<File, String> {
    let parent = paths
        .lock
        .parent()
        .ok_or_else(|| "invalid-antigravity-hook-lock-path".to_owned())?;
    reject_symlink(parent, "antigravity-hook-lock-failed")?;
    std::fs::create_dir_all(parent).map_err(|_| "antigravity-hook-lock-failed")?;
    reject_symlink(&paths.lock, "antigravity-hook-lock-failed")?;
    let mut options = OpenOptions::new();
    options.create(true).truncate(false).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(&paths.lock)
        .map_err(|_| "antigravity-hook-lock-failed")?;
    protect_private(&file)?;
    file.lock().map_err(|_| "antigravity-hook-lock-failed")?;
    Ok(file)
}

fn reject_hook_symlinks(paths: &AntigravityHookPaths) -> Result<(), String> {
    for directory in &paths.hook_directories {
        reject_symlink(directory, "antigravity-hooks-symlink-unsupported")?;
    }
    reject_symlink(&paths.hooks, "antigravity-hooks-symlink-unsupported")
}

fn load(path: &Path) -> Result<Value, String> {
    reject_symlink(path, "antigravity-hooks-symlink-unsupported")?;
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

fn desired_hook(executable: &Path) -> Result<Value, String> {
    let executable = executable
        .to_str()
        .ok_or_else(|| "invalid-nah-executable-path".to_owned())?;
    let command = if cfg!(windows) {
        format!("\"{executable}\" hook antigravity run")
    } else {
        format!("{} hook antigravity run", shell_quote(executable))
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

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
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

fn is_owned_command(command: &str) -> bool {
    let Some(executable) = command.strip_suffix(" hook antigravity run") else {
        return false;
    };
    let executable = executable.to_ascii_lowercase();
    (executable.starts_with('\'') && executable.ends_with("/nah'"))
        || (executable.starts_with('"')
            && (executable.ends_with("\\nah.exe\"") || executable.ends_with("/nah.exe\"")))
}

fn save(path: &Path, config: &Value) -> Result<(), String> {
    reject_symlink(path, "antigravity-hooks-symlink-unsupported")?;
    let parent = path
        .parent()
        .ok_or_else(|| "invalid-antigravity-hooks-path".to_owned())?;
    std::fs::create_dir_all(parent).map_err(|_| "antigravity-hooks-write-failed")?;
    let mut temporary =
        tempfile::NamedTempFile::new_in(parent).map_err(|_| "antigravity-hooks-write-failed")?;
    protect_private(temporary.as_file())?;
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

#[cfg(unix)]
fn protect_private(file: &File) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|_| "antigravity-hook-permissions-failed".into())
}

#[cfg(not(unix))]
fn protect_private(_file: &File) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn sync_parent(parent: &Path) -> Result<(), String> {
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| "antigravity-hook-sync-failed".into())
}

#[cfg(not(unix))]
fn sync_parent(_parent: &Path) -> Result<(), String> {
    Ok(())
}
