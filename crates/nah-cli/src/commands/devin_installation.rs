//! Installs and removes nah's user-level Devin PreToolUse hook.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use nah_proto::ctx::AbsolutePath;
use serde_json::{Map, Value, json};

use crate::live_state;

use super::{RuntimeHookStatus, RuntimeMutation};

const EVENTS: [&str; 3] = ["PreToolUse", "PermissionRequest", "PostToolUse"];

pub(crate) fn mutate_devin_hook(install: bool) -> Result<RuntimeMutation, String> {
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
        "Devin hook",
        path,
        Some("Restart Devin, then run /hooks to verify the hook."),
    ))
}

pub(crate) fn devin_hook_status() -> Result<RuntimeHookStatus, String> {
    let platform = live_state::host_platform();
    let home = live_state::home(platform)?;
    let paths = DevinHookPaths::new(&home);
    reject_symlinks(&paths)?;
    let mut config = load(&paths.config)?;
    validate_version(&mut config)?;
    let mut expected = config.clone();
    if !remove_owned(&mut expected)? {
        return Ok(RuntimeHookStatus::NotConfigured);
    }
    let executable =
        std::env::current_exe().map_err(|_| "nah-executable-path-unavailable".to_owned())?;
    pre_tool_hooks(&mut expected)?.push(json!({
        "matcher": "",
        "hooks": [desired_handler(&executable)?]
    }));
    Ok(if expected == config {
        RuntimeHookStatus::WiringCurrent
    } else {
        RuntimeHookStatus::NeedsReinstall
    })
}

pub(crate) fn devin_self_protection_paths() -> Result<Vec<PathBuf>, String> {
    let platform = live_state::host_platform();
    let home = live_state::home(platform)?;
    Ok(vec![DevinHookPaths::new(&home).config])
}

fn install_hook(home: &AbsolutePath, executable: &Path) -> Result<PathBuf, String> {
    let paths = DevinHookPaths::new(home);
    let lock = lock(&paths)?;
    reject_symlinks(&paths)?;
    let mut config = load(&paths.config)?;
    validate_version(&mut config)?;
    let original = config.clone();
    remove_owned(&mut config)?;
    pre_tool_hooks(&mut config)?.push(json!({
        "matcher": "",
        "hooks": [desired_handler(executable)?]
    }));
    if config != original {
        save(&paths.config, &config)?;
    }
    drop(lock);
    Ok(paths.config)
}

fn uninstall_hook(home: &AbsolutePath) -> Result<PathBuf, String> {
    let paths = DevinHookPaths::new(home);
    let lock = lock(&paths)?;
    reject_symlinks(&paths)?;
    if paths.config.exists() {
        let mut config = load(&paths.config)?;
        validate_version(&mut config)?;
        if remove_owned(&mut config)? {
            save(&paths.config, &config)?;
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

fn lock(paths: &DevinHookPaths) -> Result<File, String> {
    let parent = paths
        .lock
        .parent()
        .ok_or_else(|| "invalid-devin-hook-lock-path".to_owned())?;
    std::fs::create_dir_all(parent).map_err(|_| "devin-hook-lock-failed")?;
    reject_symlink(&paths.lock, "devin-hook-lock-failed")?;
    let mut options = OpenOptions::new();
    options.create(true).truncate(false).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(&paths.lock)
        .map_err(|_| "devin-hook-lock-failed")?;
    protect_private(&file)?;
    file.lock().map_err(|_| "devin-hook-lock-failed")?;
    Ok(file)
}

fn load(path: &Path) -> Result<Value, String> {
    reject_symlink(path, "devin-config-symlink-unsupported")?;
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Value::Object(Map::new()));
        }
        Err(_) => return Err("devin-config-read-failed".into()),
    };
    let value: Value =
        serde_json::from_reader(file).map_err(|_| "invalid-devin-config".to_owned())?;
    if !value.is_object() {
        return Err("invalid-devin-config".into());
    }
    Ok(value)
}

fn validate_version(config: &mut Value) -> Result<(), String> {
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

fn remove_owned(config: &mut Value) -> Result<bool, String> {
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
            handlers.retain(|handler| !is_owned_handler(handler));
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

fn pre_tool_hooks(config: &mut Value) -> Result<&mut Vec<Value>, String> {
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

fn desired_handler(executable: &Path) -> Result<Value, String> {
    let executable = executable
        .to_str()
        .ok_or_else(|| "invalid-nah-executable-path".to_owned())?;
    let command = if cfg!(windows) {
        format!("\"{executable}\" hook devin run")
    } else {
        format!("{} hook devin run", shell_quote(executable))
    };
    Ok(json!({"type":"command","command":command,"timeout":5}))
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn is_owned_handler(handler: &Value) -> bool {
    let Some(command) = handler
        .as_object()
        .filter(|handler| handler.get("type").and_then(Value::as_str) == Some("command"))
        .and_then(|handler| handler.get("command"))
        .and_then(Value::as_str)
    else {
        return false;
    };
    command
        .strip_suffix(" hook devin run")
        .is_some_and(is_nah_executable)
        || command
            .strip_suffix(" \"_devin-hook\"")
            .or_else(|| command.strip_suffix(" '_devin-hook'"))
            .is_some_and(is_nah_executable)
}

fn is_nah_executable(executable: &str) -> bool {
    let executable = executable.to_ascii_lowercase();
    (executable.starts_with('\'') && executable.ends_with("/nah'"))
        || (executable.starts_with('"')
            && (executable.ends_with("/nah\"")
                || executable.ends_with("\\nah.exe\"")
                || executable.ends_with("/nah.exe\"")))
}

fn save(path: &Path, config: &Value) -> Result<(), String> {
    reject_symlink(path, "devin-config-symlink-unsupported")?;
    let parent = path
        .parent()
        .ok_or_else(|| "invalid-devin-config-path".to_owned())?;
    std::fs::create_dir_all(parent).map_err(|_| "devin-config-write-failed")?;
    let mut temporary =
        tempfile::NamedTempFile::new_in(parent).map_err(|_| "devin-config-write-failed")?;
    protect_private(temporary.as_file())?;
    serde_json::to_writer_pretty(&mut temporary, config)
        .map_err(|_| "devin-config-write-failed")?;
    temporary
        .write_all(b"\n")
        .map_err(|_| "devin-config-write-failed")?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|_| "devin-config-write-failed")?;
    temporary
        .persist(path)
        .map_err(|_| "devin-config-write-failed")?;
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

fn reject_symlinks(paths: &DevinHookPaths) -> Result<(), String> {
    for directory in &paths.directories {
        reject_symlink(directory, "devin-config-symlink-unsupported")?;
    }
    reject_symlink(&paths.config, "devin-config-symlink-unsupported")
}

#[cfg(unix)]
fn protect_private(file: &File) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|_| "devin-hook-permissions-failed".into())
}

#[cfg(not(unix))]
fn protect_private(_file: &File) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn sync_parent(parent: &Path) -> Result<(), String> {
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| "devin-hook-sync-failed".into())
}

#[cfg(not(unix))]
fn sync_parent(_parent: &Path) -> Result<(), String> {
    Ok(())
}
