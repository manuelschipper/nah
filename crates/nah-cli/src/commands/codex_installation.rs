//! Installs and removes nah's user-level Codex PreToolUse hook.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use nah_proto::ctx::AbsolutePath;
use serde_json::{Map, Value, json};

use crate::{live_state, runtime::FailurePolicy};

use super::hook_config;
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
            install_hook(&home, &executable, policy)
        } else {
            uninstall_hook(&home)
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
    reject_symlinks(&paths)?;
    let hooks = load(&paths.hooks)?;
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

fn install_hook(
    home: &AbsolutePath,
    executable: &Path,
    policy: FailurePolicy,
) -> Result<PathBuf, String> {
    let paths = CodexHookPaths::new(home);
    let lock = lock(&paths)?;
    reject_symlinks(&paths)?;
    let mut hooks = load(&paths.hooks)?;
    let desired = desired_handler(executable, policy)?;
    if hook_config::add(&mut hooks, desired, is_nah_handler, "invalid-codex-hooks")? {
        save(&paths.hooks, &hooks)?;
    }
    drop(lock);
    Ok(paths.hooks)
}

fn uninstall_hook(home: &AbsolutePath) -> Result<PathBuf, String> {
    let paths = CodexHookPaths::new(home);
    let lock = lock(&paths)?;
    reject_symlinks(&paths)?;
    if paths.hooks.exists() {
        let mut hooks = load(&paths.hooks)?;
        if hook_config::remove(&mut hooks, is_nah_handler, "invalid-codex-hooks")? {
            save(&paths.hooks, &hooks)?;
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

fn lock(paths: &CodexHookPaths) -> Result<File, String> {
    let parent = paths
        .lock
        .parent()
        .ok_or_else(|| "invalid-codex-hook-lock-path".to_owned())?;
    std::fs::create_dir_all(parent).map_err(|_| "codex-hook-lock-failed")?;
    match std::fs::symlink_metadata(&paths.lock) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err("codex-hook-lock-failed".into());
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err("codex-hook-lock-failed".into()),
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
        .map_err(|_| "codex-hook-lock-failed")?;
    protect_private(&file)?;
    file.lock().map_err(|_| "codex-hook-lock-failed")?;
    Ok(file)
}

fn load(path: &Path) -> Result<Value, String> {
    reject_symlink(path)?;
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Value::Object(Map::new()));
        }
        Err(_) => return Err("codex-hooks-read-failed".into()),
    };
    let value: Value =
        serde_json::from_reader(file).map_err(|_| "invalid-codex-hooks".to_owned())?;
    if !value.is_object() {
        return Err("invalid-codex-hooks".into());
    }
    Ok(value)
}

fn save(path: &Path, hooks: &Value) -> Result<(), String> {
    reject_symlink(path)?;
    let parent = path
        .parent()
        .ok_or_else(|| "invalid-codex-hooks-path".to_owned())?;
    std::fs::create_dir_all(parent).map_err(|_| "codex-hooks-write-failed")?;
    let mut temporary =
        tempfile::NamedTempFile::new_in(parent).map_err(|_| "codex-hooks-write-failed")?;
    protect_private(temporary.as_file())?;
    serde_json::to_writer_pretty(&mut temporary, hooks).map_err(|_| "codex-hooks-write-failed")?;
    temporary
        .write_all(b"\n")
        .map_err(|_| "codex-hooks-write-failed")?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|_| "codex-hooks-write-failed")?;
    temporary
        .persist(path)
        .map_err(|_| "codex-hooks-write-failed")?;
    sync_parent(parent)
}

fn reject_symlink(path: &Path) -> Result<(), String> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err("codex-hooks-symlink-unsupported".into())
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err("codex-hooks-read-failed".into()),
    }
}

fn reject_symlinks(paths: &CodexHookPaths) -> Result<(), String> {
    for directory in &paths.directories {
        reject_symlink(directory)?;
    }
    reject_symlink(&paths.hooks)
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
            shell_quote(executable),
            policy.command_suffix()
        )
    };
    Ok(json!({
        "type": "command",
        "command": command,
        "timeout": 5
    }))
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
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
    (executable.starts_with('\'') && executable.ends_with("/nah'"))
        || (executable.starts_with('"')
            && (executable.ends_with("\\nah.exe\"") || executable.ends_with("/nah.exe\"")))
}

fn is_fail_closed_handler(handler: &Value) -> bool {
    handler
        .get("command")
        .and_then(Value::as_str)
        .is_some_and(|command| command.ends_with(" hook codex run --fail-closed"))
}

#[cfg(unix)]
fn protect_private(file: &File) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|_| "codex-hook-permissions-failed".into())
}

#[cfg(not(unix))]
fn protect_private(_file: &File) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn sync_parent(parent: &Path) -> Result<(), String> {
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| "codex-hook-sync-failed".into())
}

#[cfg(not(unix))]
fn sync_parent(_parent: &Path) -> Result<(), String> {
    Ok(())
}
