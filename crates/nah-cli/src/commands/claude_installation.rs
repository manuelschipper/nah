//! Installs and removes nah's user-level Claude Code PreToolUse hook.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use nah_proto::ctx::AbsolutePath;
use serde_json::{Map, Value, json};

use crate::{live_state, runtime::FailurePolicy};

use super::hook_config;
use super::{RuntimeHookStatus, RuntimeMutation};
use crate::private_files::{restrict_file_to_owner, sync_parent_directory};

/// The tool hook events where Nah 0.x registered its Claude hooks.
const LEGACY_EVENTS: [&str; 3] = ["PreToolUse", "PostToolUse", "PostToolUseFailure"];

pub(crate) fn mutate_claude_hook(
    install: bool,
    policy: FailurePolicy,
) -> Result<RuntimeMutation, String> {
    let platform = live_state::host_platform();
    let path = live_state::home(platform).and_then(|home| {
        if install {
            let executable = std::env::current_exe()
                .map_err(|_| "nah-executable-path-unavailable".to_owned())?;
            install_claude_hook(&home, &executable, policy)
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
    let status = hook_config::inspect_modes(
        &settings,
        &desired_handler(&executable, FailurePolicy::Delegate)?,
        &desired_handler(&executable, FailurePolicy::Block)?,
        is_nah_handler,
        is_fail_closed_handler,
        "invalid-claude-hooks",
    )?;
    Ok(if remove_legacy(&mut settings.clone(), &home)? {
        RuntimeHookStatus::stale(status.failure_policy())
    } else {
        status
    })
}

pub(crate) fn claude_self_protection_paths() -> Result<Vec<PathBuf>, String> {
    let platform = live_state::host_platform();
    let home = live_state::home(platform)?;
    Ok(vec![ClaudeHookPaths::new(&home).settings])
}

fn install_claude_hook(
    home: &AbsolutePath,
    executable: &Path,
    policy: FailurePolicy,
) -> Result<PathBuf, String> {
    let paths = ClaudeHookPaths::new(home);
    let lock = lock(&paths)?;
    reject_symlinks(&paths)?;
    let mut settings = load_settings(&paths.settings)?;
    let desired = desired_handler(executable, policy)?;
    let legacy = remove_legacy(&mut settings, home)?;
    if hook_config::add(
        &mut settings,
        desired,
        is_nah_handler,
        "invalid-claude-hooks",
    )? || legacy
    {
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
        let legacy = remove_legacy(&mut settings, home)?;
        if hook_config::remove(&mut settings, is_nah_handler, "invalid-claude-hooks")? || legacy {
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
    restrict_file_to_owner(&file).map_err(|_| "claude-hook-permissions-failed".to_owned())?;
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
    restrict_file_to_owner(temporary.as_file())
        .map_err(|_| "claude-hook-permissions-failed".to_owned())?;
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
    sync_parent_directory(parent).map_err(|_| "claude-hook-sync-failed".to_owned())
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

fn desired_handler(executable: &Path, policy: FailurePolicy) -> Result<Value, String> {
    let command = executable
        .to_str()
        .ok_or_else(|| "invalid-nah-executable-path".to_owned())?;
    let mut args = vec!["hook", "claude", "run"];
    if policy == FailurePolicy::Block {
        args.push("--fail-closed");
    }
    Ok(json!({
        "type": "command",
        "command": command,
        "args": args,
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
        Some(["hook", "claude", "run"])
            | Some(["hook", "claude", "run", "--fail-closed"])
            | Some(["hook", "claude", "run", "--strict"])
    )
}

/// Removes the hook handlers Nah 0.x wrote to Claude settings, which 1.x
/// cannot run, and reports whether any were found.
fn remove_legacy(settings: &mut Value, home: &AbsolutePath) -> Result<bool, String> {
    let scripts = legacy_scripts(home);
    let root = settings
        .as_object_mut()
        .ok_or_else(|| "invalid-claude-hooks".to_owned())?;
    let Some(hooks_value) = root.get_mut("hooks") else {
        return Ok(false);
    };
    let hooks = hooks_value
        .as_object_mut()
        .ok_or_else(|| "invalid-claude-hooks".to_owned())?;
    let mut changed = false;
    for event in LEGACY_EVENTS {
        let Some(groups_value) = hooks.get_mut(event) else {
            continue;
        };
        let groups = groups_value
            .as_array_mut()
            .ok_or_else(|| "invalid-claude-hooks".to_owned())?;
        if groups.iter().any(|group| {
            group
                .get("hooks")
                .is_some_and(|handlers| !handlers.is_array())
        }) {
            return Err("invalid-claude-hooks".into());
        }
        let mut removed = false;
        groups.retain_mut(|group| {
            let Some(handlers) = group.get_mut("hooks").and_then(Value::as_array_mut) else {
                return true;
            };
            let before = handlers.len();
            handlers.retain(|handler| !is_legacy_handler(handler, &scripts));
            let dropped = handlers.len() != before;
            removed |= dropped;
            !dropped || !handlers.is_empty()
        });
        if removed && groups.is_empty() {
            hooks.remove(event);
        }
        changed |= removed;
    }
    if changed && hooks.is_empty() {
        root.remove("hooks");
    }
    Ok(changed)
}

/// The spellings of the 0.x shim path, `~/.claude/hooks/nah_guard.py`. 0.x
/// built it from the configured home, which may be a symlink to the canonical
/// `home`, and from 0.5.3 wrote it with forward slashes.
fn legacy_scripts(home: &AbsolutePath) -> Vec<String> {
    let configured =
        live_state::configured_home(live_state::host_platform(), |name| std::env::var_os(name))
            .ok()
            .and_then(|home| home.into_string().ok());
    let mut scripts = Vec::new();
    for home in configured.iter().map(String::as_str).chain([home.as_str()]) {
        let script = Path::new(home)
            .join(".claude")
            .join("hooks")
            .join("nah_guard.py");
        let Some(script) = script.to_str() else {
            continue;
        };
        for script in [script.to_owned(), script.replace('\\', "/")] {
            if !scripts.contains(&script) {
                scripts.push(script);
            }
        }
    }
    scripts
}

/// Whether `handler` is exactly one Nah 0.x wrote: the two keys it set, and a
/// command its `_hook_command` produced for a nah executable or for a Python
/// interpreter running one of the shim `scripts`.
fn is_legacy_handler(handler: &Value, scripts: &[String]) -> bool {
    let Some(handler) = handler.as_object() else {
        return false;
    };
    let Some(command) = handler.get("command").and_then(Value::as_str) else {
        return false;
    };
    if handler.len() != 2 || handler.get("type").and_then(Value::as_str) != Some("command") {
        return false;
    }
    // 0.9.0 to 0.11.0: `quote_claude_argv([nah, "_claude-hook"])`
    if let Some(executable) = command.strip_suffix(r#" "_claude-hook""#) {
        return unquote_claude_word(executable).is_some_and(|path| {
            path.contains('/')
                && matches!(
                    path.rsplit('/')
                        .next()
                        .map(str::to_ascii_lowercase)
                        .as_deref(),
                    Some("nah" | "nah.exe")
                )
        });
    }
    scripts.iter().any(|script| {
        legacy_interpreter(command, script).is_some_and(|interpreter| is_python(&interpreter))
    })
}

/// The interpreter a 0.2.0 to 0.7.1 `_hook_command` wrote before `script`,
/// decoded from whichever of its serializations `command` is.
fn legacy_interpreter(command: &str, script: &str) -> Option<String> {
    // 0.5.3 to 0.7.1: each word double-quoted, unescaped, with forward slashes
    let posix = script.replace('\\', "/");
    if let Some(interpreter) = command
        .strip_suffix(&format!(r#" "{posix}""#))
        .and_then(|word| word.strip_prefix('"'))
        .and_then(|word| word.strip_suffix('"'))
        .filter(|interpreter| !interpreter.contains('"'))
    {
        return Some(interpreter.to_owned());
    }
    // 0.5.1 and 0.5.2: `shlex.quote` on each word
    if let Some(interpreter) = command
        .strip_suffix(&format!(" {}", shlex_quote(script)))
        .and_then(shlex_unquote)
    {
        return Some(interpreter);
    }
    // 0.2.0 to 0.5.0: both words unquoted, so everything before the script is
    // the interpreter's absolute path, spaces included. A later word starting
    // another absolute path means another program runs the interpreter.
    command
        .strip_suffix(&format!(" {script}"))
        .filter(|interpreter| {
            is_absolute_word(interpreter)
                && !interpreter.split_whitespace().skip(1).any(is_absolute_word)
                && !interpreter.contains(|c: char| "\n;&|<>$`'\"".contains(c))
        })
        .map(str::to_owned)
}

fn is_absolute_word(word: &str) -> bool {
    word.starts_with(['/', '\\']) || word.as_bytes().get(1) == Some(&b':')
}

/// Whether `path` names a Python interpreter, as `sys.executable` does.
fn is_python(path: &str) -> bool {
    let name = path
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(path)
        .to_ascii_lowercase();
    let name = name.strip_suffix(".exe").unwrap_or(&name);
    matches!(name, "python" | "python3" | "pythonw" | "py")
        || name
            .strip_prefix("python3.")
            .is_some_and(|minor| !minor.is_empty() && minor.bytes().all(|b| b.is_ascii_digit()))
}

/// Python's `shlex.quote`: unchanged when every character is safe for a POSIX
/// shell, otherwise single-quoted with each `'` written as `'"'"'`.
fn shlex_quote(word: &str) -> String {
    if word.is_empty() {
        return "''".into();
    }
    if word
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "_@%+=:,./-".contains(c))
    {
        return word.to_owned();
    }
    format!("'{}'", word.replace('\'', r#"'"'"'"#))
}

/// The word `shlex_quote` turned into `quoted`, if it produced exactly that.
fn shlex_unquote(quoted: &str) -> Option<String> {
    let word = match quoted
        .strip_prefix('\'')
        .and_then(|quoted| quoted.strip_suffix('\''))
    {
        Some(inner) => inner.replace(r#"'"'"'"#, "'"),
        None => quoted.to_owned(),
    };
    (shlex_quote(&word) == quoted).then_some(word)
}

/// The argument 0.x `quote_claude_argv` turned into `quoted`: double-quoted,
/// with backslashes made forward slashes and `"` escaped as `\"`.
fn unquote_claude_word(quoted: &str) -> Option<String> {
    let inner = quoted.strip_prefix('"')?.strip_suffix('"')?;
    let word = inner.replace(r#"\""#, "\"");
    (!word.contains('\\') && word.replace('"', r#"\""#) == inner).then_some(word)
}

fn is_fail_closed_handler(handler: &Value) -> bool {
    handler
        .get("args")
        .and_then(Value::as_array)
        .is_some_and(|args| {
            args.iter()
                .map(Value::as_str)
                .collect::<Option<Vec<_>>>()
                .as_deref()
                == Some(&["hook", "claude", "run", "--fail-closed"][..])
        })
}
