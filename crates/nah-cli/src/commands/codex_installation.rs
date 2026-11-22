//! Installs and removes nah's user-level Codex hooks: the PreToolUse one that
//! decides, and the PostToolUse ones that refresh save-then-run's rolling
//! copy and settle session memory.

use std::path::{Path, PathBuf};

use nah_proto::ctx::{AbsolutePath, Platform};
use serde_json::{Value, json};

use crate::{
    live_state,
    runtime::{FailurePolicy, Runtime},
    save_then_run,
};

use super::hook_config;
use super::hook_paths::{
    HookFileWriteErrorCodes, HookJsonReadErrorCodes, HookLockErrorCodes, acquire_hook_lock,
    read_hook_json_object, write_hook_json_atomically,
};
use super::shell_word::quote_posix_shell_word;
use super::{RuntimeHookStatus, RuntimeMutation};

pub(crate) fn mutate_codex_hook(
    install: bool,
    policy: FailurePolicy,
) -> Result<RuntimeMutation, String> {
    reject_custom_codex_home()?;
    let platform = live_state::host_platform();
    let path = live_state::home(platform).and_then(|home| {
        if install {
            let executable = std::env::current_exe()
                .map_err(|_| "nah-executable-path-unavailable".to_owned())?;
            install_codex_hook(&home, &executable, policy)
        } else {
            uninstall_codex_hook(&home)
        }
    })?;
    let mut mutation = RuntimeMutation::new(
        install,
        "Codex hook",
        path,
        Some("Open Codex, run /hooks, and trust the new hooks before use."),
    );
    if install {
        mutation.coverage_notice = codex_coverage_notice(platform);
    }
    Ok(mutation)
}

pub(super) fn codex_coverage_notice(platform: Platform) -> Option<&'static str> {
    (platform == Platform::Windows).then_some(
        "coverage: native file tools are guarded; shell commands are not analysed on Windows, even with --fail-closed",
    )
}

pub(crate) fn codex_hook_status() -> Result<RuntimeHookStatus, String> {
    reject_custom_codex_home()?;
    let platform = live_state::host_platform();
    let home = live_state::home(platform)?;
    let paths = CodexHookPaths::new(&home);
    reject_codex_hook_symlinks(&paths)?;
    let mut hooks = load_codex_hooks(&paths.hooks)?;
    let executable =
        std::env::current_exe().map_err(|_| "nah-executable-path-unavailable".to_owned())?;
    let status = hook_config::inspect_modes(
        &hooks,
        &desired_codex_handler(&executable, FailurePolicy::Delegate)?,
        &desired_codex_handler(&executable, FailurePolicy::Block)?,
        is_nah_codex_handler,
        is_fail_closed_codex_handler,
        "invalid-codex-hooks",
    )?;
    // An install without the post-call hooks is stale, as is one with
    // others than these.
    if matches!(
        status,
        RuntimeHookStatus::WiringCurrent | RuntimeHookStatus::WiringCurrentFailClosed
    ) && set_post_tool_hooks(&mut hooks, &executable)?
    {
        return Ok(RuntimeHookStatus::stale(status.failure_policy()));
    }
    Ok(status)
}

pub(crate) fn codex_self_protection_paths() -> Result<Vec<PathBuf>, String> {
    reject_custom_codex_home()?;
    let platform = live_state::host_platform();
    let home = live_state::home(platform)?;
    let paths = CodexHookPaths::new(&home);
    Ok(vec![
        paths.hooks,
        PathBuf::from(home.as_str()).join(".codex/config.toml"),
    ])
}

fn reject_custom_codex_home() -> Result<(), String> {
    if std::env::var_os("CODEX_HOME").is_some() {
        Err("custom-CODEX_HOME-unsupported".into())
    } else {
        Ok(())
    }
}

fn install_codex_hook(
    home: &AbsolutePath,
    executable: &Path,
    policy: FailurePolicy,
) -> Result<PathBuf, String> {
    let paths = CodexHookPaths::new(home);
    let lock = acquire_hook_lock(&paths.lock, &CODEX_HOOK_LOCK_ERRORS)?;
    reject_codex_hook_symlinks(&paths)?;
    let mut hooks = load_codex_hooks(&paths.hooks)?;
    let desired = desired_codex_handler(executable, policy)?;
    let post_tool = set_post_tool_hooks(&mut hooks, executable)?;
    if hook_config::add(
        &mut hooks,
        desired,
        is_nah_codex_handler,
        "invalid-codex-hooks",
    )? || post_tool
    {
        save_codex_hooks(&paths.hooks, &hooks)?;
    }
    drop(lock);
    Ok(paths.hooks)
}

fn uninstall_codex_hook(home: &AbsolutePath) -> Result<PathBuf, String> {
    let paths = CodexHookPaths::new(home);
    let lock = acquire_hook_lock(&paths.lock, &CODEX_HOOK_LOCK_ERRORS)?;
    reject_codex_hook_symlinks(&paths)?;
    if paths.hooks.exists() {
        let mut hooks = load_codex_hooks(&paths.hooks)?;
        let post_tool = hook_config::set_event_handlers(
            &mut hooks,
            "PostToolUse",
            Vec::new(),
            is_nah_codex_handler,
            "invalid-codex-hooks",
        )?;
        if hook_config::remove(&mut hooks, is_nah_codex_handler, "invalid-codex-hooks")?
            || post_tool
        {
            save_codex_hooks(&paths.hooks, &hooks)?;
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

const CODEX_HOOK_LOCK_ERRORS: HookLockErrorCodes = HookLockErrorCodes {
    invalid_path: "invalid-codex-hook-lock-path",
    failed: "codex-hook-lock-failed",
    permissions: "codex-hook-permissions-failed",
};

const CODEX_HOOKS_READ_ERRORS: HookJsonReadErrorCodes = HookJsonReadErrorCodes {
    read_failed: "codex-hooks-read-failed",
    invalid: "invalid-codex-hooks",
};

fn load_codex_hooks(path: &Path) -> Result<Value, String> {
    reject_codex_hooks_symlink(path)?;
    read_hook_json_object(path, &CODEX_HOOKS_READ_ERRORS)
}

const CODEX_HOOKS_WRITE_ERRORS: HookFileWriteErrorCodes = HookFileWriteErrorCodes {
    invalid_path: "invalid-codex-hooks-path",
    write_failed: "codex-hooks-write-failed",
    permissions: "codex-hook-permissions-failed",
    sync_failed: "codex-hook-sync-failed",
};

fn save_codex_hooks(path: &Path, hooks: &Value) -> Result<(), String> {
    reject_codex_hooks_symlink(path)?;
    write_hook_json_atomically(path, hooks, &CODEX_HOOKS_WRITE_ERRORS)
}

fn reject_codex_hooks_symlink(path: &Path) -> Result<(), String> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err("codex-hooks-symlink-unsupported".into())
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err("codex-hooks-read-failed".into()),
    }
}

fn reject_codex_hook_symlinks(paths: &CodexHookPaths) -> Result<(), String> {
    for directory in &paths.directories {
        reject_codex_hooks_symlink(directory)?;
    }
    reject_codex_hooks_symlink(&paths.hooks)
}

fn desired_codex_handler(executable: &Path, policy: FailurePolicy) -> Result<Value, String> {
    Ok(json!({
        "type": "command",
        "command": codex_command(executable, policy.command_suffix())?,
        "timeout": 5
    }))
}

/// The shell command Codex runs for a Nah hook: `nah hook codex run` and
/// `suffix`.
fn codex_command(executable: &Path, suffix: &str) -> Result<String, String> {
    let executable = executable
        .to_str()
        .ok_or_else(|| "invalid-nah-executable-path".to_owned())?;
    Ok(if cfg!(windows) {
        format!("\"{executable}\" hook codex run{suffix}")
    } else {
        format!(
            "{} hook codex run{suffix}",
            quote_posix_shell_word(executable)
        )
    })
}

/// Makes Nah's `PostToolUse` handlers current and reports whether that
/// changed `hooks`: where save-then-run saves, one in the background that
/// refreshes the rolling copy, and one Codex waits for that settles session
/// memory before the next call starts.
fn set_post_tool_hooks(hooks: &mut Value, executable: &Path) -> Result<bool, String> {
    let refresh = save_then_run::available(Some(Runtime::Codex))
        .then(|| codex_command(executable, ""))
        .transpose()?
        .map(|command| {
            json!({
                "type": "command",
                "command": command,
                "async": true,
                "timeout": 60
            })
        });
    let settle = json!({
        "type": "command",
        "command": codex_command(executable, " --settle")?,
        "timeout": 10
    });
    hook_config::set_event_handlers(
        hooks,
        "PostToolUse",
        refresh
            .into_iter()
            .chain([settle])
            .map(|handler| (Some("*"), handler))
            .collect(),
        is_nah_codex_handler,
        "invalid-codex-hooks",
    )
}

fn is_nah_codex_handler(handler: &Value) -> bool {
    let Some(handler) = handler.as_object() else {
        return false;
    };
    if handler.get("type").and_then(Value::as_str) != Some("command") {
        return false;
    }
    let Some(command) = handler.get("command").and_then(Value::as_str) else {
        return false;
    };
    let command = command
        .strip_suffix(" --fail-closed")
        .or_else(|| command.strip_suffix(" --settle"))
        .unwrap_or(command);
    let Some(executable) = command.strip_suffix(" hook codex run") else {
        return false;
    };
    let executable = executable.to_ascii_lowercase();
    hook_config::is_one_quoted_word(&executable)
        && ((executable.starts_with('\'') && executable.ends_with("/nah'"))
            || (executable.starts_with('"')
                && (executable.ends_with("\\nah.exe\"") || executable.ends_with("/nah.exe\""))))
}

fn is_fail_closed_codex_handler(handler: &Value) -> bool {
    handler
        .get("command")
        .and_then(Value::as_str)
        .is_some_and(|command| command.ends_with(" hook codex run --fail-closed"))
}
