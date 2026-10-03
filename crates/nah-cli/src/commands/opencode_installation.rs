//! Installs and removes nah's global OpenCode tool hook plugin.

use std::io::Write;
use std::path::{Path, PathBuf};

use nah_proto::ctx::AbsolutePath;

use crate::{live_state, runtime::FailurePolicy};

use super::hook_paths::{HookLockErrorCodes, acquire_hook_lock, reject_hook_path_symlink};
use super::javascript_bridge::javascript_decision_bridge;
use super::runtime::reject_unsupported_windows_runtime;
use super::{RuntimeHookStatus, RuntimeMutation};
use crate::private_files::{restrict_file_to_owner, sync_parent_directory};

const MARKER: &str = "// Managed by nah.";

pub(crate) fn mutate_opencode_hook(
    install: bool,
    policy: FailurePolicy,
) -> Result<RuntimeMutation, String> {
    let platform = live_state::host_platform();
    reject_unsupported_windows_runtime(platform)?;
    let path = live_state::home(platform).and_then(|home| {
        reject_custom_home(&home)?;
        if install {
            let executable = std::env::current_exe()
                .map_err(|_| "nah-executable-path-unavailable".to_owned())?;
            install_plugin(&home, &executable, policy)
        } else {
            uninstall_plugin(&home)
        }
    })?;
    Ok(RuntimeMutation::new(
        install,
        "OpenCode plugin",
        path,
        Some(
            "Restart OpenCode before use. OpenCode 1.x does not load this plugin; nah is not active there.",
        ),
    ))
}

pub(crate) fn opencode_hook_status() -> Result<RuntimeHookStatus, String> {
    let platform = live_state::host_platform();
    if reject_unsupported_windows_runtime(platform).is_err() {
        return Ok(RuntimeHookStatus::NotConfigured);
    }
    let home = live_state::home(platform)?;
    reject_custom_home(&home)?;
    let paths = OpenCodeHookPaths::new(&home);
    reject_symlinks(&paths)?;
    let bytes = match std::fs::read(&paths.plugin) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(RuntimeHookStatus::NotConfigured);
        }
        Err(_) => return Err("opencode-plugin-read-failed".into()),
    };
    if !owned(&bytes) {
        return Err("opencode-plugin-not-owned".into());
    }
    let executable =
        std::env::current_exe().map_err(|_| "nah-executable-path-unavailable".to_owned())?;
    Ok(
        if bytes == plugin(&executable, FailurePolicy::Delegate)?.as_bytes() {
            RuntimeHookStatus::WiringCurrent
        } else if bytes == plugin(&executable, FailurePolicy::Block)?.as_bytes() {
            RuntimeHookStatus::WiringCurrentFailClosed
        } else {
            let strict = bytes
                .windows(br#"["hook", "opencode", "run", "--fail-closed"]"#.len())
                .any(|part| part == br#"["hook", "opencode", "run", "--fail-closed"]"#);
            let delegate = bytes
                .windows(br#"["hook", "opencode", "run"]"#.len())
                .any(|part| part == br#"["hook", "opencode", "run"]"#);
            RuntimeHookStatus::stale(if strict && !delegate {
                FailurePolicy::Block
            } else {
                FailurePolicy::Delegate
            })
        },
    )
}

pub(crate) fn opencode_self_protection_paths() -> Result<Vec<PathBuf>, String> {
    let platform = live_state::host_platform();
    let home = live_state::home(platform)?;
    reject_custom_home(&home)?;
    Ok(vec![OpenCodeHookPaths::new(&home).plugin])
}

fn reject_custom_home(home: &AbsolutePath) -> Result<(), String> {
    let standard = PathBuf::from(home.as_str()).join(".config");
    if std::env::var_os("XDG_CONFIG_HOME")
        .is_some_and(|configured| Path::new(&configured) != standard)
    {
        Err("custom-XDG_CONFIG_HOME-unsupported".into())
    } else {
        Ok(())
    }
}

fn install_plugin(
    home: &AbsolutePath,
    executable: &Path,
    policy: FailurePolicy,
) -> Result<PathBuf, String> {
    let paths = OpenCodeHookPaths::new(home);
    let lock = acquire_hook_lock(&paths.lock, &OPENCODE_HOOK_LOCK_ERRORS)?;
    reject_symlinks(&paths)?;
    let parent = paths
        .plugin
        .parent()
        .ok_or_else(|| "invalid-opencode-plugin-path".to_owned())?;
    std::fs::create_dir_all(parent).map_err(|_| "opencode-plugin-write-failed")?;
    reject_symlinks(&paths)?;
    let desired = plugin(executable, policy)?;
    match std::fs::read(&paths.plugin) {
        Ok(bytes) if bytes == desired.as_bytes() => {}
        Ok(bytes) if owned(&bytes) => save(&paths.plugin, desired.as_bytes())?,
        Ok(_) => return Err("opencode-plugin-not-owned".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            save(&paths.plugin, desired.as_bytes())?;
        }
        Err(_) => return Err("opencode-plugin-read-failed".into()),
    }
    drop(lock);
    Ok(paths.plugin)
}

fn uninstall_plugin(home: &AbsolutePath) -> Result<PathBuf, String> {
    let paths = OpenCodeHookPaths::new(home);
    let lock = acquire_hook_lock(&paths.lock, &OPENCODE_HOOK_LOCK_ERRORS)?;
    reject_symlinks(&paths)?;
    match std::fs::read(&paths.plugin) {
        Ok(bytes) if owned(&bytes) => {
            std::fs::remove_file(&paths.plugin).map_err(|_| "opencode-plugin-remove-failed")?;
            if let Some(parent) = paths.plugin.parent() {
                sync_parent_directory(parent)
                    .map_err(|_| "opencode-plugin-sync-failed".to_owned())?;
                match std::fs::remove_dir(parent) {
                    Ok(()) => {
                        if let Some(config) = parent.parent() {
                            sync_parent_directory(config)
                                .map_err(|_| "opencode-plugin-sync-failed".to_owned())?;
                        }
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::DirectoryNotEmpty | std::io::ErrorKind::NotFound
                        ) => {}
                    Err(_) => return Err("opencode-plugin-remove-failed".into()),
                }
            }
        }
        Ok(_) => return Err("opencode-plugin-not-owned".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err("opencode-plugin-read-failed".into()),
    }
    drop(lock);
    Ok(paths.plugin)
}

struct OpenCodeHookPaths {
    plugin: PathBuf,
    lock: PathBuf,
    checked_directories: Vec<PathBuf>,
}

impl OpenCodeHookPaths {
    fn new(home: &AbsolutePath) -> Self {
        let home = PathBuf::from(home.as_str());
        let opencode = home.join(".config/opencode");
        let plugins = opencode.join("plugins");
        Self {
            plugin: plugins.join("nah.js"),
            lock: home.join(".nah/opencode-hook.lock"),
            checked_directories: vec![opencode, plugins],
        }
    }
}

const OPENCODE_HOOK_LOCK_ERRORS: HookLockErrorCodes = HookLockErrorCodes {
    invalid_path: "invalid-opencode-hook-lock-path",
    failed: "opencode-hook-lock-failed",
    permissions: "opencode-hook-permissions-failed",
};

fn reject_symlinks(paths: &OpenCodeHookPaths) -> Result<(), String> {
    for directory in &paths.checked_directories {
        reject_hook_path_symlink(directory, "opencode-plugin-symlink-unsupported")?;
    }
    reject_hook_path_symlink(&paths.plugin, "opencode-plugin-symlink-unsupported")
}

fn save(path: &Path, bytes: &[u8]) -> Result<(), String> {
    reject_hook_path_symlink(path, "opencode-plugin-symlink-unsupported")?;
    let parent = path
        .parent()
        .ok_or_else(|| "invalid-opencode-plugin-path".to_owned())?;
    let mut temporary =
        tempfile::NamedTempFile::new_in(parent).map_err(|_| "opencode-plugin-write-failed")?;
    restrict_file_to_owner(temporary.as_file())
        .map_err(|_| "opencode-plugin-permissions-failed".to_owned())?;
    temporary
        .write_all(bytes)
        .map_err(|_| "opencode-plugin-write-failed")?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|_| "opencode-plugin-write-failed")?;
    temporary
        .persist(path)
        .map_err(|_| "opencode-plugin-write-failed")?;
    sync_parent_directory(parent).map_err(|_| "opencode-plugin-sync-failed".to_owned())
}

fn plugin(executable: &Path, policy: FailurePolicy) -> Result<String, String> {
    let executable = executable
        .to_str()
        .ok_or_else(|| "invalid-nah-executable-path".to_owned())?;
    let executable =
        serde_json::to_string(executable).map_err(|_| "invalid-nah-executable-path".to_owned())?;
    let bridge = javascript_decision_bridge(&executable, "opencode", policy);
    Ok(format!(
        r#"{MARKER}
import {{ spawn }} from "node:child_process";

{bridge}
export default {{
  id: "nah",
  async setup(ctx) {{
    await ctx.tool.hook("execute.before", async (event) => {{
      let result;
      try {{
        // The session's own location, not the plugin's, is where its relative
        // paths and shell commands resolve.
        const session = await ctx.session.get({{ sessionID: event.sessionID }});
        result = await decide({{
          tool_name: event.tool,
          tool_input: event.input,
          cwd: session.location.directory,
          session_id: event.sessionID,
        }});
      }} catch {{
        return;
      }}
      if (result.block) throw new Error(result.reason);
    }});
  }},
}};
"#
    ))
}

fn owned(bytes: &[u8]) -> bool {
    let text = String::from_utf8_lossy(bytes);
    text.starts_with(MARKER) && text.contains(r#"["hook", "opencode", "run""#)
}
