//! Removes the Amp system plugin of Nah 1.x.

use std::path::PathBuf;

use nah_proto::ctx::AbsolutePath;

use crate::live_state;

use super::super::RuntimeMutation;
use super::super::hook_paths::{HookLockErrorCodes, acquire_hook_lock, reject_hook_path_symlink};
use super::super::runtime::reject_unsupported_windows_runtime;
use crate::private_files::sync_parent_directory;

const MARKER: &str = "// Managed by nah.";

pub(super) fn uninstall() -> Result<RuntimeMutation, String> {
    let platform = live_state::host_platform();
    reject_unsupported_windows_runtime(platform)?;
    let path = live_state::home(platform).and_then(|home| uninstall_amp_plugin(&home))?;
    Ok(RuntimeMutation::new(false, "Amp plugin", path, None))
}

fn uninstall_amp_plugin(home: &AbsolutePath) -> Result<PathBuf, String> {
    let paths = AmpHookPaths::new(home);
    let lock = acquire_hook_lock(&paths.lock, &AMP_HOOK_LOCK_ERRORS)?;
    reject_amp_hook_symlinks(&paths)?;
    match std::fs::read(&paths.plugin) {
        Ok(bytes) if is_owned_amp_plugin(&bytes) => {
            std::fs::remove_file(&paths.plugin).map_err(|_| "amp-plugin-remove-failed")?;
            if let Some(parent) = paths.plugin.parent() {
                sync_parent_directory(parent).map_err(|_| "amp-plugin-sync-failed".to_owned())?;
                match std::fs::remove_dir(parent) {
                    Ok(()) => {
                        if let Some(config) = parent.parent() {
                            sync_parent_directory(config)
                                .map_err(|_| "amp-plugin-sync-failed".to_owned())?;
                        }
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::DirectoryNotEmpty | std::io::ErrorKind::NotFound
                        ) => {}
                    Err(_) => return Err("amp-plugin-remove-failed".into()),
                }
            }
        }
        Ok(_) => return Err("amp-plugin-not-owned".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err("amp-plugin-read-failed".into()),
    }
    drop(lock);
    Ok(paths.plugin)
}

struct AmpHookPaths {
    plugin: PathBuf,
    lock: PathBuf,
    checked_directories: Vec<PathBuf>,
}

impl AmpHookPaths {
    fn new(home: &AbsolutePath) -> Self {
        let home = PathBuf::from(home.as_str());
        let amp = home.join(".config/amp");
        let plugins = amp.join("plugins");
        Self {
            plugin: plugins.join("nah.ts"),
            lock: home.join(".nah/amp-hook.lock"),
            checked_directories: vec![amp, plugins],
        }
    }
}

const AMP_HOOK_LOCK_ERRORS: HookLockErrorCodes = HookLockErrorCodes {
    invalid_path: "invalid-amp-hook-lock-path",
    failed: "amp-hook-lock-failed",
    permissions: "amp-hook-permissions-failed",
};

fn reject_amp_hook_symlinks(paths: &AmpHookPaths) -> Result<(), String> {
    for directory in &paths.checked_directories {
        reject_hook_path_symlink(directory, "amp-plugin-symlink-unsupported")?;
    }
    reject_hook_path_symlink(&paths.plugin, "amp-plugin-symlink-unsupported")
}

fn is_owned_amp_plugin(bytes: &[u8]) -> bool {
    let text = String::from_utf8_lossy(bytes);
    text.starts_with(MARKER) && text.contains(r#"["hook", "amp", "run""#)
}
