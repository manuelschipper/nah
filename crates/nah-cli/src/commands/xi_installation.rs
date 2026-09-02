//! Installs and removes nah's user-level Xi before-bash hook.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use nah_proto::ctx::AbsolutePath;

use crate::{live_state, runtime::FailurePolicy};

use super::runtime::reject_unsupported_windows_runtime;
use super::{RuntimeHookStatus, RuntimeMutation};

const MARKER: &str = "Managed by nah: Xi before-bash";

pub(crate) fn mutate_xi_hook(
    install: bool,
    policy: FailurePolicy,
) -> Result<RuntimeMutation, String> {
    let platform = live_state::host_platform();
    reject_unsupported_windows_runtime(platform)?;
    let home = live_state::home(platform)?;
    let path = if install {
        let executable =
            std::env::current_exe().map_err(|_| "nah-executable-path-unavailable".to_owned())?;
        install_hook(&home, &executable, policy)?
    } else {
        uninstall_hook(&home)?
    };
    Ok(RuntimeMutation::new(install, "Xi hook", path, None))
}

pub(crate) fn xi_hook_status() -> Result<RuntimeHookStatus, String> {
    let platform = live_state::host_platform();
    if reject_unsupported_windows_runtime(platform).is_err() {
        return Ok(RuntimeHookStatus::NotConfigured);
    }
    let home = live_state::home(platform)?;
    let paths = XiHookPaths::new(&home);
    reject_symlinks(&paths)?;
    let Some(configured) = load(&paths.hook)? else {
        return Ok(RuntimeHookStatus::NotConfigured);
    };
    if !is_owned(&configured) {
        return Err("xi-hook-file-conflict".into());
    }
    let executable =
        std::env::current_exe().map_err(|_| "nah-executable-path-unavailable".to_owned())?;
    if configured == desired_hook(&executable, FailurePolicy::Delegate)?
        && executable_file(&paths.hook)?
    {
        Ok(RuntimeHookStatus::WiringCurrent)
    } else if configured == desired_hook(&executable, FailurePolicy::Block)?
        && executable_file(&paths.hook)?
    {
        Ok(RuntimeHookStatus::WiringCurrentFailClosed)
    } else {
        Ok(RuntimeHookStatus::stale(
            if configured.contains("run --fail-closed") {
                FailurePolicy::Block
            } else {
                FailurePolicy::Delegate
            },
        ))
    }
}

pub(crate) fn xi_self_protection_paths() -> Result<Vec<PathBuf>, String> {
    let platform = live_state::host_platform();
    let home = live_state::home(platform)?;
    Ok(vec![XiHookPaths::new(&home).hook])
}

fn install_hook(
    home: &AbsolutePath,
    executable: &Path,
    policy: FailurePolicy,
) -> Result<PathBuf, String> {
    let paths = XiHookPaths::new(home);
    let lock = lock(&paths)?;
    reject_symlinks(&paths)?;
    let desired = desired_hook(executable, policy)?;
    if let Some(configured) = load(&paths.hook)? {
        if configured == desired && executable_file(&paths.hook)? {
            drop(lock);
            return Ok(paths.hook);
        }
        if !is_owned(&configured) {
            return Err("xi-hook-file-conflict".into());
        }
    }
    save(&paths.hook, &desired)?;
    drop(lock);
    Ok(paths.hook)
}

fn uninstall_hook(home: &AbsolutePath) -> Result<PathBuf, String> {
    let paths = XiHookPaths::new(home);
    let lock = lock(&paths)?;
    reject_symlinks(&paths)?;
    if let Some(configured) = load(&paths.hook)? {
        if !is_owned(&configured) {
            return Err("xi-hook-file-conflict".into());
        }
        std::fs::remove_file(&paths.hook).map_err(|_| "xi-hook-remove-failed")?;
        sync_parent(
            paths
                .hook
                .parent()
                .ok_or_else(|| "invalid-xi-hook-path".to_owned())?,
        )?;
    }
    drop(lock);
    Ok(paths.hook)
}

struct XiHookPaths {
    root: PathBuf,
    hooks: PathBuf,
    hook: PathBuf,
    lock: PathBuf,
}

impl XiHookPaths {
    fn new(home: &AbsolutePath) -> Self {
        let home = PathBuf::from(home.as_str());
        let root = home.join(".xi");
        let hooks = root.join("hooks");
        Self {
            root,
            hook: hooks.join("before-bash"),
            hooks,
            lock: home.join(".nah/xi-hook.lock"),
        }
    }
}

fn desired_hook(executable: &Path, policy: FailurePolicy) -> Result<String, String> {
    let executable = executable
        .to_str()
        .ok_or_else(|| "invalid-nah-executable-path".to_owned())?;
    Ok(format!(
        "#!/bin/sh\n# {MARKER}\nexec {} hook xi run{}\n",
        shell_quote(executable),
        policy.command_suffix()
    ))
}

fn is_owned(contents: &str) -> bool {
    let contents = contents.replacen(" hook xi run --fail-closed", " hook xi run", 1);
    let lines = contents.lines().collect::<Vec<_>>();
    let ["#!/bin/sh", marker, command] = lines.as_slice() else {
        return false;
    };
    if *marker != format!("# {MARKER}") {
        return false;
    }
    command
        .strip_prefix("exec ")
        .and_then(|command| command.strip_suffix(" hook xi run"))
        .is_some_and(|executable| {
            executable.starts_with('\'') && executable.ends_with('\'') && executable.len() > 2 && {
                let decoded = executable[1..executable.len() - 1].replace("'\"'\"'", "'");
                shell_quote(&decoded) == executable
                    && Path::new(&decoded).is_absolute()
                    && Path::new(&decoded)
                        .file_name()
                        .is_some_and(|name| name == "nah")
            }
        })
}

fn load(path: &Path) -> Result<Option<String>, String> {
    match std::fs::read_to_string(path) {
        Ok(contents) => Ok(Some(contents)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err("xi-hook-read-failed".into()),
    }
}

fn lock(paths: &XiHookPaths) -> Result<File, String> {
    let parent = paths
        .lock
        .parent()
        .ok_or_else(|| "invalid-xi-hook-lock-path".to_owned())?;
    reject_symlink(parent, "xi-hook-lock-failed")?;
    std::fs::create_dir_all(parent).map_err(|_| "xi-hook-lock-failed")?;
    reject_symlink(&paths.lock, "xi-hook-lock-failed")?;
    let mut options = OpenOptions::new();
    options.create(true).truncate(false).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(&paths.lock)
        .map_err(|_| "xi-hook-lock-failed")?;
    protect_private(&file)?;
    file.lock().map_err(|_| "xi-hook-lock-failed")?;
    Ok(file)
}

fn reject_symlinks(paths: &XiHookPaths) -> Result<(), String> {
    for path in [&paths.root, &paths.hooks, &paths.hook] {
        reject_symlink(path, "xi-hook-symlink-unsupported")?;
    }
    Ok(())
}

fn reject_symlink(path: &Path, error: &'static str) -> Result<(), String> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(error.into()),
        Ok(_) => Ok(()),
        Err(found) if found.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(error.into()),
    }
}

fn save(path: &Path, contents: &str) -> Result<(), String> {
    reject_symlink(path, "xi-hook-symlink-unsupported")?;
    let parent = path
        .parent()
        .ok_or_else(|| "invalid-xi-hook-path".to_owned())?;
    std::fs::create_dir_all(parent).map_err(|_| "xi-hook-write-failed")?;
    let mut temporary =
        tempfile::NamedTempFile::new_in(parent).map_err(|_| "xi-hook-write-failed")?;
    protect_executable(temporary.as_file())?;
    temporary
        .write_all(contents.as_bytes())
        .map_err(|_| "xi-hook-write-failed")?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|_| "xi-hook-write-failed")?;
    temporary
        .persist(path)
        .map_err(|_| "xi-hook-write-failed")?;
    sync_parent(parent)
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

#[cfg(unix)]
fn protect_private(file: &File) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|_| "xi-hook-permissions-failed".into())
}

#[cfg(not(unix))]
fn protect_private(_file: &File) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn protect_executable(file: &File) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(std::fs::Permissions::from_mode(0o700))
        .map_err(|_| "xi-hook-permissions-failed".into())
}

#[cfg(not(unix))]
fn protect_executable(_file: &File) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn executable_file(path: &Path) -> Result<bool, String> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = std::fs::metadata(path).map_err(|_| "xi-hook-read-failed")?;
    Ok(metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn executable_file(_path: &Path) -> Result<bool, String> {
    Ok(false)
}

#[cfg(unix)]
fn sync_parent(parent: &Path) -> Result<(), String> {
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| "xi-hook-sync-failed".into())
}

#[cfg(not(unix))]
fn sync_parent(_parent: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_hook_is_owned_and_modified_hooks_are_not() {
        let hook = desired_hook(Path::new("/opt/nah"), FailurePolicy::Delegate).unwrap();
        let strict = desired_hook(Path::new("/opt/nah"), FailurePolicy::Block).unwrap();
        assert!(is_owned(&hook));
        assert!(is_owned(&strict));
        assert!(!is_owned(&format!("{hook}echo unsafe\n")));
    }
}
