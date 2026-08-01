//! Installs and removes nah's user-level Cline PreToolUse hook.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use nah_proto::ctx::{AbsolutePath, Platform};

use crate::live_state;

use super::{RuntimeHookStatus, RuntimeMutation};

const MARKER: &str = "Managed by nah: Cline PreToolUse";

pub(crate) fn mutate_cline_hook(install: bool) -> Result<RuntimeMutation, String> {
    let platform = live_state::host_platform();
    let path = live_state::home(platform).and_then(|home| {
        if install {
            let executable = std::env::current_exe()
                .map_err(|_| "nah-executable-path-unavailable".to_owned())?;
            install_hook(&home, &executable, platform)
        } else {
            uninstall_hook(&home, platform)
        }
    })?;
    Ok(RuntimeMutation::new(
        install,
        "Cline hook",
        path,
        Some(
            "Reload Cline, confirm Hooks in the IDE, and verify the CLI with `cline config hooks --json`.",
        ),
    ))
}

pub(crate) fn cline_hook_status() -> Result<RuntimeHookStatus, String> {
    let platform = live_state::host_platform();
    let home = live_state::home(platform)?;
    let paths = ClineHookPaths::new(&home, platform);
    reject_symlinks(&paths)?;
    let executable =
        std::env::current_exe().map_err(|_| "nah-executable-path-unavailable".to_owned())?;
    let desired = desired_hook(&executable, platform)?;
    let ide = hook_state(&paths.ide_hook, &desired)?;
    let cli = hook_state(&paths.cli_hook, &desired)?;
    if ide.is_none() && cli.is_none() {
        return Ok(RuntimeHookStatus::NotConfigured);
    }
    if ide == Some(true) && cli == Some(true) {
        Ok(RuntimeHookStatus::WiringCurrent)
    } else {
        Ok(RuntimeHookStatus::NeedsReinstall)
    }
}

pub(crate) fn cline_self_protection_paths() -> Result<Vec<PathBuf>, String> {
    let platform = live_state::host_platform();
    let home = live_state::home(platform)?;
    let paths = ClineHookPaths::new(&home, platform);
    Ok(vec![paths.ide_hook, paths.cli_hook])
}

fn install_hook(
    home: &AbsolutePath,
    executable: &Path,
    platform: Platform,
) -> Result<PathBuf, String> {
    let paths = ClineHookPaths::new(home, platform);
    let lock = lock(&paths)?;
    reject_symlinks(&paths)?;
    let desired = desired_hook(executable, platform)?;
    let ide = hook_state(&paths.ide_hook, &desired)?;
    let cli = hook_state(&paths.cli_hook, &desired)?;
    if ide != Some(true) {
        save(&paths.ide_hook, &desired)?;
    }
    if cli != Some(true) {
        save(&paths.cli_hook, &desired)?;
    }
    drop(lock);
    Ok(paths.ide_hook)
}

fn uninstall_hook(home: &AbsolutePath, platform: Platform) -> Result<PathBuf, String> {
    let paths = ClineHookPaths::new(home, platform);
    let lock = lock(&paths)?;
    reject_symlinks(&paths)?;
    for path in paths.hooks() {
        if path.exists() {
            let configured =
                std::fs::read_to_string(path).map_err(|_| "cline-hook-read-failed".to_owned())?;
            if !is_owned(&configured) {
                return Err("cline-hook-file-conflict".into());
            }
        }
    }
    for path in paths.hooks() {
        if path.exists() {
            std::fs::remove_file(path).map_err(|_| "cline-hook-remove-failed")?;
        }
    }
    drop(lock);
    Ok(paths.ide_hook)
}

struct ClineHookPaths {
    ide_hook: PathBuf,
    cli_hook: PathBuf,
    lock: PathBuf,
    directories: Vec<PathBuf>,
}

impl ClineHookPaths {
    fn new(home: &AbsolutePath, platform: Platform) -> Self {
        let home = PathBuf::from(home.as_str());
        let cline = documents_path(&home, platform).join("Cline");
        let ide_hooks = cline.join("Hooks");
        let cli = home.join(".cline");
        let cli_hooks = cli.join("hooks");
        let file = if platform == Platform::Windows {
            "PreToolUse.ps1"
        } else {
            "PreToolUse"
        };
        Self {
            ide_hook: ide_hooks.join(file),
            cli_hook: cli_hooks.join(file),
            lock: home.join(".nah/cline-hook.lock"),
            directories: vec![cline, ide_hooks, cli, cli_hooks],
        }
    }

    fn hooks(&self) -> [&Path; 2] {
        [&self.ide_hook, &self.cli_hook]
    }
}

fn hook_state(path: &Path, desired: &str) -> Result<Option<bool>, String> {
    let configured = match std::fs::read_to_string(path) {
        Ok(configured) => configured,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("cline-hook-read-failed".into()),
    };
    if !is_owned(&configured) {
        return Err("cline-hook-file-conflict".into());
    }
    let current = configured == desired;
    #[cfg(unix)]
    let current = current && executable_file(path)?;
    Ok(Some(current))
}

fn documents_path(home: &Path, platform: Platform) -> PathBuf {
    let resolved = match platform {
        Platform::Linux => std::process::Command::new("xdg-user-dir")
            .arg("DOCUMENTS")
            .output(),
        Platform::Windows => std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "[System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::MyDocuments)",
            ])
            .output(),
        Platform::Macos => return home.join("Documents"),
    };
    resolved
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|path| path.trim().to_owned())
        .filter(|path| !path.is_empty() && Path::new(path).is_absolute())
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join("Documents"))
}

fn desired_hook(executable: &Path, platform: Platform) -> Result<String, String> {
    let executable = executable
        .to_str()
        .ok_or_else(|| "invalid-nah-executable-path".to_owned())?;
    if platform == Platform::Windows {
        let executable = executable.replace('\'', "''");
        Ok(format!(
            "# {MARKER}\n$payload = [Console]::In.ReadToEnd()\n$payload | & '{executable}' hook cline run\nexit $LASTEXITCODE\n"
        ))
    } else {
        Ok(format!(
            "#!/bin/sh\n# {MARKER}\nexec {} hook cline run\n",
            shell_quote(executable)
        ))
    }
}

fn is_owned(contents: &str) -> bool {
    let lines = contents.lines().collect::<Vec<_>>();
    match lines.as_slice() {
        ["#!/bin/sh", marker, command]
            if *marker == format!("# {MARKER}")
                && command.starts_with("exec '")
                && command.ends_with("/nah' hook cline run") =>
        {
            true
        }
        [marker, payload, command, exit]
            if *marker == format!("# {MARKER}")
                && *payload == "$payload = [Console]::In.ReadToEnd()"
                && command.starts_with("$payload | & '")
                && command
                    .to_ascii_lowercase()
                    .ends_with("nah.exe' hook cline run")
                && *exit == "exit $LASTEXITCODE" =>
        {
            true
        }
        _ => false,
    }
}

fn lock(paths: &ClineHookPaths) -> Result<File, String> {
    let parent = paths
        .lock
        .parent()
        .ok_or_else(|| "invalid-cline-hook-lock-path".to_owned())?;
    reject_symlink(parent, "cline-hook-lock-failed")?;
    std::fs::create_dir_all(parent).map_err(|_| "cline-hook-lock-failed")?;
    reject_symlink(&paths.lock, "cline-hook-lock-failed")?;
    let mut options = OpenOptions::new();
    options.create(true).truncate(false).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(&paths.lock)
        .map_err(|_| "cline-hook-lock-failed")?;
    protect_private(&file)?;
    file.lock().map_err(|_| "cline-hook-lock-failed")?;
    Ok(file)
}

fn reject_symlinks(paths: &ClineHookPaths) -> Result<(), String> {
    for directory in &paths.directories {
        reject_symlink(directory, "cline-hook-symlink-unsupported")?;
    }
    for path in paths.hooks() {
        reject_symlink(path, "cline-hook-symlink-unsupported")?;
    }
    Ok(())
}

fn save(path: &Path, contents: &str) -> Result<(), String> {
    reject_symlink(path, "cline-hook-symlink-unsupported")?;
    let parent = path
        .parent()
        .ok_or_else(|| "invalid-cline-hook-path".to_owned())?;
    std::fs::create_dir_all(parent).map_err(|_| "cline-hook-write-failed")?;
    let mut temporary =
        tempfile::NamedTempFile::new_in(parent).map_err(|_| "cline-hook-write-failed")?;
    protect_executable(temporary.as_file())?;
    temporary
        .write_all(contents.as_bytes())
        .map_err(|_| "cline-hook-write-failed")?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|_| "cline-hook-write-failed")?;
    temporary
        .persist(path)
        .map_err(|_| "cline-hook-write-failed")?;
    sync_parent(parent)
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
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
        .map_err(|_| "cline-hook-permissions-failed".into())
}

#[cfg(not(unix))]
fn protect_private(_file: &File) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn protect_executable(file: &File) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(std::fs::Permissions::from_mode(0o700))
        .map_err(|_| "cline-hook-permissions-failed".into())
}

#[cfg(not(unix))]
fn protect_executable(_file: &File) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn executable_file(path: &Path) -> Result<bool, String> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = std::fs::metadata(path).map_err(|_| "cline-hook-read-failed")?;
    Ok(metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
}

#[cfg(unix)]
fn sync_parent(parent: &Path) -> Result<(), String> {
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| "cline-hook-sync-failed".into())
}

#[cfg(not(unix))]
fn sync_parent(_parent: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_posix_and_powershell_hooks_are_owned() {
        let posix = desired_hook(Path::new("/opt/nah"), Platform::Linux).unwrap();
        let windows =
            desired_hook(Path::new(r"C:\Program Files\nah.exe"), Platform::Windows).unwrap();
        assert!(is_owned(&posix));
        assert!(is_owned(&windows));
        assert!(windows.contains("[Console]::In.ReadToEnd()"));
        assert!(!is_owned(&format!("{posix}echo unsafe\n")));
    }
}
