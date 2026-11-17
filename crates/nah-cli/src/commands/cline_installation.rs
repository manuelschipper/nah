//! Installs and removes nah's user-level Cline PreToolUse hook.

use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

use nah_proto::ctx::{AbsolutePath, Platform};

use crate::{live_state, runtime::FailurePolicy};

use super::hook_paths::{
    HookLockErrorCodes, acquire_hook_lock_in_unlinked_directory, reject_hook_path_symlink,
};
use super::shell_word::quote_posix_shell_word;
use super::{RuntimeHookStatus, RuntimeMutation};
use crate::private_files::sync_parent_directory;

const MARKER: &str = "Managed by nah: Cline PreToolUse";

pub(crate) fn mutate_cline_hook(
    install: bool,
    policy: FailurePolicy,
) -> Result<RuntimeMutation, String> {
    let platform = live_state::host_platform();
    let path = live_state::home(platform).and_then(|home| {
        if install {
            let executable = std::env::current_exe()
                .map_err(|_| "nah-executable-path-unavailable".to_owned())?;
            install_cline_hook(&home, &executable, platform, policy)
        } else {
            uninstall_cline_hook(&home, platform)
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
    reject_cline_hook_symlinks(&paths)?;
    let executable =
        std::env::current_exe().map_err(|_| "nah-executable-path-unavailable".to_owned())?;
    let delegate = desired_cline_hook(&executable, platform, FailurePolicy::Delegate)?;
    let strict = desired_cline_hook(&executable, platform, FailurePolicy::Block)?;
    let redundant = redundant_hook(&paths)?.is_some();
    let states = hook_states(&paths, &delegate)?;
    if !redundant && states.iter().all(Option::is_none) {
        return Ok(RuntimeHookStatus::NotConfigured);
    }
    if !redundant && states.iter().all(|state| *state == Some(true)) {
        Ok(RuntimeHookStatus::WiringCurrent)
    } else if !redundant
        && hook_states(&paths, &strict)?
            .iter()
            .all(|state| *state == Some(true))
    {
        Ok(RuntimeHookStatus::WiringCurrentFailClosed)
    } else {
        Ok(RuntimeHookStatus::stale(configured_policy(&paths)?))
    }
}

fn configured_policy(paths: &ClineHookPaths) -> Result<FailurePolicy, String> {
    let mut modes = Vec::new();
    for path in paths.hooks() {
        match std::fs::read_to_string(path) {
            Ok(contents) => modes.push(contents.contains(" hook cline run --fail-closed")),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err("cline-hook-read-failed".into()),
        }
    }
    // A redundant copy may be the only remaining registration, for example
    // after relocated Documents moved back, so it still carries the policy
    if let Some(contents) = redundant_hook(paths)? {
        modes.push(contents.contains(" hook cline run --fail-closed"));
    }
    Ok(
        if !modes.is_empty() && modes.into_iter().all(|strict| strict) {
            FailurePolicy::Block
        } else {
            FailurePolicy::Delegate
        },
    )
}

pub(crate) fn cline_self_protection_paths() -> Result<Vec<PathBuf>, String> {
    let platform = live_state::host_platform();
    let home = live_state::home(platform)?;
    let paths = ClineHookPaths::new(&home, platform);
    Ok(vec![paths.ide_hook, paths.cli_hook])
}

/// Nah-owned Cline hook files, including a relocated Documents directory.
/// Other runtimes discover these without starting Cline's platform helper.
pub(crate) fn installed_cline_hook_paths() -> Vec<PathBuf> {
    let platform = live_state::host_platform();
    let Ok(home) = live_state::home(platform) else {
        return Vec::new();
    };
    let home = Path::new(home.as_str());
    let file = if platform == Platform::Windows {
        "PreToolUse.ps1"
    } else {
        "PreToolUse"
    };
    // Cline's CLI also reads the literal ~/Documents hook when the IDE uses
    // a relocated directory, so both locations can hold active hooks.
    let mut directories = vec![
        home.join("Documents/Cline/Hooks"),
        home.join(".cline/hooks"),
    ];
    let ide = installed_documents_path(home, platform).join("Cline/Hooks");
    if ide != directories[0] {
        directories.push(ide);
    }
    directories
        .into_iter()
        .map(|directory| directory.join(file))
        .filter(|path| {
            std::fs::read_to_string(path)
                .ok()
                .is_some_and(|contents| is_owned_cline_hook(&contents))
        })
        .collect()
}

fn installed_documents_path(home: &Path, platform: Platform) -> PathBuf {
    match platform {
        Platform::Linux => {
            let config = std::env::var_os("XDG_CONFIG_HOME")
                .filter(|path| Path::new(path).is_absolute())
                .map(PathBuf::from)
                .unwrap_or_else(|| home.join(".config"));
            xdg_documents_path(home, &config).unwrap_or_else(|| home.join("Documents"))
        }
        #[cfg(windows)]
        Platform::Windows => windows_documents_path().unwrap_or_else(|| home.join("Documents")),
        _ => home.join("Documents"),
    }
}

/// xdg-user-dir reads this assignment as a double-quoted shell string. Decode
/// its literal escapes and leading $HOME without evaluating shell code.
fn xdg_documents_path(home: &Path, config: &Path) -> Option<PathBuf> {
    let contents = std::fs::read_to_string(config.join("user-dirs.dirs")).ok()?;
    let value = contents
        .lines()
        .rev()
        .find_map(|line| line.trim().strip_prefix("XDG_DOCUMENTS_DIR="))?
        .trim()
        .strip_prefix('"')?
        .strip_suffix('"')?;
    let mut path = String::new();
    let value = if let Some(rest) = value.strip_prefix("$HOME/") {
        path.push_str(home.to_str()?);
        path.push('/');
        rest
    } else if value == "$HOME" {
        return Some(home.to_path_buf());
    } else {
        value
    };
    let mut chars = value.chars();
    while let Some(ch) = chars.next() {
        match ch {
            '\\' => {
                let escaped = chars.next()?;
                if !matches!(escaped, '$' | '`' | '"' | '\\') {
                    path.push('\\');
                }
                path.push(escaped);
            }
            '$' | '`' | '"' => return None,
            _ => path.push(ch),
        }
    }
    let path = PathBuf::from(path);
    path.is_absolute().then_some(path)
}

#[cfg(windows)]
fn windows_documents_path() -> Option<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::UI::Shell::{
        FOLDERID_Documents, KF_FLAG_DONT_VERIFY, SHGetKnownFolderPath,
    };

    let mut path = std::ptr::null_mut();
    // The shell allocates a terminated UTF-16 path with the COM allocator.
    let status = unsafe {
        SHGetKnownFolderPath(
            &FOLDERID_Documents,
            KF_FLAG_DONT_VERIFY as u32,
            std::ptr::null_mut(),
            &mut path,
        )
    };
    if status < 0 {
        return None;
    }
    let mut length = 0;
    while unsafe { *path.add(length) } != 0 {
        length += 1;
    }
    let result = PathBuf::from(std::ffi::OsString::from_wide(unsafe {
        std::slice::from_raw_parts(path, length)
    }));
    unsafe {
        CoTaskMemFree(path.cast());
    }
    Some(result)
}

fn install_cline_hook(
    home: &AbsolutePath,
    executable: &Path,
    platform: Platform,
    policy: FailurePolicy,
) -> Result<PathBuf, String> {
    let paths = ClineHookPaths::new(home, platform);
    let lock = acquire_hook_lock_in_unlinked_directory(&paths.lock, &CLINE_HOOK_LOCK_ERRORS)?;
    reject_cline_hook_symlinks(&paths)?;
    let desired = desired_cline_hook(executable, platform, policy)?;
    let states = hook_states(&paths, &desired)?;
    for (path, state) in paths.hooks().into_iter().zip(states) {
        if state != Some(true) {
            save_cline_hook_script(path, &desired)?;
        }
    }
    if redundant_hook(&paths)?.is_some() {
        std::fs::remove_file(&paths.cli_hook).map_err(|_| "cline-hook-remove-failed")?;
    }
    drop(lock);
    Ok(paths.ide_hook)
}

fn uninstall_cline_hook(home: &AbsolutePath, platform: Platform) -> Result<PathBuf, String> {
    let paths = ClineHookPaths::new(home, platform);
    let lock = acquire_hook_lock_in_unlinked_directory(&paths.lock, &CLINE_HOOK_LOCK_ERRORS)?;
    reject_cline_hook_symlinks(&paths)?;
    for path in paths.hooks() {
        if path.exists() {
            let configured =
                std::fs::read_to_string(path).map_err(|_| "cline-hook-read-failed".to_owned())?;
            if !is_owned_cline_hook(&configured) {
                return Err("cline-hook-file-conflict".into());
            }
        }
    }
    for path in paths.hooks() {
        if path.exists() {
            std::fs::remove_file(path).map_err(|_| "cline-hook-remove-failed")?;
        }
    }
    if redundant_hook(&paths)?.is_some() {
        std::fs::remove_file(&paths.cli_hook).map_err(|_| "cline-hook-remove-failed")?;
    }
    drop(lock);
    Ok(paths.ide_hook)
}

struct ClineHookPaths {
    ide_hook: PathBuf,
    /// The hook in the CLI's own `~/.cline/hooks` root. The CLI also runs
    /// hooks from the literal `home/Documents/Cline/Hooks`, so nah installs
    /// this one only when the IDE's Documents directory is elsewhere;
    /// otherwise the CLI would run nah twice per call.
    cli_hook: PathBuf,
    cli_reads_ide_hook: bool,
    lock: PathBuf,
    directories: Vec<PathBuf>,
}

impl ClineHookPaths {
    /// Discovers paths via `documents_path`, which can launch `xdg-user-dir` on
    /// Linux or PowerShell on Windows. Uses `home/Documents` on macOS or when
    /// the helper fails or returns invalid UTF-8, an empty path, or a relative path.
    fn new(home: &AbsolutePath, platform: Platform) -> Self {
        let home = PathBuf::from(home.as_str());
        let documents = documents_path(&home, platform);
        let cli_reads_ide_hook = documents == home.join("Documents");
        let cline = documents.join("Cline");
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
            cli_reads_ide_hook,
            lock: home.join(".nah/cline-hook.lock"),
            directories: vec![cline, ide_hooks, cli, cli_hooks],
        }
    }

    /// The hooks nah installs.
    fn hooks(&self) -> Vec<&Path> {
        if self.cli_reads_ide_hook {
            vec![&self.ide_hook]
        } else {
            vec![&self.ide_hook, &self.cli_hook]
        }
    }
}

fn hook_states(paths: &ClineHookPaths, desired: &str) -> Result<Vec<Option<bool>>, String> {
    paths
        .hooks()
        .into_iter()
        .map(|path| hook_state(path, desired))
        .collect()
}

/// The contents of nah's own CLI-root hook when it is present although the
/// IDE hook already covers the CLI. A symlink or any script nah did not
/// generate exactly is the user's and stays.
fn redundant_hook(paths: &ClineHookPaths) -> Result<Option<String>, String> {
    if !paths.cli_reads_ide_hook {
        return Ok(None);
    }
    match std::fs::symlink_metadata(&paths.cli_hook) {
        Ok(metadata) if metadata.file_type().is_symlink() => return Ok(None),
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("cline-hook-read-failed".into()),
    }
    let configured =
        std::fs::read_to_string(&paths.cli_hook).map_err(|_| "cline-hook-read-failed")?;
    Ok(is_owned_cline_hook(&configured).then_some(configured))
}

fn hook_state(path: &Path, desired: &str) -> Result<Option<bool>, String> {
    let configured = match std::fs::read_to_string(path) {
        Ok(configured) => configured,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("cline-hook-read-failed".into()),
    };
    if !is_owned_cline_hook(&configured) {
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

fn desired_cline_hook(
    executable: &Path,
    platform: Platform,
    policy: FailurePolicy,
) -> Result<String, String> {
    let executable = executable
        .to_str()
        .ok_or_else(|| "invalid-nah-executable-path".to_owned())?;
    if platform == Platform::Windows {
        let executable = executable.replace('\'', "''");
        Ok(format!(
            "# {MARKER}\n$payload = [Console]::In.ReadToEnd()\n$payload | & '{executable}' hook cline run{}\nexit $LASTEXITCODE\n",
            policy.command_suffix()
        ))
    } else {
        Ok(format!(
            "#!/bin/sh\n# {MARKER}\nexec {} hook cline run{}\n",
            quote_posix_shell_word(executable),
            policy.command_suffix()
        ))
    }
}

/// Whether `contents` is exactly a hook `desired_hook` generates for some nah
/// executable and failure policy. Any other content makes the script the
/// user's, even with nah's marker.
fn is_owned_cline_hook(contents: &str) -> bool {
    let Some((executable, platform)) = generated_executable(contents) else {
        return false;
    };
    [FailurePolicy::Delegate, FailurePolicy::Block]
        .into_iter()
        .any(|policy| {
            desired_cline_hook(Path::new(&executable), platform, policy)
                .is_ok_and(|hook| hook == contents)
        })
}

/// The unquoted nah executable on a generated hook's command line, with the
/// platform whose script form names it.
fn generated_executable(contents: &str) -> Option<(String, Platform)> {
    let command = contents.lines().nth(2)?;
    if let Some(command) = command.strip_prefix("exec '") {
        let (quoted, _) = command.rsplit_once("' hook cline run")?;
        let executable = quoted.replace("'\"'\"'", "'");
        return executable
            .ends_with("/nah")
            .then_some((executable, Platform::Linux));
    }
    let command = command.strip_prefix("$payload | & '")?;
    let (quoted, _) = command.rsplit_once("' hook cline run")?;
    let executable = quoted.replace("''", "'");
    executable
        .to_ascii_lowercase()
        .ends_with("nah.exe")
        .then_some((executable, Platform::Windows))
}

const CLINE_HOOK_LOCK_ERRORS: HookLockErrorCodes = HookLockErrorCodes {
    invalid_path: "invalid-cline-hook-lock-path",
    failed: "cline-hook-lock-failed",
    permissions: "cline-hook-permissions-failed",
};

fn reject_cline_hook_symlinks(paths: &ClineHookPaths) -> Result<(), String> {
    for directory in &paths.directories {
        reject_hook_path_symlink(directory, "cline-hook-symlink-unsupported")?;
    }
    for path in paths.hooks() {
        reject_hook_path_symlink(path, "cline-hook-symlink-unsupported")?;
    }
    Ok(())
}

fn save_cline_hook_script(path: &Path, contents: &str) -> Result<(), String> {
    reject_hook_path_symlink(path, "cline-hook-symlink-unsupported")?;
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
    sync_parent_directory(parent).map_err(|_| "cline-hook-sync-failed".to_owned())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_posix_and_powershell_hooks_are_owned() {
        let posix = desired_cline_hook(
            Path::new("/opt/nah"),
            Platform::Linux,
            FailurePolicy::Delegate,
        )
        .unwrap();
        let windows = desired_cline_hook(
            Path::new(r"C:\Program Files\nah.exe"),
            Platform::Windows,
            FailurePolicy::Delegate,
        )
        .unwrap();
        assert!(is_owned_cline_hook(&posix));
        assert!(is_owned_cline_hook(&windows));
        assert!(windows.contains("[Console]::In.ReadToEnd()"));
        assert!(!is_owned_cline_hook(&format!("{posix}echo unsafe\n")));
    }

    #[test]
    fn xdg_documents_assignment_is_read_without_shell_expansion() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path();
        let config = home.join(".config");
        std::fs::create_dir(&config).unwrap();
        for (value, expected) in [
            (r#""$HOME/My Documents""#, Some(home.join("My Documents"))),
            (
                r#""$HOME/Dokumente/\"quoted\"""#,
                Some(home.join("Dokumente/\"quoted\"")),
            ),
            (r#""$HOME""#, Some(home.to_path_buf())),
            (r#""$(touch marker)""#, None),
            (r#""relative""#, None),
        ] {
            std::fs::write(
                config.join("user-dirs.dirs"),
                format!("XDG_DOCUMENTS_DIR={value}\n"),
            )
            .unwrap();
            assert_eq!(xdg_documents_path(home, &config), expected, "{value}");
        }
    }

    #[test]
    fn mixed_stale_hook_files_default_to_delegate() {
        let temp = tempfile::tempdir().unwrap();
        let paths = ClineHookPaths {
            ide_hook: temp.path().join("ide"),
            cli_hook: temp.path().join("cli"),
            cli_reads_ide_hook: false,
            lock: temp.path().join("lock"),
            directories: vec![],
        };
        std::fs::write(
            &paths.ide_hook,
            desired_cline_hook(Path::new("/old/nah"), Platform::Linux, FailurePolicy::Block)
                .unwrap(),
        )
        .unwrap();
        std::fs::write(
            &paths.cli_hook,
            desired_cline_hook(
                Path::new("/old/nah"),
                Platform::Linux,
                FailurePolicy::Delegate,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(configured_policy(&paths).unwrap(), FailurePolicy::Delegate);

        std::fs::remove_file(&paths.cli_hook).unwrap();
        assert_eq!(configured_policy(&paths).unwrap(), FailurePolicy::Block);
    }
}
