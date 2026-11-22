//! Removes the user-level Cline hook scripts of Nah 1.x.

use std::path::{Path, PathBuf};

use nah_proto::ctx::{AbsolutePath, Platform};

use crate::{live_state, runtime::FailurePolicy};

use super::super::RuntimeMutation;
use super::super::hook_paths::{
    HookLockErrorCodes, acquire_hook_lock_in_unlinked_directory, reject_hook_path_symlink,
};
use super::super::shell_word::quote_posix_shell_word;

/// The hook events Nah installed a script for: the first decided.
const EVENTS: [&str; 2] = ["PreToolUse", "PostToolUse"];

pub(super) fn uninstall() -> Result<RuntimeMutation, String> {
    let platform = live_state::host_platform();
    let path = live_state::home(platform).and_then(|home| uninstall_cline_hook(&home, platform))?;
    Ok(RuntimeMutation::new(false, "Cline hook", path, None))
}

fn uninstall_cline_hook(home: &AbsolutePath, platform: Platform) -> Result<PathBuf, String> {
    let paths = ClineHookPaths::new(home, platform);
    let lock = acquire_hook_lock_in_unlinked_directory(&paths.lock, &CLINE_HOOK_LOCK_ERRORS)?;
    for directory in &paths.directories {
        reject_hook_path_symlink(directory, "cline-hook-symlink-unsupported")?;
    }
    // Only a script Nah generated exactly is Nah's. A link, or a script
    // without Nah's marker, is the user's and stays without being followed:
    // 1.x wrote only the PreToolUse script, so other events' hooks are the
    // user's. A Nah script someone edited stays too, and is reported so it
    // can be removed by hand.
    let mut changed = Vec::new();
    for paths in EVENTS.map(|event| paths.for_event(event, platform)) {
        for path in paths.hooks() {
            match std::fs::symlink_metadata(path) {
                Ok(metadata) if metadata.is_file() => {}
                Ok(_) => continue,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(_) => return Err("cline-hook-read-failed".into()),
            }
            let configured =
                std::fs::read_to_string(path).map_err(|_| "cline-hook-read-failed".to_owned())?;
            if is_owned_cline_hook(&configured) {
                std::fs::remove_file(path).map_err(|_| "cline-hook-remove-failed")?;
            } else if configured.contains("Managed by nah: Cline") {
                changed.push(path.display().to_string());
            }
        }
        if redundant_hook(&paths)?.is_some() {
            std::fs::remove_file(&paths.cli_hook).map_err(|_| "cline-hook-remove-failed")?;
        }
    }
    drop(lock);
    if !changed.is_empty() {
        return Err(format!(
            "cline-hook-file-conflict: {} changed since Nah wrote it; remove it by hand",
            changed.join(", ")
        ));
    }
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
        let file = hook_file(EVENTS[0], platform);
        Self {
            ide_hook: ide_hooks.join(&file),
            cli_hook: cli_hooks.join(file),
            cli_reads_ide_hook,
            lock: home.join(".nah/cline-hook.lock"),
            directories: vec![cline, ide_hooks, cli, cli_hooks],
        }
    }

    /// The same hooks for `event`'s script.
    fn for_event(&self, event: &str, platform: Platform) -> Self {
        let beside = |path: &Path| path.with_file_name(hook_file(event, platform));
        Self {
            ide_hook: beside(&self.ide_hook),
            cli_hook: beside(&self.cli_hook),
            cli_reads_ide_hook: self.cli_reads_ide_hook,
            lock: self.lock.clone(),
            directories: self.directories.clone(),
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

/// The file Cline runs for `event`.
fn hook_file(event: &str, platform: Platform) -> String {
    if platform == Platform::Windows {
        format!("{event}.ps1")
    } else {
        event.to_owned()
    }
}

fn desired_cline_hook(
    executable: &Path,
    platform: Platform,
    policy: FailurePolicy,
    event: &str,
) -> Result<String, String> {
    let executable = executable
        .to_str()
        .ok_or_else(|| "invalid-nah-executable-path".to_owned())?;
    let marker = format!("Managed by nah: Cline {event}");
    if platform == Platform::Windows {
        let executable = executable.replace('\'', "''");
        Ok(format!(
            "# {marker}\n$payload = [Console]::In.ReadToEnd()\n$payload | & '{executable}' hook cline run{}\nexit $LASTEXITCODE\n",
            policy.command_suffix()
        ))
    } else {
        Ok(format!(
            "#!/bin/sh\n# {marker}\nexec {} hook cline run{}\n",
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
        .flat_map(|policy| EVENTS.map(|event| (policy, event)))
        .any(|(policy, event)| {
            desired_cline_hook(Path::new(&executable), platform, policy, event)
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
