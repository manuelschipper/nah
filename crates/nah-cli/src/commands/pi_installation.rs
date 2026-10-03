//! Installs and removes nah's global Pi tool-call extension.

use std::path::{Path, PathBuf};

use nah_proto::ctx::AbsolutePath;

use crate::{live_state, runtime::FailurePolicy};

use super::hook_paths::{
    HookFileWriteErrorCodes, HookLockErrorCodes, acquire_hook_lock, reject_hook_path_symlink,
    write_hook_file_atomically,
};
use super::{RuntimeHookStatus, RuntimeMutation};
use crate::private_files::sync_parent_directory;

const MARKER: &str = "// Managed by nah.";

pub(crate) fn mutate_pi_hook(
    install: bool,
    policy: FailurePolicy,
) -> Result<RuntimeMutation, String> {
    let platform = live_state::host_platform();
    let path = live_state::home(platform).and_then(|home| {
        if install {
            let executable = std::env::current_exe()
                .map_err(|_| "nah-executable-path-unavailable".to_owned())?;
            install_pi_extension(&home, &executable, policy)
        } else {
            uninstall_pi_extension(&home)
        }
    })?;
    Ok(RuntimeMutation::new(
        install,
        "Pi extension",
        path,
        Some("Run /reload in Pi before use."),
    ))
}

pub(crate) fn pi_hook_status() -> Result<RuntimeHookStatus, String> {
    let platform = live_state::host_platform();
    let home = live_state::home(platform)?;
    let paths = PiHookPaths::new(&home);
    reject_pi_hook_symlinks(&paths)?;
    let bytes = match std::fs::read(&paths.extension) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(RuntimeHookStatus::NotConfigured);
        }
        Err(_) => return Err("pi-extension-read-failed".into()),
    };
    if !is_owned_pi_extension(&bytes) {
        return Err("pi-extension-not-owned".into());
    }
    let executable =
        std::env::current_exe().map_err(|_| "nah-executable-path-unavailable".to_owned())?;
    Ok(
        if bytes == pi_extension_source(&executable, FailurePolicy::Delegate)?.as_bytes() {
            RuntimeHookStatus::WiringCurrent
        } else if bytes == pi_extension_source(&executable, FailurePolicy::Block)?.as_bytes() {
            RuntimeHookStatus::WiringCurrentFailClosed
        } else {
            let strict = bytes
                .windows(br#"["hook", "pi", "run", "--fail-closed"]"#.len())
                .any(|part| part == br#"["hook", "pi", "run", "--fail-closed"]"#);
            let delegate = bytes
                .windows(br#"["hook", "pi", "run"]"#.len())
                .any(|part| part == br#"["hook", "pi", "run"]"#);
            RuntimeHookStatus::stale(if strict && !delegate {
                FailurePolicy::Block
            } else {
                FailurePolicy::Delegate
            })
        },
    )
}

pub(crate) fn pi_self_protection_paths() -> Result<Vec<PathBuf>, String> {
    let platform = live_state::host_platform();
    let home = live_state::home(platform)?;
    Ok(vec![PiHookPaths::new(&home).extension])
}

fn install_pi_extension(
    home: &AbsolutePath,
    executable: &Path,
    policy: FailurePolicy,
) -> Result<PathBuf, String> {
    let paths = PiHookPaths::new(home);
    let lock = acquire_hook_lock(&paths.lock, &PI_HOOK_LOCK_ERRORS)?;
    reject_pi_hook_symlinks(&paths)?;
    let parent = paths
        .extension
        .parent()
        .ok_or_else(|| "invalid-pi-extension-path".to_owned())?;
    std::fs::create_dir_all(parent).map_err(|_| "pi-extension-write-failed")?;
    reject_pi_hook_symlinks(&paths)?;
    let desired = pi_extension_source(executable, policy)?;
    match std::fs::read(&paths.extension) {
        Ok(bytes) if bytes == desired.as_bytes() => {}
        Ok(bytes) if is_owned_pi_extension(&bytes) => {
            save_pi_extension(&paths.extension, desired.as_bytes())?
        }
        Ok(_) => return Err("pi-extension-not-owned".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            save_pi_extension(&paths.extension, desired.as_bytes())?;
        }
        Err(_) => return Err("pi-extension-read-failed".into()),
    }
    drop(lock);
    Ok(paths.extension)
}

fn uninstall_pi_extension(home: &AbsolutePath) -> Result<PathBuf, String> {
    let paths = PiHookPaths::new(home);
    let lock = acquire_hook_lock(&paths.lock, &PI_HOOK_LOCK_ERRORS)?;
    reject_pi_hook_symlinks(&paths)?;
    match std::fs::read(&paths.extension) {
        Ok(bytes) if is_owned_pi_extension(&bytes) => {
            std::fs::remove_file(&paths.extension).map_err(|_| "pi-extension-remove-failed")?;
            if let Some(parent) = paths.extension.parent() {
                sync_parent_directory(parent).map_err(|_| "pi-extension-sync-failed".to_owned())?;
                match std::fs::remove_dir(parent) {
                    Ok(()) => {
                        if let Some(extensions) = parent.parent() {
                            sync_parent_directory(extensions)
                                .map_err(|_| "pi-extension-sync-failed".to_owned())?;
                        }
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::DirectoryNotEmpty | std::io::ErrorKind::NotFound
                        ) => {}
                    Err(_) => return Err("pi-extension-remove-failed".into()),
                }
            }
        }
        Ok(_) => return Err("pi-extension-not-owned".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err("pi-extension-read-failed".into()),
    }
    drop(lock);
    Ok(paths.extension)
}

struct PiHookPaths {
    extension: PathBuf,
    lock: PathBuf,
    checked_directories: Vec<PathBuf>,
}

impl PiHookPaths {
    fn new(home: &AbsolutePath) -> Self {
        let home = PathBuf::from(home.as_str());
        let pi = home.join(".pi");
        let agent = pi.join("agent");
        let extensions = agent.join("extensions");
        let nah = extensions.join("nah");
        Self {
            extension: nah.join("index.js"),
            lock: home.join(".nah/pi-hook.lock"),
            checked_directories: vec![pi, agent, extensions, nah],
        }
    }
}

const PI_HOOK_LOCK_ERRORS: HookLockErrorCodes = HookLockErrorCodes {
    invalid_path: "invalid-pi-hook-lock-path",
    failed: "pi-hook-lock-failed",
    permissions: "pi-hook-permissions-failed",
};

fn reject_pi_hook_symlinks(paths: &PiHookPaths) -> Result<(), String> {
    for directory in &paths.checked_directories {
        reject_hook_path_symlink(directory, "pi-extension-symlink-unsupported")?;
    }
    reject_hook_path_symlink(&paths.extension, "pi-extension-symlink-unsupported")
}

const PI_EXTENSION_WRITE_ERRORS: HookFileWriteErrorCodes = HookFileWriteErrorCodes {
    invalid_path: "invalid-pi-extension-path",
    write_failed: "pi-extension-write-failed",
    permissions: "pi-extension-permissions-failed",
    sync_failed: "pi-extension-sync-failed",
};

fn save_pi_extension(path: &Path, bytes: &[u8]) -> Result<(), String> {
    reject_hook_path_symlink(path, "pi-extension-symlink-unsupported")?;
    write_hook_file_atomically(path, bytes, &PI_EXTENSION_WRITE_ERRORS)
}

fn pi_extension_source(executable: &Path, policy: FailurePolicy) -> Result<String, String> {
    let executable = executable
        .to_str()
        .ok_or_else(|| "invalid-nah-executable-path".to_owned())?;
    let executable =
        serde_json::to_string(executable).map_err(|_| "invalid-nah-executable-path".to_owned())?;
    let failure_arg = if policy == FailurePolicy::Block {
        r#", "--fail-closed""#
    } else {
        ""
    };
    Ok(format!(
        r#"{MARKER}
const {{ spawn }} = require("node:child_process");
const nahExecutable = {executable};
const maxOutputBytes = 65536;

function decide(event, context) {{
  return new Promise((resolve, reject) => {{
    const child = spawn(nahExecutable, ["hook", "pi", "run"{failure_arg}], {{
      stdio: ["pipe", "pipe", "pipe"],
    }});
    let stdout = "";
    let stderr = "";
    let settled = false;
    let timer;
    const cleanup = () => {{
      clearTimeout(timer);
      context.signal?.removeEventListener("abort", abort);
    }};
    const fail = (error) => {{
      if (settled) return;
      settled = true;
      cleanup();
      child.kill();
      reject(error);
    }};
    const append = (current, chunk) => {{
      const next = current + chunk.toString();
      if (Buffer.byteLength(next) > maxOutputBytes) {{
        fail(new Error("nah output limit exceeded"));
      }}
      return next;
    }};
    const abort = () => fail(new Error("nah decision cancelled"));
    timer = setTimeout(() => fail(new Error("nah decision timed out")), 5000);
    if (context.signal?.aborted) return fail(new Error("nah decision cancelled"));
    context.signal?.addEventListener("abort", abort, {{ once: true }});
    child.on("error", fail);
    child.stdout.on("data", (chunk) => {{ stdout = append(stdout, chunk); }});
    child.stderr.on("data", (chunk) => {{ stderr = append(stderr, chunk); }});
    child.on("close", (code) => {{
      if (settled) return;
      settled = true;
      cleanup();
      if (code !== 0) return reject(new Error("nah decision failed"));
      try {{
        const result = JSON.parse(stdout);
        if (typeof result.block !== "boolean") throw new Error("invalid nah decision");
        if (typeof result.evaluation_failed !== "boolean") throw new Error("invalid nah failure state");
        if (result.block && typeof result.reason !== "string") throw new Error("invalid nah reason");
        resolve(result);
      }} catch (error) {{
        reject(error);
      }}
    }});
    child.stdin.on("error", fail);
    child.stdin.end(JSON.stringify({{
      tool_name: event.toolName,
      tool_input: event.input,
      cwd: context.cwd,
    }}));
  }});
}}

module.exports = function nahPiExtension(pi) {{
  pi.on("tool_call", async (event, context) => {{
    try {{
      const result = await decide(event, context);
      if (result.evaluation_failed && context.hasUI) {{
        try {{
          context.ui.notify(
            result.block
              ? "nah - evaluation was incomplete; another guard blocked this call"
              : "nah - evaluation failed; this call was delegated to the runtime",
            "warning",
          );
        }} catch {{}}
      }}
      if (result.block) return {{ block: true, reason: result.reason }};
    }} catch {{
      if (context.hasUI) {{
        try {{
          context.ui.notify(
            "nah - evaluation failed; this call was delegated to the runtime",
            "warning",
          );
        }} catch {{}}
      }}
      return undefined;
    }}
  }});
}};
"#
    ))
}

fn is_owned_pi_extension(bytes: &[u8]) -> bool {
    let text = String::from_utf8_lossy(bytes);
    text.starts_with(MARKER) && text.contains(r#"["hook", "pi", "run""#)
}
