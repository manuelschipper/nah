//! Installs and removes nah's global Pi tool-call extension.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use nah_proto::ctx::AbsolutePath;

use crate::{live_state, runtime::FailurePolicy};

use super::{RuntimeHookStatus, RuntimeMutation};

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
            install_extension(&home, &executable, policy)
        } else {
            uninstall_extension(&home)
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
    reject_symlinks(&paths)?;
    let bytes = match std::fs::read(&paths.extension) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(RuntimeHookStatus::NotConfigured);
        }
        Err(_) => return Err("pi-extension-read-failed".into()),
    };
    if !owned(&bytes) {
        return Err("pi-extension-not-owned".into());
    }
    let executable =
        std::env::current_exe().map_err(|_| "nah-executable-path-unavailable".to_owned())?;
    Ok(
        if bytes == extension(&executable, FailurePolicy::Delegate)?.as_bytes() {
            RuntimeHookStatus::WiringCurrent
        } else if bytes == extension(&executable, FailurePolicy::Block)?.as_bytes() {
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

fn install_extension(
    home: &AbsolutePath,
    executable: &Path,
    policy: FailurePolicy,
) -> Result<PathBuf, String> {
    let paths = PiHookPaths::new(home);
    let lock = lock(&paths)?;
    reject_symlinks(&paths)?;
    let parent = paths
        .extension
        .parent()
        .ok_or_else(|| "invalid-pi-extension-path".to_owned())?;
    std::fs::create_dir_all(parent).map_err(|_| "pi-extension-write-failed")?;
    reject_symlinks(&paths)?;
    let desired = extension(executable, policy)?;
    match std::fs::read(&paths.extension) {
        Ok(bytes) if bytes == desired.as_bytes() => {}
        Ok(bytes) if owned(&bytes) => save(&paths.extension, desired.as_bytes())?,
        Ok(_) => return Err("pi-extension-not-owned".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            save(&paths.extension, desired.as_bytes())?;
        }
        Err(_) => return Err("pi-extension-read-failed".into()),
    }
    drop(lock);
    Ok(paths.extension)
}

fn uninstall_extension(home: &AbsolutePath) -> Result<PathBuf, String> {
    let paths = PiHookPaths::new(home);
    let lock = lock(&paths)?;
    reject_symlinks(&paths)?;
    match std::fs::read(&paths.extension) {
        Ok(bytes) if owned(&bytes) => {
            std::fs::remove_file(&paths.extension).map_err(|_| "pi-extension-remove-failed")?;
            if let Some(parent) = paths.extension.parent() {
                sync_parent(parent)?;
                match std::fs::remove_dir(parent) {
                    Ok(()) => {
                        if let Some(extensions) = parent.parent() {
                            sync_parent(extensions)?;
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

fn lock(paths: &PiHookPaths) -> Result<File, String> {
    let parent = paths
        .lock
        .parent()
        .ok_or_else(|| "invalid-pi-hook-lock-path".to_owned())?;
    std::fs::create_dir_all(parent).map_err(|_| "pi-hook-lock-failed")?;
    reject_symlink(&paths.lock, "pi-hook-lock-failed")?;
    let mut options = OpenOptions::new();
    options.create(true).truncate(false).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(&paths.lock)
        .map_err(|_| "pi-hook-lock-failed")?;
    protect_private(&file, "pi-hook-permissions-failed")?;
    file.lock().map_err(|_| "pi-hook-lock-failed")?;
    Ok(file)
}

fn reject_symlinks(paths: &PiHookPaths) -> Result<(), String> {
    for directory in &paths.checked_directories {
        reject_symlink(directory, "pi-extension-symlink-unsupported")?;
    }
    reject_symlink(&paths.extension, "pi-extension-symlink-unsupported")
}

fn reject_symlink(path: &Path, error: &str) -> Result<(), String> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(error.into()),
        Ok(_) => Ok(()),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(error.into()),
    }
}

fn save(path: &Path, bytes: &[u8]) -> Result<(), String> {
    reject_symlink(path, "pi-extension-symlink-unsupported")?;
    let parent = path
        .parent()
        .ok_or_else(|| "invalid-pi-extension-path".to_owned())?;
    let mut temporary =
        tempfile::NamedTempFile::new_in(parent).map_err(|_| "pi-extension-write-failed")?;
    protect_private(temporary.as_file(), "pi-extension-permissions-failed")?;
    temporary
        .write_all(bytes)
        .map_err(|_| "pi-extension-write-failed")?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|_| "pi-extension-write-failed")?;
    temporary
        .persist(path)
        .map_err(|_| "pi-extension-write-failed")?;
    sync_parent(parent)
}

fn extension(executable: &Path, policy: FailurePolicy) -> Result<String, String> {
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

fn owned(bytes: &[u8]) -> bool {
    let text = String::from_utf8_lossy(bytes);
    text.starts_with(MARKER) && text.contains(r#"["hook", "pi", "run""#)
}

#[cfg(unix)]
fn protect_private(file: &File, error: &str) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|_| error.into())
}

#[cfg(not(unix))]
fn protect_private(_file: &File, _error: &str) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn sync_parent(parent: &Path) -> Result<(), String> {
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| "pi-extension-sync-failed".into())
}

#[cfg(not(unix))]
fn sync_parent(_parent: &Path) -> Result<(), String> {
    Ok(())
}
