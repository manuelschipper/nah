//! Installs and removes nah's global Prime Agent tool-call extension.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use nah_proto::ctx::AbsolutePath;

use crate::{live_state, runtime::FailurePolicy};

use super::{RuntimeHookStatus, RuntimeMutation};

const MARKER: &str = "// Managed by nah.";

pub(crate) fn mutate_prime_agent_hook(
    install: bool,
    policy: FailurePolicy,
) -> Result<RuntimeMutation, String> {
    let platform = live_state::host_platform();
    let path = live_state::home(platform).and_then(|home| {
        let agent_dir = configured_agent_dir(&home, platform)?;
        if install {
            let executable = std::env::current_exe()
                .map_err(|_| "nah-executable-path-unavailable".to_owned())?;
            install_extension(&home, &agent_dir, &executable, policy)
        } else {
            uninstall_extension(&home, &agent_dir)
        }
    })?;
    Ok(RuntimeMutation::new(
        install,
        "Prime Agent extension",
        path,
        Some("Run /reload in Prime Agent before use."),
    ))
}

pub(crate) fn prime_agent_hook_status() -> Result<RuntimeHookStatus, String> {
    let platform = live_state::host_platform();
    let home = live_state::home(platform)?;
    let agent_dir = configured_agent_dir(&home, platform)?;
    let paths = PrimeAgentHookPaths::new(&home, &agent_dir);
    reject_symlinks(&paths)?;
    let bytes = match std::fs::read(&paths.extension) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(RuntimeHookStatus::NotConfigured);
        }
        Err(_) => return Err("prime-agent-extension-read-failed".into()),
    };
    if !owned(&bytes) {
        return Err("prime-agent-extension-not-owned".into());
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
                .windows(br#"["hook", "prime-agent", "run", "--fail-closed"]"#.len())
                .any(|part| part == br#"["hook", "prime-agent", "run", "--fail-closed"]"#);
            let delegate = bytes
                .windows(br#"["hook", "prime-agent", "run"]"#.len())
                .any(|part| part == br#"["hook", "prime-agent", "run"]"#);
            RuntimeHookStatus::stale(if strict && !delegate {
                FailurePolicy::Block
            } else {
                FailurePolicy::Delegate
            })
        },
    )
}

pub(crate) fn prime_agent_self_protection_paths() -> Result<Vec<PathBuf>, String> {
    let platform = live_state::host_platform();
    let home = live_state::home(platform)?;
    let agent_dir = configured_agent_dir(&home, platform)?;
    Ok(vec![PrimeAgentHookPaths::new(&home, &agent_dir).extension])
}

fn configured_agent_dir(
    home: &AbsolutePath,
    platform: nah_proto::ctx::Platform,
) -> Result<AbsolutePath, String> {
    let home_path = PathBuf::from(home.as_str());
    let configured = match std::env::var_os("PRIME_AGENT_CODING_AGENT_DIR") {
        Some(value) if !value.is_empty() => {
            let value = value
                .to_str()
                .ok_or_else(|| "prime-agent-dir-not-utf8".to_owned())?;
            if value == "~" {
                home_path
            } else if let Some(relative) = value
                .strip_prefix("~/")
                .or_else(|| value.strip_prefix("~\\"))
            {
                home_path.join(relative)
            } else {
                PathBuf::from(value)
            }
        }
        _ => home_path.join(".prime/agent"),
    };
    let configured = configured
        .to_str()
        .ok_or_else(|| "prime-agent-dir-not-utf8".to_owned())?;
    AbsolutePath::new(platform, configured).map_err(|_| "prime-agent-dir-not-absolute".to_owned())
}

fn install_extension(
    home: &AbsolutePath,
    agent_dir: &AbsolutePath,
    executable: &Path,
    policy: FailurePolicy,
) -> Result<PathBuf, String> {
    let paths = PrimeAgentHookPaths::new(home, agent_dir);
    let lock = lock(&paths)?;
    reject_symlinks(&paths)?;
    let parent = paths
        .extension
        .parent()
        .ok_or_else(|| "invalid-prime-agent-extension-path".to_owned())?;
    std::fs::create_dir_all(parent).map_err(|_| "prime-agent-extension-write-failed".to_owned())?;
    reject_symlinks(&paths)?;
    let desired = extension(executable, policy)?;
    match std::fs::read(&paths.extension) {
        Ok(bytes) if bytes == desired.as_bytes() => {}
        Ok(bytes) if owned(&bytes) => save(&paths.extension, desired.as_bytes())?,
        Ok(_) => return Err("prime-agent-extension-not-owned".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            save(&paths.extension, desired.as_bytes())?;
        }
        Err(_) => return Err("prime-agent-extension-read-failed".into()),
    }
    drop(lock);
    Ok(paths.extension)
}

fn uninstall_extension(home: &AbsolutePath, agent_dir: &AbsolutePath) -> Result<PathBuf, String> {
    let paths = PrimeAgentHookPaths::new(home, agent_dir);
    let lock = lock(&paths)?;
    reject_symlinks(&paths)?;
    match std::fs::read(&paths.extension) {
        Ok(bytes) if owned(&bytes) => {
            std::fs::remove_file(&paths.extension)
                .map_err(|_| "prime-agent-extension-remove-failed".to_owned())?;
            if let Some(parent) = paths.extension.parent() {
                sync_parent(parent)?;
            }
        }
        Ok(_) => return Err("prime-agent-extension-not-owned".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err("prime-agent-extension-read-failed".into()),
    }
    drop(lock);
    Ok(paths.extension)
}

struct PrimeAgentHookPaths {
    extension: PathBuf,
    lock: PathBuf,
}

impl PrimeAgentHookPaths {
    fn new(home: &AbsolutePath, agent_dir: &AbsolutePath) -> Self {
        Self {
            extension: PathBuf::from(agent_dir.as_str()).join("extensions/nah.js"),
            lock: PathBuf::from(home.as_str()).join(".nah/prime-agent-hook.lock"),
        }
    }
}

fn lock(paths: &PrimeAgentHookPaths) -> Result<File, String> {
    let parent = paths
        .lock
        .parent()
        .ok_or_else(|| "invalid-prime-agent-hook-lock-path".to_owned())?;
    std::fs::create_dir_all(parent).map_err(|_| "prime-agent-hook-lock-failed".to_owned())?;
    reject_symlink_ancestors(&paths.lock, "prime-agent-hook-lock-failed")?;
    let mut options = OpenOptions::new();
    options.create(true).truncate(false).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(&paths.lock)
        .map_err(|_| "prime-agent-hook-lock-failed".to_owned())?;
    protect_private(&file, "prime-agent-hook-permissions-failed")?;
    file.lock()
        .map_err(|_| "prime-agent-hook-lock-failed".to_owned())?;
    Ok(file)
}

fn reject_symlinks(paths: &PrimeAgentHookPaths) -> Result<(), String> {
    reject_symlink_ancestors(
        &paths.extension,
        "prime-agent-extension-symlink-unsupported",
    )
}

fn reject_symlink_ancestors(path: &Path, error: &str) -> Result<(), String> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => return Err(error.into()),
            Ok(_) => {}
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(error.into()),
        }
    }
    Ok(())
}

fn save(path: &Path, bytes: &[u8]) -> Result<(), String> {
    reject_symlink_ancestors(path, "prime-agent-extension-symlink-unsupported")?;
    let parent = path
        .parent()
        .ok_or_else(|| "invalid-prime-agent-extension-path".to_owned())?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)
        .map_err(|_| "prime-agent-extension-write-failed".to_owned())?;
    protect_private(
        temporary.as_file(),
        "prime-agent-extension-permissions-failed",
    )?;
    temporary
        .write_all(bytes)
        .map_err(|_| "prime-agent-extension-write-failed".to_owned())?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|_| "prime-agent-extension-write-failed".to_owned())?;
    temporary
        .persist(path)
        .map_err(|_| "prime-agent-extension-write-failed".to_owned())?;
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
    let adapter_failure_message = if policy == FailurePolicy::Block {
        "nah - required safety evaluation was unavailable; ask the operator to inspect the nah integration; do not retry through another tool or change nah state"
    } else {
        "nah - evaluation failed; this call was delegated to the runtime"
    };
    let adapter_failure_message = serde_json::to_string(adapter_failure_message)
        .map_err(|_| "invalid-prime-agent-failure-message".to_owned())?;
    let adapter_failure_return = if policy == FailurePolicy::Block {
        "return { block: true, reason: adapterFailureMessage };"
    } else {
        "return undefined;"
    };
    Ok(format!(
        r#"{MARKER}
const {{ spawn }} = require("node:child_process");
const nahExecutable = {executable};
const maxOutputBytes = 65536;
const adapterFailureMessage = {adapter_failure_message};

function decide(event, context) {{
  return new Promise((resolve, reject) => {{
    const child = spawn(nahExecutable, ["hook", "prime-agent", "run"{failure_arg}], {{
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

module.exports = function nahPrimeAgentExtension(prime) {{
  prime.on("tool_call", async (event, context) => {{
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
          context.ui.notify(adapterFailureMessage, "warning");
        }} catch {{}}
      }}
      {adapter_failure_return}
    }}
  }});
}};
"#
    ))
}

fn owned(bytes: &[u8]) -> bool {
    let text = String::from_utf8_lossy(bytes);
    text.starts_with(MARKER) && text.contains(r#"["hook", "prime-agent", "run""#)
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
        .map_err(|_| "prime-agent-extension-sync-failed".into())
}

#[cfg(not(unix))]
fn sync_parent(_parent: &Path) -> Result<(), String> {
    Ok(())
}
