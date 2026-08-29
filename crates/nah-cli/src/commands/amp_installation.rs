//! Installs and removes nah's Amp system plugin.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use nah_proto::ctx::AbsolutePath;

use crate::{live_state, runtime::FailurePolicy};

use super::runtime::reject_unsupported_windows_runtime;
use super::{RuntimeHookStatus, RuntimeMutation};

const MARKER: &str = "// Managed by nah.";

pub(crate) fn mutate_amp_hook(
    install: bool,
    policy: FailurePolicy,
) -> Result<RuntimeMutation, String> {
    let platform = live_state::host_platform();
    reject_unsupported_windows_runtime(platform)?;
    let path = live_state::home(platform).and_then(|home| {
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
        "Amp plugin",
        path,
        Some("Restart Amp or run `plugins: reload` before use."),
    ))
}

pub(crate) fn amp_hook_status() -> Result<RuntimeHookStatus, String> {
    let platform = live_state::host_platform();
    if reject_unsupported_windows_runtime(platform).is_err() {
        return Ok(RuntimeHookStatus::NotConfigured);
    }
    let home = live_state::home(platform)?;
    let paths = AmpHookPaths::new(&home);
    reject_symlinks(&paths)?;
    let bytes = match std::fs::read(&paths.plugin) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(RuntimeHookStatus::NotConfigured);
        }
        Err(_) => return Err("amp-plugin-read-failed".into()),
    };
    if !owned(&bytes) {
        return Err("amp-plugin-not-owned".into());
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
                .windows(br#"["hook", "amp", "run", "--fail-closed"]"#.len())
                .any(|part| part == br#"["hook", "amp", "run", "--fail-closed"]"#);
            let delegate = bytes
                .windows(br#"["hook", "amp", "run"]"#.len())
                .any(|part| part == br#"["hook", "amp", "run"]"#);
            RuntimeHookStatus::stale(if strict && !delegate {
                FailurePolicy::Block
            } else {
                FailurePolicy::Delegate
            })
        },
    )
}

pub(crate) fn amp_self_protection_paths() -> Result<Vec<PathBuf>, String> {
    let platform = live_state::host_platform();
    let home = live_state::home(platform)?;
    Ok(vec![AmpHookPaths::new(&home).plugin])
}

fn install_plugin(
    home: &AbsolutePath,
    executable: &Path,
    policy: FailurePolicy,
) -> Result<PathBuf, String> {
    let paths = AmpHookPaths::new(home);
    let lock = lock(&paths)?;
    reject_symlinks(&paths)?;
    let parent = paths
        .plugin
        .parent()
        .ok_or_else(|| "invalid-amp-plugin-path".to_owned())?;
    std::fs::create_dir_all(parent).map_err(|_| "amp-plugin-write-failed")?;
    reject_symlinks(&paths)?;
    let desired = plugin(executable, policy)?;
    match std::fs::read(&paths.plugin) {
        Ok(bytes) if bytes == desired.as_bytes() => {}
        Ok(bytes) if owned(&bytes) => save(&paths.plugin, desired.as_bytes())?,
        Ok(_) => return Err("amp-plugin-not-owned".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            save(&paths.plugin, desired.as_bytes())?;
        }
        Err(_) => return Err("amp-plugin-read-failed".into()),
    }
    drop(lock);
    Ok(paths.plugin)
}

fn uninstall_plugin(home: &AbsolutePath) -> Result<PathBuf, String> {
    let paths = AmpHookPaths::new(home);
    let lock = lock(&paths)?;
    reject_symlinks(&paths)?;
    match std::fs::read(&paths.plugin) {
        Ok(bytes) if owned(&bytes) => {
            std::fs::remove_file(&paths.plugin).map_err(|_| "amp-plugin-remove-failed")?;
            if let Some(parent) = paths.plugin.parent() {
                sync_parent(parent)?;
                match std::fs::remove_dir(parent) {
                    Ok(()) => {
                        if let Some(config) = parent.parent() {
                            sync_parent(config)?;
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

fn lock(paths: &AmpHookPaths) -> Result<File, String> {
    let parent = paths
        .lock
        .parent()
        .ok_or_else(|| "invalid-amp-hook-lock-path".to_owned())?;
    std::fs::create_dir_all(parent).map_err(|_| "amp-hook-lock-failed")?;
    reject_symlink(&paths.lock, "amp-hook-lock-failed")?;
    let mut options = OpenOptions::new();
    options.create(true).truncate(false).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(&paths.lock)
        .map_err(|_| "amp-hook-lock-failed")?;
    protect_private(&file, "amp-hook-permissions-failed")?;
    file.lock().map_err(|_| "amp-hook-lock-failed")?;
    Ok(file)
}

fn reject_symlinks(paths: &AmpHookPaths) -> Result<(), String> {
    for directory in &paths.checked_directories {
        reject_symlink(directory, "amp-plugin-symlink-unsupported")?;
    }
    reject_symlink(&paths.plugin, "amp-plugin-symlink-unsupported")
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
    reject_symlink(path, "amp-plugin-symlink-unsupported")?;
    let parent = path
        .parent()
        .ok_or_else(|| "invalid-amp-plugin-path".to_owned())?;
    let mut temporary =
        tempfile::NamedTempFile::new_in(parent).map_err(|_| "amp-plugin-write-failed")?;
    protect_private(temporary.as_file(), "amp-plugin-permissions-failed")?;
    temporary
        .write_all(bytes)
        .map_err(|_| "amp-plugin-write-failed")?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|_| "amp-plugin-write-failed")?;
    temporary
        .persist(path)
        .map_err(|_| "amp-plugin-write-failed")?;
    sync_parent(parent)
}

fn plugin(executable: &Path, policy: FailurePolicy) -> Result<String, String> {
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
import type {{ PluginAPI }} from "@ampcode/plugin";
import {{ spawn }} from "node:child_process";
import {{ resolve }} from "node:path";

const nahExecutable = {executable};
const maxOutputBytes = 65536;

function decide(input: unknown): Promise<{{ block: boolean; reason?: string; evaluation_failed: boolean }}> {{
  return new Promise((resolve, reject) => {{
    const child = spawn(nahExecutable, ["hook", "amp", "run"{failure_arg}], {{
      stdio: ["pipe", "pipe", "pipe"],
    }});
    let stdout = "";
    let stderr = "";
    let settled = false;
    let timer: ReturnType<typeof setTimeout>;
    const cleanup = () => clearTimeout(timer);
    const fail = (error: Error) => {{
      if (settled) return;
      settled = true;
      cleanup();
      child.kill();
      reject(error);
    }};
    const append = (current: string, chunk: Buffer) => {{
      const next = current + chunk.toString();
      if (Buffer.byteLength(next) > maxOutputBytes) {{
        fail(new Error("nah output limit exceeded"));
      }}
      return next;
    }};
    timer = setTimeout(() => fail(new Error("nah decision timed out")), 5000);
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
    child.stdin.end(JSON.stringify(input));
  }});
}}

export default function nahAmpPlugin(amp: PluginAPI) {{
  amp.on("tool.call", async (event, ctx) => {{
    const notify = (message: string) => {{
      try {{ ctx.ui.notify(message, "warning"); }} catch {{}}
    }};
    try {{
      const shell = amp.helpers.shellCommandFromToolCall(event);
      const root = amp.system.workspaceRoot;
      const cwd =
        typeof shell?.dir === "string" && shell.dir.length
          ? shell.dir
          : root
            ? amp.helpers.filePathFromURI(root)
            : null;
      if (!cwd) {{
        notify("nah - evaluation failed; this call was delegated to the runtime");
        return {{ action: "allow" }};
      }}
      let toolInput = event.input;
      if (event.tool === "download_thread_file" && !("destination" in event.input)) {{
        const remotePath = event.input.path;
        const fileName =
          typeof remotePath === "string"
            ? remotePath.replaceAll("\\", "/").split("/").pop()
            : null;
        const workingDirectory = await ctx.$`pwd`;
        if (!fileName || workingDirectory.exitCode !== 0 || !workingDirectory.stdout.trim()) {{
          notify("nah - evaluation failed; this call was delegated to the runtime");
          return {{ action: "allow" }};
        }}
        toolInput = {{
          ...event.input,
          destination: resolve(workingDirectory.stdout.trim(), fileName),
        }};
      }}
      const result = await decide({{
        tool_name: event.tool,
        tool_input: toolInput,
        cwd,
        session_id: event.thread.id,
      }});
      if (result.evaluation_failed) {{
        notify(result.block
          ? "nah - evaluation was incomplete; another guard blocked this call"
          : "nah - evaluation failed; this call was delegated to the runtime");
      }}
      return result.block
        ? {{ action: "reject-and-continue", message: result.reason! }}
        : {{ action: "allow" }};
    }} catch {{
      notify("nah - evaluation failed; this call was delegated to the runtime");
      return {{ action: "allow" }};
    }}
  }});
}}
"#
    ))
}

fn owned(bytes: &[u8]) -> bool {
    let text = String::from_utf8_lossy(bytes);
    text.starts_with(MARKER) && text.contains(r#"["hook", "amp", "run""#)
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
        .map_err(|_| "amp-plugin-sync-failed".into())
}

#[cfg(not(unix))]
fn sync_parent(_parent: &Path) -> Result<(), String> {
    Ok(())
}
