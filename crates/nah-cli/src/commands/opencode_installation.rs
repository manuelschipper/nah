//! Installs and removes nah's global OpenCode tool hook plugin.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use nah_proto::ctx::AbsolutePath;

use crate::live_state;

use super::{RuntimeHookStatus, RuntimeMutation};

const MARKER: &str = "// Managed by nah.";

pub(crate) fn mutate_opencode_hook(install: bool) -> Result<RuntimeMutation, String> {
    let platform = live_state::host_platform();
    let path = live_state::home(platform).and_then(|home| {
        reject_custom_home(&home)?;
        if install {
            let executable = std::env::current_exe()
                .map_err(|_| "nah-executable-path-unavailable".to_owned())?;
            install_plugin(&home, &executable)
        } else {
            uninstall_plugin(&home)
        }
    })?;
    Ok(RuntimeMutation::new(
        install,
        "OpenCode plugin",
        path,
        Some("Restart OpenCode before use."),
    ))
}

pub(crate) fn opencode_hook_status() -> Result<RuntimeHookStatus, String> {
    let platform = live_state::host_platform();
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
    Ok(if bytes == plugin(&executable)?.as_bytes() {
        RuntimeHookStatus::WiringCurrent
    } else {
        RuntimeHookStatus::NeedsReinstall
    })
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

fn install_plugin(home: &AbsolutePath, executable: &Path) -> Result<PathBuf, String> {
    let paths = OpenCodeHookPaths::new(home);
    let lock = lock(&paths)?;
    reject_symlinks(&paths)?;
    let parent = paths
        .plugin
        .parent()
        .ok_or_else(|| "invalid-opencode-plugin-path".to_owned())?;
    std::fs::create_dir_all(parent).map_err(|_| "opencode-plugin-write-failed")?;
    reject_symlinks(&paths)?;
    let desired = plugin(executable)?;
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
    let lock = lock(&paths)?;
    reject_symlinks(&paths)?;
    match std::fs::read(&paths.plugin) {
        Ok(bytes) if owned(&bytes) => {
            std::fs::remove_file(&paths.plugin).map_err(|_| "opencode-plugin-remove-failed")?;
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

fn lock(paths: &OpenCodeHookPaths) -> Result<File, String> {
    let parent = paths
        .lock
        .parent()
        .ok_or_else(|| "invalid-opencode-hook-lock-path".to_owned())?;
    std::fs::create_dir_all(parent).map_err(|_| "opencode-hook-lock-failed")?;
    reject_symlink(&paths.lock, "opencode-hook-lock-failed")?;
    let mut options = OpenOptions::new();
    options.create(true).truncate(false).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(&paths.lock)
        .map_err(|_| "opencode-hook-lock-failed")?;
    protect_private(&file, "opencode-hook-permissions-failed")?;
    file.lock().map_err(|_| "opencode-hook-lock-failed")?;
    Ok(file)
}

fn reject_symlinks(paths: &OpenCodeHookPaths) -> Result<(), String> {
    for directory in &paths.checked_directories {
        reject_symlink(directory, "opencode-plugin-symlink-unsupported")?;
    }
    reject_symlink(&paths.plugin, "opencode-plugin-symlink-unsupported")
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
    reject_symlink(path, "opencode-plugin-symlink-unsupported")?;
    let parent = path
        .parent()
        .ok_or_else(|| "invalid-opencode-plugin-path".to_owned())?;
    let mut temporary =
        tempfile::NamedTempFile::new_in(parent).map_err(|_| "opencode-plugin-write-failed")?;
    protect_private(temporary.as_file(), "opencode-plugin-permissions-failed")?;
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
    sync_parent(parent)
}

fn plugin(executable: &Path) -> Result<String, String> {
    let executable = executable
        .to_str()
        .ok_or_else(|| "invalid-nah-executable-path".to_owned())?;
    let executable =
        serde_json::to_string(executable).map_err(|_| "invalid-nah-executable-path".to_owned())?;
    Ok(format!(
        r#"{MARKER}
import {{ spawn }} from "node:child_process";
import {{ resolve as resolvePath }} from "node:path";

const nahExecutable = {executable};
const maxOutputBytes = 65536;

function decide(input) {{
  return new Promise((resolve, reject) => {{
    const child = spawn(nahExecutable, ["hook", "opencode", "run"], {{
      stdio: ["pipe", "pipe", "pipe"],
    }});
    let stdout = "";
    let stderr = "";
    let settled = false;
    let timer;
    const cleanup = () => clearTimeout(timer);
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

export const NahPlugin = async ({{ directory, client }}) => ({{
  "tool.execute.before": async (input, output) => {{
    const args = output.args;
    const workdir =
      input.tool === "bash" && typeof args?.workdir === "string" && args.workdir.length
        ? resolvePath(directory, args.workdir)
        : directory;
    let result;
    try {{
      result = await decide({{
        tool_name: input.tool,
        tool_input: args,
        cwd: workdir,
        session_id: input.sessionID,
      }});
    }} catch {{
      try {{
        await client.tui.showToast({{
          body: {{
            message: "nah - evaluation failed; this call was delegated to the runtime",
            variant: "warning",
          }},
        }});
      }} catch {{}}
      return;
    }}
    if (result.evaluation_failed) {{
      try {{
        await client.tui.showToast({{
          body: {{
            message: result.block
              ? "nah - evaluation was incomplete; another guard blocked this call"
              : "nah - evaluation failed; this call was delegated to the runtime",
            variant: "warning",
          }},
        }});
      }} catch {{}}
    }}
    if (result.block) throw new Error(result.reason);
  }},
}});
"#
    ))
}

fn owned(bytes: &[u8]) -> bool {
    let text = String::from_utf8_lossy(bytes);
    text.starts_with(MARKER) && text.contains(r#"["hook", "opencode", "run"]"#)
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
        .map_err(|_| "opencode-plugin-sync-failed".into())
}

#[cfg(not(unix))]
fn sync_parent(_parent: &Path) -> Result<(), String> {
    Ok(())
}
