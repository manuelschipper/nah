//! Installs and removes nah's managed OpenClaw plugin.

use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

use nah_proto::ctx::AbsolutePath;
use serde_json::{Value, json};

use crate::{live_state, runtime::FailurePolicy};

use super::{RuntimeHookStatus, RuntimeMutation};

const MARKER: &str = "// Managed by nah.";

pub(crate) fn mutate_openclaw_hook(
    install: bool,
    policy: FailurePolicy,
) -> Result<RuntimeMutation, String> {
    let platform = live_state::host_platform();
    let path = if unsupported_environment() {
        Err("custom-openclaw-home-unsupported".to_owned())
    } else {
        live_state::home(platform).and_then(|home| {
            if install {
                let executable = std::env::current_exe()
                    .map_err(|_| "nah-executable-path-unavailable".to_owned())?;
                install_plugin(&home, &executable, policy)
            } else {
                uninstall_plugin(&home)
            }
        })
    }?;
    Ok(RuntimeMutation::new(
        install,
        "OpenClaw plugin",
        path,
        Some("Restart the OpenClaw Gateway before use."),
    ))
}

pub(crate) fn openclaw_hook_status() -> Result<RuntimeHookStatus, String> {
    if unsupported_environment() {
        return Err("custom-openclaw-home-unsupported".into());
    }
    let platform = live_state::host_platform();
    let home = live_state::home(platform)?;
    let paths = OpenClawHookPaths::new(&home);
    reject_symlinks(&paths)?;
    if !paths.plugin.exists() {
        return Ok(RuntimeHookStatus::NotConfigured);
    }
    validate_owned_target(&paths)?;
    let executable =
        std::env::current_exe().map_err(|_| "nah-executable-path-unavailable".to_owned())?;
    let executable = executable
        .to_str()
        .ok_or_else(|| "invalid-nah-executable-path".to_owned())?;
    let executable =
        serde_json::to_string(executable).map_err(|_| "invalid-nah-executable-path".to_owned())?;
    let current_module =
        std::fs::read_to_string(&paths.module).map_err(|_| "openclaw-plugin-read-failed")?;
    Ok(
        if read_json(&paths.package)? == package()
            && read_json(&paths.manifest)? == manifest()
            && current_module == plugin(&executable, FailurePolicy::Delegate)
        {
            RuntimeHookStatus::WiringCurrent
        } else if read_json(&paths.package)? == package()
            && read_json(&paths.manifest)? == manifest()
            && current_module == plugin(&executable, FailurePolicy::Block)
        {
            RuntimeHookStatus::WiringCurrentFailClosed
        } else {
            let strict = current_module.contains(r#"["hook", "openclaw", "run", "--fail-closed"]"#);
            let delegate = current_module.contains(r#"["hook", "openclaw", "run"]"#);
            RuntimeHookStatus::stale(if strict && !delegate {
                FailurePolicy::Block
            } else {
                FailurePolicy::Delegate
            })
        },
    )
}

pub(crate) fn openclaw_self_protection_paths() -> Result<Vec<PathBuf>, String> {
    if unsupported_environment() {
        return Err("custom-openclaw-home-unsupported".into());
    }
    let platform = live_state::host_platform();
    let home = live_state::home(platform)?;
    let paths = OpenClawHookPaths::new(&home);
    Ok(vec![paths.plugin, paths.state.join("openclaw.json")])
}

fn unsupported_environment() -> bool {
    let custom_profile = std::env::var("OPENCLAW_PROFILE")
        .ok()
        .is_some_and(|profile| {
            !profile.trim().is_empty() && !profile.trim().eq_ignore_ascii_case("default")
        });
    [
        "OPENCLAW_HOME",
        "OPENCLAW_STATE_DIR",
        "OPENCLAW_CONFIG_PATH",
    ]
    .iter()
    .any(|name| std::env::var_os(name).is_some())
        || custom_profile
}

fn install_plugin(
    home: &AbsolutePath,
    executable: &Path,
    policy: FailurePolicy,
) -> Result<PathBuf, String> {
    let paths = OpenClawHookPaths::new(home);
    let lock = lock(&paths)?;
    reject_symlinks(&paths)?;
    validate_target(&paths)?;
    if !paths.state.exists() && paths.legacy_state.exists() {
        return Err("legacy-openclaw-state-unsupported".into());
    }
    std::fs::create_dir_all(&paths.state).map_err(|_| "openclaw-plugin-write-failed")?;
    reject_symlinks(&paths)?;

    std::fs::create_dir_all(&paths.plugin).map_err(|_| "openclaw-plugin-write-failed")?;
    reject_symlinks(&paths)?;
    save_source(&paths.plugin, executable, policy)?;
    validate_owned_target(&paths)?;
    drop(lock);
    Ok(paths.plugin)
}

fn uninstall_plugin(home: &AbsolutePath) -> Result<PathBuf, String> {
    let paths = OpenClawHookPaths::new(home);
    let lock = lock(&paths)?;
    reject_symlinks(&paths)?;
    if !paths.plugin.exists() {
        return Ok(paths.plugin);
    }
    validate_owned_target(&paths)?;
    for path in [&paths.package, &paths.manifest, &paths.module] {
        std::fs::remove_file(path).map_err(|_| "openclaw-plugin-remove-failed")?;
    }
    std::fs::remove_dir(&paths.plugin).map_err(|_| "openclaw-plugin-remove-failed")?;
    drop(lock);
    Ok(paths.plugin)
}

struct OpenClawHookPaths {
    state: PathBuf,
    legacy_state: PathBuf,
    extensions: PathBuf,
    plugin: PathBuf,
    package: PathBuf,
    manifest: PathBuf,
    module: PathBuf,
    lock: PathBuf,
}

impl OpenClawHookPaths {
    fn new(home: &AbsolutePath) -> Self {
        let home = PathBuf::from(home.as_str());
        let state = home.join(".openclaw");
        let extensions = state.join("extensions");
        let plugin = extensions.join("nah");
        Self {
            package: plugin.join("package.json"),
            manifest: plugin.join("openclaw.plugin.json"),
            module: plugin.join("index.js"),
            lock: home.join(".nah/openclaw-hook.lock"),
            legacy_state: home.join(".clawdbot"),
            state,
            extensions,
            plugin,
        }
    }
}

fn lock(paths: &OpenClawHookPaths) -> Result<File, String> {
    let parent = paths
        .lock
        .parent()
        .ok_or_else(|| "invalid-openclaw-hook-lock-path".to_owned())?;
    std::fs::create_dir_all(parent).map_err(|_| "openclaw-hook-lock-failed")?;
    reject_symlink(&paths.lock, "openclaw-hook-lock-failed")?;
    let mut options = OpenOptions::new();
    options.create(true).truncate(false).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(&paths.lock)
        .map_err(|_| "openclaw-hook-lock-failed")?;
    file.lock().map_err(|_| "openclaw-hook-lock-failed")?;
    Ok(file)
}

fn reject_symlinks(paths: &OpenClawHookPaths) -> Result<(), String> {
    for path in [
        &paths.state,
        &paths.extensions,
        &paths.plugin,
        &paths.package,
        &paths.manifest,
        &paths.module,
    ] {
        reject_symlink(path, "openclaw-plugin-symlink-unsupported")?;
    }
    Ok(())
}

fn reject_symlink(path: &Path, error: &str) -> Result<(), String> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(error.into()),
        Ok(_) => Ok(()),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(error.into()),
    }
}

fn validate_target(paths: &OpenClawHookPaths) -> Result<(), String> {
    match std::fs::read_dir(&paths.plugin) {
        Ok(_) => validate_owned_target(paths),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err("openclaw-plugin-read-failed".into()),
    }
}

fn validate_owned_target(paths: &OpenClawHookPaths) -> Result<(), String> {
    let entries = std::fs::read_dir(&paths.plugin)
        .map_err(|_| "openclaw-plugin-read-failed")?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "openclaw-plugin-read-failed")?;
    if entries.iter().any(|entry| {
        !matches!(
            entry.file_name().to_str(),
            Some("package.json" | "openclaw.plugin.json" | "index.js")
        )
    }) {
        return Err("openclaw-plugin-not-owned".into());
    }
    let package = read_json(&paths.package)?;
    let manifest = read_json(&paths.manifest)?;
    let module =
        std::fs::read_to_string(&paths.module).map_err(|_| "openclaw-plugin-read-failed")?;
    if package.pointer("/nah/managed") != Some(&Value::Bool(true))
        || manifest.get("id").and_then(Value::as_str) != Some("nah")
        || !module.starts_with(MARKER)
        || !module.contains(r#"["hook", "openclaw", "run""#)
    {
        return Err("openclaw-plugin-not-owned".into());
    }
    Ok(())
}

fn read_json(path: &Path) -> Result<Value, String> {
    let bytes = std::fs::read(path).map_err(|_| "openclaw-plugin-read-failed")?;
    serde_json::from_slice(&bytes).map_err(|_| "openclaw-plugin-not-owned".into())
}

fn save_source(directory: &Path, executable: &Path, policy: FailurePolicy) -> Result<(), String> {
    let executable = executable
        .to_str()
        .ok_or_else(|| "invalid-nah-executable-path".to_owned())?;
    let executable =
        serde_json::to_string(executable).map_err(|_| "invalid-nah-executable-path".to_owned())?;
    std::fs::write(
        directory.join("package.json"),
        serde_json::to_vec_pretty(&package()).map_err(|_| "openclaw-plugin-write-failed")?,
    )
    .map_err(|_| "openclaw-plugin-write-failed")?;
    std::fs::write(
        directory.join("openclaw.plugin.json"),
        serde_json::to_vec_pretty(&manifest()).map_err(|_| "openclaw-plugin-write-failed")?,
    )
    .map_err(|_| "openclaw-plugin-write-failed")?;
    std::fs::write(directory.join("index.js"), plugin(&executable, policy))
        .map_err(|_| "openclaw-plugin-write-failed".to_owned())
}

fn package() -> Value {
    json!({
        "name":"nah",
        "version":"1.0.0",
        "type":"module",
        "openclaw":{"extensions":["./index.js"]},
        "nah":{"managed":true}
    })
}

fn manifest() -> Value {
    json!({
        "id":"nah",
        "name":"nah",
        "description":"Guards OpenClaw tool calls with nah policy.",
        "activation":{"onStartup":true},
        "configSchema":{"type":"object","additionalProperties":false,"properties":{}}
    })
}

fn plugin(executable: &str, policy: FailurePolicy) -> String {
    let failure_arg = if policy == FailurePolicy::Block {
        r#", "--fail-closed""#
    } else {
        ""
    };
    format!(
        r#"{MARKER}
import {{ spawn }} from "node:child_process";
import {{ resolve as resolvePath }} from "node:path";
import {{ definePluginEntry }} from "openclaw/plugin-sdk/plugin-entry";

const nahExecutable = {executable};
const maxOutputBytes = 65536;

function decide(input) {{
  return new Promise((resolve, reject) => {{
    const child = spawn(nahExecutable, ["hook", "openclaw", "run"{failure_arg}], {{
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
      if (Buffer.byteLength(next) > maxOutputBytes) fail(new Error("nah output limit exceeded"));
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

export default definePluginEntry({{
  id: "nah",
  name: "nah",
  description: "Guards OpenClaw tool calls with nah policy.",
  register(api) {{
    api.on("before_tool_call", async (event, context) => {{
      try {{
        if (typeof context.agentId !== "string" || !context.agentId) {{
          throw new Error("OpenClaw agent workspace unavailable");
        }}
        const workspace = api.runtime.agent.resolveAgentWorkspaceDir(
          api.runtime.config.current(),
          context.agentId,
        );
        const workdir = event.toolName === "exec" ? event.params.workdir : undefined;
        const cwd =
          typeof workdir === "string" && workdir.length
            ? resolvePath(workspace, workdir)
            : workspace;
        const result = await decide({{
          tool_name: event.toolName,
          tool_input: event.params,
          tool_kind: event.toolKind,
          tool_input_kind: event.toolInputKind,
          derived_paths: event.derivedPaths,
          cwd,
          session_id: context.sessionId,
        }});
        if (result.evaluation_failed) {{
          api.logger?.warn?.(result.block
            ? "nah - evaluation was incomplete; another guard blocked this call"
            : "nah - evaluation failed; this call was delegated to the runtime");
        }}
        if (result.block) return {{ block: true, blockReason: result.reason }};
      }} catch {{
        api.logger?.warn?.("nah - evaluation failed; this call was delegated to the runtime");
        return undefined;
      }}
    }}, {{ priority: -1000, timeoutMs: 6000 }});
  }},
}});
"#
    )
}
