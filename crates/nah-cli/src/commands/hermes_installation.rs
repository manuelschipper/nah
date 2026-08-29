//! Installs and removes nah's native Hermes shell hook.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use nah_proto::ctx::AbsolutePath;
use serde_yaml_ng::{Mapping, Value};

use crate::{live_state, runtime::FailurePolicy};

use super::{RuntimeHookStatus, RuntimeMutation};

const COMMAND: &str = "nah hook hermes run";
const FAIL_CLOSED_COMMAND: &str = "nah hook hermes run --fail-closed";
const EVENT: &str = "pre_tool_call";

pub(crate) fn mutate_hermes_hook(
    install: bool,
    policy: FailurePolicy,
) -> Result<RuntimeMutation, String> {
    let platform = live_state::host_platform();
    let path = live_state::home(platform).and_then(|home| {
        let configured = configured_hermes_home(&home);
        let home = resolve_hermes_home(&configured, platform)?;
        if install {
            install_hook(&home, policy)
        } else {
            uninstall_hook(&home)
        }
    })?;
    Ok(RuntimeMutation::new(
        install,
        "Hermes shell hook",
        path,
        Some("Restart Hermes before use."),
    ))
}

pub(crate) fn hermes_hook_status() -> Result<RuntimeHookStatus, String> {
    let platform = live_state::host_platform();
    let home = live_state::home(platform)?;
    let configured = configured_hermes_home(&home);
    if !configured.exists() {
        return Ok(RuntimeHookStatus::NotConfigured);
    }
    let home = resolve_hermes_home(&configured, platform)?;
    let paths = HermesHookPaths::new(&home);
    reject_symlinks(&paths)?;
    if !paths.config.exists() {
        return Ok(RuntimeHookStatus::NotConfigured);
    }
    let config = load_config(&paths.config)?;
    let Some(entries) = hook_entries(&config)? else {
        return Ok(RuntimeHookStatus::NotConfigured);
    };
    let owned = entries.iter().filter(|entry| owned_hook(entry)).count();
    if owned == 0 {
        return Ok(RuntimeHookStatus::NotConfigured);
    }
    if owned != 1 {
        return Err("hermes-hook-ownership-ambiguous".into());
    }
    Ok(
        if entries
            .iter()
            .any(|entry| entry == &desired_hook(FailurePolicy::Delegate))
            && allowlisted(&paths.allowlist, FailurePolicy::Delegate)?
        {
            RuntimeHookStatus::WiringCurrent
        } else if entries
            .iter()
            .any(|entry| entry == &desired_hook(FailurePolicy::Block))
            && allowlisted(&paths.allowlist, FailurePolicy::Block)?
        {
            RuntimeHookStatus::WiringCurrentFailClosed
        } else {
            RuntimeHookStatus::stale(
                if entries
                    .iter()
                    .any(|entry| command(entry) == Some(FAIL_CLOSED_COMMAND))
                {
                    FailurePolicy::Block
                } else {
                    FailurePolicy::Delegate
                },
            )
        },
    )
}

pub(crate) fn hermes_self_protection_paths() -> Result<Vec<PathBuf>, String> {
    let platform = live_state::host_platform();
    let home = live_state::home(platform)?;
    let configured = configured_hermes_home(&home);
    let home = resolve_hermes_home(&configured, platform)?;
    let paths = HermesHookPaths::new(&home);
    Ok(vec![paths.config, paths.allowlist])
}

fn configured_hermes_home(home: &AbsolutePath) -> PathBuf {
    std::env::var_os("HERMES_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(home.as_str()).join(".hermes"))
}

fn resolve_hermes_home(
    configured: &Path,
    platform: nah_proto::ctx::Platform,
) -> Result<AbsolutePath, String> {
    let configured =
        std::fs::canonicalize(configured).map_err(|_| "hermes-home-unavailable".to_owned())?;
    let configured = configured
        .to_str()
        .ok_or_else(|| "hermes-home-not-utf8".to_owned())?;
    let configured = if platform == nah_proto::ctx::Platform::Windows {
        nah_observe::normalize_windows_observed_path(configured)
    } else {
        configured.to_owned()
    };
    AbsolutePath::new(platform, configured).map_err(|error| error.to_string())
}

fn install_hook(home: &AbsolutePath, policy: FailurePolicy) -> Result<PathBuf, String> {
    let paths = HermesHookPaths::new(home);
    let lock = lock(&paths)?;
    reject_symlinks(&paths)?;
    let mut config = load_config(&paths.config)?;
    let entries = hook_entries_mut(&mut config)?;
    if entries
        .iter()
        .any(|entry| is_nah_command(command(entry)) && !owned_hook(entry))
    {
        return Err("hermes-hook-not-owned".into());
    }
    let owned = entries
        .iter()
        .enumerate()
        .filter(|(_, entry)| owned_hook(entry))
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    match owned.as_slice() {
        [] => entries.push(desired_hook(policy)),
        [index] => entries[*index] = desired_hook(policy),
        _ => return Err("hermes-hook-ownership-ambiguous".into()),
    }
    save_config(&paths.config, &config)?;
    approve_hook(&paths, policy)?;
    drop(lock);
    Ok(paths.config)
}

fn uninstall_hook(home: &AbsolutePath) -> Result<PathBuf, String> {
    let paths = HermesHookPaths::new(home);
    let lock = lock(&paths)?;
    reject_symlinks(&paths)?;
    if paths.config.exists() {
        let mut config = load_config(&paths.config)?;
        let owned = hook_entries(&config)?
            .map(|entries| {
                entries
                    .iter()
                    .enumerate()
                    .filter(|(_, entry)| owned_hook(entry))
                    .map(|(index, _)| index)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        match owned.as_slice() {
            [] => {}
            [index] => {
                revoke_hook(&paths)?;
                remove_hook(&mut config, *index)?;
                save_config(&paths.config, &config)?;
            }
            _ => return Err("hermes-hook-ownership-ambiguous".into()),
        }
    }
    drop(lock);
    Ok(paths.config)
}

struct HermesHookPaths {
    config: PathBuf,
    allowlist: PathBuf,
    allowlist_lock: PathBuf,
    lock: PathBuf,
}

impl HermesHookPaths {
    fn new(home: &AbsolutePath) -> Self {
        let home = PathBuf::from(home.as_str());
        Self {
            config: home.join("config.yaml"),
            allowlist: home.join("shell-hooks-allowlist.json"),
            allowlist_lock: home.join("shell-hooks-allowlist.json.lock"),
            lock: home.join(".nah-hook.lock"),
        }
    }
}

fn lock(paths: &HermesHookPaths) -> Result<File, String> {
    open_lock(&paths.lock, "hermes-hook-lock-failed")
}

fn open_lock(path: &Path, error: &str) -> Result<File, String> {
    reject_symlink(path, error)?;
    let mut options = OpenOptions::new();
    options.create(true).truncate(false).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path).map_err(|_| error.to_owned())?;
    file.lock().map_err(|_| error.to_owned())?;
    Ok(file)
}

fn reject_symlinks(paths: &HermesHookPaths) -> Result<(), String> {
    for path in [&paths.config, &paths.allowlist, &paths.allowlist_lock] {
        reject_symlink(path, "hermes-hook-symlink-unsupported")?;
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

fn load_config(path: &Path) -> Result<Mapping, String> {
    match std::fs::read_to_string(path) {
        Ok(text) => match serde_yaml_ng::from_str::<Value>(&text)
            .map_err(|_| "hermes-config-invalid".to_owned())?
        {
            Value::Mapping(mapping) => Ok(mapping),
            Value::Null => Ok(Mapping::new()),
            _ => Err("hermes-config-invalid".into()),
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Mapping::new()),
        Err(_) => Err("hermes-config-read-failed".into()),
    }
}

fn save_config(path: &Path, config: &Mapping) -> Result<(), String> {
    let bytes = serde_yaml_ng::to_string(&Value::Mapping(config.clone()))
        .map_err(|_| "hermes-config-write-failed")?;
    if std::fs::read(path).is_ok_and(|current| current == bytes.as_bytes()) {
        return Ok(());
    }
    let parent = path
        .parent()
        .ok_or_else(|| "invalid-hermes-config-path".to_owned())?;
    let mut temporary =
        tempfile::NamedTempFile::new_in(parent).map_err(|_| "hermes-config-write-failed")?;
    temporary
        .write_all(bytes.as_bytes())
        .map_err(|_| "hermes-config-write-failed")?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|_| "hermes-config-write-failed")?;
    temporary
        .persist(path)
        .map_err(|_| "hermes-config-write-failed")?;
    Ok(())
}

fn hook_entries(config: &Mapping) -> Result<Option<&Vec<Value>>, String> {
    let Some(hooks) = config.get("hooks") else {
        return Ok(None);
    };
    let hooks = hooks
        .as_mapping()
        .ok_or_else(|| "hermes-config-invalid".to_owned())?;
    let Some(entries) = hooks.get(EVENT) else {
        return Ok(None);
    };
    entries
        .as_sequence()
        .map(Some)
        .ok_or_else(|| "hermes-config-invalid".to_owned())
}

fn hook_entries_mut(config: &mut Mapping) -> Result<&mut Vec<Value>, String> {
    let hooks = config
        .entry(yaml_key("hooks"))
        .or_insert_with(|| Value::Mapping(Mapping::new()))
        .as_mapping_mut()
        .ok_or_else(|| "hermes-config-invalid".to_owned())?;
    hooks
        .entry(yaml_key(EVENT))
        .or_insert_with(|| Value::Sequence(Vec::new()))
        .as_sequence_mut()
        .ok_or_else(|| "hermes-config-invalid".to_owned())
}

fn remove_hook(config: &mut Mapping, index: usize) -> Result<(), String> {
    let hooks = config
        .get_mut("hooks")
        .and_then(Value::as_mapping_mut)
        .ok_or_else(|| "hermes-config-invalid".to_owned())?;
    let entries = hooks
        .get_mut(EVENT)
        .and_then(Value::as_sequence_mut)
        .ok_or_else(|| "hermes-config-invalid".to_owned())?;
    entries.remove(index);
    if entries.is_empty() {
        hooks.remove(EVENT);
    }
    if hooks.is_empty() {
        config.remove("hooks");
    }
    Ok(())
}

fn desired_hook(policy: FailurePolicy) -> Value {
    let mut hook = Mapping::new();
    hook.insert(
        yaml_key("command"),
        Value::String(command_for(policy).into()),
    );
    hook.insert(yaml_key("timeout"), Value::Number(5.into()));
    hook.insert(yaml_key("managed_by"), Value::String("nah".into()));
    Value::Mapping(hook)
}

fn command_for(policy: FailurePolicy) -> &'static str {
    match policy {
        FailurePolicy::Delegate => COMMAND,
        FailurePolicy::Block => FAIL_CLOSED_COMMAND,
    }
}

fn is_nah_command(command: Option<&str>) -> bool {
    matches!(command, Some(COMMAND | FAIL_CLOSED_COMMAND))
}

fn owned_hook(value: &Value) -> bool {
    value
        .as_mapping()
        .and_then(|hook| hook.get("managed_by"))
        .and_then(Value::as_str)
        == Some("nah")
}

fn command(value: &Value) -> Option<&str> {
    value
        .as_mapping()
        .and_then(|hook| hook.get("command"))
        .and_then(Value::as_str)
}

fn yaml_key(value: &str) -> Value {
    Value::String(value.into())
}

fn allowlisted(path: &Path, policy: FailurePolicy) -> Result<bool, String> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(_) => return Err("hermes-hook-allowlist-read-failed".into()),
    };
    let value: serde_json::Value =
        serde_json::from_str(&text).map_err(|_| "hermes-hook-allowlist-invalid")?;
    Ok(value
        .get("approvals")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|approvals| {
            approvals.iter().any(|entry| {
                entry.get("event").and_then(serde_json::Value::as_str) == Some(EVENT)
                    && entry.get("command").and_then(serde_json::Value::as_str)
                        == Some(command_for(policy))
            })
        }))
}

fn approve_hook(paths: &HermesHookPaths, policy: FailurePolicy) -> Result<(), String> {
    update_allowlist(paths, Some(policy))
}

fn revoke_hook(paths: &HermesHookPaths) -> Result<(), String> {
    update_allowlist(paths, None)
}

fn update_allowlist(paths: &HermesHookPaths, approve: Option<FailurePolicy>) -> Result<(), String> {
    let lock = open_lock(&paths.allowlist_lock, "hermes-hook-allowlist-lock-failed")?;
    let mut value = match std::fs::read_to_string(&paths.allowlist) {
        Ok(text) => serde_json::from_str::<serde_json::Value>(&text)
            .map_err(|_| "hermes-hook-allowlist-invalid")?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            serde_json::json!({"approvals":[]})
        }
        Err(_) => return Err("hermes-hook-allowlist-read-failed".into()),
    };
    let approvals = value
        .as_object_mut()
        .and_then(|object| object.get_mut("approvals"))
        .and_then(serde_json::Value::as_array_mut)
        .ok_or_else(|| "hermes-hook-allowlist-invalid".to_owned())?;
    approvals.retain(|entry| {
        entry.get("event").and_then(serde_json::Value::as_str) != Some(EVENT)
            || !is_nah_command(entry.get("command").and_then(serde_json::Value::as_str))
    });
    if let Some(policy) = approve {
        approvals.push(serde_json::json!({
            "event": EVENT,
            "command": command_for(policy),
            "approved_at": crate::dispatch::timestamp_rfc3339(),
            "script_mtime_at_approval": null
        }));
    }
    save_allowlist(&paths.allowlist, &value)?;
    drop(lock);
    Ok(())
}

fn save_allowlist(path: &Path, value: &serde_json::Value) -> Result<(), String> {
    let mut bytes =
        serde_json::to_vec_pretty(value).map_err(|_| "hermes-hook-allowlist-write-failed")?;
    bytes.push(b'\n');
    let parent = path
        .parent()
        .ok_or_else(|| "invalid-hermes-allowlist-path".to_owned())?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)
        .map_err(|_| "hermes-hook-allowlist-write-failed")?;
    temporary
        .write_all(&bytes)
        .map_err(|_| "hermes-hook-allowlist-write-failed")?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|_| "hermes-hook-allowlist-write-failed")?;
    temporary
        .persist(path)
        .map_err(|_| "hermes-hook-allowlist-write-failed")?;
    Ok(())
}
