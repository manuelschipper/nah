//! Installs and removes nah's native Hermes shell hooks: the
//! `pre_tool_call` one that decides, and the `post_tool_call` one that
//! refreshes save-then-run's rolling copy and settles session memory.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use nah_proto::ctx::AbsolutePath;
use serde_yaml_ng::{Mapping, Value};

use crate::{live_state, runtime::FailurePolicy};

use super::hook_paths::reject_hook_path_symlink;
use super::runtime::reject_unsupported_windows_runtime;
use super::shell_word::quote_posix_shell_word;
use super::{RuntimeHookStatus, RuntimeMutation};

const PRE_EVENT: &str = "pre_tool_call";
const POST_EVENT: &str = "post_tool_call";

pub(crate) fn mutate_hermes_hook(
    install: bool,
    policy: FailurePolicy,
) -> Result<RuntimeMutation, String> {
    let platform = live_state::host_platform();
    reject_unsupported_windows_runtime(platform)?;
    let path = live_state::home(platform).and_then(|home| {
        let configured = configured_hermes_home(&home);
        let home = resolve_hermes_home(&configured, platform)?;
        if install {
            let executable = std::env::current_exe()
                .map_err(|_| "nah-executable-path-unavailable".to_owned())?;
            let hook_command = command_for(&executable, policy)?;
            // Self-protection recognizes only this form, so an executable
            // under another name would install a hook it cannot protect.
            if !is_nah_command(Some(&hook_command)) {
                return Err("nah-executable-name-unsupported".into());
            }
            install_hermes_hook(&home, &hook_command, policy)
        } else {
            uninstall_hermes_hook(&home)
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
    if reject_unsupported_windows_runtime(platform).is_err() {
        return Ok(RuntimeHookStatus::NotConfigured);
    }
    let home = live_state::home(platform)?;
    let configured = configured_hermes_home(&home);
    if !configured.exists() {
        return Ok(RuntimeHookStatus::NotConfigured);
    }
    let home = resolve_hermes_home(&configured, platform)?;
    let paths = HermesHookPaths::new(&home);
    reject_hermes_hook_symlinks(&paths)?;
    if !paths.config.exists() {
        return Ok(RuntimeHookStatus::NotConfigured);
    }
    let config = load_config(&paths.config)?;
    // Report the conflict install would refuse instead of recommending install
    let Some(owned) = owned_entry(&config, PRE_EVENT)? else {
        return Ok(RuntimeHookStatus::NotConfigured);
    };
    let post = owned_entry(&config, POST_EVENT)?;
    let executable =
        std::env::current_exe().map_err(|_| "nah-executable-path-unavailable".to_owned())?;
    let delegate_command = command_for(&executable, FailurePolicy::Delegate)?;
    let fail_closed_command = command_for(&executable, FailurePolicy::Block)?;
    // An install without the post-call hook is stale.
    let post_current = post == Some(&desired_post_hook(&delegate_command))
        && allowlisted(&paths.allowlist, POST_EVENT, &delegate_command)?;
    Ok(
        if post_current
            && owned == &desired_hermes_hook(&delegate_command, FailurePolicy::Delegate)
            && allowlisted(&paths.allowlist, PRE_EVENT, &delegate_command)?
        {
            RuntimeHookStatus::WiringCurrent
        } else if post_current
            && owned == &desired_hermes_hook(&fail_closed_command, FailurePolicy::Block)
            && allowlisted(&paths.allowlist, PRE_EVENT, &fail_closed_command)?
        {
            RuntimeHookStatus::WiringCurrentFailClosed
        } else {
            RuntimeHookStatus::stale(
                if hermes_hook_command(owned)
                    .is_some_and(|command| command.ends_with(" --fail-closed"))
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

fn install_hermes_hook(
    home: &AbsolutePath,
    hook_command: &str,
    policy: FailurePolicy,
) -> Result<PathBuf, String> {
    let paths = HermesHookPaths::new(home);
    let lock = acquire_hermes_hook_lock(&paths)?;
    reject_hermes_hook_symlinks(&paths)?;
    let mut config = load_config(&paths.config)?;
    // The post-call hook only reports, so it never carries `--fail-closed`.
    let post_command = hook_command
        .strip_suffix(FailurePolicy::Block.command_suffix())
        .unwrap_or(hook_command);
    for (event, desired) in [
        (PRE_EVENT, desired_hermes_hook(hook_command, policy)),
        (POST_EVENT, desired_post_hook(post_command)),
    ] {
        let entries = hook_entries_mut(&mut config, event)?;
        reject_unowned(entries)?;
        match owned_indices(entries).as_slice() {
            [] => entries.push(desired),
            [index] => entries[*index] = desired,
            _ => return Err("hermes-hook-ownership-ambiguous".into()),
        }
    }
    save_config(&paths.config, &config)?;
    update_allowlist(
        &paths,
        &[(PRE_EVENT, hook_command), (POST_EVENT, post_command)],
    )?;
    drop(lock);
    Ok(paths.config)
}

fn uninstall_hermes_hook(home: &AbsolutePath) -> Result<PathBuf, String> {
    let paths = HermesHookPaths::new(home);
    let lock = acquire_hermes_hook_lock(&paths)?;
    reject_hermes_hook_symlinks(&paths)?;
    if paths.config.exists() {
        let mut config = load_config(&paths.config)?;
        let mut removed = false;
        for event in [PRE_EVENT, POST_EVENT] {
            let owned = hook_entries(&config, event)?
                .map(|entries| owned_indices(entries))
                .unwrap_or_default();
            match owned.as_slice() {
                [] => {}
                [index] => {
                    remove_hook(&mut config, event, *index)?;
                    removed = true;
                }
                _ => return Err("hermes-hook-ownership-ambiguous".into()),
            }
        }
        if removed {
            update_allowlist(&paths, &[])?;
            save_config(&paths.config, &config)?;
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

fn acquire_hermes_hook_lock(paths: &HermesHookPaths) -> Result<File, String> {
    open_lock(&paths.lock, "hermes-hook-lock-failed")
}

fn open_lock(path: &Path, error: &str) -> Result<File, String> {
    reject_hook_path_symlink(path, error)?;
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

fn reject_hermes_hook_symlinks(paths: &HermesHookPaths) -> Result<(), String> {
    for path in [&paths.config, &paths.allowlist, &paths.allowlist_lock] {
        reject_hook_path_symlink(path, "hermes-hook-symlink-unsupported")?;
    }
    Ok(())
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

fn hook_entries<'a>(config: &'a Mapping, event: &str) -> Result<Option<&'a Vec<Value>>, String> {
    let Some(hooks) = config.get("hooks") else {
        return Ok(None);
    };
    let hooks = hooks
        .as_mapping()
        .ok_or_else(|| "hermes-config-invalid".to_owned())?;
    let Some(entries) = hooks.get(event) else {
        return Ok(None);
    };
    entries
        .as_sequence()
        .map(Some)
        .ok_or_else(|| "hermes-config-invalid".to_owned())
}

fn hook_entries_mut<'a>(
    config: &'a mut Mapping,
    event: &str,
) -> Result<&'a mut Vec<Value>, String> {
    let hooks = config
        .entry(yaml_key("hooks"))
        .or_insert_with(|| Value::Mapping(Mapping::new()))
        .as_mapping_mut()
        .ok_or_else(|| "hermes-config-invalid".to_owned())?;
    hooks
        .entry(yaml_key(event))
        .or_insert_with(|| Value::Sequence(Vec::new()))
        .as_sequence_mut()
        .ok_or_else(|| "hermes-config-invalid".to_owned())
}

fn remove_hook(config: &mut Mapping, event: &str, index: usize) -> Result<(), String> {
    let hooks = config
        .get_mut("hooks")
        .and_then(Value::as_mapping_mut)
        .ok_or_else(|| "hermes-config-invalid".to_owned())?;
    let entries = hooks
        .get_mut(event)
        .and_then(Value::as_sequence_mut)
        .ok_or_else(|| "hermes-config-invalid".to_owned())?;
    entries.remove(index);
    if entries.is_empty() {
        hooks.remove(event);
    }
    if hooks.is_empty() {
        config.remove("hooks");
    }
    Ok(())
}

/// The indices of Nah's own entries among one event's hooks.
fn owned_indices(entries: &[Value]) -> Vec<usize> {
    entries
        .iter()
        .enumerate()
        .filter(|(_, entry)| owned_hook(entry))
        .map(|(index, _)| index)
        .collect()
}

/// Nah's one entry for `event`, if any. A Nah command without Nah's marker
/// is refused, as install refuses it.
fn owned_entry<'a>(config: &'a Mapping, event: &str) -> Result<Option<&'a Value>, String> {
    let Some(entries) = hook_entries(config, event)? else {
        return Ok(None);
    };
    reject_unowned(entries)?;
    match owned_indices(entries).as_slice() {
        [] => Ok(None),
        [index] => Ok(Some(&entries[*index])),
        _ => Err("hermes-hook-ownership-ambiguous".into()),
    }
}

/// The `post_tool_call` hook. Hermes waits for it, so the adapter hands
/// the finished call to a process of its own, which refreshes the rolling
/// copy and settles session memory; `fail_closed` applies to no post-call
/// event.
fn desired_post_hook(hook_command: &str) -> Value {
    let mut hook = Mapping::new();
    hook.insert(yaml_key("command"), Value::String(hook_command.into()));
    hook.insert(yaml_key("timeout"), Value::Number(10.into()));
    hook.insert(yaml_key("managed_by"), Value::String("nah".into()));
    Value::Mapping(hook)
}

fn desired_hermes_hook(hook_command: &str, policy: FailurePolicy) -> Value {
    let mut hook = Mapping::new();
    hook.insert(yaml_key("command"), Value::String(hook_command.into()));
    hook.insert(yaml_key("timeout"), Value::Number(5.into()));
    if policy == FailurePolicy::Block {
        // Hermes otherwise ignores a hook that cannot start, times out, or
        // prints invalid output.
        hook.insert(yaml_key("fail_closed"), Value::Bool(true));
    }
    hook.insert(yaml_key("managed_by"), Value::String("nah".into()));
    Value::Mapping(hook)
}

/// Hermes runs the hook without a shell and resolves a bare name through its
/// own PATH, so the command names this executable by absolute path.
fn command_for(executable: &Path, policy: FailurePolicy) -> Result<String, String> {
    let executable = executable
        .to_str()
        .ok_or_else(|| "invalid-nah-executable-path".to_owned())?;
    Ok(format!(
        "{} hook hermes run{}",
        quote_posix_shell_word(executable),
        policy.command_suffix()
    ))
}

/// Whether `command` is a Hermes shell-hook command that runs Nah's Hermes
/// adapter: `nah`, or one absolute path to an executable named `nah` quoted
/// exactly as `command_for` writes it, then `hook hermes run`, optionally
/// followed by `--fail-closed`. The Hermes model in the engine recognizes the
/// same commands when `hermes hooks revoke` removes one.
fn is_nah_command(command: Option<&str>) -> bool {
    let Some(command) = command else {
        return false;
    };
    let command = command.strip_suffix(" --fail-closed").unwrap_or(command);
    let Some(executable) = command.strip_suffix(" hook hermes run") else {
        return false;
    };
    if executable == "nah" {
        return true;
    }
    let Some(path) = executable
        .strip_prefix('\'')
        .and_then(|word| word.strip_suffix('\''))
        .map(|quoted| quoted.replace("'\"'\"'", "'"))
    else {
        return false;
    };
    // Requoting rejects anything but one word in the installer's quoting,
    // such as `'/bin/echo' '/nah'`.
    quote_posix_shell_word(&path) == executable
        && path.starts_with('/')
        && path.rsplit('/').next() == Some("nah")
}

/// Rejects a hook that runs Nah's Hermes adapter without Nah's ownership
/// marker, which Nah neither claims nor removes.
fn reject_unowned(entries: &[Value]) -> Result<(), String> {
    if entries
        .iter()
        .any(|entry| is_nah_command(hermes_hook_command(entry)) && !owned_hook(entry))
    {
        return Err("hermes-hook-not-owned".into());
    }
    Ok(())
}

fn owned_hook(value: &Value) -> bool {
    value
        .as_mapping()
        .and_then(|hook| hook.get("managed_by"))
        .and_then(Value::as_str)
        == Some("nah")
}

fn hermes_hook_command(value: &Value) -> Option<&str> {
    value
        .as_mapping()
        .and_then(|hook| hook.get("command"))
        .and_then(Value::as_str)
}

fn yaml_key(value: &str) -> Value {
    Value::String(value.into())
}

fn allowlisted(path: &Path, event: &str, hook_command: &str) -> Result<bool, String> {
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
                entry.get("event").and_then(serde_json::Value::as_str) == Some(event)
                    && entry.get("command").and_then(serde_json::Value::as_str)
                        == Some(hook_command)
            })
        }))
}

/// Replaces Nah's approvals for both events with one for each of
/// `approve`'s `(event, command)` pairs.
fn update_allowlist(paths: &HermesHookPaths, approve: &[(&str, &str)]) -> Result<(), String> {
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
        !entry
            .get("event")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|event| [PRE_EVENT, POST_EVENT].contains(&event))
            || !is_nah_command(entry.get("command").and_then(serde_json::Value::as_str))
    });
    for (event, hook_command) in approve {
        approvals.push(serde_json::json!({
            "event": event,
            "command": hook_command,
            "approved_at": crate::dispatch::current_timestamp_rfc3339(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hermes_hook_command_is_one_installer_quoted_nah_executable() {
        for command in [
            "nah hook hermes run",
            "'/opt/homebrew/bin/nah' hook hermes run --fail-closed",
            "'/Users/o'\"'\"'neil/bin/nah' hook hermes run",
        ] {
            assert!(is_nah_command(Some(command)), "{command}");
        }
        for command in [
            "'/bin/echo' '/nah' hook hermes run",
            "'/tmp/example/nah-v1' hook hermes run --fail-closed",
            "'nah' hook hermes run",
            "'/opt/nah'x hook hermes run",
            "'/opt/o'neil/nah' hook hermes run",
            "/opt/homebrew/bin/nah hook hermes run",
            "'/opt/homebrew/bin/nah' hook hermes run --verbose",
        ] {
            assert!(!is_nah_command(Some(command)), "{command}");
        }
    }
}
