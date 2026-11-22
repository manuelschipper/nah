//! Removes the Kiro CLI 3 global hook of Nah 1.x.

use std::fs::File;
#[cfg(not(all(unix, not(target_os = "redox"))))]
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};

use nah_proto::ctx::{AbsolutePath, Platform};
use serde_json::Value;

use crate::live_state;

use super::super::RuntimeMutation;
use super::super::hook_paths::reject_hook_path_symlink;
use super::super::shell_word::quote_posix_shell_word;
use crate::private_files::restrict_file_to_owner;

const MAX_HOOK_FILE_BYTES: u64 = 1024 * 1024;

pub(super) fn uninstall() -> Result<RuntimeMutation, String> {
    let platform = live_state::host_platform();
    let home = live_state::home(platform)?;
    let root = kiro_root(&home, platform)?;
    let path = uninstall_kiro_hook(&home, &root)?;
    Ok(RuntimeMutation::new(false, "Kiro CLI hook", path, None))
}

fn uninstall_kiro_hook(home: &AbsolutePath, root: &Path) -> Result<PathBuf, String> {
    let paths = KiroHookPaths::new(home, root);
    let lock = acquire_kiro_hook_lock(&paths)?;
    let Some(directory) = open_hook_directory(&paths)? else {
        drop(lock);
        return Ok(paths.hook);
    };
    if let Some(configured) = load_kiro_hook(&directory)? {
        if !is_owned_kiro_hook(&configured.config) {
            return Err("kiro-hook-file-conflict".into());
        }
        remove_kiro_hook(&directory, &configured)?;
    }
    drop(lock);
    Ok(paths.hook)
}

fn kiro_root(home: &AbsolutePath, platform: Platform) -> Result<PathBuf, String> {
    let Some(configured) = std::env::var_os("KIRO_HOME") else {
        return Ok(PathBuf::from(home.as_str()).join(".kiro"));
    };
    let configured = configured
        .to_str()
        .ok_or_else(|| "invalid-kiro-home".to_owned())?;
    let configured = AbsolutePath::new(platform, configured)
        .map(|path| PathBuf::from(path.as_str()))
        .map_err(|_| "invalid-kiro-home".to_owned())?;
    let canonical =
        std::fs::canonicalize(&configured).map_err(|_| "kiro-home-cannot-be-resolved")?;
    let canonical = canonical
        .to_str()
        .map(nah_observe::normalize_windows_observed_path)
        .ok_or("invalid-kiro-home")?;
    let configured = configured.to_str().ok_or("invalid-kiro-home")?;
    let matches = if platform == Platform::Windows {
        canonical.eq_ignore_ascii_case(configured)
    } else {
        canonical == configured
    };
    if !matches {
        return Err("kiro-home-symlink-unsupported".into());
    }
    Ok(PathBuf::from(configured))
}

struct KiroHookPaths {
    root: PathBuf,
    hook: PathBuf,
    lock: PathBuf,
}

impl KiroHookPaths {
    fn new(home: &AbsolutePath, root: &Path) -> Self {
        let hooks = root.join("hooks");
        Self {
            root: root.to_owned(),
            hook: hooks.join("nah.json"),
            lock: PathBuf::from(home.as_str()).join(".nah/kiro-hook.lock"),
        }
    }
}

fn is_owned_kiro_hook(config: &Value) -> bool {
    let Some(root) = config.as_object() else {
        return false;
    };
    let Some(hooks) = config.get("hooks").and_then(Value::as_array) else {
        return false;
    };
    root.keys()
        .all(|key| matches!(key.as_str(), "version" | "hooks"))
        && config.get("version").and_then(Value::as_str) == Some("v1")
        && hooks.len() == 1
        && hooks[0].as_object().is_some_and(|hook| {
            hook.keys().all(|key| {
                matches!(
                    key.as_str(),
                    "name" | "description" | "trigger" | "action" | "timeout" | "enabled"
                )
            }) && hook.get("name").and_then(Value::as_str) == Some("nah")
                && hook.get("description").and_then(Value::as_str)
                    == Some("Block tool calls that nah proves are disasters.")
                && hook.get("trigger").and_then(Value::as_str) == Some("PreToolUse")
                && hook.get("timeout").and_then(Value::as_u64) == Some(5)
                && hook.get("enabled").and_then(Value::as_bool) == Some(true)
                && hook
                    .get("action")
                    .and_then(Value::as_object)
                    .is_some_and(|action| {
                        action
                            .keys()
                            .all(|key| matches!(key.as_str(), "type" | "command"))
                            && action.get("type").and_then(Value::as_str) == Some("command")
                            && action
                                .get("command")
                                .and_then(Value::as_str)
                                .is_some_and(is_owned_kiro_command)
                    })
        })
}

fn is_owned_kiro_command(command: &str) -> bool {
    let command = command.replacen(" hook kiro run --fail-closed", " hook kiro run", 1);
    let command = command.as_str();
    // The hyphen is the prefix these hooks used before `nah · `. A refresh
    // still has to recognize that plugin as ours so it can rewrite it.
    const UNIX_SUFFIXES: [&str; 3] = [
        " hook kiro run || { status=$?; [ \"$status\" -eq 1 ] && exit 1; \
         [ \"$status\" -eq 2 ] && exit 2; printf '%s\\n' \
         'nah · evaluation failed; this call was delegated to the runtime' \
         >&2; exit 1; }",
        " hook kiro run || { status=$?; [ \"$status\" -eq 1 ] && exit 1; \
         [ \"$status\" -eq 2 ] && exit 2; printf '%s\\n' \
         'nah - evaluation failed; this call was delegated to the runtime' \
         >&2; exit 1; }",
        " hook kiro run || { status=$?; [ \"$status\" -eq 1 ] && exit 1; \
         [ \"$status\" -eq 2 ] && exit 2; printf '%s\\n' \
         'nah · evaluation was incomplete; this call was blocked' >&2; exit 2; }",
    ];
    if let Some(executable) = UNIX_SUFFIXES
        .iter()
        .find_map(|suffix| command.strip_suffix(suffix))
    {
        if !executable.starts_with('\'') || !executable.ends_with('\'') {
            return false;
        }
        let decoded = executable[1..executable.len() - 1].replace("'\"'\"'", "'");
        return quote_posix_shell_word(&decoded) == executable
            && decoded.ends_with("/nah")
            && AbsolutePath::new(Platform::Linux, &decoded).is_ok();
    }
    command
        .strip_suffix(" hook kiro run")
        .is_some_and(|executable| {
            executable.starts_with('"')
                && executable.ends_with('"')
                && !executable[1..executable.len() - 1].contains('"')
                && {
                    let path = &executable[1..executable.len() - 1];
                    let lowercase = path.to_ascii_lowercase();
                    (lowercase.ends_with("\\nah.exe")
                        || lowercase.ends_with("/nah.exe")
                        || lowercase.ends_with("/nah"))
                        && AbsolutePath::new(Platform::Windows, path).is_ok()
                }
        })
}

#[cfg(all(unix, not(target_os = "redox")))]
fn acquire_kiro_hook_lock(paths: &KiroHookPaths) -> Result<File, String> {
    use rustix::fs::{Mode, OFlags};

    let parent = paths
        .lock
        .parent()
        .ok_or_else(|| "invalid-kiro-hook-lock-path".to_owned())?;
    reject_hook_path_symlink(parent, "kiro-hook-lock-failed")?;
    std::fs::create_dir_all(parent).map_err(|_| "kiro-hook-lock-failed")?;
    let directory = rustix::fs::open(
        parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| "kiro-hook-lock-failed")?;
    let descriptor = rustix::fs::openat(
        directory,
        "kiro-hook.lock",
        OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|_| "kiro-hook-lock-failed")?;
    let file = File::from(descriptor);
    restrict_file_to_owner(&file).map_err(|_| "kiro-hook-permissions-failed".to_owned())?;
    file.lock().map_err(|_| "kiro-hook-lock-failed")?;
    Ok(file)
}

#[cfg(not(all(unix, not(target_os = "redox"))))]
fn acquire_kiro_hook_lock(paths: &KiroHookPaths) -> Result<File, String> {
    let parent = paths
        .lock
        .parent()
        .ok_or_else(|| "invalid-kiro-hook-lock-path".to_owned())?;
    reject_hook_path_symlink(parent, "kiro-hook-lock-failed")?;
    std::fs::create_dir_all(parent).map_err(|_| "kiro-hook-lock-failed")?;
    reject_hook_path_symlink(&paths.lock, "kiro-hook-lock-failed")?;
    let mut options = OpenOptions::new();
    options.create(true).truncate(false).read(true).write(true);
    let file = options
        .open(&paths.lock)
        .map_err(|_| "kiro-hook-lock-failed")?;
    restrict_file_to_owner(&file).map_err(|_| "kiro-hook-permissions-failed".to_owned())?;
    file.lock().map_err(|_| "kiro-hook-lock-failed")?;
    Ok(file)
}

#[cfg(all(not(windows), not(all(unix, not(target_os = "redox")))))]
fn sync_parent(parent: &Path) -> Result<(), String> {
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| "kiro-hook-write-failed".to_owned())
}

#[cfg(windows)]
fn sync_parent(_parent: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(all(unix, not(target_os = "redox")))]
struct HookDirectory {
    file: File,
}

#[cfg(not(all(unix, not(target_os = "redox"))))]
struct HookDirectory {
    path: PathBuf,
}

struct LoadedHook {
    config: Value,
    #[cfg(all(unix, not(target_os = "redox")))]
    identity: FileIdentity,
}

#[cfg(all(unix, not(target_os = "redox")))]
#[derive(Clone, Copy, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    length: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

#[cfg(all(unix, not(target_os = "redox")))]
impl FileIdentity {
    // only the exchange-based rename paths compare content, and those are
    // Linux and Android alone
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn same_content(self, other: Self) -> bool {
        self.device == other.device
            && self.inode == other.inode
            && self.length == other.length
            && self.modified_seconds == other.modified_seconds
            && self.modified_nanoseconds == other.modified_nanoseconds
    }
}

/// Unix mutations stay relative to opened directories, so replacing the
/// configured `hooks` pathname cannot redirect a later write or removal.
#[cfg(all(unix, not(target_os = "redox")))]
fn open_hook_directory(paths: &KiroHookPaths) -> Result<Option<HookDirectory>, String> {
    use rustix::fs::{Mode, OFlags};

    let flags =
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let root = match rustix::fs::open(&paths.root, flags, Mode::empty()) {
        Ok(root) => File::from(root),
        Err(error) if error == rustix::io::Errno::NOENT => return Ok(None),
        Err(_) => return Err("kiro-hook-symlink-unsupported".into()),
    };
    match rustix::fs::openat(&root, "hooks", flags, Mode::empty()) {
        Ok(directory) => Ok(Some(HookDirectory {
            file: File::from(directory),
        })),
        Err(error) if error == rustix::io::Errno::NOENT => Ok(None),
        Err(_) => Err("kiro-hook-symlink-unsupported".into()),
    }
}

#[cfg(not(all(unix, not(target_os = "redox"))))]
fn open_hook_directory(paths: &KiroHookPaths) -> Result<Option<HookDirectory>, String> {
    let hooks = paths.root.join("hooks");
    reject_hook_path_symlink(&paths.root, "kiro-hook-symlink-unsupported")?;
    reject_hook_path_symlink(&hooks, "kiro-hook-symlink-unsupported")?;
    reject_hook_path_symlink(&paths.hook, "kiro-hook-symlink-unsupported")?;
    if !hooks.exists() {
        return Ok(None);
    }
    Ok(Some(HookDirectory { path: hooks }))
}

#[cfg(all(unix, not(target_os = "redox")))]
fn load_kiro_hook(directory: &HookDirectory) -> Result<Option<LoadedHook>, String> {
    load_named(directory, "nah.json")
}

#[cfg(all(unix, not(target_os = "redox")))]
fn load_named(directory: &HookDirectory, name: &str) -> Result<Option<LoadedHook>, String> {
    use rustix::fs::{Mode, OFlags};

    let descriptor = match rustix::fs::openat(
        &directory.file,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(error) if error == rustix::io::Errno::NOENT => return Ok(None),
        Err(error) if error == rustix::io::Errno::LOOP => {
            return Err("kiro-hook-symlink-unsupported".into());
        }
        Err(_) => return Err("kiro-hook-read-failed".into()),
    };
    let file = File::from(descriptor);
    let metadata = file.metadata().map_err(|_| "kiro-hook-read-failed")?;
    if !metadata.is_file() {
        return Err("invalid-kiro-hook".into());
    }
    if metadata.len() > MAX_HOOK_FILE_BYTES {
        return Err("invalid-kiro-hook".into());
    }
    let before = file_identity(&metadata);
    let config = serde_json::from_reader(&file).map_err(|_| "invalid-kiro-hook".to_owned())?;
    let after = file_identity(&file.metadata().map_err(|_| "kiro-hook-read-failed")?);
    if before != after {
        return Err("kiro-hook-file-conflict".into());
    }
    Ok(Some(LoadedHook {
        config,
        identity: after,
    }))
}

#[cfg(not(all(unix, not(target_os = "redox"))))]
fn load_kiro_hook(directory: &HookDirectory) -> Result<Option<LoadedHook>, String> {
    let path = directory.path.join("nah.json");
    reject_hook_path_symlink(&path, "kiro-hook-symlink-unsupported")?;
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("kiro-hook-read-failed".into()),
    };
    if file.metadata().map_err(|_| "kiro-hook-read-failed")?.len() > MAX_HOOK_FILE_BYTES {
        return Err("invalid-kiro-hook".into());
    }
    serde_json::from_reader(file)
        .map(|config| Some(LoadedHook { config }))
        .map_err(|_| "invalid-kiro-hook".into())
}

#[cfg(all(unix, not(target_os = "redox")))]
fn same_loaded(left: &LoadedHook, right: &LoadedHook) -> bool {
    left.identity == right.identity && left.config == right.config
}

#[cfg(not(all(unix, not(target_os = "redox"))))]
fn same_loaded(left: &LoadedHook, right: &LoadedHook) -> bool {
    left.config == right.config
}

fn unchanged(directory: &HookDirectory, expected: Option<&LoadedHook>) -> Result<(), String> {
    let current = load_kiro_hook(directory)?;
    let unchanged = match (current.as_ref(), expected) {
        (None, None) => true,
        (Some(current), Some(expected)) => same_loaded(current, expected),
        _ => false,
    };
    if unchanged {
        Ok(())
    } else {
        Err("kiro-hook-file-conflict".into())
    }
}

#[cfg(all(unix, not(target_os = "redox")))]
fn file_identity(metadata: &std::fs::Metadata) -> FileIdentity {
    use std::os::unix::fs::MetadataExt;

    FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        length: metadata.len(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn named_identity(directory: &HookDirectory, name: &str) -> Option<FileIdentity> {
    use rustix::fs::{Mode, OFlags};

    let descriptor = rustix::fs::openat(
        &directory.file,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .ok()?;
    let metadata = File::from(descriptor).metadata().ok()?;
    metadata.is_file().then(|| file_identity(&metadata))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn remove_kiro_hook(directory: &HookDirectory, expected: &LoadedHook) -> Result<(), String> {
    use rustix::fs::{AtFlags, RenameFlags};

    let temporary = format!(
        ".nah-{:016x}.remove",
        getrandom::u64().map_err(|_| "kiro-hook-remove-failed")?
    );
    unchanged(directory, Some(expected))?;
    rustix::fs::renameat_with(
        &directory.file,
        "nah.json",
        &directory.file,
        temporary.as_str(),
        RenameFlags::NOREPLACE,
    )
    .map_err(|_| "kiro-hook-remove-failed".to_owned())?;
    if named_identity(directory, temporary.as_str())
        .is_some_and(|identity| identity.same_content(expected.identity))
    {
        rustix::fs::unlinkat(&directory.file, temporary.as_str(), AtFlags::empty())
            .map_err(|_| "kiro-hook-remove-failed")?;
    } else {
        rustix::fs::renameat_with(
            &directory.file,
            temporary.as_str(),
            &directory.file,
            "nah.json",
            RenameFlags::NOREPLACE,
        )
        .map_err(|_| "kiro-hook-remove-failed".to_owned())?;
        return Err("kiro-hook-file-conflict".into());
    }
    directory
        .file
        .sync_all()
        .map_err(|_| "kiro-hook-write-failed".to_owned())
}

#[cfg(all(
    unix,
    not(target_os = "redox"),
    not(any(target_os = "linux", target_os = "android"))
))]
fn remove_kiro_hook(directory: &HookDirectory, expected: &LoadedHook) -> Result<(), String> {
    use rustix::fs::AtFlags;

    unchanged(directory, Some(expected))?;
    rustix::fs::unlinkat(&directory.file, "nah.json", AtFlags::empty())
        .map_err(|_| "kiro-hook-remove-failed")?;
    directory
        .file
        .sync_all()
        .map_err(|_| "kiro-hook-write-failed".to_owned())
}

#[cfg(not(all(unix, not(target_os = "redox"))))]
fn remove_kiro_hook(directory: &HookDirectory, expected: &LoadedHook) -> Result<(), String> {
    unchanged(directory, Some(expected))?;
    std::fs::remove_file(directory.path.join("nah.json")).map_err(|_| "kiro-hook-remove-failed")?;
    sync_parent(&directory.path)
}

#[cfg(all(test, unix, not(target_os = "redox")))]
mod tests {
    use std::os::unix::fs::symlink;

    use serde_json::json;

    use super::*;

    const UNIX_COMMAND: &str = "'/usr/bin/nah' hook kiro run || { status=$?; [ \"$status\" -eq 1 ] && exit 1; \
                    [ \"$status\" -eq 2 ] && exit 2; printf '%s\\n' \
                    'nah · evaluation failed; this call was delegated to the runtime' >&2; exit 1; }";

    /// The hook file Nah 1.x wrote, at the hooks directory of `paths`.
    fn write_owned_hook(paths: &KiroHookPaths) {
        std::fs::create_dir_all(paths.hook.parent().unwrap()).unwrap();
        let hook = json!({
            "version":"v1",
            "hooks":[{
                "name":"nah",
                "description":"Block tool calls that nah proves are disasters.",
                "trigger":"PreToolUse",
                "action":{"type":"command","command":UNIX_COMMAND},
                "timeout":5,
                "enabled":true
            }]
        });
        std::fs::write(&paths.hook, serde_json::to_vec(&hook).unwrap()).unwrap();
    }

    fn paths_in(home: &Path) -> KiroHookPaths {
        let home_absolute = AbsolutePath::new(Platform::Linux, home.to_str().unwrap()).unwrap();
        KiroHookPaths::new(&home_absolute, &home.join(".kiro"))
    }

    #[test]
    fn ownership_requires_the_generated_platform_wrapper() {
        assert!(is_owned_kiro_command(UNIX_COMMAND));
        let previous = UNIX_COMMAND.replace('·', "-");
        assert!(is_owned_kiro_command(&previous), "{previous}");
        assert!(is_owned_kiro_command(
            "\"C:\\tools\\nah.exe\" hook kiro run"
        ));
        assert!(!is_owned_kiro_command("'/usr/bin/nah' hook kiro run"));
        assert!(!is_owned_kiro_command(
            "\"C:\\tools\\nah.exe\" hook kiro run || { exit 2; }"
        ));
        assert!(!is_owned_kiro_command(
            "'relative/nah' hook kiro run || { status=$?; [ \
             \"$status\" -eq 1 ] && exit 1; [ \"$status\" -eq 2 ] && exit 2; printf '%s\\n' \
             'nah · evaluation failed; this call was delegated to the runtime' >&2; exit 1; }"
        ));
        assert!(!is_owned_kiro_command("\"relative/nah.exe\" hook kiro run"));
        assert!(!is_owned_kiro_command(&format!(
            "{UNIX_COMMAND}; printf user-command"
        )));
    }

    #[test]
    fn opened_hook_directory_cannot_be_redirected_by_a_path_swap() {
        let home = tempfile::tempdir().unwrap();
        let paths = paths_in(home.path());
        write_owned_hook(&paths);
        let directory = open_hook_directory(&paths).unwrap().unwrap();

        let moved = home.path().join("moved-hooks");
        let target = home.path().join("attacker-target");
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("nah.json"), "{}").unwrap();
        let hooks = paths.root.join("hooks");
        std::fs::rename(&hooks, &moved).unwrap();
        symlink(&target, &hooks).unwrap();

        let configured = load_kiro_hook(&directory).unwrap().unwrap();
        remove_kiro_hook(&directory, &configured).unwrap();
        assert!(!moved.join("nah.json").exists());
        assert!(target.join("nah.json").exists());
    }

    #[test]
    fn a_replaced_hook_is_not_removed() {
        let home = tempfile::tempdir().unwrap();
        let paths = paths_in(home.path());
        write_owned_hook(&paths);
        let directory = open_hook_directory(&paths).unwrap().unwrap();
        let configured = load_kiro_hook(&directory).unwrap().unwrap();
        let replacement = json!({"version":"v1","hooks":[]});
        std::fs::write(&paths.hook, serde_json::to_vec(&replacement).unwrap()).unwrap();

        assert_eq!(
            remove_kiro_hook(&directory, &configured),
            Err("kiro-hook-file-conflict".into())
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&std::fs::read(&paths.hook).unwrap()).unwrap(),
            replacement
        );
    }

    #[test]
    fn oversized_hook_configuration_is_rejected_before_parsing() {
        let home = tempfile::tempdir().unwrap();
        let paths = paths_in(home.path());
        std::fs::create_dir_all(paths.hook.parent().unwrap()).unwrap();
        std::fs::write(&paths.hook, vec![b' '; MAX_HOOK_FILE_BYTES as usize + 1]).unwrap();
        let directory = open_hook_directory(&paths).unwrap().unwrap();

        assert!(matches!(load_kiro_hook(&directory), Err(error) if error == "invalid-kiro-hook"));
    }
}
