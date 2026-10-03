//! Hook-path symlink admission, the hook lock, and the atomic hook file
//! reads and writes shared by runtime hook installers.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;

use serde_json::{Map, Value};

use crate::private_files::{restrict_file_to_owner, sync_parent_directory};

/// Rejects a hook path that is a symlink, returning the caller's runtime error
/// code. A missing path or any other existing entry is admitted. Other
/// metadata failures also return the error. This inspects only the path
/// itself: it never follows the link or checks its ancestors.
pub(super) fn reject_hook_path_symlink(path: &Path, error: &str) -> Result<(), String> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(error.into()),
        Ok(_) => Ok(()),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(error.into()),
    }
}

/// The operational error codes one runtime reports when taking its hook lock.
pub(super) struct HookLockErrorCodes {
    /// The lock path has no parent directory.
    pub(super) invalid_path: &'static str,
    /// The lock file could not be created, opened or locked, or is a symlink.
    pub(super) failed: &'static str,
    /// The lock file could not be restricted to its owner.
    pub(super) permissions: &'static str,
}

/// Acquires a runtime's exclusive hook lock, which serializes concurrent
/// installs and uninstalls of that runtime's hook. Creates the lock file's
/// parent directories and the owner-only lock file as needed, and blocks until
/// the lock is free. The lock is held until the returned file is dropped.
pub(super) fn acquire_hook_lock(
    lock_path: &Path,
    errors: &HookLockErrorCodes,
) -> Result<File, String> {
    let parent = lock_path
        .parent()
        .ok_or_else(|| errors.invalid_path.to_owned())?;
    std::fs::create_dir_all(parent).map_err(|_| errors.failed)?;
    reject_hook_path_symlink(lock_path, errors.failed)?;
    let mut options = OpenOptions::new();
    options.create(true).truncate(false).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(lock_path).map_err(|_| errors.failed)?;
    restrict_file_to_owner(&file).map_err(|_| errors.permissions.to_owned())?;
    file.lock().map_err(|_| errors.failed)?;
    Ok(file)
}

/// Acquires a runtime's hook lock like [`acquire_hook_lock`], first rejecting a
/// lock directory that is itself a symlink.
pub(super) fn acquire_hook_lock_in_unlinked_directory(
    lock_path: &Path,
    errors: &HookLockErrorCodes,
) -> Result<File, String> {
    let parent = lock_path
        .parent()
        .ok_or_else(|| errors.invalid_path.to_owned())?;
    reject_hook_path_symlink(parent, errors.failed)?;
    acquire_hook_lock(lock_path, errors)
}

/// The operational error codes one runtime reports when writing a hook file.
pub(super) struct HookFileWriteErrorCodes {
    /// The hook file path has no parent directory.
    pub(super) invalid_path: &'static str,
    /// The parent directory or the temporary file could not be created,
    /// written, flushed or renamed into place.
    pub(super) write_failed: &'static str,
    /// The temporary file could not be restricted to its owner.
    pub(super) permissions: &'static str,
    /// The parent directory could not be synced after the rename.
    pub(super) sync_failed: &'static str,
}

/// Writes a hook file atomically: the bytes go to an owner-only temporary file
/// in the same directory, which is flushed and renamed over `path`, then the
/// directory is synced. The parent directory must already exist, and the
/// caller rejects a symlinked `path` first.
pub(super) fn write_hook_file_atomically(
    path: &Path,
    bytes: &[u8],
    errors: &HookFileWriteErrorCodes,
) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| errors.invalid_path.to_owned())?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent).map_err(|_| errors.write_failed)?;
    restrict_file_to_owner(temporary.as_file()).map_err(|_| errors.permissions.to_owned())?;
    temporary
        .write_all(bytes)
        .map_err(|_| errors.write_failed)?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|_| errors.write_failed)?;
    temporary.persist(path).map_err(|_| errors.write_failed)?;
    sync_parent_directory(parent).map_err(|_| errors.sync_failed.to_owned())
}

/// Writes a runtime's JSON hook configuration like
/// [`write_hook_file_atomically`], as pretty-printed JSON with a trailing
/// newline, first creating the parent directories.
pub(super) fn write_hook_json_atomically(
    path: &Path,
    config: &Value,
    errors: &HookFileWriteErrorCodes,
) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| errors.invalid_path.to_owned())?;
    std::fs::create_dir_all(parent).map_err(|_| errors.write_failed)?;
    let mut bytes = serde_json::to_vec_pretty(config).map_err(|_| errors.write_failed)?;
    bytes.push(b'\n');
    write_hook_file_atomically(path, &bytes, errors)
}

/// The operational error codes one runtime reports when reading its JSON hook
/// configuration.
pub(super) struct HookJsonReadErrorCodes {
    /// The file exists but could not be opened.
    pub(super) read_failed: &'static str,
    /// The file is not JSON, or its top level is not an object.
    pub(super) invalid: &'static str,
}

/// Reads a runtime's JSON hook configuration, which must be a JSON object. A
/// missing file reads as an empty object. The caller rejects a symlinked
/// `path` first.
pub(super) fn read_hook_json_object(
    path: &Path,
    errors: &HookJsonReadErrorCodes,
) -> Result<Value, String> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Value::Object(Map::new()));
        }
        Err(_) => return Err(errors.read_failed.into()),
    };
    let value: Value = serde_json::from_reader(file).map_err(|_| errors.invalid.to_owned())?;
    if !value.is_object() {
        return Err(errors.invalid.into());
    }
    Ok(value)
}
