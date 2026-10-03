//! Hook-path symlink admission and the hook lock shared by runtime hook
//! installers.

use std::fs::{File, OpenOptions};
use std::path::Path;

use crate::private_files::restrict_file_to_owner;

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
