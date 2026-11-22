//! Owner-only permissions and crash-safe renames for the files Nah writes.
//! Callers map a failure to their own operational error code.

use std::fs::{File, TryLockError};
use std::path::Path;
use std::time::{Duration, Instant};

/// How long a hook waits for another Nah process to release one of Nah's
/// state locks. Nah holds them for one short read and write, so a lock still
/// held after this belongs to a stopped or stalled holder, such as a
/// suspended terminal.
pub(crate) const HOOK_LOCK_WAIT: Duration = Duration::from_millis(200);

/// Takes `file`'s exclusive lock, retrying while another process holds it
/// until `give_up`, then fails with `WouldBlock`.
pub(crate) fn lock_until(file: &File, give_up: Instant) -> Result<(), TryLockError> {
    loop {
        match file.try_lock() {
            Err(TryLockError::WouldBlock) if Instant::now() < give_up => {
                std::thread::sleep(Duration::from_millis(2));
            }
            attempt => return attempt,
        }
    }
}

/// Restricts a file Nah writes to owner read and write (mode 0600); a no-op on
/// non-Unix builds.
pub(crate) fn restrict_file_to_owner(file: &File) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
    }
    #[cfg(not(unix))]
    {
        let _ = file;
        Ok(())
    }
}

/// Syncs the parent directory so a file just renamed into it survives a crash;
/// a no-op on non-Unix builds.
pub(crate) fn sync_parent_directory(parent: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        File::open(parent).and_then(|directory| directory.sync_all())
    }
    #[cfg(not(unix))]
    {
        let _ = parent;
        Ok(())
    }
}
