//! Owner-only permissions and crash-safe renames for the files Nah writes.
//! Callers map a failure to their own operational error code.

use std::fs::File;
use std::path::Path;

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
