//! Hook-path symlink admission shared by runtime hook installers.

use std::path::Path;

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
