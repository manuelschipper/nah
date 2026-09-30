//! Paths under the user's `.nah` directory and crash-safe renames into them.

use std::fs::File;
use std::path::{Path, PathBuf};

use nah_proto::ctx::{AbsolutePath, Platform};

/// Joins `components` under `<home>/.nah` with the separator of the target
/// `platform`, not the host's.
pub(crate) fn nah_home_path(
    home: &AbsolutePath,
    platform: Platform,
    components: &[&str],
) -> PathBuf {
    let separator = if platform == Platform::Windows {
        '\\'
    } else {
        '/'
    };
    let mut path = home.as_str().trim_end_matches(['/', '\\']).to_owned();
    for component in std::iter::once(".nah").chain(components.iter().copied()) {
        path.push(separator);
        path.push_str(component);
    }
    PathBuf::from(path)
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
