//! Maps host paths and I/O failures into protocol observation values.

use nah_proto::ctx::{AbsolutePath, Platform};
use nah_proto::observation::{ObservationFailure, Observed};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub(crate) fn observed_path(result: io::Result<PathBuf>) -> Observed<AbsolutePath> {
    match result {
        Ok(path) => match absolute_from_path(&path) {
            Ok(value) => Observed::Ok { value },
            Err(error) => Observed::Error { error },
        },
        Err(error) => Observed::Error {
            error: map_io_error(&error),
        },
    }
}

pub(crate) fn canonical_absolute(path: &Path) -> Result<AbsolutePath, ObservationFailure> {
    fs::canonicalize(path)
        .map_err(|error| map_io_error(&error))
        .and_then(|path| absolute_from_path(&path))
}

pub(crate) fn absolute_from_path(path: &Path) -> Result<AbsolutePath, ObservationFailure> {
    let text = path.to_str().ok_or(ObservationFailure::NonUnicode)?;
    let platform = host_platform();
    let text = if platform == Platform::Windows {
        normalize_windows_observed_path(text)
    } else {
        text.to_owned()
    };
    AbsolutePath::new(platform, text).map_err(|_| ObservationFailure::InvalidPath)
}

/// Reduces filesystem API extended paths to the drive and UNC identities Nah models.
pub fn normalize_windows_observed_path(path: &str) -> String {
    let Some(remainder) = path.strip_prefix(r"\\?\") else {
        return path.to_owned();
    };
    if remainder
        .get(..4)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("UNC\\"))
    {
        return format!(r"\\{}", &remainder[4..]);
    }
    let bytes = remainder.as_bytes();
    if bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'\\' | b'/')
    {
        return remainder.to_owned();
    }
    path.to_owned()
}

/// Whether `flags`, an item's file flags, mark it a dataless File Provider
/// item: one whose contents its provider has not fetched yet. Opening,
/// listing or reading it asks the provider for them and waits however long
/// that takes, which is without end where the provider does not answer;
/// examining its metadata does not.
#[cfg(target_os = "macos")]
pub(crate) fn dataless_flags(flags: u32) -> bool {
    /// `sys/stat.h`.
    const SF_DATALESS: u32 = 0x4000_0000;
    flags & SF_DATALESS != 0
}

/// Whether the item at `path`, with `metadata`, is a dataless File Provider
/// item, which nothing that observes may open, list or read. Only macOS has
/// them.
pub(crate) fn dataless(path: &Path, metadata: &fs::Metadata) -> bool {
    #[cfg(test)]
    if simulated::dataless(path) {
        return true;
    }
    let _ = (path, metadata);
    #[cfg(target_os = "macos")]
    return dataless_flags(std::os::macos::fs::MetadataExt::st_flags(metadata));
    #[cfg(not(target_os = "macos"))]
    false
}

/// Items tests have read as dataless, whatever their flags say.
#[cfg(test)]
pub(crate) mod simulated {
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    static DATALESS: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

    pub(crate) fn make_dataless(path: &Path) {
        DATALESS.lock().expect("dataless").push(path.to_path_buf());
    }

    pub(crate) fn dataless(path: &Path) -> bool {
        DATALESS
            .lock()
            .expect("dataless")
            .iter()
            .any(|marked| marked == path)
    }
}

#[cfg(windows)]
pub(crate) fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
pub(crate) fn is_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

/// A reparse point can redirect an observation outside the path the policy received.
pub(crate) fn has_reparse_ancestor(path: &Path) -> Result<bool, ObservationFailure> {
    #[cfg(not(windows))]
    let _ = path;
    #[cfg(windows)]
    for ancestor in path.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) if is_reparse_point(&metadata) => return Ok(true),
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(map_io_error(&error)),
        }
    }
    Ok(false)
}

pub(crate) const fn host_platform() -> Platform {
    if cfg!(target_os = "windows") {
        Platform::Windows
    } else if cfg!(target_os = "macos") {
        Platform::Macos
    } else {
        Platform::Linux
    }
}

pub(crate) fn map_io_error(error: &io::Error) -> ObservationFailure {
    match error.kind() {
        io::ErrorKind::NotFound => ObservationFailure::NotFound,
        io::ErrorKind::PermissionDenied => ObservationFailure::PermissionDenied,
        _ => ObservationFailure::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::normalize_windows_observed_path;

    #[test]
    fn windows_extended_drive_and_unc_paths_reduce_to_policy_paths() {
        assert_eq!(
            normalize_windows_observed_path(r"\\?\C:\Users\test\.nah"),
            r"C:\Users\test\.nah"
        );
        assert_eq!(
            normalize_windows_observed_path(r"\\?\UNC\server\share\.nah"),
            r"\\server\share\.nah"
        );
        assert_eq!(
            normalize_windows_observed_path(r"\\?\Volume{1234}\state"),
            r"\\?\Volume{1234}\state"
        );
    }
}
