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
    AbsolutePath::new(host_platform(), text).map_err(|_| ObservationFailure::InvalidPath)
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
