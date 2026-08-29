//! Observes requested path identity, kind, aliases, and canonical target.

use crate::io_paths::{absolute_from_path, has_reparse_ancestor, is_reparse_point, map_io_error};
use nah_proto::ctx::AbsolutePath;
use nah_proto::observation::{ObservationFailure, Observed, PathKind, PathObservation};
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

pub(crate) fn observe_path(cwd: &AbsolutePath, requested: &str) -> Observed<PathObservation> {
    let requested = Path::new(requested);
    let resolved = if requested.is_absolute() {
        requested.to_path_buf()
    } else {
        Path::new(cwd.as_str()).join(requested)
    };
    match has_reparse_ancestor(&resolved) {
        Ok(true) => {
            return Observed::Error {
                error: ObservationFailure::Unavailable,
            };
        }
        Ok(false) => {}
        Err(error) => return Observed::Error { error },
    }
    let resolved_absolute = match entry_path(&resolved) {
        Ok(value) => value,
        Err(error) => return Observed::Error { error },
    };

    match fs::symlink_metadata(&resolved) {
        Ok(metadata) => {
            let kind = path_kind(&metadata);
            let (realpath, target_kind) = match fs::canonicalize(&resolved) {
                Ok(path) => {
                    let target_metadata = match fs::metadata(&path) {
                        Ok(metadata) => metadata,
                        Err(error) => {
                            return Observed::Error {
                                error: map_io_error(&error),
                            };
                        }
                    };
                    if target_metadata.file_type().is_file() {
                        match has_multiple_links(&path, &target_metadata) {
                            Ok(false) => {}
                            Ok(true) => {
                                return Observed::Error {
                                    error: ObservationFailure::Unavailable,
                                };
                            }
                            Err(error) => return Observed::Error { error },
                        }
                    }
                    match absolute_from_path(&path) {
                        Ok(path) => (
                            Some(path),
                            (kind == PathKind::Symlink).then(|| path_kind(&target_metadata)),
                        ),
                        Err(error) => return Observed::Error { error },
                    }
                }
                Err(error)
                    if kind == PathKind::Symlink && error.kind() == io::ErrorKind::NotFound =>
                {
                    let target = match fs::read_link(&resolved) {
                        Ok(target) if target.is_absolute() => Ok(target),
                        Ok(target) => resolved
                            .parent()
                            .ok_or(ObservationFailure::InvalidPath)
                            .map(|parent| parent.join(target)),
                        Err(error) => Err(map_io_error(&error)),
                    };
                    match target.and_then(|target| missing_realpath(&target)) {
                        Ok(path) => (Some(path), None),
                        Err(error) => return Observed::Error { error },
                    }
                }
                Err(error) => {
                    return Observed::Error {
                        error: map_io_error(&error),
                    };
                }
            };
            let mut value = PathObservation::new(resolved_absolute, realpath, kind);
            if let Some(target_kind) = target_kind {
                value = value.with_target_kind(target_kind);
            }
            Observed::Ok { value }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let realpath = match missing_realpath(&resolved) {
                Ok(value) => value,
                Err(error) => return Observed::Error { error },
            };
            Observed::Ok {
                value: PathObservation::new(resolved_absolute, Some(realpath), PathKind::Missing),
            }
        }
        Err(error) => Observed::Error {
            error: map_io_error(&error),
        },
    }
}

fn entry_path(path: &Path) -> Result<AbsolutePath, ObservationFailure> {
    let Some(name) = path.file_name() else {
        return fs::canonicalize(path)
            .map_err(|error| map_io_error(&error))
            .and_then(|path| absolute_from_path(&path));
    };
    let parent = path.parent().ok_or(ObservationFailure::InvalidPath)?;
    let parent = match fs::canonicalize(parent) {
        Ok(parent) => absolute_from_path(&parent)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => missing_realpath(parent)?,
        Err(error) => return Err(map_io_error(&error)),
    };
    absolute_from_path(&Path::new(parent.as_str()).join(name))
}

#[cfg(unix)]
pub(crate) fn has_multiple_links(
    _path: &Path,
    metadata: &fs::Metadata,
) -> Result<bool, ObservationFailure> {
    use std::os::unix::fs::MetadataExt;
    Ok(metadata.nlink() > 1)
}

#[cfg(windows)]
pub(crate) fn has_multiple_links(
    path: &Path,
    _metadata: &fs::Metadata,
) -> Result<bool, ObservationFailure> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };

    let file = fs::File::open(path).map_err(|error| map_io_error(&error))?;
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // The file owns this valid handle for the duration of the call, and the
    // output pointer refers to an initialized value of the required type.
    let succeeded =
        unsafe { GetFileInformationByHandle(file.as_raw_handle().cast(), &mut information) };
    if succeeded == 0 {
        return Err(map_io_error(&io::Error::last_os_error()));
    }
    Ok(information.nNumberOfLinks > 1)
}

// wasm (homepage demo) never observes a real filesystem; fulfillment there
// reports the fact as unavailable rather than guessing
#[cfg(not(any(unix, windows)))]
pub(crate) fn has_multiple_links(
    _path: &Path,
    _metadata: &fs::Metadata,
) -> Result<bool, ObservationFailure> {
    Err(ObservationFailure::Unavailable)
}

fn missing_realpath(path: &Path) -> Result<AbsolutePath, ObservationFailure> {
    missing_realpath_with_depth(path, 0)
}

fn missing_realpath_with_depth(
    path: &Path,
    depth: usize,
) -> Result<AbsolutePath, ObservationFailure> {
    if depth >= 40 {
        return Err(ObservationFailure::InvalidPath);
    }
    let mut ancestor = path;
    loop {
        match fs::canonicalize(ancestor) {
            Ok(real_ancestor) => {
                let suffix = path
                    .strip_prefix(ancestor)
                    .map_err(|_| ObservationFailure::InvalidPath)?;
                return absolute_from_path(&lexically_normalize(&real_ancestor.join(suffix)));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if fs::symlink_metadata(ancestor)
                    .is_ok_and(|metadata| metadata.file_type().is_symlink())
                {
                    let link = fs::read_link(ancestor).map_err(|error| map_io_error(&error))?;
                    let target = if link.is_absolute() {
                        link
                    } else {
                        ancestor
                            .parent()
                            .ok_or(ObservationFailure::InvalidPath)?
                            .join(link)
                    };
                    let real_target = missing_realpath_with_depth(&target, depth + 1)?;
                    let suffix = path
                        .strip_prefix(ancestor)
                        .map_err(|_| ObservationFailure::InvalidPath)?;
                    return absolute_from_path(&lexically_normalize(
                        &Path::new(real_target.as_str()).join(suffix),
                    ));
                }
                ancestor = ancestor.parent().ok_or(ObservationFailure::InvalidPath)?;
            }
            Err(error) => return Err(map_io_error(&error)),
        }
    }
}

fn lexically_normalize(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}

fn path_kind(metadata: &fs::Metadata) -> PathKind {
    let file_type = metadata.file_type();
    if is_reparse_point(metadata) || file_type.is_symlink() {
        PathKind::Symlink
    } else if file_type.is_file() {
        PathKind::File
    } else if file_type.is_dir() {
        PathKind::Directory
    } else if is_fifo(&file_type) {
        PathKind::Fifo
    } else {
        PathKind::Other
    }
}

#[cfg(unix)]
fn is_fifo(file_type: &fs::FileType) -> bool {
    use std::os::unix::fs::FileTypeExt;
    file_type.is_fifo()
}

#[cfg(not(unix))]
fn is_fifo(_file_type: &fs::FileType) -> bool {
    false
}
