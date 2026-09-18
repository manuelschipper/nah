//! Observes the current bytes of demanded source files.

use crate::io_paths::{absolute_from_path, has_reparse_ancestor, map_io_error};
use crate::path_facts::has_multiple_links;
use nah_proto::ctx::AbsolutePath;
use nah_proto::observation::ObservationFailure;
use std::fs;
use std::io;
use std::path::Path;

/// One demanded source file: the canonical identity the bytes came from, and
/// exactly the bytes present at that identity when it was read.
pub struct ObservedSourceFile {
    pub path: AbsolutePath,
    pub bytes: Vec<u8>,
}

/// Why a demanded source file yielded no bytes. Each reason is host evidence,
/// never a policy verdict.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceFileUnavailable {
    Missing,
    NotAFile,
    /// The bytes live outside the admitted root, directly or through a link.
    Escaped,
    /// The requested path does not identify the bytes on its own: the file has
    /// more than one link, or an ancestor reparse point redirects the path.
    Ambiguous,
    Denied,
    TooLarge,
    Unavailable,
}

/// Read the current bytes of `requested`, resolved against `root` and admitted
/// only when its canonical identity stays inside `root`. The read is
/// demand-driven: it opens exactly one file and never lists a directory, walks
/// a tree, or executes anything.
pub fn observe_source_file(
    root: &AbsolutePath,
    requested: &str,
    max_bytes: u64,
) -> Result<ObservedSourceFile, SourceFileUnavailable> {
    let canonical_root =
        fs::canonicalize(root.as_str()).map_err(|error| unavailable(map_io_error(&error)))?;
    let requested = Path::new(requested);
    let resolved = if requested.is_absolute() {
        requested.to_path_buf()
    } else {
        Path::new(root.as_str()).join(requested)
    };
    match has_reparse_ancestor(&resolved) {
        Ok(true) => return Err(SourceFileUnavailable::Ambiguous),
        Ok(false) => {}
        Err(error) => return Err(unavailable(error)),
    }
    let path = fs::canonicalize(&resolved).map_err(|error| unavailable(map_io_error(&error)))?;
    if !path.starts_with(&canonical_root) {
        return Err(SourceFileUnavailable::Escaped);
    }
    let metadata = fs::metadata(&path).map_err(|error| unavailable(map_io_error(&error)))?;
    if !metadata.file_type().is_file() {
        return Err(SourceFileUnavailable::NotAFile);
    }
    match has_multiple_links(&path, &metadata) {
        Ok(false) => {}
        Ok(true) => return Err(SourceFileUnavailable::Ambiguous),
        Err(error) => return Err(unavailable(error)),
    }
    if metadata.len() > max_bytes {
        return Err(SourceFileUnavailable::TooLarge);
    }
    let path = absolute_from_path(&path).map_err(unavailable)?;
    let bytes = fs::read(path.as_str()).map_err(|error| unavailable(map_io_error(&error)))?;
    // A file that grew between the size check and the read stays bounded.
    if bytes.len() as u64 > max_bytes {
        return Err(SourceFileUnavailable::TooLarge);
    }
    Ok(ObservedSourceFile { path, bytes })
}

/// Native-extension file endings a Python import can select ahead of source.
const NATIVE_EXTENSION_ENDINGS: [&str; 4] = [".so", ".pyd", ".dll", ".dylib"];

/// Bounded directory entries one demand may observe before the answer is unproven.
const NATIVE_CANDIDATE_ENTRIES: usize = 256;

/// Whether the directory holding `requested` demonstrably contains no native
/// extension that could be imported in place of that module stem.
///
/// It observes exactly that one directory, never a tree, and answers false
/// whenever the observation is incomplete: a missing observation is not proof
/// that a native extension is absent.
pub fn native_extension_candidates_absent(root: &AbsolutePath, requested: &str) -> bool {
    let requested = Path::new(requested);
    let Some(stem) = requested.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let Ok(canonical_root) = fs::canonicalize(root.as_str()) else {
        return false;
    };
    let parent = if requested.is_absolute() {
        requested.parent().map(Path::to_path_buf)
    } else {
        Some(Path::new(root.as_str()).join(requested.parent().unwrap_or(Path::new(""))))
    };
    let Some(parent) = parent else {
        return false;
    };
    let directory = match fs::canonicalize(&parent) {
        Ok(directory) => directory,
        // A directory that does not exist holds no candidate.
        Err(error) if error.kind() == io::ErrorKind::NotFound => return true,
        Err(_) => return false,
    };
    if !directory.starts_with(&canonical_root) {
        return false;
    }
    let Ok(entries) = fs::read_dir(&directory) else {
        return false;
    };
    for (index, entry) in entries.enumerate() {
        if index >= NATIVE_CANDIDATE_ENTRIES {
            return false;
        }
        let Ok(entry) = entry else {
            return false;
        };
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return false;
        };
        if name.strip_prefix(stem).is_some_and(|suffix| {
            suffix.starts_with('.')
                && NATIVE_EXTENSION_ENDINGS
                    .iter()
                    .any(|ending| suffix.ends_with(ending))
        }) {
            return false;
        }
    }
    true
}

fn unavailable(error: ObservationFailure) -> SourceFileUnavailable {
    match error {
        ObservationFailure::NotFound => SourceFileUnavailable::Missing,
        ObservationFailure::PermissionDenied => SourceFileUnavailable::Denied,
        ObservationFailure::InvalidPath | ObservationFailure::NonUnicode => {
            SourceFileUnavailable::Ambiguous
        }
        ObservationFailure::Timeout | ObservationFailure::Unavailable => {
            SourceFileUnavailable::Unavailable
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cwd(dir: &std::path::Path) -> AbsolutePath {
        absolute_from_path(&fs::canonicalize(dir).unwrap()).unwrap()
    }

    #[test]
    fn a_demanded_file_reads_its_current_bytes_and_a_missing_one_stays_explicit() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("cleanup.py"), b"import shutil\n").unwrap();
        let root = cwd(dir.path());
        let observed = observe_source_file(&root, "cleanup.py", 1024).unwrap();
        assert_eq!(observed.bytes, b"import shutil\n");
        assert!(observed.path.as_str().ends_with("cleanup.py"));
        assert_eq!(
            observe_source_file(&root, "absent.py", 1024).err().unwrap(),
            SourceFileUnavailable::Missing
        );
        assert_eq!(
            observe_source_file(&root, ".", 1024).err().unwrap(),
            SourceFileUnavailable::NotAFile
        );
        fs::write(dir.path().join("big.py"), b"0123456789").unwrap();
        assert_eq!(
            observe_source_file(&root, "big.py", 4).err().unwrap(),
            SourceFileUnavailable::TooLarge
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_source_reports_its_canonical_identity_and_extra_links_stay_ambiguous() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("helper.py"), b"import os\n").unwrap();
        std::os::unix::fs::symlink(dir.path().join("helper.py"), dir.path().join("link.py"))
            .unwrap();
        let root = cwd(dir.path());
        let observed = observe_source_file(&root, "link.py", 1024).unwrap();
        assert_eq!(observed.bytes, b"import os\n");
        assert!(observed.path.as_str().ends_with("helper.py"));
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("secret.py"), b"token\n").unwrap();
        std::os::unix::fs::symlink(
            outside.path().join("secret.py"),
            dir.path().join("escape.py"),
        )
        .unwrap();
        assert_eq!(
            observe_source_file(&root, "escape.py", 1024).err().unwrap(),
            SourceFileUnavailable::Escaped
        );
        fs::hard_link(dir.path().join("helper.py"), dir.path().join("hard.py")).unwrap();
        assert_eq!(
            observe_source_file(&root, "helper.py", 1024).err().unwrap(),
            SourceFileUnavailable::Ambiguous
        );
    }
}
