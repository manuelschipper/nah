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

/// Cargo's own record of which binaries each installed package owns, written
/// and rewritten by `cargo install` and `cargo uninstall` in the install root
/// they act on. It describes Cargo's own bookkeeping, not a user's content.
pub const CARGO_INSTALL_REGISTRY: &str = ".crates2.json";

/// Whether a canonical path is the one file admitted from outside the
/// invocation's own root.
///
/// It matches on the file name alone, because the install root is whichever
/// one the request already resolved — `--root`, `CARGO_INSTALL_ROOT`,
/// `CARGO_HOME`, or `$HOME/.cargo`. No other entry beside it is admitted, so
/// this opens one named file, not a second root.
fn admitted_beside_root(path: &Path) -> bool {
    path.file_name()
        .is_some_and(|name| name == CARGO_INSTALL_REGISTRY)
}

/// Read the current bytes of `requested`, resolved against `root` and admitted
/// only when its canonical identity stays inside `root` or is the Cargo
/// install registry named above. The read is demand-driven: it opens exactly
/// one file and never lists a directory, walks a tree, or executes anything.
///
/// `max_bytes` limits the contents this returns, not how much is read: the
/// file's size is checked before a whole-file read and the bytes again after
/// it, so a file that grows in between is read in full and then rejected as
/// `TooLarge`.
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
    if !path.starts_with(&canonical_root) && !admitted_beside_root(&path) {
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
    // A file that grew between the size check and the read was read in full;
    // reject it here so the returned contents stay within `max_bytes`.
    if bytes.len() as u64 > max_bytes {
        return Err(SourceFileUnavailable::TooLarge);
    }
    Ok(ObservedSourceFile { path, bytes })
}

/// List the entries directly inside the directory `requested` names, resolved
/// against `root` and admitted only when its canonical identity stays inside
/// `root`.
///
/// It observes exactly that one directory: entry names only, never their bytes,
/// never a nested directory, and no link followed beyond the canonicalization a
/// byte read already performs. The Cargo install registry `observe_source_file`
/// admits beside the root opens one named file rather than a second root, so no
/// directory outside `root` is listed. An error or a directory wider than the
/// bound leaves the listing unproven instead of partial.
pub fn observe_source_directory(
    root: &AbsolutePath,
    requested: &str,
) -> Result<Vec<AbsolutePath>, SourceFileUnavailable> {
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
    let directory =
        fs::canonicalize(&resolved).map_err(|error| unavailable(map_io_error(&error)))?;
    if !directory.starts_with(&canonical_root) {
        return Err(SourceFileUnavailable::Escaped);
    }
    let metadata = fs::metadata(&directory).map_err(|error| unavailable(map_io_error(&error)))?;
    // A listing needs a directory, exactly as a byte read needs a regular file.
    if !metadata.file_type().is_dir() {
        return Err(SourceFileUnavailable::NotAFile);
    }
    let mut entries = Vec::new();
    for entry in fs::read_dir(&directory).map_err(|error| unavailable(map_io_error(&error)))? {
        if entries.len() >= DIRECTORY_ENTRY_LIMIT {
            return Err(SourceFileUnavailable::TooLarge);
        }
        let entry = entry.map_err(|error| unavailable(map_io_error(&error)))?;
        entries.push(absolute_from_path(&directory.join(entry.file_name())).map_err(unavailable)?);
    }
    // Directory order is not stable across hosts; one identity needs one answer.
    entries.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    Ok(entries)
}

/// Bounded directory entries one demand may observe before the answer is unproven.
const DIRECTORY_ENTRY_LIMIT: usize = 256;

/// Whether the directory holding `requested` demonstrably contains no native
/// extension that could be imported in place of that module stem.
///
/// It observes exactly that one directory, never a tree, and answers false
/// whenever the observation is incomplete: a missing observation is not proof
/// that a native extension is absent. `is_candidate(name, stem)` is the
/// engine protocol's naming rule, supplied by the caller because this crate
/// does not link the engine.
pub fn native_extension_candidates_absent(
    root: &AbsolutePath,
    requested: &str,
    is_candidate: fn(&str, &str) -> bool,
) -> bool {
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
        if index >= DIRECTORY_ENTRY_LIMIT {
            return false;
        }
        let Ok(entry) = entry else {
            return false;
        };
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return false;
        };
        if is_candidate(name, stem) {
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

    #[cfg(unix)]
    #[test]
    fn a_listed_directory_serves_sorted_entry_names_only_inside_the_root() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("variables.tf"), b"variable \"a\" {}\n").unwrap();
        fs::write(dir.path().join("main.tf"), b"resource \"t\" \"n\" {}\n").unwrap();
        fs::create_dir(dir.path().join("modules")).unwrap();
        fs::write(dir.path().join("modules/nested.tf"), b"# nested\n").unwrap();
        let root = cwd(dir.path());
        let entries = observe_source_directory(&root, ".").unwrap();
        let names = entries
            .iter()
            .map(|entry| {
                entry
                    .as_str()
                    .strip_prefix(root.as_str())
                    .unwrap()
                    .to_owned()
            })
            .collect::<Vec<_>>();
        // Sorted direct entries, with the nested file left to its own demand.
        assert_eq!(names, ["/main.tf", "/modules", "/variables.tf"]);
        assert_eq!(
            observe_source_directory(&root, "main.tf").err().unwrap(),
            SourceFileUnavailable::NotAFile
        );
        assert_eq!(
            observe_source_directory(&root, "absent").err().unwrap(),
            SourceFileUnavailable::Missing
        );
        // A link out of the root lists nothing, and neither does the install
        // root the one admitted registry file sits in.
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join(CARGO_INSTALL_REGISTRY), b"{}").unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join("escape")).unwrap();
        for path in [dir.path().join("escape"), outside.path().to_path_buf()] {
            assert_eq!(
                observe_source_directory(&root, path.to_str().unwrap())
                    .err()
                    .unwrap(),
                SourceFileUnavailable::Escaped
            );
        }
    }

    #[test]
    fn a_directory_wider_than_the_bound_stays_unproven() {
        let dir = tempfile::tempdir().unwrap();
        for index in 0..=DIRECTORY_ENTRY_LIMIT {
            fs::write(dir.path().join(format!("f{index}.tf")), b"").unwrap();
        }
        assert_eq!(
            observe_source_directory(&cwd(dir.path()), ".")
                .err()
                .unwrap(),
            SourceFileUnavailable::TooLarge
        );
    }

    #[test]
    fn only_the_cargo_install_registry_is_admitted_outside_the_root() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("in.py"), b"import os\n").unwrap();
        let root = cwd(dir.path());
        let install_root = tempfile::tempdir().unwrap();
        fs::write(
            install_root.path().join(CARGO_INSTALL_REGISTRY),
            b"{\"installs\":{}}",
        )
        .unwrap();
        fs::write(install_root.path().join("credentials.toml"), b"token\n").unwrap();
        let registry = install_root.path().join(CARGO_INSTALL_REGISTRY);
        let observed = observe_source_file(&root, registry.to_str().unwrap(), 1024).unwrap();
        assert_eq!(observed.bytes, b"{\"installs\":{}}");
        let neighbour = install_root.path().join("credentials.toml");
        assert_eq!(
            observe_source_file(&root, neighbour.to_str().unwrap(), 1024)
                .err()
                .unwrap(),
            SourceFileUnavailable::Escaped
        );
    }
}
