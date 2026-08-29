//! Discovers validated Git project and linked-worktree roots.

use crate::io_paths::{canonical_absolute, has_reparse_ancestor, is_reparse_point, map_io_error};
use nah_proto::ctx::AbsolutePath;
use nah_proto::observation::{ObservationFailure, Observed, Root, RootKind};
use std::ffi::OsStr;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;
#[cfg(not(target_arch = "wasm32"))]
use wait_timeout::ChildExt;

// wasm has no subprocesses: spawn fails before a wait can happen, so this
// shim exists only to satisfy the homepage demo's wasm32 build
#[cfg(target_arch = "wasm32")]
trait ChildExt {
    fn wait_timeout(
        &mut self,
        timeout: Duration,
    ) -> std::io::Result<Option<std::process::ExitStatus>>;
}
#[cfg(target_arch = "wasm32")]
impl ChildExt for std::process::Child {
    fn wait_timeout(
        &mut self,
        _timeout: Duration,
    ) -> std::io::Result<Option<std::process::ExitStatus>> {
        unreachable!("wasm cannot spawn the child this waits on")
    }
}

const GIT_POINTER_MAX_BYTES: u64 = 4 * 1024;

pub(crate) fn discover_roots(
    cwd: &AbsolutePath,
    git: &Path,
    timeout: Duration,
) -> Observed<Vec<Root>> {
    match has_reparse_ancestor(Path::new(cwd.as_str())) {
        Ok(true) => {
            return Observed::Error {
                error: ObservationFailure::Unavailable,
            };
        }
        Ok(false) => {}
        Err(error) => return Observed::Error { error },
    }
    let marker_root = match find_git_marker(Path::new(cwd.as_str())) {
        Ok(Some(marker_root)) => marker_root,
        Ok(None) => return Observed::Ok { value: vec![] },
        Err(error) => return Observed::Error { error },
    };
    let marker_root = match canonical_absolute(marker_root) {
        Ok(value) => value,
        Err(error) => return Observed::Error { error },
    };
    let project_text = match git_rev_parse(git, cwd.as_str(), "--show-toplevel", timeout) {
        Ok(value) => value,
        Err(error) => {
            return Observed::Error {
                error: error.observation_failure(),
            };
        }
    };
    let common_text = match git_rev_parse(git, cwd.as_str(), "--git-common-dir", timeout) {
        Ok(value) => value,
        Err(error) => {
            return Observed::Error {
                error: error.observation_failure(),
            };
        }
    };

    if !Path::new(&project_text).is_absolute() {
        return Observed::Error {
            error: ObservationFailure::InvalidPath,
        };
    }
    let project = match canonical_absolute(Path::new(&project_text)) {
        Ok(value) => value,
        Err(error) => return Observed::Error { error },
    };
    if project != marker_root {
        return Observed::Error {
            error: ObservationFailure::InvalidPath,
        };
    }
    let common_path = if Path::new(&common_text).is_absolute() {
        PathBuf::from(common_text)
    } else {
        Path::new(cwd.as_str()).join(common_text)
    };
    let common = match fs::canonicalize(common_path) {
        Ok(value) => value,
        Err(error) => {
            return Observed::Error {
                error: map_io_error(&error),
            };
        }
    };
    let mut roots = vec![Root::new(RootKind::Project, project.clone())];
    match validated_worktree_main(Path::new(project.as_str()), &common) {
        Ok(Some(main)) if main != project => {
            roots.push(Root::new(RootKind::WorktreeMain, main));
        }
        Ok(_) => {}
        Err(error) => return Observed::Error { error },
    }
    Observed::Ok { value: roots }
}

fn git_rev_parse(
    git: &Path,
    cwd: &str,
    query: &str,
    timeout: Duration,
) -> Result<String, GitError> {
    let mut command = Command::new(git);
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("GIT_") {
            command.env_remove(name);
        }
    }
    let mut child = command
        .args([
            OsStr::new("-C"),
            OsStr::new(cwd),
            OsStr::new("rev-parse"),
            OsStr::new(query),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| GitError::Observation(ObservationFailure::Unavailable))?;

    match child
        .wait_timeout(timeout)
        .map_err(|_| GitError::Observation(ObservationFailure::Unavailable))?
    {
        None => {
            let _ = child.kill();
            let _ = child.wait();
            Err(GitError::Observation(ObservationFailure::Timeout))
        }
        Some(status) if !status.success() => Err(GitError::Nonzero),
        Some(_) => {
            let output = child
                .wait_with_output()
                .map_err(|_| GitError::Observation(ObservationFailure::Unavailable))?;
            let text = String::from_utf8(output.stdout)
                .map_err(|_| GitError::Observation(ObservationFailure::NonUnicode))?;
            let value = text.trim_end_matches(['\r', '\n']);
            if value.is_empty() || value.contains(['\r', '\n']) {
                Err(GitError::Observation(ObservationFailure::Unavailable))
            } else {
                Ok(value.to_owned())
            }
        }
    }
}

enum GitError {
    Nonzero,
    Observation(ObservationFailure),
}

impl GitError {
    fn observation_failure(self) -> ObservationFailure {
        match self {
            Self::Nonzero => ObservationFailure::Unavailable,
            Self::Observation(error) => error,
        }
    }
}

fn find_git_marker(cwd: &Path) -> Result<Option<&Path>, ObservationFailure> {
    for ancestor in cwd.ancestors() {
        let marker = ancestor.join(".git");
        let metadata = match fs::symlink_metadata(&marker) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(map_io_error(&error)),
        };
        if is_reparse_point(&metadata) {
            return Err(ObservationFailure::Unavailable);
        }
        if metadata.file_type().is_file()
            || (metadata.file_type().is_dir()
                && fs::symlink_metadata(marker.join("HEAD"))
                    .is_ok_and(|metadata| !is_reparse_point(&metadata)))
        {
            return Ok(Some(ancestor));
        }
    }
    Ok(None)
}

fn validated_worktree_main(
    project: &Path,
    common: &Path,
) -> Result<Option<AbsolutePath>, ObservationFailure> {
    let marker = project.join(".git");
    let metadata = fs::symlink_metadata(&marker).map_err(|error| map_io_error(&error))?;
    if is_reparse_point(&metadata) {
        return Err(ObservationFailure::Unavailable);
    }
    if metadata.file_type().is_dir() {
        let marker = fs::canonicalize(marker).map_err(|error| map_io_error(&error))?;
        return if marker == common {
            Ok(None)
        } else {
            Err(ObservationFailure::InvalidPath)
        };
    }
    if !metadata.file_type().is_file() {
        return Err(ObservationFailure::InvalidPath);
    }

    let pointer = read_small_regular(&marker, GIT_POINTER_MAX_BYTES)?;
    let gitdir = pointer
        .trim()
        .strip_prefix("gitdir:")
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or(ObservationFailure::InvalidPath)?;
    let gitdir = if Path::new(gitdir).is_absolute() {
        PathBuf::from(gitdir)
    } else {
        project.join(gitdir)
    };
    let gitdir = fs::canonicalize(gitdir).map_err(|error| map_io_error(&error))?;
    let commondir_path = gitdir.join("commondir");
    let expected_common = match fs::symlink_metadata(&commondir_path) {
        Ok(metadata) if metadata.file_type().is_file() => {
            let value = read_small_regular(&commondir_path, GIT_POINTER_MAX_BYTES)?;
            let value = value.trim();
            if value.is_empty() {
                return Err(ObservationFailure::InvalidPath);
            }
            let value = if Path::new(value).is_absolute() {
                PathBuf::from(value)
            } else {
                gitdir.join(value)
            };
            fs::canonicalize(value).map_err(|error| map_io_error(&error))?
        }
        Ok(_) => return Err(ObservationFailure::InvalidPath),
        Err(error) if error.kind() == io::ErrorKind::NotFound => gitdir.clone(),
        Err(error) => return Err(map_io_error(&error)),
    };
    if expected_common != common {
        return Err(ObservationFailure::InvalidPath);
    }

    let worktrees = common.join("worktrees");
    let worktrees = match fs::canonicalize(worktrees) {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };
    if gitdir.parent() != Some(worktrees.as_path())
        || common.file_name() != Some(OsStr::new(".git"))
    {
        return Ok(None);
    }
    let back_pointer = read_small_regular(&gitdir.join("gitdir"), GIT_POINTER_MAX_BYTES)?;
    let back_pointer = back_pointer.trim();
    if back_pointer.is_empty() {
        return Err(ObservationFailure::InvalidPath);
    }
    let back_pointer = if Path::new(back_pointer).is_absolute() {
        PathBuf::from(back_pointer)
    } else {
        gitdir.join(back_pointer)
    };
    let back_pointer = fs::canonicalize(back_pointer).map_err(|error| map_io_error(&error))?;
    let marker = fs::canonicalize(marker).map_err(|error| map_io_error(&error))?;
    if back_pointer != marker {
        return Err(ObservationFailure::InvalidPath);
    }
    let main = common.parent().ok_or(ObservationFailure::InvalidPath)?;
    canonical_absolute(main).map(Some)
}

fn read_small_regular(path: &Path, max_bytes: u64) -> Result<String, ObservationFailure> {
    let metadata = fs::symlink_metadata(path).map_err(|error| map_io_error(&error))?;
    if is_reparse_point(&metadata) || !metadata.file_type().is_file() || metadata.len() > max_bytes
    {
        return Err(ObservationFailure::InvalidPath);
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    fs::File::open(path)
        .and_then(|file| file.take(max_bytes + 1).read_to_end(&mut bytes))
        .map_err(|error| map_io_error(&error))?;
    if bytes.len() as u64 > max_bytes {
        return Err(ObservationFailure::InvalidPath);
    }
    String::from_utf8(bytes).map_err(|_| ObservationFailure::NonUnicode)
}
