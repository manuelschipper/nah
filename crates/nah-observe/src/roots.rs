//! Discovers validated Git project and linked-worktree roots.

use crate::git_state::git_exit_and_output;
use crate::io_paths::{canonical_absolute, has_reparse_ancestor, is_reparse_point, map_io_error};
use nah_proto::ctx::AbsolutePath;
use nah_proto::observation::{ObservationFailure, Observed, Root, RootKind};
use std::ffi::OsStr;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};
#[cfg(not(target_arch = "wasm32"))]
pub(crate) use wait_timeout::ChildExt;

// wasm has no subprocesses: spawn fails before a wait can happen, so this
// shim exists only to satisfy the homepage demo's wasm32 build
#[cfg(target_arch = "wasm32")]
pub(crate) trait ChildExt {
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

/// Most bytes of the two paths `rev-parse` prints.
const REV_PARSE_MAX_BYTES: u64 = 64 * 1024;

/// Most bytes of a repository `config` read when deciding a root without git.
#[cfg(unix)]
const GIT_CONFIG_MAX_BYTES: u64 = 64 * 1024;

/// How long observation waits for one git child: the per-spawn limit, cut
/// short at the deadline of the decision the observation serves.
#[derive(Clone, Copy, Debug)]
pub(crate) struct GitWait {
    pub(crate) per_spawn: Duration,
    pub(crate) deadline: Option<Instant>,
}

impl GitWait {
    pub(crate) fn per_spawn(per_spawn: Duration) -> Self {
        Self {
            per_spawn,
            deadline: None,
        }
    }

    /// How long a child started now may run.
    pub(crate) fn timeout(self) -> Duration {
        self.deadline.map_or(self.per_spawn, |deadline| {
            self.per_spawn
                .min(deadline.saturating_duration_since(Instant::now()))
        })
    }
}

pub(crate) fn discover_roots(cwd: &AbsolutePath, git: &Path, wait: GitWait) -> Observed<Vec<Root>> {
    match has_reparse_ancestor(Path::new(cwd.as_str())) {
        Ok(true) => {
            return Observed::Error {
                error: ObservationFailure::Unavailable,
            };
        }
        Ok(false) => {}
        Err(error) => return Observed::Error { error },
    }
    let (project, common) = match locate_repository(Path::new(cwd.as_str()), git, wait) {
        Ok(Some(located)) => located,
        Ok(None) => return Observed::Ok { value: vec![] },
        Err(error) => return Observed::Error { error },
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

/// The canonical work tree top level of the repository Git finds from
/// `directory`, and its canonical common git directory; `None` where no
/// `.git` lies at or above `directory`.
///
/// The nearest `.git` names the repository. A `.git` directory
/// `plain_directory_repository` takes, with its parent as the work tree, is
/// answered without Git. Anything else, a `.git` file included, is asked
/// of Git in one call, and Git's top level must be where that `.git` lies.
pub(crate) fn locate_repository(
    directory: &Path,
    git: &Path,
    wait: GitWait,
) -> Result<Option<(AbsolutePath, PathBuf)>, ObservationFailure> {
    let Some(marker_root) = find_git_marker(directory)? else {
        return Ok(None);
    };
    let top_level = canonical_absolute(marker_root)?;
    #[cfg(unix)]
    {
        // SAFETY: `geteuid` has no preconditions and cannot fail.
        let owner = unsafe { libc::geteuid() };
        if plain_directory_repository(directory, marker_root, owner) {
            let common =
                fs::canonicalize(marker_root.join(".git")).map_err(|error| map_io_error(&error))?;
            return Ok(Some((top_level, common)));
        }
    }
    let (project_text, common_text) = git_top_level_and_common_dir(git, directory, wait)?;
    if !Path::new(&project_text).is_absolute() {
        return Err(ObservationFailure::InvalidPath);
    }
    if canonical_absolute(Path::new(&project_text))? != top_level {
        return Err(ObservationFailure::InvalidPath);
    }
    let common =
        fs::canonicalize(directory.join(common_text)).map_err(|error| map_io_error(&error))?;
    Ok(Some((top_level, common)))
}

/// Whether the `.git` directory in `root` is taken, from the filesystem alone
/// and without running Git, as the repository for `directory`, with `root`
/// its work tree. It is taken only when it passes Git's minimum repository
/// check, `owner`, the effective user, owns it, Git would find it from
/// `directory`, and its `config` leaves the work tree beside it. Anything
/// else answers false and leaves the question to Git:
///
/// - climbing from `directory` across a filesystem boundary, or past a
///   directory that may itself be a repository (one holding `HEAD`);
/// - a `.git` without a `HEAD` that names a branch or commit within the
///   bytes Git reads, or without `objects` and `refs` directories this
///   process may search (Git skips such a `.git` and climbs on);
/// - a `.git` whose `commondir` borrows another repository;
/// - a work tree or `.git` that `owner` does not own;
/// - a `config` that `config_keeps_work_tree` does not accept: one setting
///   `core.worktree` or a true `core.bare`, naming an extension or include,
///   or holding a line it does not fully understand.
///
/// True does not promise that Git would accept the repository. Git also
/// refuses one for reasons that leave its work tree where it is, such as an
/// invalid value of an unrelated setting (`core.filemode = invalid`) or a
/// malformed global configuration, and this still answers true. That is
/// deliberate: the directory is still the user's project, and recognizing it
/// keeps project-scope guards on. It is safe because the only root this
/// yields is `root`, the directory holding `.git`, so taking a repository
/// Git would refuse never widens a root beyond it.
///
/// Links are not followed: a linked `HEAD`, `objects` or `refs` leaves the
/// question to Git.
#[cfg(unix)]
pub(crate) fn plain_directory_repository(directory: &Path, root: &Path, owner: u32) -> bool {
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::MetadataExt;

    let absent = |path: &Path| {
        fs::symlink_metadata(path).is_err_and(|error| error.kind() == io::ErrorKind::NotFound)
    };
    let Ok(device) = fs::symlink_metadata(directory).map(|metadata| metadata.dev()) else {
        return false;
    };
    for ancestor in directory.ancestors() {
        if !fs::symlink_metadata(ancestor).is_ok_and(|metadata| metadata.dev() == device) {
            return false;
        }
        if ancestor == root {
            break;
        }
        if !absent(&ancestor.join("HEAD")) {
            return false;
        }
    }
    let git_dir = root.join(".git");
    let owned =
        |path: &Path| fs::symlink_metadata(path).is_ok_and(|metadata| metadata.uid() == owner);
    // Git checks a repository directory with `access(X_OK)`, as here.
    let directory_entry = |name: &str| {
        let path = git_dir.join(name);
        fs::symlink_metadata(&path).is_ok_and(|metadata| metadata.is_dir())
            && std::ffi::CString::new(path.into_os_string().into_vec()).is_ok_and(|path| {
                // SAFETY: `path` is a NUL-terminated string that outlives the call.
                unsafe { libc::access(path.as_ptr(), libc::X_OK) == 0 }
            })
    };
    let config = git_dir.join("config");
    owned(root)
        && owned(&git_dir)
        && directory_entry("objects")
        && directory_entry("refs")
        && absent(&git_dir.join("commondir"))
        && read_small_regular(&git_dir.join("HEAD"), GIT_POINTER_MAX_BYTES)
            .is_ok_and(|head| names_branch_or_commit(&head))
        && (absent(&config)
            || read_small_regular(&config, GIT_CONFIG_MAX_BYTES)
                .is_ok_and(|text| config_keeps_work_tree(&text)))
}

/// Whether a `HEAD` file holds what Git requires of one: `ref: refs/...`, or
/// a commit id, within the first 255 bytes, which are all Git reads.
#[cfg(unix)]
fn names_branch_or_commit(head: &str) -> bool {
    let head = &head.as_bytes()[..head.len().min(255)];
    match head.strip_prefix(b"ref:") {
        // Git skips only ASCII space, tab and line endings here.
        Some(target) => {
            let skipped = target
                .iter()
                .take_while(|byte| matches!(byte, b' ' | b'\t' | b'\n' | b'\r'))
                .count();
            target[skipped..].starts_with(b"refs/")
        }
        None => head
            .get(..40)
            .is_some_and(|id| id.iter().all(u8::is_ascii_hexdigit)),
    }
}

/// Whether a repository `config`, read as Git reads it to set up a
/// repository, leaves the work tree beside `.git`: no `core.worktree`, no
/// true `core.bare`, format version 0 or 1, and no extension or include,
/// which could change either. A line this does not fully understand answers
/// false.
#[cfg(unix)]
pub(crate) fn config_keeps_work_tree(text: &str) -> bool {
    let name_chars = |name: &str| {
        !name.is_empty()
            && name
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || character == '-')
    };
    // The section name, lowercased, and whether it has a subsection;
    // `None` before the first header.
    let mut section = None::<(String, bool)>;
    for line in text.lines() {
        let mut line = line.trim_start();
        // A value continued on the next line could hide anything there.
        if line.ends_with('\\') {
            return false;
        }
        if let Some(header) = line.strip_prefix('[') {
            let (name, subsection, rest) = match header.split_once('"') {
                // Git requires a space before the quoted subsection.
                Some((name, quoted)) if name != name.trim_end() => {
                    let Some((_, rest)) = quoted.split_once("\"]") else {
                        return false;
                    };
                    (name.trim_end(), true, rest)
                }
                Some(_) => return false,
                None => {
                    let Some((name, rest)) = header.split_once(']') else {
                        return false;
                    };
                    match name.split_once('.') {
                        Some((name, _)) => (name, true, rest),
                        None => (name, false, rest),
                    }
                }
            };
            if !name_chars(name) || rest.contains('"') {
                return false;
            }
            section = Some((name.to_ascii_lowercase(), subsection));
            line = rest.trim_start();
        }
        if line.is_empty() || line.starts_with(['#', ';']) {
            continue;
        }
        let key_end = line
            .find(|character: char| !(character.is_ascii_alphanumeric() || character == '-'))
            .unwrap_or(line.len());
        let (key, rest) = line.split_at(key_end);
        let rest = rest.trim_start();
        let value = if rest.is_empty() || rest.starts_with(['#', ';']) {
            None
        } else if let Some(value) = rest.strip_prefix('=') {
            let value = value.split(['#', ';']).next().unwrap_or_default().trim();
            if value.contains('"') {
                return false;
            }
            Some(value.to_ascii_lowercase())
        } else {
            return false;
        };
        let Some((name, subsection)) = &section else {
            return false;
        };
        if !key.starts_with(|character: char| character.is_ascii_alphabetic()) {
            return false;
        }
        let key = key.to_ascii_lowercase();
        let keeps = match (name.as_str(), *subsection, key.as_str()) {
            ("core", false, "worktree") => false,
            ("core", false, "bare") => {
                matches!(value.as_deref(), Some("false" | "no" | "off" | "0" | ""))
            }
            ("core", false, "repositoryformatversion") => {
                matches!(value.as_deref(), Some("0" | "1"))
            }
            ("extensions" | "include" | "includeif", _, _) => false,
            _ => true,
        };
        if !keeps {
            return false;
        }
    }
    true
}

/// A `git` invocation that inherits none of the caller's `GIT_*` variables,
/// so it answers for the repository it is pointed at, and that starts no
/// program the repository's configuration names: no filesystem monitor hook
/// and no fetch. Configuration given here outranks the repository's, and Git
/// passes it on to the Git processes it starts, such as a submodule's.
///
/// A command that reads tracked files' contents, as `status` does, also runs
/// the filter drivers the configuration names, which only that repository's
/// configuration can list: see `filter_drivers_disabled` in `git_state.rs`.
pub(crate) fn git_command(git: &Path) -> Command {
    let mut command = Command::new(git);
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("GIT_") {
            command.env_remove(name);
        }
    }
    // Git for Windows must not discard these overrides in its children.
    command.args([
        "-c",
        "core.fsmonitor=false",
        "-c",
        "help.autocorrect=0",
        "-c",
        "core.unsetenvvars=",
    ]);
    // A partial clone can fetch during an ordinary read. Git treats an empty
    // transport allowlist as allowing an empty helper name. Allow only a name
    // ending in '/' and containing '?', which cannot name an executable on
    // Unix or Windows. Disable correction so Git cannot substitute a
    // repository alias for that missing helper.
    command.env("GIT_ALLOW_PROTOCOL", "nah-observation-disabled?.helper/");
    command
}

/// Git's work tree top level and common git directory for `directory`, from
/// one `rev-parse`.
fn git_top_level_and_common_dir(
    git: &Path,
    directory: &Path,
    wait: GitWait,
) -> Result<(String, String), ObservationFailure> {
    let directory = directory.to_str().ok_or(ObservationFailure::Unavailable)?;
    let (code, output) = git_exit_and_output(
        git,
        directory,
        &["rev-parse", "--show-toplevel", "--git-common-dir"],
        REV_PARSE_MAX_BYTES,
        wait,
        &[],
    )?;
    if code != Some(0) {
        return Err(ObservationFailure::Unavailable);
    }
    let text = String::from_utf8(output).map_err(|_| ObservationFailure::NonUnicode)?;
    let mut lines = text.lines();
    match (lines.next(), lines.next(), lines.next()) {
        (Some(top_level), Some(common), None)
            if !top_level.is_empty()
                && !common.is_empty()
                && !top_level.contains('\r')
                && !common.contains('\r') =>
        {
            Ok((top_level.to_owned(), common.to_owned()))
        }
        _ => Err(ObservationFailure::Unavailable),
    }
}

pub(crate) fn find_git_marker(cwd: &Path) -> Result<Option<&Path>, ObservationFailure> {
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
