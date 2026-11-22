//! The host reads session memory makes (`nah-cli`'s `session_memory`): file
//! digests and text, link resolution, modification times, a few Git
//! questions, and the running processes and crontab. Session memory reaches
//! them through its world interface, whose replay implementation answers
//! from supplied state instead. They run on the hook's own thread, without
//! the deadline the decision's observations have (nah-275#6).

use std::collections::BTreeSet;
use std::path::Path;
use std::process::{Command, Stdio};

use nah_proto::effinterp_proto::content_digest;

use crate::git_command;

/// The content digest of the regular file at `path`; `None` for a missing
/// or special file, or one past `max_bytes`.
pub fn file_digest(path: &str, max_bytes: u64) -> Option<String> {
    let metadata = std::fs::metadata(path).ok()?;
    if !metadata.is_file() || metadata.len() > max_bytes {
        return None;
    }
    std::fs::read(path).ok().map(|bytes| content_digest(&bytes))
}

/// The file at `path` as UTF-8 text.
pub fn read_text(path: &str) -> std::io::Result<String> {
    std::fs::read_to_string(path)
}

/// `path` with links resolved. For a path that does not exist yet, its
/// nearest existing ancestor's links are resolved and the rest appended.
pub fn canonical(path: &str) -> String {
    let path = Path::new(path);
    path.ancestors()
        .find_map(|ancestor| {
            let resolved = std::fs::canonicalize(ancestor).ok()?;
            let rest = path.strip_prefix(ancestor).ok()?;
            // Joining an empty rest would append a separator.
            Some(if rest.as_os_str().is_empty() {
                resolved
            } else {
                resolved.join(rest)
            })
        })
        .and_then(|path| path.to_str().map(str::to_owned))
        .unwrap_or_else(|| path.to_string_lossy().into_owned())
}

/// Whether `path` is a folder, its links followed.
pub fn is_dir(path: &str) -> bool {
    Path::new(path).is_dir()
}

/// When `path` was last modified, in nanoseconds since the Unix epoch.
pub fn modified_ns(path: &str) -> Option<u128> {
    let modified = std::fs::metadata(path).ok()?.modified().ok()?;
    Some(
        modified
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_nanos(),
    )
}

/// Whether `git check-ignore` run in `folder` says Git ignores `path`;
/// `None` when Git could not be run.
pub fn git_check_ignore(folder: &str, path: &str) -> Option<bool> {
    let mut command = git_command(Path::new("git"));
    command
        .arg("-C")
        .arg(folder)
        .args(["check-ignore", "-q", "--", path]);
    quiet_status(command)
}

/// Whether the index of the work tree at `worktree` tracks `path`; `None`
/// when Git could not be run.
pub fn git_tracked(worktree: &str, path: &str) -> Option<bool> {
    let mut command = git_command(Path::new("git"));
    command
        .arg("-C")
        .arg(worktree)
        .args(["ls-files", "--error-unmatch", "--", path]);
    quiet_status(command)
}

fn quiet_status(mut command: Command) -> Option<bool> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .ok()
        .map(|status| status.success())
}

/// Whether the index holds labelled bytes at `path` that `HEAD` does not, so
/// a commit would add them to history: the staged blob differs from HEAD's
/// and is the file's current content or content whose digest is in
/// `label_digests`.
pub fn index_holds_label(worktree: &str, path: &str, label_digests: &BTreeSet<String>) -> bool {
    let Some(relative) = path
        .strip_prefix(worktree)
        .and_then(|rest| rest.strip_prefix('/'))
    else {
        return false;
    };
    let git = |args: &[&str]| -> Option<Vec<u8>> {
        let mut command = git_command(Path::new("git"));
        let output = command
            .arg("-C")
            .arg(worktree)
            .args(args)
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .ok()?;
        output.status.success().then_some(output.stdout)
    };
    let Some(staged) = git(&["rev-parse", "-q", "--verify", &format!(":./{relative}")]) else {
        return false;
    };
    if git(&["rev-parse", "-q", "--verify", &format!("HEAD:./{relative}")]) == Some(staged.clone())
    {
        return false;
    }
    if git(&["hash-object", "--", path]) == Some(staged.clone()) {
        return true;
    }
    let blob = String::from_utf8_lossy(&staged).trim().to_owned();
    git(&["cat-file", "blob", &blob])
        .is_some_and(|bytes| label_digests.contains(&content_digest(&bytes)))
}

/// The command lines of the running processes; `None` when `ps` could not
/// list them.
pub fn running_commands() -> Option<String> {
    let output = Command::new("ps")
        .args(["-axww", "-o", "command="])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
}

/// The user's crontab as `crontab -l` prints it, empty for none; `None`
/// when `crontab` could not be run.
pub fn crontab() -> Option<String> {
    let output = Command::new("crontab")
        .arg("-l")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    Some(String::from_utf8_lossy(&output.stdout).into_owned())
}
