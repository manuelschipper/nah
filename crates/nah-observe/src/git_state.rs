//! Observes what a Git repository holds that is in no commit.

use crate::io_paths::canonical_absolute;
use crate::roots::{ChildExt, git_command};
use nah_proto::observation::{
    GitStateObservation, GitUntrackedObservation, MAX_GIT_STATE_ENTRIES, ObservationFailure,
    Observed,
};
use std::ffi::OsStr;
use std::io::{Read, Write};
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

/// Most bytes of `git status` output read: more is a tree too large to list.
const STATUS_MAX_BYTES: u64 = 1024 * 1024;

/// Most bytes of the index listing read, which names every tracked file.
const INDEX_MAX_BYTES: u64 = 32 * 1024 * 1024;

/// Variables that point Git at a repository other than the one found from
/// the directory it runs in.
const REDIRECTING_VARIABLES: [&str; 4] = [
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_COMMON_DIR",
];

/// The uncommitted state of the repository Git finds from `directory`:
/// whether a tracked file differs from `HEAD` or is hidden from that
/// comparison, whether the stash holds an entry and, with
/// `inspect_untracked`, its untracked and ignored entries.
///
/// The commands a caller asks about inherit the caller's environment, which
/// this observation does not: when that environment points Git at another
/// repository, the state observed here is not the state they act on, so
/// nothing is reported.
pub(crate) fn observe_git_state(
    directory: &str,
    inspect_untracked: bool,
    git: &Path,
    timeout: Duration,
) -> Observed<GitStateObservation> {
    let unavailable = |error| Observed::Error { error };
    if REDIRECTING_VARIABLES
        .iter()
        .any(|name| std::env::var_os(name).is_some())
    {
        return unavailable(ObservationFailure::Unavailable);
    }
    // The repository is the one Git finds above `directory`, so every later
    // answer is about the tree that starts at its top level, not at
    // `directory`.
    let top_level = match git_output(
        git,
        directory,
        &["rev-parse", "--show-toplevel"],
        STATUS_MAX_BYTES,
        timeout,
    ) {
        Ok((true, output)) => String::from_utf8(output)
            .ok()
            .map(|text| text.trim_end_matches(['\r', '\n']).to_owned())
            .filter(|text| !text.is_empty() && !text.contains(['\r', '\n']))
            .and_then(|text| canonical_absolute(Path::new(&text)).ok()),
        Ok((false, _)) => None,
        Err(error) => return unavailable(error),
    };
    let Some(top_level) = top_level else {
        return unavailable(ObservationFailure::Unavailable);
    };
    // Neither command writes: `--no-optional-locks` keeps status from
    // refreshing the index, and no filesystem monitor hook is started.
    let mut status = vec![
        "--no-optional-locks",
        "-c",
        "core.fsmonitor=false",
        "status",
        "--porcelain=v1",
        "-z",
        "--ignore-submodules=none",
    ];
    status.extend(if inspect_untracked {
        ["--untracked-files=normal", "--ignored=matching"]
    } else {
        ["--untracked-files=no", "--ignored=no"]
    });
    let entries = match git_output(git, directory, &status, STATUS_MAX_BYTES, timeout) {
        Ok((true, output)) => output,
        Ok((false, _)) => return unavailable(ObservationFailure::Unavailable),
        Err(error) => return unavailable(error),
    };
    let Ok(entries) = String::from_utf8(entries) else {
        return unavailable(ObservationFailure::NonUnicode);
    };
    let (mut tracked_changes, mut untracked, mut ignored) = (false, Vec::new(), Vec::new());
    let mut fields = entries.split_terminator('\0');
    while let Some(entry) = fields.next() {
        let Some((state, path)) = entry.split_at_checked(3) else {
            return unavailable(ObservationFailure::Unavailable);
        };
        match state {
            "?? " => untracked.push(path.to_owned()),
            "!! " => ignored.push(path.to_owned()),
            _ => {
                tracked_changes = true;
                // A rename or copy is followed by the path it came from.
                if state.starts_with(['R', 'C']) {
                    fields.next();
                }
            }
        }
    }
    if untracked.len() > MAX_GIT_STATE_ENTRIES || ignored.len() > MAX_GIT_STATE_ENTRIES {
        return unavailable(ObservationFailure::Unavailable);
    }
    // Status does not look at a file the index marks assume-unchanged or
    // skip-worktree, yet a checkout or reset overwrites an edit to one. The
    // index listing tags the first with a lowercase letter, the second `S`.
    // It lists the directory it runs in, so it runs at the top level.
    if !tracked_changes {
        tracked_changes = match git_output(
            git,
            top_level.as_str(),
            &["ls-files", "-v", "-z"],
            INDEX_MAX_BYTES,
            timeout,
        ) {
            Ok((true, index)) => index.split(|byte| *byte == 0).any(|entry| {
                entry
                    .first()
                    .is_some_and(|tag| tag.is_ascii_lowercase() || *tag == b'S')
            }),
            Ok((false, _)) => return unavailable(ObservationFailure::Unavailable),
            Err(error) => return unavailable(error),
        };
    }
    // `--verify --quiet` exits 1 with no output for a ref that does not
    // exist; the status above already proved the repository readable.
    let stash_entries = match git_output(
        git,
        directory,
        &["rev-parse", "--verify", "--quiet", "refs/stash"],
        STATUS_MAX_BYTES,
        timeout,
    ) {
        Ok((found, _)) => found,
        Err(error) => return unavailable(error),
    };
    let state = GitStateObservation::new(top_level, tracked_changes, stash_entries);
    if !inspect_untracked {
        return Observed::Ok { value: state };
    }
    match GitUntrackedObservation::new(untracked, ignored) {
        Ok(untracked) => Observed::Ok {
            value: state.with_untracked(untracked),
        },
        Err(_) => unavailable(ObservationFailure::Unavailable),
    }
}

/// Runs `git -C directory args` with `input` as its standard input,
/// returning its exit code and what it printed. Output past `max_bytes` or a
/// run past `timeout` is a failure, never a partial answer.
pub(crate) fn git_exit_and_output(
    git: &Path,
    directory: &str,
    args: &[&str],
    max_bytes: u64,
    timeout: Duration,
    input: &[u8],
) -> Result<(Option<i32>, Vec<u8>), ObservationFailure> {
    let mut child = git_command(git)
        .args([OsStr::new("-C"), OsStr::new(directory)])
        .args(args)
        .stdin(if input.is_empty() {
            Stdio::null()
        } else {
            Stdio::piped()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| ObservationFailure::Unavailable)?;
    // Written beside the read below, so neither pipe fills while Git waits
    // on the other. A child that exits early leaves the write to fail.
    if let Some(mut stdin) = child.stdin.take() {
        let input = input.to_vec();
        std::thread::spawn(move || {
            let _ = stdin.write_all(&input);
        });
    }
    // Read while waiting, so a listing larger than the pipe does not stall
    // the child until the timeout.
    let stdout = child.stdout.take().expect("stdout is piped");
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout
            .take(max_bytes + 1)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });
    let status = match child.wait_timeout(timeout) {
        Ok(Some(status)) => status,
        Ok(None) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(ObservationFailure::Timeout);
        }
        Err(_) => return Err(ObservationFailure::Unavailable),
    };
    let bytes = reader
        .join()
        .ok()
        .and_then(Result::ok)
        .ok_or(ObservationFailure::Unavailable)?;
    if bytes.len() as u64 > max_bytes {
        return Err(ObservationFailure::Unavailable);
    }
    Ok((status.code(), bytes))
}

/// `git_exit_and_output` without input, as whether Git succeeded.
fn git_output(
    git: &Path,
    directory: &str,
    args: &[&str],
    max_bytes: u64,
    timeout: Duration,
) -> Result<(bool, Vec<u8>), ObservationFailure> {
    git_exit_and_output(git, directory, args, max_bytes, timeout, &[])
        .map(|(code, output)| (code == Some(0), output))
}
