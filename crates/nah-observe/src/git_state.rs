//! Observes what a Git repository holds that is in no commit.

use crate::io_paths::canonical_absolute;
use crate::roots::{ChildExt, GitWait, git_command};
use nah_proto::observation::{
    GitStateObservation, GitUntrackedObservation, MAX_GIT_STATE_ENTRIES, ObservationFailure,
    Observed,
};
use std::ffi::OsStr;
use std::io::{Read, Write};
use std::path::Path;
use std::process::Stdio;
use std::sync::mpsc;
use std::time::Instant;

/// Most bytes of `git status` output read: more is a tree too large to list.
const STATUS_MAX_BYTES: u64 = 1024 * 1024;

/// Most bytes of the index listing read, which names every tracked file.
const INDEX_MAX_BYTES: u64 = 32 * 1024 * 1024;

/// Variables that point Git at a repository other than the one found from
/// the directory it runs in.
pub(crate) const REDIRECTING_VARIABLES: [&str; 4] = [
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
    wait: GitWait,
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
    // `directory`. The same rev-parse prints the stash commit after the top
    // level and exits 0 if it exists, or prints only the top level and exits
    // 1 if it does not. Other exits leave the repository state unknown.
    let (top_level, stash_entries) = match git_exit_and_output(
        git,
        directory,
        &[
            "rev-parse",
            "--show-toplevel",
            "--verify",
            "--quiet",
            "refs/stash",
        ],
        STATUS_MAX_BYTES,
        wait,
        &[],
    ) {
        Ok((Some(code @ (0 | 1)), output)) => {
            let stash_entries = code == 0;
            let top_level = String::from_utf8(output).ok().and_then(|text| {
                let lines = text.lines().collect::<Vec<_>>();
                let expected = if stash_entries { 2 } else { 1 };
                (lines.len() == expected
                    && lines
                        .iter()
                        .all(|line| !line.is_empty() && !line.contains('\r')))
                .then(|| canonical_absolute(Path::new(lines[0])).ok())
                .flatten()
            });
            (top_level, stash_entries)
        }
        Ok(_) => (None, false),
        Err(error) => return unavailable(error),
    };
    let Some(top_level) = top_level else {
        return unavailable(ObservationFailure::Unavailable);
    };
    // Status compares a tracked file whose metadata changed by its contents,
    // which runs the filter drivers the repository's configuration names.
    let filters = match filter_drivers_disabled(git, directory, wait) {
        Ok(filters) => filters,
        Err(error) => return unavailable(error),
    };
    // `--no-optional-locks` keeps status from writing the refreshed index.
    // Status does not look inside a submodule: Git would ask it with the
    // submodule's own configuration, whose filter drivers are not disabled.
    let mut status = vec!["--no-optional-locks"];
    status.extend(filters.iter().map(String::as_str));
    status.extend([
        "status",
        "--porcelain=v1",
        "-z",
        "--ignore-submodules=dirty",
    ]);
    status.extend(if inspect_untracked {
        ["--untracked-files=normal", "--ignored=matching"]
    } else {
        ["--untracked-files=no", "--ignored=no"]
    });
    let entries = match git_output(git, directory, &status, STATUS_MAX_BYTES, wait) {
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
    // Nor did it look inside a submodule, so one may hold changes: the
    // listing gives it mode `160000`. It lists the directory it runs in, so
    // it runs at the top level.
    if !tracked_changes {
        tracked_changes = match git_output(
            git,
            top_level.as_str(),
            &["ls-files", "-v", "-s", "-z"],
            INDEX_MAX_BYTES,
            wait,
        ) {
            Ok((true, index)) => index.split(|byte| *byte == 0).any(|entry| {
                entry
                    .first()
                    .is_some_and(|tag| tag.is_ascii_lowercase() || *tag == b'S')
                    || entry.get(2..8) == Some(b"160000")
            }),
            Ok((false, _)) => return unavailable(ObservationFailure::Unavailable),
            Err(error) => return unavailable(error),
        };
    }
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

/// The `-c` options that disable every filter driver the configuration of
/// the repository Git finds from `directory` names, so a command that reads
/// tracked files' contents starts none of them. A driver Git cannot be told
/// about on its command line, one whose name holds `=`, is a failure.
pub(crate) fn filter_drivers_disabled(
    git: &Path,
    directory: &str,
    wait: GitWait,
) -> Result<Vec<String>, ObservationFailure> {
    let names = match git_exit_and_output(
        git,
        directory,
        &["config", "-z", "--name-only", "--get-regexp", r"^filter\."],
        STATUS_MAX_BYTES,
        wait,
        &[],
    )? {
        (Some(0), names) => String::from_utf8(names).map_err(|_| ObservationFailure::NonUnicode)?,
        // No key matches.
        (Some(1), _) => return Ok(Vec::new()),
        _ => return Err(ObservationFailure::Unavailable),
    };
    // A key is `filter.<driver>.<setting>`; the driver name may hold dots.
    let drivers = names
        .split_terminator('\0')
        .filter_map(|name| name.strip_prefix("filter.")?.rsplit_once('.'))
        .map(|(driver, _)| driver)
        .collect::<std::collections::BTreeSet<_>>();
    if drivers.iter().any(|driver| driver.contains('=')) {
        return Err(ObservationFailure::Unavailable);
    }
    // An empty command is no filter. A driver the configuration marks
    // required then fails the command, which answers nothing.
    Ok(drivers
        .into_iter()
        .flat_map(|driver| {
            ["clean", "smudge", "process"].map(|setting| format!("filter.{driver}.{setting}="))
        })
        .flat_map(|option| ["-c".to_owned(), option])
        .collect())
}

/// Runs `git -C directory args` with `input` as its standard input,
/// returning its exit code and what it printed. Output past `max_bytes` or a
/// run past the time `wait` leaves is a failure, never a partial answer.
pub(crate) fn git_exit_and_output(
    git: &Path,
    directory: &str,
    args: &[&str],
    max_bytes: u64,
    wait: GitWait,
    input: &[u8],
) -> Result<(Option<i32>, Vec<u8>), ObservationFailure> {
    if wait.timeout().is_zero() {
        return Err(ObservationFailure::Timeout);
    }
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
    // One deadline bounds the run and the collection of its output: a
    // process the child leaves behind can hold the pipe open after the child
    // exits, and is then left to finish alone.
    let stop = Instant::now() + wait.timeout();
    // Read while waiting, so a listing larger than the pipe does not stall
    // the child until the timeout.
    let stdout = child.stdout.take().expect("stdout is piped");
    let (sender, output) = mpsc::channel();
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = sender.send(
            stdout
                .take(max_bytes + 1)
                .read_to_end(&mut bytes)
                .map(|_| bytes),
        );
    });
    let status = match child.wait_timeout(stop.saturating_duration_since(Instant::now())) {
        Ok(Some(status)) => status,
        Ok(None) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(ObservationFailure::Timeout);
        }
        Err(_) => return Err(ObservationFailure::Unavailable),
    };
    let bytes = match output.recv_timeout(stop.saturating_duration_since(Instant::now())) {
        Ok(Ok(bytes)) => bytes,
        Err(mpsc::RecvTimeoutError::Timeout) => return Err(ObservationFailure::Timeout),
        Ok(Err(_)) | Err(mpsc::RecvTimeoutError::Disconnected) => {
            return Err(ObservationFailure::Unavailable);
        }
    };
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
    wait: GitWait,
) -> Result<(bool, Vec<u8>), ObservationFailure> {
    git_exit_and_output(git, directory, args, max_bytes, wait, &[])
        .map(|(code, output)| (code == Some(0), output))
}
