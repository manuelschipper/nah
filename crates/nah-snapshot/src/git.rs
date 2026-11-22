//! Runs git for a snapshot: against the project's repository, which it only
//! reads, and against the store's own object directory.

use crate::Refusal;
use std::io::{self, BufWriter, Read, Write};
use std::path::Path;
use std::process::{ChildStdin, Command, Stdio};
use std::time::Instant;
use wait_timeout::ChildExt;

/// Why a git child produced no answer.
#[derive(Debug)]
pub(crate) enum GitFailure {
    Deadline,
    /// It could not start, or exited unsuccessfully; holds what it printed.
    Failed(String),
}

impl GitFailure {
    /// The refusal a failed read of the project's repository becomes.
    pub(crate) fn repository(self) -> Refusal {
        match self {
            GitFailure::Deadline => Refusal::OverDeadline,
            GitFailure::Failed(detail) => Refusal::RepositoryUnreadable { detail },
        }
    }

    /// The refusal a failed write to the store becomes.
    pub(crate) fn store(self) -> Refusal {
        match self {
            GitFailure::Deadline => Refusal::OverDeadline,
            GitFailure::Failed(detail) if detail.contains("No space left on device") => {
                Refusal::DiskFull
            }
            GitFailure::Failed(detail) => Refusal::StoreUnwritable { detail },
        }
    }
}

/// Git run against the project's repository at `top`, reading only. On top
/// of `nah_observe::git_command`, it runs no hook and no filter driver the
/// repository names (`filters` from `git_filter_drivers_disabled`), and takes
/// no optional lock, so `status` leaves the index as it found it.
pub(crate) fn repository(git: &Path, top: &Path, filters: &[String]) -> Command {
    let mut command = nah_observe::git_command(git);
    command
        .arg("-C")
        .arg(top)
        .args(["-c", "core.hooksPath=/dev/null", "--no-optional-locks"])
        .args(filters);
    command
}

/// Git run against the store's own bare repository `git_dir`, writing new
/// objects to `objects` when given, where existing ones are found through the
/// store's shared object directory.
pub(crate) fn store(git: &Path, git_dir: &Path, objects: Option<&Path>) -> Command {
    let mut command = nah_observe::git_command(git);
    command
        .arg("--git-dir")
        .arg(git_dir)
        .args(["-c", "core.hooksPath=/dev/null"])
        .current_dir(git_dir);
    if let Some(objects) = objects {
        command
            .env("GIT_OBJECT_DIRECTORY", objects)
            .env("GIT_ALTERNATE_OBJECT_DIRECTORIES", git_dir.join("objects"));
    }
    command
}

/// Runs `command` with `input` on its standard input and returns what it
/// printed. A child still running at `deadline` is killed.
pub(crate) fn output(
    command: Command,
    input: Vec<u8>,
    deadline: Instant,
) -> Result<Vec<u8>, GitFailure> {
    output_and_warnings(command, input, deadline).map(|(printed, _)| printed)
}

/// As `output`, with the warnings a successful run printed besides, in the
/// C locale's words.
pub(crate) fn output_and_warnings(
    command: Command,
    input: Vec<u8>,
    deadline: Instant,
) -> Result<(Vec<u8>, String), GitFailure> {
    run(command, input, u64::MAX - 1, deadline)
}

/// As `output`, reading no more than `cap` bytes of what it prints: `None`
/// once it printed more, which ends it.
pub(crate) fn output_capped(
    command: Command,
    input: Vec<u8>,
    cap: u64,
    deadline: Instant,
) -> Result<Option<Vec<u8>>, GitFailure> {
    match run(command, input, cap, deadline) {
        Ok((printed, _)) if printed.len() as u64 > cap => Ok(None),
        Ok((printed, _)) => Ok(Some(printed)),
        Err(failure) => Err(failure),
    }
}

/// Runs `command`, reading at most one byte past `cap` of what it prints; a
/// child that prints more ends when it next writes, and its answer is what
/// it printed up to then.
fn run(
    mut command: Command,
    input: Vec<u8>,
    cap: u64,
    deadline: Instant,
) -> Result<(Vec<u8>, String), GitFailure> {
    let timeout = deadline.saturating_duration_since(Instant::now());
    if timeout.is_zero() {
        return Err(GitFailure::Deadline);
    }
    command
        .env("LC_ALL", "C")
        .stdin(if input.is_empty() {
            Stdio::null()
        } else {
            Stdio::piped()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|error| GitFailure::Failed(format!("git could not start: {error}")))?;
    let stdin = child.stdin.take();
    let mut stdout = child.stdout.take().expect("stdout is piped");
    let mut stderr = child.stderr.take().expect("stderr is piped");
    std::thread::scope(|scope| {
        if let Some(mut stdin) = stdin {
            scope.spawn(move || {
                let _ = stdin.write_all(&input);
            });
        }
        let printed = scope.spawn(move || {
            let mut bytes = Vec::new();
            let _ = (&mut stdout).take(cap + 1).read_to_end(&mut bytes);
            // Closing the pipe ends a child still printing.
            drop(stdout);
            bytes
        });
        let complained = scope.spawn(move || {
            let mut bytes = Vec::new();
            let _ = stderr.read_to_end(&mut bytes);
            bytes
        });
        let status = match child.wait_timeout(timeout) {
            Ok(Some(status)) => status,
            Ok(None) | Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(GitFailure::Deadline);
            }
        };
        let printed = printed.join().unwrap_or_default();
        let complained = complained.join().unwrap_or_default();
        let complained = String::from_utf8_lossy(&complained).trim().to_owned();
        if status.success() || printed.len() as u64 > cap {
            Ok((printed, complained))
        } else {
            Err(GitFailure::Failed(complained))
        }
    })
}

/// Why feeding a child stopped.
pub(crate) enum FeedFailure {
    Refused(Refusal),
    /// The child stopped reading, having failed.
    Pipe,
}

impl From<Refusal> for FeedFailure {
    fn from(refusal: Refusal) -> Self {
        FeedFailure::Refused(refusal)
    }
}

impl From<io::Error> for FeedFailure {
    fn from(_: io::Error) -> Self {
        FeedFailure::Pipe
    }
}

/// Runs `command` on the store, streaming its standard input from `write`,
/// and waits for it to succeed. A refusal from `write`, or the deadline,
/// stops and kills the child.
pub(crate) fn feed(
    mut command: Command,
    deadline: Instant,
    write: impl FnOnce(&mut BufWriter<ChildStdin>) -> Result<(), FeedFailure>,
) -> Result<(), Refusal> {
    if Instant::now() >= deadline {
        return Err(Refusal::OverDeadline);
    }
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|error| GitFailure::Failed(format!("git could not start: {error}")).store())?;
    let stdin = child.stdin.take().expect("stdin is piped");
    let mut stderr = child.stderr.take().expect("stderr is piped");
    std::thread::scope(|scope| {
        let complained = scope.spawn(move || {
            let mut bytes = Vec::new();
            let _ = stderr.read_to_end(&mut bytes);
            bytes
        });
        let mut input = BufWriter::with_capacity(1 << 20, stdin);
        let fed = write(&mut input).and_then(|()| input.flush().map_err(FeedFailure::from));
        drop(input);
        if let Err(FeedFailure::Refused(refusal)) = fed {
            let _ = child.kill();
            let _ = child.wait();
            return Err(refusal);
        }
        let timeout = deadline.saturating_duration_since(Instant::now());
        let status = match child.wait_timeout(timeout) {
            Ok(Some(status)) => status,
            Ok(None) | Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(Refusal::OverDeadline);
            }
        };
        let complained = complained.join().unwrap_or_default();
        if status.success() && fed.is_ok() {
            Ok(())
        } else {
            Err(GitFailure::Failed(String::from_utf8_lossy(&complained).trim().to_owned()).store())
        }
    })
}
