//! Observes the directory a Git repository runs its hooks from.

use crate::git_state::{REDIRECTING_VARIABLES, git_exit_and_output};
use crate::io_paths::{absolute_from_path, dataless};
use crate::roots::GitWait;
use nah_proto::ctx::AbsolutePath;
use nah_proto::observation::{ObservationFailure, Observed};
use std::fs;
use std::path::Path;

/// Most bytes of `git rev-parse` output read.
const MAX_BYTES: u64 = 64 * 1024;

/// The hook directory of the repository Git finds from `directory`, as Git
/// itself resolves it: `core.hooksPath` from any configuration file Git
/// reads, a relative value taken from the work tree's top level, or else the
/// Git directory's `hooks`. An answer that exists and is no directory, such
/// as `core.hooksPath = /dev/null`, the usual way to turn hooks off, is no
/// hook directory: Git runs nothing from it, so it is `NotFound`. One that
/// does not exist yet still counts, since a write may create it.
///
/// The commands a caller asks about inherit the caller's environment, which
/// this observation does not: when that environment points Git at another
/// repository, nothing is reported, as for the Git state.
pub(crate) fn observe_git_hooks(
    directory: &str,
    git: &Path,
    wait: GitWait,
) -> Observed<AbsolutePath> {
    match hook_directory(directory, git, wait) {
        Ok(value) => Observed::Ok { value },
        Err(error) => Observed::Error { error },
    }
}

fn hook_directory(
    directory: &str,
    git: &Path,
    wait: GitWait,
) -> Result<AbsolutePath, ObservationFailure> {
    if REDIRECTING_VARIABLES
        .iter()
        .any(|name| std::env::var_os(name).is_some())
    {
        return Err(ObservationFailure::Unavailable);
    }
    // `--path-format` needs Git 2.31. An older Git prints the option back
    // as an argument, which the line checks below refuse.
    let (code, output) = git_exit_and_output(
        git,
        directory,
        &[
            "rev-parse",
            "--path-format=absolute",
            "--git-common-dir",
            "--git-path",
            "hooks",
        ],
        MAX_BYTES,
        wait,
        &[],
    )?;
    if code != Some(0) {
        return Err(ObservationFailure::Unavailable);
    }
    let text = String::from_utf8(output).map_err(|_| ObservationFailure::NonUnicode)?;
    let [common, hooks] = text.lines().collect::<Vec<_>>()[..] else {
        return Err(ObservationFailure::Unavailable);
    };
    let (common, hooks) = (Path::new(common), Path::new(hooks));
    if !common.is_absolute() || !hooks.is_absolute() || text.contains('\r') {
        return Err(ObservationFailure::Unavailable);
    }
    // Git reads a configuration it cannot read, as it cannot read a
    // dataless one, as empty: its answer is then the default directory.
    let config = common.join("config");
    if fs::symlink_metadata(&config).is_ok_and(|metadata| dataless(&config, &metadata)) {
        return Err(ObservationFailure::Unavailable);
    }
    if fs::metadata(hooks).is_ok_and(|metadata| !metadata.is_dir()) {
        return Err(ObservationFailure::NotFound);
    }
    absolute_from_path(hooks)
}
