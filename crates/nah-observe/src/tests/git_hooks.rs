use super::support::{absolute, canonical, init_repo, run, value};
use crate::{TEST_GIT_TIMEOUT, fulfill_with_git};
use nah_proto::ctx::SchemaVersion;
use nah_proto::observation::{
    ObservationFailure, ObservationQuery, ObservationRequest, ObservationValue, Observed,
};
use std::fs;
use std::path::Path;
use std::process::Command;

fn hooks(cwd: &Path) -> Observed<nah_proto::ctx::AbsolutePath> {
    let request = ObservationRequest::new(
        SchemaVersion::V1,
        "request",
        vec![
            ObservationQuery::Cwd {
                key: "cwd".into(),
                requested: absolute(cwd),
            },
            ObservationQuery::Roots {
                key: "roots".into(),
                cwd_key: "cwd".into(),
            },
            ObservationQuery::GitHooks {
                key: "hooks".into(),
                cwd_key: "cwd".into(),
            },
        ],
    )
    .expect("request");
    let observation =
        fulfill_with_git(&request, Path::new("git"), TEST_GIT_TIMEOUT).expect("observation");
    let ObservationValue::GitHooks { observed } = value(&observation, "hooks") else {
        panic!("a hook directory fact")
    };
    observed.clone()
}

/// The guard matches writes below this answer, so it must be the directory
/// Git runs hooks from wherever in the work tree the call runs: a relative
/// `core.hooksPath` is taken from the top level, not from the working
/// directory, and without one it is the Git directory's `hooks`.
#[test]
fn hook_directory_is_the_one_git_runs_hooks_from() {
    let temp = tempfile::tempdir().expect("tempdir");
    let repo = temp.path().join("repo");
    init_repo(&repo);
    let subdirectory = repo.join("src");
    fs::create_dir(&subdirectory).expect("subdirectory");
    let directory = |path: &Path| Observed::Ok {
        value: absolute(path),
    };
    let top = Path::new(&canonical(&repo)).to_owned();
    assert_eq!(hooks(&subdirectory), directory(&top.join(".git/hooks")));

    run(Command::new("git")
        .args(["config", "core.hooksPath", ".husky"])
        .current_dir(&repo));
    assert_eq!(hooks(&subdirectory), directory(&top.join(".husky")));

    // Turning hooks off by pointing Git at a file, usually `/dev/null`,
    // leaves no hook directory, so writes such as `2>/dev/null` are not
    // writes into one.
    fs::write(repo.join("hooks-off"), "").expect("file");
    run(Command::new("git")
        .args(["config", "core.hooksPath", "hooks-off"])
        .current_dir(&repo));
    assert_eq!(
        hooks(&subdirectory),
        Observed::Error {
            error: ObservationFailure::NotFound
        }
    );

    let outside = temp.path().join("outside");
    fs::create_dir(&outside).expect("outside directory");
    assert_eq!(
        hooks(&outside),
        Observed::Error {
            error: ObservationFailure::NotFound
        }
    );
}
