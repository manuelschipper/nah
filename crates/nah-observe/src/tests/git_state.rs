use super::support::{canonical, init_repo, run};
use crate::TEST_GIT_TIMEOUT;
use crate::git_state::observe_git_state;
use nah_proto::observation::{GitStateObservation, Observed};
use std::fs;
use std::path::Path;
use std::process::Command;

fn state(directory: &Path, inspect_untracked: bool) -> Observed<GitStateObservation> {
    observe_git_state(
        directory.to_str().expect("unicode test path"),
        inspect_untracked,
        Path::new("git"),
        TEST_GIT_TIMEOUT,
    )
}

/// A discard is delegated on this answer, so every kind of uncommitted state
/// must be told apart from a clean repository: a staged rename (two paths in
/// one entry), an untracked file, an ignored file, a directory ignored as a
/// whole, and a stash entry.
#[test]
fn uncommitted_state_is_told_apart_from_a_clean_repository() {
    let temp = tempfile::tempdir().expect("tempdir");
    let repo = temp.path().join("repo");
    init_repo(&repo);
    fs::write(repo.join(".gitignore"), "target/\n.env\n").expect("ignore rules");
    let git = |args: &[&str]| {
        run(Command::new("git")
            .args([
                "-c",
                "user.name=Nah Test",
                "-c",
                "user.email=nah@example.invalid",
            ])
            .args(args)
            .current_dir(&repo))
    };
    git(&["add", ".gitignore"]);
    git(&["commit", "-qm", "ignore"]);

    let Observed::Ok { value: clean } = state(&repo, true) else {
        panic!("a clean repository is observable")
    };
    assert!(!clean.tracked_changes() && !clean.stash_entries());
    let entries = clean.untracked().expect("untracked entries were asked for");
    assert!(entries.untracked().is_empty() && entries.ignored().is_empty());
    assert!(matches!(
        state(&repo, false),
        Observed::Ok { value } if value.untracked().is_none()
    ));

    fs::write(repo.join("tracked"), "two\n").expect("edit");
    git(&["stash", "-q"]);
    git(&["mv", "tracked", "renamed"]);
    fs::write(repo.join("draft.md"), "draft\n").expect("untracked file");
    fs::write(repo.join(".env"), "TOKEN=1\n").expect("ignored file");
    fs::create_dir(repo.join("target")).expect("ignored directory");
    fs::write(repo.join("target/out"), "out\n").expect("build output");

    let Observed::Ok { value: dirty } = state(&repo, true) else {
        panic!("a dirty repository is observable")
    };
    assert!(dirty.tracked_changes() && dirty.stash_entries());
    let entries = dirty.untracked().expect("untracked entries were asked for");
    assert_eq!(entries.untracked(), ["draft.md"]);
    assert_eq!(entries.ignored(), [".env", "target/"]);

    assert!(matches!(state(temp.path(), true), Observed::Error { .. }));

    // An edit to an assume-unchanged file is invisible to status, and a
    // checkout overwrites it.
    let hidden = temp.path().join("hidden");
    init_repo(&hidden);
    run(Command::new("git")
        .args(["update-index", "--assume-unchanged", "tracked"])
        .current_dir(&hidden));
    fs::write(hidden.join("tracked"), "local\n").expect("hidden edit");
    assert!(matches!(
        state(&hidden, false),
        Observed::Ok { value } if value.tracked_changes()
    ));

    // A discard run in a subdirectory acts on the whole repository, so the
    // state read from there is the repository's: its top level, and a hidden
    // edit that lies outside the subdirectory.
    let nested = temp.path().join("nested");
    init_repo(&nested);
    fs::create_dir(nested.join("crates")).expect("subdirectory");
    let Observed::Ok { value: below } = state(&nested.join("crates"), false) else {
        panic!("a subdirectory is observable")
    };
    assert_eq!(below.top_level().as_str(), canonical(&nested));
    assert!(!below.tracked_changes());
    run(Command::new("git")
        .args(["update-index", "--assume-unchanged", "tracked"])
        .current_dir(&nested));
    fs::write(nested.join("tracked"), "local\n").expect("hidden edit above");
    assert!(matches!(
        state(&nested.join("crates"), false),
        Observed::Ok { value } if value.tracked_changes()
    ));
}
