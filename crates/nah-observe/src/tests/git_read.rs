use super::support::{canonical, init_repo, run};
use crate::TEST_GIT_TIMEOUT;
use crate::git_read::observe_git_read;
use crate::roots::GitWait;
use nah_proto::observation::{GitReadKind, GitReadSelection, Observed};
use std::fs;
use std::path::Path;
use std::process::Command;

/// Ordinary files must not exhaust the credential observation's entry or
/// byte limit. Filtering candidates must still honor the command's paths,
/// exclusions and cwd, including changed paths and the stash's third tree.
#[test]
fn credential_candidates_stay_small_and_intersect_git_pathspecs() {
    use GitReadKind::*;
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    init_repo(&repo);
    let git = |args: &[&str]| {
        run(Command::new("git")
            .current_dir(&repo)
            .args([
                "-c",
                "user.name=Nah Test",
                "-c",
                "user.email=nah@example.invalid",
            ])
            .args(args));
    };
    let ordinary = repo
        .join("x".repeat(200))
        .join("y".repeat(200))
        .join("z".repeat(200));
    fs::create_dir_all(&ordinary).unwrap();
    let files = (0..1400)
        .map(|index| ordinary.join(format!("{index:04}-{}.txt", "f".repeat(180))))
        .collect::<Vec<_>>();
    assert!(
        files
            .iter()
            .map(|path| path.strip_prefix(&repo).unwrap().as_os_str().len() + 1)
            .sum::<usize>()
            > 1024 * 1024
    );
    for file in &files {
        fs::write(file, "ordinary\n").unwrap();
    }
    fs::create_dir(repo.join("src")).unwrap();
    for file in [".env", "src/.pgpass", ".env.example"] {
        fs::write(repo.join(file), "TOKEN=before\n").unwrap();
    }
    git(&["add", "."]);
    git(&["commit", "-qm", "large credential fixture"]);
    let check = |kind, cwd: &Path, paths: &[&str], options: &[&str], expected: &[&str]| {
        let observed = observe_git_read(
            &canonical(cwd),
            &GitReadSelection {
                kind,
                revisions: match kind {
                    Commit => vec!["HEAD".into()],
                    Stash | StashUntracked | StashOnlyUntracked => vec!["0".into()],
                    _ => vec![],
                },
                revision_options: vec![],
                pathspecs: paths.iter().map(|value| (*value).into()).collect(),
                pathspec_options: options.iter().map(|value| (*value).into()).collect(),
            },
            Path::new("git"),
            GitWait::per_spawn(TEST_GIT_TIMEOUT),
        );
        let Observed::Ok { value } = observed else {
            panic!("{kind:?}: {observed:?}")
        };
        let mut expected = expected
            .iter()
            .map(|path| format!("{}/{path}", canonical(&repo)))
            .collect::<Vec<_>>();
        expected.sort();
        assert_eq!(
            value.iter().map(|path| path.as_str()).collect::<Vec<_>>(),
            expected,
            "{kind:?} {paths:?} {options:?} {cwd:?}"
        );
    };
    for kind in [
        Tracked,
        Cached,
        Untracked,
        UntrackedAll,
        Directory,
        DirectoryExcluded,
        Commit,
    ] {
        check(kind, &repo, &[], &[], &[".env", "src/.pgpass"]);
    }
    for (paths, options, expected) in [
        (vec!["src"], vec![], vec!["src/.pgpass"]),
        (vec!["*.txt"], vec![], vec![]),
        (vec![".", ":!.env"], vec![], vec!["src/.pgpass"]),
        (
            vec![".", ":!.env"],
            vec!["--literal-pathspecs"],
            vec![".env", "src/.pgpass"],
        ),
        (vec![":(glob)src/**"], vec![], vec!["src/.pgpass"]),
        (
            vec![":(glob)**/.env*", ":(exclude,glob)**/*.example"],
            vec![],
            vec![".env"],
        ),
        (vec![":(icase)SRC"], vec![], vec!["src/.pgpass"]),
        (vec!["SRC"], vec!["--icase-pathspecs"], vec!["src/.pgpass"]),
        (vec!["*"], vec!["--noglob-pathspecs"], vec![]),
    ] {
        check(Tracked, &repo, &paths, &options, &expected);
    }
    check(Tracked, &repo.join("src"), &[], &[], &["src/.pgpass"]);
    check(Tracked, &repo.join("src"), &[":"], &[], &["src/.pgpass"]);
    check(Tracked, &repo.join("src"), &[":!.pgpass"], &[], &[]);
    check(
        Tracked,
        &repo.join("src"),
        &[":(exclude,top).env"],
        &[],
        &["src/.pgpass"],
    );
    check(
        Tracked,
        &repo.join("src"),
        &[":/"],
        &[],
        &[".env", "src/.pgpass"],
    );
    check(
        Commit,
        &repo.join("src"),
        &[],
        &[],
        &[".env", "src/.pgpass"],
    );
    check(Commit, &repo.join("src"), &["."], &[], &["src/.pgpass"]);
    fs::write(repo.join(".gitignore"), ".env.local\n").unwrap();
    fs::write(repo.join(".env.local"), "TOKEN=ignored\n").unwrap();
    check(Untracked, &repo, &[], &[], &[".env", "src/.pgpass"]);
    for kind in [UntrackedAll, Directory] {
        check(
            kind,
            &repo,
            &[],
            &[],
            &[".env", ".env.local", "src/.pgpass"],
        );
    }
    check(DirectoryExcluded, &repo, &[], &[], &[".env", "src/.pgpass"]);
    for file in files
        .iter()
        .cloned()
        .chain([repo.join(".env"), repo.join("src/.pgpass")])
    {
        fs::write(file, "TOKEN=after\n").unwrap();
    }
    for kind in [Diff, HeadDiff] {
        check(kind, &repo, &[], &[], &[".env", "src/.pgpass"]);
        check(kind, &repo.join("src"), &[], &[], &[".env", "src/.pgpass"]);
        check(kind, &repo.join("src"), &["."], &[], &["src/.pgpass"]);
        check(kind, &repo.join("src"), &[":"], &[], &["src/.pgpass"]);
        check(kind, &repo.join("src"), &[":!.pgpass"], &[], &[".env"]);
        check(
            kind,
            &repo,
            &[".", ":(exclude)**/.pgpass", ":!.env"],
            &[],
            &[],
        );
    }
    git(&["add", "."]);
    check(StagedDiff, &repo, &[], &[], &[".env", "src/.pgpass"]);
    fs::write(repo.join(".pgpass"), "TOKEN=untracked\n").unwrap();
    git(&["stash", "push", "-uqm", "large stash"]);
    check(Stash, &repo, &[], &[], &[".env", "src/.pgpass"]);
    check(
        StashUntracked,
        &repo.join("src"),
        &[],
        &[],
        &[".env", ".pgpass", "src/.pgpass"],
    );
    check(StashOnlyUntracked, &repo, &[], &[], &[".pgpass"]);
    git(&["config", "stash.showIncludeUntracked", "true"]);
    check(Stash, &repo, &[], &[], &[".env", ".pgpass", "src/.pgpass"]);
}

/// A long history must be unknown rather than silently limited to its newest
/// commits; an explicit short selection still has a complete answer.
#[test]
fn history_walk_limit_and_deadline_remain_boundaries() {
    use nah_proto::observation::ObservationFailure;
    use std::io::Write;
    use std::process::Stdio;
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    init_repo(&repo);
    let mut input = String::new();
    for index in 1..=65 {
        input.push_str(&format!("commit refs/heads/history\nmark :{index}\ncommitter Nah Test <nah@example.invalid> {index} +0000\ndata 7\nhistory\n"));
        if index > 1 {
            input.push_str(&format!("from :{}\n", index - 1));
        }
        input.push('\n');
    }
    let mut child = Command::new("git")
        .current_dir(&repo)
        .args(["fast-import", "--quiet"])
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    assert!(child.wait().unwrap().success());
    let mut selection = GitReadSelection {
        kind: GitReadKind::History,
        revisions: vec!["history".into()],
        revision_options: vec![],
        pathspecs: vec![],
        pathspec_options: vec![],
    };
    let observe = |selection: &GitReadSelection, wait| {
        observe_git_read(&canonical(&repo), selection, Path::new("git"), wait)
    };
    assert!(matches!(
        observe(&selection, GitWait::per_spawn(TEST_GIT_TIMEOUT)),
        Observed::Error {
            error: ObservationFailure::Unavailable
        }
    ));
    selection.revision_options = vec!["--max-count=64".into()];
    assert!(
        matches!(observe(&selection, GitWait::per_spawn(TEST_GIT_TIMEOUT)), Observed::Ok { value } if value.is_empty())
    );
    assert!(matches!(
        observe(
            &selection,
            GitWait {
                per_spawn: TEST_GIT_TIMEOUT,
                deadline: Some(std::time::Instant::now())
            }
        ),
        Observed::Error {
            error: ObservationFailure::Timeout
        }
    ));
}
