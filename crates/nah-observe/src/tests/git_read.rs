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
                changes: vec![],
                user_configuration_changed: false,
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
    // A tracked file whose metadata alone changed makes porcelain diff
    // rewrite the index; the observation must leave the repository alone.
    fs::File::options()
        .write(true)
        .open(repo.join(".env.example"))
        .unwrap()
        .set_modified(std::time::UNIX_EPOCH)
        .unwrap();
    let index = || {
        let path = repo.join(".git/index");
        (
            fs::read(&path).unwrap(),
            fs::metadata(&path).unwrap().modified().unwrap(),
        )
    };
    let before = index();
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
    check(Addable, &repo, &[], &[], &[".env", "src/.pgpass"]);
    check(
        AddableAll,
        &repo,
        &[],
        &[],
        &[".env", ".env.local", "src/.pgpass"],
    );
    check(StagedDiff, &repo, &[], &[], &[]);
    assert!(index() == before, "a git read wrote the index");
    git(&["add", "."]);
    check(StagedDiff, &repo, &[], &[], &[".env", "src/.pgpass"]);
    fs::write(repo.join(".pgpass"), "TOKEN=untracked\n").unwrap();
    // Staged files have nothing left to add; an untracked one does, from
    // anywhere in the tree unless a pathspec narrows it.
    check(Addable, &repo.join("src"), &[], &[], &[".pgpass"]);
    check(Addable, &repo.join("src"), &["."], &[], &[]);
    check(AddableAll, &repo, &[], &[], &[".env.local", ".pgpass"]);
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
/// Status columns only say which side changed. A file staged and then
/// restored in the work tree is no change against `HEAD`, and a deleted
/// tracked file has no contents for `git add -u` to stage.
#[test]
fn status_selections_compare_contents_against_head() {
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
    for file in [".env", ".pgpass"] {
        fs::write(repo.join(file), "TOKEN=baseline\n").unwrap();
    }
    git(&["add", "."]);
    git(&["commit", "-qm", "credentials"]);
    fs::write(repo.join(".env"), "TOKEN=changed\n").unwrap();
    git(&["add", ".env"]);
    fs::write(repo.join(".env"), "TOKEN=baseline\n").unwrap();
    fs::remove_file(repo.join(".pgpass")).unwrap();
    let check = |kind, expected: &[&str]| {
        let observed = observe_git_read(
            &canonical(&repo),
            &GitReadSelection {
                kind,
                revisions: vec![],
                revision_options: vec![],
                pathspecs: vec![],
                pathspec_options: vec![],
                changes: vec![],
                user_configuration_changed: false,
            },
            Path::new("git"),
            GitWait::per_spawn(TEST_GIT_TIMEOUT),
        );
        let Observed::Ok { value } = observed else {
            panic!("{kind:?}: {observed:?}")
        };
        let expected = expected
            .iter()
            .map(|path| format!("{}/{path}", canonical(&repo)))
            .collect::<Vec<_>>();
        assert_eq!(
            value.iter().map(|path| path.as_str()).collect::<Vec<_>>(),
            expected,
            "{kind:?}"
        );
    };
    check(HeadDiff, &[".pgpass"]);
    check(StagedDiff, &[".env"]);
    check(Diff, &[".env", ".pgpass"]);
    check(AddableTracked, &[".env"]);
    // A commit of `.env` alone builds on `HEAD`, which the work tree matches.
    check(AddableHead, &[]);
}

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
        changes: vec![],
        user_configuration_changed: false,
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

/// A staging selection asked with the call's earlier changes answers for
/// the disk they leave: Git's ignore rules with their precedence and the
/// bytes an append joins to, the index for tracked-only staging, the
/// command's pathspecs and start directory, and a change that may not have
/// finished first leaving what it would remove.
#[test]
fn staging_after_changes_reads_git_rules_and_the_index() {
    use GitReadKind::*;
    use nah_proto::observation::{StagingChange, StagingOperation};
    let temp = tempfile::tempdir().unwrap();
    // A repository with `committed` files in its first commit, then
    // `untracked` files written beside them, `removed` ones deleted from
    // the work tree and `.git/info/exclude` holding `exclude`.
    let repository = |name: &str,
                      committed: &[(&str, &str)],
                      untracked: &[(&str, &str)],
                      removed: &[&str],
                      exclude: &str| {
        let repo = temp.path().join(name);
        init_repo(&repo);
        let write = |files: &[(&str, &str)]| {
            for (path, text) in files {
                let path = repo.join(path);
                fs::create_dir_all(path.parent().unwrap()).unwrap();
                fs::write(path, text).unwrap();
            }
        };
        write(committed);
        run(Command::new("git").current_dir(&repo).args(["add", "-A"]));
        run(Command::new("git").current_dir(&repo).args([
            "-c",
            "user.name=Nah Test",
            "-c",
            "user.email=nah@example.invalid",
            "commit",
            "-qm",
            "base",
            "--allow-empty",
        ]));
        write(untracked);
        for path in removed {
            fs::remove_file(repo.join(path)).unwrap();
        }
        fs::write(repo.join(".git/info/exclude"), exclude).unwrap();
        canonical(&repo)
    };
    let write = |path: &str, content: Option<&str>, append: bool| StagingChange {
        path: path.into(),
        operation: StagingOperation::Write {
            content: content.map(str::to_owned),
            append,
        },
        certain: true,
    };
    let delete = |path: &str, certain: bool| StagingChange {
        path: path.into(),
        operation: StagingOperation::Delete { recursive: false },
        certain,
    };
    // With `configuration_changed`, as for a call that names its own
    // global configuration file.
    let check_with = |configuration_changed: bool,
                      repo: &str,
                      directory: &str,
                      kind,
                      pathspecs: &[&str],
                      changes: Vec<StagingChange>,
                      expected: &[&str]| {
        let observed = observe_git_read(
            &format!("{repo}{directory}"),
            &GitReadSelection {
                kind,
                revisions: vec![],
                revision_options: vec![],
                pathspecs: pathspecs.iter().map(|path| (*path).into()).collect(),
                pathspec_options: vec![],
                changes: changes.clone(),
                user_configuration_changed: configuration_changed,
            },
            Path::new("git"),
            GitWait::per_spawn(TEST_GIT_TIMEOUT),
        );
        let Observed::Ok { value } = observed else {
            panic!("{changes:?}: {observed:?}")
        };
        assert_eq!(
            value.iter().map(|path| path.as_str()).collect::<Vec<_>>(),
            expected
                .iter()
                .map(|path| format!("{repo}/{path}"))
                .collect::<Vec<_>>(),
            "{changes:?}"
        );
    };
    let check = |repo: &str,
                 directory: &str,
                 kind,
                 pathspecs: &[&str],
                 changes: Vec<StagingChange>,
                 expected: &[&str]| {
        check_with(false, repo, directory, kind, pathspecs, changes, expected)
    };
    let env = [(".env", "STAND_IN=1\n")];
    let ignored = repository(
        "ignored",
        &[(".gitignore", ".env\n"), ("sub/keep", "")],
        &env,
        &[],
        "",
    );
    let at = |path: &str| format!("{ignored}/{path}");
    // Removing the rule, or a removal that may not have run, takes `.env`;
    // rewriting it with the rule kept, or adding it to `info/exclude`, does
    // not.
    for certain in [true, false] {
        check(
            &ignored,
            "",
            Addable,
            &[],
            vec![delete(&at(".gitignore"), certain)],
            &[".env"],
        );
    }
    check(
        &ignored,
        "",
        Addable,
        &[],
        vec![write(&at(".gitignore"), Some("dist/\n.env\n"), false)],
        &[".gitignore"],
    );
    check(
        &ignored,
        "",
        Addable,
        &[],
        vec![write(&at(".git/info/exclude"), Some(".env\n"), true)],
        &[],
    );
    // A write that may not have run first leaves `.env` out only when the
    // rules leave it out both before and after it, and a rewrite that may
    // have failed may leave the file empty.
    let uncertain = |path: &str, content: &str, append: bool| StagingChange {
        certain: false,
        ..write(path, Some(content), append)
    };
    check(
        &ignored,
        "",
        Addable,
        &[],
        vec![uncertain(&at(".gitignore"), "dist/\n", true)],
        &[".gitignore"],
    );
    for (content, append) in [("!.env\n", true), (".env\n", false)] {
        check(
            &ignored,
            "",
            Addable,
            &[],
            vec![uncertain(&at(".gitignore"), content, append)],
            &[".env", ".gitignore"],
        );
    }
    // However many such appends there are, and whatever other files they
    // reach.
    check(
        &ignored,
        "",
        Addable,
        &[],
        (0..12)
            .flat_map(|index| {
                [
                    uncertain(&at(".gitignore"), &format!("build-{index}/\n"), true),
                    uncertain(&at("sample.ignore"), &format!("out-{index}/\n"), true),
                ]
            })
            .collect(),
        &[".gitignore", "sample.ignore"],
    );
    // The excludes file the repository's own configuration names, relative
    // to the top level, still decides once the call names other global
    // configuration, and while the call writes another file first.
    let local = repository("local", &[("README.md", "")], &env, &[], "");
    run(Command::new("git").current_dir(&local).args([
        "config",
        "core.excludesFile",
        "local.ignore",
    ]));
    fs::write(Path::new(&local).join("local.ignore"), ".env\n").unwrap();
    let notes = format!("{local}/notes.txt");
    for configuration_changed in [false, true] {
        for changes in [vec![], vec![write(&notes, None, false)]] {
            let expected: &[&str] = if changes.is_empty() {
                &[]
            } else {
                &["notes.txt"]
            };
            check_with(
                configuration_changed,
                &local,
                "",
                Addable,
                &[],
                changes,
                expected,
            );
        }
    }
    // A rule file whose new text is not known may re-include anything.
    check(
        &ignored,
        "",
        Addable,
        &[],
        vec![write(&at(".gitignore"), None, false)],
        &[".env", ".gitignore"],
    );
    // From a subdirectory a whole-tree add still takes the top level; an
    // excluding pathspec and an ignore rule leave a written file out.
    check(
        &ignored,
        "/sub",
        Addable,
        &[],
        vec![write(&at("f.txt"), None, false)],
        &["f.txt"],
    );
    check(
        &ignored,
        "",
        Addable,
        &[":(exclude)f.txt"],
        vec![write(&at("f.txt"), None, false)],
        &[],
    );
    check(
        &ignored,
        "",
        Addable,
        &[],
        vec![write(&at("sub/.env"), None, false)],
        &[],
    );
    // An append joins the bytes already there: `dist` without a final
    // newline becomes `dist.env`.
    let joined = repository("joined", &[(".gitignore", "dist")], &env, &[], "");
    check(
        &joined,
        "",
        Addable,
        &[],
        vec![write(&format!("{joined}/.gitignore"), Some(".env\n"), true)],
        &[".env", ".gitignore"],
    );
    // A nearer `!` rule keeps re-including what a new top-level rule names.
    let nested = repository(
        "nested",
        &[(".gitignore", "dist/\n"), ("sub/.gitignore", "!.env\n")],
        &[("sub/.env", "STAND_IN=1\n")],
        &[],
        "",
    );
    check(
        &nested,
        "",
        Addable,
        &[],
        vec![write(&format!("{nested}/.gitignore"), Some(".env\n"), true)],
        &[".gitignore", "sub/.env"],
    );
    // `info/exclude` still leaves out what a removed `.gitignore` did not.
    let excluded = repository(
        "excluded",
        &[(".gitignore", "dist/\n")],
        &env,
        &[],
        ".env\n",
    );
    check(
        &excluded,
        "",
        Addable,
        &[],
        vec![delete(&format!("{excluded}/.gitignore"), true)],
        &[],
    );
    // Tracked-only staging asks the index, not the disk: a tracked file
    // written again after it went missing is staged, an untracked one is
    // not.
    let tracked = repository("tracked", &env, &[], &[".env"], "");
    let at = |path: &str| format!("{tracked}/{path}");
    check(
        &tracked,
        "",
        AddableTracked,
        &[],
        vec![
            write(&at(".env"), None, false),
            write(&at("f.txt"), None, false),
        ],
        &[".env"],
    );
    // Removing a link removes the link, never the file it points to.
    #[cfg(unix)]
    {
        let linked = repository("linked", &[], &env, &[], "");
        std::os::unix::fs::symlink(".env", format!("{linked}/alias.txt")).unwrap();
        check(
            &linked,
            "",
            Addable,
            &[],
            vec![delete(&format!("{linked}/alias.txt"), true)],
            &[".env"],
        );
    }
}
