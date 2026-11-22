use super::support::{canonical, init_repo, run};
use crate::TEST_GIT_TIMEOUT;
use crate::git_state::observe_git_state;
use crate::roots::GitWait;
use nah_proto::observation::{GitCleanIgnored, GitRestoreSource, GitStateObservation, Observed};
use std::fs;
use std::path::Path;
use std::process::Command;

fn observe(
    directory: &Path,
    pathspecs: &[&str],
    pathspec_options: &[&str],
    restores: Option<&GitRestoreSource>,
    untracked: Option<GitCleanIgnored>,
) -> Observed<GitStateObservation> {
    let owned = |words: &[&str]| {
        words
            .iter()
            .map(|word| (*word).to_owned())
            .collect::<Vec<_>>()
    };
    observe_git_state(
        directory.to_str().expect("unicode test path"),
        &owned(pathspecs),
        &owned(pathspec_options),
        restores,
        untracked,
        false,
        &[],
        &[],
        Path::new("git"),
        GitWait::per_spawn(TEST_GIT_TIMEOUT),
    )
}

fn tree(revision: &str) -> GitRestoreSource {
    GitRestoreSource::Tree(revision.into())
}

/// Whether a copy from `source` over the whole tree, or what `pathspecs`
/// match, changes nothing.
fn restores_nothing(
    directory: &Path,
    pathspecs: &[&str],
    pathspec_options: &[&str],
    source: &GitRestoreSource,
) -> bool {
    match observe(directory, pathspecs, pathspec_options, Some(source), None) {
        Observed::Ok { value } => value.restores_nothing().expect("asked"),
        Observed::Error { error } => panic!("{pathspecs:?} is observable: {error:?}"),
    }
}

/// Whether Git lists an untracked entry of `kind`.
fn lists_untracked(directory: &Path, pathspecs: &[&str], kind: GitCleanIgnored) -> bool {
    match observe(directory, pathspecs, &[], None, Some(kind)) {
        Observed::Ok { value } => value.untracked().expect("asked"),
        Observed::Error { error } => panic!("{kind:?} is observable: {error:?}"),
    }
}

fn commit(repo: &Path, message: &str) {
    run(Command::new("git").args(["add", "-A"]).current_dir(repo));
    run(Command::new("git")
        .args([
            "-c",
            "user.name=Nah Test",
            "-c",
            "user.email=nah@example.invalid",
            "commit",
            "-qm",
            message,
        ])
        .current_dir(repo));
}

/// A discard is delegated on this answer, so every way a copy could change
/// a tracked file must answer that it does: a staged rename, an edit the
/// index hides (assume-unchanged), one outside the subfolder a discard runs
/// in, whatever `diff.relative` says, and a stash entry; and every kind of
/// untracked entry must be listed: an untracked file, an ignored file, a
/// directory ignored as a whole.
#[test]
fn uncommitted_state_is_told_apart_from_a_clean_repository() {
    let temp = tempfile::tempdir().expect("tempdir");
    let repo = temp.path().join("repo");
    init_repo(&repo);
    fs::write(repo.join(".gitignore"), "target/\n.env\n").expect("ignore rules");
    commit(&repo, "ignore");
    let head = tree("HEAD");

    let Observed::Ok { value: clean } =
        observe(&repo, &[], &[], Some(&head), Some(GitCleanIgnored::Also))
    else {
        panic!("a clean repository is observable")
    };
    assert_eq!(clean.restores_nothing(), Some(true));
    assert_eq!(clean.untracked(), Some(false));
    assert!(!clean.stash_entries());
    assert!(matches!(
        observe(&repo, &[], &[], None, None),
        Observed::Ok { value } if value.restores_nothing().is_none() && value.untracked().is_none()
    ));

    fs::write(repo.join("tracked"), "two\n").expect("edit");
    run(Command::new("git").args(["stash", "-q"]).current_dir(&repo));
    run(Command::new("git")
        .args(["mv", "tracked", "renamed"])
        .current_dir(&repo));
    let Observed::Ok { value: dirty } = observe(&repo, &[], &[], Some(&head), None) else {
        panic!("a dirty repository is observable")
    };
    assert_eq!(dirty.restores_nothing(), Some(false));
    assert!(dirty.stash_entries());
    // The rename is staged: its working copy equals the index.
    assert!(restores_nothing(&repo, &[], &[], &GitRestoreSource::Index));

    fs::write(repo.join("draft.md"), "draft\n").expect("untracked file");
    assert!(lists_untracked(&repo, &[], GitCleanIgnored::No));
    assert!(!lists_untracked(&repo, &[], GitCleanIgnored::Only));
    fs::remove_file(repo.join("draft.md")).expect("remove untracked");
    fs::write(repo.join(".env"), "TOKEN=1\n").expect("ignored file");
    assert!(lists_untracked(&repo, &[], GitCleanIgnored::Only));
    assert!(!lists_untracked(&repo, &[], GitCleanIgnored::No));
    fs::remove_file(repo.join(".env")).expect("remove ignored");
    fs::create_dir(repo.join("target")).expect("ignored directory");
    fs::write(repo.join("target/out"), "out\n").expect("build output");
    assert!(lists_untracked(&repo, &[], GitCleanIgnored::Also));

    assert!(matches!(
        observe(temp.path(), &[], &[], Some(&head), None),
        Observed::Error { .. }
    ));

    // An edit to an assume-unchanged file is invisible to comparison, and a
    // checkout overwrites it.
    let hidden = temp.path().join("hidden");
    init_repo(&hidden);
    run(Command::new("git")
        .args(["update-index", "--assume-unchanged", "tracked"])
        .current_dir(&hidden));
    fs::write(hidden.join("tracked"), "local\n").expect("hidden edit");
    assert!(!restores_nothing(
        &hidden,
        &[],
        &[],
        &GitRestoreSource::Index
    ));

    // A discard run in a subdirectory acts on the whole repository, so the
    // state read from there is the repository's: its top level, and an edit
    // that lies outside the subdirectory, even where `diff.relative` would
    // leave it out of a diff run there.
    let nested = temp.path().join("nested");
    init_repo(&nested);
    fs::create_dir(nested.join("crates")).expect("subdirectory");
    let Observed::Ok { value: below } =
        observe(&nested.join("crates"), &[], &[], Some(&head), None)
    else {
        panic!("a subdirectory is observable")
    };
    assert_eq!(below.top_level().as_str(), canonical(&nested));
    assert_eq!(below.restores_nothing(), Some(true));
    run(Command::new("git")
        .args(["config", "diff.relative", "true"])
        .current_dir(&nested));
    fs::write(nested.join("tracked"), "local\n").expect("edit above");
    assert!(!restores_nothing(&nested.join("crates"), &[], &[], &head));
}

/// A discard limited to pathspecs runs when nothing they reach would
/// change, so the limited answer must be Git's own match of them: a change
/// outside leaves it unchanged, while a change Git matches by a glob,
/// without regard to case, or hidden from comparison shows, as does a copy
/// from `HEAD` over a staged edit that a copy from the index keeps.
#[test]
fn pathspecs_limit_the_state_to_what_git_matches() {
    let temp = tempfile::tempdir().expect("tempdir");
    let repo = temp.path().join("repo");
    init_repo(&repo);
    fs::create_dir(repo.join("src")).expect("source folder");
    fs::write(repo.join("src/lib.rs"), "one\n").expect("source file");
    commit(&repo, "source");
    let index = GitRestoreSource::Index;
    fs::write(repo.join("src/lib.rs"), "staged\n").expect("staged edit");
    run(Command::new("git").args(["add", "src"]).current_dir(&repo));
    assert!(restores_nothing(&repo, &["src"], &[], &index));
    assert!(!restores_nothing(&repo, &["src"], &[], &tree("HEAD")));
    fs::write(repo.join("src/lib.rs"), "two\n").expect("edit");
    let changed =
        |pathspecs: &[&str], options: &[&str]| !restores_nothing(&repo, pathspecs, options, &index);
    assert!(!changed(&["tracked"], &[]));
    assert!(changed(&["src"], &[]));
    assert!(changed(&["tracked", "*.rs"], &[]));
    assert!(!changed(&["SRC/LIB.RS"], &[]));
    assert!(changed(&["SRC/LIB.RS"], &["--icase-pathspecs"]));
    assert!(!changed(&["*.rs"], &["--literal-pathspecs"]));
    fs::write(repo.join("draft.md"), "draft\n").expect("untracked file");
    assert!(lists_untracked(&repo, &["draft.md"], GitCleanIgnored::No));
    assert!(!lists_untracked(&repo, &["src"], GitCleanIgnored::No));
    assert!(matches!(
        observe(
            &repo,
            &["tracked"],
            &["-c", "core.pager=true"],
            Some(&index),
            None
        ),
        Observed::Error { .. }
    ));

    run(Command::new("git")
        .args(["update-index", "--skip-worktree", "tracked"])
        .current_dir(&repo));
    fs::write(repo.join("tracked"), "local\n").expect("hidden edit");
    assert!(changed(&["tracked"], &[]));
}

/// A copy from another tree changes nothing only where the index and the
/// working copy already hold that tree, and an index whose paths could
/// name one file on a case-folding filesystem, or that a normalizing one
/// may spell otherwise, answers that it may, as does a file Git converts on
/// its way to the working tree.
#[test]
fn a_copy_from_another_tree_and_doubtful_paths() {
    let temp = tempfile::tempdir().expect("tempdir");
    let repo = temp.path().join("repo");
    init_repo(&repo);
    run(Command::new("git")
        .args(["branch", "other"])
        .current_dir(&repo));
    assert!(restores_nothing(&repo, &[], &[], &tree("other")));
    run(Command::new("git")
        .args(["checkout", "-q", "other"])
        .current_dir(&repo));
    fs::write(repo.join("added"), "other\n").expect("file of other");
    commit(&repo, "other");
    run(Command::new("git")
        .args(["checkout", "-q", "-"])
        .current_dir(&repo));
    assert!(!restores_nothing(&repo, &[], &[], &tree("other")));
    assert!(matches!(
        observe(&repo, &[], &[], Some(&tree("missing")), None),
        Observed::Error { .. }
    ));

    let blob = {
        let output = Command::new("git")
            .args(["hash-object", "-w", "tracked"])
            .current_dir(&repo)
            .output()
            .expect("hash-object");
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    };
    for path in ["TRACKED", "caf\u{e9}"] {
        run(Command::new("git")
            .args(["update-index", "--add", "--cacheinfo"])
            .arg(format!("100644,{blob},{path}"))
            .current_dir(&repo));
        assert!(!restores_nothing(&repo, &[], &[], &GitRestoreSource::Index));
        run(Command::new("git")
            .args(["update-index", "--force-remove", path])
            .current_dir(&repo));
    }

    let index = GitRestoreSource::Index;
    for (attributes, converts) in [
        ("tracked text eol=lf\n", true),
        ("tracked filter=lfs\n", true),
        ("tracked working-tree-encoding=UTF-16\n", true),
        ("tracked ident\n", true),
        ("tracked -text -filter\n", false),
    ] {
        fs::write(repo.join(".gitattributes"), attributes).expect("attributes");
        assert_eq!(
            restores_nothing(&repo, &["tracked"], &[], &index),
            !converts,
            "{attributes}"
        );
    }
    fs::remove_file(repo.join(".gitattributes")).expect("remove attributes");
    run(Command::new("git")
        .args(["config", "core.autocrlf", "input"])
        .current_dir(&repo));
    assert!(!restores_nothing(&repo, &["tracked"], &[], &index));
}

/// Git observations leave a dataless File Provider item unobserved: a
/// repository whose `.git/config` is dataless is not handed to Git to find,
/// a stash reference Git could not read is not taken as no stash, and, on
/// macOS, a run in which Git reports it could not read an item is not an
/// answer.
#[test]
fn git_observations_leave_dataless_items_unobserved() {
    use crate::io_paths::simulated::make_dataless;

    let temp = tempfile::tempdir().expect("tempdir");
    let repo = fs::canonicalize(temp.path()).unwrap().join("repo");
    init_repo(&repo);
    let located = |repo: &Path| {
        crate::roots::locate_repository(
            repo,
            Path::new("git"),
            GitWait::per_spawn(TEST_GIT_TIMEOUT),
        )
    };
    let other = fs::canonicalize(temp.path()).unwrap().join("other");
    init_repo(&other);
    assert!(matches!(located(&other), Ok(Some(_))));
    make_dataless(&other.join(".git/config"));
    assert!(located(&other).is_err());

    // Git answers a stash reference it cannot read as absent, as it answers
    // one whose read the kernel refuses because it is dataless; here the
    // reference is unreadable by its permissions.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let stashed = fs::canonicalize(temp.path()).unwrap().join("stashed");
        init_repo(&stashed);
        fs::write(stashed.join("tracked"), "two\n").expect("edit");
        run(Command::new("git")
            .args([
                "-c",
                "user.name=Nah Test",
                "-c",
                "user.email=nah@example.invalid",
                "stash",
                "-q",
            ])
            .current_dir(&stashed));
        assert!(matches!(
            observe(&stashed, &[], &[], None, None),
            Observed::Ok { value } if value.stash_entries()
        ));
        let reference = stashed.join(".git/refs/stash");
        fs::set_permissions(&reference, fs::Permissions::from_mode(0o000)).unwrap();
        let unreadable = observe(&stashed, &[], &[], None, None);
        fs::set_permissions(&reference, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(unreadable, Observed::Error { .. }));
    }

    #[cfg(target_os = "macos")]
    {
        use std::os::unix::fs::PermissionsExt;
        let refusing_git = temp.path().join("refusing-git");
        fs::write(
            &refusing_git,
            "#!/bin/sh\necho \"warning: could not open directory 'cloud/': Resource deadlock avoided\" >&2\nexit 0\n",
        )
        .unwrap();
        fs::set_permissions(&refusing_git, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(
            crate::git_state::git_exit_and_output(
                &refusing_git,
                repo.to_str().unwrap(),
                &["status"],
                1024,
                GitWait::per_spawn(TEST_GIT_TIMEOUT),
                &[],
            )
            .is_err()
        );
    }
}

/// Git's own comparison trusts a file's metadata: an edit that keeps the
/// size and the timestamp the index recorded reads as clean to it. The
/// working copy's bytes decide here, and a symlink's target does.
#[test]
fn working_copies_are_judged_by_their_bytes() {
    let temp = tempfile::tempdir().expect("tempdir");
    let repo = temp.path().join("repo");
    init_repo(&repo);
    let file = repo.join("dated");
    fs::write(&file, "one\n").expect("file");
    let old = std::time::SystemTime::now() - std::time::Duration::from_secs(600);
    let stamp = |file: &Path| {
        fs::File::options()
            .write(true)
            .open(file)
            .expect("open")
            .set_modified(old)
            .expect("set mtime");
    };
    stamp(&file);
    #[cfg(unix)]
    std::os::unix::fs::symlink("dated", repo.join("link")).expect("symlink");
    commit(&repo, "dated");
    run(Command::new("git")
        .args(["config", "core.checkStat", "minimal"])
        .current_dir(&repo));
    run(Command::new("git")
        .args(["config", "core.trustctime", "false"])
        .current_dir(&repo));
    let index = GitRestoreSource::Index;
    assert!(restores_nothing(&repo, &[], &[], &index));

    fs::write(&file, "two\n").expect("same-size edit");
    stamp(&file);
    let git_sees = Command::new("git")
        .args(["diff-files", "--quiet"])
        .current_dir(&repo)
        .status()
        .expect("diff-files");
    assert!(git_sees.success(), "Git's comparison should miss the edit");
    assert!(!restores_nothing(&repo, &[], &[], &index));
    fs::write(&file, "one\n").expect("restore");
    stamp(&file);

    #[cfg(unix)]
    {
        fs::remove_file(repo.join("link")).expect("remove link");
        std::os::unix::fs::symlink("elsewhere", repo.join("link")).expect("retarget");
        assert!(!restores_nothing(&repo, &["link"], &[], &index));
    }
}

/// A rebase, amend or reset delegates where Git records the move in a
/// reflog: `core.logAllRefUpdates=false` still appends to a reflog that
/// exists and creates none, and a `gc.*reflogExpire` setting may expire the
/// entry early. A forced `filter-branch` delegates where no backup exists,
/// and a reset where its target already reaches `HEAD`'s commit.
#[test]
fn history_observation_tells_whether_a_reflog_or_backup_keeps_a_move() {
    let temp = tempfile::tempdir().expect("tempdir");
    let history_with = |repo: &Path, targets: &[String]| {
        match observe_git_state(
            repo.to_str().expect("unicode test path"),
            &[],
            &[],
            None,
            None,
            true,
            targets,
            &[],
            Path::new("git"),
            GitWait::per_spawn(TEST_GIT_TIMEOUT),
        ) {
            Observed::Ok { value } => value.history().cloned().expect("history was asked for"),
            // Which repository, under which of its own settings, and why, so a
            // failure on a loaded host can be told from a wrong answer.
            other => panic!(
                "{} is observable with {:?}, got {other:?}",
                repo.display(),
                String::from_utf8_lossy(
                    &Command::new("git")
                        .args(["config", "--local", "--list"])
                        .current_dir(repo)
                        .output()
                        .map(|output| output.stdout)
                        .unwrap_or_default()
                )
            ),
        }
    };
    let history = |repo: &Path| history_with(repo, &[]);
    let git = |repo: &Path, args: &[&str]| run(Command::new("git").args(args).current_dir(repo));

    let logged = temp.path().join("logged");
    init_repo(&logged);
    git(&logged, &["config", "core.logAllRefUpdates", "false"]);
    let observed = history(&logged);
    // Only the reflog that exists keeps the move, which a hook may remove.
    assert!(observed.moves_logged && !observed.creates_reflogs && !observed.backups);
    git(&logged, &["config", "gc.reflogExpire", "now"]);
    assert!(!history(&logged).moves_logged);
    // Ninety days keeps the replaced entry longer than Git's default for
    // it; a day does not.
    git(&logged, &["config", "gc.reflogExpire", "90.days.ago"]);
    assert!(history(&logged).moves_logged);
    git(
        &logged,
        &["config", "gc.reflogExpireUnreachable", "1.day.ago"],
    );
    assert!(!history(&logged).moves_logged);
    git(
        &logged,
        &["config", "--unset", "gc.reflogExpireUnreachable"],
    );
    git(&logged, &["config", "--unset", "gc.reflogExpire"]);
    git(
        &logged,
        &["update-ref", "refs/original/refs/heads/main", "HEAD"],
    );
    assert!(history(&logged).backups);

    let unlogged = temp.path().join("unlogged");
    fs::create_dir_all(&unlogged).expect("repo directory");
    git(&unlogged, &["init", "-q"]);
    git(&unlogged, &["config", "core.logAllRefUpdates", "false"]);
    git(
        &unlogged,
        &[
            "-c",
            "user.name=Nah Test",
            "-c",
            "user.email=nah@example.invalid",
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            "initial",
        ],
    );
    assert!(!history(&unlogged).moves_logged);
    git(&unlogged, &["branch", "behind"]);
    git(
        &unlogged,
        &[
            "-c",
            "user.name=Nah Test",
            "-c",
            "user.email=nah@example.invalid",
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            "second",
        ],
    );
    git(&unlogged, &["branch", "ahead"]);
    git(&unlogged, &["reset", "-q", "--soft", "behind"]);
    let targets = ["ahead", "behind", "missing", "--all"].map(String::from);
    assert_eq!(
        history_with(&unlogged, &targets).targets_holding_head,
        ["ahead", "behind"]
    );

    let default = temp.path().join("default");
    init_repo(&default);
    assert!(history(&default).creates_reflogs);
}

/// Git matches a deleted path by its bytes, so a path the filesystem
/// reaches only through another spelling, as one that folds case reaches
/// `Éclair` through `éclair`, restores something; one spelled as listed,
/// or missing, does not.
#[test]
fn a_path_spelled_unlike_its_listing_restores_something() {
    let temp = tempfile::tempdir().expect("tempdir");
    let repo = Path::new(&canonical(temp.path())).join("repo");
    init_repo(&repo);
    fs::create_dir(repo.join("Éclair")).expect("folder");
    let changed = |name: &str| {
        let pathspec = format!(":(literal,icase){}", repo.join(name).display());
        !restores_nothing(&repo, &[&pathspec], &[], &tree("HEAD"))
    };
    assert!(!changed("Éclair"));
    assert!(!changed("missing"));
    if repo.join("éclair").exists() {
        assert!(changed("éclair"));
    }
}
