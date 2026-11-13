use super::support::{canonical, init_repo, request, run, value};
use crate::fulfill_observation_request;
#[cfg(unix)]
use crate::roots::{GitWait, config_keeps_work_tree, plain_directory_repository};
#[cfg(unix)]
use crate::{DecisionObservation, TEST_GIT_TIMEOUT, fulfill_with_git};
use nah_proto::observation::{
    ObservationFailure, ObservationValue, Observed, ProjectGuardDeclaration, RootKind,
};
use std::fs;
use std::path::Path;
use std::process::Command;
#[cfg(unix)]
use std::time::{Duration, Instant};

#[test]
fn ordinary_non_repository_has_a_successful_empty_root_set() {
    let temp = tempfile::tempdir().expect("tempdir");
    let observation = fulfill_observation_request(&request(temp.path(), &[])).expect("observation");
    assert!(matches!(
        value(&observation, "roots"),
        ObservationValue::Roots {
            observed: Observed::Ok { value }
        } if value.is_empty()
    ));
    assert_eq!(
        observation.project_guard_declaration().unwrap(),
        &ProjectGuardDeclaration::Absent
    );
}

#[test]
fn linked_worktree_reports_distinct_project_and_main_roots() {
    let temp = tempfile::tempdir().expect("tempdir");
    let main = temp.path().join("main");
    let worktree = temp.path().join("linked");
    init_repo(&main);
    run(Command::new("git")
        .args([
            "worktree",
            "add",
            "-qb",
            "linked",
            worktree.to_str().unwrap(),
        ])
        .current_dir(&main));

    let observation = fulfill_observation_request(&request(&worktree, &[])).expect("observation");
    let ObservationValue::Roots {
        observed: Observed::Ok { value: roots },
    } = value(&observation, "roots")
    else {
        panic!("expected roots");
    };

    assert_eq!(roots.len(), 2);
    assert!(roots.iter().any(|root| {
        root.kind() == RootKind::Project && root.path().as_str() == canonical(&worktree)
    }));
    assert!(roots.iter().any(|root| {
        root.kind() == RootKind::WorktreeMain && root.path().as_str() == canonical(&main)
    }));
}

#[test]
fn linked_worktree_requires_a_matching_gitdir_back_pointer() {
    let temp = tempfile::tempdir().expect("tempdir");
    let main = temp.path().join("main");
    let worktree = temp.path().join("linked");
    init_repo(&main);
    run(Command::new("git")
        .args([
            "worktree",
            "add",
            "-qb",
            "linked",
            worktree.to_str().unwrap(),
        ])
        .current_dir(&main));

    let pointer = fs::read_to_string(worktree.join(".git")).expect("gitdir pointer");
    let gitdir = pointer
        .trim()
        .strip_prefix("gitdir:")
        .expect("gitdir prefix")
        .trim();
    fs::write(
        Path::new(gitdir).join("gitdir"),
        main.join(".git").to_string_lossy().as_bytes(),
    )
    .expect("tamper backlink");

    let observation = fulfill_observation_request(&request(&worktree, &[])).expect("observation");
    assert!(matches!(
        value(&observation, "roots"),
        ObservationValue::Roots {
            observed: Observed::Error {
                error: ObservationFailure::InvalidPath
            }
        }
    ));
}

#[test]
fn configured_worktree_cannot_expand_the_project_root() {
    let temp = tempfile::tempdir().expect("tempdir");
    let repo = temp.path().join("repo");
    let outside = temp.path().join("outside");
    init_repo(&repo);
    fs::create_dir(&outside).expect("outside");
    run(Command::new("git")
        .args(["config", "core.worktree", outside.to_str().unwrap()])
        .current_dir(&repo));

    let observation = fulfill_observation_request(&request(&repo, &[])).expect("observation");
    assert!(matches!(
        value(&observation, "roots"),
        ObservationValue::Roots {
            observed: Observed::Error {
                error: ObservationFailure::InvalidPath
            }
        }
    ));
}

/// A `.git` directory Git would take becomes a root without Git. A `.git`
/// file still needs Git, and fails closed when Git is missing, stalls, or
/// answers with a relative top level.
#[cfg(unix)]
#[test]
fn directory_repository_needs_no_git_and_gitfile_fails_closed_without_it() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().expect("tempdir");
    let main = temp.path().join("main");
    let worktree = temp.path().join("linked");
    init_repo(&main);
    run(Command::new("git")
        .args([
            "worktree",
            "add",
            "-qb",
            "linked",
            worktree.to_str().unwrap(),
        ])
        .current_dir(&main));
    let missing_git = temp.path().join("does-not-exist");

    let plain = fulfill_with_git(
        &request(&main, &[]),
        &missing_git,
        Duration::from_millis(50),
    )
    .expect("directory repository observation");
    let ObservationValue::Roots {
        observed: Observed::Ok { value: roots },
    } = value(&plain, "roots")
    else {
        panic!("a directory repository needs no git");
    };
    assert!(matches!(
        roots.as_slice(),
        [root] if root.kind() == RootKind::Project && root.path().as_str() == canonical(&main)
    ));

    let request = request(&worktree, &[]);
    let missing = fulfill_with_git(&request, &missing_git, Duration::from_millis(50))
        .expect("missing git observation");
    assert!(matches!(
        value(&missing, "roots"),
        ObservationValue::Roots {
            observed: Observed::Error {
                error: ObservationFailure::Unavailable
            }
        }
    ));
    assert_eq!(
        missing.project_guard_declaration().unwrap(),
        &ProjectGuardDeclaration::ReadFailure
    );

    let slow_git = temp.path().join("slow-git");
    fs::write(&slow_git, "#!/bin/sh\nexec sleep 5\n").unwrap();
    fs::set_permissions(&slow_git, fs::Permissions::from_mode(0o755)).unwrap();
    let slow = fulfill_with_git(&request, &slow_git, Duration::from_millis(20))
        .expect("slow git observation");
    assert!(matches!(
        value(&slow, "roots"),
        ObservationValue::Roots {
            observed: Observed::Error {
                error: ObservationFailure::Timeout
            }
        }
    ));

    let relative_git = temp.path().join("relative-git");
    fs::write(
        &relative_git,
        "#!/bin/sh\nprintf 'relative-root\\n.git\\n'\n",
    )
    .unwrap();
    fs::set_permissions(&relative_git, fs::Permissions::from_mode(0o755)).unwrap();
    let relative = fulfill_with_git(&request, &relative_git, Duration::from_secs(1))
        .expect("relative git observation");
    assert!(matches!(
        value(&relative, "roots"),
        ObservationValue::Roots {
            observed: Observed::Error {
                error: ObservationFailure::InvalidPath
            }
        }
    ));

    // Missing the common directory must not establish a project root.
    let short_git = temp.path().join("short-git");
    fs::write(
        &short_git,
        format!("#!/bin/sh\nprintf '%s\\n' '{}'\n", canonical(&worktree)),
    )
    .unwrap();
    fs::set_permissions(&short_git, fs::Permissions::from_mode(0o755)).unwrap();
    let short = fulfill_with_git(&request, &short_git, Duration::from_secs(1))
        .expect("short git observation");
    assert!(matches!(
        value(&short, "roots"),
        ObservationValue::Roots {
            observed: Observed::Error {
                error: ObservationFailure::Unavailable
            }
        }
    ));
}

/// The filesystem alone makes a root only of a `.git` directory Git would
/// take: one holding only `HEAD`, one another user owns, or one below a
/// directory that may be a repository itself is left to Git.
#[cfg(unix)]
#[test]
fn git_rejected_directories_are_not_roots_without_git() {
    let temp = tempfile::tempdir().expect("tempdir");
    let head_only = temp.path().join("head-only");
    fs::create_dir_all(head_only.join(".git")).unwrap();
    fs::write(head_only.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
    let observation = fulfill_with_git(
        &request(&head_only, &[]),
        &temp.path().join("does-not-exist"),
        Duration::from_millis(50),
    )
    .expect("head-only observation");
    assert!(matches!(
        value(&observation, "roots"),
        ObservationValue::Roots {
            observed: Observed::Error {
                error: ObservationFailure::Unavailable
            }
        }
    ));

    let repo = temp.path().join("repo");
    init_repo(&repo);
    let repo = fs::canonicalize(repo).unwrap();
    // SAFETY: `geteuid` has no preconditions and cannot fail.
    let owner = unsafe { libc::geteuid() };
    assert!(plain_directory_repository(&repo, &repo, owner));
    assert!(!plain_directory_repository(&repo, &repo, owner + 1));
    // Git needs to search `objects` and `refs`, which root always may.
    if owner != 0 {
        use std::os::unix::fs::PermissionsExt;

        for name in ["objects", "refs"] {
            let directory = repo.join(".git").join(name);
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o600)).unwrap();
            let accepted = plain_directory_repository(&repo, &repo, owner);
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
            assert!(!accepted, "unsearchable {name}");
        }
        assert!(plain_directory_repository(&repo, &repo, owner));
    }
    fs::create_dir(repo.join("nested")).unwrap();
    fs::write(repo.join("nested/HEAD"), "ref: refs/heads/main\n").unwrap();
    assert!(!plain_directory_repository(
        &repo.join("nested"),
        &repo,
        owner
    ));
    // Git skips only ASCII space after `ref:`, so a no-break space makes the
    // `.git` invalid.
    fs::write(repo.join(".git/HEAD"), "ref:\u{a0}refs/heads/main\n").unwrap();
    assert!(!plain_directory_repository(&repo, &repo, owner));
    // Git reads only HEAD's first 255 bytes, so the reference must start
    // within them.
    for (spaces, accepted) in [(246, true), (247, false)] {
        let head = format!("ref:{}refs/heads/main\n", " ".repeat(spaces));
        fs::write(repo.join(".git/HEAD"), head).unwrap();
        assert_eq!(
            plain_directory_repository(&repo, &repo, owner),
            accepted,
            "{spaces} spaces"
        );
    }
}

/// The root shortcut promises the marker directory, not Git's acceptance: an
/// invalid value of an unrelated setting makes Git refuse the repository, and
/// it is still the project root without Git.
#[cfg(unix)]
#[test]
fn repository_git_refuses_for_an_unrelated_setting_is_still_the_project_root() {
    let temp = tempfile::tempdir().expect("tempdir");
    let repo = temp.path().join("repo");
    init_repo(&repo);
    run(Command::new("git")
        .args(["config", "core.filemode", "invalid"])
        .current_dir(&repo));
    let refused = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .current_dir(&repo)
        .output()
        .expect("git rev-parse");
    assert!(
        !refused.status.success(),
        "git refuses core.filemode=invalid"
    );

    let observation = fulfill_with_git(
        &request(&repo, &[]),
        &temp.path().join("does-not-exist"),
        Duration::from_millis(50),
    )
    .expect("observation");
    assert!(matches!(
        value(&observation, "roots"),
        ObservationValue::Roots {
            observed: Observed::Ok { value }
        } if matches!(
            value.as_slice(),
            [root] if root.kind() == RootKind::Project && root.path().as_str() == canonical(&repo)
        )
    ));
}

/// A configuration that may move the work tree or make the repository bare,
/// or that this reading does not fully understand, leaves the root to Git.
#[cfg(unix)]
#[test]
fn only_configs_that_keep_the_work_tree_are_answered_without_git() {
    for (config, keeps) in [
        (
            "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n",
            true,
        ),
        ("[remote \"origin\"]\n\turl = x\n\tworktree = y\n", true),
        ("[CORE] WorkTree = /elsewhere\n", false),
        ("[core]\n\tbare\n", false),
        ("[core]\n\tbare = yes\n", false),
        ("[core]\n\trepositoryformatversion = 2\n", false),
        ("[extensions]\n\tworktreeConfig = true\n", false),
        ("[includeIf \"gitdir:/x/\"]\n\tpath = more\n", false),
        ("[core]\n\tbare = fa\\\nlse\n", false),
        ("worktree = /elsewhere\n", false),
    ] {
        assert_eq!(config_keeps_work_tree(config), keeps, "{config}");
    }
}

/// One decision discovers a cwd's roots once, and stops waiting for Git at
/// its deadline however long one spawn may take, or a process it leaves
/// behind holds its output open.
#[cfg(unix)]
#[test]
fn decision_observation_discovers_roots_once_within_its_deadline() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().expect("tempdir");
    let main = temp.path().join("main");
    let worktree = temp.path().join("linked");
    init_repo(&main);
    run(Command::new("git")
        .args([
            "worktree",
            "add",
            "-qb",
            "linked",
            worktree.to_str().unwrap(),
        ])
        .current_dir(&main));
    let request = request(&worktree, &[]);

    let log = temp.path().join("git-runs");
    let counting_git = temp.path().join("counting-git");
    fs::write(
        &counting_git,
        format!(
            "#!/bin/sh\necho run >> '{}'\nexec git \"$@\"\n",
            log.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&counting_git, fs::Permissions::from_mode(0o755)).unwrap();
    let mut observation = DecisionObservation {
        git: counting_git,
        wait: GitWait {
            per_spawn: TEST_GIT_TIMEOUT,
            deadline: Some(Instant::now() + Duration::from_secs(60)),
        },
        roots: None,
    };
    for _ in 0..3 {
        let answer = observation.fulfill(&request).expect("observation");
        assert!(matches!(
            value(&answer, "roots"),
            ObservationValue::Roots {
                observed: Observed::Ok { value }
            } if value.len() == 2
        ));
    }
    assert_eq!(fs::read_to_string(&log).unwrap().lines().count(), 1);

    let slow_git = temp.path().join("slow-git");
    fs::write(&slow_git, "#!/bin/sh\nexec sleep 10\n").unwrap();
    let pipe_holding_git = temp.path().join("pipe-holding-git");
    fs::write(
        &pipe_holding_git,
        format!(
            "#!/bin/sh\nsleep 10 &\nprintf '%s\\n' '{}' '{}'\nexec true\n",
            canonical(&worktree),
            canonical(&main.join(".git"))
        ),
    )
    .unwrap();
    for git in [slow_git, pipe_holding_git] {
        fs::set_permissions(&git, fs::Permissions::from_mode(0o755)).unwrap();
        let mut observation = DecisionObservation {
            git,
            wait: GitWait {
                per_spawn: TEST_GIT_TIMEOUT,
                deadline: Some(Instant::now() + Duration::from_secs(1)),
            },
            roots: None,
        };
        let started = Instant::now();
        let answer = observation.fulfill(&request).expect("observation");
        assert!(started.elapsed() < Duration::from_secs(3));
        assert!(matches!(
            value(&answer, "roots"),
            ObservationValue::Roots {
                observed: Observed::Error {
                    error: ObservationFailure::Timeout
                }
            }
        ));
    }
}
