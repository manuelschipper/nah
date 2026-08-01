use super::support::{init_repo, request, run, value};
use crate::{fulfill, fulfill_with_git};
use nah_proto::observation::{
    ObservationFailure, ObservationValue, Observed, ProjectGuardDeclaration, RootKind,
};
use std::fs;
use std::path::Path;
use std::process::Command;
#[cfg(unix)]
use std::time::Duration;

#[test]
fn ordinary_non_repository_has_a_successful_empty_root_set() {
    let temp = tempfile::tempdir().expect("tempdir");
    let observation = fulfill(&request(temp.path(), &[])).expect("observation");
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

    let observation = fulfill(&request(&worktree, &[])).expect("observation");
    let ObservationValue::Roots {
        observed: Observed::Ok { value: roots },
    } = value(&observation, "roots")
    else {
        panic!("expected roots");
    };

    assert_eq!(roots.len(), 2);
    assert!(roots.iter().any(|root| {
        root.kind() == RootKind::Project
            && root.path().as_str() == worktree.canonicalize().unwrap().to_str().unwrap()
    }));
    assert!(roots.iter().any(|root| {
        root.kind() == RootKind::WorktreeMain
            && root.path().as_str() == main.canonicalize().unwrap().to_str().unwrap()
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

    let observation = fulfill(&request(&worktree, &[])).expect("observation");
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

    let observation = fulfill(&request(&repo, &[])).expect("observation");
    assert!(matches!(
        value(&observation, "roots"),
        ObservationValue::Roots {
            observed: Observed::Error {
                error: ObservationFailure::InvalidPath
            }
        }
    ));
}

#[cfg(unix)]
#[test]
fn missing_or_slow_git_fails_roots_closed() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().expect("tempdir");
    let repo = temp.path().join("repo");
    init_repo(&repo);
    let request = request(&repo, &[]);

    let missing = fulfill_with_git(
        &request,
        &temp.path().join("does-not-exist"),
        Duration::from_millis(50),
    )
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
    fs::write(&relative_git, "#!/bin/sh\nprintf 'relative-root\\n'\n").unwrap();
    fs::set_permissions(&relative_git, fs::Permissions::from_mode(0o755)).unwrap();
    let relative = fulfill_with_git(&request, &relative_git, Duration::from_millis(50))
        .expect("relative git observation");
    assert!(matches!(
        value(&relative, "roots"),
        ObservationValue::Roots {
            observed: Observed::Error {
                error: ObservationFailure::InvalidPath
            }
        }
    ));
}
