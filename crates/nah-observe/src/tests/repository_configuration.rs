use super::support::{absolute, init_repo, run};
use crate::TEST_GIT_TIMEOUT;
use crate::git_state::observe_git_state;
use crate::ignored_entries::{Listings, observe_ignored_entries};
use crate::roots::{GitWait, discover_roots};
use nah_proto::observation::Observed;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

/// Observation runs inside the hook, before any prompt, so a program the
/// repository's configuration names would run unasked for whatever repository
/// the agent reaches. Each setting below makes Git start one during a read:
/// a filesystem monitor hook, a filter driver of the repository and one of a
/// submodule, and the fetch of an object a partial clone lacks.
#[test]
fn repository_configuration_starts_no_program() {
    let temp = tempfile::tempdir().expect("tempdir");
    let marker = temp.path().join("ran");
    let probe = temp.path().join("probe.sh");
    fs::write(
        &probe,
        format!("#!/bin/sh\necho \"$@\" >> '{}'\n", marker.display()),
    )
    .expect("probe script");
    fs::set_permissions(&probe, fs::Permissions::from_mode(0o755)).expect("probe mode");
    let probe = probe.to_str().expect("unicode test path");
    let git = |directory: &Path, args: &[&str]| {
        run(Command::new("git")
            .args([
                "-c",
                "user.name=Nah Test",
                "-c",
                "user.email=nah@example.invalid",
            ])
            .args(args)
            .current_dir(directory))
    };

    let repo = temp.path().join("repo");
    init_repo(&repo);
    let sub = repo.join("sub");
    init_repo(&sub);
    for directory in [&repo, &sub] {
        fs::write(
            directory.join(".gitattributes"),
            "tracked filter=probe\n.pypirc filter=probe diff=probe\n",
        )
        .expect("attributes");
    }
    fs::write(repo.join(".gitignore"), ".env\n").expect("ignore rules");
    git(&sub, &["add", ".gitattributes"]);
    git(&sub, &["commit", "-qm", "attributes"]);
    fs::write(repo.join(".pypirc"), "TOKEN=fixture\n").expect("tracked credential");
    git(
        &repo,
        &["add", ".gitattributes", ".gitignore", ".pypirc", "sub"],
    );
    git(&repo, &["commit", "-qm", "attributes"]);
    fs::write(repo.join(".env"), "TOKEN=1\n").expect("ignored file");
    fs::write(repo.join("tracked"), "stashed\n").expect("stashed edit");
    fs::write(repo.join(".pgpass"), "fixture\n").expect("untracked stash file");
    git(&repo, &["stash", "push", "-uqm", "observation fixture"]);

    git(
        &repo,
        &["config", "core.fsmonitor", &format!("{probe} fsmonitor")],
    );
    git(
        &repo,
        &["config", "filter.probe.clean", &format!("{probe} clean")],
    );
    // The submodule's driver has its own name, which the repository's
    // configuration does not list.
    fs::write(sub.join(".gitattributes"), "tracked filter=subprobe\n").expect("attributes");
    git(
        &sub,
        &["config", "filter.subprobe.clean", &format!("{probe} sub")],
    );
    // Rewritten unchanged, so Git compares them by contents.
    for directory in [&repo, &sub] {
        fs::write(directory.join("tracked"), "one\n").expect("tracked file");
    }

    // A staged rename whose new contents the partial clone lacks: telling it
    // from a copy reads them, which fetches them from the promisor remote.
    let partial = temp.path().join("partial");
    init_repo(&partial);
    git(&partial, &["rm", "-q", "--cached", "tracked"]);
    git(
        &partial,
        &[
            "update-index",
            "--add",
            "--cacheinfo",
            "100644,1234567890123456789012345678901234567890,renamed",
        ],
    );
    for (key, value) in [
        ("core.repositoryformatversion", "1"),
        ("extensions.partialClone", "origin"),
        ("remote.origin.promisor", "true"),
        ("remote.origin.url", &format!("ext::{probe} fetch")),
        ("protocol.ext.allow", "always"),
    ] {
        git(&partial, &["config", key, value]);
    }

    let directory = repo.to_str().expect("unicode test path");
    let git_executable = Path::new("git");
    assert!(matches!(
        discover_roots(
            &absolute(&repo),
            git_executable,
            GitWait::per_spawn(TEST_GIT_TIMEOUT)
        ),
        Observed::Ok { .. }
    ));
    assert!(matches!(
        observe_ignored_entries(directory, &mut Listings::new()),
        Observed::Ok { value } if !value.entries().is_empty()
    ));
    // The submodule was not looked inside, so it may hold changes.
    assert!(matches!(
        observe_git_state(directory, true, git_executable, GitWait::per_spawn(TEST_GIT_TIMEOUT)),
        Observed::Ok { value } if value.tracked_changes()
    ));
    assert_eq!(fs::read_to_string(&marker).ok(), None);
    // A process filter takes precedence over a clean filter, so disabling
    // only the latter must not leave a program running during observation.
    git(
        &repo,
        &[
            "config",
            "filter.probe.process",
            &format!("{probe} process"),
        ],
    );
    // Patch observations must not execute the same filters, textconv or
    // external diff commands that a real patch may run.
    fs::write(
        repo.join(".gitattributes"),
        "tracked filter=probe diff=probe\n.pypirc filter=probe diff=probe\n",
    )
    .expect("attributes");
    git(
        &repo,
        &["config", "diff.external", &format!("{probe} diff")],
    );
    git(
        &repo,
        &[
            "config",
            "diff.probe.textconv",
            &format!("{probe} textconv"),
        ],
    );
    for kind in [
        nah_proto::observation::GitReadKind::Commit,
        nah_proto::observation::GitReadKind::History,
        nah_proto::observation::GitReadKind::RevisionGrep,
        nah_proto::observation::GitReadKind::Diff,
        nah_proto::observation::GitReadKind::StagedDiff,
        nah_proto::observation::GitReadKind::Stash,
        nah_proto::observation::GitReadKind::StashUntracked,
        nah_proto::observation::GitReadKind::StashOnlyUntracked,
    ] {
        assert!(matches!(
            crate::git_read::observe_git_read(
                directory,
                &nah_proto::observation::GitReadSelection {
                    kind,
                    revisions: if matches!(
                        kind,
                        nah_proto::observation::GitReadKind::Stash
                            | nah_proto::observation::GitReadKind::StashUntracked
                            | nah_proto::observation::GitReadKind::StashOnlyUntracked
                    ) {
                        vec!["0".into()]
                    } else if kind == nah_proto::observation::GitReadKind::RevisionGrep {
                        vec!["HEAD".into()]
                    } else {
                        vec![]
                    },
                    revision_options: vec![],
                    pathspecs: vec![],
                    pathspec_options: vec![],
                },
                git_executable,
                GitWait::per_spawn(TEST_GIT_TIMEOUT),
            ),
            Observed::Ok { .. }
        ));
    }
    assert!(matches!(
        crate::git_read::observe_git_read(
            directory,
            &nah_proto::observation::GitReadSelection {
                kind: nah_proto::observation::GitReadKind::Diff,
                revisions: vec![],
                revision_options: vec![],
                pathspecs: vec![],
                pathspec_options: vec![],
            },
            git_executable,
            GitWait {
                per_spawn: TEST_GIT_TIMEOUT,
                deadline: Some(std::time::Instant::now())
            },
        ),
        Observed::Error {
            error: nah_proto::observation::ObservationFailure::Timeout
        }
    ));
    let state = observe_git_state(
        directory,
        true,
        git_executable,
        GitWait::per_spawn(TEST_GIT_TIMEOUT),
    );
    assert_eq!(fs::read_to_string(&marker).ok(), None);
    assert!(matches!(state, Observed::Ok { value } if value.tracked_changes()));
    assert!(matches!(
        observe_git_state(
            partial.to_str().expect("unicode test path"),
            false,
            git_executable,
            GitWait::per_spawn(TEST_GIT_TIMEOUT),
        ),
        Observed::Error { .. }
    ));
    assert_eq!(fs::read_to_string(&marker).ok(), None);

    // A repository can allow its own transport name and use a relative
    // remote-helper path to run the script without installing it on PATH.
    fs::create_dir(partial.join("git-remote-..")).expect("helper path component");
    for (key, value) in [
        ("remote.origin.url", "unused"),
        ("remote.origin.vcs", "../../../probe.sh"),
        ("protocol.../../../probe.sh.allow", "always"),
    ] {
        git(&partial, &["config", key, value]);
    }
    assert!(matches!(
        observe_git_state(
            partial.to_str().expect("unicode test path"),
            false,
            git_executable,
            GitWait::per_spawn(TEST_GIT_TIMEOUT),
        ),
        Observed::Error { .. }
    ));
    assert_eq!(fs::read_to_string(&marker).ok(), None);

    // Git's empty allowlist admits an empty helper name; an allowed helper
    // that cannot execute may still autocorrect to a repository alias.
    for (key, value) in [
        ("alias.remote-", format!("!{probe} empty")),
        (
            "alias.remote-nah-observation-disabled?.helper",
            format!("!{probe} autocorrect"),
        ),
        ("help.autocorrect", "-1".to_owned()),
    ] {
        git(&partial, &["config", key, &value]);
    }
    for (url, helper) in [
        ("::unused", ""),
        ("unused", "nah-observation-disabled?.helper/"),
    ] {
        git(&partial, &["config", "remote.origin.url", url]);
        git(&partial, &["config", "remote.origin.vcs", helper]);
        let state = observe_git_state(
            partial.to_str().expect("unicode test path"),
            false,
            git_executable,
            GitWait::per_spawn(TEST_GIT_TIMEOUT),
        );
        assert_eq!(fs::read_to_string(&marker).ok(), None);
        assert!(matches!(state, Observed::Error { .. }));
    }
}
