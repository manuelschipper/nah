#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

use crate::support;

#[cfg(unix)]
use std::process::Command;

use nah_cli::decide_with;
use nah_proto::action::Coverage;
use nah_proto::decision::Verdict;
use serde_json::json;
#[cfg(unix)]
use support::git;
use support::{call, ctx, repo};

#[cfg(unix)]
#[test]
fn destructive_git_guards_are_semantic_end_to_end() {
    let temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah resolves
    // paths before matching them
    let root = support::test_temp_path(temp.path());
    let repo = repo(&root);
    let context = ctx(&root);
    // Decision cases live in corpus/git.jsonl; these keep a real repository's
    // observed .git in the decision path.
    for (command, guard) in [
        ("rm -rf .git", "git-metadata"),
        ("git reset --hard", "git-hard-reset"),
    ] {
        let result = decide_with(
            &call("Bash", json!({"command":command}), &repo),
            &context,
            support::fulfill_observation,
        );
        assert_eq!(result.core().verdict(), Verdict::Block, "{command}");
        assert!(
            result
                .core()
                .policy_attributions()
                .iter()
                .any(|attribution| attribution.name() == guard),
            "{command}: {:?}",
            result.core().policy_attributions()
        );
    }

    for (path, expected) in [(".git/packed-refs", true), ("src/generated.rs", false)] {
        let result = decide_with(
            &call(
                "Write",
                json!({"file_path": repo.join(path), "content": "replacement"}),
                &repo,
            ),
            &context,
            support::fulfill_observation,
        );
        assert_eq!(
            result
                .core()
                .policy_attributions()
                .iter()
                .any(|guard| guard.name() == "git-metadata"),
            expected
        );
        assert_eq!(result.core().verdict() == Verdict::Block, expected);
    }

    // Each push protection remains independent of the other guard settings.
    for force in [false, true] {
        for history in [false, true] {
            for protected in [false, true] {
                let states = nah_cli::shipped_guard_states()
                    .into_iter()
                    .map(|state| match state.name() {
                        "git-force-push" => {
                            nah_proto::ctx::ShippedGuardState::new(state.name(), force).unwrap()
                        }
                        "git-history-rewrite" => {
                            nah_proto::ctx::ShippedGuardState::new(state.name(), history).unwrap()
                        }
                        "git-protected-push" => {
                            nah_proto::ctx::ShippedGuardState::new(state.name(), protected).unwrap()
                        }
                        _ => state,
                    })
                    .collect();
                let context = nah_proto::ctx::Ctx::new(
                    support::host_platform(),
                    support::absolute(&root),
                    states,
                    vec![],
                    nah_proto::ctx::TrustProjection::new(vec![]).unwrap(),
                )
                .unwrap();
                for (command, applicable) in [
                    (
                        "git push --force-with-lease origin main",
                        vec![
                            "git-force-push",
                            "git-history-rewrite",
                            "git-protected-push",
                        ],
                    ),
                    (
                        "git push --force-with-lease origin +feature:main",
                        vec![
                            "git-force-push",
                            "git-history-rewrite",
                            "git-protected-push",
                        ],
                    ),
                    (
                        "git push --force-with-lease=refs/heads/master origin +HEAD:refs/heads/master",
                        vec![
                            "git-force-push",
                            "git-history-rewrite",
                            "git-protected-push",
                        ],
                    ),
                    ("git push origin main", vec!["git-protected-push"]),
                    (
                        "git push --force origin main",
                        vec!["git-force-push", "git-protected-push"],
                    ),
                    (
                        "git push --force-with-lease=feature origin main",
                        vec!["git-history-rewrite", "git-protected-push"],
                    ),
                    (
                        "git push --force-with-lease origin main:feature",
                        vec!["git-history-rewrite"],
                    ),
                    (
                        "git push --force-with-lease origin feature",
                        vec!["git-history-rewrite"],
                    ),
                    ("git push --force-with-lease", vec!["git-history-rewrite"]),
                    (
                        "git push --force-with-lease origin \"$REF\"",
                        vec!["git-history-rewrite"],
                    ),
                    (
                        "git push --force-with-lease --force origin main",
                        vec![
                            "git-force-push",
                            "git-history-rewrite",
                            "git-protected-push",
                        ],
                    ),
                    (
                        "git push --force-with-lease=other origin +main",
                        vec![
                            "git-force-push",
                            "git-history-rewrite",
                            "git-protected-push",
                        ],
                    ),
                    ("git push --force-with-lease --dry-run origin main", vec![]),
                    ("git push --force-with-lease --help origin main", vec![]),
                    ("git push --force-with-lease --version origin main", vec![]),
                    (
                        "git push --force-with-lease --no-force-with-lease origin main",
                        vec!["git-protected-push"],
                    ),
                ] {
                    let expected = applicable
                        .into_iter()
                        .filter(|name| match *name {
                            "git-force-push" => force,
                            "git-history-rewrite" => history,
                            "git-protected-push" => protected,
                            _ => true,
                        })
                        .collect::<std::collections::BTreeSet<_>>();
                    let result = decide_with(
                        &call("Bash", json!({"command": command}), &repo),
                        &context,
                        support::fulfill_observation,
                    );
                    let actual = result
                        .core()
                        .policy_attributions()
                        .iter()
                        .map(|guard| guard.name())
                        .collect::<std::collections::BTreeSet<_>>();
                    assert_eq!(
                        actual, expected,
                        "{command}: force={force}, history={history}, protected={protected}"
                    );
                    assert_eq!(
                        result.core().verdict(),
                        if expected.is_empty() {
                            Verdict::Delegate
                        } else {
                            Verdict::Block
                        },
                        "{command}"
                    );
                }
            }
        }
    }

    let states = nah_cli::shipped_guard_states()
        .into_iter()
        .map(|state| match state.name() {
            "git-ref-delete" => nah_proto::ctx::ShippedGuardState::new(state.name(), true).unwrap(),
            "git-force-push" | "git-history-rewrite" | "git-protected-push" => {
                nah_proto::ctx::ShippedGuardState::new(state.name(), false).unwrap()
            }
            _ => state,
        })
        .collect();
    let ref_delete_only = nah_proto::ctx::Ctx::new(
        support::host_platform(),
        support::absolute(&root),
        states,
        vec![],
        nah_proto::ctx::TrustProjection::new(vec![]).unwrap(),
    )
    .unwrap();
    // A deletion blocks under git-ref-delete even when the same push is also
    // forced, leased, or updates a protected branch whose guards are off.
    for command in [
        "git push origin :old",
        "git push --force origin :old",
        "git push --force-with-lease origin :old",
        "git push origin main :old",
    ] {
        let result = decide_with(
            &call("Bash", json!({"command": command}), &repo),
            &ref_delete_only,
            support::fulfill_observation,
        );
        assert_eq!(result.core().verdict(), Verdict::Block, "{command}");
        assert_eq!(
            result.core().policy_attributions()[0].name(),
            "git-ref-delete",
            "{command}"
        );
    }
}

/// Executes host Git only, pinning the path effects of destructive forms that
/// Nah's Git model must agree with. It never invokes Nah, so a model
/// regression cannot fail it; modeled verdicts are qualified by the Nah tests
/// in this suite and by the corpus.
#[cfg(unix)]
#[test]
fn host_git_destructive_forms_have_expected_path_effects() {
    let clean_temp = tempfile::tempdir().unwrap();
    let clean_repo = repo(clean_temp.path());
    std::fs::write(clean_repo.join("untracked"), "discard me\n").unwrap();
    git(&clean_repo, &["clean", ".", "-f"]);
    assert!(!clean_repo.join("untracked").exists());
    std::fs::write(clean_repo.join("lexical"), "discard me too\n").unwrap();
    git(&clean_repo, &["clean", "-f", ".git/.."]);
    assert!(!clean_repo.join("lexical").exists());
    std::fs::write(clean_repo.join("lone-dash"), "discard me too\n").unwrap();
    git(&clean_repo, &["clean", ".", "-f", "-"]);
    assert!(!clean_repo.join("lone-dash").exists());

    let branch_temp = tempfile::tempdir().unwrap();
    let branch_repo = repo(branch_temp.path());
    git(&branch_repo, &["branch", "origin/other"]);
    std::fs::remove_file(branch_repo.join("src/lib.rs")).unwrap();
    git(
        &branch_repo,
        &[
            "checkout",
            "-f",
            "-b",
            "topic",
            "--no-detach",
            "origin/other",
        ],
    );
    assert!(branch_repo.join("src/lib.rs").exists());
    std::fs::remove_file(branch_repo.join("src/lib.rs")).unwrap();
    git(&branch_repo, &["checkout", "-f", "--no-merge"]);
    assert!(branch_repo.join("src/lib.rs").exists());
    std::fs::remove_file(branch_repo.join("src/lib.rs")).unwrap();
    git(&branch_repo, &["checkout", "-f", "--no-patch"]);
    assert!(branch_repo.join("src/lib.rs").exists());
    std::fs::remove_file(branch_repo.join("src/lib.rs")).unwrap();
    git(
        &branch_repo,
        &["switch", "-f", "--no-merge", "origin/other"],
    );
    assert!(branch_repo.join("src/lib.rs").exists());

    let dash_temp = tempfile::tempdir().unwrap();
    let dash_repo = repo(dash_temp.path());
    std::fs::write(dash_repo.join("--keep"), "tracked\n").unwrap();
    git(&dash_repo, &["add", "--", "--keep"]);
    git(
        &dash_repo,
        &[
            "-c",
            "user.name=nah test",
            "-c",
            "user.email=nah@example.invalid",
            "commit",
            "-qm",
            "dash path fixture",
        ],
    );
    std::fs::remove_file(dash_repo.join("src/lib.rs")).unwrap();
    std::fs::remove_file(dash_repo.join("--keep")).unwrap();
    git(&dash_repo, &["checkout", "--", ".", "--keep"]);
    assert!(dash_repo.join("src/lib.rs").exists());
    assert!(dash_repo.join("--keep").exists());
    std::fs::remove_file(dash_repo.join("src/lib.rs")).unwrap();
    git(&dash_repo, &["checkout", "HEAD", "."]);
    assert!(dash_repo.join("src/lib.rs").exists());
    std::fs::remove_file(dash_repo.join("src/lib.rs")).unwrap();
    git(&dash_repo, &["checkout", "--no-patch", "--", "."]);
    assert!(dash_repo.join("src/lib.rs").exists());
    std::fs::remove_file(dash_repo.join("src/lib.rs")).unwrap();
    std::fs::remove_file(dash_repo.join("--keep")).unwrap();
    git(&dash_repo, &["restore", "--", ".", "--keep"]);
    assert!(dash_repo.join("src/lib.rs").exists());
    assert!(dash_repo.join("--keep").exists());

    let alternate_temp = tempfile::tempdir().unwrap();
    let alternate_repo = repo(alternate_temp.path());
    let alternate_tree = alternate_temp.path().join("alternate");
    std::fs::create_dir(&alternate_tree).unwrap();
    std::fs::write(alternate_tree.join("untracked"), "discard me\n").unwrap();
    let status = Command::new("git")
        .current_dir(&alternate_repo)
        .env("GIT_WORK_TREE", &alternate_tree)
        .args(["clean", "-f"])
        .status()
        .unwrap();
    assert!(status.success());
    assert!(!alternate_tree.join("untracked").exists());
    assert!(alternate_repo.join("src/lib.rs").exists());

    let metadata_temp = tempfile::tempdir().unwrap();
    let metadata_repo = repo(metadata_temp.path());
    let refused = Command::new("git")
        .arg("-C")
        .arg(&metadata_repo)
        .args(["clean", ".git"])
        .status()
        .unwrap();
    assert!(!refused.success());
    git(&metadata_repo, &["clean", "-f", ".git"]);
    assert!(metadata_repo.join(".git").exists());
}

#[test]
fn granular_git_operations_lower_to_their_exact_coverage() {
    let temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah resolves
    // paths before matching them
    let root = support::test_temp_path(temp.path());
    let repo = repo(&root);
    let context = ctx(&root);

    // The corpus fixture observes neither path, so these stay on the host.
    for command in ["git status > status.txt", "git add src"] {
        let result = decide_with(
            &call("Bash", json!({"command":command}), &repo),
            &context,
            support::fulfill_observation,
        );
        assert_eq!(result.core().verdict(), Verdict::Delegate, "{command}");
        assert_eq!(result.core().coverage(), Coverage::Full, "{command}");
    }

    let outside = &root.join("outside");
    std::fs::create_dir(outside).unwrap();
    let result = decide_with(
        &call("Bash", json!({"command":"git status"}), outside),
        &context,
        support::fulfill_observation,
    );
    assert_eq!(result.core().verdict(), Verdict::Delegate);
    assert_eq!(result.core().coverage(), Coverage::Full);
}

#[cfg(unix)]
#[test]
fn stash_and_forced_tree_loss_block_at_factory_defaults_and_keep_independent_controls() {
    use nah_proto::ctx::{Ctx, ShippedGuardState, TrustProjection};

    let temp = tempfile::tempdir().unwrap();
    let root = support::test_temp_path(temp.path());
    let repo = repo(&root);
    for (command, loss_guard) in [
        ("git stash clear", "git-recovery-destroy"),
        ("git stash clear --", "git-recovery-destroy"),
        ("git worktree remove -ff old", "git-worktree-discard"),
        (
            "git submodule --quiet deinit -f vendor/library",
            "git-worktree-discard",
        ),
        ("git submodule deinit --force --all", "git-worktree-discard"),
    ] {
        for controls in [
            None,
            Some((true, false)),
            Some((false, true)),
            Some((true, true)),
            Some((false, false)),
        ] {
            let context = if let Some((loss_enabled, ref_enabled)) = controls {
                Ctx::new(
                    support::host_platform(),
                    support::absolute(&root),
                    vec![
                        ShippedGuardState::new(loss_guard, loss_enabled).unwrap(),
                        ShippedGuardState::new("git-ref-delete", ref_enabled).unwrap(),
                    ],
                    vec![],
                    TrustProjection::new(vec![]).unwrap(),
                )
                .unwrap()
            } else {
                support::factory_ctx(&root)
            };
            let result = decide_with(
                &call("Bash", json!({"command": command}), &repo),
                &context,
                support::fulfill_observation,
            );
            let (loss_enabled, ref_enabled) = controls.unwrap_or((true, false));
            assert_eq!(
                result.core().verdict(),
                if loss_enabled || ref_enabled {
                    Verdict::Block
                } else {
                    Verdict::Delegate
                },
                "{command}"
            );
            let names = result
                .core()
                .policy_attributions()
                .iter()
                .map(|guard| guard.name())
                .collect::<Vec<_>>();
            assert_eq!(names.contains(&loss_guard), loss_enabled, "{command}");
            assert_eq!(names.contains(&"git-ref-delete"), ref_enabled, "{command}");
            assert_eq!(
                names.len(),
                usize::from(loss_enabled) + usize::from(ref_enabled),
                "{command}"
            );
        }
    }
}
