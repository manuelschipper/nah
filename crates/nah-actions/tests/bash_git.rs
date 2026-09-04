mod support;

use nah_actions::finalize;
use nah_proto::action::{Coverage, EffectKind, FilesystemOperation, InvocationEffect, Sensitivity};
use support::{bash_plan, observe};

#[test]
fn git_guard_evidence_is_semantic_and_flag_sensitive() {
    for (source, operation) in [
        ("rm -rf .git", "metadata-mutation"),
        ("rm -rf .git/objects/aa", "metadata-mutation"),
        ("rm -rf .git/refs", "metadata-mutation"),
        ("rm -rf .git/logs", "metadata-mutation"),
        ("rm -f .git/packed-refs", "metadata-mutation"),
        ("rm -rf .git/worktrees", "metadata-mutation"),
        ("rm -rf '.git/*'", "metadata-mutation"),
        ("rm -rf '.git/{objects,refs}'", "metadata-mutation"),
        ("unlink .git/objects/aa", "metadata-mutation"),
        ("rmdir .git/refs", "metadata-mutation"),
        ("echo corrupt > .git/objects/aa", "metadata-mutation"),
        ("cp replacement .git/refs/heads/main", "metadata-mutation"),
        ("touch .git/packed-refs", "metadata-mutation"),
        ("git push --force", "force-push"),
        ("git push --mirror origin", "force-push"),
        (
            "git -c advice.detachedHead=false push --mirror",
            "force-push",
        ),
        ("git push --force --repo --help origin main", "force-push"),
        ("git push --force \"$REMOTE\"", "force-push"),
        ("git push origin +main", "force-push"),
        (
            "git push --force-with-lease=other origin +main",
            "force-push",
        ),
        (
            "git push --force-with-lease --no-force-with-lease origin +main",
            "force-push",
        ),
        (
            "git push --repo --force-with-lease origin +main",
            "force-push",
        ),
        ("git reset --hard", "hard-reset"),
        ("git reset --hard \"$REV\"", "hard-reset"),
        ("git filter-branch -f -- --all", "rewrite-force"),
        ("git filter-branch --force -- --all", "rewrite-force"),
        ("git filter-repo --force", "rewrite-force"),
        (
            "git filter-repo --force --replace-text --help",
            "rewrite-force",
        ),
        ("sudo git filter-repo --force", "rewrite-force"),
        ("git reflog expire --all --expire=now", "recovery-destroy"),
        (
            "git reflog expire --expire-unreachable=now --all",
            "recovery-destroy",
        ),
        ("git gc --prune=now", "recovery-destroy"),
        ("git prune --expire=now", "recovery-destroy"),
        ("git prune --expire now", "recovery-destroy"),
        ("git -C /repo reset --hard", "hard-reset"),
        ("git -C \"$REPO\" reset --hard", "hard-reset"),
        ("sudo git push -f", "force-push"),
    ] {
        let plan = bash_plan(source);
        let observation = observe(plan.observation_request(), "echo");
        let stream = finalize(plan, observation);
        assert!(
            stream.effects().iter().any(|effect| {
                matches!(
                    effect.kind(),
                    EffectKind::Git { operation: actual } if actual.as_str() == operation
                )
            }),
            "{source}: {:?}",
            stream.effects()
        );
    }

    for source in [
        "rm -rf .git/index",
        "rm -rf .git/hooks/pre-commit",
        "git push -- --force",
        "git -- push --force",
        "git reset --soft HEAD~1",
        "git reset -- --hard",
        "git filter-repo --dry-run --force",
        "git filter-repo --analyze",
        "git filter-repo --version",
        "git reflog show",
        "git reflog show expire",
        "git reflog expire --dry-run --all --expire=now",
        "git reflog expire -n --all --expire=now",
        "git reflog delete HEAD@{0}",
        "git gc -- --prune=now",
        "git push --dry-run --force origin main",
        "git push -nf origin main",
        "git push --dry-run --mirror origin",
        "git push -n --mirror origin",
        "git clone --mirror origin local.git",
        "git push --prune origin",
        "git prune",
        "git prune --expire=2.weeks.ago",
        "echo safe > .git/index",
        "echo safe > .git/hooks/pre-commit",
        "git push --help --mirror",
        "git reset --hard --help",
        "git filter-repo --force --help",
        "git gc --prune=now --help",
        "git push -- --delete",
        "git push -- --mirror",
        "git push \"$FLAGS\"",
        "git prune --dry-run",
        "git prune -n",
        "git prune --help",
        "git reflog \"$ACTION\"",
        "git worktree list",
        "git worktree prune --dry-run",
        "git worktree -- remove old",
    ] {
        let plan = bash_plan(source);
        let observation = observe(plan.observation_request(), "echo");
        let stream = finalize(plan, observation);
        assert!(
            !stream
                .effects()
                .iter()
                .any(|effect| matches!(effect.kind(), EffectKind::Git { .. })),
            "{source}: {:?}",
            stream.effects()
        );
    }
}

#[test]
fn git_history_rewrite_evidence_is_complementary_and_recovery_safe() {
    for source in [
        "git rebase main",
        "git rebase --continue",
        "git rebase --skip",
        "git rebase -- --abort",
        "git filter-branch -- --all",
        "git filter-repo --invert-paths --path secret",
        "git reflog expire --all",
        "git gc --aggressive",
        "git gc --prune=2.weeks.ago",
        "git gc --no-prune --aggressive",
        "git push --force-with-lease",
        "git push --force-with-lease=main origin +main",
    ] {
        let plan = bash_plan(source);
        let observation = observe(plan.observation_request(), "echo");
        let stream = finalize(plan, observation);
        let operations = stream
            .effects()
            .iter()
            .filter_map(|effect| match effect.kind() {
                EffectKind::Git { operation } => Some(operation.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            operations,
            ["history-rewrite"],
            "{source}: {:?}",
            stream.effects()
        );
    }

    for (source, operation) in [
        ("git filter-repo --force", "rewrite-force"),
        ("git reflog expire --all --expire=now", "recovery-destroy"),
        ("git gc --aggressive --prune=now", "recovery-destroy"),
        ("git push --force-with-lease --force", "force-push"),
        (
            "git push --force-with-lease=other origin +main",
            "force-push",
        ),
    ] {
        let plan = bash_plan(source);
        let observation = observe(plan.observation_request(), "echo");
        let stream = finalize(plan, observation);
        let operations = stream
            .effects()
            .iter()
            .filter_map(|effect| match effect.kind() {
                EffectKind::Git { operation } => Some(operation.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(operations, [operation], "{source}: {:?}", stream.effects());
    }

    for source in [
        "git rebase --abort",
        "git rebase --quit",
        "git rebase --show-current-patch",
        "git rebase --help",
        "git filter-repo --dry-run --force",
        "git filter-repo --analyze",
        "git filter-branch --help",
        "git reflog expire --dry-run --all",
        "git gc",
        "git gc --prune=2.weeks.ago --no-prune",
        "git push --force-with-lease --no-force-with-lease",
        "git commit --amend -m update",
        "git cherry-pick topic",
    ] {
        let plan = bash_plan(source);
        let observation = observe(plan.observation_request(), "echo");
        let stream = finalize(plan, observation);
        assert!(
            !stream.effects().iter().any(|effect| {
                matches!(effect.kind(), EffectKind::Git { operation } if operation.as_str() == "history-rewrite")
            }),
            "{source}: {:?}",
            stream.effects()
        );
    }
}

#[test]
fn git_ref_deletes_lower_to_one_semantic_operation() {
    for source in [
        "git branch -d topic",
        "git branch -D \"$BRANCH\"",
        "git branch -vrd one two",
        "git branch --delete -- topic",
        "git tag -d v1",
        "git tag --delete \"$TAG\"",
        "git stash drop 'stash@{0}'",
        "git stash drop --quiet \"$STASH\"",
        "git stash clear",
        "git push --delete origin old",
        "git push origin --delete old",
        "git push -vd \"$REMOTE\" \"$REF\"",
        "git push origin :old",
        "git push :main",
        "git update-ref -d refs/heads/topic",
        "git update-ref --delete \"$REF\"",
        "git worktree remove -f \"$PATH\"",
        "git worktree remove -ff old",
        "git worktree prune --expire now",
        "git submodule deinit vendor/library",
        "git submodule deinit -q vendor/library",
        "git submodule --quiet deinit -- \"$PATH\"",
        "timeout 5 git worktree remove old",
    ] {
        let plan = bash_plan(source);
        let observation = observe(plan.observation_request(), "echo");
        let stream = finalize(plan, observation);
        let operations = stream
            .effects()
            .iter()
            .filter_map(|effect| match effect.kind() {
                EffectKind::Git { operation } => Some(operation.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            operations,
            ["ref-delete"],
            "{source}: {:?}",
            stream.effects()
        );
    }
}

#[test]
fn git_ref_delete_rejects_nonexecuting_and_invalid_shapes() {
    for source in [
        "git branch -d",
        "git branch --delete --list old",
        "git branch -m old new",
        "git branch -M old new",
        "git branch -c old new",
        "git branch -C old new",
        "git branch \"$FLAG\" old",
        "git branch topic",
        "git tag -d",
        "git tag --list --delete v1",
        "git tag v1",
        "git stash drop one two",
        "git stash clear extra",
        "git stash push",
        "git stash apply",
        "git stash pop",
        "git stash \"$ACTION\"",
        "git push --delete origin",
        "git push --dry-run --delete origin old",
        "git push -nd origin old",
        "git push --delete origin :old",
        "git push :",
        "git push origin main",
        "git push -- --delete",
        "git update-ref -d",
        "git update-ref --stdin",
        "git update-ref -d refs/heads/topic old extra",
        "git update-ref \"$FLAG\" refs/heads/topic",
        "git worktree remove",
        "git worktree remove one two",
        "git worktree prune --dry-run",
        "git worktree prune -n",
        "git worktree prune --expire",
        "git worktree add ../topic",
        "git worktree list",
        "git worktree \"$ACTION\" old",
        "git submodule deinit",
        "git submodule deinit -f",
        "git submodule deinit --all",
        "git submodule update --init",
        "git submodule \"$ACTION\" vendor/library",
        "git remote remove origin",
        "git branch -D old --help",
        "git tag -d v1 --help",
        "git stash clear --help",
        "git push --delete origin old --help",
        "git update-ref -d refs/heads/topic --help",
        "git worktree remove old --help",
        "git submodule deinit vendor/library --help",
    ] {
        let plan = bash_plan(source);
        let observation = observe(plan.observation_request(), "echo");
        let stream = finalize(plan, observation);
        assert!(
            !stream.effects().iter().any(|effect| {
                matches!(effect.kind(), EffectKind::Git { operation } if operation.as_str() == "ref-delete")
            }),
            "{source}: {:?}",
            stream.effects()
        );
    }
}

#[test]
fn destructive_clean_and_discard_evidence_is_bounded() {
    for (source, operation) in [
        ("git clean -f", "clean-force"),
        ("git clean -fdx", "clean-force"),
        ("git clean --f", "clean-force"),
        ("git clean --no-force -f", "clean-force"),
        ("git clean -f -e '*.keep'", "clean-force"),
        ("git clean . -f", "clean-force"),
        ("git clean build -f .", "clean-force"),
        ("git clean -f .git/..", "clean-force"),
        ("git clean . -f -", "clean-force"),
        ("git -c clean.requireForce=false clean", "clean-force"),
        ("git checkout -f", "worktree-discard"),
        ("git checkout -qf", "worktree-discard"),
        ("git checkout -f --no-merge", "worktree-discard"),
        ("git checkout -f --no-patch", "worktree-discard"),
        ("git checkout -f -", "worktree-discard"),
        ("git checkout -f -b topic", "worktree-discard"),
        (
            "git checkout -f -b topic --no-detach origin/other",
            "worktree-discard",
        ),
        ("git checkout -fb topic", "worktree-discard"),
        ("git checkout -- . --keep", "worktree-discard"),
        ("git checkout --no-patch -- .", "worktree-discard"),
        ("git checkout HEAD .", "worktree-discard"),
        ("git checkout -f -- src/lib.rs", "path-discard"),
        ("git checkout HEAD -- src/lib.rs", "path-discard"),
        ("git restore -- . --keep", "worktree-discard"),
        ("git restore src/lib.rs", "path-discard"),
        ("git restore --staged --worktree src/lib.rs", "path-discard"),
        ("git restore src/lib.rs > .", "path-discard"),
        ("git switch -f main", "worktree-discard"),
        ("git switch -f --no-merge main", "worktree-discard"),
        ("git switch --discard-changes main", "worktree-discard"),
        ("git switch --di main", "worktree-discard"),
        ("git switch -f -", "worktree-discard"),
    ] {
        let plan = bash_plan(source);
        let stream = finalize(plan.clone(), observe(plan.observation_request(), "echo"));
        assert!(stream.effects().iter().any(|effect| {
            matches!(effect.kind(), EffectKind::Git { operation: actual } if actual.as_str() == operation)
        }), "{source}: {:?}", stream.effects());
        if operation == "path-discard" {
            assert!(
                stream.effects().iter().all(|effect| {
                    !matches!(effect.kind(), EffectKind::Git { operation: actual }
                    if actual.as_str() == "worktree-discard")
                }),
                "{source}: {:?}",
                stream.effects()
            );
        }
    }

    for source in [
        "git checkout -- .",
        "git restore .",
        "git checkout -f",
        "git switch -f main",
    ] {
        let plan = bash_plan(source);
        let stream = finalize(plan.clone(), observe(plan.observation_request(), "echo"));
        assert!(
            stream.effects().iter().all(|effect| {
                !matches!(effect.kind(), EffectKind::Git { operation }
                if operation.as_str() == "path-discard")
            }),
            "{source}: {:?}",
            stream.effects()
        );
    }

    for source in [
        "git clean -f --no-force",
        "git clean -n -f",
        "git clean -i -f",
        "git clean -nef .",
        "git clean -ef .",
        "git clean -f :/",
        "git clean -- . -f",
        "git clean -f ':!keep'",
        "git clean -f \"$PATH\"",
        "git -c clean.requireForce=maybe clean",
        "git checkout -f main",
        "git checkout -bf",
        "git switch -C main",
        "git switch --force-create main",
        "git switch -f",
        "git switch -f --no-force main",
        "git switch --discard-changes --no-discard-changes main",
        "git switch -f \"$BRANCH\"",
        "git checkout -f --no-merge --merge",
        "git checkout -f --no-patch --patch",
        "git checkout --no-patch --patch -- .",
        "git switch -f --no-merge --merge main",
        "git switch -f main other",
        "git checkout HEAD HEAD -- .",
        "GIT_WORK_TREE=/tmp/alternate git clean -f",
        "git clean .git",
        "git clean -f .git",
        "git clean -- . -f",
        "git restore 'src/*'",
        "git restore \"$PATH\"",
        "GIT_WORK_TREE=/tmp/alternate git restore src/lib.rs",
    ] {
        let plan = bash_plan(source);
        let stream = finalize(plan.clone(), observe(plan.observation_request(), "echo"));
        assert!(
            !stream.effects().iter().any(|effect| {
                matches!(effect.kind(), EffectKind::Git { operation } if matches!(operation.as_str(), "clean-force" | "worktree-discard" | "path-discard"))
            }),
            "{source}: {:?}",
            stream.effects()
        );
    }
}

#[test]
fn clean_checkout_and_restore_project_literal_filesystem_effects() {
    for (source, operation) in [
        ("git clean -f", FilesystemOperation::Delete),
        ("git clean -fdx -- .", FilesystemOperation::Delete),
        ("git clean . -f", FilesystemOperation::Delete),
        ("git clean -f .git/..", FilesystemOperation::Delete),
        ("git checkout -- .", FilesystemOperation::Write),
        ("git checkout .", FilesystemOperation::Write),
        ("git checkout HEAD -- .", FilesystemOperation::Write),
        ("git checkout -- . --keep", FilesystemOperation::Write),
        ("git checkout HEAD .", FilesystemOperation::Write),
        ("git restore -- . --keep", FilesystemOperation::Write),
        ("git restore .", FilesystemOperation::Write),
        ("git restore --source=HEAD~1 .", FilesystemOperation::Write),
        (
            "git restore --staged --worktree .",
            FilesystemOperation::Write,
        ),
    ] {
        let plan = bash_plan(source);
        let stream = finalize(plan.clone(), observe(plan.observation_request(), "echo"));
        assert!(
            stream.effects().iter().any(|effect| {
                matches!(
                    effect.kind(),
                    EffectKind::Filesystem { effect }
                        if effect.operation == operation && effect.selects_root
                )
            }),
            "{source}: {:?}",
            stream.effects()
        );
    }

    for source in [
        "git clean -n -f",
        "git clean -i -f",
        "git clean -f build/generated",
        "git clean -f :/",
        "git clean -f .git",
        "git checkout -f -- src/lib.rs",
        "git restore src/lib.rs",
        "git restore --staged .",
        "git restore --patch .",
        "git restore :/",
        "git restore ':!keep'",
    ] {
        let plan = bash_plan(source);
        let stream = finalize(plan.clone(), observe(plan.observation_request(), "echo"));
        assert!(
            !stream.effects().iter().any(|effect| {
                matches!(effect.kind(), EffectKind::Filesystem { effect } if effect.selects_root)
            }),
            "{source}: {:?}",
            stream.effects()
        );
    }
}

#[test]
fn git_commands_lower_only_their_exact_semantic_operations() {
    for (source, operation) in [
        ("git status --short", "status"),
        ("git --no-pager status", "status"),
        ("git branch -av", "branch-list"),
        ("git tag --list 'v*'", "tag-list"),
        ("git rev-parse HEAD", "rev-parse"),
        ("git describe --always", "describe"),
        ("git remote", "remote-list"),
        ("git add src/lib.rs", "add"),
        ("git commit -m update", "commit"),
        ("git commit --message=update --quiet", "commit"),
        ("git stash push", "stash"),
        ("git stash apply", "stash"),
        ("git stash pop", "stash"),
        ("git stash branch recovered", "stash"),
        ("git switch -c topic", "switch"),
        ("git switch --create=topic", "switch"),
        ("git checkout -b topic", "checkout-branch"),
        ("git checkout HEAD -- src/lib.rs", "checkout-worktree"),
        ("git checkout .", "checkout-worktree"),
        ("git clean -n", "clean"),
        ("git restore src/lib.rs", "restore-worktree"),
        ("git restore --staged src/lib.rs", "restore-staged"),
        (
            "git restore --staged --source=HEAD~1 src/lib.rs",
            "restore-staged",
        ),
        (
            "git restore --staged --worktree src/lib.rs",
            "restore-worktree",
        ),
    ] {
        let plan = bash_plan(source);
        let observation = observe(plan.observation_request(), "echo");
        let stream = finalize(plan, observation);
        assert_eq!(stream.coverage(), Coverage::Full, "{source}");
        assert!(stream.effects().iter().any(|effect| {
            matches!(
                effect.kind(),
                EffectKind::Invocation {
                    invocation: InvocationEffect::Known {
                        program,
                        operation: actual,
                        ..
                    }
                } if program == "git" && actual.as_str() == operation
            )
        }));
        assert!(stream.effects().iter().any(|effect| {
            matches!(effect.kind(), EffectKind::Git { operation: actual } if actual.as_str() == operation)
        }));
    }

    let plan = bash_plan("git fetch origin");
    let observation = observe(plan.observation_request(), "echo");
    let stream = finalize(plan, observation);
    assert_eq!(stream.coverage(), Coverage::Full);
    assert!(stream.effects().iter().any(|effect| {
        matches!(effect.kind(), EffectKind::Git { operation } if operation.as_str() == "fetch")
    }));
    assert!(
        stream
            .effects()
            .iter()
            .any(|effect| matches!(effect.kind(), EffectKind::Network { .. }))
    );

    for source in [
        "git diff --output=patch.txt",
        "git diff --output patch.txt",
        "git diff --ext-diff",
        "git diff --no-index ../one ../two",
        "git log --oneline -5",
        "git diff --cached",
        "git show HEAD",
        "git blame src/lib.rs",
        "git blame --contents ../outside src/lib.rs",
        "git blame --ignore-revs-file ../outside src/lib.rs",
        "git log \"$FLAGS\"",
        "git branch --list --delete old",
        "git tag --list --delete v1",
        "git add --pathspec-from-file=../outside",
        "git add --edit src/lib.rs",
        "git add -A",
        "git add .",
        "git add 'src/*'",
        "git commit --amend -m update",
        "git commit -am update",
        "git commit --all -m update",
        "git commit --include src/lib.rs -m update",
        "git commit --only src/lib.rs -m update",
        "git commit -m update src/lib.rs",
        "git commit",
        "git commit -F ../message",
        "git commit -t ../template",
        "git commit -Skey -m update",
        "git commit --no-verify -m update",
        "git commit -n -m update",
        "git switch --discard-changes main",
        "git switch main",
        "git switch --create=topic main",
        "git switch '--create=topic*'",
        "git switch '--create=topic{one,two}'",
        "git switch --force-create main",
        "git switch --orphan topic",
        "git switch --detach HEAD",
        "git switch --recurse-submodules main",
        "git switch --merge main",
        "git checkout -b topic -B existing",
        "git checkout -b topic main",
        "git checkout '-btopic*'",
        "git checkout :/",
        "git restore :/",
        "git restore --staged 'src/*'",
        "git restore --staged",
        "git -c core.pager=evil log",
        "git -c include.path=/tmp/other-config status",
    ] {
        let plan = bash_plan(source);
        let observation = observe(plan.observation_request(), "echo");
        assert_eq!(
            finalize(plan, observation).coverage(),
            Coverage::Partial,
            "{source}"
        );
    }

    for source in [
        "git branch topic",
        "git tag v1",
        "git checkout main",
        "git checkout --orphan topic",
        "git -C /outside status",
        "cd /outside && git status",
    ] {
        let plan = bash_plan(source);
        let observation = observe(plan.observation_request(), "echo");
        let stream = finalize(plan, observation);
        assert_eq!(stream.coverage(), Coverage::Full, "{source}");
        assert!(
            !stream
                .effects()
                .iter()
                .any(|effect| matches!(effect.kind(), EffectKind::Git { .. })),
            "{source}: {:?}",
            stream.effects()
        );
    }
}

#[test]
fn git_content_commands_expose_explicit_sensitive_paths_to_guards() {
    for source in [
        "git diff -- .env",
        "git show HEAD:.env",
        "git log -p -- .env",
        "git blame .env",
    ] {
        let plan = bash_plan(source);
        let observation = observe(plan.observation_request(), "echo");
        let stream = finalize(plan, observation);
        assert_eq!(stream.coverage(), Coverage::Partial, "{source}");
        assert!(stream.effects().iter().any(|effect| {
            matches!(
                effect.kind(),
                EffectKind::Filesystem { effect }
                    if effect.operation == FilesystemOperation::Read
                        && effect.sensitivity == Sensitivity::EnvironmentSecret
            )
        }));
    }
}

#[test]
fn stash_cleanup_lowers_without_a_stash_operation() {
    for source in ["git stash drop 'stash@{0}'", "git stash clear"] {
        let plan = bash_plan(source);
        let observation = observe(plan.observation_request(), "echo");
        let stream = finalize(plan, observation);
        assert!(
            !stream
                .effects()
                .iter()
                .any(|effect| matches!(effect.kind(), EffectKind::Git { operation } if operation.as_str() == "stash")),
            "{source}: {:?}",
            stream.effects()
        );
    }
}
