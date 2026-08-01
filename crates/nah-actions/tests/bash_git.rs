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
        "git push --force-with-lease",
        "git push --force-with-lease=main",
        "git push --force-with-lease origin +main",
        "git push --force-with-lease=main origin +main",
        "git push -- --force",
        "git -- push --force",
        "git reset --soft HEAD~1",
        "git reset -- --hard",
        "git filter-branch -- --all",
        "git filter-repo --invert-paths --path secret",
        "git filter-repo --dry-run --force",
        "git filter-repo --analyze",
        "git filter-repo --version",
        "git reflog show",
        "git reflog show expire",
        "git reflog expire --all",
        "git reflog expire --dry-run --all --expire=now",
        "git reflog delete HEAD@{0}",
        "git gc --prune=2.weeks.ago",
        "git gc -- --prune=now",
        "git push --dry-run --force origin main",
        "git push -nf origin main",
        "git push --dry-run --mirror origin",
        "git push -n --mirror origin",
        "git clone --mirror origin local.git",
        "git push origin --delete old",
        "git push --delete \"$REMOTE\" \"$REF\"",
        "git push origin :old",
        "git push --prune origin",
        "git push -vd origin old",
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
        "git stash drop 'stash@{0}'",
        "git stash clear",
        "git worktree list",
        "git worktree remove \"$PATH\"",
        "git worktree prune",
        "git worktree prune --dry-run",
        "git worktree -- remove old",
        "timeout 5 git worktree remove old",
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
        ("git restore src/lib.rs", "restore-worktree"),
        ("git restore --staged src/lib.rs", "restore-staged"),
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
        "git restore --staged --worktree src/lib.rs",
        "git restore --staged --source=HEAD~1 src/lib.rs",
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
