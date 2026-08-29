#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

mod support;

use std::process::Command;

use nah_cli::decide_with;
use nah_proto::action::Coverage;
use nah_proto::decision::Verdict;
use serde_json::json;
use support::{call, ctx, git, repo};

#[cfg(unix)]
#[test]
fn destructive_git_guards_are_semantic_end_to_end() {
    let temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah resolves
    // paths before matching them
    let root = std::fs::canonicalize(temp.path()).unwrap();
    let repo = repo(&root);
    let context = ctx(&root);
    for (command, guard) in [
        ("rm -rf .git", "git-metadata"),
        ("rm -rf .git/objects/aa", "git-metadata"),
        ("rm -rf .git//objects/aa", "git-metadata"),
        ("unlink .git/objects/aa", "git-metadata"),
        ("rm -rf '.git/*'", "git-metadata"),
        ("rm -rf '.git/{objects,refs}'", "git-metadata"),
        ("echo corrupt > .git/objects/aa", "git-metadata"),
        ("cp replacement .git/refs/heads/main", "git-metadata"),
        ("touch .git/packed-refs", "git-metadata"),
        ("rm -rf backup.git/objects", "git-metadata"),
        ("echo corrupt > backup.git/refs/heads/main", "git-metadata"),
        ("git push --force", "git-force-push"),
        ("git push --mirror origin", "git-force-push"),
        (
            "git -c advice.detachedHead=false push --mirror",
            "git-force-push",
        ),
        (
            "git push --force --repo --help origin main",
            "git-force-push",
        ),
        ("git push --force \"$REMOTE\"", "git-force-push"),
        ("git push origin +main", "git-force-push"),
        (
            "git push --force-with-lease=other origin +main",
            "git-force-push",
        ),
        ("git reset --hard", "git-hard-reset"),
        ("git -c 'alias.wipe=reset --hard' wipe", "git-hard-reset"),
        ("git -c 'alias.wipe=!rm -rf /' wipe", "fs-system-tree"),
        ("git reset --h", "git-hard-reset"),
        ("/usr/bin/git reset --h", "git-hard-reset"),
        ("git reset --hard \"$REV\"", "git-hard-reset"),
        ("git filter-branch -f -- --all", "git-rewrite-force"),
        ("git filter-branch --force -- --all", "git-rewrite-force"),
        ("git filter-repo --force", "git-rewrite-force"),
        (
            "git filter-repo --force --replace-text --help",
            "git-rewrite-force",
        ),
        ("sudo git filter-repo --force", "git-rewrite-force"),
        (
            "git reflog expire --all --expire=now",
            "git-recovery-destroy",
        ),
        (
            "git reflog expire --expire-unreachable=now --all",
            "git-recovery-destroy",
        ),
        ("git gc --prune=now", "git-recovery-destroy"),
        ("git -c gc.pruneExpire=now gc", "git-recovery-destroy"),
        ("git gc --p=now", "git-recovery-destroy"),
        ("git prune --expire=now", "git-recovery-destroy"),
        ("git prune --exp=now", "git-recovery-destroy"),
        ("git prune --expire now", "git-recovery-destroy"),
        (
            "git reflog expire --expire-=now --a",
            "git-recovery-destroy",
        ),
        ("git push --force-w=other origin +main", "git-force-push"),
        ("sudo git -C . reset --hard", "git-hard-reset"),
        ("git clean -f", "git-clean-force"),
        ("git clean -fdx", "git-clean-force"),
        ("git clean . -f", "git-clean-force"),
        ("git clean build -f .", "git-clean-force"),
        ("git clean -f .git/..", "git-clean-force"),
        ("git clean . -f -", "git-clean-force"),
        ("git -c clean.requireForce=false clean", "git-clean-force"),
        ("git checkout -- .", "git-worktree-discard"),
        ("git checkout .", "git-worktree-discard"),
        ("git restore .", "git-worktree-discard"),
        ("git restore --staged --worktree .", "git-worktree-discard"),
        ("git checkout -f", "git-worktree-discard"),
        ("git checkout -f --no-merge", "git-worktree-discard"),
        ("git checkout -f --no-patch", "git-worktree-discard"),
        (
            "git checkout -f -b topic --no-detach origin/other",
            "git-worktree-discard",
        ),
        ("git checkout -- . --keep", "git-worktree-discard"),
        ("git checkout --no-patch -- .", "git-worktree-discard"),
        ("git checkout HEAD .", "git-worktree-discard"),
        ("git restore -- . --keep", "git-worktree-discard"),
        ("git switch --discard-changes main", "git-worktree-discard"),
        ("git switch -f --no-merge main", "git-worktree-discard"),
        ("gh repo delete", "git-remote-delete"),
        (
            "gh repo delete github.example.com/owner/project --yes",
            "git-remote-delete",
        ),
        (
            "gh repo delete owner/project --confirm=1",
            "git-remote-delete",
        ),
        ("glab repo delete group/project -y", "git-remote-delete"),
        (
            "glab repo delete group/project -y=TRUE",
            "git-remote-delete",
        ),
        ("gh api -X DELETE repos/{owner}/{repo}", "git-remote-delete"),
        (
            "gh api -X DELETE 'repos/owner/project#/issues'",
            "git-remote-delete",
        ),
        (
            "glab api --method DELETE projects/group%2Fproject",
            "git-remote-delete",
        ),
        (
            "glab api -X DELETE 'projects/123#anything'",
            "git-remote-delete",
        ),
        (
            "gh repo delete owner/project --yes --help=false",
            "git-remote-delete",
        ),
        (
            "glab api --help=0 -X DELETE projects/123",
            "git-remote-delete",
        ),
    ] {
        let result = decide_with(
            &call("Bash", json!({"command":command}), &repo),
            &context,
            |request| nah_observe::fulfill(request).map_err(|error| error.to_string()),
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

    for command in [
        "rm -rf .git/index",
        "rm -rf .git/objects/../index",
        "rm -rf .git/hooks/pre-commit",
        "rm -rf assets.git/index",
        "git push --force-with-lease",
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
        "git prune --d --exp=now",
        "git prune -n",
        "git reflog \"$ACTION\"",
        "git reflog expire --d --a --expire=now",
        "git push --dr --force origin main",
        "git stash drop 'stash@{0}'",
        "git stash clear",
        "git worktree list",
        "git worktree remove \"$PATH\"",
        "git worktree prune",
        "git worktree prune --dry-run",
        "git worktree -- remove old",
        "git -c user.name=Alice status",
        "git -c gc.pruneExpire=now gc --no-prune",
        "git -c gc.pruneExpire=now gc --prune=2.weeks.ago",
        "timeout 5 git worktree remove old",
        "git clean -n -f",
        "git clean -f -- src/lib.rs",
        "git clean -f ':/'",
        "git clean -- . -f",
        "GIT_WORK_TREE=/tmp/alternate git clean -f",
        "git clean .git",
        "git clean -f .git",
        "git checkout -f main",
        "git checkout HEAD HEAD -- .",
        "git checkout -f -- src/lib.rs",
        "git restore src/lib.rs",
        "git restore src/lib.rs > .",
        "git restore ':/'",
        "git switch -f main other",
        "git checkout -f --no-merge --merge",
        "git checkout -f --no-patch --patch",
        "git checkout --no-patch --patch -- .",
        "git switch -f --no-merge --merge main",
        "git branch -D old",
        "gh repo archive owner/project --yes",
        "gh repo delete \"$REPOSITORY\" --yes",
        "gh api -X DELETE repos/owner/project/issues",
        "glab repo transfer group/project other",
        "glab api -X DELETE projects/group/project",
        "curl -X DELETE https://api.github.com/repos/owner/project",
    ] {
        let result = decide_with(
            &call("Bash", json!({"command":command}), &repo),
            &context,
            |request| nah_observe::fulfill(request).map_err(|error| error.to_string()),
        );
        assert_ne!(result.core().verdict(), Verdict::Block, "{command}");
    }

    for (command, coverage) in [
        ("git -c user.name=Alice status", Coverage::Full),
        ("git -c \"user.name=$NAME\" status", Coverage::Full),
        ("git -c \"alias.wipe=$ALIAS\" wipe", Coverage::Partial),
        ("git --config-env=alias.wipe=ALIAS wipe", Coverage::Partial),
    ] {
        let result = decide_with(
            &call("Bash", json!({"command":command}), &repo),
            &context,
            |request| nah_observe::fulfill(request).map_err(|error| error.to_string()),
        );
        assert_eq!(result.core().verdict(), Verdict::Delegate, "{command}");
        assert_eq!(result.core().coverage(), coverage, "{command}");
    }
}

#[cfg(unix)]
#[test]
fn parser_regressions_match_real_git_behavior() {
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

    let inherited_home = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_nah"))
        .current_dir(&alternate_repo)
        .env("HOME", inherited_home.path())
        .env("GIT_WORK_TREE", &alternate_tree)
        .args(["test", "--json", "git clean -f"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["decision"]["verdict"], "delegate");
    assert_eq!(result["decision"]["coverage"], "partial");
}

#[test]
fn granular_git_operations_lower_to_their_exact_coverage() {
    let temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah resolves
    // paths before matching them
    let root = std::fs::canonicalize(temp.path()).unwrap();
    let repo = repo(&root);
    std::fs::write(repo.join(".env"), "TOKEN=secret\n").unwrap();
    let context = ctx(&root);

    for command in [
        "git status --short",
        "git status > status.txt",
        "git branch -a",
        "git tag --list",
        "git remote",
        "git add src/lib.rs",
        "git commit -m update",
        "git switch -c topic",
        "git checkout -b topic",
        "git restore --staged src/lib.rs",
        "git restore --staged --source=HEAD~1 src/lib.rs",
    ] {
        let result = decide_with(
            &call("Bash", json!({"command":command}), &repo),
            &context,
            |request| nah_observe::fulfill(request).map_err(|error| error.to_string()),
        );
        assert_eq!(result.core().verdict(), Verdict::Delegate, "{command}");
        assert_eq!(result.core().coverage(), Coverage::Full, "{command}");
    }

    for (command, coverage) in [
        ("git fetch origin", Coverage::Full),
        ("git log --oneline -1", Coverage::Partial),
        ("git diff -- src/lib.rs", Coverage::Partial),
        ("git show HEAD:src/lib.rs", Coverage::Partial),
        ("git blame src/lib.rs", Coverage::Partial),
        ("git branch topic", Coverage::Full),
        ("git tag v1", Coverage::Full),
        ("git remote -v", Coverage::Full),
        ("git checkout main", Coverage::Full),
        ("git restore src/lib.rs", Coverage::Full),
        ("git stash push", Coverage::Full),
        ("git stash apply", Coverage::Full),
        ("git diff --output=patch.txt", Coverage::Partial),
        ("git commit --amend -m update", Coverage::Partial),
        ("git commit -am update", Coverage::Partial),
        ("git commit -m update src/lib.rs", Coverage::Partial),
        ("git commit --no-verify -m update", Coverage::Partial),
        ("git commit -n -m update", Coverage::Partial),
        ("git add -A", Coverage::Partial),
        ("git add .", Coverage::Partial),
        ("git add src", Coverage::Partial),
        ("git add 'src/*'", Coverage::Partial),
        ("git switch main", Coverage::Partial),
        ("git switch --create=topic main", Coverage::Partial),
        ("git switch --orphan topic", Coverage::Partial),
        ("git switch --detach HEAD", Coverage::Partial),
        ("git restore --staged 'src/*'", Coverage::Partial),
        ("git restore --staged", Coverage::Partial),
    ] {
        let result = decide_with(
            &call("Bash", json!({"command":command}), &repo),
            &context,
            |request| nah_observe::fulfill(request).map_err(|error| error.to_string()),
        );
        assert_eq!(result.core().verdict(), Verdict::Delegate, "{command}");
        assert_eq!(result.core().coverage(), coverage, "{command}");
    }

    for command in [
        "git diff -- .env",
        "git show HEAD:.env",
        "git log -p -- .env",
        "git blame .env",
        "git add .env",
    ] {
        let result = decide_with(
            &call("Bash", json!({"command":command}), &repo),
            &context,
            |request| nah_observe::fulfill(request).map_err(|error| error.to_string()),
        );
        assert_eq!(result.core().verdict(), Verdict::Block, "{command}");
        assert!(
            result
                .core()
                .policy_attributions()
                .iter()
                .any(|guard| guard.name() == "secrets-env"),
            "{command}: {:?}",
            result.core().policy_attributions()
        );
    }

    let outside = &root.join("outside");
    std::fs::create_dir(outside).unwrap();
    let result = decide_with(
        &call("Bash", json!({"command":"git status"}), outside),
        &context,
        |request| nah_observe::fulfill(request).map_err(|error| error.to_string()),
    );
    assert_eq!(result.core().verdict(), Verdict::Delegate);
    assert_eq!(result.core().coverage(), Coverage::Partial);
}
