//! Evaluates destructive Git guards; it does not interpret command-line syntax.

use nah_proto::action::{ActionStream, EffectKind, FilesystemOperation, PathScope, SemanticCode};
use nah_proto::ctx::PolicyCtx;
use nah_proto::decision::{DecisionError, GuardAttribution, GuardContribution};

pub(crate) fn add(
    action_stream: &ActionStream,
    policy_ctx: &PolicyCtx,
    contributions: &mut Vec<GuardContribution>,
) -> Result<bool, DecisionError> {
    let mut blocked = false;
    for (name, operation, reason) in [
        (
            "git-clean-force",
            &SemanticCode::CLEAN_FORCE,
            "git-clean-force blocked a forced clean selecting the project root; preview with git clean -n, name the intended target, or ask the operator to perform the project-wide clean",
        ),
        (
            "git-metadata",
            &SemanticCode::METADATA_MUTATION,
            "git-metadata blocked a destructive change to Git metadata; use Git commands instead of editing or deleting .git data directly",
        ),
        (
            "git-path-discard",
            &SemanticCode::PATH_DISCARD,
            "git-path-discard blocked a named-path working-tree discard; inspect git diff and stash wanted work before replacing the path",
        ),
        (
            "git-force-push",
            &SemanticCode::FORCE_PUSH,
            "git-force-push blocked a force push without lease protection; fetch and review remote changes; ask the operator to verify the refs before using --force-with-lease",
        ),
        (
            "git-hard-reset",
            &SemanticCode::HARD_RESET,
            "git-hard-reset blocked git reset --hard; inspect the diff and preserve wanted work; use a targeted restore or ask the operator to perform the full reset",
        ),
        (
            "git-rewrite-force",
            &SemanticCode::REWRITE_FORCE,
            "git-rewrite-force blocked a forced history rewrite; remove the force bypass and preview the rewrite; ask the operator to verify the affected history",
        ),
        (
            "git-recovery-destroy",
            &SemanticCode::RECOVERY_DESTROY,
            "git-recovery-destroy blocked deletion of Git recovery history; keep reflogs and recovery refs; ask the operator to verify they are no longer needed",
        ),
        (
            "git-remote-repo-delete",
            &SemanticCode::GIT_REMOTE_REPO_DELETE,
            "git-remote-repo-delete blocked deletion of an entire hosted repository; preserve the hosted project and ask the operator to verify any whole-repository deletion",
        ),
        (
            "git-worktree-discard",
            &SemanticCode::WORKTREE_DISCARD,
            "git-worktree-discard blocked a project-wide working-tree discard; inspect git diff, stash wanted work, use a named restore, or ask the operator to perform the broad discard",
        ),
    ] {
        if !policy_ctx
            .enabled_shipped_guards()
            .iter()
            .any(|enabled| enabled == name)
            || !matches_guard(operation, action_stream)
        {
            continue;
        }
        let guard = GuardAttribution::shipped(name)?;
        contributions.push(GuardContribution::new(guard, reason)?);
        blocked = true;
    }
    Ok(blocked)
}

fn matches_guard(operation: &SemanticCode, action_stream: &ActionStream) -> bool {
    action_stream.effects().iter().any(|effect| {
        let EffectKind::Git { operation: actual } = effect.kind() else {
            return false;
        };
        actual == operation
    }) || operation == &SemanticCode::PATH_DISCARD && matches_show_path_discard(action_stream)
}

fn matches_show_path_discard(action_stream: &ActionStream) -> bool {
    action_stream.effects().iter().any(|show| {
        matches!(
            show.kind(),
            EffectKind::Git { operation } if operation.as_str() == "show"
        ) && action_stream.effects().iter().any(|read_effect| {
            let EffectKind::Filesystem { effect: read } = read_effect.kind() else {
                return false;
            };
            read_effect.stage() == show.stage()
                && read.operation == FilesystemOperation::Read
                && matches!(&read.scope, PathScope::Project { .. })
                && !read.selects_root
                && !read.pattern
                && action_stream.effects().iter().any(|write_effect| {
                    let EffectKind::Filesystem { effect: write } = write_effect.kind() else {
                        return false;
                    };
                    write_effect.stage() == show.stage()
                        && write.operation == FilesystemOperation::Write
                        && matches!(&write.scope, PathScope::Project { .. })
                        && !write.selects_root
                        && !write.pattern
                        && write.target == read.target
                })
        })
    })
}
