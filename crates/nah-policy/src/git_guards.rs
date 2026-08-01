//! Evaluates destructive Git guards; it does not interpret command-line syntax.

use nah_proto::action::{ActionStream, EffectKind, SemanticCode};
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
            "git-metadata",
            &SemanticCode::METADATA_MUTATION,
            "git-metadata blocked a destructive change to Git metadata; use Git commands instead of editing or deleting .git data directly",
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
    ] {
        if !policy_ctx
            .enabled_shipped_guards()
            .iter()
            .any(|enabled| enabled == name)
            || !action_stream.effects().iter().any(|effect| {
                matches!(effect.kind(), EffectKind::Git { operation: actual } if actual == operation)
            })
        {
            continue;
        }
        let guard = GuardAttribution::shipped(name, policy_ctx.policy_version())?;
        contributions.push(GuardContribution::new(guard, reason)?);
        blocked = true;
    }
    Ok(blocked)
}
