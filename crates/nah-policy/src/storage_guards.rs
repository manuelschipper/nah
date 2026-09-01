//! Evaluates remote-storage and backup guards from typed system-state effects.

use nah_proto::action::{ActionStream, EffectKind, SemanticCode};
use nah_proto::ctx::PolicyCtx;
use nah_proto::decision::{DecisionError, GuardAttribution, GuardContribution};

pub(crate) fn add(
    action_stream: &ActionStream,
    policy_ctx: &PolicyCtx,
    contributions: &mut Vec<GuardContribution>,
) -> Result<bool, DecisionError> {
    let mut added = false;
    for (name, operation, message) in [
        (
            "storage-destroy",
            SemanticCode::STORAGE_DESTROY,
            "storage-destroy blocked deletion of a complete backup repository or every selected backup; keep the recovery set intact and ask the operator to perform any deliberate repository removal",
        ),
        (
            "storage-recursive-delete",
            SemanticCode::STORAGE_RECURSIVE_DELETE,
            "storage-recursive-delete blocked broad remote deletion or destination-deleting synchronization; narrow the selection or ask the operator to perform the reviewed cleanup",
        ),
        (
            "storage-snapshot-delete",
            SemanticCode::STORAGE_SNAPSHOT_DELETE,
            "storage-snapshot-delete blocked snapshot, archive, volume, or retention deletion; keep the recovery point intact and ask the operator to perform the reviewed removal",
        ),
    ] {
        if !policy_ctx
            .enabled_shipped_guards()
            .iter()
            .any(|enabled| enabled == name)
            || !action_stream.effects().iter().any(|effect| {
                matches!(
                    effect.kind(),
                    EffectKind::SystemState { operation: candidate }
                        if candidate == &operation
                )
            })
        {
            continue;
        }
        let guard = GuardAttribution::shipped(name)?;
        contributions.push(GuardContribution::new(guard, message)?);
        added = true;
    }
    Ok(added)
}
