//! Evaluates package-registry guards from typed system-state effects.

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
            "registry-publish",
            SemanticCode::REGISTRY_PUBLISH,
            "registry-publish blocked publication to a package registry; keep the release unpublished and ask the operator to verify the package, version, and destination",
        ),
        (
            "registry-unpublish",
            SemanticCode::REGISTRY_UNPUBLISH,
            "registry-unpublish blocked package removal or published-name control transfer; preserve the published identity and ask the operator to verify the removal or owner change",
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
