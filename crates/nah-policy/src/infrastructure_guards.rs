//! Evaluates infrastructure guards from typed whole-stack effects.

use nah_proto::action::{ActionStream, EffectKind, SemanticCode};
use nah_proto::ctx::PolicyCtx;
use nah_proto::decision::{DecisionError, GuardAttribution, GuardContribution};

pub(crate) fn add(
    action_stream: &ActionStream,
    policy_ctx: &PolicyCtx,
    contributions: &mut Vec<GuardContribution>,
) -> Result<bool, DecisionError> {
    const NAME: &str = "infra-iac-destroy";
    if !policy_ctx
        .enabled_shipped_guards()
        .iter()
        .any(|enabled| enabled == NAME)
        || !action_stream.effects().iter().any(|effect| {
            matches!(
                effect.kind(),
                EffectKind::SystemState { operation }
                    if operation == &SemanticCode::INFRA_IAC_DESTROY
            )
        })
    {
        return Ok(false);
    }
    let guard = GuardAttribution::shipped(NAME)?;
    contributions.push(GuardContribution::new(
        guard,
        "infra-iac-destroy blocked whole-stack infrastructure destruction; keep the stack intact and ask the operator to perform any complete teardown",
    )?);
    Ok(true)
}
