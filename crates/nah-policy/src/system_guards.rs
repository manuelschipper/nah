//! Evaluates local host-state guards from typed invocation effects.

use nah_proto::action::{ActionStream, EffectKind, InvocationEffect, SemanticCode};
use nah_proto::ctx::PolicyCtx;
use nah_proto::decision::{DecisionError, GuardAttribution, GuardContribution};

pub(crate) fn add(
    action_stream: &ActionStream,
    policy_ctx: &PolicyCtx,
    contributions: &mut Vec<GuardContribution>,
) -> Result<bool, DecisionError> {
    if !policy_ctx
        .enabled_shipped_guards()
        .iter()
        .any(|enabled| enabled == "sys-power")
        || !action_stream.effects().iter().any(|effect| {
            matches!(
                effect.kind(),
                EffectKind::Invocation {
                    invocation: InvocationEffect::Known { operation, .. }
                } if operation == &SemanticCode::HOST_POWER
            )
        })
    {
        return Ok(false);
    }
    let guard = GuardAttribution::shipped("sys-power")?;
    contributions.push(GuardContribution::new(
        guard,
        "sys-power blocked a host power action; keep the host running and ask the operator to perform any intentional power action",
    )?);
    Ok(true)
}
