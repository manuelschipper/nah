//! Evaluates local host-state guards from typed invocation effects.

use nah_proto::action::{ActionStream, EffectKind, InvocationEffect, SemanticCode};
use nah_proto::ctx::PolicyCtx;
use nah_proto::decision::{DecisionError, GuardAttribution, GuardContribution};

pub(crate) fn add(
    action_stream: &ActionStream,
    policy_ctx: &PolicyCtx,
    contributions: &mut Vec<GuardContribution>,
) -> Result<bool, DecisionError> {
    let mut added = false;
    for (name, matched, message) in [
        (
            "sys-power",
            action_stream.effects().iter().any(|effect| {
                matches!(
                    effect.kind(),
                    EffectKind::Invocation {
                        invocation: InvocationEffect::Known { operation, .. }
                    } if operation == &SemanticCode::HOST_POWER
                )
            }),
            "sys-power blocked a host power action; keep the host running and ask the operator to perform any intentional power action",
        ),
        (
            "sys-service-stop",
            action_stream.effects().iter().any(|effect| {
                matches!(
                    effect.kind(),
                    EffectKind::SystemState { operation }
                        if operation == &SemanticCode::SERVICE_STOP
                )
            }),
            "sys-service-stop blocked a reviewed service or stop-all container shutdown; keep the service or containers running and ask the operator to perform any intentional stop",
        ),
    ] {
        if !policy_ctx
            .enabled_shipped_guards()
            .iter()
            .any(|enabled| enabled == name)
            || !matched
        {
            continue;
        }
        let guard = GuardAttribution::shipped(name)?;
        contributions.push(GuardContribution::new(guard, message)?);
        added = true;
    }
    Ok(added)
}
