//! Evaluates local host-state guards from typed invocation effects.

use Knowledge::Known;
use nah_proto::ctx::PolicyCtx;
use nah_proto::decision::{DecisionError, GuardAttribution, GuardContribution};
use nah_proto::effects::*;

pub(crate) fn add(
    evidence: &GuardEvidence,
    policy_ctx: &PolicyCtx,
    contributions: &mut Vec<GuardContribution>,
) -> Result<bool, DecisionError> {
    let mut added = false;
    for (name, matched, message) in [
        (
            "sys-power",
            matches("sys-power", evidence),
            "sys-power blocked a host power action; keep the host running and ask the operator to perform any intentional power action",
        ),
        (
            "sys-service-stop",
            matches("sys-service-stop", evidence),
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

fn matches(name: &str, evidence: &GuardEvidence) -> bool {
    evidence.graph().facts.iter().any(|fact| {
        if fact.certainty != Certainty::Exact || fact.condition.is_some() {
            return false;
        }
        match &fact.payload {
            FactPayload::SystemChange {
                operation,
                active: Known(true),
                cancel: Known(false),
                help: Known(false),
                ..
            } => matches!(
                (name, operation),
                ("sys-power", SystemOperation::Power)
                    | ("sys-service-stop", SystemOperation::ServiceStop)
            ),
            FactPayload::ContainerChange {
                operation: ContainerOperation::Stop,
                all: Known(true),
                active: Known(true),
                dry_run: Known(false),
                ..
            } => name == "sys-service-stop",
            _ => false,
        }
    })
}
