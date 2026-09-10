//! Evaluates package-registry guards from typed system-state effects.

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
    for (name, message) in [
        (
            "registry-publish",
            "registry-publish blocked publication to a package registry; keep the release unpublished and ask the operator to verify the package, version, and destination",
        ),
        (
            "registry-unpublish",
            "registry-unpublish blocked package removal or published-name control transfer; preserve the published identity and ask the operator to verify the removal or owner change",
        ),
    ] {
        if !policy_ctx
            .enabled_shipped_guards()
            .iter()
            .any(|enabled| enabled == name)
            || !matches(name, evidence)
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
            FactPayload::PackageChange {
                operation,
                ecosystem,
                active: Known(true),
                dry_run: Known(false),
                ..
            } => match name {
                "registry-publish" => *operation == PackageOperation::Publish,
                "registry-unpublish" => {
                    matches!(
                        operation,
                        PackageOperation::Remove | PackageOperation::TransferOwnership
                    ) || *operation == PackageOperation::Yank
                        && matches!(ecosystem, Known(ecosystem) if ecosystem == "gem")
                }
                _ => false,
            },
            _ => false,
        }
    })
}
