//! Evaluates infrastructure guards from typed system-state effects.

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
            "infra-container-reset",
            "infra-container-reset blocked a complete Podman runtime reset; keep the runtime state intact and ask the operator to perform any deliberate reset",
        ),
        (
            "infra-container-volume-delete",
            "infra-container-volume-delete blocked broad unused-volume cleanup; narrow the cleanup or ask the operator to perform the reviewed prune",
        ),
        (
            "infra-iac-destroy",
            "infra-iac-destroy blocked whole-stack infrastructure destruction; keep the stack intact and ask the operator to perform any complete teardown",
        ),
        (
            "infra-k8s-delete",
            "infra-k8s-delete blocked a reviewed broad Kubernetes deletion; narrow the selection or ask the operator to perform the cluster change",
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
            FactPayload::ContainerChange {
                target,
                operation,
                selection,
                broad_unused,
                named_volumes,
                attached_volume_removal,
                active: Known(true),
                dry_run: Known(false),
                ..
            } => {
                let kind = evidence
                    .graph()
                    .resources
                    .iter()
                    .find(|resource| resource.id == *target)
                    .map(|resource| resource.identity.kind);
                match name {
                    "infra-container-reset" => {
                        *operation == ContainerOperation::ResetRuntime
                            && kind == Some(ResourceKind::ContainerRuntime)
                            && *selection == Selection::Whole
                    }
                    "infra-container-volume-delete" => {
                        *operation == ContainerOperation::DeleteVolume
                            && (*attached_volume_removal == Known(true)
                                || *broad_unused == Known(true)
                                    && (kind == Some(ResourceKind::ContainerRuntime)
                                        || kind == Some(ResourceKind::ContainerVolume)
                                            && *named_volumes == Known(true)))
                    }
                    _ => false,
                }
            }
            FactPayload::InfrastructureChange {
                operation,
                kind,
                scope,
                selection,
                active: Known(true),
                preview: Known(false),
                help: Known(false),
                dry_run: Known(false),
                ..
            } => match name {
                "infra-iac-destroy" => {
                    *kind == InfrastructureKind::ManagedStack
                        && *operation == InfrastructureOperation::Destroy
                        && *selection == Selection::Whole
                }
                "infra-k8s-delete" => {
                    *kind == InfrastructureKind::KubernetesResource
                        && *operation == InfrastructureOperation::Delete
                        && (matches!(
                            scope,
                            Known(InfrastructureScope::Namespace | InfrastructureScope::Cluster)
                        ) || *scope == Known(InfrastructureScope::NamespacedResource)
                            && matches!(selection, Selection::Whole | Selection::Pattern { .. }))
                }
                _ => false,
            },
            _ => false,
        }
    })
}
