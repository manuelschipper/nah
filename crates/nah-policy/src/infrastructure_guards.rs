//! Evaluates infrastructure guards from typed system-state effects.

use nah_proto::action::{ActionStream, EffectKind, SemanticCode};
use nah_proto::ctx::PolicyCtx;
use nah_proto::decision::{DecisionError, GuardAttribution, GuardContribution};

pub(crate) fn add(
    action_stream: &ActionStream,
    policy_ctx: &PolicyCtx,
    contributions: &mut Vec<GuardContribution>,
) -> Result<bool, DecisionError> {
    let mut added = false;
    for (name, operations, message) in [
        (
            "infra-container-prune",
            &[SemanticCode::INFRA_CONTAINER_PRUNE][..],
            "infra-container-prune blocked broad unused-volume cleanup; narrow the cleanup or ask the operator to perform the reviewed prune",
        ),
        (
            "infra-container-reset",
            &[SemanticCode::INFRA_CONTAINER_RESET][..],
            "infra-container-reset blocked a complete Podman runtime reset; keep the runtime state intact and ask the operator to perform any deliberate reset",
        ),
        (
            "infra-iac-destroy",
            &[SemanticCode::INFRA_IAC_DESTROY][..],
            "infra-iac-destroy blocked whole-stack infrastructure destruction; keep the stack intact and ask the operator to perform any complete teardown",
        ),
        (
            "infra-k8s-delete",
            &[
                SemanticCode::INFRA_K8S_NAMESPACE_DELETE,
                SemanticCode::INFRA_K8S_CLUSTER_RESOURCE_DELETE,
                SemanticCode::INFRA_K8S_BULK_RESOURCE_DELETE,
            ][..],
            "infra-k8s-delete blocked a reviewed broad Kubernetes deletion; narrow the selection or ask the operator to perform the cluster change",
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
                        if operations.contains(candidate)
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
