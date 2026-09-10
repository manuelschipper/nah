#![allow(clippy::disallowed_types)]

use crate::support;
use nah_proto::effects::*;

use nah_proto::action::{ActionStream, Coverage, EffectKind, SemanticCode};
use nah_proto::decision::Verdict;
use support::{guard_policy, guarded_stream};

#[test]
fn infrastructure_destroy_requires_its_enabled_guard() {
    let evidence = support::operation_evidence(infrastructure(
        InfrastructureKind::ManagedStack,
        Knowledge::Unknown,
    ));
    let stream = ActionStream::new(Coverage::Partial, vec![], vec![]).unwrap();

    let enabled = nah_policy::decide(
        &stream,
        &evidence,
        &guard_policy("infra-iac-destroy", true),
        &[],
    )
    .unwrap();
    assert_eq!(enabled.verdict(), Verdict::Block);
    assert_eq!(
        enabled
            .policy_attributions()
            .iter()
            .map(|guard| guard.name())
            .collect::<Vec<_>>(),
        vec!["infra-iac-destroy"]
    );
    support::assert_operation_uncertainty(&evidence, "infra-iac-destroy");

    let disabled = nah_policy::decide(
        &stream,
        &evidence,
        &guard_policy("infra-iac-destroy", false),
        &[],
    )
    .unwrap();
    assert_eq!(disabled.verdict(), Verdict::Delegate);
}

#[test]
fn container_guards_require_their_matching_enabled_facts() {
    for (name, operation) in [
        (
            "infra-container-volume-delete",
            container(ContainerOperation::DeleteVolume),
        ),
        (
            "infra-container-reset",
            container(ContainerOperation::ResetRuntime),
        ),
    ] {
        let evidence = support::operation_evidence(operation);
        let stream = ActionStream::new(Coverage::Partial, vec![], vec![]).unwrap();
        let enabled =
            nah_policy::decide(&stream, &evidence, &guard_policy(name, true), &[]).unwrap();
        assert_eq!(enabled.verdict(), Verdict::Block, "{name}");
        assert_eq!(
            enabled
                .policy_attributions()
                .iter()
                .map(|guard| guard.name())
                .collect::<Vec<_>>(),
            vec![name]
        );
        support::assert_operation_uncertainty(&evidence, name);

        let disabled =
            nah_policy::decide(&stream, &evidence, &guard_policy(name, false), &[]).unwrap();
        assert_eq!(disabled.verdict(), Verdict::Delegate, "{name}");
    }
}

#[test]
fn container_reset_and_volume_delete_guards_are_isolated() {
    for (enabled, operation) in [
        (
            "infra-container-volume-delete",
            container(ContainerOperation::ResetRuntime),
        ),
        (
            "infra-container-reset",
            container(ContainerOperation::DeleteVolume),
        ),
    ] {
        let evidence = support::operation_evidence(operation);
        let stream = ActionStream::new(Coverage::Partial, vec![], vec![]).unwrap();
        let decision =
            nah_policy::decide(&stream, &evidence, &guard_policy(enabled, true), &[]).unwrap();
        assert_eq!(decision.verdict(), Verdict::Delegate, "{enabled}");
    }
}

#[test]
fn infrastructure_guard_ignores_legacy_codes() {
    for (effect, invocation) in [
        (
            EffectKind::SystemState {
                operation: SemanticCode::LOGICAL_STORAGE_DESTROY,
            },
            false,
        ),
        (
            EffectKind::Git {
                operation: SemanticCode::INFRA_IAC_DESTROY,
            },
            false,
        ),
        (
            EffectKind::known("terraform", "infra-iac-destroy").unwrap(),
            true,
        ),
    ] {
        let stream = if invocation {
            ActionStream::new(Coverage::Partial, vec![vec![effect]], vec![]).unwrap()
        } else {
            guarded_stream(effect)
        };
        let decision = nah_policy::decide(
            &stream,
            &crate::support::evidence(&stream, &nah_inline::InlineReport::default()),
            &guard_policy("infra-iac-destroy", true),
            &[],
        )
        .unwrap();
        assert_eq!(decision.verdict(), Verdict::Delegate);
    }
}

#[test]
fn kubernetes_guard_matches_each_reviewed_scope_when_enabled() {
    for operation in [
        Knowledge::Known(InfrastructureScope::Namespace),
        Knowledge::Known(InfrastructureScope::Cluster),
        Knowledge::Known(InfrastructureScope::NamespacedResource),
    ] {
        let evidence = support::operation_evidence(infrastructure(
            InfrastructureKind::KubernetesResource,
            operation,
        ));
        let stream = ActionStream::new(Coverage::Partial, vec![], vec![]).unwrap();
        let enabled = nah_policy::decide(
            &stream,
            &evidence,
            &guard_policy("infra-k8s-delete", true),
            &[],
        )
        .unwrap();
        assert_eq!(enabled.verdict(), Verdict::Block);
        assert_eq!(
            enabled
                .policy_attributions()
                .iter()
                .map(|guard| guard.name())
                .collect::<Vec<_>>(),
            vec!["infra-k8s-delete"]
        );
        support::assert_operation_uncertainty(&evidence, "infra-k8s-delete");

        let disabled = nah_policy::decide(
            &stream,
            &evidence,
            &guard_policy("infra-k8s-delete", false),
            &[],
        )
        .unwrap();
        assert_eq!(disabled.verdict(), Verdict::Delegate);
    }
}

#[test]
fn kubernetes_guard_requires_a_system_state_effect() {
    for code in [
        SemanticCode::INFRA_K8S_NAMESPACE_DELETE,
        SemanticCode::INFRA_K8S_CLUSTER_RESOURCE_DELETE,
        SemanticCode::INFRA_K8S_BULK_RESOURCE_DELETE,
    ] {
        let stream = ActionStream::new(
            Coverage::Partial,
            vec![vec![
                EffectKind::known("kubectl", code.as_str()).expect("semantic code is valid"),
            ]],
            vec![],
        )
        .unwrap();
        let decision = nah_policy::decide(
            &stream,
            &crate::support::evidence(&stream, &nah_inline::InlineReport::default()),
            &guard_policy("infra-k8s-delete", true),
            &[],
        )
        .unwrap();
        assert_eq!(decision.verdict(), Verdict::Delegate);
    }
}

fn infrastructure(kind: InfrastructureKind, scope: Knowledge<InfrastructureScope>) -> FactPayload {
    FactPayload::InfrastructureChange {
        target: ResourceId(0),
        kind,
        scope,
        operation: if kind == InfrastructureKind::ManagedStack {
            InfrastructureOperation::Destroy
        } else {
            InfrastructureOperation::Delete
        },
        selection: Selection::Whole,
        active: Knowledge::Known(true),
        preview: Knowledge::Known(false),
        help: Knowledge::Known(false),
        dry_run: Knowledge::Known(false),
    }
}

fn container(operation: ContainerOperation) -> FactPayload {
    FactPayload::ContainerChange {
        target: ResourceId(0),
        operation,
        selection: Selection::Whole,
        broad_unused: Knowledge::Known(true),
        named_volumes: Knowledge::Known(true),
        anonymous_volumes: Knowledge::Unknown,
        attached_volume_removal: Knowledge::Known(false),
        all: Knowledge::Known(true),
        active: Knowledge::Known(true),
        dry_run: Knowledge::Known(false),
    }
}
