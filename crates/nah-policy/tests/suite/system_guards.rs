#![allow(clippy::disallowed_types)]

use crate::support;
use nah_proto::effects::*;

use nah_proto::action::{ActionStream, Coverage, EffectKind, SemanticCode};
use nah_proto::decision::Verdict;
use support::{guard_policy, guarded_stream};

#[test]
fn sys_power_requires_its_enabled_guard() {
    let stream = invocation_stream(
        EffectKind::known("shutdown", SemanticCode::HOST_POWER.as_str()).unwrap(),
    );

    let evidence = support::operation_evidence(system(SystemOperation::Power));

    let enabled =
        nah_policy::decide(&stream, &evidence, &guard_policy("sys-power", true), &[]).unwrap();
    assert_eq!(enabled.verdict(), Verdict::Block);
    assert_eq!(
        enabled
            .policy_attributions()
            .iter()
            .map(|guard| guard.name())
            .collect::<Vec<_>>(),
        vec!["sys-power"]
    );
    support::assert_operation_uncertainty(&evidence, "sys-power");

    let disabled =
        nah_policy::decide(&stream, &evidence, &guard_policy("sys-power", false), &[]).unwrap();
    assert_eq!(disabled.verdict(), Verdict::Delegate);
}

#[test]
fn sys_power_matches_only_the_known_host_power_operation() {
    for effect in [
        EffectKind::known("shutdown", "local-utility").unwrap(),
        EffectKind::opaque("shutdown").unwrap(),
    ] {
        let decision = nah_policy::decide(
            &invocation_stream(effect.clone()),
            &crate::support::evidence(
                &invocation_stream(effect),
                &nah_inline::InlineReport::default(),
            ),
            &guard_policy("sys-power", true),
            &[],
        )
        .unwrap();
        assert_eq!(decision.verdict(), Verdict::Delegate);
    }

    let decision = nah_policy::decide(
        &guarded_stream(EffectKind::SystemState {
            operation: SemanticCode::HOST_POWER,
        }),
        &crate::support::evidence(
            &guarded_stream(EffectKind::SystemState {
                operation: SemanticCode::HOST_POWER,
            }),
            &nah_inline::InlineReport::default(),
        ),
        &guard_policy("sys-power", true),
        &[],
    )
    .unwrap();
    assert_eq!(decision.verdict(), Verdict::Delegate);
}

#[test]
fn sys_power_is_a_shipped_guard() {
    assert!(nah_policy::SHIPPED_GUARDS.contains(&"sys-power"));
}

#[test]
fn sys_service_stop_requires_its_enabled_guard() {
    let stream = guarded_stream(EffectKind::SystemState {
        operation: SemanticCode::SERVICE_STOP,
    });

    let evidence = support::operation_evidence(system(SystemOperation::ServiceStop));

    let enabled = nah_policy::decide(
        &stream,
        &evidence,
        &guard_policy("sys-service-stop", true),
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
        vec!["sys-service-stop"]
    );
    support::assert_operation_uncertainty(&evidence, "sys-service-stop");

    let disabled = nah_policy::decide(
        &stream,
        &evidence,
        &guard_policy("sys-service-stop", false),
        &[],
    )
    .unwrap();
    assert_eq!(disabled.verdict(), Verdict::Delegate);
}

#[test]
fn sys_service_stop_matches_only_the_system_state_operation() {
    for effect in [
        EffectKind::known("systemctl", SemanticCode::SERVICE_STOP.as_str()).unwrap(),
        EffectKind::opaque("systemctl").unwrap(),
    ] {
        let decision = nah_policy::decide(
            &invocation_stream(effect.clone()),
            &crate::support::evidence(
                &invocation_stream(effect),
                &nah_inline::InlineReport::default(),
            ),
            &guard_policy("sys-service-stop", true),
            &[],
        )
        .unwrap();
        assert_eq!(decision.verdict(), Verdict::Delegate);
    }

    let decision = nah_policy::decide(
        &guarded_stream(EffectKind::SystemState {
            operation: SemanticCode::STARTUP_MANAGEMENT,
        }),
        &crate::support::evidence(
            &guarded_stream(EffectKind::SystemState {
                operation: SemanticCode::STARTUP_MANAGEMENT,
            }),
            &nah_inline::InlineReport::default(),
        ),
        &guard_policy("sys-service-stop", true),
        &[],
    )
    .unwrap();
    assert_eq!(decision.verdict(), Verdict::Delegate);
}

#[test]
fn sys_service_stop_is_a_shipped_guard() {
    assert!(nah_policy::SHIPPED_GUARDS.contains(&"sys-service-stop"));
}

fn invocation_stream(effect: EffectKind) -> ActionStream {
    ActionStream::new(Coverage::Partial, vec![vec![effect]], vec![]).unwrap()
}

fn system(operation: SystemOperation) -> FactPayload {
    FactPayload::SystemChange {
        target: ResourceId(0),
        operation,
        selection: Selection::Unknown,
        runtime_only: Knowledge::Unknown,
        persistent: Knowledge::Unknown,
        active: Knowledge::Known(true),
        cancel: Knowledge::Known(false),
        help: Knowledge::Known(false),
    }
}
