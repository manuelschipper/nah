#![allow(clippy::disallowed_types)]

mod support;

use nah_proto::action::{ActionStream, Coverage, EffectKind, SemanticCode};
use nah_proto::decision::Verdict;
use support::{guard_policy, guarded_stream};

#[test]
fn sys_power_requires_its_enabled_guard() {
    let stream = invocation_stream(
        EffectKind::known("shutdown", SemanticCode::HOST_POWER.as_str()).unwrap(),
    );

    let enabled = nah_policy::decide(&stream, &guard_policy("sys-power", true), &[]).unwrap();
    assert_eq!(enabled.verdict(), Verdict::Block);
    assert_eq!(enabled.policy_attributions()[0].name(), "sys-power");

    let disabled = nah_policy::decide(&stream, &guard_policy("sys-power", false), &[]).unwrap();
    assert_eq!(disabled.verdict(), Verdict::Delegate);
}

#[test]
fn sys_power_matches_only_the_known_host_power_operation() {
    for effect in [
        EffectKind::known("shutdown", "local-utility").unwrap(),
        EffectKind::opaque("shutdown").unwrap(),
    ] {
        let decision = nah_policy::decide(
            &invocation_stream(effect),
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

fn invocation_stream(effect: EffectKind) -> ActionStream {
    ActionStream::new(Coverage::Partial, vec![vec![effect]], vec![]).unwrap()
}
