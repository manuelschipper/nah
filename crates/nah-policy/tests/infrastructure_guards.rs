#![allow(clippy::disallowed_types)]

mod support;

use nah_proto::action::{ActionStream, Coverage, EffectKind, SemanticCode};
use nah_proto::decision::Verdict;
use support::{guard_policy, guarded_stream};

#[test]
fn infrastructure_destroy_requires_its_enabled_guard() {
    let stream = guarded_stream(EffectKind::SystemState {
        operation: SemanticCode::INFRA_IAC_DESTROY,
    });

    let enabled =
        nah_policy::decide(&stream, &guard_policy("infra-iac-destroy", true), &[]).unwrap();
    assert_eq!(enabled.verdict(), Verdict::Block);
    assert_eq!(enabled.policy_attributions()[0].name(), "infra-iac-destroy");

    let disabled =
        nah_policy::decide(&stream, &guard_policy("infra-iac-destroy", false), &[]).unwrap();
    assert_eq!(disabled.verdict(), Verdict::Delegate);
}

#[test]
fn infrastructure_guard_matches_only_its_system_state_code() {
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
        let decision =
            nah_policy::decide(&stream, &guard_policy("infra-iac-destroy", true), &[]).unwrap();
        assert_eq!(decision.verdict(), Verdict::Delegate);
    }
}
