#![allow(clippy::disallowed_types)]

mod support;

use nah_proto::action::{ActionStream, Coverage, EffectKind, SemanticCode};
use nah_proto::decision::Verdict;
use support::{guard_policy, guarded_stream};

#[test]
fn registry_guards_require_their_matching_enabled_code() {
    for (name, operation) in [
        ("registry-publish", SemanticCode::REGISTRY_PUBLISH),
        ("registry-unpublish", SemanticCode::REGISTRY_UNPUBLISH),
    ] {
        let stream = guarded_stream(EffectKind::SystemState { operation });
        let enabled = nah_policy::decide(&stream, &guard_policy(name, true), &[]).unwrap();
        assert_eq!(enabled.verdict(), Verdict::Block, "{name}");
        assert_eq!(enabled.policy_attributions()[0].name(), name);

        let disabled = nah_policy::decide(&stream, &guard_policy(name, false), &[]).unwrap();
        assert_eq!(disabled.verdict(), Verdict::Delegate, "{name}");
    }
}

#[test]
fn publish_and_unpublish_guards_are_isolated() {
    for (enabled, operation) in [
        ("registry-publish", SemanticCode::REGISTRY_UNPUBLISH),
        ("registry-unpublish", SemanticCode::REGISTRY_PUBLISH),
    ] {
        let stream = guarded_stream(EffectKind::SystemState { operation });
        let decision = nah_policy::decide(&stream, &guard_policy(enabled, true), &[]).unwrap();
        assert_eq!(decision.verdict(), Verdict::Delegate, "{enabled}");
    }
}

#[test]
fn registry_guards_match_only_system_state_codes() {
    for (name, operation) in [
        ("registry-publish", SemanticCode::REGISTRY_PUBLISH),
        ("registry-unpublish", SemanticCode::REGISTRY_UNPUBLISH),
    ] {
        for (effect, invocation) in [
            (
                EffectKind::Git {
                    operation: operation.clone(),
                },
                false,
            ),
            (
                EffectKind::known("registry", operation.as_str()).unwrap(),
                true,
            ),
        ] {
            let stream = if invocation {
                ActionStream::new(Coverage::Partial, vec![vec![effect]], vec![]).unwrap()
            } else {
                guarded_stream(effect)
            };
            let decision = nah_policy::decide(&stream, &guard_policy(name, true), &[]).unwrap();
            assert_eq!(decision.verdict(), Verdict::Delegate, "{name}");
        }
    }
}
