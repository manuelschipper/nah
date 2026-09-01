#![allow(clippy::disallowed_types)]

mod support;

use nah_proto::action::{ActionStream, Coverage, EffectKind, SemanticCode};
use nah_proto::decision::Verdict;
use support::{guard_policy, guarded_stream};

#[test]
fn each_storage_guard_requires_its_matching_enabled_code() {
    for (name, operation) in [
        ("storage-destroy", SemanticCode::STORAGE_DESTROY),
        (
            "storage-recursive-delete",
            SemanticCode::STORAGE_RECURSIVE_DELETE,
        ),
        (
            "storage-snapshot-delete",
            SemanticCode::STORAGE_SNAPSHOT_DELETE,
        ),
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
fn storage_guards_are_independent() {
    for (enabled, operation) in [
        ("storage-destroy", SemanticCode::STORAGE_RECURSIVE_DELETE),
        ("storage-destroy", SemanticCode::STORAGE_SNAPSHOT_DELETE),
        ("storage-recursive-delete", SemanticCode::STORAGE_DESTROY),
        (
            "storage-recursive-delete",
            SemanticCode::STORAGE_SNAPSHOT_DELETE,
        ),
        ("storage-snapshot-delete", SemanticCode::STORAGE_DESTROY),
        (
            "storage-snapshot-delete",
            SemanticCode::STORAGE_RECURSIVE_DELETE,
        ),
    ] {
        let stream = guarded_stream(EffectKind::SystemState { operation });
        let decision = nah_policy::decide(&stream, &guard_policy(enabled, true), &[]).unwrap();
        assert_eq!(decision.verdict(), Verdict::Delegate, "{enabled}");
    }
}

#[test]
fn storage_guards_match_only_system_state_evidence() {
    for (effect, invocation) in [
        (
            EffectKind::SystemState {
                operation: SemanticCode::LOGICAL_STORAGE_DESTROY,
            },
            false,
        ),
        (
            EffectKind::Git {
                operation: SemanticCode::STORAGE_DESTROY,
            },
            false,
        ),
        (EffectKind::known("borg", "storage-destroy").unwrap(), true),
    ] {
        let stream = if invocation {
            ActionStream::new(Coverage::Partial, vec![vec![effect]], vec![]).unwrap()
        } else {
            guarded_stream(effect)
        };
        let decision =
            nah_policy::decide(&stream, &guard_policy("storage-destroy", true), &[]).unwrap();
        assert_eq!(decision.verdict(), Verdict::Delegate);
    }
}
