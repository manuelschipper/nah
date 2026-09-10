#![allow(clippy::disallowed_types)]

use crate::support;
use nah_proto::effects::*;

use nah_proto::action::{ActionStream, Coverage, EffectKind, SemanticCode};
use nah_proto::decision::Verdict;
use support::{guard_policy, guarded_stream};

#[test]
fn registry_guards_require_their_matching_enabled_facts() {
    for (name, operation) in [
        ("registry-publish", package(PackageOperation::Publish)),
        ("registry-unpublish", package(PackageOperation::Remove)),
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
fn publish_and_unpublish_guards_are_isolated() {
    for (enabled, operation) in [
        ("registry-publish", package(PackageOperation::Remove)),
        ("registry-unpublish", package(PackageOperation::Publish)),
    ] {
        let evidence = support::operation_evidence(operation);
        let stream = ActionStream::new(Coverage::Partial, vec![], vec![]).unwrap();
        let decision =
            nah_policy::decide(&stream, &evidence, &guard_policy(enabled, true), &[]).unwrap();
        assert_eq!(decision.verdict(), Verdict::Delegate, "{enabled}");
    }
}

#[test]
fn registry_guards_ignore_legacy_codes() {
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
            let decision = nah_policy::decide(
                &stream,
                &crate::support::evidence(&stream, &nah_inline::InlineReport::default()),
                &guard_policy(name, true),
                &[],
            )
            .unwrap();
            assert_eq!(decision.verdict(), Verdict::Delegate, "{name}");
        }
    }
}

fn package(operation: PackageOperation) -> FactPayload {
    FactPayload::PackageChange {
        target: ResourceId(0),
        operation,
        ecosystem: Knowledge::Known("npm".into()),
        versions: Selection::Unknown,
        active: Knowledge::Known(true),
        dry_run: Knowledge::Known(false),
    }
}
