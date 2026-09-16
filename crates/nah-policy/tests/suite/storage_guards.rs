#![allow(clippy::disallowed_types)]

use crate::support;
use nah_proto::effects::*;

use nah_proto::action::{ActionStream, Coverage, EffectKind, SemanticCode};
use nah_proto::decision::Verdict;
use support::{guard_policy, guarded_stream};

#[test]
fn each_storage_guard_requires_its_matching_enabled_facts() {
    for (name, operation) in [
        (
            "storage-backup-destroy",
            storage(StorageTarget::BackupRepository, false),
        ),
        (
            "storage-recursive-delete",
            storage(StorageTarget::ObjectTree, true),
        ),
        (
            "storage-snapshot-delete",
            storage(StorageTarget::Snapshot, false),
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
fn storage_guards_are_independent() {
    for (enabled, operation) in [
        (
            "storage-backup-destroy",
            storage(StorageTarget::ObjectTree, true),
        ),
        (
            "storage-backup-destroy",
            storage(StorageTarget::Snapshot, false),
        ),
        (
            "storage-recursive-delete",
            storage(StorageTarget::BackupRepository, false),
        ),
        (
            "storage-recursive-delete",
            storage(StorageTarget::Snapshot, false),
        ),
        (
            "storage-snapshot-delete",
            storage(StorageTarget::BackupRepository, false),
        ),
        (
            "storage-snapshot-delete",
            storage(StorageTarget::ObjectTree, true),
        ),
    ] {
        let evidence = support::operation_evidence(operation);
        let stream = ActionStream::new(Coverage::Partial, vec![], vec![]).unwrap();
        let decision =
            nah_policy::decide(&stream, &evidence, &guard_policy(enabled, true), &[]).unwrap();
        assert_eq!(decision.verdict(), Verdict::Delegate, "{enabled}");
    }

    use Knowledge::{Known, Unknown};
    let policy = support::context(
        &[
            ("storage-backup-destroy", true),
            ("storage-snapshot-delete", true),
        ],
        vec![],
        nah_proto::observation::ProjectGuardDeclaration::Absent,
    )
    .1;
    let stream = ActionStream::new(Coverage::Partial, vec![], vec![]).unwrap();
    for (allow, all, expected) in [
        (Known(true), Known(false), vec!["storage-backup-destroy"]),
        (Known(false), Known(true), vec!["storage-backup-destroy"]),
        (Known(false), Known(false), vec!["storage-snapshot-delete"]),
        (Unknown, Known(false), vec![]),
        (Known(false), Unknown, vec![]),
    ] {
        let mut payload = storage(StorageTarget::Snapshot, false);
        if let FactPayload::StorageChange {
            allow_remove_all,
            all_selection_requested,
            selection,
            ..
        } = &mut payload
        {
            *allow_remove_all = allow;
            *all_selection_requested = all;
            *selection = Selection::Exact;
        }
        let evidence = support::operation_evidence(payload);
        let decision = nah_policy::decide(&stream, &evidence, &policy, &[]).unwrap();
        assert_eq!(
            decision
                .policy_attributions()
                .iter()
                .map(|guard| guard.name())
                .collect::<Vec<_>>(),
            expected
        );
        assert_eq!(
            decision.verdict(),
            if expected.is_empty() {
                Verdict::Delegate
            } else {
                Verdict::Block
            }
        );
    }
    let base = support::operation_evidence(storage(StorageTarget::Snapshot, false));
    let mut graph = base.graph().clone();
    graph.facts.push(EffectFact {
        id: FactId(1),
        payload: storage(StorageTarget::BackupRepository, false),
        ..graph.facts[0].clone()
    });
    let evidence = GuardEvidence::new(graph, base.public_selection().clone()).unwrap();
    let decision = nah_policy::decide(&stream, &evidence, &policy, &[]).unwrap();
    assert_eq!(
        decision
            .policy_attributions()
            .iter()
            .map(|guard| guard.name())
            .collect::<Vec<_>>(),
        vec!["storage-backup-destroy", "storage-snapshot-delete"]
    );

    for provider in ["aws", "gcloud", "az"] {
        let mut payload = storage(StorageTarget::LiveVolume, false);
        if let FactPayload::StorageChange { operation, .. } = &mut payload {
            *operation = StorageOperation::Destroy;
        }
        let base = support::operation_evidence(payload);
        let mut graph = base.graph().clone();
        graph.resources[0].identity.provider = Known(provider.into());
        let evidence = GuardEvidence::new(graph, base.public_selection().clone()).unwrap();
        for snapshot_enabled in [false, true] {
            let policy = support::context(
                &[
                    ("fs-volume-destroy", true),
                    ("storage-snapshot-delete", snapshot_enabled),
                ],
                vec![],
                nah_proto::observation::ProjectGuardDeclaration::Absent,
            )
            .1;
            let decision = nah_policy::decide(&stream, &evidence, &policy, &[]).unwrap();
            assert_eq!(
                decision
                    .policy_attributions()
                    .iter()
                    .map(|guard| guard.name())
                    .collect::<Vec<_>>(),
                if snapshot_enabled {
                    vec!["storage-snapshot-delete"]
                } else {
                    vec![]
                },
                "{provider}"
            );
            assert_eq!(
                decision.verdict(),
                if snapshot_enabled {
                    Verdict::Block
                } else {
                    Verdict::Delegate
                }
            );
        }
    }

    let mut filtered = storage(StorageTarget::ObjectTree, true);
    if let FactPayload::StorageChange { selection, .. } = &mut filtered {
        *selection = Selection::Pattern {
            pattern: "*.log".into(),
            bound: Bound::Unknown,
        };
    }
    let decision = nah_policy::decide(
        &stream,
        &support::operation_evidence(filtered),
        &guard_policy("storage-recursive-delete", true),
        &[],
    )
    .unwrap();
    assert_eq!(decision.verdict(), Verdict::Delegate);
    assert!(decision.policy_attributions().is_empty());
}

#[test]
fn storage_guards_ignore_legacy_codes() {
    for (effect, invocation) in [
        (
            EffectKind::SystemState {
                operation: SemanticCode::LOGICAL_STORAGE_DESTROY,
            },
            false,
        ),
        (
            EffectKind::Git {
                operation: SemanticCode::STORAGE_BACKUP_DESTROY,
            },
            false,
        ),
        (
            EffectKind::known("borg", "storage-backup-destroy").unwrap(),
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
            &guard_policy("storage-backup-destroy", true),
            &[],
        )
        .unwrap();
        assert_eq!(decision.verdict(), Verdict::Delegate);
    }
}

fn storage(kind: StorageTarget, recursive: bool) -> FactPayload {
    FactPayload::StorageChange {
        target: ResourceId(0),
        destination: None,
        operation: StorageOperation::Delete,
        kind,
        selection: Selection::Unknown,
        recursive: Knowledge::Known(recursive),
        destination_deletion: Knowledge::Known(false),
        allow_remove_all: Knowledge::Known(false),
        all_selection_requested: Knowledge::Known(false),
    }
}
