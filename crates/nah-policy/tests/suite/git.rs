#![allow(clippy::disallowed_types)]

use crate::support;
use Knowledge::{Known, Unknown};
use nah_proto::action::{ActionStream, Coverage};
use nah_proto::decision::Verdict;
use nah_proto::effects::*;

fn evidence(payloads: Vec<FactPayload>) -> GuardEvidence {
    let mut graph = support::empty_evidence().graph().clone();
    graph.calls.push(EffectCall {
        id: CallId(0),
        parent: None,
        kind: InvocationKind::Argv,
        identity: Unknown,
        input: None,
        cwd: Unknown,
        payload_group: Unknown,
        visibility_ordinal: Unknown,
        coverage: Coverage::Partial,
    });
    let kind = match payloads.first() {
        Some(FactPayload::HostedDeletion {
            kind: HostedTarget::Repository,
            ..
        }) => ResourceKind::HostedRepository,
        Some(FactPayload::HostedDeletion { .. }) => ResourceKind::HostedResource,
        Some(FactPayload::FilesystemAccess { .. }) => ResourceKind::HostPath,
        _ => ResourceKind::GitRepository,
    };
    graph.resources.push(EffectResource {
        id: ResourceId(0),
        realm: Realm::Host,
        identity: ResourceIdentity {
            kind,
            details: Unknown,
            provider: Unknown,
            name: Unknown,
        },
        selection: Selection::Exact,
        labels: None,
    });
    for payload in payloads {
        graph.facts.push(EffectFact {
            id: FactId(graph.facts.len() as u32),
            call: CallId(0),
            realm: Realm::Host,
            certainty: Certainty::Exact,
            modality: Modality::MustOnSuccess,
            condition: None,
            occurrences: None,
            payload,
        });
    }
    GuardEvidence::new(graph, support::empty_evidence().public_selection().clone()).unwrap()
}

fn discard(mode: GitDiscardMode, selection: Selection) -> FactPayload {
    FactPayload::GitDiscard {
        target: ResourceId(0),
        mode,
        reset: Known(ResetMode::Hard),
        selection,
        untracked: Known(true),
        force: Known(true),
        dry_run: Known(false),
    }
}
fn history(force: bool) -> FactPayload {
    FactPayload::GitHistory {
        target: ResourceId(0),
        operation: GitHistoryOperation::Filter,
        selection: Selection::Whole,
        active: Known(true),
        abort: Known(false),
        dry_run: Known(false),
        force: Known(force),
    }
}
fn recovery() -> FactPayload {
    FactPayload::GitRecovery {
        target: ResourceId(0),
        operation: GitRecoveryOperation::Remove,
        selection: Selection::Whole,
        active: Known(true),
        abort: Known(false),
        dry_run: Known(false),
        force: Unknown,
    }
}
fn deletion() -> FactPayload {
    FactPayload::GitRefChange {
        target: ResourceId(0),
        operation: GitRefOperation::Delete,
        selection: Selection::Exact,
        active: Known(true),
        abort: Known(false),
        dry_run: Known(false),
        force: Unknown,
    }
}
fn push(force: bool, lease: bool, destination: &str) -> FactPayload {
    FactPayload::GitPush {
        repository: ResourceId(0),
        destinations: vec![PushDestination {
            source: Known("HEAD".into()),
            destination: Known(destination.into()),
            forced: Known(false),
        }],
        destinations_complete: Known(true),
        selection: Selection::Exact,
        explicit_force: Known(force),
        lease_requested: Known(lease),
        all_refs_lease: Known(lease),
        leased_refs: Known(vec![]),
        delete: Known(false),
        all: Known(false),
        branches: Known(false),
        mirror: Known(false),
        prune: Known(false),
        dry_run: Known(false),
    }
}
fn hosted(kind: HostedTarget) -> FactPayload {
    FactPayload::HostedDeletion {
        target: ResourceId(0),
        kind,
        provider: Known("github".into()),
        object_kind: Unknown,
        selection: Selection::Exact,
        delete: Known(true),
    }
}
fn stream() -> ActionStream {
    ActionStream::new(Coverage::Partial, vec![], vec![]).unwrap()
}

#[test]
fn git_guards_match_shared_facts_and_honor_enablement_and_assurance() {
    for (guard, payload) in [
        (
            "git-clean-force",
            discard(GitDiscardMode::Clean, Selection::Whole),
        ),
        (
            "git-hard-reset",
            discard(GitDiscardMode::Reset, Selection::Whole),
        ),
        (
            "git-worktree-discard",
            discard(GitDiscardMode::Checkout, Selection::Whole),
        ),
        (
            "git-path-discard",
            discard(GitDiscardMode::Restore, Selection::Exact),
        ),
        ("git-force-push", push(true, false, "feature")),
        ("git-protected-push", push(false, false, "main")),
        ("git-history-rewrite", history(false)),
        ("git-rewrite-force", history(true)),
        ("git-recovery-destroy", recovery()),
        ("git-ref-delete", deletion()),
        ("git-remote-repo-delete", hosted(HostedTarget::Repository)),
        ("git-remote-resource-delete", hosted(HostedTarget::Resource)),
    ] {
        let evidence = evidence(vec![payload]);
        for enabled in [false, true] {
            let decision = nah_policy::decide(
                &stream(),
                &evidence,
                &support::guard_policy(guard, enabled),
                &[],
            )
            .unwrap();
            assert_eq!(decision.verdict() == Verdict::Block, enabled, "{guard}");
            assert_eq!(decision.policy_attributions().len(), usize::from(enabled));
        }
        let mut graph = evidence.graph().clone();
        graph.facts[0].modality = Modality::May;
        let uncertain = GuardEvidence::new(graph, evidence.public_selection().clone()).unwrap();
        assert_eq!(
            nah_policy::decide(
                &stream(),
                &uncertain,
                &support::guard_policy(guard, true),
                &[]
            )
            .unwrap()
            .verdict(),
            Verdict::Delegate,
            "{guard}"
        );
        assert_eq!(
            nah_policy::decide(
                &stream(),
                &support::empty_evidence(),
                &support::guard_policy(guard, true),
                &[]
            )
            .unwrap()
            .verdict(),
            Verdict::Delegate,
            "{guard}"
        );
    }
}

#[test]
fn leased_protected_pushes_keep_all_contributions_independent() {
    let evidence = evidence(vec![push(false, true, "refs/heads/main")]);
    for mask in 0..8 {
        let names = [
            "git-force-push",
            "git-history-rewrite",
            "git-protected-push",
        ];
        let settings = names
            .iter()
            .enumerate()
            .map(|(i, name)| (*name, mask & (1 << i) != 0))
            .collect::<Vec<_>>();
        let policy = support::context(
            &settings,
            vec![],
            nah_proto::observation::ProjectGuardDeclaration::Absent,
        )
        .1;
        let decision = nah_policy::decide(&stream(), &evidence, &policy, &[]).unwrap();
        let mut actual = decision
            .policy_attributions()
            .iter()
            .map(|a| a.name())
            .collect::<Vec<_>>();
        actual.sort();
        let expected = settings
            .iter()
            .filter_map(|(name, enabled)| enabled.then_some(*name))
            .collect::<Vec<_>>();
        assert_eq!(actual, expected);
        assert_eq!(decision.verdict() == Verdict::Block, mask != 0);
    }
}

#[test]
fn force_origin_scoped_leases_and_deletion_fallback_use_all_push_facts() {
    for (explicit, forced, leased, expected_force) in [
        (false, true, "feature", false),
        (false, true, "other", true),
        (true, true, "feature", true),
    ] {
        let mut payload = push(explicit, true, "refs/heads/feature");
        if let FactPayload::GitPush {
            destinations,
            all_refs_lease,
            leased_refs,
            ..
        } = &mut payload
        {
            destinations[0].forced = Known(forced);
            *all_refs_lease = Known(false);
            *leased_refs = Known(vec![leased.into()]);
        }
        let evidence = evidence(vec![payload]);
        assert_eq!(
            nah_policy::decide(
                &stream(),
                &evidence,
                &support::guard_policy("git-force-push", true),
                &[]
            )
            .unwrap()
            .verdict()
                == Verdict::Block,
            expected_force
        );
        assert_eq!(
            nah_policy::decide(
                &stream(),
                &evidence,
                &support::guard_policy("git-history-rewrite", true),
                &[]
            )
            .unwrap()
            .verdict(),
            Verdict::Block
        );
    }
    // Ref deletion is a classifier fallback, even when the stronger controls are disabled.
    for leased in [false, true] {
        let mut payload = push(false, leased, "main");
        if let FactPayload::GitPush {
            destinations,
            delete,
            ..
        } = &mut payload
        {
            destinations[0].source = Known(String::new());
            *delete = Known(true);
        }
        let evidence = evidence(vec![payload, deletion()]);
        assert_eq!(
            nah_policy::decide(
                &stream(),
                &evidence,
                &support::guard_policy("git-ref-delete", true),
                &[]
            )
            .unwrap()
            .verdict()
                == Verdict::Block,
            !leased
        );
        assert_eq!(
            nah_policy::decide(
                &stream(),
                &evidence,
                &support::guard_policy("git-protected-push", true),
                &[]
            )
            .unwrap()
            .verdict(),
            Verdict::Delegate
        );
    }
}

#[test]
fn git_loss_and_ref_deletion_guards_match_independently() {
    for (guard, loss) in [
        ("git-recovery-destroy", recovery()),
        (
            "git-worktree-discard",
            discard(GitDiscardMode::WorktreeRemove, Selection::Exact),
        ),
    ] {
        let evidence = evidence(if guard == "git-worktree-discard" {
            vec![loss]
        } else {
            vec![loss, deletion()]
        });
        for loss_enabled in [false, true] {
            for ref_enabled in [false, true] {
                let policy = support::context(
                    &[(guard, loss_enabled), ("git-ref-delete", ref_enabled)],
                    vec![],
                    nah_proto::observation::ProjectGuardDeclaration::Absent,
                )
                .1;
                let decision = nah_policy::decide(&stream(), &evidence, &policy, &[]).unwrap();
                let actual = decision
                    .policy_attributions()
                    .iter()
                    .map(|a| a.name())
                    .collect::<Vec<_>>();
                assert_eq!(actual.contains(&guard), loss_enabled);
                assert_eq!(actual.contains(&"git-ref-delete"), ref_enabled);
            }
        }
    }
}

#[test]
fn git_discard_modes_and_incomplete_push_destinations_do_not_expand_protection() {
    let mut reset = discard(GitDiscardMode::Reset, Selection::Whole);
    if let FactPayload::GitDiscard { reset, .. } = &mut reset {
        *reset = Known(ResetMode::Merge);
    }
    for (guard, payload) in [
        ("git-hard-reset", reset),
        (
            "git-clean-force",
            discard(GitDiscardMode::Clean, Selection::Exact),
        ),
        (
            "git-worktree-discard",
            discard(GitDiscardMode::Checkout, Selection::Exact),
        ),
        (
            "git-path-discard",
            discard(GitDiscardMode::Restore, Selection::Whole),
        ),
        ("git-history-rewrite", history(true)),
        ("git-rewrite-force", history(false)),
    ] {
        assert_eq!(
            nah_policy::decide(
                &stream(),
                &evidence(vec![payload]),
                &support::guard_policy(guard, true),
                &[]
            )
            .unwrap()
            .verdict(),
            Verdict::Delegate,
            "{guard}"
        );
    }
    let mut incomplete = push(false, false, "main");
    if let FactPayload::GitPush {
        destinations_complete,
        ..
    } = &mut incomplete
    {
        *destinations_complete = Unknown;
    }
    assert_eq!(
        nah_policy::decide(
            &stream(),
            &evidence(vec![incomplete]),
            &support::guard_policy("git-protected-push", true),
            &[]
        )
        .unwrap()
        .verdict(),
        Verdict::Delegate
    );
}

fn filesystem(operation: FilesystemOperation) -> FactPayload {
    FactPayload::FilesystemAccess {
        operation,
        target: ResourceId(0),
        destination: None,
        recursive: Known(true),
        truncate: Unknown,
        permissions: PermissionGrants {
            world_write: Unknown,
            setuid: Unknown,
            setgid: Unknown,
        },
        purpose: AccessPurpose::Explicit,
    }
}
fn path_evidence(path: &str, payloads: Vec<FactPayload>) -> GuardEvidence {
    let evidence = evidence(payloads);
    let mut graph = evidence.graph().clone();
    let path = support::path(path);
    graph.resources[0].identity.details = Known(ResourceDetails::Path {
        lexical: Known(path.clone()),
    });
    graph.resources[0].labels = Some(ResourceLabels {
        lexical: Known(path),
        canonical: Unknown,
        scope: Known(support::project_scope()),
        sensitivity: Unknown,
        protection: Unknown,
        host_integrity: Unknown,
        selects_project: Reach::No,
        selects_home: Reach::No,
        selects_root: Reach::No,
        is_symlink: Unknown,
        link_target: Unknown,
        descendants_complete: Unknown,
        reach: vec![],
    });
    GuardEvidence::new(graph, evidence.public_selection().clone()).unwrap()
}

#[test]
fn metadata_requires_a_host_mutation_to_protected_git_identity() {
    for (path, operation, matches) in [
        (
            "/repo/.git/refs/heads/main",
            FilesystemOperation::Write,
            true,
        ),
        ("/repo/.git/objects", FilesystemOperation::Delete, true),
        ("/repo/.git/objects", FilesystemOperation::Read, false),
        ("/repo/source", FilesystemOperation::Write, false),
    ] {
        let evidence = path_evidence(path, vec![filesystem(operation)]);
        for enabled in [false, true] {
            let decision = nah_policy::decide(
                &stream(),
                &evidence,
                &support::guard_policy("git-metadata", enabled),
                &[],
            )
            .unwrap();
            assert_eq!(decision.verdict() == Verdict::Block, matches && enabled);
        }
    }
    let evidence = path_evidence(
        "/repo/admin/objects",
        vec![filesystem(FilesystemOperation::Write)],
    );
    let mut graph = evidence.graph().clone();
    graph.resources.push(EffectResource {
        id: ResourceId(1),
        realm: Realm::Host,
        identity: ResourceIdentity {
            kind: ResourceKind::GitRepository,
            provider: Unknown,
            name: Unknown,
            details: Known(ResourceDetails::Git {
                worktree: Known(support::path("/repo")),
                git_dir: Known(support::path("/repo/admin")),
                reference: Unknown,
            }),
        },
        selection: Selection::Exact,
        labels: None,
    });
    let linked = GuardEvidence::new(graph, evidence.public_selection().clone()).unwrap();
    assert_eq!(
        nah_policy::decide(
            &stream(),
            &linked,
            &support::guard_policy("git-metadata", true),
            &[]
        )
        .unwrap()
        .verdict(),
        Verdict::Block
    );

    let evidence = path_evidence(
        "/repo/.git/packed-refs",
        vec![filesystem(FilesystemOperation::Write)],
    );
    for destination_metadata in [false, true] {
        let mut graph = evidence.graph().clone();
        let mut ordinary = graph.resources[0].clone();
        ordinary.id = ResourceId(1);
        ordinary.identity.details = Known(ResourceDetails::Path {
            lexical: Known(support::path("/repo/file")),
        });
        ordinary.labels.as_mut().unwrap().lexical = Known(support::path("/repo/file"));
        graph.resources.push(ordinary);
        if let FactPayload::FilesystemAccess {
            operation,
            target,
            destination,
            ..
        } = &mut graph.facts[0].payload
        {
            *operation = FilesystemOperation::Move;
            *target = ResourceId(u32::from(destination_metadata));
            *destination = Some(ResourceId(u32::from(!destination_metadata)));
        }
        let evidence = GuardEvidence::new(graph, evidence.public_selection().clone()).unwrap();
        assert_eq!(
            nah_policy::decide(
                &stream(),
                &evidence,
                &support::guard_policy("git-metadata", true),
                &[]
            )
            .unwrap()
            .verdict(),
            Verdict::Block
        );
    }
}

#[test]
fn path_discard_requires_show_and_same_invocation_read_and_overwrite() {
    let evidence = path_evidence(
        "/repo/file",
        vec![
            filesystem(FilesystemOperation::Read),
            filesystem(FilesystemOperation::Write),
            FactPayload::Other {
                operation: "git.show".into(),
                domain: "git".into(),
                resource_kind: "modeled".into(),
                resources: vec![],
            },
        ],
    );
    let policy = support::guard_policy("git-path-discard", true);
    assert_eq!(
        nah_policy::decide(&stream(), &evidence, &policy, &[])
            .unwrap()
            .verdict(),
        Verdict::Block
    );
    for mismatch in 0..4 {
        let mut graph = evidence.graph().clone();
        match mismatch {
            0 => {
                let mut call = graph.calls[0].clone();
                call.id = CallId(1);
                graph.calls.push(call);
                graph.facts[1].call = CallId(1);
            }
            1 => {
                graph.resources[0].selection = Selection::Pattern {
                    pattern: "/repo/*".into(),
                    bound: Bound::Unknown,
                }
            }
            2 => graph.facts[1].modality = Modality::May,
            3 => {
                graph.facts.pop();
            }
            _ => unreachable!(),
        }
        let evidence = GuardEvidence::new(graph, evidence.public_selection().clone()).unwrap();
        assert_eq!(
            nah_policy::decide(&stream(), &evidence, &policy, &[])
                .unwrap()
                .verdict(),
            Verdict::Delegate
        );
    }
}
