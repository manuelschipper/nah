#![allow(clippy::disallowed_types)]

mod support;

use nah_proto::action::{
    ActionStream, Coverage, EffectKind, FilesystemOperation, PathScope, SemanticCode,
};
use nah_proto::decision::Verdict;
use support::{filesystem, guard_policy, guarded_stream, project_scope};

#[test]
fn git_guards_block_only_their_one_sentence_operation() {
    for (guard, operation) in [
        ("git-clean-force", "clean-force"),
        ("git-metadata", "metadata-mutation"),
        ("git-force-push", "force-push"),
        ("git-hard-reset", "hard-reset"),
        ("git-path-discard", "path-discard"),
        ("git-protected-push", "protected-push"),
        ("git-history-rewrite", "history-rewrite"),
        ("git-recovery-destroy", "recovery-destroy"),
        ("git-ref-delete", "ref-delete"),
        ("git-remote-repo-delete", "git-remote-repo-delete"),
        ("git-remote-resource-delete", "git-remote-resource-delete"),
        ("git-rewrite-force", "rewrite-force"),
        ("git-worktree-discard", "worktree-discard"),
    ] {
        let stream = guarded_stream(EffectKind::Git {
            operation: nah_proto::action::SemanticCode::new(operation).unwrap(),
        });
        let decision = nah_policy::decide(&stream, &guard_policy(guard, true), &[]).unwrap();
        assert_eq!(decision.verdict(), Verdict::Block, "{guard}");
        assert_eq!(decision.policy_attributions()[0].name(), guard);
        if guard == "git-force-push" {
            assert!(
                decision
                    .reason()
                    .contains("before using --force-with-lease")
            );
        }

        let disabled = nah_policy::decide(&stream, &guard_policy(guard, false), &[]).unwrap();
        assert_eq!(disabled.verdict(), Verdict::Delegate, "{guard}");
    }

    let stream = ActionStream::new(
        Coverage::Partial,
        vec![vec![
            EffectKind::opaque("git").unwrap(),
            EffectKind::Git {
                operation: SemanticCode::PROTECTED_PUSH,
            },
            EffectKind::Git {
                operation: SemanticCode::HISTORY_REWRITE,
            },
        ]],
        vec![],
    )
    .unwrap();
    for history in [false, true] {
        for protected in [false, true] {
            let policy = support::context(
                &[
                    ("git-history-rewrite", history),
                    ("git-protected-push", protected),
                ],
                vec![],
                nah_proto::observation::ProjectGuardDeclaration::Absent,
            )
            .1;
            let decision = nah_policy::decide(&stream, &policy, &[]).unwrap();
            let expected = [
                ("git-history-rewrite", history),
                ("git-protected-push", protected),
            ]
            .into_iter()
            .filter_map(|(name, enabled)| enabled.then_some(name))
            .collect::<std::collections::BTreeSet<_>>();
            assert_eq!(
                decision
                    .policy_attributions()
                    .iter()
                    .map(|guard| guard.name())
                    .collect::<std::collections::BTreeSet<_>>(),
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
    }
}

#[test]
fn path_discard_matches_same_stage_show_read_and_write_of_one_project_path() {
    for (read_target, write_target, scope, expected) in [
        ("/repo/file", "/repo/file", project_scope(), Verdict::Block),
        (
            "/repo/source",
            "/repo/destination",
            project_scope(),
            Verdict::Delegate,
        ),
        ("/repo", "/repo", project_scope(), Verdict::Delegate),
        (
            "/outside/file",
            "/outside/file",
            PathScope::OutsideProject,
            Verdict::Delegate,
        ),
    ] {
        let stream = ActionStream::new(
            Coverage::Partial,
            vec![vec![
                EffectKind::opaque("git").unwrap(),
                EffectKind::Git {
                    operation: SemanticCode::new("show").unwrap(),
                },
                filesystem(
                    FilesystemOperation::Read,
                    read_target,
                    scope.clone(),
                    nah_proto::action::Sensitivity::None,
                ),
                filesystem(
                    FilesystemOperation::Write,
                    write_target,
                    scope,
                    nah_proto::action::Sensitivity::None,
                ),
            ]],
            vec![],
        )
        .unwrap();
        assert_eq!(
            nah_policy::decide(&stream, &guard_policy("git-path-discard", true), &[])
                .unwrap()
                .verdict(),
            expected
        );
    }
}

#[test]
fn path_discard_does_not_join_show_effects_across_stages() {
    let stream = ActionStream::new(
        Coverage::Partial,
        vec![
            vec![
                EffectKind::opaque("git").unwrap(),
                EffectKind::Git {
                    operation: SemanticCode::new("show").unwrap(),
                },
                filesystem(
                    FilesystemOperation::Read,
                    "/repo/file",
                    project_scope(),
                    nah_proto::action::Sensitivity::None,
                ),
            ],
            vec![
                EffectKind::opaque("redirect").unwrap(),
                filesystem(
                    FilesystemOperation::Write,
                    "/repo/file",
                    project_scope(),
                    nah_proto::action::Sensitivity::None,
                ),
            ],
        ],
        vec![],
    )
    .unwrap();
    assert_eq!(
        nah_policy::decide(&stream, &guard_policy("git-path-discard", true), &[])
            .unwrap()
            .verdict(),
        Verdict::Delegate
    );
}

#[test]
fn root_filesystem_effects_cannot_substitute_for_guard_evidence() {
    for (guard, operation, filesystem_operation) in [
        ("git-clean-force", "clean", FilesystemOperation::Delete),
        (
            "git-worktree-discard",
            "restore-worktree",
            FilesystemOperation::Write,
        ),
    ] {
        let stream = ActionStream::new(
            Coverage::Partial,
            vec![vec![
                EffectKind::opaque("git").unwrap(),
                EffectKind::Git {
                    operation: nah_proto::action::SemanticCode::new(operation).unwrap(),
                },
                filesystem(
                    filesystem_operation,
                    "/repo",
                    project_scope(),
                    nah_proto::action::Sensitivity::None,
                ),
            ]],
            vec![],
        )
        .unwrap();
        assert_eq!(
            nah_policy::decide(&stream, &guard_policy(guard, true), &[])
                .unwrap()
                .verdict(),
            Verdict::Delegate,
            "{guard}"
        );
    }
}

#[test]
fn git_loss_and_ref_deletion_guards_match_independently() {
    for (loss_guard, loss) in [
        ("git-recovery-destroy", "recovery-destroy"),
        ("git-worktree-discard", "worktree-discard"),
    ] {
        let stream = ActionStream::new(
            Coverage::Partial,
            vec![vec![
                EffectKind::opaque("git").unwrap(),
                EffectKind::Git {
                    operation: SemanticCode::new(loss).unwrap(),
                },
                EffectKind::Git {
                    operation: SemanticCode::REF_DELETE,
                },
            ]],
            vec![],
        )
        .unwrap();
        for (loss_enabled, ref_enabled) in
            [(true, false), (false, true), (true, true), (false, false)]
        {
            let (_, policy) = support::context(
                &[(loss_guard, loss_enabled), ("git-ref-delete", ref_enabled)],
                vec![],
                nah_proto::observation::ProjectGuardDeclaration::Absent,
            );
            let decision = nah_policy::decide(&stream, &policy, &[]).unwrap();
            assert_eq!(
                decision.verdict(),
                if loss_enabled || ref_enabled {
                    Verdict::Block
                } else {
                    Verdict::Delegate
                }
            );
            let names = decision
                .policy_attributions()
                .iter()
                .map(|guard| guard.name())
                .collect::<Vec<_>>();
            assert_eq!(names.contains(&loss_guard), loss_enabled);
            assert_eq!(names.contains(&"git-ref-delete"), ref_enabled);
            assert_eq!(
                names.len(),
                usize::from(loss_enabled) + usize::from(ref_enabled)
            );
        }
    }
}
