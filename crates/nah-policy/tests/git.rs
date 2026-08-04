#![allow(clippy::disallowed_types)]

mod support;

use nah_proto::action::{ActionStream, Coverage, EffectKind, FilesystemOperation};
use nah_proto::decision::Verdict;
use support::{filesystem, guard_policy, guarded_stream, project_scope};

#[test]
fn git_guards_block_only_their_one_sentence_operation() {
    for (guard, operation) in [
        ("git-metadata", "metadata-mutation"),
        ("git-force-push", "force-push"),
        ("git-hard-reset", "hard-reset"),
        ("git-recovery-destroy", "recovery-destroy"),
        ("git-rewrite-force", "rewrite-force"),
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
}

#[test]
fn git_clean_force_requires_a_same_stage_project_root_delete() {
    let root_delete = filesystem(
        FilesystemOperation::Delete,
        "/repo",
        project_scope(),
        nah_proto::action::Sensitivity::None,
    );
    let named_delete = filesystem(
        FilesystemOperation::Delete,
        "/repo/build",
        project_scope(),
        nah_proto::action::Sensitivity::None,
    );
    for (stages, expected) in [
        (
            vec![vec![
                EffectKind::opaque("git").unwrap(),
                EffectKind::Git {
                    operation: nah_proto::action::SemanticCode::CLEAN_FORCE,
                },
                root_delete.clone(),
            ]],
            Verdict::Block,
        ),
        (
            vec![vec![
                EffectKind::opaque("git").unwrap(),
                EffectKind::Git {
                    operation: nah_proto::action::SemanticCode::CLEAN_FORCE,
                },
                named_delete,
            ]],
            Verdict::Delegate,
        ),
        (
            vec![
                vec![
                    EffectKind::opaque("git").unwrap(),
                    EffectKind::Git {
                        operation: nah_proto::action::SemanticCode::CLEAN_FORCE,
                    },
                ],
                vec![EffectKind::opaque("writer").unwrap(), root_delete],
            ],
            Verdict::Delegate,
        ),
    ] {
        let stream = ActionStream::new(Coverage::Partial, stages, vec![]).unwrap();
        let decision =
            nah_policy::decide(&stream, &guard_policy("git-clean-force", true), &[]).unwrap();
        assert_eq!(decision.verdict(), expected);
    }
}

#[test]
fn git_worktree_discard_accepts_proven_branch_mode_or_same_stage_root_write() {
    let direct = guarded_stream(EffectKind::Git {
        operation: nah_proto::action::SemanticCode::WORKTREE_DISCARD,
    });
    assert_eq!(
        nah_policy::decide(&direct, &guard_policy("git-worktree-discard", true), &[],)
            .unwrap()
            .verdict(),
        Verdict::Block
    );

    let root_write = filesystem(
        FilesystemOperation::Write,
        "/repo",
        project_scope(),
        nah_proto::action::Sensitivity::None,
    );
    let correlated = ActionStream::new(
        Coverage::Full,
        vec![vec![
            EffectKind::opaque("git").unwrap(),
            EffectKind::Git {
                operation: nah_proto::action::SemanticCode::new("restore-worktree").unwrap(),
            },
            root_write.clone(),
        ]],
        vec![],
    )
    .unwrap();
    assert_eq!(
        nah_policy::decide(
            &correlated,
            &guard_policy("git-worktree-discard", true),
            &[],
        )
        .unwrap()
        .verdict(),
        Verdict::Block
    );

    let split = ActionStream::new(
        Coverage::Partial,
        vec![
            vec![
                EffectKind::opaque("git").unwrap(),
                EffectKind::Git {
                    operation: nah_proto::action::SemanticCode::new("checkout-worktree").unwrap(),
                },
            ],
            vec![EffectKind::opaque("writer").unwrap(), root_write],
        ],
        vec![],
    )
    .unwrap();
    assert_eq!(
        nah_policy::decide(&split, &guard_policy("git-worktree-discard", true), &[],)
            .unwrap()
            .verdict(),
        Verdict::Delegate
    );
}
