#![allow(clippy::disallowed_types)]

mod support;

use nah_proto::action::{ActionStream, Coverage, EffectKind, FilesystemOperation};
use nah_proto::decision::Verdict;
use support::{filesystem, guard_policy, guarded_stream, project_scope};

#[test]
fn git_guards_block_only_their_one_sentence_operation() {
    for (guard, operation) in [
        ("git-clean-force", "clean-force"),
        ("git-metadata", "metadata-mutation"),
        ("git-force-push", "force-push"),
        ("git-hard-reset", "hard-reset"),
        ("git-recovery-destroy", "recovery-destroy"),
        ("git-remote-delete", "git-remote-delete"),
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
