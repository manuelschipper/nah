#![allow(clippy::disallowed_types)]

mod support;

use nah_proto::action::EffectKind;
use nah_proto::decision::Verdict;
use support::{guard_policy, guarded_stream};

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
