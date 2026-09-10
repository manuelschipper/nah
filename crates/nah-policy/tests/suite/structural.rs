#![allow(clippy::disallowed_types)]

use crate::support;

use nah_policy::EnforcementMode;
use nah_proto::action::{
    ActionStream, Coverage, EffectKind, FilesystemEffect, FilesystemOperation, NahProtectionTier,
    PathScope, Sensitivity,
};
use nah_proto::decision::Verdict;
use nah_proto::observation::ProjectGuardDeclaration;
use support::{context, guard_policy, path, protected_stream};

#[test]
fn critical_self_protection_is_not_a_disableable_guard() {
    let filesystem = protected_stream(NahProtectionTier::Critical);
    let decision = nah_policy::decide(
        &filesystem,
        &crate::support::evidence(&filesystem, &nah_inline::InlineReport::default()),
        &guard_policy("fs-system-tree", false),
        &[],
    )
    .unwrap();
    assert_eq!(decision.verdict(), Verdict::Block);
    assert!(decision.reason().contains("do not retry"));
    assert!(decision.reason().contains("nah nap"));
    assert!(decision.policy_attributions().is_empty());

    for program in [
        "nah", "cargo", "agy", "amp", "copilot", "droid", "hermes", "openclaw",
    ] {
        let invocation = ActionStream::new(
            Coverage::Full,
            vec![vec![
                EffectKind::known(program, "critical-mutation").unwrap(),
            ]],
            vec![],
        )
        .unwrap();
        let decision = nah_policy::decide(
            &invocation,
            &crate::support::evidence(&invocation, &nah_inline::InlineReport::default()),
            &guard_policy("fs-system-tree", false),
            &[],
        )
        .unwrap();
        assert_eq!(decision.verdict(), Verdict::Block);
        assert!(decision.reason().contains("do not retry"));
        assert!(decision.policy_attributions().is_empty());
    }
}

#[test]
fn nap_modes_pause_only_the_agreed_enforcement_layers() {
    let policy = guard_policy("fs-system-tree", false);
    let critical = protected_stream(NahProtectionTier::Critical);
    let permanent = protected_stream(NahProtectionTier::Permanent);
    let refused = ActionStream::new(
        Coverage::Partial,
        vec![vec![
            EffectKind::opaque("bash").unwrap(),
            EffectKind::SystemState {
                operation: nah_proto::action::SemanticCode::ANALYSIS_REFUSED,
            },
        ]],
        vec![],
    )
    .unwrap();

    let self_paused = nah_policy::decide_with_mode(
        &critical,
        &crate::support::evidence(&critical, &nah_inline::InlineReport::default()),
        &policy,
        &[],
        EnforcementMode::SelfProtectionPaused,
    )
    .unwrap();
    assert_eq!(self_paused.verdict(), Verdict::Delegate);

    let all_paused = nah_policy::decide_with_mode(
        &critical,
        &crate::support::evidence(&critical, &nah_inline::InlineReport::default()),
        &policy,
        &[],
        EnforcementMode::AllPaused,
    )
    .unwrap();
    assert_eq!(all_paused.verdict(), Verdict::Delegate);

    for mode in [
        EnforcementMode::Normal,
        EnforcementMode::SelfProtectionPaused,
        EnforcementMode::AllPaused,
    ] {
        let decision = nah_policy::decide_with_mode(
            &permanent,
            &crate::support::evidence(&permanent, &nah_inline::InlineReport::default()),
            &policy,
            &[],
            mode,
        )
        .unwrap();
        assert_eq!(decision.verdict(), Verdict::Block);
        assert!(decision.reason().contains("operator"));

        let decision = nah_policy::decide_with_mode(
            &refused,
            &crate::support::evidence(&refused, &nah_inline::InlineReport::default()),
            &policy,
            &[],
            mode,
        )
        .unwrap();
        assert_eq!(decision.verdict(), Verdict::Delegate);
        assert!(decision.policy_attributions().is_empty());
    }
}

#[test]
fn proposal_tier_delegates_to_the_runtime_instead_of_blocking() {
    let stream = protected_stream(NahProtectionTier::Proposal);
    let (_, policy) = context(&[], vec![], ProjectGuardDeclaration::Absent);
    let decision = nah_policy::decide(
        &stream,
        &crate::support::evidence(&stream, &nah_inline::InlineReport::default()),
        &policy,
        &[],
    )
    .unwrap();
    assert_eq!(decision.verdict(), Verdict::Delegate);
    assert!(decision.policy_attributions().is_empty());
}

#[test]
fn incomplete_analysis_does_not_hide_a_recognized_guard_effect() {
    let stream = ActionStream::new(
        Coverage::Partial,
        vec![vec![
            EffectKind::opaque("bash").unwrap(),
            EffectKind::Filesystem {
                effect: FilesystemEffect {
                    operation: FilesystemOperation::Delete,
                    target: path("/"),
                    scope: PathScope::OutsideProject,
                    sensitivity: Sensitivity::None,
                    protection: None,
                    host_integrity: None,
                    selects_root: false,
                    selects_home: false,
                    recursive: true,
                    pattern: false,
                },
            },
            EffectKind::SystemState {
                operation: nah_proto::action::SemanticCode::ANALYSIS_REFUSED,
            },
        ]],
        vec![],
    )
    .unwrap();

    let decision = nah_policy::decide(
        &stream,
        &crate::support::evidence(&stream, &nah_inline::InlineReport::default()),
        &guard_policy("fs-system-tree", true),
        &[],
    )
    .unwrap();
    assert_eq!(decision.verdict(), Verdict::Block);
    assert_eq!(decision.policy_attributions()[0].name(), "fs-system-tree");
}

#[test]
fn terminal_candidates_follow_structural_nap_modes() {
    use nah_proto::action::{
        InvocationEffect, InvocationInput, ProtectedNahOperation, TerminalCandidate,
        TerminalCarrier, TerminalContent, TerminalControl, TerminalOperation,
    };
    for (operation, tier) in [
        (ProtectedNahOperation::Nap, NahProtectionTier::Permanent),
        (
            ProtectedNahOperation::Maintenance,
            NahProtectionTier::Critical,
        ),
    ] {
        let stream = ActionStream::new(
            Coverage::Partial,
            vec![vec![EffectKind::Invocation {
                invocation: InvocationEffect::TerminalControl {
                    program: "tmux".into(),
                    input: InvocationInput::shell("tmux", vec!["tmux".into()], None),
                    cwd: None,
                    control: TerminalControl {
                        carrier: TerminalCarrier::Tmux,
                        target: None,
                        selector: None,
                        operation: TerminalOperation::Input,
                        content: TerminalContent::Literal {
                            text: "protected command".into(),
                        },
                        candidate: Some(TerminalCandidate { operation, tier }),
                    },
                },
            }]],
            vec![],
        )
        .unwrap();
        for mode in [
            EnforcementMode::Normal,
            EnforcementMode::SelfProtectionPaused,
            EnforcementMode::AllPaused,
        ] {
            let decision = nah_policy::decide_with_mode(
                &stream,
                &crate::support::evidence(&stream, &nah_inline::InlineReport::default()),
                &guard_policy("fs-system-tree", false),
                &[],
                mode,
            )
            .unwrap();
            assert_eq!(
                decision.verdict(),
                if tier == NahProtectionTier::Permanent || mode == EnforcementMode::Normal {
                    Verdict::Block
                } else {
                    Verdict::Delegate
                }
            );
        }
    }
}
