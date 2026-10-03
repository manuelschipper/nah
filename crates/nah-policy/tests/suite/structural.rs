#![allow(clippy::disallowed_types)]

use crate::support;

use nah_policy::EnforcementMode;
use nah_proto::action::Coverage;
use nah_proto::decision::Verdict;
use nah_proto::effinterp_proto::ConditionKind;
use nah_proto::labels::NahProtectionTier;
use nah_proto::observation::ProjectGuardDeclaration;
use support::{context, control_mutation, guard_policy, protected_write, quiet_evidence};

#[test]
fn critical_self_protection_is_not_a_disableable_guard() {
    let filesystem = protected_write(NahProtectionTier::Critical);
    let decide = |evidence| {
        nah_policy::reduce_policy_decision(
            evidence,
            &nah_policy::ShippedGuards::new(),
            &Default::default(),
            Coverage::Full,
            &guard_policy("fs-system-tree", false),
            &[],
            EnforcementMode::Normal,
        )
        .unwrap()
    };
    let decision = decide(&filesystem);
    assert_eq!(decision.verdict(), Verdict::Block);
    assert!(decision.reason().contains("do not retry"));
    assert!(decision.reason().contains("nah nap"));
    assert!(decision.policy_attributions().is_empty());
    // A write through a link created earlier in the same invocation, as in
    // `ln -s ~/.nah/config alias && echo x > alias`, happens once `ln`
    // succeeds.
    let after_link = support::conditioned(&filesystem, ConditionKind::ShortCircuit, false);
    let decision = decide(&after_link);
    assert_eq!(decision.verdict(), Verdict::Block);
    assert!(decision.reason().contains("do not retry"));

    let decision = decide(&control_mutation(NahProtectionTier::Critical));
    assert_eq!(decision.verdict(), Verdict::Block);
    assert!(decision.reason().contains("do not retry"));
    assert!(decision.policy_attributions().is_empty());
}

#[test]
fn nap_modes_pause_only_the_agreed_enforcement_layers() {
    let policy = guard_policy("fs-system-tree", false);
    let critical = protected_write(NahProtectionTier::Critical);
    let permanent = protected_write(NahProtectionTier::Permanent);
    // A refused analysis leaves partial coverage and no fact to match.
    let refused = quiet_evidence();
    let decide = |evidence, coverage, mode| {
        nah_policy::reduce_policy_decision(
            evidence,
            &nah_policy::ShippedGuards::new(),
            &Default::default(),
            coverage,
            &policy,
            &[],
            mode,
        )
        .unwrap()
    };

    let self_paused = decide(
        &critical,
        Coverage::Full,
        EnforcementMode::SelfProtectionPaused,
    );
    assert_eq!(self_paused.verdict(), Verdict::Delegate);

    let all_paused = decide(&critical, Coverage::Full, EnforcementMode::AllPaused);
    assert_eq!(all_paused.verdict(), Verdict::Delegate);

    for mode in [
        EnforcementMode::Normal,
        EnforcementMode::SelfProtectionPaused,
        EnforcementMode::AllPaused,
    ] {
        let decision = decide(&permanent, Coverage::Full, mode);
        assert_eq!(decision.verdict(), Verdict::Block);
        assert!(decision.reason().contains("operator"));

        let decision = decide(&refused, Coverage::Partial, mode);
        assert_eq!(decision.verdict(), Verdict::Delegate);
        assert!(decision.policy_attributions().is_empty());
    }
}

#[test]
fn proposal_tier_delegates_to_the_runtime_instead_of_blocking() {
    let (_, policy) = context(&[], vec![], ProjectGuardDeclaration::Absent);
    let decision = nah_policy::reduce_policy_decision(
        &protected_write(NahProtectionTier::Proposal),
        &nah_policy::ShippedGuards::new(),
        &Default::default(),
        Coverage::Full,
        &policy,
        &[],
        EnforcementMode::Normal,
    )
    .unwrap();
    assert_eq!(decision.verdict(), Verdict::Delegate);
    assert!(decision.policy_attributions().is_empty());
}

#[test]
fn terminal_candidates_follow_structural_nap_modes() {
    for tier in [NahProtectionTier::Permanent, NahProtectionTier::Critical] {
        let evidence = support::terminal_input("tmux", tier);
        for mode in [
            EnforcementMode::Normal,
            EnforcementMode::SelfProtectionPaused,
            EnforcementMode::AllPaused,
        ] {
            let decision = nah_policy::reduce_policy_decision(
                &evidence,
                &nah_policy::ShippedGuards::new(),
                &Default::default(),
                Coverage::Partial,
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
