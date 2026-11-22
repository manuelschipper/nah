#![allow(clippy::disallowed_types)]

use crate::support;

use nah_policy::EnforcementMode;
use nah_proto::action::Coverage;
use nah_proto::decision::Verdict;
use nah_proto::effinterp_proto::ConditionKind;
use nah_proto::labels::{NahProtectionTier, SelfRule};
use support::{control_mutation, guard_policy, protected_write, quiet_evidence};

#[test]
fn critical_self_protection_is_not_a_disableable_guard() {
    let filesystem = protected_write(NahProtectionTier::Critical);
    let launches = [
        SelfRule::NahConfigChange,
        SelfRule::AgentConfigChange,
        SelfRule::UnguardedAgentLaunch,
    ]
    .map(|rule| (rule, control_mutation(NahProtectionTier::Critical, rule)));
    let decide = |evidence| {
        nah_policy::reduce_policy_decision(
            evidence,
            &nah_policy::ShippedGuards::new(),
            &Default::default(),
            Coverage::Full,
            &guard_policy("machine/system-files-modify", false),
            EnforcementMode::Normal,
            false,
        )
        .unwrap()
    };
    let decision = decide(&filesystem);
    assert_eq!(decision.verdict(), Verdict::Block);
    assert!(decision.reason().starts_with("self/nah-config-change: "));
    assert!(decision.reason().contains("nah nap"));
    assert!(decision.policy_attributions().is_empty());
    // A write through a link created earlier in the same invocation, as in
    // `ln -s ~/.nah/config alias && echo x > alias`, happens once `ln`
    // succeeds.
    let after_link = support::conditioned(&filesystem, ConditionKind::ShortCircuit, false);
    let decision = decide(&after_link);
    assert_eq!(decision.verdict(), Verdict::Block);

    // The block names the self rule its control evidence falls under.
    for (rule, evidence) in &launches {
        let decision = decide(evidence);
        assert_eq!(decision.verdict(), Verdict::Block);
        assert!(decision.reason().starts_with(&format!("{}: ", rule.id())));
        assert!(decision.policy_attributions().is_empty());
    }
}

#[test]
fn every_blocking_self_rule_is_named_after_the_first() {
    use NahProtectionTier::{Critical, Permanent};
    let policy = guard_policy("machine/system-files-modify", false);
    let decide = |evidence, mode| {
        nah_policy::reduce_policy_decision(
            evidence,
            &nah_policy::ShippedGuards::new(),
            &Default::default(),
            Coverage::Full,
            &policy,
            mode,
            false,
        )
        .unwrap()
    };
    let two_critical = support::control_mutations(&[
        (Critical, SelfRule::AgentConfigChange),
        (Critical, SelfRule::NahConfigChange),
        (Critical, SelfRule::AgentConfigChange),
    ]);
    assert_eq!(
        decide(&two_critical, EnforcementMode::Normal)
            .reason()
            .split_once(". Also blocked by ")
            .map(|(lead, rest)| (lead.split_once(':').unwrap().0, rest)),
        Some(("self/agent-config-change", "self/nah-config-change."))
    );

    // A nap leads; a critical rule beside it is named only while
    // self-protection runs.
    let nap_and_launch = support::control_mutations(&[
        (Critical, SelfRule::UnguardedAgentLaunch),
        (Permanent, SelfRule::NahConfigChange),
    ]);
    let normal = decide(&nap_and_launch, EnforcementMode::Normal);
    assert!(normal.reason().starts_with("self/nah-config-change: "));
    assert!(
        normal
            .reason()
            .ends_with(" Also blocked by self/unguarded-agent-launch.")
    );
    let paused = decide(&nap_and_launch, EnforcementMode::SelfProtectionPaused);
    assert_eq!(paused.verdict(), Verdict::Block);
    assert!(!paused.reason().contains("self/unguarded-agent-launch"));

    // A terminal's own text speaks only when its input leads.
    let mut tmux = support::resource(nah_proto::effects::ResourceKind::Unknown);
    tmux.id = nah_proto::effects::ResourceId(1);
    tmux.identity.provider = nah_proto::effects::Knowledge::Known("tmux".into());
    let wiring_then_tmux = |reversed: bool| {
        let mut payloads = vec![
            nah_proto::effects::FactPayload::ControlMutation {
                target: nah_proto::effects::ResourceId(0),
                action: nah_proto::effects::ControlAction::Other,
                candidate_identity: nah_proto::effects::Knowledge::Unknown,
                tier: nah_proto::effects::Knowledge::Known(Critical),
                rule: SelfRule::AgentConfigChange,
            },
            nah_proto::effects::FactPayload::ControlInput {
                target: nah_proto::effects::ResourceId(1),
                action: nah_proto::effects::ControlAction::Deliver,
                transport: nah_proto::effects::ControlTransport::Input,
                payload_certainty: nah_proto::effects::Certainty::Conservative,
                candidate_identity: nah_proto::effects::Knowledge::Unknown,
                tier: nah_proto::effects::Knowledge::Known(Critical),
            },
        ];
        if reversed {
            payloads.reverse();
        }
        support::facts_evidence(
            vec![
                support::resource(nah_proto::effects::ResourceKind::Unknown),
                tmux.clone(),
            ],
            payloads,
        )
    };
    let (wiring, typed) = (wiring_then_tmux(false), wiring_then_tmux(true));
    let wiring = decide(&wiring, EnforcementMode::Normal);
    assert!(wiring.reason().starts_with("self/agent-config-change: "));
    assert!(!wiring.reason().contains("tmux"));
    let typed = decide(&typed, EnforcementMode::Normal);
    assert!(typed.reason().starts_with("self/nah-config-change: "));
    assert!(typed.reason().contains("tmux"));
}

#[test]
fn self_blocks_name_every_matching_shipped_rule() {
    let policy = support::only_rules(&[
        ("machine/system-files-modify", true),
        ("machine/permissions-weaken", true),
    ]);
    let decision = nah_policy::reduce_policy_decision(
        &protected_write(NahProtectionTier::Critical),
        &nah_policy::ShippedGuards::new(),
        &support::guard_matches(&[
            ("machine/system-files-modify", 0),
            ("machine/permissions-weaken", 0),
        ]),
        Coverage::Full,
        &policy,
        EnforcementMode::Normal,
        false,
    )
    .unwrap();
    assert_eq!(decision.verdict(), Verdict::Block);
    assert!(decision.reason().starts_with("self/nah-config-change: "));
    assert!(
        decision.reason().ends_with(
            " Also blocked by machine/permissions-weaken and machine/system-files-modify."
        )
    );
    assert!(decision.reason().contains("`nah nap all`"));
    assert_eq!(
        decision
            .policy_attributions()
            .iter()
            .map(|guard| guard.name())
            .collect::<Vec<_>>(),
        vec!["machine/permissions-weaken", "machine/system-files-modify"]
    );

    // A permanent block names them too, unless a nap of everything paused
    // them.
    let permanent = |mode| {
        nah_policy::reduce_policy_decision(
            &protected_write(NahProtectionTier::Permanent),
            &nah_policy::ShippedGuards::new(),
            &support::guard_matches(&[("machine/permissions-weaken", 0)]),
            Coverage::Full,
            &policy,
            mode,
            false,
        )
        .unwrap()
    };
    let normal = permanent(EnforcementMode::Normal);
    assert!(
        normal
            .reason()
            .ends_with(" Also blocked by machine/permissions-weaken.")
    );
    let all_paused = permanent(EnforcementMode::AllPaused);
    assert_eq!(all_paused.verdict(), Verdict::Block);
    assert!(all_paused.policy_attributions().is_empty());
    assert!(!all_paused.reason().contains("machine/permissions-weaken"));
    // Everything is already paused. This permanent block is the one that
    // stops an agent starting a nap, so it names no further nap command.
    assert!(!all_paused.reason().contains("`nah nap"));
}

/// A rule nap does not show up as a shipped block, so a self-protection
/// block on a call that rule also matches must not suggest a bare nap: that
/// nap would wake the rule. `nah nap all` keeps both paused.
#[test]
fn a_rule_nap_and_self_protection_suggest_a_nap_of_everything() {
    let policy = support::only_rules(&[("machine/system-files-modify", false)]);
    let decide = |rules_paused| {
        nah_policy::reduce_policy_decision(
            &protected_write(NahProtectionTier::Critical),
            &nah_policy::ShippedGuards::new(),
            &support::guard_matches(&[("machine/system-files-modify", 0)]),
            Coverage::Full,
            &policy,
            EnforcementMode::Normal,
            rules_paused,
        )
        .unwrap()
    };
    let paused = decide(true);
    assert!(paused.policy_attributions().is_empty());
    assert!(paused.reason().contains("`nah nap all`"));
    let awake = decide(false);
    assert!(awake.reason().contains("`nah nap`"));
    assert!(!awake.reason().contains("`nah nap all`"));

    let all_paused = nah_policy::reduce_policy_decision(
        &control_mutation(NahProtectionTier::Permanent, SelfRule::AgentConfigChange),
        &nah_policy::ShippedGuards::new(),
        &Default::default(),
        Coverage::Full,
        &policy,
        EnforcementMode::AllPaused,
        false,
    )
    .unwrap();
    assert_eq!(all_paused.verdict(), Verdict::Block);
    assert!(all_paused.reason().contains("operator"));
    assert!(!all_paused.reason().contains("`nah nap"));
}

#[test]
fn nap_modes_pause_only_the_agreed_enforcement_layers() {
    let policy = guard_policy("machine/system-files-modify", false);
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
            mode,
            false,
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
                &guard_policy("machine/system-files-modify", false),
                mode,
                false,
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
