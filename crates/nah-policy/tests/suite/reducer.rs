#![allow(clippy::disallowed_types)]

use crate::support;

use nah_policy::EnforcementMode;
use nah_proto::action::Coverage;
use nah_proto::ctx::{Guard, GuardLevel, GuardSettings, RuleOverride};
use nah_proto::decision::Verdict;
use support::{only_rules, quiet_evidence};

#[test]
fn full_and_partial_coverage_both_delegate_when_no_guard_blocks() {
    let policy = only_rules(&[]);

    let full_decision = nah_policy::reduce_policy_decision(
        &quiet_evidence(),
        &nah_policy::ShippedGuards::new(),
        &Default::default(),
        Coverage::Full,
        &policy,
        EnforcementMode::Normal,
        false,
    )
    .unwrap();
    assert_eq!(full_decision.verdict(), Verdict::Delegate);
    assert_eq!(full_decision.reason(), "no guard blocked this call");
    assert!(full_decision.policy_attributions().is_empty());

    let partial_decision = nah_policy::reduce_policy_decision(
        &quiet_evidence(),
        &nah_policy::ShippedGuards::new(),
        &Default::default(),
        Coverage::Partial,
        &policy,
        EnforcementMode::Normal,
        false,
    )
    .unwrap();
    assert_eq!(partial_decision.verdict(), Verdict::Delegate);
    assert_eq!(partial_decision.reason(), "partial coverage");
}

#[test]
fn a_guard_witness_stands_beside_an_unrelated_gap() {
    use nah_proto::effects::{
        CallId, Domain, EffectGap, GapCategory, GapId, GapPhase, GuardEvidence,
    };
    let witnessed = support::quiet_evidence();
    let mut graph = witnessed.graph().clone();
    graph.gaps.push(EffectGap {
        id: GapId(graph.gaps.len() as u32),
        phase: GapPhase::Translation,
        category: GapCategory::Unmodeled,
        call: CallId(0),
        domain: Some(Domain::Storage),
        code: "storage-target-kind-and-mode-unavailable".into(),
    });
    let evidence = GuardEvidence::new(graph, witnessed.public_selection().clone()).unwrap();
    let policy = only_rules(&[("machine/system-halt", true)]);

    let core = nah_policy::reduce_policy_decision(
        &evidence,
        &nah_policy::ShippedGuards::new(),
        &support::guard_matches(&[("machine/system-halt", 0)]),
        Coverage::Partial,
        &policy,
        EnforcementMode::Normal,
        false,
    )
    .unwrap();
    assert_eq!(core.verdict(), Verdict::Block);
    assert_eq!(
        core.policy_attributions()
            .iter()
            .map(|guard| guard.name())
            .collect::<Vec<_>>(),
        ["machine/system-halt"]
    );
}

/// `machine/system-halt`'s parts in definition order: power (core), then
/// service stop (strict). A fork bomb is its own rule. The two core parts of
/// `machine/disk-overwrite` still attribute once.
const POWER: (&str, usize) = ("machine/system-halt", 0);
const SERVICE_STOP: (&str, usize) = ("machine/system-halt", 1);
const FORK_BOMB: (&str, usize) = ("machine/fork-bomb", 0);
const RAW_DEVICE: (&str, usize) = ("machine/disk-overwrite", 0);
const VOLUME: (&str, usize) = ("machine/disk-overwrite", 1);
const SYSTEM_FILES: (&str, usize) = ("machine/system-files-modify", 0);

#[test]
fn a_part_blocks_when_its_rule_level_reaches_it_and_each_rule_is_attributed_once() {
    let evidence = support::quiet_evidence();
    let decide = |settings: GuardSettings, matched: &[(&'static str, usize)]| {
        let policy = settings;
        nah_policy::reduce_policy_decision(
            &evidence,
            &nah_policy::ShippedGuards::new(),
            &support::guard_matches(matched),
            Coverage::Full,
            &policy,
            EnforcementMode::Normal,
            false,
        )
        .unwrap()
    };
    let attributions = |decision: &nah_proto::decision::DecisionCore| {
        decision
            .policy_attributions()
            .iter()
            .map(|guard| guard.name().to_owned())
            .collect::<Vec<_>>()
    };
    let machine_at = |level| {
        let mut settings = GuardSettings::default();
        settings.set_guard(Guard::Machine, level);
        settings
    };

    // Two core parts of one rule attribute once. A fork bomb is its own rule,
    // so it is not folded into shutdown.
    let core = decide(
        GuardSettings::default(),
        &[
            POWER,
            FORK_BOMB,
            SERVICE_STOP,
            SYSTEM_FILES,
            RAW_DEVICE,
            VOLUME,
        ],
    );
    assert_eq!(core.verdict(), Verdict::Block);
    assert_eq!(
        attributions(&core),
        [
            "machine/disk-overwrite",
            "machine/fork-bomb",
            "machine/system-files-modify",
            "machine/system-halt",
        ]
    );

    // A strict part runs only at strict or under an `enabled` override.
    assert_eq!(
        decide(GuardSettings::default(), &[SERVICE_STOP]).verdict(),
        Verdict::Delegate
    );
    assert_eq!(
        attributions(&decide(machine_at(GuardLevel::Strict), &[SERVICE_STOP])),
        ["machine/system-halt"]
    );
    assert_eq!(
        attributions(&decide(
            only_rules(&[("machine/system-halt", true)]),
            &[SERVICE_STOP]
        )),
        ["machine/system-halt"]
    );

    // `disabled` and a guard turned off stop every part; neither suppresses
    // another rule's block.
    let mut disabled = machine_at(GuardLevel::Strict);
    disabled.set_rule("machine/system-halt", Some(RuleOverride::Disabled));
    let one = decide(disabled.clone(), &[POWER, SYSTEM_FILES]);
    assert_eq!(attributions(&one), ["machine/system-files-modify"]);
    assert_eq!(decide(disabled, &[POWER]).verdict(), Verdict::Delegate);
    assert_eq!(
        decide(machine_at(GuardLevel::Off), &[POWER, SYSTEM_FILES]).verdict(),
        Verdict::Delegate
    );
}
