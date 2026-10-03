#![allow(clippy::disallowed_types)]

use crate::support;

use nah_policy::EnforcementMode;
use nah_proto::action::Coverage;
use nah_proto::decision::{DecisionError, Verdict};
use nah_proto::extension::{ExtensionResponse, validate_response};
use nah_proto::observation::ProjectGuardDeclaration;
use support::{activation, context, quiet_evidence};

#[test]
fn full_and_partial_coverage_both_delegate_when_no_guard_blocks() {
    let (_, policy) = context(&[], vec![], ProjectGuardDeclaration::Absent);

    let full_decision = nah_policy::reduce_policy_decision(
        &quiet_evidence(),
        &nah_policy::ShippedGuards::new(),
        &Default::default(),
        Coverage::Full,
        &policy,
        &[],
        EnforcementMode::Normal,
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
        &[],
        EnforcementMode::Normal,
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
    let (_, policy) = context(
        &[("sys-power", true), ("sys-service-stop", true)],
        vec![],
        ProjectGuardDeclaration::Absent,
    );

    let core = nah_policy::reduce_policy_decision(
        &evidence,
        &nah_policy::ShippedGuards::new(),
        &support::guard_matches(&["sys-power"]),
        Coverage::Partial,
        &policy,
        &[],
        EnforcementMode::Normal,
    )
    .unwrap();
    assert_eq!(core.verdict(), Verdict::Block);
    assert_eq!(
        core.policy_attributions()
            .iter()
            .map(|guard| guard.name())
            .collect::<Vec<_>>(),
        ["sys-power"]
    );
}

#[test]
fn only_enabled_matched_guards_block_and_each_is_attributed() {
    let evidence = support::quiet_evidence();
    let decide = |enabled: &[(&str, bool)], matched: &[&'static str]| {
        let (_, policy) = context(enabled, vec![], ProjectGuardDeclaration::Absent);
        nah_policy::reduce_policy_decision(
            &evidence,
            &nah_policy::ShippedGuards::new(),
            &support::guard_matches(matched),
            Coverage::Full,
            &policy,
            &[],
            EnforcementMode::Normal,
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

    let both = decide(
        &[("sys-power", true), ("fs-system-tree", true)],
        &["sys-power", "fs-system-tree"],
    );
    assert_eq!(both.verdict(), Verdict::Block);
    assert_eq!(attributions(&both), ["fs-system-tree", "sys-power"]);

    // A disabled guard's match neither blocks nor suppresses an enabled one.
    let one = decide(
        &[("sys-power", false), ("fs-system-tree", true)],
        &["sys-power", "fs-system-tree"],
    );
    assert_eq!(one.verdict(), Verdict::Block);
    assert_eq!(attributions(&one), ["fs-system-tree"]);

    // An enabled guard never blocks on another guard's match.
    let other = decide(
        &[("sys-power", false), ("fs-system-tree", true)],
        &["sys-power"],
    );
    assert_eq!(other.verdict(), Verdict::Delegate);
    assert!(attributions(&other).is_empty());
}

#[test]
fn validated_extensions_can_only_add_a_block() {
    let quiet = activation("read");
    let guard = activation("custom-guard");
    let (ctx, policy) = context(
        &[],
        vec![quiet.clone(), guard.clone()],
        ProjectGuardDeclaration::Absent,
    );
    let abstained = validate_response(
        &ctx,
        &quiet,
        ExtensionResponse {
            block: None,
            abstain: Some(true),
            reason: None,
        },
    )
    .unwrap();
    let guard_response = validate_response(
        &ctx,
        &guard,
        ExtensionResponse {
            block: Some(true),
            abstain: None,
            reason: Some("custom guard blocked".into()),
        },
    )
    .unwrap();
    let decide = |responses: &[_]| {
        nah_policy::reduce_policy_decision(
            &quiet_evidence(),
            &nah_policy::ShippedGuards::new(),
            &Default::default(),
            Coverage::Full,
            &policy,
            responses,
            EnforcementMode::Normal,
        )
    };

    let quiet_decision = decide(std::slice::from_ref(&abstained)).unwrap();
    assert_eq!(quiet_decision.verdict(), Verdict::Delegate);
    assert!(quiet_decision.policy_attributions().is_empty());

    assert_eq!(
        decide(&[guard_response.clone(), guard_response.clone()]),
        Err(DecisionError::DuplicateAttribution)
    );

    let block = decide(&[abstained, guard_response]).unwrap();
    assert_eq!(block.verdict(), Verdict::Block);
    assert_eq!(block.reason(), "custom guard blocked");
}
