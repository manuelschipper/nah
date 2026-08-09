#![allow(clippy::disallowed_types)]

mod support;

use std::hint::black_box;
use std::time::{Duration, Instant};

use nah_proto::action::{Coverage, Sensitivity};
use nah_proto::decision::{DecisionError, Verdict};
use nah_proto::extension::{ExtensionResponse, validate_response};
use nah_proto::observation::ProjectGuardDeclaration;
use support::{activation, context, project_scope, read_stream};

#[test]
fn full_and_partial_coverage_both_delegate_when_no_guard_blocks() {
    let full = read_stream(Coverage::Full, project_scope(), Sensitivity::None);
    let partial = read_stream(Coverage::Partial, project_scope(), Sensitivity::None);
    let (_, policy) = context(&[], vec![], ProjectGuardDeclaration::Absent);

    let full_decision = nah_policy::decide(&full, &policy, &[]).unwrap();
    assert_eq!(full_decision.verdict(), Verdict::Delegate);
    assert_eq!(full_decision.reason(), "no guard blocked this call");
    assert!(full_decision.policy_attributions().is_empty());

    let partial_decision = nah_policy::decide(&partial, &policy, &[]).unwrap();
    assert_eq!(partial_decision.verdict(), Verdict::Delegate);
    assert_eq!(partial_decision.reason(), "partial coverage");
}

#[test]
fn validated_extensions_can_only_add_a_block() {
    let stream = read_stream(Coverage::Full, project_scope(), Sensitivity::None);
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
        &stream,
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
        &stream,
        ExtensionResponse {
            block: Some(true),
            abstain: None,
            reason: Some("custom guard blocked".into()),
        },
    )
    .unwrap();

    let quiet_decision =
        nah_policy::decide(&stream, &policy, std::slice::from_ref(&abstained)).unwrap();
    assert_eq!(quiet_decision.verdict(), Verdict::Delegate);
    assert!(quiet_decision.policy_attributions().is_empty());

    assert_eq!(
        nah_policy::decide(
            &stream,
            &policy,
            &[guard_response.clone(), guard_response.clone()]
        ),
        Err(DecisionError::DuplicateAttribution)
    );

    let block = nah_policy::decide(&stream, &policy, &[abstained, guard_response]).unwrap();
    assert_eq!(block.verdict(), Verdict::Block);
    assert_eq!(block.reason(), "custom guard blocked");
}

#[test]
fn captured_policy_p99_is_below_one_millisecond() {
    let stream = read_stream(Coverage::Full, project_scope(), Sensitivity::None);
    let (_, policy) = context(
        &[("fs-system-tree", true)],
        vec![],
        ProjectGuardDeclaration::Absent,
    );
    for _ in 0..100 {
        black_box(nah_policy::decide(&stream, &policy, &[]).unwrap());
    }

    let mut samples = Vec::with_capacity(2_000);
    for _ in 0..2_000 {
        let started = Instant::now();
        black_box(nah_policy::decide(&stream, &policy, &[]).unwrap());
        samples.push(started.elapsed());
    }
    samples.sort_unstable();
    let p99 = samples[(samples.len() * 99) / 100];
    assert!(
        p99 <= Duration::from_millis(1),
        "captured policy p99 {p99:?} exceeds 1 ms"
    );
}
