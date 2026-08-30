use nah_proto::action::{ActionStream, Coverage, EffectKind};
use nah_proto::decision::{
    DecisionCore, DecisionError, GuardAttribution, GuardContribution, Verdict,
};

fn known(program: &str, operation: &str) -> EffectKind {
    EffectKind::known(program, operation).unwrap()
}

fn decision_stream(coverage: Coverage, effect_count: usize) -> ActionStream {
    let mut effects = vec![known("echo", "print")];
    effects.extend((1..effect_count).map(|_| EffectKind::network(None)));
    ActionStream::new(coverage, vec![effects], vec![]).unwrap()
}

#[test]
fn decision_reason_is_canonical() {
    let a = GuardAttribution::shipped("a-guard").unwrap();
    let z = GuardAttribution::shipped("z-guard").unwrap();
    let stream = decision_stream(Coverage::Partial, 1);
    let core = DecisionCore::new(
        &stream,
        Verdict::Block,
        vec![
            GuardContribution::new(z, "second").unwrap(),
            GuardContribution::new(a, "first").unwrap(),
        ],
    )
    .unwrap();

    assert_eq!(core.reason(), "first\nsecond");
    assert_eq!(core.policy_attributions()[0].name(), "a-guard");
}

#[test]
fn delegate_reason_states_coverage_or_that_no_guard_fired() {
    let partial = DecisionCore::new(
        &decision_stream(Coverage::Partial, 1),
        Verdict::Delegate,
        vec![],
    )
    .unwrap();
    assert_eq!(partial.reason(), "partial coverage");

    let full = DecisionCore::new(
        &decision_stream(Coverage::Full, 1),
        Verdict::Delegate,
        vec![],
    )
    .unwrap();
    assert_eq!(full.reason(), "no guard blocked this call");
}

#[test]
fn decision_core_accepts_coverage_without_the_legacy_stream_shape() {
    let core =
        DecisionCore::new_with_coverage(Coverage::Partial, Verdict::Delegate, vec![]).unwrap();

    assert_eq!(core.coverage(), Coverage::Partial);
    assert_eq!(core.reason(), "partial coverage");
}

#[test]
fn decision_reducer_deduplicates_and_canonicalizes_contributions() {
    let a_guard = GuardAttribution::shipped("a-guard").unwrap();
    let z_guard = GuardAttribution::shipped("z-guard").unwrap();
    let stream = decision_stream(Coverage::Full, 11);

    let build = |contributions| DecisionCore::new(&stream, Verdict::Block, contributions).unwrap();
    let first = build(vec![
        GuardContribution::new(z_guard.clone(), "same guard reason").unwrap(),
        GuardContribution::new(a_guard.clone(), "same guard reason").unwrap(),
    ]);
    let permuted = build(vec![
        GuardContribution::new(a_guard, "same guard reason").unwrap(),
        GuardContribution::new(z_guard, "same guard reason").unwrap(),
    ]);

    assert_eq!(first.reason(), "same guard reason");
    assert_eq!(first, permuted);
    assert_eq!(first.verdict(), Verdict::Block);
    assert_eq!(first.coverage(), Coverage::Full);
}

#[test]
fn decision_reducer_rejects_delegate_attributions_and_duplicates() {
    let guard = GuardAttribution::shipped("guard").unwrap();

    assert_eq!(
        DecisionCore::new(
            &decision_stream(Coverage::Full, 1),
            Verdict::Delegate,
            vec![GuardContribution::new(guard.clone(), "unexpected").unwrap()],
        ),
        Err(DecisionError::UnexpectedAttribution)
    );
    assert_eq!(
        DecisionCore::new(&decision_stream(Coverage::Full, 1), Verdict::Block, vec![],),
        Err(DecisionError::MissingVerdictContribution)
    );
    assert_eq!(
        DecisionCore::new(
            &decision_stream(Coverage::Full, 1),
            Verdict::Block,
            vec![
                GuardContribution::new(guard.clone(), "one").unwrap(),
                GuardContribution::new(guard, "two").unwrap(),
            ],
        ),
        Err(DecisionError::DuplicateAttribution)
    );
}
