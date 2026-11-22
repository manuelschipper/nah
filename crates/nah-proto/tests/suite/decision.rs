use nah_proto::action::Coverage;
use nah_proto::decision::{
    DecisionCore, DecisionError, GuardAttribution, GuardContribution, Verdict,
};

#[test]
fn decision_reason_is_canonical() {
    let a = GuardAttribution::shipped("a-guard").unwrap();
    let z = GuardAttribution::shipped("z-guard").unwrap();
    let core = DecisionCore::new_with_coverage(
        Coverage::Partial,
        Verdict::Block,
        vec![
            GuardContribution::new(z, "second").unwrap(),
            GuardContribution::new(a, "first").unwrap(),
        ],
    )
    .unwrap();

    assert_eq!(core.reason(), "a-guard: first. Also blocked by z-guard.");
    assert_eq!(core.policy_attributions()[0].name(), "a-guard");
}

#[test]
fn delegate_reason_states_coverage_or_that_no_guard_fired() {
    let partial =
        DecisionCore::new_with_coverage(Coverage::Partial, Verdict::Delegate, vec![]).unwrap();
    assert_eq!(partial.reason(), "partial coverage");

    let full = DecisionCore::new_with_coverage(Coverage::Full, Verdict::Delegate, vec![]).unwrap();
    assert_eq!(full.reason(), "no guard blocked this call");
}

#[test]
fn decision_core_accepts_coverage_without_the_legacy_stream_shape() {
    let core =
        DecisionCore::new_with_coverage(Coverage::Partial, Verdict::Delegate, vec![]).unwrap();

    assert_eq!(core.coverage(), Coverage::Partial);
    assert_eq!(core.reason(), "partial coverage");
    let structural =
        DecisionCore::structural_block_with_coverage(Coverage::Partial, None, "protected target")
            .unwrap();
    assert_eq!(structural.coverage(), Coverage::Partial);
    assert_eq!(structural.verdict(), Verdict::Block);
    assert!(structural.policy_attributions().is_empty());
}

#[test]
fn decision_reducer_deduplicates_and_canonicalizes_contributions() {
    let secrets = GuardAttribution::shipped("secrets/key-files-access").unwrap();
    let machine = GuardAttribution::shipped("machine/outside-workspace-delete").unwrap();

    let build = |contributions| {
        DecisionCore::new_with_coverage(Coverage::Full, Verdict::Block, contributions).unwrap()
    };
    let first = build(vec![
        GuardContribution::new(secrets.clone(), "this would read keys").unwrap(),
        GuardContribution::new(machine.clone(), "this would delete your home folder").unwrap(),
    ]);
    let permuted = build(vec![
        GuardContribution::new(machine, "this would delete your home folder").unwrap(),
        GuardContribution::new(secrets, "this would read keys").unwrap(),
    ]);

    // The first rule in catalog order leads; the others are named after it.
    assert_eq!(
        first.reason(),
        "machine/outside-workspace-delete: this would delete your home folder. Also blocked by secrets/key-files-access."
    );
    assert_eq!(first, permuted);
    assert_eq!(first.verdict(), Verdict::Block);
    assert_eq!(first.coverage(), Coverage::Full);
}

#[test]
fn decision_reducer_rejects_delegate_attributions_and_duplicates() {
    let guard = GuardAttribution::shipped("guard").unwrap();

    assert_eq!(
        DecisionCore::new_with_coverage(
            Coverage::Full,
            Verdict::Delegate,
            vec![GuardContribution::new(guard.clone(), "unexpected").unwrap()],
        ),
        Err(DecisionError::UnexpectedAttribution)
    );
    assert_eq!(
        DecisionCore::new_with_coverage(Coverage::Full, Verdict::Block, vec![],),
        Err(DecisionError::MissingVerdictContribution)
    );
    assert_eq!(
        DecisionCore::new_with_coverage(
            Coverage::Full,
            Verdict::Block,
            vec![
                GuardContribution::new(guard.clone(), "one").unwrap(),
                GuardContribution::new(guard, "two").unwrap(),
            ],
        ),
        Err(DecisionError::DuplicateAttribution)
    );
}
