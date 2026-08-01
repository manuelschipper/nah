mod support;

use nah_actions::finalize;
use nah_proto::action::Coverage;
use nah_proto::ctx::SchemaVersion;
use nah_proto::observation::Observation;
use support::{Change, bash_plan, facts, observation_with, observe};

#[test]
fn every_observation_binding_change_fails_closed() {
    let exact_plan = bash_plan("echo hi > out");
    let request = exact_plan.observation_request().clone();
    assert_eq!(
        finalize(exact_plan, observe(&request, "echo")).coverage(),
        Coverage::Full
    );

    let wrong_id_plan = bash_plan("echo hi > out");
    let wrong_id = observation_with(
        wrong_id_plan.observation_request(),
        "wrong-request",
        Change::None,
    );
    assert_eq!(
        finalize(wrong_id_plan, wrong_id).coverage(),
        Coverage::Partial
    );

    for change in [Change::MissingPath, Change::ChangedPath, Change::ExtraEnv] {
        let plan = bash_plan("echo hi > out");
        let observation = observation_with(
            plan.observation_request(),
            plan.observation_request().request_id(),
            change,
        );
        assert_eq!(finalize(plan, observation).coverage(), Coverage::Partial);
    }

    let request = bash_plan("echo hi > out").observation_request().clone();
    let mut facts = facts(&request, "echo", Change::None);
    facts.push(facts.last().expect("fact").clone());
    assert!(Observation::new(SchemaVersion::V1, request.request_id(), facts).is_err());
}

#[test]
fn parseable_unlowerable_and_unparseable_inputs_are_partial() {
    let plan = bash_plan("for x in a; do echo $x; done");
    let observation = observe(plan.observation_request(), "echo");
    assert_eq!(finalize(plan, observation).coverage(), Coverage::Full);

    let plan = bash_plan("echo hi 2>&1 >out");
    let observation = observe(plan.observation_request(), "echo");
    assert_eq!(finalize(plan, observation).coverage(), Coverage::Full);

    for source in ["echo $(unclosed", ""] {
        let plan = bash_plan(source);
        let observation = observe(plan.observation_request(), "echo");
        assert_eq!(finalize(plan, observation).coverage(), Coverage::Partial);
    }
}
