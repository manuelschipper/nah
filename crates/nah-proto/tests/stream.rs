#![cfg(feature = "effinterp")]

use nah_proto::action::{ActionStreamVersion, Coverage};
use nah_proto::ctx::{AbsolutePath, ExecProtocolVersion, Platform};
use nah_proto::labels::{PathScope, Sensitivity};
use nah_proto::observation::{ObservationFailure, Observed};
use nah_proto::stream::effinterp_proto::Plan;
use nah_proto::stream::{ActionStream, EffectAnnotation, ExecRequest, PathLabel};

const FIXTURES: [&str; 4] = [
    include_str!("fixtures/effinterp/curl-upload-endpoint.json"),
    include_str!("fixtures/effinterp/exec-rm-recursive.json"),
    include_str!("fixtures/effinterp/shell-env-opaque-nested.json"),
    include_str!("fixtures/effinterp/symbolic-widened.json"),
];

#[test]
fn fixture_plans_round_trip_with_positional_annotations() {
    for (index, fixture) in FIXTURES.into_iter().enumerate() {
        let plan = fixture_plan(fixture);
        let annotations = vec![EffectAnnotation::default(); plan.effects.len()];
        let stream = ActionStream::new(plan, annotations).unwrap();

        assert_eq!(stream.version(), ActionStreamVersion::V1);
        assert_eq!(
            stream.coverage(),
            if index < 2 {
                Coverage::Full
            } else {
                Coverage::Partial
            }
        );
        assert_eq!(
            serde_json::from_str::<ActionStream>(&stream.canonical_json()).unwrap(),
            stream
        );
    }
}

#[test]
fn stream_rejects_invalid_plans_annotation_domains_and_counts() {
    let plan = fixture_plan(FIXTURES[1]);
    assert!(ActionStream::new(plan.clone(), vec![]).is_err());

    let mut annotations = vec![EffectAnnotation::default(); plan.effects.len()];
    annotations[0].path = Some(PathLabel::Unresolved);
    assert!(ActionStream::new(plan.clone(), annotations).is_err());

    let mut annotations = vec![EffectAnnotation::default(); plan.effects.len()];
    annotations[1].runtime_cli = Some("codex".into());
    assert!(ActionStream::new(plan, annotations).is_err());

    let mut invalid_plan = fixture_plan(FIXTURES[1]);
    invalid_plan.schema = "future/plan".into();
    let annotations = vec![EffectAnnotation::default(); invalid_plan.effects.len()];
    assert!(ActionStream::new(invalid_plan, annotations).is_err());
}

#[test]
fn resolved_project_labels_are_normalized_contained_and_root_consistent() {
    let plan = fixture_plan(FIXTURES[1]);
    let mut annotations = vec![EffectAnnotation::default(); plan.effects.len()];
    annotations[1].path = Some(resolved_project_path("/repo/cache", "/repo", false));
    assert!(ActionStream::new(plan.clone(), annotations).is_ok());

    for label in [
        resolved_project_path("/outside", "/repo", false),
        resolved_project_path("/repo", "/repo", false),
        resolved_project_path("/repo/../outside", "/repo", false),
    ] {
        let mut annotations = vec![EffectAnnotation::default(); plan.effects.len()];
        annotations[1].path = Some(label);
        assert!(ActionStream::new(plan.clone(), annotations).is_err());
    }
}

#[test]
fn exec_request_carries_the_new_shape_and_decodes_versions_first() {
    let plan = fixture_plan(FIXTURES[0]);
    let stream = ActionStream::new(
        plan.clone(),
        vec![EffectAnnotation::default(); plan.effects.len()],
    )
    .unwrap();
    let request = ExecRequest::new(
        stream.clone(),
        Observed::Ok {
            value: AbsolutePath::new(Platform::Linux, "/work").unwrap(),
        },
        Observed::Error {
            error: ObservationFailure::Unavailable,
        },
    )
    .unwrap();

    assert_eq!(request.version(), ExecProtocolVersion::V1);
    assert_eq!(request.action_stream(), &stream);
    assert_eq!(
        serde_json::from_value::<ExecRequest>(serde_json::to_value(&request).unwrap()).unwrap(),
        request
    );

    let stream_error = serde_json::from_value::<ActionStream>(serde_json::json!({
        "v": 2,
        "plan": {"future": true}
    }))
    .unwrap_err();
    assert!(stream_error.to_string().contains("unsupported-version"));

    let request_error = serde_json::from_value::<ExecRequest>(serde_json::json!({
        "v": 2,
        "action_stream": {"future": true}
    }))
    .unwrap_err();
    assert!(request_error.to_string().contains("unsupported-version"));
}

fn fixture_plan(fixture: &str) -> Plan {
    serde_json::from_str(fixture).unwrap()
}

fn resolved_project_path(path: &str, root: &str, selects_root: bool) -> PathLabel {
    PathLabel::Resolved {
        path: AbsolutePath::new(Platform::Linux, path).unwrap(),
        scope: PathScope::Project {
            root: AbsolutePath::new(Platform::Linux, root).unwrap(),
        },
        sensitivity: Sensitivity::None,
        protection: None,
        host_integrity: None,
        selects_root,
        selects_home: false,
    }
}
