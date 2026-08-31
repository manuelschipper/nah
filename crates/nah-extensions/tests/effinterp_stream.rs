#![cfg(all(unix, feature = "effinterp"))]
#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

mod support;

use std::fs;

use nah_extensions::consult_extensions;
use nah_proto::stream::effinterp_proto::{Plan, SCHEMA_V1};
use nah_proto::stream::{ActionStream as EffinterpActionStream, EffectAnnotation};

use support::Fixture;

/// A plan whose one process effect invokes `tool`, the program the test
/// bundles activate on.
const TOOL_PLAN: &str = include_str!("fixtures/effinterp/exec-tool-recursive.json");

#[test]
fn guards_receive_the_effinterp_stream_shape_when_the_feature_is_on() {
    let fixture = Fixture::shell(
        "effinterp-shape",
        r#"cat > "$PWD/request.json"
printf '%s\n' '{"block":true,"reason":"shaped"}'"#,
    );
    let stream = tool_stream();

    consult_extensions(
        &fixture.catalog,
        &fixture.ctx,
        &fixture.observation,
        &fixture.action_stream,
        Some(&stream),
        &fixture.cache,
    );

    let request: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(fixture.run.parent().unwrap().join("request.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(request["v"], 1);
    assert_eq!(request["action_stream"]["v"], 1);
    assert_eq!(
        request["action_stream"]["plan"]["schema"],
        serde_json::json!(SCHEMA_V1)
    );
    assert_eq!(
        request["action_stream"]["annotations"]
            .as_array()
            .unwrap()
            .len(),
        stream.plan().effects.len()
    );
    assert!(request["action_stream"]["effects"].is_null());
    assert!(request["observation"].is_object());
}

#[test]
fn each_stream_shape_uses_its_own_memo_entry() {
    let fixture = Fixture::shell(
        "effinterp-memo",
        r#"count_file="$PWD/count"
count=0
if [ -f "$count_file" ]; then count=$(cat "$count_file"); fi
printf '%s' "$((count + 1))" > "$count_file"
printf '%s\n' '{"block":true,"reason":"counted"}'"#,
    );
    let stream = tool_stream();

    for effinterp in [None, Some(&stream), None, Some(&stream)] {
        consult_extensions(
            &fixture.catalog,
            &fixture.ctx,
            &fixture.observation,
            &fixture.action_stream,
            effinterp,
            &fixture.cache,
        );
    }

    assert_eq!(
        fs::read_to_string(fixture.run.parent().unwrap().join("count")).unwrap(),
        "2"
    );
}

fn tool_stream() -> EffinterpActionStream {
    let plan: Plan = serde_json::from_str(TOOL_PLAN).unwrap();
    let annotations = vec![EffectAnnotation::default(); plan.effects.len()];
    EffinterpActionStream::new(plan, annotations).unwrap()
}
