use nah_proto::action::{ActionStream, Coverage, EffectKind};
use nah_proto::decision::{
    Decision, DecisionCore, DecisionEnvelope, DecisionError, DecisionOutput, ExitCode,
    GuardAttribution, GuardContribution, Verdict,
};

fn decision_stream(coverage: Coverage, effect_count: usize) -> ActionStream {
    let mut effects = vec![EffectKind::known("echo", "print").unwrap()];
    effects.extend((1..effect_count).map(|_| EffectKind::network(None)));
    ActionStream::new(coverage, vec![effects], vec![]).unwrap()
}

#[test]
fn decision_wire_types_have_exact_v1_projection_and_round_trip() {
    let guard = GuardAttribution::shipped("fs-system-tree").unwrap();
    let stream = decision_stream(Coverage::Full, 1);
    let core = DecisionCore::new(
        &stream,
        Verdict::Block,
        vec![GuardContribution::new(guard, "fs-system-tree blocked a root delete").unwrap()],
    )
    .unwrap();
    let envelope = DecisionEnvelope::new("decision-1", "2026-07-22T12:34:56.123Z", 42).unwrap();
    let decision = Decision::new(core.clone(), envelope.clone());
    let output = DecisionOutput::from(&decision);
    assert_eq!(
        DecisionOutput::new(&core, "decision-1", 42).unwrap(),
        output
    );
    assert_eq!(
        DecisionOutput::new(&core, "", 42),
        Err(DecisionError::EmptyText)
    );
    assert_eq!(ExitCode::from(Verdict::Block).value(), 1);
    assert_eq!(ExitCode::from(Verdict::Delegate).value(), 2);

    assert_eq!(
        serde_json::to_value(&decision).unwrap(),
        serde_json::json!({
            "v": 1,
            "core": {
                "verdict": "block",
                "reason": "fs-system-tree blocked a root delete",
                "policy_attributions": [{
                    "kind": "shipped",
                    "name": "fs-system-tree"
                }],
                "coverage": "full"
            },
            "envelope": {
                "id": "decision-1",
                "timestamp_rfc3339": "2026-07-22T12:34:56.123Z",
                "duration_us": 42
            }
        })
    );
    assert_eq!(
        serde_json::to_string(&output).unwrap(),
        r#"{"schema":"nah/decide/v1","v":1,"verdict":"block","reason":"fs-system-tree blocked a root delete","policy_attributions":[{"kind":"shipped","name":"fs-system-tree"}],"id":"decision-1","coverage":"full","duration_us":42}"#
    );
    assert_eq!(output.schema(), "nah/decide/v1");
    assert_eq!(
        serde_json::from_value::<Decision>(serde_json::to_value(decision.clone()).unwrap())
            .unwrap(),
        decision
    );
    assert_eq!(
        serde_json::from_value::<DecisionOutput>(serde_json::to_value(output.clone()).unwrap())
            .unwrap(),
        output
    );
}

#[test]
fn decision_deserialization_rejects_noncanonical_and_invalid_envelopes() {
    let guard = |name| {
        serde_json::json!({
            "kind": "shipped",
            "name": name
        })
    };
    let unsorted_core = serde_json::json!({
        "verdict": "block",
        "reason": "blocked",
        "policy_attributions": [guard("z"), guard("a")],
        "coverage": "full"
    });
    assert!(serde_json::from_value::<DecisionCore>(unsorted_core).is_err());

    let stored_allow = serde_json::json!({
        "verdict": "allow",
        "reason": "project write approved",
        "policy_attributions": [],
        "coverage": "full"
    });
    assert!(serde_json::from_value::<DecisionCore>(stored_allow).is_err());

    let old_attribution = serde_json::json!({
        "verdict": "block",
        "reason": "blocked",
        "policy_attributions": [{
            "kind": "shipped",
            "name": "fs-system-tree",
            "policy_version": 1
        }],
        "coverage": "full"
    });
    assert!(serde_json::from_value::<DecisionCore>(old_attribution).is_err());

    let old_declines = serde_json::json!({
        "verdict": "delegate",
        "reason": "no guard blocked this call",
        "policy_attributions": [],
        "decline_reasons": [],
        "coverage": "full"
    });
    assert!(serde_json::from_value::<DecisionCore>(old_declines).is_err());

    let structural = DecisionCore::structural_block(
        &decision_stream(Coverage::Partial, 1),
        "nah critical state is protected",
    )
    .unwrap();
    assert!(structural.policy_attributions().is_empty());
    assert_eq!(
        serde_json::from_value::<DecisionCore>(serde_json::to_value(&structural).unwrap()).unwrap(),
        structural
    );

    for timestamp in ["not-a-time", "2025-02-29T00:00:00Z", "2026-07-22 12:00:00Z"] {
        assert!(DecisionEnvelope::new("decision-1", timestamp, 0).is_err());
    }
    assert!(DecisionEnvelope::new("", "2026-07-22T12:00:00Z", 0).is_err());

    let version_error = serde_json::from_value::<DecisionOutput>(serde_json::json!({
        "schema": "nah/decide/v1",
        "v": 2,
        "verdict": {"future": true}
    }))
    .unwrap_err();
    assert!(version_error.to_string().contains("unsupported-version"));

    let schema_error = serde_json::from_value::<DecisionOutput>(serde_json::json!({
        "schema": "nah/test/v1",
        "v": 1,
        "verdict": "delegate",
        "reason": "no guard blocked this call",
        "policy_attributions": [],
        "id": "decision-1",
        "coverage": "full",
        "duration_us": 1
    }))
    .unwrap_err();
    assert!(
        schema_error
            .to_string()
            .contains("unsupported-decision-schema")
    );
}

#[test]
fn machine_output_does_not_expose_extension_supplied_reasons() {
    let extension: GuardAttribution = serde_json::from_value(serde_json::json!({
        "kind": "extension",
        "activation": {
            "identity": {"scope":"user","name":"custom"},
            "bundle_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "protocol": 1,
            "match_programs": ["echo"]
        }
    }))
    .unwrap();
    let stream = decision_stream(Coverage::Full, 1);
    let core = DecisionCore::new(
        &stream,
        Verdict::Block,
        vec![GuardContribution::new(extension, "planted invocation secret").unwrap()],
    )
    .unwrap();
    let output = DecisionOutput::new(&core, "decision-extension", 1).unwrap();

    assert_eq!(core.reason(), "planted invocation secret");
    assert_eq!(output.reason(), "extension guard blocked the call");
    assert!(!serde_json::to_string(&output).unwrap().contains("planted"));
}
