use nah_proto::action::{ActionStream, Coverage, EffectKind};
use nah_proto::ctx::{
    AbsolutePath, ActivationProjection, ContentHash, Ctx, ExecProtocolVersion, GuardIdentity,
    Platform, PolicyVersion, SchemaVersion, TrustProjection,
};
use nah_proto::extension::{
    ConsultationOutcome, ExtensionConsultation, ExtensionResponse, ExtensionValidationError,
    validate_response,
};

#[test]
fn raw_response_preserves_semantically_invalid_both_arm_shape() {
    let raw: ExtensionResponse =
        serde_json::from_str(r#"{"block":true,"abstain":true,"reason":"invalid both-arm"}"#)
            .unwrap();

    assert_eq!(raw.block, Some(true));
    assert_eq!(raw.abstain, Some(true));

    let raw: ExtensionResponse =
        serde_json::from_str(r#"{"block":true,"reason":"round trip"}"#).unwrap();
    assert_eq!(
        serde_json::from_value::<ExtensionResponse>(serde_json::to_value(&raw).unwrap()).unwrap(),
        raw
    );
}

#[test]
fn raw_response_rejects_unknown_fields() {
    for text in [r#"{"cliam":["e0"]}"#, r#"{"claim":["e0"],"reason":"ok"}"#] {
        let error = serde_json::from_str::<ExtensionResponse>(text).unwrap_err();
        assert!(error.to_string().contains("unknown field"), "{text}");
    }
}

#[test]
fn consultation_outcomes_have_stable_tags() {
    let activation: ActivationProjection = serde_json::from_value(serde_json::json!({
        "identity": {"scope": "user", "name": "corp"},
        "bundle_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "protocol": 1,
        "match_programs": ["curl"]
    }))
    .unwrap();
    let consultation = ExtensionConsultation {
        activation: activation.clone(),
        outcome: ConsultationOutcome::RejectedTransport {
            code: nah_proto::extension::TransportRejectionCode::InvalidJson,
        },
    };

    let value = serde_json::to_value(consultation).unwrap();
    assert_eq!(
        value["outcome"],
        serde_json::json!({"kind": "rejected-transport", "code": "invalid-json"})
    );
    assert_eq!(
        serde_json::to_value(
            serde_json::from_value::<ExtensionConsultation>(value.clone()).unwrap()
        )
        .unwrap(),
        value
    );

    let cases = [
        (
            ConsultationOutcome::Silence,
            serde_json::json!({"kind":"silence"}),
        ),
        (
            ConsultationOutcome::Crash,
            serde_json::json!({"kind":"crash"}),
        ),
        (
            ConsultationOutcome::Timeout,
            serde_json::json!({"kind":"timeout"}),
        ),
        (
            ConsultationOutcome::SpawnFailure,
            serde_json::json!({"kind":"spawn-failure"}),
        ),
        (
            ConsultationOutcome::Response {
                response: ExtensionResponse {
                    block: Some(true),
                    abstain: None,
                    reason: Some("blocked".into()),
                },
            },
            serde_json::json!({"kind":"response","response":{"block":true,"reason":"blocked"}}),
        ),
    ];
    for (outcome, expected) in cases {
        assert_eq!(
            serde_json::to_value(ExtensionConsultation {
                activation: activation.clone(),
                outcome,
            })
            .unwrap()["outcome"],
            expected
        );
    }
}

#[test]
fn validator_is_the_only_guard_response_boundary() {
    let activation = activation("guard");
    let ctx = ctx_with(activation.clone());
    let stream = action_stream();

    let validated = validate_response(
        &ctx,
        &activation,
        &stream,
        ExtensionResponse {
            block: Some(true),
            abstain: None,
            reason: Some("unsafe operation".into()),
        },
    )
    .unwrap();

    assert!(validated.is_block());
    assert_eq!(validated.reason(), "unsafe operation");
    assert_eq!(validated.activation(), &activation);
}

#[test]
fn validator_accepts_exact_abstention() {
    let activation = activation("extension");
    let validated = validate_response(
        &ctx_with(activation.clone()),
        &activation,
        &action_stream(),
        ExtensionResponse {
            block: None,
            abstain: Some(true),
            reason: None,
        },
    )
    .unwrap();

    assert!(validated.is_abstain());
    assert!(!validated.is_block());
    assert_eq!(validated.reason(), "");
}

#[test]
fn validator_rejects_inactive_ambiguous_and_shapeless_responses() {
    let guard = activation("guard");
    let inactive = activation("inactive");
    let ctx = ctx_with(guard.clone());
    let stream = action_stream();

    let response = ExtensionResponse {
        block: Some(true),
        abstain: None,
        reason: Some("reason".into()),
    };
    assert_eq!(
        validate_response(&ctx, &inactive, &stream, response.clone()),
        Err(ExtensionValidationError::InactiveActivation)
    );
    assert_eq!(
        validate_response(
            &ctx,
            &guard,
            &stream,
            ExtensionResponse {
                block: Some(true),
                abstain: Some(true),
                reason: Some("ambiguous".into()),
            },
        ),
        Err(ExtensionValidationError::AmbiguousResponse)
    );
    assert_eq!(
        validate_response(
            &ctx,
            &guard,
            &stream,
            ExtensionResponse {
                block: None,
                abstain: Some(false),
                reason: None,
            },
        ),
        Err(ExtensionValidationError::AbstainMustBeTrue)
    );
    assert_eq!(
        validate_response(
            &ctx,
            &guard,
            &stream,
            ExtensionResponse {
                block: None,
                abstain: Some(true),
                reason: Some("not part of abstention".into()),
            },
        ),
        Err(ExtensionValidationError::AbstainHasReason)
    );
}

#[test]
fn validator_rejects_every_invalid_block_shape() {
    let guard = activation("guard");
    let ctx = ctx_with(guard.clone());
    let stream = action_stream();

    let cases = [
        (
            ExtensionResponse {
                block: None,
                abstain: None,
                reason: Some("nothing".into()),
            },
            ExtensionValidationError::MissingOutcome,
        ),
        (
            ExtensionResponse {
                block: Some(false),
                abstain: None,
                reason: Some("false is never a block".into()),
            },
            ExtensionValidationError::BlockMustBeTrue,
        ),
        (
            ExtensionResponse {
                block: Some(true),
                abstain: None,
                reason: None,
            },
            ExtensionValidationError::MissingReason,
        ),
        (
            ExtensionResponse {
                block: Some(true),
                abstain: None,
                reason: Some(String::new()),
            },
            ExtensionValidationError::MissingReason,
        ),
        (
            ExtensionResponse {
                block: Some(true),
                abstain: None,
                reason: Some("x".repeat(1025)),
            },
            ExtensionValidationError::ReasonTooLong,
        ),
        (
            ExtensionResponse {
                block: Some(true),
                abstain: None,
                reason: Some("escape\u{1b}".into()),
            },
            ExtensionValidationError::InvalidReasonControl,
        ),
    ];
    for (response, expected) in cases {
        assert_eq!(
            validate_response(&ctx, &guard, &stream, response),
            Err(expected)
        );
    }
}

#[test]
fn validator_rejects_unsupported_protocol_and_action_stream_rejects_duplicate_ids() {
    let future_protocol = serde_json::from_value(serde_json::json!(2)).unwrap();
    let future_activation = ActivationProjection::new(
        GuardIdentity::user("future").unwrap(),
        ContentHash::new("b".repeat(64)).unwrap(),
        future_protocol,
        vec!["curl".into()],
    )
    .unwrap();
    let ctx = ctx_with(future_activation.clone());
    let stream = action_stream();
    let response = ExtensionResponse {
        block: Some(true),
        abstain: None,
        reason: Some("reason".into()),
    };
    assert_eq!(
        validate_response(&ctx, &future_activation, &stream, response.clone()),
        Err(ExtensionValidationError::UnsupportedExecProtocol)
    );

    let mut duplicate_stream = serde_json::to_value(&stream).unwrap();
    duplicate_stream["effects"][1]["id"] = serde_json::json!("e0");
    assert!(serde_json::from_value::<ActionStream>(duplicate_stream).is_err());

    let mut future_stream = serde_json::to_value(stream).unwrap();
    future_stream["v"] = serde_json::json!(2);
    assert!(
        serde_json::from_value::<ActionStream>(future_stream)
            .unwrap_err()
            .to_string()
            .contains("unsupported-version")
    );
}

fn activation(name: &str) -> ActivationProjection {
    ActivationProjection::new(
        GuardIdentity::user(name).unwrap(),
        ContentHash::new("a".repeat(64)).unwrap(),
        ExecProtocolVersion::V1,
        vec!["curl".into()],
    )
    .unwrap()
}

fn ctx_with(activation: ActivationProjection) -> Ctx {
    Ctx::new(
        SchemaVersion::V1,
        Platform::Linux,
        AbsolutePath::new(Platform::Linux, "/home/test").unwrap(),
        vec![],
        vec![activation],
        TrustProjection::new(vec![]).unwrap(),
        PolicyVersion::V1,
    )
    .unwrap()
}

fn action_stream() -> ActionStream {
    ActionStream::new(
        Coverage::Full,
        vec![vec![
            EffectKind::known("curl", "request").unwrap(),
            EffectKind::network(Some("example.com")),
        ]],
        vec![],
    )
    .unwrap()
}
