use nah_proto::ctx::{
    AbsolutePath, ActivationProjection, ContentHash, Ctx, ExecProtocolVersion, GuardIdentity,
    Platform, SchemaVersion, TrustProjection,
};
use nah_proto::decision::Verdict;
use nah_proto::extension::{ExtensionResponse, validate_response};
use nah_proto::tool::ToolCallInput;
use serde_json::json;

use super::{
    ConsultedExtensions, EvaluationFailure, EvaluationFailureSource, RecoveryAdvice, decide_with,
    decide_with_extensions, decide_with_extensions_mode, failure_recovery,
};
use crate::catalog::{POLICY_VERSION, all_shipped_guard_states_enabled};

#[test]
fn selected_extension_failure_delegates_with_typed_failure() {
    let temp = tempfile::tempdir().unwrap();
    let (ctx, input) = context_and_input(temp.path());

    let result = decide_with_extensions(
        &input,
        &ctx,
        |request| nah_observe::fulfill(request).map_err(|error| error.to_string()),
        |_, _| ConsultedExtensions {
            failures: vec![custom_failure("broken", "timeout")],
            ..ConsultedExtensions::default()
        },
    );

    assert_eq!(result.core().verdict(), Verdict::Delegate);
    assert_eq!(result.failures(), [custom_failure("broken", "timeout")]);
}

#[test]
fn shipped_block_survives_a_custom_guard_failure() {
    let temp = tempfile::tempdir().unwrap();
    let home = AbsolutePath::new(Platform::Linux, temp.path().to_str().unwrap()).unwrap();
    let ctx = Ctx::new(
        SchemaVersion::V1,
        Platform::Linux,
        home.clone(),
        all_shipped_guard_states_enabled(),
        vec![],
        TrustProjection::new(vec![]).unwrap(),
        POLICY_VERSION,
    )
    .unwrap();
    let input = ToolCallInput::new(
        SchemaVersion::V1,
        "Bash",
        json!({"command":"rm -rf /etc"}),
        home.as_str(),
        None,
    )
    .unwrap();

    let result = decide_with_extensions(
        &input,
        &ctx,
        |request| nah_observe::fulfill(request).map_err(|error| error.to_string()),
        |_, _| ConsultedExtensions {
            failures: vec![custom_failure("broken", "crash")],
            ..ConsultedExtensions::default()
        },
    );

    assert_eq!(result.core().verdict(), Verdict::Block);
    assert_eq!(result.failures(), [custom_failure("broken", "crash")]);
}

#[test]
fn custom_block_survives_another_custom_guard_failure() {
    let temp = tempfile::tempdir().unwrap();
    let home = AbsolutePath::new(Platform::Linux, temp.path().to_str().unwrap()).unwrap();
    let activation = ActivationProjection::new(
        GuardIdentity::user("blocking").unwrap(),
        ContentHash::new("a".repeat(64)).unwrap(),
        ExecProtocolVersion::V1,
        vec!["unknown-tool".into()],
    )
    .unwrap();
    let ctx = Ctx::new(
        SchemaVersion::V1,
        Platform::Linux,
        home.clone(),
        vec![],
        vec![activation.clone()],
        TrustProjection::new(vec![]).unwrap(),
        POLICY_VERSION,
    )
    .unwrap();
    let input = ToolCallInput::new(
        SchemaVersion::V1,
        "Bash",
        json!({"command":"unknown-tool"}),
        home.as_str(),
        None,
    )
    .unwrap();

    let result = decide_with_extensions(
        &input,
        &ctx,
        |request| nah_observe::fulfill(request).map_err(|error| error.to_string()),
        |_, stream| {
            let response = validate_response(
                &ctx,
                &activation,
                stream,
                ExtensionResponse {
                    block: Some(true),
                    abstain: None,
                    reason: Some("blocked by custom guard".into()),
                },
            )
            .unwrap();
            ConsultedExtensions {
                responses: vec![response],
                failures: vec![custom_failure("broken", "timeout")],
                ..ConsultedExtensions::default()
            }
        },
    );

    assert_eq!(result.core().verdict(), Verdict::Block);
    assert_eq!(result.failures(), [custom_failure("broken", "timeout")]);
    assert_eq!(result.core().policy_attributions()[0].name(), "blocking");
}

#[test]
fn healthy_abstention_path_remains_available_to_delegate() {
    let temp = tempfile::tempdir().unwrap();
    let (ctx, input) = context_and_input(temp.path());

    let result = decide_with_extensions(
        &input,
        &ctx,
        |request| nah_observe::fulfill(request).map_err(|error| error.to_string()),
        |_, _| ConsultedExtensions::default(),
    );

    assert_eq!(result.core().verdict(), Verdict::Delegate);
    assert!(result.failures().is_empty());
}

#[test]
fn observation_failure_delegates_with_typed_failure() {
    let temp = tempfile::tempdir().unwrap();
    let (ctx, input) = context_and_input(temp.path());

    let result = decide_with(&input, &ctx, |_| Err("observer offline".into()));

    assert_eq!(result.core().verdict(), Verdict::Delegate);
    assert_eq!(result.failures()[0].component(), "observation");
    assert_eq!(result.failures()[0].code(), "failed");
    assert!(result.observation().is_none());
}

#[test]
fn inline_analyzer_failure_during_all_nap_delegates_with_typed_failure() {
    let temp = tempfile::tempdir().unwrap();
    let (ctx, _) = context_and_input(temp.path());
    let input = ToolCallInput::new(
        SchemaVersion::V1,
        "Bash",
        json!({"command": r#"python3 -c "print('inline')""#}),
        temp.path().to_str().unwrap(),
        None,
    )
    .unwrap();

    let result = decide_with_extensions_mode(
        &input,
        None,
        &ctx,
        &nah_actions::SelfProtectionProjection::default(),
        nah_policy::EnforcementMode::AllPaused,
        |request| nah_observe::fulfill(request).map_err(|error| error.to_string()),
        |_, _| panic!("all-nap calls must not consult extensions"),
        true,
    );

    assert_eq!(result.core().verdict(), Verdict::Delegate);
    assert_eq!(
        result.failures(),
        [EvaluationFailure::nah("inline-analysis", "failed")]
    );
}

#[test]
fn shipped_effect_block_survives_an_inline_analyzer_failure() {
    let temp = tempfile::tempdir().unwrap();
    let home = AbsolutePath::new(Platform::Linux, temp.path().to_str().unwrap()).unwrap();
    let ctx = Ctx::new(
        SchemaVersion::V1,
        Platform::Linux,
        home.clone(),
        all_shipped_guard_states_enabled(),
        vec![],
        TrustProjection::new(vec![]).unwrap(),
        POLICY_VERSION,
    )
    .unwrap();
    let input = ToolCallInput::new(
        SchemaVersion::V1,
        "Bash",
        json!({"command": "rm -rf /etc; python3 -c 'print(1)'"}),
        home.as_str(),
        None,
    )
    .unwrap();

    let result = decide_with_extensions_mode(
        &input,
        None,
        &ctx,
        &nah_actions::SelfProtectionProjection::default(),
        nah_policy::EnforcementMode::Normal,
        |request| nah_observe::fulfill(request).map_err(|error| error.to_string()),
        |_, _| ConsultedExtensions::default(),
        true,
    );

    assert_eq!(
        result.core().verdict(),
        Verdict::Block,
        "{:#?}",
        result.action_stream()
    );
    assert_eq!(
        result.failures(),
        [EvaluationFailure::nah("inline-analysis", "failed")]
    );
}

#[test]
fn malformed_pre_policy_inputs_delegate_without_health_failures() {
    let temp = tempfile::tempdir().unwrap();
    let (ctx, _) = context_and_input(temp.path());
    let relative = ToolCallInput::new(
        SchemaVersion::V1,
        "Bash",
        json!({"command":"rm -rf /"}),
        "relative",
        None,
    )
    .unwrap();
    let malformed = ToolCallInput::new(
        SchemaVersion::V1,
        "Bash",
        json!({}),
        temp.path().to_str().unwrap(),
        None,
    )
    .unwrap();

    for input in [relative, malformed] {
        let result = decide_with(&input, &ctx, |_| {
            unreachable!("invalid input must stop before observation")
        });
        assert_eq!(result.core().verdict(), Verdict::Delegate);
        assert!(result.failures().is_empty());
        assert!(result.observation().is_none());
    }
}

#[test]
fn policy_reducer_failure_delegates_with_typed_failure() {
    let temp = tempfile::tempdir().unwrap();
    let home = AbsolutePath::new(Platform::Linux, temp.path().to_str().unwrap()).unwrap();
    let activation = ActivationProjection::new(
        GuardIdentity::user("duplicate").unwrap(),
        ContentHash::new("a".repeat(64)).unwrap(),
        ExecProtocolVersion::V1,
        vec!["unknown-tool".into()],
    )
    .unwrap();
    let ctx = Ctx::new(
        SchemaVersion::V1,
        Platform::Linux,
        home.clone(),
        vec![],
        vec![activation.clone()],
        TrustProjection::new(vec![]).unwrap(),
        POLICY_VERSION,
    )
    .unwrap();
    let input = ToolCallInput::new(
        SchemaVersion::V1,
        "Bash",
        json!({"command":"unknown-tool"}),
        home.as_str(),
        None,
    )
    .unwrap();

    let result = decide_with_extensions(
        &input,
        &ctx,
        |request| nah_observe::fulfill(request).map_err(|error| error.to_string()),
        |_, stream| {
            let response = validate_response(
                &ctx,
                &activation,
                stream,
                ExtensionResponse {
                    block: Some(true),
                    abstain: None,
                    reason: Some("duplicate".into()),
                },
            )
            .unwrap();
            ConsultedExtensions {
                responses: vec![response.clone(), response],
                ..ConsultedExtensions::default()
            }
        },
    );

    assert_eq!(result.core().verdict(), Verdict::Delegate);
    assert_eq!(result.failures()[0].component(), "shipped-policy");
    assert_eq!(result.failures()[0].code(), "failed");
}

fn custom_failure(component: &str, code: &str) -> EvaluationFailure {
    EvaluationFailure {
        source: EvaluationFailureSource::CustomGuard,
        component: component.to_owned(),
        code: code.to_owned(),
    }
}

#[test]
fn recovery_categories_are_fixed_and_severity_ordered() {
    assert_eq!(
        failure_recovery(&custom_failure("guard", "timeout")),
        RecoveryAdvice::RetryOnce
    );
    assert_eq!(
        failure_recovery(&custom_failure("guard", "silence")),
        RecoveryAdvice::OperatorRequired
    );
    assert!(RecoveryAdvice::OperatorRequired > RecoveryAdvice::CorrectOrSimplify);
    assert!(RecoveryAdvice::CorrectOrSimplify > RecoveryAdvice::RetryOnce);
    for advice in [
        RecoveryAdvice::RetryOnce,
        RecoveryAdvice::CorrectOrSimplify,
        RecoveryAdvice::OperatorRequired,
    ] {
        let message = advice.message();
        assert!(!message.contains("stderr"));
        assert!(!message.contains("cache"));
        assert!(!message.contains("retry until"));
    }
}

fn context_and_input(path: &std::path::Path) -> (Ctx, ToolCallInput) {
    let home = AbsolutePath::new(Platform::Linux, path.to_str().unwrap()).unwrap();
    let ctx = Ctx::new(
        SchemaVersion::V1,
        Platform::Linux,
        home.clone(),
        vec![],
        vec![],
        TrustProjection::new(vec![]).unwrap(),
        POLICY_VERSION,
    )
    .unwrap();
    let input = ToolCallInput::new(
        SchemaVersion::V1,
        "Bash",
        json!({"command":"unknown-tool"}),
        home.as_str(),
        None,
    )
    .unwrap();
    (ctx, input)
}
