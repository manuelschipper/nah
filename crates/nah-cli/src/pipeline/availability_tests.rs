use nah_proto::ctx::{
    AbsolutePath, ActivationProjection, ContentHash, Ctx, ExecProtocolVersion, GuardIdentity,
    Platform, SchemaVersion, TrustProjection,
};
use nah_proto::decision::Verdict;
use nah_proto::extension::{ExtensionResponse, validate_response};
use nah_proto::tool::ToolCallInput;
use serde_json::json;
use std::time::{Duration, Instant};

use super::{
    ConsultedExtensions, EvaluationFailure, EvaluationFailureSource, RecoveryAdvice, decide_with,
    decide_with_extensions, failure_recovery, production_evidence_deadline,
};
use crate::catalog::all_shipped_guard_states_enabled;

// A stalled Git observation must leave custom guards time, and a host without
// a CPU clock must not keep waiting after its short analysis budget expires.
#[test]
fn production_evidence_deadline_bounds_observations_with_time_for_custom_guards() {
    let started = Instant::now();
    for (cpu_clock_available, hook_time_left, wall_budget) in [
        (true, Duration::from_secs(4), Duration::from_secs(2)),
        (true, Duration::from_millis(500), Duration::from_millis(500)),
        (false, Duration::from_secs(4), Duration::from_millis(100)),
        (false, Duration::from_millis(50), Duration::from_millis(50)),
        (true, Duration::ZERO, Duration::ZERO),
        (false, Duration::ZERO, Duration::ZERO),
    ] {
        assert_eq!(
            production_evidence_deadline(started, started + hook_time_left, cpu_clock_available),
            started + wall_budget,
        );
    }
}

#[test]
fn selected_extension_failure_delegates_with_typed_failure() {
    let temp = tempfile::tempdir().unwrap();
    let (ctx, input) = context_and_input(temp.path());

    let result = decide_with_extensions(
        &input,
        &ctx,
        |request| {
            nah_observe::fulfill_with_git_timeout(request, nah_observe::TEST_GIT_TIMEOUT)
                .map_err(|error| error.to_string())
        },
        |_, _| ConsultedExtensions {
            failures: vec![custom_failure("broken", "timeout")],
            ..ConsultedExtensions::default()
        },
    );

    assert_eq!(result.core().verdict(), Verdict::Delegate);
    assert_eq!(result.failures(), [custom_failure("broken", "timeout")]);
}

#[test]
fn shipped_block_skips_custom_guards_without_a_failure() {
    let temp = tempfile::tempdir().unwrap();
    let home = AbsolutePath::new(Platform::Linux, temp.path().to_str().unwrap()).unwrap();
    let ctx = Ctx::new(
        Platform::Linux,
        home.clone(),
        all_shipped_guard_states_enabled(),
        vec![],
        TrustProjection::new(vec![]).unwrap(),
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
        |request| {
            nah_observe::fulfill_with_git_timeout(request, nah_observe::TEST_GIT_TIMEOUT)
                .map_err(|error| error.to_string())
        },
        |_, _| panic!("custom guards cannot tighten a built-in block"),
    );

    assert_eq!(result.core().verdict(), Verdict::Block);
    assert!(result.failures().is_empty());
    assert!(result.consultations().is_empty());
}

#[test]
fn custom_block_survives_another_custom_guard_failure() {
    let temp = tempfile::tempdir().unwrap();
    let home = AbsolutePath::new(Platform::Linux, temp.path().to_str().unwrap()).unwrap();
    let activation = ActivationProjection::new(
        GuardIdentity::user("blocking").unwrap(),
        ContentHash::new("a".repeat(64)).unwrap(),
        ExecProtocolVersion::V2,
        vec!["unknown-tool".into()],
    )
    .unwrap();
    let ctx = Ctx::new(
        Platform::Linux,
        home.clone(),
        vec![],
        vec![activation.clone()],
        TrustProjection::new(vec![]).unwrap(),
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
        |request| {
            nah_observe::fulfill_with_git_timeout(request, nah_observe::TEST_GIT_TIMEOUT)
                .map_err(|error| error.to_string())
        },
        |_, _| {
            let response = validate_response(
                &ctx,
                &activation,
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
        |request| {
            nah_observe::fulfill_with_git_timeout(request, nah_observe::TEST_GIT_TIMEOUT)
                .map_err(|error| error.to_string())
        },
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

    // Source effects established before observation fails remain actionable,
    // even though the input does not match the no-plan shell screen.
    let home = ctx.home().clone();
    let ctx = Ctx::new(
        ctx.platform(),
        home.clone(),
        crate::catalog::shipped_guard_states(),
        vec![],
        TrustProjection::new(vec![]).unwrap(),
    )
    .unwrap();
    let input = ToolCallInput::new(
        SchemaVersion::V1,
        "Bash",
        json!({"command": format!("python3 -c 'import shutil; shutil.rmtree(\"{}\")'", home.as_str())}),
        input.cwd(),
        None,
    )
    .unwrap();
    let result = decide_with(&input, &ctx, |_| Err("observer offline".into()));
    assert_eq!(
        result.core().verdict(),
        Verdict::Block,
        "{:?}",
        result.effinterp().map(|analysis| &analysis.plan().effects)
    );
    assert!(result.evaluation_failed());
    assert!(result.effinterp().is_some());
    assert!(result.core().policy_attributions().is_empty());
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
        ExecProtocolVersion::V2,
        vec!["unknown-tool".into()],
    )
    .unwrap();
    let ctx = Ctx::new(
        Platform::Linux,
        home.clone(),
        vec![],
        vec![activation.clone()],
        TrustProjection::new(vec![]).unwrap(),
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
        |request| {
            nah_observe::fulfill_with_git_timeout(request, nah_observe::TEST_GIT_TIMEOUT)
                .map_err(|error| error.to_string())
        },
        |_, _| {
            let response = validate_response(
                &ctx,
                &activation,
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
        Platform::Linux,
        home.clone(),
        vec![],
        vec![],
        TrustProjection::new(vec![]).unwrap(),
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

#[test]
fn late_observation_deadline_preserves_completed_guard_exemptions() {
    for (command, expected) in [
        ("wc -l .env", Verdict::Delegate),
        ("cp .env .env.bak", Verdict::Delegate),
        ("docker compose --env-file .env up -d", Verdict::Delegate),
        ("cat .env", Verdict::Block),
    ] {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join(".env"), "A=1\n").unwrap();
        let home = AbsolutePath::new(Platform::Linux, temp.path().to_str().unwrap()).unwrap();
        let ctx = Ctx::new(
            Platform::Linux,
            home.clone(),
            crate::catalog::shipped_guard_states(),
            vec![],
            TrustProjection::new(vec![]).unwrap(),
        )
        .unwrap();
        let input = ToolCallInput::new(
            SchemaVersion::V1,
            "Bash",
            json!({"command":command}),
            home.as_str(),
            None,
        )
        .unwrap();
        let healthy = decide_with(&input, &ctx, |request| {
            nah_observe::fulfill_with_git_timeout(request, nah_observe::TEST_GIT_TIMEOUT)
                .map_err(|error| error.to_string())
        });
        let deadline = nah_effinterp::InvocationDeadline::after(Duration::from_secs(30));
        let expire = deadline.clone();
        let late = super::decide_with_evidence_budget(
            &input,
            None,
            &ctx,
            &nah_proto::runtime_protection::SelfProtectionProjection::default(),
            nah_policy::EnforcementMode::Normal,
            nah_effinterp::EvidenceBudget::with_deadline(deadline),
            None,
            move |request| {
                expire.expire();
                nah_observe::fulfill_with_git_timeout(request, nah_observe::TEST_GIT_TIMEOUT)
                    .map_err(|error| error.to_string())
            },
            |_, _, _| ConsultedExtensions::default(),
        );
        assert_eq!(healthy.core().verdict(), expected, "{command}");
        assert_eq!(late.core().verdict(), expected, "{command}");
        assert!(
            late.guard_evidence().is_some(),
            "guards must have run: {command}"
        );
        assert!(
            late.refusals()
                .iter()
                .any(|refusal| refusal.code() == "deadline-exceeded")
        );
        assert!(late.evaluation_failed());
        if command == "docker compose --env-file .env up -d" {
            // Exhaustion in another guard cannot revoke secrets-env's exemption.
            let mut work_limited = late;
            work_limited.refusals = vec![super::AnalysisRefusal::new(
                "shipped-guards",
                "guard-work-limit",
                RecoveryAdvice::CorrectOrSimplify,
            )];
            if let Some(Ok(evidence)) = work_limited.guard_evidence.as_mut() {
                evidence.refuse_evaluation("shipped-guards", "guard-work-limit");
            }
            super::failure_suspicion::block_suspicious_failure(
                &mut work_limited,
                &input,
                &ctx,
                nah_policy::EnforcementMode::Normal,
                Some(&["fs-home"]),
            );
            assert_eq!(work_limited.core().verdict(), Verdict::Delegate);
            super::failure_suspicion::block_suspicious_failure(
                &mut work_limited,
                &input,
                &ctx,
                nah_policy::EnforcementMode::Normal,
                Some(&["secrets-env"]),
            );
            assert_eq!(work_limited.core().verdict(), Verdict::Block);
        }
    }
}
