use nah_proto::ctx::{AbsolutePath, Ctx, Platform, SchemaVersion};
use nah_proto::decision::Verdict;
use nah_proto::tool::ToolCallInput;
use serde_json::json;
use std::time::{Duration, Instant};

use super::{
    EvaluationFailure, RecoveryAdvice, decide_with, failure_recovery, production_evidence_deadline,
};

// A stalled Git observation must leave the hook time to answer, and a host
// without a CPU clock must not keep waiting after its short analysis budget
// expires.
#[test]
fn production_evidence_deadline_bounds_observations_inside_the_hook_budget() {
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
        nah_proto::ctx::GuardSettings::default(),
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
fn recovery_categories_are_fixed_and_severity_ordered() {
    assert_eq!(
        failure_recovery(&EvaluationFailure::nah("observation", "failed")),
        RecoveryAdvice::RetryOnce
    );
    assert_eq!(
        failure_recovery(&EvaluationFailure::nah("effinterp", "failed")),
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
        nah_proto::ctx::GuardSettings::every_guard_at(nah_proto::ctx::GuardLevel::Off),
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
            nah_proto::ctx::GuardSettings::default(),
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
            false,
            nah_effinterp::EvidenceBudget::with_deadline(deadline),
            None,
            crate::save_then_run::SaveMode::Unavailable,
            move |request| {
                expire.expire();
                nah_observe::fulfill_with_git_timeout(request, nah_observe::TEST_GIT_TIMEOUT)
                    .map_err(|error| error.to_string())
            },
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
                Some(&["machine/outside-workspace-delete"]),
            );
            assert_eq!(work_limited.core().verdict(), Verdict::Delegate);
            super::failure_suspicion::block_suspicious_failure(
                &mut work_limited,
                &input,
                &ctx,
                nah_policy::EnforcementMode::Normal,
                Some(&["secrets/env-files-read"]),
            );
            assert_eq!(work_limited.core().verdict(), Verdict::Block);
        }
    }
}
