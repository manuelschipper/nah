#![allow(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types
)]

use crate::support;

use std::process::Command;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use nah_cli::{DecisionResult, decide_with};
use nah_proto::action::Coverage;
use nah_proto::ctx::Ctx;
use nah_proto::decision::Verdict;
use nah_proto::observation::Observation;
use nah_proto::tool::ToolCallInput;
use serde_json::json;
use support::{call, ctx, repo};

const SAMPLES: usize = 10_000;

fn serialize_kpi_test() -> MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Decides `input` against the live filesystem and records every observation
/// the engine requested, in order. The engine re-plans after binding the
/// environment, so one decision can need several observation rounds.
fn capture(input: &ToolCallInput, context: &Ctx) -> (DecisionResult, Vec<Observation>) {
    let mut captured = Vec::new();
    let result = decide_with(input, context, |request| {
        let observation = support::fulfill_observation(request)?;
        captured.push(observation.clone());
        Ok(observation)
    });
    (result, captured)
}

/// Decides `input` answering the engine's observation rounds from `captured`
/// in order, and requires the decision to consume all of them.
fn replay(input: &ToolCallInput, context: &Ctx, captured: &[Observation]) -> DecisionResult {
    let mut observations = captured.iter();
    let result = decide_with(input, context, |_| {
        observations
            .next()
            .cloned()
            .ok_or_else(|| "unexpected observation round".to_owned())
    });
    assert!(observations.next().is_none(), "unused observation round");
    result
}

/// Times `SAMPLES` replayed decisions; `check` asserts each one's verdict so a
/// wrong replay is never timed as a fast decision.
fn replay_percentiles(
    input: &ToolCallInput,
    context: &Ctx,
    captured: &[Observation],
    check: impl Fn(&DecisionResult),
) -> (Duration, Duration) {
    let mut samples = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let started = Instant::now();
        let result = replay(input, context, captured);
        samples.push(started.elapsed());
        check(&result);
    }
    samples.sort_unstable();
    (
        samples[(samples.len() * 50) / 100],
        samples[(samples.len() * 99) / 100],
    )
}

/// An unoptimized build runs these tests an order of magnitude slower; CI
/// runs them optimized, where `release` applies.
fn budget(release: Duration) -> Duration {
    if cfg!(debug_assertions) {
        release * 10
    } else {
        release
    }
}

#[test]
#[ignore = "release-mode KPI; the CI Release KPIs step runs it"]
fn captured_read_p99_is_within_budget() {
    let _serial = serialize_kpi_test();
    let temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah resolves
    // paths before matching them
    let root = support::test_temp_path(temp.path());
    let repo = repo(&root);
    let context = ctx(&root);
    let input = call("Read", json!({"file_path":"src/lib.rs"}), &repo);
    let (first, captured) = capture(&input, &context);
    assert_eq!(first.core().verdict(), Verdict::Delegate);
    // A file Read depends on no environment variable, so the engine's first
    // plan is final and one evidence observation answers it.
    assert_eq!(captured.len(), 1);

    let (p50, p99) = replay_percentiles(&input, &context, &captured, |result| {
        assert_eq!(result.core().verdict(), Verdict::Delegate);
    });
    println!("captured Read p50 {p50:?}, p99 {p99:?}");
    // Measured p99 0.65–1.0 ms on an 8-core Linux VPS, 2026-09-29.
    let limit = budget(Duration::from_micros(2_500));
    assert!(p99 <= limit, "captured Read p99 {p99:?} exceeds {limit:?}");
}

#[test]
#[ignore = "release-mode KPI; the CI Release KPIs step runs it"]
fn captured_bash_pipeline_p99_is_within_budget() {
    let _serial = serialize_kpi_test();
    let temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah resolves
    // paths before matching them
    let root = support::test_temp_path(temp.path());
    let repo = repo(&root);
    let context = ctx(&root);
    let input = call("Bash", json!({"command":"echo hello | cat"}), &repo);
    let (first, captured) = capture(&input, &context);
    assert_eq!(first.core().verdict(), Verdict::Delegate);
    assert_eq!(first.core().coverage(), Coverage::Full);
    // The pipeline depends on no environment variable, so the engine's first
    // plan is final and one evidence observation answers it.
    assert_eq!(captured.len(), 1);

    let (p50, p99) = replay_percentiles(&input, &context, &captured, |result| {
        assert_eq!(result.core().verdict(), Verdict::Delegate);
        assert_eq!(result.core().coverage(), Coverage::Full);
    });
    println!("captured Bash pipeline p50 {p50:?}, p99 {p99:?}");
    // Measured p99 0.87–1.1 ms on an 8-core Linux VPS, 2026-09-29.
    let limit = budget(Duration::from_millis(3));
    assert!(
        p99 <= limit,
        "captured Bash pipeline p99 {p99:?} exceeds {limit:?}"
    );
}

#[test]
#[ignore = "release-mode KPI; the CI Release KPIs step runs it"]
fn captured_ambient_preflight_p99_is_within_budget() {
    let _serial = serialize_kpi_test();
    let temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah resolves
    // paths before matching them
    let root = support::test_temp_path(temp.path());
    let repo = repo(&root);
    let context = ctx(&root);
    let input = call("Bash", json!({"command":"echo \"$PATH\""}), &repo);
    let (first, captured) = capture(&input, &context);
    assert_eq!(first.core().verdict(), Verdict::Delegate);
    assert_eq!(first.core().coverage(), Coverage::Full);
    // The command expands `$PATH`: the engine observes it, re-plans with it
    // bound, observes it again to confirm the re-planned host still holds,
    // then makes the evidence observation.
    assert_eq!(captured.len(), 3);

    let (p50, p99) = replay_percentiles(&input, &context, &captured, |result| {
        assert_eq!(result.core().verdict(), Verdict::Delegate);
        assert_eq!(result.core().coverage(), Coverage::Full);
    });
    println!("captured ambient preflight p50 {p50:?}, p99 {p99:?}");
    // Measured p99 0.81–1.2 ms on an 8-core Linux VPS, 2026-09-29.
    let limit = budget(Duration::from_millis(3));
    assert!(
        p99 <= limit,
        "captured ambient preflight p99 {p99:?} exceeds {limit:?}"
    );
}

#[test]
#[ignore = "release-mode KPI; the CI Release KPIs step runs it"]
fn captured_python_rmtree_p99_is_within_budget() {
    let _serial = serialize_kpi_test();
    let temp = tempfile::tempdir().unwrap();
    let root = support::test_temp_path(temp.path());
    let repo = repo(&root);
    let context = ctx(&root);
    let input = call(
        "Bash",
        json!({"command": "python3 -c \"import shutil; shutil.rmtree('/')\""}),
        &repo,
    );
    let (first, captured) = capture(&input, &context);
    assert_eq!(first.core().verdict(), Verdict::Block);
    // Python's startup depends on PYTHONPATH and related variables: the
    // engine observes them, re-plans with them bound, observes them again to
    // confirm the re-planned host still holds, then makes the evidence
    // observation.
    assert_eq!(captured.len(), 3);

    let (p50, p99) = replay_percentiles(&input, &context, &captured, |result| {
        assert_eq!(result.core().verdict(), Verdict::Block);
    });
    println!("captured Python rmtree p50 {p50:?}, p99 {p99:?}");
    // Measured p99 3.2–4.1 ms on an 8-core Linux VPS, 2026-09-29.
    let limit = budget(Duration::from_millis(10));
    assert!(
        p99 <= limit,
        "captured Python rmtree p99 {p99:?} exceeds {limit:?}"
    );
}

#[test]
#[ignore = "release-mode KPI; the CI Release KPIs step runs it"]
fn captured_git_force_push_p99_is_within_budget() {
    let _serial = serialize_kpi_test();
    let temp = tempfile::tempdir().unwrap();
    let root = support::test_temp_path(temp.path());
    let repo = repo(&root);
    let context = ctx(&root);
    let input = call(
        "Bash",
        json!({"command": "git push --force origin main"}),
        &repo,
    );
    let (first, captured) = capture(&input, &context);
    assert_eq!(first.core().verdict(), Verdict::Block);
    assert!(
        first
            .evidence_provenance()
            .unwrap()
            .producer
            .starts_with("effinterp/")
    );
    // The push depends on no environment variable, so the engine's first
    // plan is final and one evidence observation answers it.
    assert_eq!(captured.len(), 1);

    let (p50, p99) = replay_percentiles(&input, &context, &captured, |result| {
        assert_eq!(result.core().verdict(), Verdict::Block);
    });
    println!("captured Git force-push p50 {p50:?}, p99 {p99:?}");
    // Measured p99 1.5–1.9 ms on an 8-core Linux VPS, 2026-09-29.
    let limit = budget(Duration::from_millis(4));
    assert!(
        p99 <= limit,
        "captured Git force-push p99 {p99:?} exceeds {limit:?}"
    );
}

#[test]
#[ignore = "release-mode KPI; the CI Release KPIs step runs it"]
fn a_cold_captured_git_force_push_decision_is_within_budget() {
    const CAPTURE_PATH: &str = "NAH_COLD_KPI_CAPTURE_PATH";
    const CAPTURE_ROOT: &str = "NAH_COLD_KPI_CAPTURE_ROOT";
    const TEST_NAME: &str = "latency::a_cold_captured_git_force_push_decision_is_within_budget";

    let _serial = serialize_kpi_test();
    let mut temp = None;
    let root = match std::env::var_os(CAPTURE_ROOT) {
        Some(root) => root.into(),
        None => {
            let directory = tempfile::tempdir().unwrap();
            let root = support::test_temp_path(directory.path());
            repo(&root);
            temp = Some(directory);
            root
        }
    };
    let repo = root.join("repo");
    let context = ctx(&root);
    let input = call(
        "Bash",
        json!({"command": "git push --force origin main"}),
        &repo,
    );

    // The capture runs in a child process so this process's replay is its
    // first decision.
    if let Some(path) = std::env::var_os(CAPTURE_PATH) {
        let (result, captured) = capture(&input, &context);
        assert_eq!(result.core().verdict(), Verdict::Block);
        std::fs::write(path, serde_json::to_vec(&captured).unwrap()).unwrap();
        return;
    }

    let capture_path = root.join("cold-git-force-push-observations.json");
    let output = Command::new(std::env::current_exe().unwrap())
        .arg(TEST_NAME)
        .arg("--exact")
        .arg("--ignored")
        .arg("--test-threads=1")
        .env(CAPTURE_PATH, &capture_path)
        .env(CAPTURE_ROOT, &root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "observation capture failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let captured: Vec<Observation> =
        serde_json::from_slice(&std::fs::read(capture_path).unwrap()).unwrap();
    // The push depends on no environment variable, so the engine's first
    // plan is final and one evidence observation answers it.
    assert_eq!(captured.len(), 1);

    let started = Instant::now();
    let result = replay(&input, &context, &captured);
    let elapsed = started.elapsed();
    assert_eq!(result.core().verdict(), Verdict::Block);
    assert!(
        result
            .evidence_provenance()
            .unwrap()
            .producer
            .starts_with("effinterp/")
    );
    println!("cold captured Git force-push decision {elapsed:?}");
    // A fresh process pays for loading the engine catalog before its first
    // decision, so its budget is separate from the warm p99 budget.
    // Measured 2.6–5.7 ms on an 8-core Linux VPS, 2026-09-29.
    let limit = budget(Duration::from_millis(10));
    assert!(
        elapsed <= limit,
        "cold captured Git force-push decision {elapsed:?} exceeds {limit:?}"
    );

    drop(temp);
}
