#![allow(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types
)]

use crate::support;

use std::process::Command;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use nah_cli::decide_with;
use nah_proto::action::Coverage;
use nah_proto::decision::Verdict;
use serde_json::json;
use support::{call, ctx, repo};

fn serialize_kpi_test() -> MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[test]
#[ignore = "release-mode KPI; the CI Release KPIs step runs it"]
fn captured_read_p99_is_below_one_millisecond() {
    let _serial = serialize_kpi_test();
    let temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah resolves
    // paths before matching them
    let root = support::test_temp_path(temp.path());
    let repo = repo(&root);
    let context = ctx(&root);
    let input = call("Read", json!({"file_path":"src/lib.rs"}), &repo);
    let mut captured = None;
    let first = decide_with(&input, &context, |request| {
        let observation = support::fulfill_observation(request)?;
        captured = Some(observation.clone());
        Ok(observation)
    });
    assert_eq!(first.core().verdict(), Verdict::Delegate);
    let observation = captured.unwrap();

    let mut samples = Vec::with_capacity(10_000);
    for _ in 0..10_000 {
        let started = Instant::now();
        let result = decide_with(&input, &context, |_| Ok(observation.clone()));
        assert_eq!(result.core().verdict(), Verdict::Delegate);
        samples.push(started.elapsed());
    }
    samples.sort_unstable();
    let p99 = samples[(samples.len() * 99) / 100];
    println!("captured Read p99 {p99:?}");
    // The workspace's normal debug test run gets scheduler/allocator slack;
    // CI also runs this exact test optimized, where the product budget applies.
    let limit = if cfg!(debug_assertions) {
        Duration::from_millis(10)
    } else {
        Duration::from_millis(1)
    };
    assert!(p99 <= limit, "captured Read p99 {p99:?} exceeds {limit:?}");
}

#[test]
#[ignore = "release-mode KPI; the CI Release KPIs step runs it"]
fn captured_bash_pipeline_p99_is_below_one_millisecond() {
    let _serial = serialize_kpi_test();
    let temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah resolves
    // paths before matching them
    let root = support::test_temp_path(temp.path());
    let repo = repo(&root);
    let context = ctx(&root);
    let input = call("Bash", json!({"command":"echo hello | cat"}), &repo);
    let mut captured = None;
    let first = decide_with(&input, &context, |request| {
        let observation = support::fulfill_observation(request)?;
        captured = Some(observation.clone());
        Ok(observation)
    });
    assert_eq!(first.core().verdict(), Verdict::Delegate);
    assert_eq!(first.core().coverage(), Coverage::Full);
    let observation = captured.unwrap();

    let mut samples = Vec::with_capacity(10_000);
    for _ in 0..10_000 {
        let started = Instant::now();
        let result = decide_with(&input, &context, |_| Ok(observation.clone()));
        assert_eq!(result.core().coverage(), Coverage::Full);
        samples.push(started.elapsed());
    }
    samples.sort_unstable();
    let p99 = samples[(samples.len() * 99) / 100];
    println!("captured Bash pipeline p99 {p99:?}");
    let limit = if cfg!(debug_assertions) {
        Duration::from_millis(10)
    } else {
        Duration::from_millis(1)
    };
    assert!(
        p99 <= limit,
        "captured Bash pipeline p99 {p99:?} exceeds {limit:?}"
    );
}

#[test]
#[ignore = "release-mode KPI; the CI Release KPIs step runs it"]
fn captured_ambient_preflight_p99_is_below_one_millisecond() {
    let _serial = serialize_kpi_test();
    let temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah resolves
    // paths before matching them
    let root = support::test_temp_path(temp.path());
    let repo = repo(&root);
    let context = ctx(&root);
    let input = call("Bash", json!({"command":"echo \"$PATH\""}), &repo);
    let mut captured = Vec::new();
    let first = decide_with(&input, &context, |request| {
        let observation = support::fulfill_observation(request)?;
        captured.push(observation.clone());
        Ok(observation)
    });
    assert_eq!(first.core().verdict(), Verdict::Delegate);
    assert_eq!(first.core().coverage(), Coverage::Full);
    assert_eq!(captured.len(), 2, "stable ambient input must observe twice");

    let mut samples = Vec::with_capacity(10_000);
    for _ in 0..10_000 {
        let mut observations = captured.iter();
        let started = Instant::now();
        let result = decide_with(&input, &context, |_| {
            observations
                .next()
                .cloned()
                .ok_or_else(|| "unexpected observation round".to_owned())
        });
        assert!(observations.next().is_none());
        assert_eq!(result.core().verdict(), Verdict::Delegate);
        assert_eq!(result.core().coverage(), Coverage::Full);
        samples.push(started.elapsed());
    }
    samples.sort_unstable();
    let p50 = samples[(samples.len() * 50) / 100];
    let p99 = samples[(samples.len() * 99) / 100];
    println!("captured ambient preflight p50 {p50:?}, p99 {p99:?}");
    let limit = if cfg!(debug_assertions) {
        Duration::from_millis(10)
    } else {
        Duration::from_millis(1)
    };
    assert!(
        p99 <= limit,
        "captured ambient preflight p99 {p99:?} exceeds {limit:?}"
    );
}

#[test]
#[ignore = "release-mode KPI; the CI Release KPIs step runs it"]
fn captured_python_rmtree_p99_is_below_one_millisecond() {
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
    let mut captured = None;
    let first = decide_with(&input, &context, |request| {
        let observation = support::fulfill_observation(request)?;
        captured = Some(observation.clone());
        Ok(observation)
    });
    assert_eq!(first.core().verdict(), Verdict::Block);
    let observation = captured.unwrap();

    let mut samples = Vec::with_capacity(10_000);
    for _ in 0..10_000 {
        let started = Instant::now();
        let result = decide_with(&input, &context, |_| Ok(observation.clone()));
        assert_eq!(result.core().verdict(), Verdict::Block);
        samples.push(started.elapsed());
    }
    samples.sort_unstable();
    let p50 = samples[(samples.len() * 50) / 100];
    let p99 = samples[(samples.len() * 99) / 100];
    println!("captured Python rmtree p50 {p50:?}, p99 {p99:?}");
    let limit = if cfg!(debug_assertions) {
        Duration::from_millis(10)
    } else {
        Duration::from_millis(1)
    };
    assert!(
        p99 <= limit,
        "captured Python rmtree p99 {p99:?} exceeds {limit:?}"
    );
}

#[test]
#[ignore = "release-mode KPI; the CI Release KPIs step runs it"]
fn captured_git_force_push_p99_is_below_one_millisecond() {
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
    let mut captured = Vec::new();
    let first = decide_with(&input, &context, |request| {
        let observation = support::fulfill_observation(request)?;
        captured.push(observation.clone());
        Ok(observation)
    });
    assert_eq!(first.core().verdict(), Verdict::Block);
    assert!(
        first
            .evidence_provenance()
            .unwrap()
            .producer
            .starts_with("effinterp/")
    );

    let mut samples = Vec::with_capacity(10_000);
    for _ in 0..10_000 {
        let mut observations = captured.iter();
        let started = Instant::now();
        let result = decide_with(&input, &context, |_| {
            observations
                .next()
                .cloned()
                .ok_or_else(|| "unexpected observation round".to_owned())
        });
        assert!(observations.next().is_none());
        assert_eq!(result.core().verdict(), Verdict::Block);
        samples.push(started.elapsed());
    }
    samples.sort_unstable();
    let p50 = samples[(samples.len() * 50) / 100];
    let p99 = samples[(samples.len() * 99) / 100];
    println!("captured Git force-push p50 {p50:?}, p99 {p99:?}");
    let limit = if cfg!(debug_assertions) {
        Duration::from_millis(10)
    } else {
        Duration::from_millis(1)
    };
    assert!(
        p99 <= limit,
        "captured Git force-push p99 {p99:?} exceeds {limit:?}"
    );
}

#[test]
#[ignore = "release-mode KPI; the CI Release KPIs step runs it"]
fn a_cold_captured_git_force_push_decision_is_below_two_milliseconds() {
    const CAPTURE_PATH: &str = "NAH_COLD_KPI_CAPTURE_PATH";
    const CAPTURE_ROOT: &str = "NAH_COLD_KPI_CAPTURE_ROOT";
    const TEST_NAME: &str =
        "latency::a_cold_captured_git_force_push_decision_is_below_two_milliseconds";

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

    if let Some(path) = std::env::var_os(CAPTURE_PATH) {
        let mut captured = Vec::new();
        let result = decide_with(&input, &context, |request| {
            let observation = support::fulfill_observation(request)?;
            captured.push(observation.clone());
            Ok(observation)
        });
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
    let captured: Vec<nah_proto::observation::Observation> =
        serde_json::from_slice(&std::fs::read(capture_path).unwrap()).unwrap();
    let mut observations = captured.iter();

    let started = Instant::now();
    let result = decide_with(&input, &context, |_| {
        observations
            .next()
            .cloned()
            .ok_or_else(|| "unexpected observation round".to_owned())
    });
    let elapsed = started.elapsed();
    assert!(observations.next().is_none());
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
    // decision; the warm p99 tests keep the 1 ms budget.
    let limit = if cfg!(debug_assertions) {
        Duration::from_millis(10)
    } else {
        Duration::from_millis(2)
    };
    assert!(
        elapsed <= limit,
        "cold captured Git force-push decision {elapsed:?} exceeds {limit:?}"
    );

    drop(temp);
}
