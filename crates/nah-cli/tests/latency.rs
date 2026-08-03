#![allow(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types
)]

mod support;

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
fn captured_walking_skeleton_p99_is_below_one_millisecond() {
    let _serial = serialize_kpi_test();
    let temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah resolves
    // paths before matching them
    let root = std::fs::canonicalize(temp.path()).unwrap();
    let repo = repo(&root);
    let context = ctx(&root);
    let input = call("Read", json!({"file_path":"src/lib.rs"}), &repo);
    let mut captured = None;
    let first = decide_with(&input, &context, |request| {
        let observation = nah_observe::fulfill(request).map_err(|error| error.to_string())?;
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
    // The workspace's normal debug test run gets scheduler/allocator slack;
    // CI also runs this exact test optimized, where the product budget applies.
    let limit = if cfg!(debug_assertions) {
        Duration::from_millis(5)
    } else {
        Duration::from_millis(1)
    };
    assert!(
        p99 <= limit,
        "captured walking-skeleton p99 {p99:?} exceeds {limit:?}"
    );
}

#[test]
fn captured_bash_spine_p99_is_below_one_millisecond() {
    let _serial = serialize_kpi_test();
    let temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah resolves
    // paths before matching them
    let root = std::fs::canonicalize(temp.path()).unwrap();
    let repo = repo(&root);
    let context = ctx(&root);
    let input = call("Bash", json!({"command":"echo hello | cat"}), &repo);
    let mut captured = None;
    let first = decide_with(&input, &context, |request| {
        let observation = nah_observe::fulfill(request).map_err(|error| error.to_string())?;
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
    let limit = if cfg!(debug_assertions) {
        Duration::from_millis(5)
    } else {
        Duration::from_millis(1)
    };
    assert!(p99 <= limit, "captured Bash p99 {p99:?} exceeds {limit:?}");
}

#[test]
fn captured_ambient_preflight_p99_is_below_one_millisecond() {
    let _serial = serialize_kpi_test();
    let temp = tempfile::tempdir().unwrap();
    // macOS temp directories sit under a symlinked /var, and nah resolves
    // paths before matching them
    let root = std::fs::canonicalize(temp.path()).unwrap();
    let repo = repo(&root);
    let context = ctx(&root);
    let input = call("Bash", json!({"command":"echo \"$PATH\""}), &repo);
    let mut captured = Vec::new();
    let first = decide_with(&input, &context, |request| {
        let observation = nah_observe::fulfill(request).map_err(|error| error.to_string())?;
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
        Duration::from_millis(5)
    } else {
        Duration::from_millis(1)
    };
    assert!(
        p99 <= limit,
        "captured ambient preflight p99 {p99:?} exceeds {limit:?}"
    );
}

#[test]
#[cfg_attr(debug_assertions, ignore = "release-mode KPI run")]
fn captured_inline_signature_p99_is_below_one_millisecond() {
    let _serial = serialize_kpi_test();
    let temp = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(temp.path()).unwrap();
    let repo = repo(&root);
    let context = ctx(&root);
    let input = call(
        "Bash",
        json!({"command": "python3 -c \"import shutil; shutil.rmtree('/')\""}),
        &repo,
    );
    let mut captured = None;
    let first = decide_with(&input, &context, |request| {
        let observation = nah_observe::fulfill(request).map_err(|error| error.to_string())?;
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
    let p99 = samples[(samples.len() * 99) / 100];
    let limit = if cfg!(debug_assertions) {
        Duration::from_millis(5)
    } else {
        Duration::from_millis(1)
    };
    assert!(
        p99 <= limit,
        "captured inline-signature p99 {p99:?} exceeds {limit:?}"
    );
}
