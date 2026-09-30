//! Runs the layered semantic evaluation corpus. The committed corpus must have
//! zero missing_effect, false_positive, boundary_missing, or invalid_plan;
//! known engine gaps are tracked as `known_gap` and printed, not failed.
#![allow(clippy::disallowed_macros)]

use std::path::PathBuf;

use effinterp_bench::layered::{LayeredClass, evaluate_layered_case, load_layered_cases};
use effinterp_engine::Engine;

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures")
}

#[test]
fn layered_corpus_has_no_failures() {
    let engine = Engine::new().with_causality_detail(true);
    let root = fixture_root();
    let mut failures = Vec::new();
    let mut gaps = Vec::new();
    let mut passes = 0usize;

    for case in load_layered_cases() {
        let outcome = evaluate_layered_case(&case, &engine, &root);
        match outcome.class {
            LayeredClass::Pass => passes += 1,
            LayeredClass::KnownGap => gaps.push((outcome.id, outcome.detail)),
            _ => failures.push((outcome.id, outcome.class, outcome.detail)),
        }
    }

    if !gaps.is_empty() {
        eprintln!("known gaps ({}):", gaps.len());
        for (id, detail) in &gaps {
            eprintln!("  {id}: {}", detail.as_deref().unwrap_or(""));
        }
    }
    eprintln!("passes: {passes}");

    assert!(
        failures.is_empty(),
        "corpus failures:\n{}",
        failures
            .iter()
            .map(|(id, c, d)| format!("  {id} [{}] {}", c.as_str(), d.as_deref().unwrap_or("")))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn corpus_is_deterministic_across_runs() {
    let engine = Engine::new().with_causality_detail(true);
    let root = fixture_root();
    let run = || {
        load_layered_cases()
            .iter()
            .map(|c| (c.id.clone(), evaluate_layered_case(c, &engine, &root).class))
            .collect::<Vec<_>>()
    };
    assert_eq!(run(), run());
}
