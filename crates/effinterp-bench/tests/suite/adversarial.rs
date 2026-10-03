//! The adversarial honesty corpus, as a test. No row may come back a silent
//! miss, a wrong resource or a crash that the committed scoreboard does not
//! already record, and no literal operand the analyzer resolved may vanish
//! when it is replaced by a symbolic one.
//!
//! These were gate rules (c) and (d2), reachable only through
//! `measure --group correctness`. They are the one tier-1 honesty check that
//! had no test, so they ran only when somebody chose to publish numbers.
#![allow(clippy::disallowed_methods)]

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::sync::Arc;

use effinterp_bench::invocation::corpus::load_invocation_rows;
use effinterp_bench::invocation::score::{AdversarialScore, Scoreboard, score_adversarial};
use effinterp_bench::invocation::{Mutation, analyze_rows};
use effinterp_engine::Engine;

fn bench_dir() -> &'static Path {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../../bench"))
}

fn committed() -> AdversarialScore {
    let scoreboard: Scoreboard =
        serde_json::from_slice(&fs::read(bench_dir().join("scoreboard.json")).unwrap()).unwrap();
    scoreboard
        .correctness
        .adversarial
        .expect("bench/scoreboard.json carries an adversarial section")
}

/// A verdict already in the committed scoreboard is a known gap; only a new
/// one is a regression. An improvement ratchets on a deliberate publish, so
/// it must not break the build.
#[test]
fn adversarial_verdicts_and_symbolic_operands_hold() {
    let rows: Vec<_> = load_invocation_rows(&bench_dir().join("invocation"))
        .unwrap()
        .into_iter()
        .filter(|row| row.source == "adversarial")
        .collect();
    assert!(
        !rows.is_empty(),
        "the adversarial corpus is the oracle here"
    );
    let rows = Arc::new(rows);
    let engine = Arc::new(Engine::new().with_causality_detail(true));
    let outcomes = analyze_rows(&engine, &rows, Mutation::All);
    let measured = score_adversarial(&rows, &outcomes);
    let committed = committed();

    let mut appeared = Vec::new();
    for ((kind, now), (_, before)) in measured.ids.gated().into_iter().zip(committed.ids.gated()) {
        let before: BTreeSet<&String> = before.iter().collect();
        appeared.extend(
            now.iter()
                .filter(|id| !before.contains(id))
                .map(|id| format!("{kind} {id}")),
        );
    }
    assert!(
        appeared.is_empty(),
        "new adversarial verdicts: {appeared:?}"
    );

    // A mutation population that silently emptied would pass every drop
    // assertion below without testing anything.
    assert!(
        measured.silent_drops.mutants > 0,
        "no symbolic mutants were exercised"
    );
    let before: BTreeSet<_> = committed
        .silent_drops
        .drops
        .iter()
        .map(|drop| (&drop.id, &drop.word, &drop.domain))
        .collect();
    let dropped: Vec<_> = measured
        .silent_drops
        .drops
        .iter()
        .filter(|drop| !before.contains(&(&drop.id, &drop.word, &drop.domain)))
        .map(|drop| format!("{} drops {} on `{}`", drop.id, drop.operation, drop.word))
        .collect();
    assert!(dropped.is_empty(), "new silent drops: {dropped:?}");
}
