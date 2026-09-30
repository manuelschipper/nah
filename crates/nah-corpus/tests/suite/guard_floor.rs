//! Every shipped guard, on or off by default, keeps a floor of delivered block
//! rows and at least one delivered benign twin run with the guard enabled, so a
//! thin guard cannot quietly lose the rows that prove it fires or the everyday
//! call that proves it stays quiet.

use std::collections::{BTreeMap, BTreeSet};

use nah_corpus::{corpus_dir, expected_fail_ids, load_cases, load_fixtures};
use nah_corpus_schema::{Expectation, ExpectedVerdict};

/// The fewest delivered block rows any guard may have. `fs-permission-weaken`
/// sets it with exactly ten.
const MIN_BLOCK_ROWS: usize = 10;

#[test]
fn every_shipped_guard_has_a_block_floor_and_a_benign_twin() {
    let dir = corpus_dir();
    let cases = load_cases(&dir).expect("load corpus");
    let ledger = std::fs::read_to_string(dir.join("TRIAGE.md")).expect("triage ledger");
    let (expected_fail, _) = expected_fail_ids(&ledger);
    let fixtures = load_fixtures(&dir.join("FIXTURES.json")).expect("typed fixtures");
    let guards = nah_cli::shipped_guard_states();
    let mut blocks = guards
        .iter()
        .map(|guard| (guard.name(), 0usize))
        .collect::<BTreeMap<_, _>>();
    let mut twins = BTreeSet::new();
    for case in &cases {
        let Expectation::Decision { verdict, guard, .. } = &case.expected else {
            continue;
        };
        match (verdict, guard) {
            (ExpectedVerdict::Block, Some(guard)) if !expected_fail.contains(case.id.as_str()) => {
                *blocks.entry(guard.as_str()).or_default() += 1;
            }
            // A twin proves the guard stays quiet only when the guard is on
            // and the row's delegate verdict is delivered.
            (ExpectedVerdict::Delegate, _) if !expected_fail.contains(case.id.as_str()) => {
                if let Some((prefix, _)) = case.id.split_once('.')
                    && fixtures
                        .ctx_fixture(&case.ctx_fixture)
                        .expect("known context fixture")
                        .enabled_shipped_guards()
                        .expect("context fixture")
                        .contains(prefix)
                {
                    twins.insert(prefix);
                }
            }
            _ => {}
        }
    }
    let thin = blocks
        .iter()
        .filter(|(_, count)| **count < MIN_BLOCK_ROWS)
        .collect::<Vec<_>>();
    assert!(
        thin.is_empty(),
        "guards below {MIN_BLOCK_ROWS} delivered block rows: {thin:?}"
    );
    let untwinned = guards
        .iter()
        .map(|guard| guard.name())
        .filter(|name| !twins.contains(name))
        .collect::<Vec<_>>();
    assert!(
        untwinned.is_empty(),
        "guards without an enabled, delivered delegate row under their id prefix: {untwinned:?}"
    );
}
