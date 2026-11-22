//! Every shipped rule, whatever level it applies at, keeps a floor of delivered
//! block rows and at least one delivered benign twin run with the rule enabled,
//! so a thin rule cannot quietly lose the rows that prove it fires or the
//! everyday call that proves it stays quiet.

use std::collections::{BTreeMap, BTreeSet};

use nah_corpus::{corpus_dir, expected_fail_ids, load_cases, load_fixtures};
use nah_corpus_schema::{Expectation, ExpectedVerdict};

/// The fewest delivered block rows any rule may have.
/// `machine/permissions-weaken` sets it with exactly ten.
const MIN_BLOCK_ROWS: usize = 10;

#[test]
fn every_shipped_rule_has_a_block_floor_and_a_benign_twin() {
    let dir = corpus_dir();
    let cases = load_cases(&dir).expect("load corpus");
    let ledger = std::fs::read_to_string(dir.join("TRIAGE.md")).expect("triage ledger");
    let (expected_fail, _) = expected_fail_ids(&ledger);
    let fixtures = load_fixtures(&dir.join("FIXTURES.json")).expect("typed fixtures");
    let shipped = nah_policy::ShippedGuards::new();
    let mut blocks = shipped
        .rule_ids()
        .iter()
        .map(|rule| (*rule, 0usize))
        .collect::<BTreeMap<_, _>>();
    // A row family (its id prefix) twins the rules its own block rows expect.
    let mut family_rules = BTreeMap::<&str, BTreeSet<&str>>::new();
    for case in &cases {
        if let Expectation::Decision {
            verdict: ExpectedVerdict::Block,
            guard: Some(guard),
            ..
        } = &case.expected
            && let Some((prefix, _)) = case.id.split_once('.')
        {
            family_rules
                .entry(prefix)
                .or_default()
                .insert(guard.as_str());
        }
    }
    let mut twins = BTreeSet::new();
    for case in &cases {
        let Expectation::Decision { verdict, guard, .. } = &case.expected else {
            continue;
        };
        match (verdict, guard) {
            (ExpectedVerdict::Block, Some(guard)) if !expected_fail.contains(case.id.as_str()) => {
                *blocks.entry(guard.as_str()).or_default() += 1;
            }
            // A twin proves the rule stays quiet only when the rule runs and
            // the row's delegate verdict is delivered.
            (ExpectedVerdict::Delegate, _) if !expected_fail.contains(case.id.as_str()) => {
                let Some((prefix, _)) = case.id.split_once('.') else {
                    continue;
                };
                let enabled = fixtures
                    .ctx_fixture(&case.ctx_fixture)
                    .expect("known context fixture")
                    .enabled_rules()
                    .expect("context fixture");
                for rule in family_rules.get(prefix).into_iter().flatten() {
                    if enabled.contains(*rule) {
                        twins.insert(*rule);
                    }
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
        "rules below {MIN_BLOCK_ROWS} delivered block rows: {thin:?}"
    );
    let untwinned = shipped
        .rule_ids()
        .iter()
        .filter(|rule| !twins.contains(**rule))
        .collect::<Vec<_>>();
    assert!(
        untwinned.is_empty(),
        "rules without an enabled, delivered delegate row in a family that blocks on them: {untwinned:?}"
    );
}
