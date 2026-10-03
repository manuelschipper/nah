//! Every example in the built-in guard knowledge records
//! (`crates/nah-cli/guards/*.toml`) names a delivered corpus row that shows
//! what the record claims, so the TUI, `nah docs guards`, and the guard
//! reference cannot drift from the decisions Nah makes.

use std::collections::BTreeMap;

use nah_cli::{PassCause, guard_knowledge};
use nah_corpus::{
    corpus_dir, expected_fail_ids, load_cases, load_fixtures, reconcile_triage_ledger,
};
use nah_corpus_schema::{Expectation, ExpectedVerdict};

/// A block example's row expects a block naming the guard. A pass example's
/// row expects a delegate under a context that enables the guard. An
/// `unresolved` pass must also report partial coverage; an `out-of-scope` pass
/// may too, because partial coverage also records gaps unrelated to the
/// guard, such as an unmodeled read-only subcommand. No example may be an
/// expected failure.
#[test]
fn guard_knowledge_examples_match_their_corpus_rows() {
    let dir = corpus_dir();
    let cases = load_cases(&dir).expect("load corpus");
    let fixtures = load_fixtures(&dir.join("FIXTURES.json")).expect("typed fixtures");
    let ledger = std::fs::read_to_string(dir.join("TRIAGE.md")).expect("triage ledger");
    let (expected_fail, _) = expected_fail_ids(&ledger);
    let by_id = cases
        .iter()
        .map(|case| (case.id.as_str(), case))
        .collect::<BTreeMap<_, _>>();

    let mut errors = Vec::new();
    let mut passes = Vec::new();
    let mut replayed = BTreeMap::new();
    for guard in guard_knowledge() {
        let name = guard.name;
        let rows = guard
            .blocks
            .iter()
            .map(|block| (block.row.as_str(), None))
            .chain(
                guard
                    .passes
                    .iter()
                    .map(|pass| (pass.row.as_str(), Some(pass.cause))),
            );
        for (row, cause) in rows {
            let Some(case) = by_id.get(row) else {
                errors.push(format!("{name}: `{row}` is not a corpus row"));
                continue;
            };
            if expected_fail.contains(row) {
                errors.push(format!("{name}: `{row}` is an expected failure"));
            }
            let Expectation::Decision {
                verdict,
                guard: expected_guard,
                guards,
                ..
            } = &case.expected
            else {
                errors.push(format!("{name}: `{row}` expects no decision"));
                continue;
            };
            match (cause, verdict) {
                (None, ExpectedVerdict::Block) => {
                    if expected_guard.as_deref() != Some(name)
                        && !guards.iter().flatten().any(|guard| guard == name)
                    {
                        errors.push(format!("{name}: block `{row}` expects another guard"));
                    }
                }
                (Some(cause), ExpectedVerdict::Delegate) => {
                    let enabled = fixtures
                        .ctx_fixture(&case.ctx_fixture)
                        .expect("known context fixture")
                        .enabled_shipped_guards()
                        .expect("context fixture");
                    if !enabled.contains(name) {
                        errors.push(format!("{name}: pass `{row}` runs with the guard off"));
                    }
                    passes.push((row, name, cause));
                    replayed.insert(row, (*case).clone());
                }
                (None, _) => errors.push(format!("{name}: block `{row}` expects a delegate")),
                (Some(_), _) => errors.push(format!("{name}: pass `{row}` expects a block")),
            }
        }
    }

    let replayed = replayed.into_values().collect::<Vec<_>>();
    let result = reconcile_triage_ledger(&replayed, &fixtures, "");
    errors.extend(result.unexpected_failures);
    for (row, name, cause) in passes {
        if cause == PassCause::Unresolved && !result.partial_coverage.contains(row) {
            errors.push(format!(
                "{name}: unresolved pass `{row}` reports full coverage"
            ));
        }
    }
    assert!(errors.is_empty(), "{}", errors.join("\n"));
}
