//! Hook rows run through Nah's real hook, each in a repository of its own.
//! They hold save-then-run, which saves only on a Unix host.

use std::collections::BTreeSet;

use nah_corpus::{corpus_dir, load_cases, load_hook_cases, run_hook_case};

#[test]
fn every_hook_row_answers_as_expected() {
    let dir = corpus_dir();
    let cases = load_hook_cases(&dir).unwrap_or_else(|errors| panic!("{}", errors.join("\n")));
    assert!(!cases.is_empty(), "no hook rows in {}", dir.display());
    let frozen = load_cases(&dir)
        .expect("load corpus")
        .into_iter()
        .map(|case| case.id)
        .collect::<BTreeSet<_>>();
    let nah = std::path::Path::new(env!("CARGO_BIN_EXE_nah-corpus-hook"));
    let failures = cases
        .iter()
        .filter_map(|case| {
            if frozen.contains(&case.id) {
                return Some(format!("{}: a frozen row has the same id", case.id));
            }
            run_hook_case(case, nah)
                .err()
                .map(|error| format!("{}: {error}", case.id))
        })
        .collect::<Vec<_>>();
    assert!(
        failures.is_empty(),
        "hook rows that failed:\n{}",
        failures.join("\n")
    );
}
