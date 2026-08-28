#![allow(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types
)]

//! Typed corpus loading, frozen execution, and strict triage reconciliation.

use std::path::{Path, PathBuf};

mod case;
mod fixtures;
mod runner;

pub use case::{
    CaseInput, CorpusCase, CorpusSummary, Expectation, ExpectedCoverage, ExpectedVerdict,
    load_cases, load_summary,
};
pub use fixtures::{ContextFixture, FixtureRegistry, ObservationFixture, load_fixtures};
pub use runner::{Reconciliation, reconcile};

pub fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus")
        .canonicalize()
        .expect("corpus dir")
}
