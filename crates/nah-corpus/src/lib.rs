#![allow(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types
)]

//! Typed corpus loading, frozen execution, strict triage reconciliation, and
//! hook rows run through Nah's real hook.

use std::path::{Path, PathBuf};

mod case;
mod fixtures;
mod hook_rows;
mod hook_sessions;
mod runner;

pub use case::{CorpusSummary, load_cases, load_summary};
pub use fixtures::{FixtureRegistry, load_fixtures};
pub use hook_rows::{load_hook_cases, run_hook_case};
pub use hook_sessions::{HookSession, Outcome, Recorded, Step, record_hook_session};
pub use nah_cli::supplied_state::{ContextFixture, ObservationFixture};
pub use runner::{
    DecisionShape, Reconciliation, RowMatches, decide_case_in_shell, decision_shape,
    expected_fail_ids, reconcile_triage_ledger, row_matches,
};

/// The repository's `corpus/` directory, canonicalized.
pub fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus")
        .canonicalize()
        .expect("corpus dir")
}
