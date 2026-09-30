//! Model authoring: compile candidate documents, run their declared fixtures
//! and mutations against the engine, and report what a candidate would change.
//! Discovery may be assisted; what ships is deterministic and reviewable.
//! Promoted documents use the schema's canonical JSON form. After any hand edit,
//! run `repin` so formatting, identity, and pinned evidence move together.
// Development tool: reads and rewrites model documents on disk.
#![allow(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types
)]

mod assertion_seeding;
mod candidate_promotion;
mod document_verification;
mod fixture_evidence;
mod model_directory;
mod model_normalization;
mod mutation_checks;
mod repin;

use std::fmt;
use std::path::PathBuf;

pub use assertion_seeding::seed_assertions;
pub use candidate_promotion::{normalize_candidate, promote_candidate, promote_file};
pub use document_verification::{verify_directory, verify_directory_with_options};
pub use fixture_evidence::migrate_fixture;
pub use repin::repin_directory;

/// Why a model factory command failed.
#[derive(Debug)]
pub enum FactoryError {
    Io { path: PathBuf, detail: String },
    Json(String),
    Validation(String),
    Fixture { name: String, detail: String },
    Mutation { name: String, detail: String },
    Usage(String),
}

impl fmt::Display for FactoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, detail } => write!(f, "{}: {detail}", path.display()),
            Self::Json(detail) | Self::Validation(detail) | Self::Usage(detail) => {
                f.write_str(detail)
            }
            Self::Fixture { name, detail } => write!(f, "fixture {name:?}: {detail}"),
            Self::Mutation { name, detail } => write!(f, "mutation {name:?}: {detail}"),
        }
    }
}

impl std::error::Error for FactoryError {}
