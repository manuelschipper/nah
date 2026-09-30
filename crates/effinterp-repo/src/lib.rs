//! Entrypoint effect index: discover a repository's entrypoints, analyze each
//! with the invocation engine, and index the resulting effects so forward
//! (entrypoint -> effects) and reverse (resource -> entrypoints) queries can be
//! answered.
//!
//! Beyond single-entrypoint analysis it also composes effects ACROSS FILES: a
//! source-module registry extracts each Python/JS file's function summaries,
//! call edges, and imports, and cross-file composition follows an entrypoint's
//! calls into functions in other files (with argument substitution, a bounded
//! fixpoint, and widening on recursion), so the reverse query traces effects
//! through user code across module boundaries. An incremental update
//! re-extracts only a changed file and re-composes only the entrypoints that
//! depend on it. It still lacks whole-program type inference and dataflow, so
//! it remains an effect index rather than a full compiler. Unlike the engine it
//! reads source files from the target repository — source is analyzed, never
//! executed, and symlinks are never followed. Every query result is bound to an
//! analyzed-input fingerprint (a manifest of the exact inputs plus the analyzer
//! and model-set identity), and the crawl reports what it skipped rather than
//! silently bounding coverage.

use std::path::{Component, Path};

mod compose;
// Repository indexing owns the filesystem walk and its worker threads; the
// remaining modules analyze what these modules read.
#[allow(clippy::disallowed_methods, clippy::disallowed_types)]
mod discover;
mod dispatch;
#[allow(clippy::disallowed_methods, clippy::disallowed_types)]
mod index;
mod launch;
mod linker;
#[allow(clippy::disallowed_methods, clippy::disallowed_types)]
mod module;
mod normalize;
mod query;
mod resource;
#[allow(clippy::disallowed_methods, clippy::disallowed_types)]
mod shallow;
mod snapshot;
#[allow(clippy::disallowed_methods, clippy::disallowed_types)]
mod store;
mod surface;

fn canonical_repo_path(root: &Path, path: &Path) -> Option<String> {
    let relative = path.strip_prefix(root).ok()?;
    let mut parts = Vec::new();
    for component in relative.components() {
        let Component::Normal(component) = component else {
            return None;
        };
        let component = component.to_str()?;
        if component.is_empty() || component.contains('\\') {
            return None;
        }
        parts.push(component);
    }
    Some(parts.join("/"))
}

pub use compose::{
    ComposeBudget, ComposedBoundary, ComposedEffect, ComposedOccurrence, Composition,
};
pub use discover::{
    Entrypoint, EntrypointEvidence, EntrypointKind, LaunchEdge, ProcessLaunchEvidence, SpanSeg,
};
pub use dispatch::DispatchVia;
pub use index::{
    ANALYSIS_PANIC_ERROR, AnalyzedEntrypoint, CrawlLimits, EntrypointOutcome, GoRootEffect,
    IndexLimits, InvalidationAction, RepoChange, RepoIndex, RepositoryLimits, Skip, SkipCategory,
    UpdateFailure, UpdateOutcome, UpdateReport, apply_changes, build_index, invalidation_action,
};
pub use module::{ModuleFile, Registry};
pub use normalize::normalize_surface;
pub use query::{effects_of, reach};
pub use resource::{
    DatabaseIdentitySelector, GitIdentitySelector, RealmFilter, Selector, identity_from_selector,
};
pub use shallow::ShallowSourceResolver;
pub use snapshot::{
    DependencyKind, DependencyManifest, DependencyRecord, FRONTEND_IDS, InputRecord, snapshot_id,
};
pub use store::{REPO_INDEX_SCHEMA, save_index};
pub use surface::{
    EffectiveBoundary, EffectiveEffect, EffectiveSurface, ProvStep, effective_surface,
};
