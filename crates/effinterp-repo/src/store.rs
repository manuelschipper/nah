//! Versioned, deterministic serialization of a repository index. The stored
//! form follows the effinterp-proto canonical conventions — pretty JSON with
//! struct field order, sorted maps, and a trailing newline — so the same index
//! value always produces identical bytes, and an incremental update compares
//! these bytes to decide whether it changed the published snapshot.

use std::collections::{BTreeMap, BTreeSet};

use effinterp_engine::{Assurance, TransferBinding};
use effinterp_proto::{
    AnalysisStatus, BoundaryReason, CalleeReference, CoverageLevel, Effect, ResourceExpr,
};
use serde::Serialize;

use crate::compose::Composition;
use crate::dispatch::DispatchVia;
use crate::index::{AnalyzedEntrypoint, RepoIndex, SkippedPath};
use crate::snapshot::DependencyManifest;

/// Schema identifier every stored repo index must carry.
pub const REPO_INDEX_SCHEMA: &str = "effinterp/repo-index/v19";

#[derive(Clone, Serialize)]
#[serde(rename_all = "snake_case")]
enum StoredAssurance {
    Exact,
    Alternatives,
    Heuristic,
}

impl From<Assurance> for StoredAssurance {
    fn from(value: Assurance) -> Self {
        match value {
            Assurance::Exact => Self::Exact,
            Assurance::Alternatives => Self::Alternatives,
            Assurance::Heuristic => Self::Heuristic,
        }
    }
}

#[derive(Clone, Serialize)]
struct StoredDispatchVia {
    model: String,
    registration_path: Vec<String>,
    dispatch_path: Vec<String>,
}

impl From<&DispatchVia> for StoredDispatchVia {
    fn from(value: &DispatchVia) -> Self {
        Self {
            model: value.model.clone(),
            registration_path: value.registration_path.clone(),
            dispatch_path: value.dispatch_path.clone(),
        }
    }
}

/// Serializable mirror of [`ComposedEffect`]. The composition types themselves
/// stay analysis-internal (another concern owns them), so the storage schema is
/// pinned here instead of derived from them.
#[derive(Clone, Serialize)]
struct StoredComposedEffect {
    effect: Effect,
    occurrences: u32,
    unconditional_occurrences: u32,
}

/// Serializable mirror of [`ComposedBoundary`].
#[derive(Clone, Serialize)]
struct StoredComposedBoundary {
    source_file: Option<String>,
    callee: Option<CalleeReference>,
    class: effinterp_proto::BoundaryClass,
    reason: BoundaryReason,
    detail: String,
    domains: Vec<String>,
    affected_resource: Option<ResourceExpr>,
    limit: Option<String>,
    occurrences: u32,
    exemplar_paths: Vec<Vec<String>>,
    via_dispatch: Option<StoredDispatchVia>,
}

#[derive(Clone, Serialize)]
struct StoredOccurrence {
    effect: usize,
    condition: Option<effinterp_proto::Condition>,
    source_file: String,
    path: Vec<String>,
    assurance: StoredAssurance,
    via_dispatch: Option<StoredDispatchVia>,
}

#[derive(Clone, Serialize)]
struct StoredResolvedCall {
    source_file: String,
    callee: CalleeReference,
}

/// Serializable mirror of [`Composition`].
#[derive(Clone, Serialize)]
struct StoredComposition {
    effects: Vec<StoredComposedEffect>,
    occurrence_effects: Vec<StoredOccurrence>,
    transfers: Vec<TransferBinding>,
    boundaries: Vec<StoredComposedBoundary>,
    resolved_calls: Vec<StoredResolvedCall>,
    coverage: Vec<(String, CoverageLevel)>,
    deps: Vec<String>,
    occurrences: usize,
    compose_steps: u64,
}

impl From<&Composition> for StoredComposition {
    fn from(c: &Composition) -> Self {
        Self {
            effects: c
                .effects
                .iter()
                .map(|e| StoredComposedEffect {
                    effect: e.effect.clone(),
                    occurrences: e.occurrences,
                    unconditional_occurrences: e.unconditional_occurrences,
                })
                .collect(),
            occurrence_effects: c
                .occurrence_effects
                .iter()
                .map(|occurrence| StoredOccurrence {
                    effect: occurrence.effect,
                    condition: occurrence.condition.clone(),
                    source_file: occurrence.source_file.clone(),
                    path: occurrence.path.clone(),
                    assurance: occurrence.assurance.into(),
                    via_dispatch: occurrence
                        .via_dispatch
                        .as_ref()
                        .map(StoredDispatchVia::from),
                })
                .collect(),
            transfers: c.transfers.clone(),
            boundaries: c
                .boundaries
                .iter()
                .map(|b| StoredComposedBoundary {
                    source_file: b.source_file.clone(),
                    callee: b.callee.clone(),
                    class: b.class,
                    reason: b.reason.clone(),
                    detail: b.detail.clone(),
                    domains: b.domains.clone(),
                    affected_resource: b.affected_resource.clone(),
                    limit: b.limit.clone(),
                    occurrences: b.occurrences,
                    exemplar_paths: b.exemplar_paths.clone(),
                    via_dispatch: b.via_dispatch.as_ref().map(StoredDispatchVia::from),
                })
                .collect(),
            resolved_calls: c
                .resolved_calls
                .iter()
                .map(|resolved| StoredResolvedCall {
                    source_file: resolved.source_file.clone(),
                    callee: resolved.callee.clone(),
                })
                .collect(),
            coverage: c.coverage.clone(),
            deps: c.deps.clone(),
            occurrences: c.occurrences,
            compose_steps: c.budget.steps,
        }
    }
}

/// Metadata and plans of a stored index. Compositions are stored beside it
/// in [`StoredQueryIndex`].
#[derive(Serialize)]
struct StoredIndex {
    schema: String,
    root: String,
    fingerprint: String,
    analyzer: String,
    model_set: String,
    limits: crate::index::IndexLimits,
    dependency_manifest: DependencyManifest,
    module_paths: Vec<String>,
    derived_dependencies: BTreeMap<String, Vec<String>>,
    skipped_dependencies: BTreeMap<String, Vec<String>>,
    skipped_roots: BTreeSet<String>,
    snapshot_state: AnalysisStatus,
    entrypoints: Vec<AnalyzedEntrypoint>,
    skipped: Vec<SkippedPath>,
    skips_truncated: bool,
    launch_edges: Vec<crate::discover::LaunchEdge>,
    go_root_effects: BTreeMap<String, Vec<crate::index::GoRootEffect>>,
}

fn stored_index(index: &RepoIndex) -> StoredIndex {
    StoredIndex {
        schema: REPO_INDEX_SCHEMA.to_string(),
        root: index.root.clone(),
        fingerprint: index.fingerprint.clone(),
        analyzer: index.analyzer.clone(),
        model_set: index.model_set.clone(),
        limits: index.limits.clone(),
        dependency_manifest: index.dependency_manifest.clone(),
        module_paths: index.module_paths.clone(),
        derived_dependencies: index.derived_dependencies.clone(),
        skipped_dependencies: index.skipped_dependencies.clone(),
        skipped_roots: index.skipped_roots.clone(),
        snapshot_state: index.snapshot_state.clone(),
        entrypoints: index.entrypoints.clone(),
        skipped: index.skipped.clone(),
        skips_truncated: index.skips_truncated,
        launch_edges: index.launch_edges.clone(),
        go_root_effects: index.go_root_effects.clone(),
    }
}

#[derive(Serialize)]
struct StoredQueryIndex {
    #[serde(flatten)]
    index: StoredIndex,
    composed: BTreeMap<String, StoredComposition>,
}

/// Serialize a self-contained repository index in its canonical stored form.
///
/// Returns the JSON text and writes no file; the caller owns storage.
/// Unsupported: loading a stored index. This crate has no inverse
/// deserializer, so a usable `RepoIndex` always comes from
/// [`crate::build_index`], and incremental updates start from that live index.
pub fn save_index(index: &RepoIndex) -> String {
    let stored = StoredQueryIndex {
        index: stored_index(index),
        composed: index
            .composed
            .iter()
            .map(|(id, c)| (id.clone(), StoredComposition::from(c.as_ref())))
            .collect(),
    };
    let mut out = serde_json::to_string_pretty(&stored).expect("index serialization cannot fail");
    out.push('\n');
    out
}
