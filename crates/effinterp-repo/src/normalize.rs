//! Canonical normalized serialization of a [`RepoIndex`]'s entire public query
//! surface.
//!
//! This is the incremental clean-rebuild oracle in its strongest form: an index
//! reached by a sequence of incremental events and one rebuilt cleanly to the
//! same on-disk state must produce byte-identical strings here. Unlike a bare
//! fingerprint-and-effect comparison, this captures every field a public query
//! can surface — for every entrypoint (sorted): each effect's operation,
//! rendered resource, structural resource expression, realm, modality,
//! condition, every attribute, destructive flag, origin file, and provenance
//! rendered as structural steps; every boundary; coverage per domain; plus each
//! entrypoint's failure record, the analyzed-input manifest, the skip records,
//! the fingerprint, and the model manifest (analyzer, model set, and analysis
//! limits).
//!
//! Determinism: provenance identifiers that are intentionally unstable are
//! rendered to structural paths via [`ProvenanceStep::render`], never omitted; every
//! collection is either a `BTreeMap` (sorted keys) or a `Vec` explicitly sorted
//! by its serialized form, so nothing depends on HashMap iteration order.

use std::collections::BTreeMap;

use effinterp_proto::{
    AnalysisStatus, AttrValue, BoundaryReason, Condition, CoverageLevel, ExecutionRealm, Modality,
    ResourceExpr,
};
use serde::Serialize;

use crate::discover::EntrypointKind;
use crate::index::{EntrypointOutcome, RepoIndex, SkippedPath};
use crate::snapshot::DependencyKind;
use crate::surface::effective_surface;

/// The normalized public surface of a whole index, serialized deterministically.
#[derive(Serialize)]
struct NormIndex {
    fingerprint: String,
    analyzer: String,
    model_set: String,
    /// The model manifest's analysis limits, `name=value`, sorted.
    limits: Vec<String>,
    dependency_manifest: Vec<NormDependency>,
    derived_dependencies: BTreeMap<String, Vec<String>>,
    skipped_dependencies: BTreeMap<String, Vec<String>>,
    skipped_roots: std::collections::BTreeSet<String>,
    snapshot_state: AnalysisStatus,
    skipped: Vec<SkippedPath>,
    entrypoints: Vec<NormEntrypoint>,
}

#[derive(Serialize)]
struct NormDependency {
    key: String,
    kind: DependencyKind,
    digest: String,
}

#[derive(Serialize)]
struct NormEntrypoint {
    id: String,
    kind: EntrypointKind,
    source_file: String,
    evidence_file: String,
    outcome: NormOutcome,
}

#[derive(Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
enum NormOutcome {
    Analyzed {
        effects: Vec<NormEffect>,
        boundaries: Vec<NormBoundary>,
        coverage: BTreeMap<String, CoverageLevel>,
    },
    Failed {
        error: String,
    },
    LimitReached {
        limit: String,
    },
}

#[derive(Serialize)]
struct NormEffect {
    occurrences: u32,
    paths: Vec<Vec<String>>,
    operation: String,
    resource: String,
    family: String,
    realm: ExecutionRealm,
    modality: Modality,
    condition: Option<Condition>,
    attributes: BTreeMap<String, AttrValue>,
    destructive: bool,
    origin_file: String,
    /// Provenance rendered to stable structural steps.
    provenance: Vec<String>,
    /// The raw structural resource expression (stable: names/families/patterns).
    resource_expr: ResourceExpr,
}

#[derive(Serialize)]
struct NormBoundary {
    occurrences: u32,
    exemplar_paths: Vec<Vec<String>>,
    reason: BoundaryReason,
    domains: Vec<String>,
    affected_resource: Option<ResourceExpr>,
    detail: Option<String>,
    provenance: Vec<String>,
}

/// Serialize each element to JSON and sort the vector by that string, so the
/// order is fully determined by content rather than by insertion order.
fn sort_by_json<T: Serialize>(items: &mut [T]) {
    items.sort_by_cached_key(|item| serde_json::to_string(item).expect("serialize"));
}

/// Produce the canonical normalized serialization of `index`'s entire public
/// query surface. Two indexes reaching the same on-disk state — one clean, one
/// incremental — must yield byte-identical output.
pub fn normalize_surface(index: &RepoIndex) -> String {
    let mut limits: Vec<String> = crate::index::repo_analysis_limits()
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect();
    limits.sort();

    let dependency_manifest: Vec<NormDependency> = index
        .dependency_manifest
        .records()
        .iter()
        .map(|r| NormDependency {
            key: r.key.clone(),
            kind: r.kind,
            digest: r.digest.clone(),
        })
        .collect();

    let mut skipped = index.skipped.clone();
    sort_by_json(&mut skipped);

    let mut entrypoints: Vec<NormEntrypoint> = index
        .entrypoints
        .iter()
        .map(|analyzed| {
            let id = analyzed.entrypoint.id.clone();
            let outcome = match &analyzed.outcome {
                EntrypointOutcome::Failed { error } => NormOutcome::Failed {
                    error: error.clone(),
                },
                EntrypointOutcome::LimitReached { limit } => NormOutcome::LimitReached {
                    limit: limit.clone(),
                },
                EntrypointOutcome::Analyzed { .. } => {
                    let surface =
                        effective_surface(index, &id).expect("analyzed entrypoint has a surface");
                    let mut effects: Vec<NormEffect> = surface
                        .effects
                        .iter()
                        .map(|e| NormEffect {
                            occurrences: e.occurrences,
                            paths: e.paths.clone(),
                            operation: e.operation.clone(),
                            resource: e.resource.clone(),
                            family: e.family.to_string(),
                            realm: e.realm.clone(),
                            modality: e.modality,
                            condition: e.condition.clone(),
                            attributes: e.attributes.clone(),
                            destructive: e.destructive,
                            origin_file: e.origin_file.clone(),
                            provenance: e.provenance.iter().map(|p| p.render()).collect(),
                            resource_expr: e.resource_expr.clone(),
                        })
                        .collect();
                    sort_by_json(&mut effects);
                    let mut boundaries: Vec<NormBoundary> = surface
                        .boundaries
                        .iter()
                        .map(|b| NormBoundary {
                            occurrences: b.occurrences,
                            exemplar_paths: b.exemplar_paths.clone(),
                            reason: b.reason.clone(),
                            domains: b.domains.clone(),
                            affected_resource: b.affected_resource.clone(),
                            detail: b.detail.clone(),
                            provenance: b.provenance.iter().map(|p| p.render()).collect(),
                        })
                        .collect();
                    sort_by_json(&mut boundaries);
                    NormOutcome::Analyzed {
                        effects,
                        boundaries,
                        coverage: surface.coverage.clone(),
                    }
                }
            };
            NormEntrypoint {
                id,
                kind: analyzed.entrypoint.evidence.kind,
                source_file: analyzed.entrypoint.source_file.clone(),
                evidence_file: analyzed.entrypoint.evidence.file.clone(),
                outcome,
            }
        })
        .collect();
    entrypoints.sort_by(|a, b| a.id.cmp(&b.id));

    let norm = NormIndex {
        fingerprint: index.fingerprint.clone(),
        analyzer: index.analyzer.clone(),
        model_set: index.model_set.clone(),
        limits,
        dependency_manifest,
        derived_dependencies: index.derived_dependencies.clone(),
        skipped_dependencies: index.skipped_dependencies.clone(),
        skipped_roots: index.skipped_roots.clone(),
        snapshot_state: index.snapshot_state.clone(),
        skipped,
        entrypoints,
    };
    serde_json::to_string_pretty(&norm).expect("normalized surface serializes")
}
