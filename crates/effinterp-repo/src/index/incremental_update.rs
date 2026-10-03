//! Incremental index update: apply repository changes to a built index by
//! re-extracting the changed files and re-composing only the entrypoints
//! that depend on them, then publish the candidate or report why it failed.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;

use super::{
    AnalyzedEntrypoint, EntrypointOutcome, IndexBudget, IndexLimits, LAUNCH_COMPOSITION_PREFIX,
    RepoIndex, RepositoryLimits, SkipCategory, SkippedPath, analyze_entrypoint, build_index,
    derived_dependencies, entrypoint_dependencies, go_root_effects_all, launch_composition_key,
    limit_launched_entrypoints, registry_roots, repo_engine, skipped_dependencies, snapshot_state,
};
use crate::compose::{compose_callable, compose_with_package_init};
use crate::discover::discover;
use crate::snapshot::{DependencyKind, analyzer_build_digest, dependency_manifest, snapshot_id};

/// A repository change to apply incrementally. Rename is expressed as a
/// `Deleted` of the old path plus an `Added` of the new one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepoChange {
    Added(String),
    Modified(String),
    Deleted(String),
    /// A tool/config identity changed outside the working-tree event stream.
    IdentityChanged {
        kind: DependencyKind,
        key: String,
    },
    /// A change kind not understood by this index implementation.
    Unknown(String),
}

impl RepoChange {
    fn path(&self) -> Option<&str> {
        match self {
            RepoChange::Added(p) | RepoChange::Modified(p) | RepoChange::Deleted(p) => Some(p),
            RepoChange::IdentityChanged { .. } | RepoChange::Unknown(_) => None,
        }
    }
}

/// The strongest work invalidated by a change. Ordering is deliberate so a
/// set of events deterministically selects the safest required action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum InvalidationAction {
    Reextract,
    Reanalyze,
    Recompose,
    Rediscover,
    Rebuild,
}

/// Classify one event through the discovery, frontend, and linker-owned
/// policies. Identity and unknown events always fail closed to a rebuild.
pub fn invalidation_action(change: &RepoChange) -> InvalidationAction {
    match change {
        RepoChange::IdentityChanged { .. } | RepoChange::Unknown(_) => InvalidationAction::Rebuild,
        RepoChange::Added(path) | RepoChange::Modified(path) | RepoChange::Deleted(path) => [
            crate::module::invalidation_for_path(path),
            crate::discover::invalidation_for_path(path),
            crate::linker::invalidation_for_path(path),
        ]
        .into_iter()
        .flatten()
        .max()
        .unwrap_or(InvalidationAction::Rediscover),
    }
}

/// What an incremental update recomputed. Old and new fingerprint let a caller
/// confirm the index moved (or did not) as expected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateReport {
    pub outcome: UpdateOutcome,
    pub invalidation: InvalidationAction,
    /// Source files re-extracted or newly extracted.
    pub reextracted: Vec<String>,
    /// Entrypoint ids reanalyzed (their direct plan recomputed).
    pub reanalyzed: Vec<String>,
    /// Entrypoint ids whose composition was recomputed.
    pub recomposed: Vec<String>,
    pub old_fingerprint: String,
    pub new_fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateOutcome {
    Published,
    Unchanged,
    Failed { failure: UpdateFailure },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateFailure {
    Read { path: String },
    Parse { entrypoint: String, reason: String },
    Analysis { entrypoint: String, reason: String },
}

fn failed_update(
    index: &RepoIndex,
    invalidation: InvalidationAction,
    failure: UpdateFailure,
) -> UpdateReport {
    UpdateReport {
        outcome: UpdateOutcome::Failed { failure },
        invalidation,
        reextracted: Vec::new(),
        reanalyzed: Vec::new(),
        recomposed: Vec::new(),
        old_fingerprint: index.fingerprint.clone(),
        new_fingerprint: index.fingerprint.clone(),
    }
}

fn persisted_snapshot_unchanged(previous: &RepoIndex, candidate: &RepoIndex) -> bool {
    candidate.fingerprint == previous.fingerprint
        && crate::store::save_index(candidate) == crate::store::save_index(previous)
}

fn dependencies_changed(dependencies: Option<&Vec<String>>, changed: &BTreeSet<String>) -> bool {
    dependencies.is_none_or(|dependencies| {
        dependencies
            .iter()
            .any(|dependency| changed.contains(dependency))
    })
}

fn candidate_failure(
    previous: Option<&RepoIndex>,
    candidate: &RepoIndex,
    affected_paths: &BTreeSet<String>,
    reanalyzed: &BTreeSet<String>,
    full_rebuild: bool,
) -> Option<UpdateFailure> {
    if let Some(skip) = candidate.skipped.iter().find(|skip| {
        skip.category == SkipCategory::Failure
            && (affected_paths.contains(&skip.path)
                || !previous.is_some_and(|previous| {
                    previous.skipped.iter().any(|old| {
                        old.path == skip.path
                            && old.category == skip.category
                            && old.reason == skip.reason
                    })
                }))
    }) {
        return Some(if skip.reason.starts_with("parse_error:") {
            UpdateFailure::Parse {
                entrypoint: skip.path.clone(),
                reason: "parse_error".into(),
            }
        } else {
            UpdateFailure::Read {
                path: skip.path.clone(),
            }
        });
    }
    for analyzed in &candidate.entrypoints {
        let affected = full_rebuild || reanalyzed.contains(&analyzed.entrypoint.id);
        let directly_affected = affected_paths.contains(&analyzed.entrypoint.source_file)
            || affected_paths.contains(&analyzed.entrypoint.evidence.file);
        match &analyzed.outcome {
            EntrypointOutcome::Failed { error } if affected => {
                let previously_accepted = !directly_affected
                    && previous.is_some_and(|previous| {
                        previous.find(&analyzed.entrypoint.id).is_some_and(|old| {
                            matches!(&old.outcome, EntrypointOutcome::Failed { error: old } if old == error)
                        })
                    });
                if !previously_accepted {
                    return Some(UpdateFailure::Analysis {
                        entrypoint: analyzed.entrypoint.id.clone(),
                        reason: error.clone(),
                    });
                }
            }
            EntrypointOutcome::Analyzed { plan } if affected => {
                if let Some(boundary) = plan
                    .boundaries
                    .iter()
                    .filter(|boundary| {
                        boundary.reason == effinterp_proto::BoundaryReason::PARSE_ERROR
                    })
                    .find(|boundary| {
                        directly_affected
                            || !previous.is_some_and(|previous| {
                                previous.find(&analyzed.entrypoint.id).is_some_and(|old| {
                                    old.plan().is_some_and(|plan| {
                                        plan.boundaries.iter().any(|old| old == *boundary)
                                    })
                                })
                            })
                    })
                {
                    return Some(UpdateFailure::Parse {
                        entrypoint: analyzed.entrypoint.id.clone(),
                        reason: boundary.reason.to_string(),
                    });
                }
            }
            EntrypointOutcome::Failed { .. }
            | EntrypointOutcome::Analyzed { .. }
            | EntrypointOutcome::LimitReached { .. } => {}
        }
    }
    None
}

/// Apply repository change events incrementally. The result is byte-equivalent
/// to a clean [`build_index`] of the final repository state (the correctness
/// oracle), while reusing cached module extractions for unchanged files and
/// cached entrypoint plans for entrypoints whose source did not change.
///
/// `root` must already reflect the changes on disk (added/modified files
/// readable, deleted files gone); the events only say which paths changed so
/// unchanged inputs are not re-read or re-analyzed.
fn apply_changes_in_place(
    index: &mut RepoIndex,
    root: &Path,
    limits: &IndexLimits,
    requested_invalidation: InvalidationAction,
) -> UpdateReport {
    let old_fingerprint = index.fingerprint.clone();
    let old_ruby_resolution = index.registry.ruby_resolution_digest();
    let old_derived_dependencies = index.derived_dependencies.clone();
    let old_entrypoints = index
        .entrypoints
        .iter()
        .map(|analyzed| effinterp_proto::canonical_json(&analyzed.entrypoint))
        .collect::<Vec<_>>();
    let old_launch_edges = index.launch_edges.clone();
    let old_state_evidence = effinterp_proto::canonical_json(&(
        &index.skipped,
        &index.skipped_dependencies,
        &index.skipped_roots,
        index.skips_truncated,
        &index.snapshot_state,
    ));

    let mut budget = IndexBudget::new(limits.repository);
    let mut discovery = discover(root, &limits.crawl, &mut budget, &limits.engine);
    discovery
        .entrypoints
        .sort_by(|left, right| left.id.cmp(&right.id));
    let admitted: BTreeSet<String> = discovery
        .manifest
        .iter()
        .map(|input| input.path.clone())
        .collect();
    let old_admitted: BTreeSet<String> = index
        .dependency_manifest
        .source_paths()
        .map(str::to_string)
        .collect();
    let manifest = discovery.manifest.clone();
    let current_manifest = dependency_manifest(
        &manifest,
        &discovery.skipped_sources,
        analyzer_build_digest(),
        &index.model_set,
        limits,
    );
    let changed_dependencies = index
        .dependency_manifest
        .changed_keys(&current_manifest)
        .into_iter()
        .collect::<BTreeSet<_>>();
    let source_membership_changed = old_admitted != admitted;

    // 1. Re-extract exactly the module summaries whose recorded dependency
    //    keys changed, plus newly admitted source modules.
    let mut reextracted = Vec::new();
    index.registry.bind_source_root(root, limits);
    index.registry.retain_admitted(&admitted);
    for file in index.registry.files.values() {
        let _ = budget.charge(0, file.summary.retained_bytes());
    }
    for input in &discovery.manifest {
        let output = format!("module:{}", input.path);
        if index.registry.files.contains_key(&input.path)
            && !dependencies_changed(old_derived_dependencies.get(&output), &changed_dependencies)
        {
            continue;
        }
        if input.path.ends_with(".py") && !index.registry.files.contains_key(&input.path) {
            if changed_dependencies.contains(&format!("source:{}", input.path)) {
                reextracted.push(input.path.clone());
            }
            continue;
        }
        if let Err(limit) = budget.charge(1, 0) {
            index.registry.files.remove(&input.path);
            if discovery.skipped.len() < limits.crawl.max_skips {
                discovery.skipped.push(SkippedPath {
                    path: input.path.clone(),
                    category: SkipCategory::Limit,
                    reason: limit.into(),
                });
            } else {
                discovery.skips_truncated = true;
            }
            continue;
        }
        if let Ok(content) = std::fs::read_to_string(root.join(&input.path))
            && index
                .registry
                .apply_source_change(&input.path, Some(&content))
        {
            reextracted.push(input.path.clone());
            let bytes = index
                .registry
                .files
                .get(&input.path)
                .map_or(0, |file| file.summary.retained_bytes());
            if let Err(limit) = budget.charge(0, bytes) {
                index.registry.files.remove(&input.path);
                if discovery.skipped.len() < limits.crawl.max_skips {
                    discovery.skipped.push(SkippedPath {
                        path: input.path.clone(),
                        category: SkipCategory::Limit,
                        reason: limit.into(),
                    });
                } else {
                    discovery.skips_truncated = true;
                }
            }
        }
    }

    // 2. Re-discover entrypoints (handles new/removed entrypoints and changed
    //    discovery inputs such as package scripts). Reuse a cached plan only
    //    when its recorded dependencies and current dependency shape agree.
    let engine = repo_engine(root, &limits.crawl, &manifest, limits.engine.clone());
    let mut old_plans = BTreeMap::new();
    for analyzed in index.entrypoints.drain(..) {
        old_plans.insert(analyzed.entrypoint.id.clone(), analyzed);
    }

    let mut reanalyzed = Vec::new();
    let entrypoints: Vec<AnalyzedEntrypoint> = discovery
        .entrypoints
        .into_iter()
        .map(|entrypoint| {
            let output = format!("entrypoint:{}", entrypoint.id);
            let old = old_plans.remove(&entrypoint.id);
            let reuse = old.as_ref().is_some_and(|old| {
                let Some(plan) = old.plan() else {
                    return false;
                };
                old.entrypoint.subject == entrypoint.subject
                    && old.entrypoint.source_cwd == entrypoint.source_cwd
                    && old_derived_dependencies.get(&output)
                        == Some(&entrypoint_dependencies(
                            &current_manifest,
                            &entrypoint,
                            Some(plan),
                            &discovery.launch_edges,
                        ))
                    && !dependencies_changed(
                        old_derived_dependencies.get(&output),
                        &changed_dependencies,
                    )
            });
            let outcome = if let Err(limit) = budget.charge(0, 0) {
                EntrypointOutcome::LimitReached {
                    limit: limit.into(),
                }
            } else if reuse {
                old.unwrap().outcome
            } else {
                reanalyzed.push(entrypoint.id.clone());
                let (outcome, stats) = analyze_entrypoint(&engine, &entrypoint);
                match budget.charge(stats.steps, 0) {
                    Ok(()) => outcome,
                    Err(limit) => EntrypointOutcome::LimitReached {
                        limit: limit.into(),
                    },
                }
            };
            let outcome = match &outcome {
                EntrypointOutcome::Analyzed { plan } => {
                    match budget.charge(0, effinterp_proto::canonical_json(plan).len() as u64) {
                        Ok(()) => outcome,
                        Err(limit) => EntrypointOutcome::LimitReached {
                            limit: limit.into(),
                        },
                    }
                }
                _ => outcome,
            };
            AnalyzedEntrypoint {
                entrypoint,
                outcome,
            }
        })
        .collect();

    let roots = registry_roots(
        entrypoints.iter().flat_map(|entrypoint| {
            std::iter::once(entrypoint.entrypoint.source_file.clone())
                .chain(entrypoint.entrypoint.package_inits.iter().cloned())
        }),
        &discovery.launch_edges,
    );
    let (materialized, materialization_skips) = index.registry.refresh_python_closure(
        root,
        &manifest,
        &roots,
        &mut budget,
        limits.crawl.max_skips,
    );
    reextracted.extend(materialized);
    let remaining_skips = limits
        .crawl
        .max_skips
        .saturating_sub(discovery.skipped.len());
    if materialization_skips.len() > remaining_skips {
        discovery.skips_truncated = true;
    }
    discovery
        .skipped
        .extend(materialization_skips.into_iter().take(remaining_skips));
    reextracted.sort();
    reextracted.dedup();

    index.registry.reindex_ruby_inputs(
        root,
        &discovery.manifest,
        &discovery.launch_edges,
        &mut budget,
    );
    let ruby_load_paths_changed = old_ruby_resolution != index.registry.ruby_resolution_digest();

    // 3. Recompose outputs invalidated by their recorded keys. Source-set
    //    changes recompose every output because package/module resolution can
    //    change even when an existing source file did not.
    index.entrypoints = entrypoints;
    let mut previous_composed = std::mem::take(&mut index.composed);
    let reanalyzed_set: BTreeSet<&str> = reanalyzed.iter().map(String::as_str).collect();
    let mut recomposed = Vec::new();
    for analyzed in &mut index.entrypoints {
        if let Err(limit) = budget.charge(0, 0) {
            analyzed.outcome = EntrypointOutcome::LimitReached {
                limit: limit.into(),
            };
            continue;
        }
        let id = &analyzed.entrypoint.id;
        let output = format!("composition:{id}");
        let invalidated = ruby_load_paths_changed
            || source_membership_changed
            || reanalyzed_set.contains(id.as_str())
            || dependencies_changed(old_derived_dependencies.get(&output), &changed_dependencies);
        if invalidated {
            let had_composition = previous_composed.remove(id).is_some();
            let file = &analyzed.entrypoint.source_file;
            if let Some(module) = index.registry.files.get(file) {
                let composition = compose_with_package_init(
                    &index.registry,
                    module,
                    analyzed.entrypoint.entry_function.as_deref(),
                    analyzed.entrypoint.registration.as_ref(),
                    &analyzed.entrypoint.package_inits,
                    limits.repository,
                );
                if !composition.effects.is_empty()
                    || !composition.boundaries.is_empty()
                    || !composition.resolved_calls.is_empty()
                {
                    recomposed.push(id.clone());
                    if let Err(limit) =
                        budget.charge(composition.budget.steps, composition.retained_bytes())
                    {
                        analyzed.outcome = EntrypointOutcome::LimitReached {
                            limit: limit.into(),
                        };
                    } else {
                        index.composed.insert(id.clone(), Arc::new(composition));
                    }
                } else if had_composition {
                    recomposed.push(id.clone());
                }
            } else if had_composition {
                recomposed.push(id.clone());
            }
        } else if let Some(composition) = previous_composed.remove(id) {
            if let Err(limit) = budget.charge(0, composition.retained_bytes()) {
                analyzed.outcome = EntrypointOutcome::LimitReached {
                    limit: limit.into(),
                };
            } else {
                index.composed.insert(id.clone(), composition);
            }
        }
    }
    let launched_sources: BTreeSet<&str> = discovery
        .launch_edges
        .iter()
        .map(|edge| edge.launched.as_str())
        .collect();
    for file in launched_sources {
        if let Err(limit) = budget.charge(0, 0) {
            limit_launched_entrypoints(
                &mut index.entrypoints,
                &discovery.launch_edges,
                &mut index.composed,
                file,
                limit,
            );
            continue;
        }
        let key = launch_composition_key(file);
        let output = format!("launch-composition:{file}");
        let invalidated = ruby_load_paths_changed
            || source_membership_changed
            || dependencies_changed(old_derived_dependencies.get(&output), &changed_dependencies);
        if invalidated {
            let had_composition = previous_composed.remove(&key).is_some();
            if let Some(module) = index.registry.files.get(file) {
                let composition = compose_callable(&index.registry, module, limits.repository);
                if !composition.effects.is_empty()
                    || !composition.boundaries.is_empty()
                    || !composition.resolved_calls.is_empty()
                {
                    recomposed.push(file.to_string());
                    if budget
                        .charge(composition.budget.steps, composition.retained_bytes())
                        .is_ok()
                    {
                        index.composed.insert(key, Arc::new(composition));
                    }
                } else if had_composition {
                    recomposed.push(file.to_string());
                }
            } else if had_composition {
                recomposed.push(file.to_string());
            }
        } else if let Some(composition) = previous_composed.remove(&key)
            && budget.charge(0, composition.retained_bytes()).is_ok()
        {
            index.composed.insert(key, composition);
        }
        if let Some(limit) = budget.saturated {
            limit_launched_entrypoints(
                &mut index.entrypoints,
                &discovery.launch_edges,
                &mut index.composed,
                file,
                limit,
            );
        }
    }
    index.go_root_effects = go_root_effects_all(
        &mut index.entrypoints,
        &index.registry,
        &mut index.composed,
        &mut budget,
    );
    recomposed.sort();
    recomposed.dedup();

    // 4. Rebuild dependency/state evidence from the current inputs.
    index.limits = limits.clone();
    index.dependency_manifest = current_manifest;
    index.skipped = discovery.skipped;
    index.skips_truncated = discovery.skips_truncated;
    index.launch_edges = discovery.launch_edges;
    index.snapshot_state = snapshot_state(
        &index.entrypoints,
        &index.skipped,
        index.skips_truncated,
        &index.composed,
        &index.launch_edges,
    );
    index.module_paths = index.registry.files.keys().cloned().collect();
    index.skipped_dependencies = skipped_dependencies(
        &index.dependency_manifest,
        &index.registry,
        &index.entrypoints,
        &index.composed,
        &index.launch_edges,
        &discovery.skipped_dependencies,
    );
    index.skipped_roots = discovery.skipped_roots;
    index.derived_dependencies = derived_dependencies(
        &index.dependency_manifest,
        &index.entrypoints,
        &index.module_paths,
        &index.composed,
        &index.launch_edges,
    );
    index.fingerprint = snapshot_id(&index.dependency_manifest);
    let entrypoints = index
        .entrypoints
        .iter()
        .map(|analyzed| effinterp_proto::canonical_json(&analyzed.entrypoint))
        .collect::<Vec<_>>();
    let state_evidence = effinterp_proto::canonical_json(&(
        &index.skipped,
        &index.skipped_dependencies,
        &index.skipped_roots,
        index.skips_truncated,
        &index.snapshot_state,
    ));
    let invalidation = if old_entrypoints != entrypoints
        || old_launch_edges != index.launch_edges
        || old_state_evidence != state_evidence
    {
        InvalidationAction::Rediscover
    } else if !recomposed.is_empty() {
        InvalidationAction::Recompose
    } else if !reanalyzed.is_empty() {
        InvalidationAction::Reanalyze
    } else if !reextracted.is_empty() {
        InvalidationAction::Reextract
    } else {
        requested_invalidation
    };

    UpdateReport {
        outcome: UpdateOutcome::Published,
        invalidation,
        reextracted,
        reanalyzed,
        recomposed,
        old_fingerprint,
        new_fingerprint: index.fingerprint.clone(),
    }
}

/// Apply changes through an isolated candidate and publish only after all work
/// succeeds. A failed update leaves every byte of the prior snapshot intact.
pub fn apply_changes(
    index: &mut RepoIndex,
    root: &Path,
    limits: &IndexLimits,
    changes: &[RepoChange],
) -> UpdateReport {
    apply_changes_controlled(index, root, limits, changes)
}

fn apply_changes_controlled(
    index: &mut RepoIndex,
    root: &Path,
    limits: &IndexLimits,
    changes: &[RepoChange],
) -> UpdateReport {
    let invalidation = if &index.limits != limits
        || limits.repository != RepositoryLimits::default()
        || index
            .entrypoints
            .iter()
            .any(|entrypoint| matches!(entrypoint.outcome, EntrypointOutcome::LimitReached { .. }))
    {
        InvalidationAction::Rebuild
    } else {
        changes
            .iter()
            .map(invalidation_action)
            .max()
            .unwrap_or(InvalidationAction::Rediscover)
    };

    let mut candidate;
    let mut report;
    if invalidation == InvalidationAction::Rebuild {
        candidate = build_index(root, limits.clone());
        report = UpdateReport {
            outcome: UpdateOutcome::Published,
            invalidation,
            reextracted: candidate.registry.files.keys().cloned().collect(),
            reanalyzed: candidate
                .entrypoints
                .iter()
                .map(|entrypoint| entrypoint.entrypoint.id.clone())
                .collect(),
            recomposed: candidate
                .composed
                .keys()
                .map(|key| {
                    key.strip_prefix(LAUNCH_COMPOSITION_PREFIX)
                        .unwrap_or(key)
                        .to_string()
                })
                .collect(),
            old_fingerprint: index.fingerprint.clone(),
            new_fingerprint: candidate.fingerprint.clone(),
        };
    } else {
        candidate = index.clone();
        report = apply_changes_in_place(&mut candidate, root, limits, invalidation);
    }

    let affected_paths: BTreeSet<String> = changes
        .iter()
        .filter_map(|change| change.path().map(str::to_string))
        .collect();
    let reanalyzed: BTreeSet<String> = report.reanalyzed.iter().cloned().collect();
    if let Some(failure) = candidate_failure(
        Some(index),
        &candidate,
        &affected_paths,
        &reanalyzed,
        invalidation == InvalidationAction::Rebuild,
    ) {
        return failed_update(index, invalidation, failure);
    }
    if persisted_snapshot_unchanged(index, &candidate) {
        report.outcome = UpdateOutcome::Unchanged;
        report.new_fingerprint = index.fingerprint.clone();
        return report;
    }

    *index = candidate;
    report.outcome = UpdateOutcome::Published;
    report.new_fingerprint = index.fingerprint.clone();
    report
}
