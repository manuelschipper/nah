//! Composition accumulation: how a walk's effects, boundaries, transfers,
//! dependencies and coverage are pushed into a [`Composition`], deduplicated
//! by evidence key, and finalized into deterministic order.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::hash::{Hash, Hasher};

use effinterp_engine::{Assurance, TransferBinding};
use effinterp_proto::{
    BoundaryReason, CalleeReference, CoverageLevel, Effect, Modality, ResourceExpr,
};

use super::budget;
use super::lifecycle::LifecycleState;
use super::{
    BoundaryOccurrence, ComposedBoundary, ComposedEffect, ComposedOccurrence, Composition,
    EffectOccurrence,
};
use crate::dispatch::DispatchVia;

pub(super) fn effect_evidence_key(effect: &Effect) -> String {
    let mut effect = effect.clone();
    effect.condition = effect
        .condition
        .as_ref()
        .map(effinterp_proto::Condition::identity);
    effinterp_proto::canonical_json(&effect)
}

pub(super) fn composed_effect_id(effect: &Effect) -> effinterp_proto::EffectId {
    effinterp_proto::EffectId::derive(&effinterp_proto::EffectIdentity {
        operation: effect.operation.clone(),
        resource: effect.resource.clone(),
        realm: effect.realm.clone(),
        modality: effect.modality,
        request_assurance: effect.request_assurance,
        attributes: effect.attributes.clone(),
        condition: None,
        occurrence: effinterp_proto::EffectOccurrence {
            subject_digest: effinterp_proto::stable_hash("effinterp/repo-composition/v1", &()),
            realm: effect.realm.clone(),
            ordinal: 0,
        },
    })
}

// Recursive fixed-point caches retain evidence per origin and dispatch.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct EffectOccurrenceKey {
    pub(super) source_file: String,
    pub(super) effect: effinterp_proto::EffectId,
    pub(super) via_dispatch: Option<DispatchVia>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ComposedBoundaryKey {
    class: effinterp_proto::BoundaryClass,
    reason: BoundaryReason,
    detail: String,
    source_file: Option<String>,
    callee: Option<CalleeReference>,
    domains: Vec<String>,
    affected_resource: Option<ResourceExpr>,
    limit: Option<String>,
    via_dispatch: Option<DispatchVia>,
}

impl Hash for ComposedBoundaryKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.class.hash(state);
        self.reason.as_str().hash(state);
        self.detail.hash(state);
        self.source_file.hash(state);
        self.callee.hash(state);
        self.domains.hash(state);
        self.affected_resource
            .as_ref()
            .map(effinterp_proto::canonical_json)
            .hash(state);
        self.limit.hash(state);
        self.via_dispatch.hash(state);
    }
}

#[derive(Debug, Clone, Default)]
pub(super) struct BoundaryCollection {
    pub(super) rows: Vec<ComposedBoundary>,
    pub(super) positions: HashMap<ComposedBoundaryKey, usize>,
    pub(super) paths: HashMap<ComposedBoundaryKey, BTreeSet<Vec<String>>>,
}

pub(super) fn boundary_key(boundary: &ComposedBoundary) -> ComposedBoundaryKey {
    ComposedBoundaryKey {
        class: boundary.class,
        reason: boundary.reason.clone(),
        detail: boundary.detail.clone(),
        source_file: boundary.source_file.clone(),
        callee: boundary.callee.clone(),
        domains: boundary.domains.clone(),
        affected_resource: boundary.affected_resource.clone(),
        limit: boundary.limit.clone(),
        via_dispatch: boundary.via_dispatch.clone(),
    }
}

pub(super) fn merge_boundary(
    existing: &mut ComposedBoundary,
    incoming: &ComposedBoundary,
    count: usize,
) {
    existing.occurrences = count as u32;
    existing
        .exemplar_paths
        .extend(incoming.exemplar_paths.iter().cloned());
    existing
        .exemplar_paths
        .sort_by(|a, b| a.len().cmp(&b.len()).then(a.cmp(b)));
    existing.exemplar_paths.dedup();
    existing.exemplar_paths.truncate(4);
}

pub(super) fn push_composed_boundary(out: &mut Composition, mut boundary: BoundaryOccurrence) {
    // Attach the call site before coalescing so counts, memo captures, and
    // exemplar paths all retain the frame where composition stopped.
    if let Some((path, call)) = &out.boundary_call
        && boundary.path == *path
    {
        boundary.path.push(call.clone());
    }
    let paths = vec![boundary.path.clone()];
    push_coalesced_boundary(out, boundary.into(), &paths);
}

pub(super) fn push_coalesced_boundary(
    out: &mut Composition,
    mut boundary: ComposedBoundary,
    paths: &[Vec<String>],
) {
    boundary.exemplar_paths = paths.to_vec();
    boundary
        .exemplar_paths
        .sort_by(|a, b| a.len().cmp(&b.len()).then(a.cmp(b)));
    boundary.exemplar_paths.dedup();
    boundary.exemplar_paths.truncate(4);
    let key = boundary_key(&boundary);
    // Capture each callable's own evidence, even when the global row already exists.
    for collection in &mut out.memo_boundaries {
        if collection.positions.contains_key(&key)
            || collection.rows.len() < out.budget.limits.max_composed_boundaries
        {
            collection
                .paths
                .entry(key.clone())
                .or_default()
                .extend(paths.iter().cloned());
        }
        if let Some(index) = collection.positions.get(&key) {
            merge_boundary(
                &mut collection.rows[*index],
                &boundary,
                collection.paths[&key].len(),
            );
        } else if collection.rows.len() < out.budget.limits.max_composed_boundaries {
            collection
                .positions
                .insert(key.clone(), collection.rows.len());
            let mut captured = boundary.clone();
            captured.occurrences = collection.paths[&key].len() as u32;
            collection.rows.push(captured);
        }
    }
    if out.boundary_keys.contains_key(&key)
        || out.boundaries.len() < out.budget.limits.max_composed_boundaries
        || boundary.reason == BoundaryReason::LIMIT_SATURATED
    {
        out.boundary_paths
            .entry(key.clone())
            .or_default()
            .extend(paths.iter().cloned());
    }
    if let Some(index) = out.boundary_keys.get(&key) {
        merge_boundary(
            &mut out.boundaries[*index],
            &boundary,
            out.boundary_paths[&key].len(),
        );
    } else if boundary.reason == BoundaryReason::LIMIT_SATURATED
        || out.boundaries.len() < out.budget.limits.max_composed_boundaries
    {
        boundary.occurrences = out.boundary_paths[&key].len() as u32;
        out.boundary_keys.insert(key, out.boundaries.len());
        out.boundaries.push(boundary);
    } else {
        budget::report_limit(
            out,
            &boundary.exemplar_paths[0],
            "repository.max_composed_boundaries",
        );
    }
}

pub(super) fn push_dependency(out: &mut Composition, dependency: String) {
    if out.dep_keys.insert(dependency.clone()) {
        out.deps.push(dependency);
    }
}

pub(super) fn push_coverage(out: &mut Composition, coverage: (String, CoverageLevel)) {
    if !out.coverage.contains(&coverage) {
        out.coverage.push(coverage);
    }
}

/// Occurrence multiplicity keyed by effect, operation, causal path, assurance, and dispatch.
pub(super) type OccurrenceCounts =
    BTreeMap<(usize, String, Vec<String>, Assurance, Option<DispatchVia>), usize>;

// A round contributes the maximum multiplicity observed at each causal path,
// rather than adding another copy of every fact from earlier rounds. Distinct
// calls within one walk still contribute separate occurrences at the same path.
#[derive(Debug, Clone)]
pub(super) struct RecursiveOccurrences {
    previous: OccurrenceCounts,
    current: OccurrenceCounts,
}

impl RecursiveOccurrences {
    pub(super) fn new(occurrences: &[ComposedOccurrence]) -> Self {
        let mut previous = BTreeMap::new();
        for occurrence in occurrences {
            *previous
                .entry((
                    occurrence.effect,
                    occurrence.source_file.clone(),
                    occurrence.path.clone(),
                    occurrence.assurance,
                    occurrence.via_dispatch.clone(),
                ))
                .or_default() += 1;
        }
        Self {
            previous,
            current: BTreeMap::new(),
        }
    }
}

pub(super) fn push_composed_effect(out: &mut Composition, mut effect: EffectOccurrence) -> bool {
    if let (Some(condition), Some(instance)) =
        (&mut effect.effect.condition, &out.walk_call_instance)
    {
        condition.rebind(instance);
    }
    effect.effect.condition = effinterp_proto::Condition::compose(
        effect
            .effect
            .condition
            .iter()
            .chain(out.walk_condition.iter()),
    );
    push_bound_composed_effect(out, effect)
}

pub(super) fn push_bound_composed_effect(
    out: &mut Composition,
    mut effect: EffectOccurrence,
) -> bool {
    if out.budget.saturated.is_some() {
        return false;
    }
    if out.recursive_round {
        effect.effect.modality = Modality::May;
        effect.effect.condition = Some(effinterp_proto::Condition::Widened);
    }
    if effect
        .effect
        .condition
        .as_ref()
        .is_some_and(effinterp_proto::Condition::is_widened)
    {
        effect.effect.modality = Modality::May;
        if !out
            .boundaries
            .iter()
            .any(|boundary| boundary.limit.as_deref() == Some("max_causal_condition"))
        {
            push_composed_boundary(
                out,
                BoundaryOccurrence {
                    class: effinterp_proto::BoundaryClass::Limit,
                    reason: BoundaryReason::LIMIT_SATURATED,
                    detail: "causal condition composition widened".to_string(),
                    source_file: Some(effect.source_file.clone()),
                    callee: None,
                    domains: vec!["dataflow".to_string()],
                    affected_resource: None,
                    limit: Some("max_causal_condition".to_string()),
                    path: effect.path.clone(),
                    via_dispatch: effect.via_dispatch.clone(),
                },
            );
            push_coverage(out, ("dataflow".to_string(), CoverageLevel::Partial));
        }
    }
    if out.force_may || !out.required {
        effect.effect.modality = Modality::May;
    }
    if effect.assurance != Assurance::Exact
        || effect
            .effect
            .condition
            .as_ref()
            .is_some_and(effinterp_proto::Condition::is_widened)
    {
        effect.effect.request_assurance = effinterp_proto::RequestAssurance::Conservative;
    }
    let key = composed_effect_id(&effect.effect);
    let index = out
        .effect_positions
        .get(&key)
        .copied()
        .unwrap_or(out.effects.len());
    // Inner rounds must suppress their own iteration duplicates before an
    // enclosing round counts this as one of its calls.
    for round in out.recursive_occurrences.iter_mut().rev() {
        let occurrence = (
            index,
            effect.source_file.clone(),
            effect.path.clone(),
            effect.assurance,
            effect.via_dispatch.clone(),
        );
        let count = round.current.entry(occurrence.clone()).or_default();
        *count += 1;
        if *count <= round.previous.get(&occurrence).copied().unwrap_or_default() {
            return true;
        }
    }
    if index == out.effects.len() && !budget::reserve_new_effect(out, &effect.path) {
        return false;
    }
    let condition = effect.effect.condition.clone();
    if index == out.effects.len() {
        effect.effect.condition = condition
            .as_ref()
            .map(|_| effinterp_proto::Condition::Widened);
        effect.effect.id = key.clone();
        out.effect_positions.insert(key, index);
        out.effects.push(ComposedEffect {
            effect: effect.effect,
            occurrences: 0,
            unconditional_occurrences: 0,
        });
    }
    if condition.is_none() {
        out.effects[index].unconditional_occurrences += 1;
        out.effects[index].effect.condition = None;
    }
    out.effects[index].occurrences = out.effects[index].occurrences.saturating_add(1);
    out.occurrences += 1;
    if out.occurrence_effects.len() < out.budget.limits.max_composed_occurrences {
        out.occurrence_effects.push(ComposedOccurrence {
            effect: index,
            condition,
            source_file: effect.source_file,
            path: effect.path,
            assurance: effect.assurance,
            via_dispatch: effect.via_dispatch,
        });
    } else {
        budget::report_limit(out, &effect.path, "repository.max_composed_occurrences");
    }
    true
}

/// Push an effect and report the occurrence slot it landed in, if it produced
/// a new occurrence. The boolean keeps `push_composed_effect`'s meaning: false
/// means the traversal budget is exhausted and the caller must stop.
pub(super) fn push_composed_effect_slot(
    out: &mut Composition,
    effect: EffectOccurrence,
) -> (bool, Option<usize>) {
    let before = out.occurrence_effects.len();
    let retained = push_composed_effect(out, effect);
    let slot = (out.occurrence_effects.len() > before).then(|| out.occurrence_effects.len() - 1);
    (retained, slot)
}

/// Record one source-to-destination pairing over composed occurrence slots.
/// Bindings are bounded by the same ceiling as occurrence rows, so a
/// saturated walk keeps its endpoint effects and simply carries no pairing.
pub(super) fn push_composed_transfer(out: &mut Composition, binding: TransferBinding) {
    let slots = out.occurrence_effects.len() as u32;
    if binding.source >= slots || binding.destination >= slots {
        return;
    }
    if binding.source == binding.destination {
        return;
    }
    if out.transfers.len() >= out.budget.limits.max_composed_occurrences {
        return;
    }
    if !out.transfers.contains(&binding) {
        out.transfers.push(binding);
    }
}

/// Replay a summary's own transfer pairings against the composed occurrence
/// slots its effects landed in. A binding whose endpoint effect was not
/// composed (a template skipped, a budget reached) contributes nothing rather
/// than a pairing pointing at an unrelated occurrence.
pub(super) fn replay_summary_transfers(
    out: &mut Composition,
    transfers: &[TransferBinding],
    slots: &[Option<usize>],
) {
    for binding in transfers {
        let Some(Some(source)) = slots.get(binding.source as usize).copied() else {
            continue;
        };
        let Some(Some(destination)) = slots.get(binding.destination as usize).copied() else {
            continue;
        };
        push_composed_transfer(out, TransferBinding::new(source as u32, destination as u32));
    }
}

pub(super) fn rebuild_effect_positions(out: &mut Composition) {
    out.effect_positions = out
        .effects
        .iter()
        .enumerate()
        .map(|(index, effect)| (composed_effect_id(&effect.effect), index))
        .collect();
}

pub(super) fn remove_composed_occurrence(out: &mut Composition, slot: usize) {
    out.memo.clear();
    let occurrence = out.occurrence_effects.remove(slot);
    let index = occurrence.effect;
    out.effects[index].occurrences -= 1;
    if occurrence.condition.is_none() {
        out.effects[index].unconditional_occurrences -= 1;
        if out.effects[index].unconditional_occurrences == 0 {
            out.effects[index].effect.condition = Some(effinterp_proto::Condition::Widened);
        }
    }
    out.occurrences -= 1;
    let removed_identity = out.effects[index].occurrences == 0;
    if removed_identity {
        out.effects.remove(index);
        for occurrence in &mut out.occurrence_effects {
            if occurrence.effect > index {
                occurrence.effect -= 1;
            }
        }
    }
    for round in &mut out.recursive_occurrences {
        for counts in [&mut round.previous, &mut round.current] {
            if let Some(count) = counts.get_mut(&(
                index,
                occurrence.source_file.clone(),
                occurrence.path.clone(),
                occurrence.assurance,
                occurrence.via_dispatch.clone(),
            )) {
                *count = count.saturating_sub(1);
            }
            if removed_identity {
                *counts = std::mem::take(counts)
                    .into_iter()
                    .filter_map(
                        |((effect, source_file, path, assurance, via_dispatch), count)| {
                            (effect != index).then(|| {
                                (
                                    (
                                        effect - usize::from(effect > index),
                                        source_file,
                                        path,
                                        assurance,
                                        via_dispatch,
                                    ),
                                    count,
                                )
                            })
                        },
                    )
                    .collect();
            }
        }
    }
    // Remove pairings with the replaced occurrence and rebase retained slots.
    let slot = slot as u32;
    out.transfers
        .retain(|binding| binding.source != slot && binding.destination != slot);
    for binding in &mut out.transfers {
        binding.source -= u32::from(binding.source > slot);
        binding.destination -= u32::from(binding.destination > slot);
    }
    rebuild_effect_positions(out);
}

pub(super) fn finalize(out: &mut Composition) {
    out.resolved_decorators.sort();
    out.resolved_decorators.dedup();
    out.boundaries.retain(|boundary| {
        boundary.reason != BoundaryReason::UNRESOLVED_DECORATOR
            || !out.resolved_decorators.iter().any(|resolved| {
                boundary.source_file.as_deref().is_some_and(|source_file| {
                    resolved.matches_boundary(
                        source_file,
                        boundary.callee.as_ref(),
                        Some(&boundary.detail),
                    )
                })
            })
    });
    out.resolved_calls.sort_by(|left, right| {
        (&left.source_file, &left.callee).cmp(&(&right.source_file, &right.callee))
    });
    out.resolved_calls.dedup();
    out.resolved_calls
        .retain(|resolved| !out.unresolved_calls.contains(resolved));
    out.unresolved_calls = Vec::new();
    out.boundaries.retain(|boundary| {
        (boundary.reason != BoundaryReason::UNRESOLVED_CALL
            && boundary.reason != BoundaryReason::UNMODELED_IMPORT)
            || !boundary
                .source_file
                .as_ref()
                .zip(boundary.callee.as_ref())
                .is_some_and(|(source_file, callee)| {
                    out.resolved_calls
                        .binary_search_by(|resolved| {
                            (&resolved.source_file, &resolved.callee).cmp(&(source_file, callee))
                        })
                        .is_ok()
                })
    });
    out.boundary_keys = out
        .boundaries
        .iter()
        .enumerate()
        .map(|(index, boundary)| (boundary_key(boundary), index))
        .collect();
    let mut boundary_evidence: HashSet<(Vec<String>, String)> = out
        .boundaries
        .iter()
        .flat_map(|boundary| {
            out.boundary_paths
                .get(&boundary_key(boundary))
                .into_iter()
                .flatten()
                .flat_map(|path| {
                    boundary
                        .domains
                        .iter()
                        .map(move |domain| (path.clone(), domain.clone()))
                })
        })
        .collect();
    let domains: BTreeSet<_> = out
        .coverage
        .iter()
        .map(|(domain, _)| domain.clone())
        .collect();
    for (path, claims) in std::mem::take(&mut out.coverage_segments) {
        for (domain, level) in &claims {
            if *level != CoverageLevel::Full
                && !boundary_evidence.contains(&(path.clone(), domain.clone()))
            {
                boundary_evidence.insert((path.clone(), domain.clone()));
                push_composed_boundary(
                    out,
                    BoundaryOccurrence {
                        class: effinterp_proto::BoundaryClass::Unmodeled,
                        reason: BoundaryReason::FRONTEND_PARTIAL,
                        detail: "contributing function coverage remains incomplete".to_string(),
                        source_file: None,
                        callee: None,
                        domains: vec![domain.clone()],
                        affected_resource: None,
                        limit: None,
                        path: path.clone(),
                        via_dispatch: None,
                    },
                );
            }
        }
        let missing: Vec<_> = domains
            .iter()
            .filter(|domain| !claims.iter().any(|(claimed, _)| claimed == *domain))
            .cloned()
            .collect();
        if !missing.is_empty() {
            push_composed_boundary(
                out,
                BoundaryOccurrence {
                    class: effinterp_proto::BoundaryClass::Unmodeled,
                    reason: BoundaryReason::FRONTEND_PARTIAL,
                    detail: "contributing function summary makes no claim in these domains"
                        .to_string(),
                    source_file: None,
                    callee: None,
                    domains: missing.clone(),
                    affected_resource: None,
                    limit: None,
                    path,
                    via_dispatch: None,
                },
            );
            for domain in missing {
                push_coverage(out, (domain, CoverageLevel::Partial));
            }
        }
    }
    out.deps.sort();
    out.deps.dedup();
    out.memo = HashMap::new();
    out.effect_positions = HashMap::new();
    out.boundary_keys = HashMap::new();
    out.boundary_paths = HashMap::new();
    out.dep_keys = HashSet::new();
    out.executed = HashSet::new();
    out.lifecycle = LifecycleState::default();
    out.walk_via_dispatch = None;
}
