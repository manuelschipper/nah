use std::collections::{BTreeMap, BTreeSet};

use effinterp_proto::{
    CoverageLevel, Indeterminate, Match, Payload, ReachHit, ReachReport, RepoQueryEnvelope,
    ResourceExpr,
};

use super::{EnvelopeBuilder, operation_matches, protocol_resource, worst_coverage};
use crate::index::RepoIndex;
use crate::resource::ResourceSelector;
use crate::surface::effective_surface;

/// Reverse query: which entrypoints may affect the selected resource. Returns
/// concrete/symbolic matches and — crucially — entrypoints whose opacity in the
/// queried domain leaves the answer indeterminate. `operation` restricts the
/// matches to one operation, domain, or verb ("what can WRITE this path");
/// indeterminate entrypoints are unaffected — opacity cannot rule the
/// operation out either.
pub fn reach(
    index: &RepoIndex,
    selector: &ResourceSelector,
    operation: Option<&str>,
) -> RepoQueryEnvelope {
    let domain = selector.domain().to_string();
    let mut matches = Vec::new();
    let mut indeterminate = Vec::new();
    let mut builder = EnvelopeBuilder::new(index);
    let mut coverage = BTreeMap::new();

    for analyzed in &index.entrypoints {
        let id = &analyzed.entrypoint.id;
        let Some(surface) = effective_surface(index, id) else {
            continue;
        };
        let source_file = surface.source_file.clone();
        coverage
            .entry(domain.clone())
            .or_insert(CoverageLevel::Full);
        if let Some(level) = surface.coverage.get(&domain) {
            coverage
                .entry(domain.clone())
                .and_modify(|current| *current = worst_coverage(*current, *level))
                .or_insert(*level);
        }

        // Effects on the canonical surface (direct + cross-file), filtered by
        // the selector's realm so a host query is never satisfied by a
        // container-realm effect.
        for e in &surface.effects {
            if let Some(f) = operation
                && !operation_matches(&e.operation, f)
            {
                continue;
            }
            let fact = builder.fact(id, e);
            match selector.match_effect(&fact) {
                matched @ Match::Satisfied { .. } => matches.push(ReachHit { fact, matched }),
                matched @ Match::Indeterminate { .. } => {
                    indeterminate.push(Indeterminate::Effect {
                        fact,
                        domain: domain.clone(),
                        coverage: *surface
                            .coverage
                            .get(&domain)
                            .unwrap_or(&CoverageLevel::None),
                        matched,
                    })
                }
                Match::NotSatisfied => (),
            }
        }

        // Any boundary covering the queried domain leaves this entrypoint
        // unable to exclude the resource. Every boundary that declares the
        // domain is retained as envelope evidence even when its typed resource
        // narrows it out of the payload: the coverage this query reports for
        // the domain is exactly what those boundaries caused.
        for b in &surface.boundaries {
            if !b.domains.iter().any(|have| have == &domain) {
                continue;
            }
            // Dataflow boundaries are admitted without an effect-domain coverage
            // claim; this surface cannot claim coverage for their causal analysis.
            let level = if domain == "dataflow" && !surface.coverage.contains_key(&domain) {
                CoverageLevel::None
            } else {
                *surface
                    .coverage
                    .get(&domain)
                    .expect("a boundary domain has coverage")
            };
            coverage
                .entry(domain.clone())
                .and_modify(|current| *current = worst_coverage(*current, level));
            let (boundary_id, provenance_roots, dispatch) = builder.boundary(b, &source_file);
            if boundary_matches_selector(&b.domains, b.affected_resource.as_ref(), selector) {
                indeterminate.push(Indeterminate::Boundary {
                    evidence: effinterp_proto::BoundaryIndeterminate {
                        boundary_id: effinterp_proto::BoundaryId(boundary_id),
                        entrypoint: id.clone(),
                        domain: domain.clone(),
                        coverage: level,
                        boundary_reason: b.reason.clone(),
                        affected_resource: b.affected_resource.as_ref().map(protocol_resource),
                        boundary_detail: b.detail.clone(),
                        limit: b.limit.clone(),
                        dispatch,
                        source_file: source_file.clone(),
                        provenance_roots,
                    },
                });
            }
        }
    }

    matches.sort_by_cached_key(effinterp_proto::canonical_json);
    matches.dedup();
    indeterminate.sort_by_cached_key(effinterp_proto::canonical_json);
    let mut seen = BTreeSet::new();
    indeterminate.retain(|row| match row {
        Indeterminate::Boundary { evidence } => seen.insert(effinterp_proto::canonical_json(&(
            &evidence.entrypoint,
            &evidence.boundary_reason,
            &evidence.boundary_detail,
            &evidence.affected_resource,
        ))),
        Indeterminate::Effect { .. } => true,
    });
    indeterminate.dedup();
    builder.finish(
        Payload::Reach(ReachReport {
            selector: render_selector(selector),
            domain,
            operation: operation.map(str::to_string),
            matches,
            indeterminate,
        }),
        coverage,
        None,
    )
}

/// The canonical text form of a selector, so a query echoes the identity it
/// actually applied rather than the caller's spelling.
fn render_selector(selector: &ResourceSelector) -> String {
    format!(
        "{}/{}:{}",
        selector.realm.render(),
        selector.family,
        selector.needle
    )
}

fn boundary_matches_selector(
    domains: &[String],
    affected_resource: Option<&ResourceExpr>,
    selector: &ResourceSelector,
) -> bool {
    domains.iter().any(|domain| domain == selector.domain())
        && affected_resource.is_none_or(|resource| {
            // A resource in another domain can identify the missing source, not
            // the hidden effect's target. It cannot narrow the declared domain.
            if effinterp_proto::resource_domain(resource) != Some(selector.domain()) {
                return true;
            }
            let Some(set) = selector.scope_set() else {
                return true;
            };
            // No realm is established for this boundary. Only resource disjointness excludes it.
            effinterp_proto::scope_intersects(
                &effinterp_proto::Scope { realm: None, set },
                &effinterp_proto::QualifiedExpr {
                    realm: effinterp_proto::ExecutionRealm::Host,
                    expr: resource.clone(),
                },
                &effinterp_proto::Bindings::none(effinterp_proto::PathPlatform::Posix),
            ) != Match::NotSatisfied
        })
}
