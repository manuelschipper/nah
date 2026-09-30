use super::*;

/// Forward query: every effect reachable from one entrypoint — direct AND
/// cross-file — with coverage and boundaries, from the canonical surface.
/// Returns None if the entrypoint id is unknown or failed.
pub fn effects_of(index: &RepoIndex, entrypoint_id: &str) -> Option<RepoQueryEnvelope> {
    let surface = effective_surface(index, entrypoint_id)?;
    let mut builder = EnvelopeBuilder::for_entrypoint(index, entrypoint_id);
    let mut effects = Vec::new();
    for effect in &surface.effects {
        effects.push(builder.fact(entrypoint_id, effect));
    }
    let mut boundary_rows = Vec::new();
    for boundary in &surface.boundaries {
        let (boundary_id, provenance_roots, dispatch) =
            builder.boundary(boundary, &surface.source_file);
        boundary_rows.push(BoundaryRow {
            occurrences: boundary.occurrences,
            exemplar_paths: boundary.exemplar_paths.clone(),
            boundary_id: effinterp_proto::BoundaryId(boundary_id),
            reason: boundary.reason.clone(),
            domains: protocol_domains(&boundary.domains),
            affected_resource: boundary.affected_resource.as_ref().map(protocol_resource),
            display_domains: boundary.domains.clone(),
            detail: boundary.detail.clone(),
            limit: boundary.limit.clone(),
            dispatch,
            provenance_roots,
        });
    }
    effects.sort_by_cached_key(fact_sort_key);
    effects.dedup();
    boundary_rows.sort_by_cached_key(|boundary| {
        serde_json::to_string(&serde_json::json!([
            boundary.reason,
            boundary.domains,
            boundary.affected_resource,
            boundary.detail,
            boundary.limit,
            boundary.dispatch,
            boundary.boundary_id,
        ]))
        .expect("boundary key serializes")
    });
    boundary_rows.dedup_by(|a, b| {
        a.boundary_id == b.boundary_id
            && a.domains == b.domains
            && a.affected_resource == b.affected_resource
            && a.detail == b.detail
            && a.limit == b.limit
            && a.dispatch == b.dispatch
    });
    let coverage = surface.coverage.clone();
    let mut report = builder.finish(
        Payload::Effects(EffectsReport {
            entrypoint: entrypoint_id.to_string(),
            effects,
            coverage: BTreeMap::new(),
            boundaries: boundary_rows,
        }),
        coverage,
        None,
    );
    if let Payload::Effects(payload) = &mut report.payload {
        payload.coverage = report.coverage.domains.clone();
    }
    report.reseal();
    Some(report)
}
