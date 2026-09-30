//! Helpers that several modules carried as byte-identical copies.

pub(crate) fn antecedent_origins(
    dag: &effinterp_proto::ProvenanceDag,
    roots: &[effinterp_proto::OccurrenceId],
) -> Vec<String> {
    let mut seen: std::collections::BTreeSet<_> = roots.iter().cloned().collect();
    let mut pending: Vec<_> = roots.to_vec();
    while let Some(id) = pending.pop() {
        for edge in dag.edges.iter().filter(|edge| edge.to == id) {
            if seen.insert(edge.from.clone()) {
                pending.push(edge.from.clone());
            }
        }
    }
    dag.nodes
        .iter()
        .filter(|node| seen.contains(&node.id))
        .flat_map(|node| {
            let mut names = vec![node.occurrence.origin.clone()];
            if let effinterp_proto::ProtocolProvenanceKind::CrossFileCall { from, into } =
                &node.evidence
            {
                names.push(from.clone());
                names.push(into.clone());
            }
            names
        })
        .collect()
}
