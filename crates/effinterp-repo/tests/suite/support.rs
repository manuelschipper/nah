//! Helpers that several modules carried as byte-identical copies.

use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use effinterp_proto::ResourceExpr;
use effinterp_repo::{IndexLimits, ResourceSelector, build_index, effects_of, reach};

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

static NEXT_TEMP_REPO: AtomicU64 = AtomicU64::new(0);

/// Writes `files` into a fresh temporary repository whose directory name is
/// unique per call, so tests sharing a `tag` never share a root.
pub(crate) fn temp_repo(tag: &str, files: &[(&str, &str)]) -> PathBuf {
    let nonce = NEXT_TEMP_REPO.fetch_add(1, Ordering::Relaxed);
    let root = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("{tag}-{}-{nonce}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    for (rel, content) in files {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }
    root
}

/// Writes one repository file, creating its parent directories.
pub(crate) fn write_file(root: &Path, rel: &str, content: &str) {
    let path = root.join(rel);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, content).unwrap();
}

/// The filesystem deletes `entry` reaches, as (resource, originating file).
pub(crate) fn deletes(root: &Path, entry: &str) -> Vec<(String, String)> {
    let idx = build_index(root, IndexLimits::default());
    let report = effects_of(&idx, entry).expect("entry analyzed");
    report
        .payload
        .as_effects()
        .unwrap()
        .effects
        .iter()
        .filter(|e| e.operation.as_str() == "filesystem.delete")
        .map(|e| {
            (
                effinterp_proto::display_resource_with_scope(&e.resource),
                e.origin
                    .as_ref()
                    .expect("effect origin")
                    .source_file
                    .clone(),
            )
        })
        .collect()
}

/// Whether any entrypoint of the repository deletes `fs:/important`.
pub(crate) fn deletes_important(root: &Path) -> bool {
    let idx = build_index(root, IndexLimits::default());
    reach(
        &idx,
        &ResourceSelector::parse("fs:/important").unwrap(),
        None,
    )
    .payload
    .as_reach()
    .unwrap()
    .matches
    .iter()
    .any(|h| h.fact.operation.as_str() == "filesystem.delete")
}

/// The ids of every discovered entrypoint, in index order.
pub(crate) fn ids(idx: &effinterp_repo::RepoIndex) -> Vec<String> {
    idx.entrypoints
        .iter()
        .map(|e| e.entrypoint.id.clone())
        .collect()
}

/// The effect's resource as displayed, without its scope.
pub(crate) fn display(effect: &effinterp_proto::EffectFact) -> String {
    effinterp_proto::display_resource(&effect.resource)
}

/// The source file an effect originates in, or "" when it has no origin.
pub(crate) fn origin(effect: &effinterp_proto::EffectFact) -> &str {
    effect
        .origin
        .as_ref()
        .map(|origin| origin.source_file.as_str())
        .unwrap_or("")
}

/// The value of a literal resource expression.
pub(crate) fn literal(expr: &ResourceExpr) -> Option<&str> {
    match expr {
        ResourceExpr::Literal { value } => Some(value),
        _ => None,
    }
}
