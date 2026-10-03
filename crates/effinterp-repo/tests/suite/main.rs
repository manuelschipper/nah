//! Repository and analysis semantics reached through the effinterp-repo
//! library: indexing, incremental updates, and the forward and reverse queries.
#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

mod analysis_v1;
mod canonical;
mod canonical_semantics;
mod composition_dispatch_entrypoints;
mod composition_launch;
mod composition_reexports_process;
mod cross_lang_resolve;
mod cross_module;
mod discovery_roots;
mod domain_family_registry;
mod domain_universe;
mod effect_ir_facts;
mod effect_ir_lifecycle;
mod effect_ir_linker;
mod effect_ir_surface;
mod exec_reach_probe;
mod execution_reachability;
mod fuzz_selector;
mod go_dispatch;
mod import_resolution;
mod incremental_oracle;
mod index;
mod index_budget;
mod index_correctness;
mod index_store;
mod java_instance_dispatch;
mod java_qualified_edges;
mod js_member_resolution;
mod js_reexports;
mod js_workspace;
mod local_import_precedence;
mod model_identity;
mod north_star_polyglot;
mod packaging_entrypoints;
mod php_autoload;
mod python_import_semantics;
mod python_instance_dispatch;
mod python_local_imports;
mod python_src_layout;
mod qualified_call_edges;
mod query;
mod query_surface;
mod realm_identity;
mod realm_namespace;
mod recursion_fixpoint;
mod repo;
mod repo_fixtures;
mod resource_algebra;
mod resource_query_precision;
mod resource_transfer;
mod ruby_compose;
mod rust_dispatch;
mod script_discovery;
mod support;

use std::path::Path;

use effinterp_proto::{
    CausalityGraph, EffectFact, ExecutionGraph, ExecutionNodeRef, ExecutionRealm, OccurrenceId,
    Operation, RepoQueryEnvelope, ResourceExpr,
};
use effinterp_repo::{
    EffectiveBoundary, IndexLimits, RepoIndex, build_index, effective_surface, effects_of,
};

/// A directory analyzed on demand.
fn live(root: &Path) -> RepoIndex {
    build_index(root, IndexLimits::default())
}

/// Effects on every entrypoint's forward surface that originate in `file`, or
/// in `file:function` when a function is named: a direct effect of the file
/// matches on the file alone, and a composed effect matches when its call path
/// or provenance entered that function.
fn origin_effects(index: &RepoIndex, file: &str, function: Option<&str>) -> Vec<EffectFact> {
    let mut effects = Vec::new();
    for analyzed in &index.entrypoints {
        let Some(report) = effects_of(index, &analyzed.entrypoint.id) else {
            continue;
        };
        for fact in &report.payload.as_effects().unwrap().effects {
            if fact
                .origin
                .as_ref()
                .map(|origin| origin.source_file.as_str())
                != Some(file)
            {
                continue;
            }
            let entered = function.is_none_or(|function| {
                let target = format!("{file}:{function}");
                fact.exemplar_paths
                    .iter()
                    .any(|path| path.contains(&target))
                    || support::antecedent_origins(&report.provenance, &fact.provenance_roots)
                        .contains(&target)
            });
            if entered {
                effects.push(fact.clone());
            }
        }
    }
    effects
}

/// One effect of an analyzed plan, tagged with the execution node that
/// produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ExecutionEffect {
    operation: Operation,
    resource: ResourceExpr,
    realm: ExecutionRealm,
    execution: ExecutionNodeRef,
}

/// An entrypoint's retained execution graph and the distinct effects each
/// node produced, read from its analyzed plan on the built index, with the
/// boundaries on the entrypoint's effective surface.
struct PlanExecution<'a> {
    graph: &'a ExecutionGraph,
    effects: Vec<ExecutionEffect>,
    boundaries: Vec<EffectiveBoundary>,
}

fn plan_execution<'a>(index: &'a RepoIndex, entrypoint: &str) -> Option<PlanExecution<'a>> {
    let plan = index.find(entrypoint)?.plan()?;
    let mut effects: Vec<_> = plan
        .effects
        .iter()
        .map(|effect| ExecutionEffect {
            operation: effect.operation.clone(),
            resource: effect.resource.clone(),
            realm: effect.realm.clone(),
            execution: effect.execution,
        })
        .collect();
    effects.sort_by_cached_key(|effect| {
        effinterp_proto::canonical_json(&(
            &effect.operation,
            &effect.resource,
            &effect.realm,
            effect.execution,
        ))
    });
    effects.dedup();
    Some(PlanExecution {
        graph: &plan.execution_graph,
        effects,
        boundaries: effective_surface(index, entrypoint)?.boundaries,
    })
}

/// The occurrence graph of an entrypoint's analyzed plan.
fn plan_causality<'a>(index: &'a RepoIndex, entrypoint: &str) -> Option<&'a CausalityGraph> {
    index.find(entrypoint)?.plan()?.causality.graph.as_ref()
}

/// The shortest causal path from one occurrence to another, breadth first over
/// successors in occurrence-id order.
fn causal_path(
    graph: &CausalityGraph,
    from: &OccurrenceId,
    to: &OccurrenceId,
) -> Option<Vec<OccurrenceId>> {
    let mut successors: std::collections::BTreeMap<&OccurrenceId, Vec<&OccurrenceId>> =
        std::collections::BTreeMap::new();
    for edge in &graph.edges {
        successors.entry(&edge.from).or_default().push(&edge.to);
    }
    for next in successors.values_mut() {
        next.sort();
        next.dedup();
    }
    let mut predecessor = std::collections::BTreeMap::new();
    let mut visited = std::collections::BTreeSet::from([from]);
    let mut queue = std::collections::VecDeque::from([from]);
    while let Some(node) = queue.pop_front() {
        for next in successors.get(node).into_iter().flatten() {
            if visited.insert(*next) {
                predecessor.insert(*next, node);
                queue.push_back(*next);
            }
        }
    }
    if !visited.contains(to) {
        return None;
    }
    let mut path = vec![to.clone()];
    let mut current = to;
    while current != from {
        current = predecessor[current];
        path.push(current.clone());
    }
    path.reverse();
    Some(path)
}

/// The exact typed selector `<family>:@<hex JSON identity>` that
/// `ResourceSelector::parse` decodes for a concrete, already normalized resource.
fn typed_selector(resource: &ResourceExpr) -> String {
    let ResourceExpr::Concrete { identity } = resource else {
        panic!("typed selectors name concrete resources");
    };
    let json = serde_json::to_string(identity).unwrap();
    let hex: String = json.bytes().map(|byte| format!("{byte:02x}")).collect();
    format!("{}:@{hex}", effinterp_proto::identity_family(identity))
}

/// The envelope as JSON, after the protocol validation every published
/// envelope must pass.
fn json(report: &RepoQueryEnvelope) -> serde_json::Value {
    effinterp_proto::validate_repo_query(report).unwrap();
    serde_json::to_value(report).unwrap()
}
