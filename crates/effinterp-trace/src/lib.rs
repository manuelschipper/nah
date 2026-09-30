#![forbid(unsafe_code)]
#![forbid(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types
)]

//! Policy-neutral causal reachability over a serialized `Plan`. This crate
//! depends only on the public protocol and never re-parses source.
//!
//! Every result states mechanism, never a judgment: one resource occurrence
//! reaches another through the occurrence graph, with the shortest bounded
//! path that connects them.
//!
//! Unsupported: runtime effect observation and collector adapters are a
//! non-goal; this crate only provides static reachability over a `Plan`.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use effinterp_proto::{
    BoundaryReason, CausalEdge, CausalReason, CausalityGraph, Condition, ExecutionRealm, Modality,
    OccurrenceId, OccurrenceKind, OccurrenceNode, Plan, ResourceExpr,
};

/// The plan did not publish graph detail needed to answer a causal query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DetailUnavailable;

impl std::fmt::Display for DetailUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("causality detail unavailable")
    }
}

impl std::error::Error for DetailUnavailable {}

/// One causal effect endpoint: a resource-interaction occurrence in a plan's
/// causality graph with its operation, resource and realm. Not the repository-query
/// `effinterp_proto::EffectFact`, which aggregates occurrences under a fact id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CausalEffectEndpoint {
    pub occurrence_id: OccurrenceId,
    pub op: String,
    pub resource: ResourceExpr,
    pub realm: ExecutionRealm,
}

/// One directed source-to-destination transfer the plan recorded: the
/// source-side interaction, the destination-side interaction, the guard both
/// endpoints are under, and each endpoint's own realm (a container copy or an
/// `scp` crosses realms, so the two need not match).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceTransfer {
    pub source: CausalEffectEndpoint,
    pub destination: CausalEffectEndpoint,
    pub modality: Modality,
    pub condition: Option<Condition>,
}

/// One effect occurrence that causally reaches another, with the shortest
/// occurrence path between them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reach {
    pub from: CausalEffectEndpoint,
    pub to: CausalEffectEndpoint,
    pub path: Vec<OccurrenceId>,
}

/// What stopped a reachability search early: path depth, pair count, or a limit
/// the plan's producer already saturated.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ReachabilityLimit {
    Depth,
    Pairs,
    Producer(String),
}

/// All reachable effect pairs in a plan, or the pairs found before a limit
/// saturated the search, with the occurrences whose reach is incomplete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reachability {
    Complete(Vec<Reach>),
    Saturated {
        pairs: Vec<Reach>,
        limits: BTreeSet<ReachabilityLimit>,
        incomplete_from: BTreeSet<OccurrenceId>,
    },
}

impl Reachability {
    pub fn pairs(&self) -> &[Reach] {
        match self {
            Self::Complete(pairs) | Self::Saturated { pairs, .. } => pairs,
        }
    }

    pub fn saturated_limits(&self) -> Option<&BTreeSet<ReachabilityLimit>> {
        match self {
            Self::Complete(_) => None,
            Self::Saturated { limits, .. } => Some(limits),
        }
    }

    pub fn is_complete_from(&self, occurrence: &OccurrenceId) -> bool {
        match self {
            Self::Complete(_) => true,
            Self::Saturated {
                incomplete_from, ..
            } => !incomplete_from.contains(occurrence),
        }
    }
}

/// Every reachable resource-interaction pair, preserving distinct occurrence
/// endpoints even when their display-level effect facts are equal.
///
/// Plan-limited reachability: unlike the graph-only `causal_path_in_graph`
/// helpers, this reads the plan limits `max_causal_depth` and
/// `max_causal_pairs` from `plan.analysis.limits`, treating an absent limit as
/// no limit, and reports `Reachability::Saturated` when either cap stops the
/// search or a causality coverage gap records a `LIMIT_SATURATED` producer
/// boundary. Edges are followed regardless of their conditions. Expects a
/// validated plan and does not validate it; returns `DetailUnavailable` when
/// the plan published no causality graph.
pub fn reachable_pairs(plan: &Plan) -> Result<Reachability, DetailUnavailable> {
    let graph = plan.causality.graph.as_ref().ok_or(DetailUnavailable)?;
    let adjacency = adjacency(graph);
    // A schema-valid plan need not declare these; an undeclared limit is no
    // limit, matching how the engine reads its own limits.
    let limit = |name: &str| {
        plan.analysis
            .limits
            .get(name)
            .copied()
            .map_or(usize::MAX, |value| {
                usize::try_from(value).unwrap_or(usize::MAX)
            })
    };
    let max_depth = limit("max_causal_depth");
    let max_pairs = limit("max_causal_pairs");
    let resources: Vec<_> = graph
        .nodes
        .iter()
        .filter(|node| matches!(node.occurrence, OccurrenceKind::ResourceInteraction { .. }))
        .map(|node| node.id.clone())
        .collect();
    let resource_set: BTreeSet<_> = resources.iter().cloned().collect();
    let endpoints = causal_effect_endpoints(graph);

    let mut out = Vec::new();
    let mut saturated = plan
        .causality
        .coverage
        .gaps
        .iter()
        .filter_map(|reference| plan.boundaries.get(reference.0 as usize))
        .filter(|boundary| boundary.reason == BoundaryReason::LIMIT_SATURATED)
        .filter_map(|boundary| boundary.limit.clone())
        .map(ReachabilityLimit::Producer)
        .collect::<BTreeSet<_>>();
    let mut incomplete_from = if saturated.is_empty() {
        BTreeSet::new()
    } else {
        resource_set.clone()
    };
    for producer in resources {
        let (visited, predecessor, depth_saturated) = walk(&adjacency, &producer, max_depth);
        if depth_saturated {
            saturated.insert(ReachabilityLimit::Depth);
            incomplete_from.insert(producer.clone());
        }
        for consumer in visited {
            if consumer == producer || !resource_set.contains(&consumer) {
                continue;
            }
            if out.len() >= max_pairs {
                saturated.insert(ReachabilityLimit::Pairs);
                incomplete_from.insert(producer.clone());
                continue;
            }
            out.push(Reach {
                from: endpoints[&producer].clone(),
                to: endpoints[&consumer].clone(),
                path: reconstruct(&predecessor, &producer, &consumer),
            });
        }
    }
    if saturated.is_empty() {
        Ok(Reachability::Complete(out))
    } else {
        Ok(Reachability::Saturated {
            pairs: out,
            limits: saturated,
            incomplete_from,
        })
    }
}

/// Every source-to-destination transfer the plan recorded, in plan edge order.
///
/// A transfer states which endpoint the movement came from and which it
/// reached. It is not a claim that the transfer committed, and it never
/// implies syscall chronology.
pub fn resource_transfers(plan: &Plan) -> Result<Vec<ResourceTransfer>, DetailUnavailable> {
    let graph = plan.causality.graph.as_ref().ok_or(DetailUnavailable)?;
    let endpoints = causal_effect_endpoints(graph);
    Ok(graph
        .edges
        .iter()
        .filter(|edge| edge.reason == CausalReason::ResourceTransfer)
        .filter_map(|edge| {
            Some(ResourceTransfer {
                source: endpoints.get(&edge.from)?.clone(),
                destination: endpoints.get(&edge.to)?.clone(),
                modality: edge.modality,
                condition: edge.condition.clone(),
            })
        })
        .collect())
}

fn causal_effect_endpoints(graph: &CausalityGraph) -> BTreeMap<OccurrenceId, CausalEffectEndpoint> {
    graph
        .nodes
        .iter()
        .filter_map(|node| match &node.occurrence {
            OccurrenceKind::ResourceInteraction {
                operation,
                resource,
                ..
            } => Some((
                node.id.clone(),
                CausalEffectEndpoint {
                    occurrence_id: node.id.clone(),
                    op: operation.0.clone(),
                    resource: resource.clone(),
                    realm: node.realm.clone(),
                },
            )),
            _ => None,
        })
        .collect()
}

/// Shortest deterministic causal path between two occurrence ids.
///
/// Graph-only: searches the supplied graph by breadth-first search over
/// sorted successors, without reading plan limits, causality coverage gaps or
/// edge conditions, so no path means none exists in this graph, not that the
/// plan proved its absence. Callers needing plan limits use `reachable_pairs`.
pub fn causal_path_in_graph(
    graph: &CausalityGraph,
    from: &OccurrenceId,
    to: &OccurrenceId,
) -> Option<Vec<OccurrenceId>> {
    let adjacency = adjacency(graph);
    shortest_path(from, to, |node| {
        adjacency.get(node).cloned().unwrap_or_default()
    })
}

/// Shortest deterministic causal path whose occurrences and edges satisfy a
/// caller-owned traversal policy. `nodes` indexes the graph's occurrences by
/// id and `edges_from` its edges by source occurrence; the caller builds both
/// once per graph, so repeated queries do not re-index it. The policy is only
/// consulted for occurrences and edges the search reaches.
///
/// Graph-only, like `causal_path_in_graph`: it does not read plan limits or
/// causality coverage gaps, and edge conditions matter only through
/// `edge_allowed`.
pub fn causal_path_in_graph_with(
    nodes: &BTreeMap<&OccurrenceId, &OccurrenceNode>,
    edges_from: &BTreeMap<&OccurrenceId, Vec<&CausalEdge>>,
    from: &OccurrenceId,
    to: &OccurrenceId,
    mut occurrence_allowed: impl FnMut(&OccurrenceNode) -> bool,
    mut edge_allowed: impl FnMut(&CausalEdge) -> bool,
) -> Option<Vec<OccurrenceId>> {
    let mut allowed =
        |id: &OccurrenceId| nodes.get(id).is_some_and(|node| occurrence_allowed(node));
    if !allowed(from) || !allowed(to) {
        return None;
    }
    // Every node the search expands was itself allowed, so an edge needs only
    // its own policy and an allowed destination.
    shortest_path(from, to, |node| {
        let mut successors = edges_from
            .get(node)
            .into_iter()
            .flatten()
            .filter(|edge| edge_allowed(edge) && allowed(&edge.to))
            .map(|edge| edge.to.clone())
            .collect::<Vec<_>>();
        successors.sort();
        successors.dedup();
        successors
    })
}

fn adjacency(graph: &CausalityGraph) -> BTreeMap<OccurrenceId, Vec<OccurrenceId>> {
    let mut adjacency: BTreeMap<OccurrenceId, Vec<OccurrenceId>> = BTreeMap::new();
    for edge in &graph.edges {
        adjacency
            .entry(edge.from.clone())
            .or_default()
            .push(edge.to.clone());
    }
    normalize_adjacency(&mut adjacency);
    adjacency
}

fn normalize_adjacency(adjacency: &mut BTreeMap<OccurrenceId, Vec<OccurrenceId>>) {
    for successors in adjacency.values_mut() {
        successors.sort();
        successors.dedup();
    }
}

/// Breadth-first search that visits each node's sorted successors in order
/// and stops once `target` is discovered. A node's predecessor is fixed when
/// it is first discovered, so the path equals the one a full walk records.
fn shortest_path(
    start: &OccurrenceId,
    target: &OccurrenceId,
    mut successors: impl FnMut(&OccurrenceId) -> Vec<OccurrenceId>,
) -> Option<Vec<OccurrenceId>> {
    if start == target {
        return Some(vec![start.clone()]);
    }
    let mut predecessor = BTreeMap::new();
    let mut visited = BTreeSet::from([start.clone()]);
    let mut queue = VecDeque::from([start.clone()]);
    while let Some(node) = queue.pop_front() {
        for successor in successors(&node) {
            if visited.insert(successor.clone()) {
                predecessor.insert(successor.clone(), node.clone());
                if successor == *target {
                    return Some(reconstruct(&predecessor, start, target));
                }
                queue.push_back(successor);
            }
        }
    }
    None
}

fn walk(
    adjacency: &BTreeMap<OccurrenceId, Vec<OccurrenceId>>,
    start: &OccurrenceId,
    max_depth: usize,
) -> (
    BTreeSet<OccurrenceId>,
    BTreeMap<OccurrenceId, OccurrenceId>,
    bool,
) {
    let mut predecessor = BTreeMap::new();
    let mut visited = BTreeSet::from([start.clone()]);
    let mut blocked = BTreeSet::new();
    let mut queue = VecDeque::from([(start.clone(), 0usize)]);
    while let Some((node, depth)) = queue.pop_front() {
        if depth >= max_depth {
            if let Some(successors) = adjacency.get(&node) {
                blocked.extend(successors.iter().cloned());
            }
            continue;
        }
        let Some(successors) = adjacency.get(&node) else {
            continue;
        };
        for successor in successors {
            if visited.insert(successor.clone()) {
                predecessor.insert(successor.clone(), node.clone());
                queue.push_back((successor.clone(), depth + 1));
            }
        }
    }
    let saturated = blocked.iter().any(|node| !visited.contains(node));
    (visited, predecessor, saturated)
}

fn reconstruct(
    predecessor: &BTreeMap<OccurrenceId, OccurrenceId>,
    start: &OccurrenceId,
    end: &OccurrenceId,
) -> Vec<OccurrenceId> {
    let mut path = vec![end.clone()];
    let mut current = end.clone();
    while current != *start {
        current = predecessor[&current].clone();
        path.push(current.clone());
    }
    path.reverse();
    path
}
