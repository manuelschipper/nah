use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{
    AttrValue, BoundaryReason, Condition, CoverageClaim, ExecutionNodeRef, ExecutionRealm,
    Modality, OccurrenceId, Operation, ProvenanceRef, ResourceExpr,
};

/// A typed connection point shared by language values, process streams, and
/// protocol boundaries.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Port {
    Stdin,
    Stdout,
    Stderr,
    Code,
    Arg(u32),
    Value,
    Property(String),
    Element(u32),
    HttpRequestBody,
    HttpResponseBody,
    SqlInput,
    SqlResult,
    ArchiveInput,
    ArchiveOutput,
}

/// Bounded occurrence count. `max: None` is an explicit widened upper bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CausalCardinality {
    pub min: u32,
    pub max: Option<u32>,
}

impl CausalCardinality {
    /// Necessity bounds the minimum count, without proving an upper bound.
    pub fn from_modality(modality: Modality) -> Self {
        Self {
            min: u32::from(modality == Modality::MustOnSuccess),
            max: None,
        }
    }

    pub const MAYBE_ONCE: Self = Self {
        min: 0,
        max: Some(1),
    };
    pub const EXACTLY_ONCE: Self = Self {
        min: 1,
        max: Some(1),
    };
    pub const WIDENED: Self = Self { min: 0, max: None };
}

/// One identity-bearing occurrence in the state and causality graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum OccurrenceKind {
    Value {
        value: ResourceExpr,
    },
    Port {
        port: Port,
    },
    ResourceInteraction {
        operation: Operation,
        resource: ResourceExpr,
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        attributes: BTreeMap<String, AttrValue>,
    },
    Boundary {
        reason: BoundaryReason,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        limit: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detail: Option<String>,
    },
}

/// A stable occurrence. `order` is the deterministic order within the plan;
/// it does not imply an edge between otherwise unrelated occurrences.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OccurrenceNode {
    pub id: OccurrenceId,
    #[serde(flatten)]
    pub occurrence: OccurrenceKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution: Option<ExecutionNodeRef>,
    #[serde(default, skip_serializing_if = "ExecutionRealm::is_host")]
    pub realm: ExecutionRealm,
    pub modality: Modality,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub condition: Option<Condition>,
    pub order: u32,
    pub cardinality: CausalCardinality,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provenance: Vec<ProvenanceRef>,
}

/// Closed, stable causal vocabulary. Resource operations remain open-ended;
/// the small set of ways occurrences relate does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CausalReason {
    ValueDependency,
    ControlDependency,
    Launch,
    /// Successive state interactions with the same resource, in order.
    ResourceTransition,
    /// A directed source-to-destination movement of content or of a directory
    /// entry: the `from` occurrence is the transfer's source-side interaction
    /// and the `to` occurrence its destination-side interaction. It states
    /// dependence between the two endpoints of one modeled transfer, never
    /// syscall chronology or that the transfer committed.
    ResourceTransfer,
    Alias,
    Containment,
}

/// Evidence for a relation, independent of whether either endpoint executes.
/// Exact proves the stated structural dependency under its conditions; it
/// does not prove feasibility, nonempty data, or successful completion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CausalAssurance {
    Exact,
    Conservative,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CausalEdge {
    pub from: OccurrenceId,
    pub to: OccurrenceId,
    pub reason: CausalReason,
    pub assurance: CausalAssurance,
    pub modality: Modality,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub condition: Option<Condition>,
    pub order: u32,
    pub cardinality: CausalCardinality,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provenance: Vec<ProvenanceRef>,
}

/// One occurrence-based graph over values, ports, resource state, execution,
/// and visible widening boundaries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CausalityGraph {
    pub nodes: Vec<OccurrenceNode>,
    pub edges: Vec<CausalEdge>,
}

/// Causal coverage is always published; graph omission means detail is unavailable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Causality {
    pub coverage: CoverageClaim,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub graph: Option<CausalityGraph>,
}
