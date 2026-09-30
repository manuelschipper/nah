use serde::{Deserialize, Serialize};

/// Index into a plan's `provenance` list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProvenanceRef(pub u32);

/// One evidence step. Nodes form a DAG: `antecedents` may only reference
/// earlier nodes in the plan's list, which forces topological order and
/// keeps serialization deterministic.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProvenanceNode {
    #[serde(flatten)]
    pub kind: ProvenanceKind,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub antecedents: Vec<ProvenanceRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProvenanceKind {
    /// A value supplied by the consumer as host context.
    HostContext { name: String },
    /// Admitted supporting input bytes; reading data does not imply executing it.
    SourceInput { path: String, digest: String },
    /// Byte span in the subject's source (shell subjects).
    SourceSpan { start: u32, end: u32 },
    /// An argv element of the subject (exec subjects).
    Argument { index: u32 },
    /// A named field in a native tool call's typed arguments.
    ToolArgument { name: String },
    /// A command or API model was applied. `model` is the model's stable id.
    ModelApplication { model: String },
    /// Analysis crossed into this node of the plan's execution graph.
    Execution { node: u32 },
    /// A host answered one observation request. The outcome carries bounded
    /// metadata only: an identity, a kind, or a typed refusal, never bytes.
    /// Evidence about initial host state, not proof the operation happened.
    HostObservation {
        query: crate::ObservationQuery,
        outcome: crate::ObservationOutcome,
    },
}
