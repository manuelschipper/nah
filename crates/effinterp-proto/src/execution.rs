use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{
    BoundaryRef, ByteSpan, ContainerStorage, ExecutionRealm, ProvenanceRef, ResourceExpr, Subject,
};

/// Index into an execution graph's node table.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct ExecutionNodeRef(pub u32);

/// Confidence in the evidence selecting an execution target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionAssurance {
    Exact,
    Alternatives,
    Heuristic,
    Widened,
}

/// A stream endpoint inherited from another execution node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionStreamRef {
    pub node: ExecutionNodeRef,
    pub stream: ExecutionStream,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStream {
    Stdin,
    Stdout,
    Stderr,
}

/// A value supplied directly to an execution's stdin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionStreamValue {
    pub value: ResourceExpr,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provenance: Vec<ProvenanceRef>,
}

/// Known stream connections for an execution. An absent endpoint is inherited
/// from the launcher without reinterpretation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionStreams {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stdin: Option<ExecutionStreamRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stdin_value: Option<ExecutionStreamValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stdout: Option<ExecutionStreamRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stderr: Option<ExecutionStreamRef>,
}

/// One analyzed launch or a typed unresolved continuation. A boundary node
/// keeps the intended subject and context so a failed transition remains
/// queryable instead of disappearing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionNode {
    pub subject: Subject,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub boundary: Option<BoundaryRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub argv: Vec<ResourceExpr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd: Option<ResourceExpr>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub environment: BTreeMap<String, Option<ResourceExpr>>,
    #[serde(default)]
    pub streams: ExecutionStreams,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mounts: Vec<ContainerStorage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_span: Option<ByteSpan>,
    pub realm: ExecutionRealm,
    pub assurance: ExecutionAssurance,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<ProvenanceRef>,
    /// Evidence for the file-backed execution input, when one was selected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input: Option<ExecutionInput>,
}

/// Why control moved between two execution nodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionEdgeKind {
    Launch,
    Interpreter,
    Script,
    PackageScript,
    BuildTarget,
    ContainerRealm,
    CiRealm,
    DatabaseClient,
    ToolModel,
    Widening,
    Startup,
    Preload,
    Import,
    NativeLoader,
    BuildHook,
    PackageHook,
    VcsHook,
    Plugin,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionEdge {
    pub from: ExecutionNodeRef,
    pub to: ExecutionNodeRef,
    pub kind: ExecutionEdgeKind,
    /// Exact re-entry into an active node. Cycle edges are retained and are
    /// the only execution edges allowed to point to an earlier node.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub cycle: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<ProvenanceRef>,
}

/// The causal execution graph for one plan. Node zero is always the analyzed
/// entry subject; every other node has at least one incoming edge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionGraph {
    pub entry: ExecutionNodeRef,
    pub nodes: Vec<ExecutionNode>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub edges: Vec<ExecutionEdge>,
}

impl ExecutionGraph {
    /// A request proof cannot cross a widened or uncertain execution selection.
    pub fn exact_request_selections(&self) -> Vec<bool> {
        exact_request_selections(self.nodes.iter().map(|node| node.assurance), &self.edges)
    }
}

pub(crate) fn exact_request_selections(
    assurances: impl Iterator<Item = ExecutionAssurance>,
    edges: &[ExecutionEdge],
) -> Vec<bool> {
    let mut exact: Vec<_> = assurances
        .map(|value| value == ExecutionAssurance::Exact)
        .collect();
    let mut children = vec![Vec::new(); exact.len()];
    for edge in edges {
        if let Some(children) = children.get_mut(edge.from.0 as usize) {
            children.push(edge.to.0 as usize);
        }
        if edge.kind == ExecutionEdgeKind::Widening
            && let Some(value) = exact.get_mut(edge.to.0 as usize)
        {
            *value = false;
        }
    }
    let mut pending: Vec<_> = exact
        .iter()
        .enumerate()
        .filter_map(|(i, value)| (!value).then_some(i))
        .collect();
    while let Some(parent) = pending.pop() {
        for &child in &children[parent] {
            if let Some(value) = exact.get_mut(child)
                && *value
            {
                *value = false;
                pending.push(child);
            }
        }
    }
    exact
}

/// Raw-byte content identity, shared with repository inputs. This is content-derived
/// evidence: it enables equality testing, but authenticates neither a file nor a runtime.
pub fn content_digest(bytes: &[u8]) -> String {
    format!("blake3:{}", blake3::hash(bytes).to_hex())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionInputRole {
    ExplicitInvocation,
    UnexpectedSelected,
    DependencyRequest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionPhase {
    Main,
    Startup,
    Preload,
    Import,
    NativeLoader,
    BuildHook,
    PackageHook,
    VcsHook,
    Plugin,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExecutionSelector {
    InvocationPath,
    Environment { variable: String },
    RuntimeOption { option: String },
    Dependency { specifier: String },
    SearchPath,
    Convention { name: String },
}

/// Search candidates are ordered by runtime precedence, with the selected index
/// naming the winning candidate; direct selection records its literal request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExecutionSelection {
    Direct {
        request: String,
    },
    Search {
        candidates: Vec<ResourceExpr>,
        selected: Option<u32>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExecutionInputReason {
    Missing,
    Escapes,
    NotAFile,
    NamespaceDenied,
    Stale,
    Mismatched,
    Ambiguous,
    Oversize,
    BudgetRefused { limit: String },
    DependencyNotTraversed,
    ResolverUnavailable,
}

/// Observed bytes always have their raw digest, including unsupported encodings.
/// Predicted bytes were written earlier in the same invocation, so the input
/// does not depend on the host file as it exists before analysis.
/// Unobserved inputs cannot carry a digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExecutionContent {
    Observed { digest: String },
    Predicted { digest: String },
    Unobserved { reason: ExecutionInputReason },
}

/// The requester is a prior execution node, distinct from the selected resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionInput {
    pub role: ExecutionInputRole,
    pub phase: ExecutionPhase,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected: Option<ResourceExpr>,
    pub assurance: ExecutionAssurance,
    pub selector: ExecutionSelector,
    pub requester: ExecutionNodeRef,
    pub requester_component: String,
    pub selection: ExecutionSelection,
    pub content: ExecutionContent,
}

impl ExecutionNode {
    /// Literal path of the selected execution input, for source-local attribution.
    pub fn selected_source_path(&self) -> Option<&str> {
        match self.input.as_ref()?.selected.as_ref()? {
            ResourceExpr::Literal { value } => Some(value),
            ResourceExpr::Concrete {
                identity: crate::ResourceIdentity::FsPath { path },
            } => Some(path),
            _ => None,
        }
    }
}
