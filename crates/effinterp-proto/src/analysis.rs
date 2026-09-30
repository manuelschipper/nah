use crate::Payload;
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize, Serializer};

use crate::{
    CoverageClaim, DispatchIdentity, OccurrenceDescriptor, OccurrenceId, PathPlatform,
    ResourceExpr, Subject,
};

pub const REPO_QUERY_SCHEMA_V1: &str = "effinterp/repo-query/v1";

/// Query families covered by protocol v1. This enum is closed;
/// operation and domain vocabularies inside payload rows remain open strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PayloadKind {
    Effects,
    Reach,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisGraph {
    Effects,
    Execution,
    Occurrences,
    ResourceState,
    Causality,
    Provenance,
}

/// Exact graph scope affected by one partial or stale cause. An empty
/// `entrypoints` list is meaningful only when `all_entrypoints` is true.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AffectedScope {
    pub all_entrypoints: bool,
    pub entrypoints: Vec<String>,
    pub graphs: Vec<AnalysisGraph>,
}

impl AffectedScope {
    pub fn all(graphs: Vec<AnalysisGraph>) -> Self {
        Self {
            all_entrypoints: true,
            entrypoints: Vec::new(),
            graphs,
        }
    }

    pub fn entrypoint(entrypoint: String, graphs: Vec<AnalysisGraph>) -> Self {
        Self {
            all_entrypoints: false,
            entrypoints: vec![entrypoint],
            graphs,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisDependencyKind {
    SourceModule,
    SkippedSource,
    EntrypointDiscovery,
    ResolverConfig,
    ParserFrontend,
    Analyzer,
    ModelSet,
    Limit,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnalysisDependency {
    pub key: String,
    pub kind: AnalysisDependencyKind,
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnalysisConfiguration {
    pub path_platform: PathPlatform,
    pub limits: BTreeMap<String, u64>,
}

impl AnalysisConfiguration {
    pub fn digest(&self) -> String {
        crate::stable_hash("effinterp/analysis-configuration/v1", self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnalyzerIdentity {
    pub name: String,
    pub version: String,
    pub build_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnalysisIdentity {
    pub analyzer: AnalyzerIdentity,
    pub configuration_digest: String,
    pub model_set_digest: String,
    pub dependencies: Vec<AnalysisDependency>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnalysisSubject {
    pub entrypoint: String,
    pub source_path: String,
    pub subject: Subject,
    pub subject_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PartialReason {
    UnsupportedEvidence {
        boundary_id: String,
        scope: AffectedScope,
    },
    UnanalyzedInput {
        path: String,
        scope: AffectedScope,
    },
    AnalysisFailure {
        entrypoint: String,
        scope: AffectedScope,
    },
    LimitReached {
        limit: String,
        scope: AffectedScope,
    },
    Truncated {
        collection: String,
        limit: u64,
        scope: AffectedScope,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum StaleReason {
    SnapshotSuperseded {
        current_snapshot_id: String,
        scope: AffectedScope,
    },
    InputChanged {
        dependency: String,
        path: String,
        scope: AffectedScope,
    },
    InputMissing {
        dependency: String,
        path: String,
        scope: AffectedScope,
    },
    UnknownDependency {
        key: String,
        scope: AffectedScope,
    },
    AnalyzerChanged {
        dependency: String,
        current_analyzer_version: String,
        scope: AffectedScope,
    },
    ModelSetChanged {
        dependency: String,
        current_model_set_digest: String,
        scope: AffectedScope,
    },
    ParserChanged {
        dependency: String,
        parser: String,
        scope: AffectedScope,
    },
    ConfigChanged {
        dependency: String,
        path: String,
        scope: AffectedScope,
    },
    LimitsChanged {
        dependency: String,
        limit: String,
        scope: AffectedScope,
    },
}

/// Completeness is always explicit. Partial and stale values cannot be
/// constructed from JSON without at least a `reasons` field; semantic
/// validation additionally rejects an empty list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AnalysisStatus {
    Complete,
    Partial { reasons: Vec<PartialReason> },
    Stale { reasons: Vec<StaleReason> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnalysisCoverage {
    pub domains: BTreeMap<String, CoverageClaim<String>>,
    pub causality: Option<CoverageClaim<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SourceEvidence {
    Span { start: u32, end: u32 },
    Argument { index: u32 },
    Function { name: String },
    Execution { node: u32, origin: Option<String> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProtocolProvenanceKind {
    Entrypoint {
        entrypoint: String,
    },
    Source {
        evidence: SourceEvidence,
    },
    ModelApplication {
        declaration_id: String,
        declaration_digest: Option<String>,
    },
    CrossFileCall {
        from: String,
        into: String,
    },
    Dispatch {
        model: String,
        registration_roots: Vec<OccurrenceId>,
        dispatch_roots: Vec<OccurrenceId>,
    },
    Boundary {
        reason: crate::BoundaryReason,
    },
    CausalOccurrence {
        entrypoint: String,
        semantic_kind: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolProvenanceNode {
    pub id: OccurrenceId,
    pub occurrence: OccurrenceDescriptor,
    pub evidence: ProtocolProvenanceKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceEdgeKind {
    DerivedFrom,
    Calls,
    AppliesModel,
    Dispatches,
    Supports,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceEdge {
    pub from: OccurrenceId,
    pub kind: ProvenanceEdgeKind,
    pub to: OccurrenceId,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceDag {
    pub nodes: Vec<ProtocolProvenanceNode>,
    pub edges: Vec<ProvenanceEdge>,
}

impl ProvenanceDag {
    /// Reachability follows evidence edges from payload and envelope boundary roots.
    pub fn reachable_nodes(
        &self,
        payload: &Payload,
        boundaries: &[AnalysisBoundary],
    ) -> std::collections::BTreeSet<OccurrenceId> {
        let mut pending: Vec<_> = payload
            .provenance_roots()
            .into_iter()
            .chain(boundaries.iter().flat_map(|b| {
                b.provenance_roots.iter().chain(
                    b.dispatch
                        .iter()
                        .flat_map(|d| d.registration_roots.iter().chain(&d.dispatch_roots)),
                )
            }))
            .cloned()
            .collect();
        let mut reachable = std::collections::BTreeSet::new();
        let mut edges = std::collections::BTreeMap::<_, Vec<_>>::new();
        for edge in &self.edges {
            edges.entry(&edge.to).or_default().push(&edge.from);
        }
        for node in &self.nodes {
            if let ProtocolProvenanceKind::Dispatch {
                registration_roots,
                dispatch_roots,
                ..
            } = &node.evidence
            {
                edges
                    .entry(&node.id)
                    .or_default()
                    .extend(registration_roots.iter().chain(dispatch_roots));
            }
        }
        while let Some(id) = pending.pop() {
            if reachable.insert(id.clone())
                && let Some(targets) = edges.get(&id)
            {
                pending.extend(targets.iter().map(|id| (*id).clone()));
            }
        }
        reachable
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnalysisBoundary {
    pub class: crate::BoundaryClass,
    pub id: String,
    pub reason: crate::BoundaryReason,
    pub domains: Vec<String>,
    pub affected_resource: Option<ResourceExpr>,
    pub detail: Option<String>,
    pub limit: Option<String>,
    pub dispatch: Option<DispatchIdentity>,
    pub provenance_roots: Vec<OccurrenceId>,
}

impl AnalysisBoundary {
    pub fn expected_id(&self) -> String {
        #[derive(Serialize)]
        struct Identity<'a> {
            class: crate::BoundaryClass,
            reason: &'a crate::BoundaryReason,
            domains: &'a [String],
            affected_resource: &'a Option<ResourceExpr>,
            detail: &'a Option<String>,
            limit: &'a Option<String>,
            provenance_roots: &'a [OccurrenceId],
            dispatch: &'a Option<DispatchIdentity>,
        }
        format!(
            "boundary:{}",
            crate::stable_hash(
                "effinterp/analysis-boundary/v1",
                &Identity {
                    class: self.class,
                    reason: &self.reason,
                    domains: &self.domains,
                    affected_resource: &self.affected_resource,
                    detail: &self.detail,
                    limit: &self.limit,
                    provenance_roots: &self.provenance_roots,
                    dispatch: &self.dispatch,
                }
            )
        )
    }
}

/// One repository-analysis answer bound to an immutable analyzed snapshot.
/// The hash covers this canonical structure with `content_hash` omitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepoQueryEnvelope {
    pub schema: String,
    pub snapshot_id: String,
    pub identity: AnalysisIdentity,
    pub subjects: Vec<AnalysisSubject>,
    pub status: AnalysisStatus,
    pub coverage: AnalysisCoverage,
    pub boundaries: Vec<AnalysisBoundary>,
    pub provenance: ProvenanceDag,
    pub payload_kind: PayloadKind,
    #[serde(serialize_with = "serialize_canonical_payload")]
    pub payload: Payload,
    pub content_hash: String,
}

#[derive(Serialize)]
#[serde(bound(serialize = "T: Serialize"))]
struct HashInput<'a, T> {
    schema: &'a str,
    snapshot_id: &'a str,
    identity: &'a AnalysisIdentity,
    subjects: &'a [AnalysisSubject],
    status: &'a AnalysisStatus,
    coverage: &'a AnalysisCoverage,
    boundaries: &'a [AnalysisBoundary],
    provenance: &'a ProvenanceDag,
    payload_kind: PayloadKind,
    #[serde(serialize_with = "serialize_canonical_payload")]
    payload: &'a T,
}

fn serialize_canonical_payload<T: Serialize, S: Serializer>(
    payload: &T,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serde_json::to_value(payload)
        .map_err(serde::ser::Error::custom)?
        .serialize(serializer)
}

impl RepoQueryEnvelope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        snapshot_id: String,
        identity: AnalysisIdentity,
        subjects: Vec<AnalysisSubject>,
        status: AnalysisStatus,
        coverage: AnalysisCoverage,
        boundaries: Vec<AnalysisBoundary>,
        provenance: ProvenanceDag,
        payload_kind: PayloadKind,
        payload: Payload,
    ) -> Self {
        let mut envelope = Self {
            schema: REPO_QUERY_SCHEMA_V1.to_string(),
            snapshot_id,
            identity,
            subjects,
            status,
            coverage,
            boundaries,
            provenance,
            payload_kind,
            payload,
            content_hash: String::new(),
        };
        envelope.reseal();
        envelope
    }

    pub fn expected_content_hash(&self) -> String {
        crate::stable_hash(
            "effinterp/repo-query-content/v1",
            &HashInput {
                schema: &self.schema,
                snapshot_id: &self.snapshot_id,
                identity: &self.identity,
                subjects: &self.subjects,
                status: &self.status,
                coverage: &self.coverage,
                boundaries: &self.boundaries,
                provenance: &self.provenance,
                payload_kind: self.payload_kind,
                payload: &self.payload,
            },
        )
    }

    pub fn reseal(&mut self) {
        self.content_hash = self.expected_content_hash();
    }

    pub fn to_canonical_json(&self) -> String {
        crate::canonical_json(self)
    }
}

impl<'de> Deserialize<'de> for RepoQueryEnvelope {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct EnvelopeWire {
            pub schema: String,
            pub snapshot_id: String,
            pub identity: AnalysisIdentity,
            pub subjects: Vec<AnalysisSubject>,
            pub status: AnalysisStatus,
            pub coverage: AnalysisCoverage,
            pub boundaries: Vec<AnalysisBoundary>,
            pub provenance: ProvenanceDag,
            pub payload_kind: PayloadKind,
            pub payload: serde_json::Value,
            pub content_hash: String,
        }
        let wire = EnvelopeWire::deserialize(deserializer)?;
        let original_payload = wire.payload.clone();
        let payload = match wire.payload_kind {
            PayloadKind::Effects => {
                serde_path_to_error::deserialize(wire.payload).map(Payload::Effects)
            }
            PayloadKind::Reach => {
                serde_path_to_error::deserialize(wire.payload).map(Payload::Reach)
            }
        }
        .map_err(|error| {
            let path = error.path().to_string();
            let path = if path == "." {
                "payload".to_string()
            } else {
                format!("payload.{path}")
            };
            serde::de::Error::custom(format!("{path}: {}", error.inner()))
        })?;
        if let Some(path) = payload_shape_difference(
            &original_payload,
            &serde_json::to_value(&payload).map_err(serde::de::Error::custom)?,
            "payload",
        ) {
            return Err(serde::de::Error::custom(format!(
                "{path}: payload shape does not round-trip"
            )));
        }
        Ok(Self {
            schema: wire.schema,
            snapshot_id: wire.snapshot_id,
            identity: wire.identity,
            subjects: wire.subjects,
            status: wire.status,
            coverage: wire.coverage,
            boundaries: wire.boundaries,
            provenance: wire.provenance,
            payload_kind: wire.payload_kind,
            content_hash: wire.content_hash,
            payload,
        })
    }
}

// Shared invocation types can omit defaults or ignore unknown fields. At the
// query boundary those changes must be rejected before returning a typed payload.
fn payload_shape_difference(
    original: &serde_json::Value,
    typed: &serde_json::Value,
    path: &str,
) -> Option<String> {
    if original == typed {
        return None;
    }
    match (original, typed) {
        (serde_json::Value::Object(a), serde_json::Value::Object(b)) => {
            for name in a.keys().chain(b.keys()) {
                match (a.get(name), b.get(name)) {
                    (Some(a), Some(b)) => {
                        if let Some(path) =
                            payload_shape_difference(a, b, &format!("{path}.{name}"))
                        {
                            return Some(path);
                        }
                    }
                    _ => return Some(format!("{path}.{name}")),
                }
            }
        }
        (serde_json::Value::Array(a), serde_json::Value::Array(b)) if a.len() == b.len() => {
            for (i, (a, b)) in a.iter().zip(b).enumerate() {
                if let Some(path) = payload_shape_difference(a, b, &format!("{path}[{i}]")) {
                    return Some(path);
                }
            }
        }
        _ => {}
    }
    Some(path.to_string())
}
