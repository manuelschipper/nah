use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{
    AttrValue, Condition, ExecutionRealm, Modality, Operation, PathPlatform, ResourceExpr,
};

/// Stable byte coordinates in one analyzed input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ByteSpan {
    pub start: u32,
    pub end: u32,
}

/// The identity-bearing fields of one semantic occurrence. Repository roots,
/// timestamps, display strings, and enumeration order outside the file are
/// deliberately absent.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OccurrenceDescriptor {
    pub input_digest: String,
    pub origin: String,
    pub span: ByteSpan,
    pub semantic_kind: String,
    pub local_ordinal: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OccurrenceId(pub String);

impl OccurrenceId {
    pub fn derive(descriptor: &OccurrenceDescriptor) -> Self {
        let hash = crate::stable_hash("effinterp/analysis-occurrence/v1", descriptor);
        Self(format!("occurrence:{hash}"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FactId(pub String);

/// Dispatch evidence that participates in fact identity. The paths are stable
/// occurrence ids, never rendered source paths.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DispatchIdentity {
    pub model: String,
    pub registration_roots: Vec<OccurrenceId>,
    pub dispatch_roots: Vec<OccurrenceId>,
}

/// The normalized semantic tuple whose digest identifies one fact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactIdentity {
    pub operation: Operation,
    pub resource: ResourceExpr,
    pub realm: ExecutionRealm,
    pub modality: Modality,
    pub request_assurance: crate::RequestAssurance,
    pub attributes: BTreeMap<String, AttrValue>,
    pub condition: Option<Condition>,
    pub provenance_roots: Vec<OccurrenceId>,
    pub dispatch: Option<DispatchIdentity>,
}

impl FactId {
    pub fn derive(identity: &FactIdentity) -> Self {
        let mut normalized = identity.clone();
        normalized.condition = normalized.condition.as_ref().map(Condition::identity);
        normalized.resource = crate::normalize_resource(normalized.resource, PathPlatform::Posix);
        let hash = crate::stable_hash("effinterp/analysis-fact/v1", &normalized);
        Self(format!("fact:{hash}"))
    }
}
