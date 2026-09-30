use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::provenance::ProvenanceRef;
use crate::realm::ExecutionRealm;
use crate::resource::ResourceExpr;
use crate::{Condition, DispatchIdentity, ExecutionNodeRef, FactId, FactIdentity, OccurrenceId};

/// A typed operation such as `filesystem.delete`: lowercase dot-separated
/// segments, at least two, where the first segment is the effect domain.
/// Open-ended so consumers can retain operations newer than this crate.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Operation(pub String);

impl Operation {
    pub fn new(op: impl Into<String>) -> Self {
        Self(op.into())
    }

    /// The effect domain: the segment before the first dot.
    pub fn domain(&self) -> &str {
        self.spec().map_or_else(
            || self.0.split('.').next().unwrap_or(""),
            |spec| spec.domain,
        )
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether the string is a well-formed operation.
    pub fn is_well_formed(&self) -> bool {
        let segments: Vec<&str> = self.0.split('.').collect();
        segments.len() >= 2
            && segments.iter().all(|s| {
                !s.is_empty()
                    && s.chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
            })
    }

    pub fn is_destructive(&self) -> bool {
        self.spec().is_some_and(|spec| spec.destructive)
    }
}

/// Static modality of an effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Modality {
    /// A possible effect in the conservative bound; its path may be infeasible.
    May,
    /// Required on every modeled normally completing path. Must not be
    /// published when an opaque path could avoid the effect.
    MustOnSuccess,
}

impl Modality {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::May => "may",
            Self::MustOnSuccess => "must-on-success",
        }
    }
}

/// Proof that the selected invocation requests this operation under its modeled
/// selection and controls. Exact does not establish physical identity, occurrence,
/// feasibility, success, necessity, or a causal relation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestAssurance {
    Conservative,
    Exact,
}

/// Attribute values are scalars or flat lists of scalars; structure belongs in
/// the resource expression, not in attributes. A list never nests another
/// list, and its order is the one its emitter states: some follow the
/// invocation, and some, such as `excluded_names`, are sorted sets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AttrValue {
    Bool(bool),
    Int(i64),
    String(String),
    List(Vec<AttrValue>),
}

/// How repository-level resolution found an effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionAssurance {
    Exact,
    Alternatives,
    Heuristic,
}

impl ResolutionAssurance {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Alternatives => "alternatives",
            Self::Heuristic => "heuristic",
        }
    }
}

/// Source location retained for a repository effect fact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectOrigin {
    pub source_file: String,
    pub execution_node: Option<ExecutionNodeRef>,
}

/// The authoritative repository-query representation of one effect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectFact {
    pub occurrences: u32,
    pub exemplar_paths: Vec<Vec<String>>,
    pub fact_id: FactId,
    pub entrypoint: String,
    pub operation: Operation,
    pub resource: ResourceExpr,
    pub realm: ExecutionRealm,
    pub modality: Modality,
    pub request_assurance: RequestAssurance,
    pub attributes: BTreeMap<String, AttrValue>,
    pub condition: Option<Condition>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<EffectOrigin>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assurance: Option<ResolutionAssurance>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dispatch: Option<DispatchIdentity>,
    pub provenance_roots: Vec<OccurrenceId>,
}

impl EffectFact {
    pub fn identity(&self) -> FactIdentity {
        FactIdentity {
            operation: self.operation.clone(),
            resource: self.resource.clone(),
            realm: self.realm.clone(),
            modality: self.modality,
            request_assurance: self.request_assurance,
            attributes: self.attributes.clone(),
            condition: self.condition.clone(),
            provenance_roots: self.provenance_roots.clone(),
            dispatch: self.dispatch.clone(),
        }
    }

    pub fn expected_fact_id(&self) -> FactId {
        FactId::derive(&self.identity())
    }
}

/// A typed interaction with state outside the analyzed computation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Effect {
    pub id: EffectId,
    pub operation: Operation,
    pub resource: ResourceExpr,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attributes: BTreeMap<String, AttrValue>,
    pub modality: Modality,
    pub request_assurance: RequestAssurance,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub condition: Option<Condition>,
    /// The execution context this effect occurs in. Absent (Host) in the
    /// common case so a host effect serializes exactly as before.
    #[serde(default, skip_serializing_if = "ExecutionRealm::is_host")]
    pub realm: ExecutionRealm,
    /// Execution node and realm that produced this effect.
    pub execution: ExecutionNodeRef,
    /// Minimal provenance roots needed to explain this effect.
    pub provenance: Vec<ProvenanceRef>,
}

impl Effect {
    /// Pair the supplied resource with its realm without expanding recursive reach.
    pub fn qualified_resource(&self) -> crate::QualifiedExpr {
        crate::QualifiedExpr {
            realm: self.realm.clone(),
            expr: self.resource.clone(),
        }
    }
}
/// Content-derived plan effect identity. Empty only while constructing an effect.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EffectId(pub String);

impl EffectId {
    pub const BYTES: usize = 78;

    pub fn derive(identity: &EffectIdentity) -> Self {
        let mut identity = identity.clone();
        identity.condition = identity.condition.as_ref().map(Condition::identity);
        identity.resource =
            crate::normalize_resource(identity.resource, crate::PathPlatform::Posix);
        Self(format!(
            "effect:{}",
            crate::stable_hash("effinterp/plan-effect/v1", &identity)
        ))
    }

    pub fn is_well_formed(&self) -> bool {
        self.0.strip_prefix("effect:blake3:").is_some_and(|hex| {
            hex.len() == 64
                && hex
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
    }
}

/// Duplicate ordinals follow plan effect order across all identical subject tuples,
/// including subjects represented by different execution nodes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectOccurrence {
    pub subject_digest: String,
    pub realm: ExecutionRealm,
    pub ordinal: u32,
}

/// Identity excludes analysis metadata and positional references. Editing the
/// launching subject or its context can rename every effect under that subject.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectIdentity {
    pub operation: Operation,
    pub resource: ResourceExpr,
    pub realm: ExecutionRealm,
    pub modality: Modality,
    pub request_assurance: RequestAssurance,
    pub attributes: BTreeMap<String, AttrValue>,
    pub condition: Option<Condition>,
    pub occurrence: EffectOccurrence,
}
