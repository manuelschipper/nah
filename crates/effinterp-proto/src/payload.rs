use crate::{
    BoundaryReason, CoverageClaim, DispatchIdentity, EffectFact, ExecutionRealm, OccurrenceId,
    ResourceExpr,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// One reverse-query hit: an effect that may reach the selected resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReachHit {
    pub fact: EffectFact,
    #[serde(rename = "match")]
    pub matched: crate::Match,
}

/// An entrypoint whose analysis is opaque in the queried domain, so the
/// resource cannot be excluded even though no explicit effect matched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundaryIndeterminate {
    pub boundary_id: BoundaryId,
    pub entrypoint: String,
    pub domain: String,
    /// Coverage the entrypoint declares for the queried domain.
    pub coverage: crate::CoverageLevel,
    pub boundary_reason: BoundaryReason,
    pub affected_resource: Option<ResourceExpr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub boundary_detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dispatch: Option<DispatchIdentity>,
    pub source_file: String,
    pub provenance_roots: Vec<OccurrenceId>,
}

/// Unknown effect relations and opaque boundaries retain distinct evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "row_kind", rename_all = "snake_case", deny_unknown_fields)]
// One row is built and serialized once, so boxing would add an indirection to the
// wire shape without removing a move that happens on a hot path.
#[allow(clippy::large_enum_variant)]
pub enum Indeterminate {
    Boundary {
        #[serde(flatten)]
        evidence: BoundaryIndeterminate,
    },
    Effect {
        fact: EffectFact,
        domain: String,
        coverage: crate::CoverageLevel,
        #[serde(rename = "match")]
        matched: crate::Match,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReachReport {
    pub selector: String,
    pub domain: String,
    /// The operation filter the matches were restricted to, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    /// Concrete and symbolic matches.
    pub matches: Vec<ReachHit>,
    /// Entrypoints that cannot be excluded because they went opaque in the
    /// queried domain. A non-empty list means an empty `matches` is NOT proof
    /// that no entrypoint affects the resource.
    pub indeterminate: Vec<Indeterminate>,
}

/// A boundary on an entrypoint's canonical surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundaryRow {
    pub occurrences: u32,
    pub exemplar_paths: Vec<Vec<String>>,
    pub boundary_id: BoundaryId,
    pub reason: BoundaryReason,
    pub domains: Vec<String>,
    pub affected_resource: Option<ResourceExpr>,
    #[serde(skip)]
    pub display_domains: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dispatch: Option<DispatchIdentity>,
    pub provenance_roots: Vec<OccurrenceId>,
}

/// Forward query result: effects plus the coverage and boundaries that qualify
/// them. Effects alone would overstate certainty.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectsReport {
    pub entrypoint: String,
    pub effects: Vec<EffectFact>,
    pub coverage: BTreeMap<String, CoverageClaim<String>>,
    pub boundaries: Vec<BoundaryRow>,
}

/// The enclosing envelope selects the variant; the payload object has no extra tag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum Payload {
    Effects(EffectsReport),
    Reach(ReachReport),
}

impl Payload {
    /// Provenance roots directly referenced by the typed payload rows.
    pub fn provenance_roots(&self) -> Vec<&OccurrenceId> {
        fn roots<'a>(
            roots: &'a [OccurrenceId],
            dispatch: Option<&'a DispatchIdentity>,
        ) -> impl Iterator<Item = &'a OccurrenceId> {
            roots.iter().chain(
                dispatch
                    .into_iter()
                    .flat_map(|d| d.registration_roots.iter().chain(&d.dispatch_roots)),
            )
        }
        match self {
            Self::Effects(r) => r
                .effects
                .iter()
                .flat_map(|f| roots(&f.provenance_roots, f.dispatch.as_ref()))
                .chain(
                    r.boundaries
                        .iter()
                        .flat_map(|b| roots(&b.provenance_roots, b.dispatch.as_ref())),
                )
                .collect(),
            Self::Reach(r) => r
                .matches
                .iter()
                .flat_map(|h| roots(&h.fact.provenance_roots, h.fact.dispatch.as_ref()))
                .chain(r.indeterminate.iter().flat_map(|b| match b {
                    Indeterminate::Boundary { evidence } => {
                        roots(&evidence.provenance_roots, evidence.dispatch.as_ref())
                    }
                    Indeterminate::Effect { fact, .. } => {
                        roots(&fact.provenance_roots, fact.dispatch.as_ref())
                    }
                }))
                .collect(),
        }
    }

    pub fn kind(&self) -> crate::PayloadKind {
        match self {
            Self::Effects(..) => crate::PayloadKind::Effects,
            Self::Reach(..) => crate::PayloadKind::Reach,
        }
    }
    pub fn into_effects(self) -> Option<EffectsReport> {
        if let Self::Effects(report) = self {
            Some(report)
        } else {
            None
        }
    }
    pub fn as_effects(&self) -> Option<&EffectsReport> {
        if let Self::Effects(report) = self {
            Some(report)
        } else {
            None
        }
    }
    pub fn into_reach(self) -> Option<ReachReport> {
        if let Self::Reach(report) = self {
            Some(report)
        } else {
            None
        }
    }
    pub fn as_reach(&self) -> Option<&ReachReport> {
        if let Self::Reach(report) = self {
            Some(report)
        } else {
            None
        }
    }
}

pub fn realm_key(realm: &ExecutionRealm) -> String {
    match realm {
        ExecutionRealm::Host => "host".to_string(),
        ExecutionRealm::Container { runtime, name } => format!("container/{runtime}/{name}"),
        ExecutionRealm::Kubernetes {
            namespace,
            pod,
            container,
        } => format!(
            "pod/{}/{pod}/{}",
            namespace.as_deref().unwrap_or(""),
            container.as_deref().unwrap_or(""),
        ),
        ExecutionRealm::Chroot { host_root } => {
            format!("chroot/{}", host_root.as_deref().unwrap_or(""))
        }
        ExecutionRealm::Remote { endpoint } => format!("remote/{endpoint}"),
    }
}

/// Content-addressed identity of a boundary in the enclosing query.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct BoundaryId(pub String);

impl std::fmt::Display for BoundaryId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}
