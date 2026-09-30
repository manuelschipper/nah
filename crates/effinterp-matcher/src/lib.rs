#![forbid(unsafe_code)]
#![forbid(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types
)]

//! Engine-neutral matching of effect, flow and boundary assertions over a
//! validated `Plan`.
//!
//! A [`Query`] is versioned, serializable data: no callbacks, regular
//! expressions, unbounded recursion or host I/O. [`Evaluator::evaluate`]
//! answers it with an [`Outcome`]: a witnessed match, a disproof under the
//! evaluation's [`Absence`] mode, named unknowns, or a refusal when the query is
//! invalid or the evaluation exceeds its work bound. An unknown never
//! collapses into either answer. [`Evaluator::evaluate_in`] answers a query
//! against a scope of the plan's effects under an explicit [`Absence`] mode;
//! Nah's shipped guards use [`Absence::Conclusive`] and account for coverage
//! gaps themselves.
//!
//! Typed resource relations reuse the protocol's resource algebra
//! (`effinterp_proto::EffectQuery`). The `rendered` predicate instead tests the
//! text projection in [`render`]; a rendered prefix is never path containment.
//! A match is a witness to the query, not a claim that the operation ran.

mod evaluate;
mod query;
pub mod render;
#[cfg(test)]
mod tests;
mod validate;

pub use evaluate::{Evaluator, success_path};
pub use query::{
    Absence, Assertion, AttributePredicate, AttributeTest, BoundaryDomainsPredicate,
    BoundaryProvenancePredicate, ByteFlowAssurance, ByteFlowEdgeKind, Closure, ConditionPredicate,
    EffectRelation, EffectRelationship, ElementTest, Endpoint, KubernetesNamespacePredicate,
    LabelId, LabelProvider, LabelResource, LabelSelection, LabelStatus, NO_LABELS, NativeTool,
    NoLabels, ObservationBinding, ObservedPathKind, OperationMatch, Outcome, PathKindStatus,
    PortKind, PortScope, Projection, Query, RealmPredicate, Refusal, ResourceField,
    ResourcePredicate, ResourceVariant, RouteProvenance, SCHEMA_VERSION, SelectionLabelResource,
    SelectionShape, SelectionTarget, Selector, SubjectKind, TextPredicate, Traversal, Truth,
    Unknown, Witness,
};
pub use validate::QueryLimits;
