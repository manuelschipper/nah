#![forbid(unsafe_code)]
#![forbid(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types
)]

//! Effect Interpreter protocol v1: the versioned, consumer-neutral contract
//! for effect plans. This crate owns types, deterministic serialization, and
//! validation. It performs no analysis.

mod analysis;
mod canonical;
mod condition;
mod effect;
mod execution;
mod flow;
mod glob;
mod observation;
mod occurrence;
mod operation;
mod pattern;
mod plan;
mod provenance;
mod realm;
mod resource;
pub use pattern::{Field, PortField, ResourcePattern, TextField};
mod resource_scope;
mod subject;
mod validate;

pub use operation::{OPERATIONS, OperationSpec};

pub use effect::{
    AttrValue, Effect, EffectFact, EffectId, EffectIdentity, EffectOccurrence, EffectOrigin,
    Modality, Operation, RequestAssurance, ResolutionAssurance,
};
pub use execution::{
    ExecutionAssurance, ExecutionContent, ExecutionEdge, ExecutionEdgeKind, ExecutionGraph,
    ExecutionInput, ExecutionInputReason, ExecutionInputRole, ExecutionNode, ExecutionNodeRef,
    ExecutionPhase, ExecutionSelection, ExecutionSelector, ExecutionStream, ExecutionStreamRef,
    ExecutionStreamValue, ExecutionStreams, content_digest,
};
pub use flow::{
    CausalAssurance, CausalCardinality, CausalEdge, CausalReason, Causality, CausalityGraph,
    OccurrenceKind, OccurrenceNode, Port,
};
pub use glob::{collapse_wildcard_parents, glob_parent_prefix};
pub use observation::{
    Fact, ListedEntry, ListingFact, MAX_LISTING_DEPTH, MAX_LISTING_ENTRIES,
    MAX_OBSERVATION_PATH_BYTES, ObservationOutcome, ObservationQuery, ObservationRefusal, PathFact,
    PathKind, PathTarget, native_extension_candidate, valid_observation_outcome,
    valid_observation_query,
};
pub use occurrence::{
    ByteSpan, DispatchIdentity, FactId, FactIdentity, OccurrenceDescriptor, OccurrenceId,
};
pub use plan::{
    Analysis, AnalysisOutcome, AnalysisRefusalKind, BOUNDARY_REASONS, Boundary, BoundaryClass,
    BoundaryReason, BoundaryReasonSpec, BoundaryRef, BoundaryScope, CalleeReference, Coverage,
    CoverageClaim, CoverageLevel, DOMAINS, Domain, Limits, Plan,
};
pub use provenance::{ProvenanceKind, ProvenanceNode, ProvenanceRef};
pub use realm::ExecutionRealm;
pub use resource::{
    ArtifactEcosystem, ArtifactReference, ContainerStorage, KubernetesNamespace, PathPlatform,
    ResourceExpr, ResourceFamily, ResourceIdentity, display_identity, display_resource,
    display_resource_with_scope, filesystem_path, fold_fs_join, identity_family, is_absolute_path,
    normalize_container_runtime, normalize_path, normalize_resource, resource_domain,
    selector_family,
};
pub use subject::{
    FileDeleteArgs, FileEditArgs, FileEditBatchArgs, FileEditEntry, FilePatchArgs, FileReadArgs,
    FileTransferArgs, FileWriteArgs, FsFindArgs, FsGlobArgs, FsGrepArgs, FsListArgs, HostContext,
    LineRange, McpCallArgs, McpServerIdentity, McpStdioSource, McpTransport, OsDialect,
    PatchFormat, SourceDialect, SqlConnection, SqlDialect, Subject, ToolCall, TransferDirection,
    UnknownToolArgs,
};
pub use validate::repo_query::{
    RepoQueryParseError, RepoQueryValidationError, from_repo_query_json, validate_repo_query,
};
pub use validate::{
    SubjectValidationError, ValidationError, validate_effect_resource, validate_plan,
    validate_subject,
};

/// Schema identifier every v1 plan must carry.
pub const SCHEMA_V1: &str = "effinterp/plan/v1";

/// Parse a plan from JSON. Parsing does not validate semantic invariants;
/// call [`validate_plan`] on the result before trusting it.
pub fn from_plan_json(input: &str) -> Result<Plan, serde_json::Error> {
    serde_json::from_str(input)
}
pub use analysis::{
    AffectedScope, AnalysisBoundary, AnalysisConfiguration, AnalysisCoverage, AnalysisDependency,
    AnalysisDependencyKind, AnalysisGraph, AnalysisIdentity, AnalysisStatus, AnalysisSubject,
    AnalyzerIdentity, PartialReason, PayloadKind, ProtocolProvenanceKind, ProtocolProvenanceNode,
    ProvenanceDag, ProvenanceEdge, ProvenanceEdgeKind, REPO_QUERY_SCHEMA_V1, RepoQueryEnvelope,
    SourceEvidence, StaleReason,
};
pub use canonical::reject_duplicate_keys;
pub use canonical::{
    CONDITION_CALL_HASH_DOMAIN, CONDITION_SITE_HASH_DOMAIN, CONDITION_SOURCE_HASH_DOMAIN,
    REDACTED_LITERAL_HASH_DOMAIN, canonical_hash, canonical_json, stable_hash,
};
pub use validate::selector_identity_is_valid;

pub use resource_scope::{
    NamespaceKind, ResourceScope, ScopeDimension, ScopeEvidence, ScopeEvidenceKind, ScopeMatch,
    ScopeSelection, ScopeValue, cloud_scope, compare_scope, compare_scoped_identity,
    messaging_scope, namespace_resource, normalize_scope, object_scope, qualify_scope_origin,
};

mod satisfies;
pub use satisfies::{
    Binding, BindingSource, Bindings, EffectQuery, EffectTarget, Match, MatchReason, Proof,
    ProofStep, QualifiedExpr, QualifiedIdentity, RELATION_BYTE_LIMIT, RELATION_DEPTH_LIMIT,
    RELATION_WORK_LIMIT, RelationRequest, Scope, ScopeSet, satisfies, scope_intersects,
};

/// Validate a filesystem glob pattern against the glob grammar without
/// matching it. Failures are reported as a [`MatchReason`].
pub fn validate_glob(pattern: &str) -> Result<(), MatchReason> {
    glob::validate_glob(pattern).map_err(|error| match error {
        glob::GlobError::InvalidPattern => MatchReason::InvalidInput,
        glob::GlobError::Limit => MatchReason::Limit,
    })
}

/// Match a whole filesystem path against a glob pattern. Ordinary wildcards
/// stay inside one path segment and exclude a leading `.`; a whole-segment
/// `**` includes hidden descendants. Exceeding the match budget is
/// [`MatchReason::Limit`], never a silent `false`.
pub fn glob_match(pattern: &str, text: &str) -> Result<bool, MatchReason> {
    glob::glob_match(pattern, text).map_err(|error| match error {
        glob::GlobError::InvalidPattern => MatchReason::InvalidInput,
        glob::GlobError::Limit => MatchReason::Limit,
    })
}

/// [`glob_match`] where a wildcard also matches a leading `.`, as it does for
/// a tool that selects hidden entries (PowerShell's `-Force`).
pub fn glob_match_hidden(pattern: &str, text: &str) -> Result<bool, MatchReason> {
    glob::glob_match_hidden(pattern, text).map_err(|error| match error {
        glob::GlobError::InvalidPattern => MatchReason::InvalidInput,
        glob::GlobError::Limit => MatchReason::Limit,
    })
}

pub use satisfies::{SATISFIES_CASE_SCHEMA_V1, SatisfiesCase};

mod redacted;
pub use redacted::{
    REDACTED_SCHEMA_V1, RedactedBoundary, RedactedCausality, RedactedCausalityGraph,
    RedactedContainerStorage, RedactedEffect, RedactedExecutionGraph, RedactedExecutionInput,
    RedactedExecutionNode, RedactedExecutionSelection, RedactedExecutionSelector,
    RedactedExecutionStreamValue, RedactedKubernetesNamespace, RedactedOccurrenceKind,
    RedactedOccurrenceNode, RedactedPlan, RedactedProvenanceKind, RedactedProvenanceNode,
    RedactedRealm, RedactedResourceScope, RedactedScopeEvidence, RedactedStreams, RedactedSubject,
    RedactedSubjectKind, RedactedValidationError, ResourceShape, ResourceShapeIdentity,
    redact_plan, validate_redacted,
};

pub use condition::{
    Condition, ConditionAtom, ConditionEvidence, ConditionKind, ConditionOrigin, ConditionSource,
    MAX_CONDITION_DEPTH, MAX_CONDITION_EXCERPT_BYTES, MAX_CONDITION_NODES,
};

mod registration;
pub use registration::{Registration, RegistrationKind};

mod payload;
pub use payload::{
    BoundaryId, BoundaryIndeterminate, BoundaryRow, EffectsReport, Indeterminate, Payload,
    ReachHit, ReachReport, realm_key,
};
