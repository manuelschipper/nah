use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::Serialize;
mod payload;

use crate::analysis::{
    AffectedScope, AnalysisDependencyKind, AnalysisStatus, PartialReason, ProtocolProvenanceKind,
    REPO_QUERY_SCHEMA_V1, RepoQueryEnvelope, StaleReason,
};
use crate::flow::{CausalReason, OccurrenceKind};
use crate::occurrence::{FactId, OccurrenceId};
use crate::plan::{
    BoundaryClass, BoundaryReason, BoundaryRef, BoundaryScope, CoverageLevel, DOMAINS, Plan,
};
use crate::provenance::{ProvenanceKind, ProvenanceRef};
use crate::resource::{ContainerStorage, ResourceExpr, ResourceIdentity, resource_domain};
use crate::subject::{Subject, ToolCall};
use crate::{SCHEMA_V1, effect::Operation};

/// A semantic invariant violated by an analyzed subject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubjectValidationError {
    InvalidToolCall { message: &'static str },
    InvalidContext { message: &'static str },
    InvalidSource { message: &'static str },
}

impl fmt::Display for SubjectValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidToolCall { message }
            | Self::InvalidSource { message }
            | Self::InvalidContext { message } => f.write_str(message),
        }
    }
}

impl std::error::Error for SubjectValidationError {}

/// Validate invariants that Rust's field types cannot express.
pub fn validate_subject(subject: &Subject) -> Result<(), SubjectValidationError> {
    let context = match subject {
        Subject::Exec { context, .. }
        | Subject::Shell { context, .. }
        | Subject::Source { context, .. }
        | Subject::ToolCall { context, .. } => Some(context),
        Subject::Sql { .. } => None,
    };
    if context.is_some_and(|context| {
        context
            .env_unset
            .iter()
            .any(|name| context.env.contains_key(name))
    }) {
        return Err(SubjectValidationError::InvalidContext {
            message: "environment name is both present and absent",
        });
    }
    match subject {
        Subject::Source {
            language, dialect, ..
        } => {
            if !matches!(
                language.as_str(),
                "python"
                    | "js"
                    | "go"
                    | "ruby"
                    | "php"
                    | "java"
                    | "rust"
                    | "powershell"
                    | "cmd"
                    | "lua"
                    | "r"
                    | "julia"
                    | "perl"
                    | "swift"
            ) {
                return Err(SubjectValidationError::InvalidSource {
                    message: "unsupported source language",
                });
            }
            let valid_dialect = matches!(
                (language.as_str(), dialect),
                (
                    "python",
                    None | Some(crate::SourceDialect::Ipython | crate::SourceDialect::PrimeAgent)
                ) | (
                    "js",
                    Some(crate::SourceDialect::Js | crate::SourceDialect::Ts)
                ) | (
                    "go" | "ruby"
                        | "php"
                        | "java"
                        | "rust"
                        | "powershell"
                        | "cmd"
                        | "lua"
                        | "r"
                        | "julia"
                        | "perl"
                        | "swift",
                    None,
                )
            );
            if !valid_dialect {
                return Err(SubjectValidationError::InvalidSource {
                    message: "source dialect does not match source language",
                });
            }
            Ok(())
        }
        Subject::ToolCall { call, .. } => validate_tool_call(call),
        _ => Ok(()),
    }
}

fn validate_tool_call(call: &ToolCall) -> Result<(), SubjectValidationError> {
    call.validation_error().map_or(Ok(()), |message| {
        Err(SubjectValidationError::InvalidToolCall { message })
    })
}

/// A semantic or integrity violation in an analysis envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepoQueryValidationError {
    WrongSchema { found: String },
    EmptyField { field: &'static str },
    MissingStatusReasons { status: &'static str },
    CompleteWithBoundaries,
    InvalidDigest { field: &'static str, value: String },
    InvalidOccurrence { id: String },
    AbsoluteOrigin { origin: String },
    DuplicateProvenanceNode { id: String },
    DanglingProvenanceRef { id: String },
    CyclicProvenance,
    InvalidBoundary { id: String },
    InvalidPayload { path: String },
    ContentHashMismatch { expected: String, found: String },
}

impl fmt::Display for RepoQueryValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// JSON syntax or semantic validation failure while parsing an envelope.
#[derive(Debug)]
pub enum RepoQueryParseError {
    Json(serde_json::Error),
    Validation(Vec<RepoQueryValidationError>),
    NonCanonical,
}

impl fmt::Display for RepoQueryParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(error) => write!(f, "invalid analysis JSON: {error}"),
            Self::Validation(errors) => write!(f, "invalid analysis envelope: {errors:?}"),
            Self::NonCanonical => write!(f, "analysis envelope is not canonical JSON"),
        }
    }
}

impl std::error::Error for RepoQueryParseError {}

/// A semantic invariant violated by a parsed plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    InvalidCondition {
        context: String,
    },
    InvalidRequestAssurance {
        effect: usize,
    },
    InvalidEffectId {
        effect: usize,
    },
    DuplicateEffectId {
        effect: usize,
    },
    WrongSchema {
        found: String,
    },
    EmptyAnalysisField {
        field: &'static str,
    },
    InvalidSubject {
        error: SubjectValidationError,
    },
    MalformedOperation {
        effect: usize,
        operation: String,
    },
    NestedAttributeList {
        effect: usize,
        attribute: String,
    },
    UncoveredDomain {
        effect: usize,
        domain: String,
    },
    DanglingProvenanceRef {
        context: String,
        index: u32,
    },
    InvalidSourceInputProvenance {
        node: usize,
    },
    InvalidHostObservationProvenance {
        node: usize,
    },
    ForwardAntecedent {
        node: usize,
        antecedent: u32,
    },
    DanglingExecutionRef {
        context: String,
        node: u32,
    },
    ConflictingStdinSources {
        node: usize,
    },
    DanglingBoundaryRef {
        node: usize,
        boundary: u32,
    },
    InvalidExecutionInput {
        node: usize,
    },
    MissingExecutionEntry,
    ExecutionEdgeOrder {
        edge: usize,
    },
    ExecutionNodeWithoutIncoming {
        node: usize,
    },
    EffectRealmMismatch {
        effect: usize,
    },
    EmptyResourceParts {
        effect: usize,
    },
    InvalidPattern {
        effect: usize,
    },
    EmptyPattern {
        effect: usize,
    },
    EmptyBoundaryDomains {
        boundary: usize,
    },
    MalformedBoundaryReason {
        boundary: usize,
        reason: String,
    },
    InvalidBoundaryDomain {
        boundary: usize,
        domain: String,
    },
    UnexplainedCoverage {
        domain: String,
    },
    UnexplainedCausalityCoverage,
    InvalidCoverageGaps {
        domain: String,
    },
    UnclaimedBoundaryDomain {
        boundary: usize,
        domain: String,
    },
    /// A boundary declares opacity in a domain the coverage map still reports
    /// as Full — a plan cannot be both opaque and complete there.
    BoundaryContradictsCoverage {
        boundary: usize,
        domain: String,
    },
    BoundaryResourceDomainMismatch {
        boundary: usize,
        domain: Option<String>,
    },
    InvalidBoundaryResource {
        boundary: usize,
    },
    NonCanonicalBoundaryResource {
        boundary: usize,
    },
    InvalidBoundaryLimit {
        boundary: usize,
        limit: Option<String>,
    },
    /// Environment scope on a reason that does not name environment behavior,
    /// or on a boundary that is a limit or a parse or support failure.
    InvalidEnvironmentScope {
        boundary: usize,
    },
    /// A concrete resource identity carries an empty required field or an
    /// otherwise invalid identity field: an invalid resource scope, a
    /// managed-infrastructure tool other than `terraform`/`tofu`, only one of
    /// `resource_type` and `address`, or a forbidden artifact field shape.
    EmptyResourceIdentity {
        effect: usize,
    },
    NonCanonicalResource {
        effect: usize,
    },
    /// A concrete effect targets a resource identity of an incompatible
    /// family (e.g. filesystem.* on a database table).
    IncompatibleResourceFamily {
        effect: usize,
        operation: String,
        identity: &'static str,
    },
    DuplicateOccurrenceId {
        node: usize,
        id: String,
    },
    CausalRealmMismatch {
        node: usize,
    },
    CausalDanglingOccurrence {
        edge: usize,
        id: String,
    },
    /// A `resource_transfer` edge whose endpoint is not a resource
    /// interaction: a transfer relates the two endpoints of one modeled
    /// movement, so a port, value, or boundary endpoint is corrupt.
    CausalTransferEndpoint {
        edge: usize,
    },
    InvalidCausalCardinality {
        context: String,
    },
    CausalOrder {
        context: String,
    },
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCondition { context } => write!(f, "invalid condition at {context}"),
            Self::InvalidRequestAssurance { effect } => write!(
                f,
                "effects[{effect}] has unsupported exact request assurance"
            ),
            Self::InvalidEffectId { effect } => {
                write!(f, "effects[{effect}] has an invalid or mismatched ID")
            }
            Self::DuplicateEffectId { effect } => write!(f, "effects[{effect}] has a duplicate ID"),
            Self::WrongSchema { found } => {
                write!(f, "schema is {found:?}, expected {SCHEMA_V1:?}")
            }
            Self::EmptyAnalysisField { field } => write!(f, "analysis.{field} is empty"),
            Self::InvalidSubject { error } => write!(f, "subject is invalid: {error}"),
            Self::MalformedOperation { effect, operation } => {
                write!(f, "effects[{effect}] operation {operation:?} is malformed")
            }
            Self::NestedAttributeList { effect, attribute } => write!(
                f,
                "effects[{effect}] attribute {attribute:?} nests a list in a list"
            ),
            Self::UncoveredDomain { effect, domain } => write!(
                f,
                "effects[{effect}] domain {domain:?} has no coverage entry"
            ),
            Self::InvalidSourceInputProvenance { node } => {
                write!(f, "invalid supporting source provenance at node {node}")
            }
            Self::InvalidHostObservationProvenance { node } => {
                write!(f, "invalid host observation provenance at node {node}")
            }
            Self::DanglingProvenanceRef { context, index } => {
                write!(f, "{context} references missing provenance node {index}")
            }
            Self::ForwardAntecedent { node, antecedent } => write!(
                f,
                "provenance[{node}] antecedent {antecedent} is not an earlier node"
            ),
            Self::DanglingExecutionRef { context, node } => {
                write!(f, "{context} references missing execution node {node}")
            }
            Self::ConflictingStdinSources { node } => write!(
                f,
                "execution_graph.nodes[{node}] has both a stdin reference and stdin value"
            ),
            Self::DanglingBoundaryRef { node, boundary } => {
                write!(
                    f,
                    "execution_graph.nodes[{node}] references missing boundary {boundary}"
                )
            }
            Self::InvalidExecutionInput { node } => {
                write!(f, "invalid execution input at node {node}")
            }
            Self::MissingExecutionEntry => write!(f, "execution graph has no valid entry node"),
            Self::ExecutionEdgeOrder { edge } => write!(
                f,
                "execution_graph.edges[{edge}] violates execution-node order"
            ),
            Self::ExecutionNodeWithoutIncoming { node } => {
                write!(f, "execution_graph.nodes[{node}] has no incoming edge")
            }
            Self::EffectRealmMismatch { effect } => {
                write!(f, "effects[{effect}] realm differs from its execution node")
            }
            Self::EmptyResourceParts { effect } => {
                write!(f, "effects[{effect}] has an empty join or union")
            }
            Self::InvalidPattern { effect } => {
                write!(f, "effects[{effect}] has an invalid filesystem pattern")
            }
            Self::EmptyPattern { effect } => {
                write!(f, "effects[{effect}] has an empty resource pattern")
            }
            Self::EmptyBoundaryDomains { boundary } => {
                write!(f, "boundaries[{boundary}] affects no domains")
            }
            Self::MalformedBoundaryReason { boundary, reason } => write!(
                f,
                "boundaries[{boundary}] reason {reason:?} is not lower snake case"
            ),
            Self::InvalidBoundaryDomain { boundary, domain } => {
                write!(f, "boundaries[{boundary}] names unknown domain {domain:?}")
            }
            Self::UnexplainedCoverage { domain } => {
                write!(f, "non-full coverage for {domain:?} has no boundary")
            }
            Self::InvalidCoverageGaps { domain } => write!(
                f,
                "coverage gaps for {domain:?} must exactly name its boundaries in ascending order"
            ),
            Self::UnclaimedBoundaryDomain { boundary, domain } => write!(
                f,
                "boundaries[{boundary}] domain {domain:?} has no coverage claim"
            ),
            Self::UnexplainedCausalityCoverage => {
                write!(f, "non-full causality coverage has no dataflow boundary")
            }
            Self::BoundaryContradictsCoverage { boundary, domain } => write!(
                f,
                "boundaries[{boundary}] declares opacity in {domain:?} but coverage is Full"
            ),
            Self::BoundaryResourceDomainMismatch { boundary, domain } => write!(
                f,
                "boundaries[{boundary}] affected resource has undeclared domain {domain:?}"
            ),
            Self::InvalidBoundaryResource { boundary } => {
                write!(f, "boundaries[{boundary}] has an invalid affected resource")
            }
            Self::NonCanonicalBoundaryResource { boundary } => write!(
                f,
                "boundaries[{boundary}] has a non-canonical affected resource"
            ),
            Self::InvalidBoundaryLimit { boundary, limit } => write!(
                f,
                "boundaries[{boundary}] has invalid limit attribution {limit:?}"
            ),
            Self::InvalidEnvironmentScope { boundary } => write!(
                f,
                "boundaries[{boundary}] cannot be scoped to the environment"
            ),
            Self::EmptyResourceIdentity { effect } => {
                write!(
                    f,
                    "effects[{effect}] has an empty concrete resource identity"
                )
            }
            Self::NonCanonicalResource { effect } => {
                write!(
                    f,
                    "effects[{effect}] has a non-canonical resource expression"
                )
            }
            Self::IncompatibleResourceFamily {
                effect,
                operation,
                identity,
            } => write!(
                f,
                "effects[{effect}] operation {operation:?} targets incompatible {identity} identity"
            ),
            Self::DuplicateOccurrenceId { node, id } => {
                write!(f, "causality.nodes[{node}] duplicates occurrence id {id}")
            }
            Self::CausalRealmMismatch { node } => write!(
                f,
                "causality.nodes[{node}] realm differs from its execution node"
            ),
            Self::CausalDanglingOccurrence { edge, id } => {
                write!(
                    f,
                    "causality.edges[{edge}] references missing occurrence {id}"
                )
            }
            Self::CausalTransferEndpoint { edge } => write!(
                f,
                "causality.edges[{edge}] is a resource_transfer between occurrences that are not both resource interactions"
            ),
            Self::InvalidCausalCardinality { context } => {
                write!(f, "{context} has an invalid cardinality")
            }
            Self::CausalOrder { context } => write!(f, "{context} has a noncanonical order"),
        }
    }
}

/// Check every semantic invariant of a v1 plan, accumulating all violations.
pub fn validate_plan(plan: &Plan) -> Result<(), Vec<ValidationError>> {
    let mut errors = Vec::new();

    if plan.schema != SCHEMA_V1 {
        errors.push(ValidationError::WrongSchema {
            found: plan.schema.clone(),
        });
    }
    if plan.analysis.engine_version.is_empty() {
        errors.push(ValidationError::EmptyAnalysisField {
            field: "engine_version",
        });
    }
    if plan.analysis.model_set.is_empty() {
        errors.push(ValidationError::EmptyAnalysisField { field: "model_set" });
    }
    if let Err(error) = validate_subject(&plan.subject) {
        errors.push(ValidationError::InvalidSubject { error });
    }

    let node_count = plan.provenance.len() as u32;
    let execution_count = plan.execution_graph.nodes.len() as u32;
    let check_refs = |context: String, refs: &[ProvenanceRef], errors: &mut Vec<_>| {
        for r in refs {
            if r.0 >= node_count {
                errors.push(ValidationError::DanglingProvenanceRef {
                    context: context.clone(),
                    index: r.0,
                });
            }
        }
    };

    let request_selections = plan.execution_graph.exact_request_selections();
    let expected_ids = plan.expected_effect_ids().ok();
    let mut effect_ids = BTreeSet::new();
    for (i, effect) in plan.effects.iter().enumerate() {
        if effect.request_assurance == crate::RequestAssurance::Exact
            && (request_selections.get(effect.execution.0 as usize) != Some(&true)
                || effect
                    .condition
                    .as_ref()
                    .is_some_and(crate::Condition::is_widened)
                || !effect.provenance.iter().any(|reference| {
                    plan.provenance
                        .get(reference.0 as usize)
                        .is_some_and(|node| {
                            matches!(node.kind, ProvenanceKind::ModelApplication { .. })
                        })
                }))
        {
            errors.push(ValidationError::InvalidRequestAssurance { effect: i });
        }
        if effect.condition.as_ref().is_some_and(|c| {
            !c.is_valid() || (c.is_widened() && effect.modality == crate::Modality::MustOnSuccess)
        }) {
            errors.push(ValidationError::InvalidCondition {
                context: format!("effect[{i}]"),
            });
        }
        if !effect.id.is_well_formed()
            || expected_ids.as_ref().is_some_and(|ids| effect.id != ids[i])
        {
            errors.push(ValidationError::InvalidEffectId { effect: i });
        }
        if !effect_ids.insert(&effect.id) {
            errors.push(ValidationError::DuplicateEffectId { effect: i });
        }
        if effect.execution.0 >= execution_count {
            errors.push(ValidationError::DanglingExecutionRef {
                context: format!("effects[{i}]"),
                node: effect.execution.0,
            });
        } else if plan.execution_graph.nodes[effect.execution.0 as usize].realm != effect.realm {
            errors.push(ValidationError::EffectRealmMismatch { effect: i });
        }
        if !effect.operation.is_well_formed() {
            errors.push(ValidationError::MalformedOperation {
                effect: i,
                operation: effect.operation.0.clone(),
            });
        }
        for (name, value) in &effect.attributes {
            if let crate::AttrValue::List(values) = value
                && values
                    .iter()
                    .any(|value| matches!(value, crate::AttrValue::List(_)))
            {
                errors.push(ValidationError::NestedAttributeList {
                    effect: i,
                    attribute: name.clone(),
                });
            }
        }
        let domain = effect.operation.domain();
        if !plan.coverage.0.keys().any(|d| d.0 == domain) {
            errors.push(ValidationError::UncoveredDomain {
                effect: i,
                domain: domain.to_string(),
            });
        }
        validate_effect_resource(i, &effect.operation, &effect.resource, &mut errors);
        if crate::normalize_resource(effect.resource.clone(), crate::PathPlatform::Posix)
            != effect.resource
            && crate::normalize_resource(effect.resource.clone(), crate::PathPlatform::Windows)
                != effect.resource
        {
            errors.push(ValidationError::NonCanonicalResource { effect: i });
        }
        check_refs(format!("effects[{i}]"), &effect.provenance, &mut errors);
    }

    for (i, node) in plan.provenance.iter().enumerate() {
        for a in &node.antecedents {
            if a.0 as usize >= i {
                errors.push(ValidationError::ForwardAntecedent {
                    node: i,
                    antecedent: a.0,
                });
            }
        }
        if let ProvenanceKind::SourceInput { path, digest } = &node.kind
            && (path.is_empty() || !valid_digest(digest))
        {
            errors.push(ValidationError::InvalidSourceInputProvenance { node: i });
        }
        if let ProvenanceKind::HostObservation { query, outcome } = &node.kind
            && !(crate::valid_observation_query(query)
                && crate::valid_observation_outcome(query, outcome))
        {
            errors.push(ValidationError::InvalidHostObservationProvenance { node: i });
        }
        if let ProvenanceKind::Execution { node: execution } = node.kind
            && execution >= execution_count
        {
            errors.push(ValidationError::DanglingExecutionRef {
                context: format!("provenance[{i}]"),
                node: execution,
            });
        }
    }

    if execution_count == 0 || plan.execution_graph.entry.0 >= execution_count {
        errors.push(ValidationError::MissingExecutionEntry);
    }
    let mut incoming = vec![0usize; execution_count as usize];
    for (i, node) in plan.execution_graph.nodes.iter().enumerate() {
        if !valid_execution_input(node, i) {
            errors.push(ValidationError::InvalidExecutionInput { node: i });
        }
        if let Err(error) = validate_subject(&node.subject) {
            errors.push(ValidationError::InvalidSubject { error });
        }
        if let Some(boundary) = node.boundary
            && boundary.0 as usize >= plan.boundaries.len()
        {
            errors.push(ValidationError::DanglingBoundaryRef {
                node: i,
                boundary: boundary.0,
            });
        }
        check_refs(
            format!("execution_graph.nodes[{i}]"),
            &node.evidence,
            &mut errors,
        );
        if node.streams.stdin.is_some() && node.streams.stdin_value.is_some() {
            errors.push(ValidationError::ConflictingStdinSources { node: i });
        }
        if let Some(value) = &node.streams.stdin_value {
            check_refs(
                format!("execution_graph.nodes[{i}].streams.stdin_value"),
                &value.provenance,
                &mut errors,
            );
        }
        for stream in [
            node.streams.stdin.as_ref(),
            node.streams.stdout.as_ref(),
            node.streams.stderr.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            if stream.node.0 >= execution_count {
                errors.push(ValidationError::DanglingExecutionRef {
                    context: format!("execution_graph.nodes[{i}].streams"),
                    node: stream.node.0,
                });
            }
        }
    }
    for (i, edge) in plan.execution_graph.edges.iter().enumerate() {
        for reference in [edge.from, edge.to] {
            if reference.0 >= execution_count {
                errors.push(ValidationError::DanglingExecutionRef {
                    context: format!("execution_graph.edges[{i}]"),
                    node: reference.0,
                });
            }
        }
        if edge.to.0 < execution_count {
            incoming[edge.to.0 as usize] += 1;
        }
        if (!edge.cycle && edge.to.0 <= edge.from.0) || (edge.cycle && edge.to.0 > edge.from.0) {
            errors.push(ValidationError::ExecutionEdgeOrder { edge: i });
        }
        check_refs(
            format!("execution_graph.edges[{i}]"),
            &edge.evidence,
            &mut errors,
        );
    }
    for (i, count) in incoming.into_iter().enumerate() {
        if i != plan.execution_graph.entry.0 as usize && count == 0 {
            errors.push(ValidationError::ExecutionNodeWithoutIncoming { node: i });
        }
    }

    let mut explained_domains: BTreeMap<&str, Vec<BoundaryRef>> = BTreeMap::new();
    for (i, boundary) in plan.boundaries.iter().enumerate() {
        if boundary.domains.is_empty() {
            errors.push(ValidationError::EmptyBoundaryDomains { boundary: i });
        }
        if !boundary.reason.is_valid() {
            errors.push(ValidationError::MalformedBoundaryReason {
                boundary: i,
                reason: boundary.reason.to_string(),
            });
        }
        for domain in &boundary.domains {
            if domain.0 != "dataflow" && !DOMAINS.contains(&domain.0.as_str()) {
                errors.push(ValidationError::InvalidBoundaryDomain {
                    boundary: i,
                    domain: domain.0.clone(),
                });
            }
            let refs = explained_domains.entry(domain.0.as_str()).or_default();
            if refs.last() != Some(&BoundaryRef(i as u32)) {
                refs.push(BoundaryRef(i as u32));
            }
            if domain.0 != "dataflow" && !plan.coverage.0.contains_key(domain) {
                errors.push(ValidationError::UnclaimedBoundaryDomain {
                    boundary: i,
                    domain: domain.0.clone(),
                });
            }
            if plan.coverage.is_full(domain)
                || domain.0 == "dataflow" && plan.causality.coverage.level == CoverageLevel::Full
            {
                errors.push(ValidationError::BoundaryContradictsCoverage {
                    boundary: i,
                    domain: domain.0.clone(),
                });
            }
        }
        if let Some(resource) = &boundary.affected_resource {
            let domain = resource_domain(resource);
            let mut resource_errors = Vec::new();
            validate_resource(0, resource, &mut resource_errors);
            if !resource_errors.is_empty() || resource_has_invalid_identity_fields(resource) {
                errors.push(ValidationError::InvalidBoundaryResource { boundary: i });
            }
            if domain.is_none()
                || !boundary
                    .domains
                    .iter()
                    .any(|declared| Some(declared.0.as_str()) == domain)
            {
                errors.push(ValidationError::BoundaryResourceDomainMismatch {
                    boundary: i,
                    domain: domain.map(str::to_string),
                });
            }
            if crate::normalize_resource(resource.clone(), crate::PathPlatform::Posix) != *resource
                && crate::normalize_resource(resource.clone(), crate::PathPlatform::Windows)
                    != *resource
            {
                errors.push(ValidationError::NonCanonicalBoundaryResource { boundary: i });
            }
        }
        if boundary.limit.as_ref().is_some_and(String::is_empty)
            || boundary.reason == BoundaryReason::LIMIT_SATURATED
                && (boundary.limit.is_none() || boundary.class != BoundaryClass::Limit)
        {
            errors.push(ValidationError::InvalidBoundaryLimit {
                boundary: i,
                limit: boundary.limit.clone(),
            });
        }
        if boundary.scope == BoundaryScope::Environment
            && (boundary.limit.is_some()
                || !matches!(
                    boundary.class,
                    BoundaryClass::Unmodeled | BoundaryClass::Unresolved
                )
                || !boundary.reason.spec().is_some_and(|spec| spec.environment))
        {
            errors.push(ValidationError::InvalidEnvironmentScope { boundary: i });
        }
        check_refs(
            format!("boundaries[{i}]"),
            &boundary.provenance,
            &mut errors,
        );
    }
    for (domain, level) in &plan.coverage.0 {
        if level.level != CoverageLevel::Full && !explained_domains.contains_key(domain.0.as_str())
        {
            errors.push(ValidationError::UnexplainedCoverage {
                domain: domain.0.clone(),
            });
        }
    }
    if plan.causality.coverage.level != CoverageLevel::Full
        && !explained_domains.contains_key("dataflow")
    {
        errors.push(ValidationError::UnexplainedCausalityCoverage);
    }

    for (domain, claim) in plan
        .coverage
        .0
        .iter()
        .map(|(domain, claim)| (domain.0.as_str(), claim))
        .chain(std::iter::once(("dataflow", &plan.causality.coverage)))
    {
        let expected = explained_domains.get(domain).map_or(&[][..], Vec::as_slice);
        if claim.gaps != expected
            || (claim.level == CoverageLevel::Full && !claim.gaps.is_empty())
            || (claim.level != CoverageLevel::Full && claim.gaps.is_empty())
        {
            errors.push(ValidationError::InvalidCoverageGaps {
                domain: domain.to_string(),
            });
        }
    }

    if let Some(graph) = &plan.causality.graph {
        let mut occurrence_ids = BTreeSet::new();
        let mut resource_occurrences = BTreeSet::new();
        let mut widened_occurrences = BTreeSet::new();
        for (i, node) in graph.nodes.iter().enumerate() {
            if node.condition.as_ref().is_some_and(|c| {
                !c.is_valid() || (c.is_widened() && node.modality == crate::Modality::MustOnSuccess)
            }) {
                errors.push(ValidationError::InvalidCondition {
                    context: format!("node[{i}]"),
                });
            }
            if node
                .condition
                .as_ref()
                .is_some_and(crate::Condition::is_widened)
            {
                widened_occurrences.insert(&node.id);
            }
            if !occurrence_ids.insert(node.id.clone()) {
                errors.push(ValidationError::DuplicateOccurrenceId {
                    node: i,
                    id: node.id.0.clone(),
                });
            }
            if matches!(node.occurrence, OccurrenceKind::ResourceInteraction { .. }) {
                resource_occurrences.insert(node.id.clone());
            }
            if node.order != i as u32 {
                errors.push(ValidationError::CausalOrder {
                    context: format!("causality.nodes[{i}]"),
                });
            }
            if !causal_cardinality_is_legal(node.modality, node.cardinality) {
                errors.push(ValidationError::InvalidCausalCardinality {
                    context: format!("causality.nodes[{i}]"),
                });
            }
            if let Some(execution) = node.execution {
                if execution.0 >= execution_count {
                    errors.push(ValidationError::DanglingExecutionRef {
                        context: format!("causality.nodes[{i}]"),
                        node: execution.0,
                    });
                } else if node.realm != plan.execution_graph.nodes[execution.0 as usize].realm {
                    errors.push(ValidationError::CausalRealmMismatch { node: i });
                }
            }
            check_refs(
                format!("causality.nodes[{i}]"),
                &node.provenance,
                &mut errors,
            );
        }
        for (i, edge) in graph.edges.iter().enumerate() {
            if edge.condition.as_ref().is_some_and(|c| {
                !c.is_valid() || (c.is_widened() && edge.modality == crate::Modality::MustOnSuccess)
            }) {
                errors.push(ValidationError::InvalidCondition {
                    context: format!("edge[{i}]"),
                });
            }
            if edge.assurance == crate::CausalAssurance::Exact
                && (edge
                    .condition
                    .as_ref()
                    .is_some_and(crate::Condition::is_widened)
                    || widened_occurrences.contains(&edge.from)
                    || widened_occurrences.contains(&edge.to))
            {
                errors.push(ValidationError::InvalidCondition {
                    context: format!("edge[{i}].assurance"),
                });
            }
            for id in [&edge.from, &edge.to] {
                if !occurrence_ids.contains(id) {
                    errors.push(ValidationError::CausalDanglingOccurrence {
                        edge: i,
                        id: id.0.clone(),
                    });
                }
            }
            if edge.order != i as u32 {
                errors.push(ValidationError::CausalOrder {
                    context: format!("causality.edges[{i}]"),
                });
            }
            if edge.reason == CausalReason::ResourceTransfer
                && !(resource_occurrences.contains(&edge.from)
                    && resource_occurrences.contains(&edge.to))
            {
                errors.push(ValidationError::CausalTransferEndpoint { edge: i });
            }
            if !causal_cardinality_is_legal(edge.modality, edge.cardinality) {
                errors.push(ValidationError::InvalidCausalCardinality {
                    context: format!("causality.edges[{i}]"),
                });
            }
            check_refs(
                format!("causality.edges[{i}]"),
                &edge.provenance,
                &mut errors,
            );
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// The per-effect resource rules: structural resource errors (empty join/union
/// parts, empty pattern), empty or otherwise invalid identity fields (see
/// [`ValidationError::EmptyResourceIdentity`]), and operation/family
/// compatibility. `validate(plan)` and `PlanBuilder::effect` share this one
/// definition so the builder cannot drift from the protocol.
pub fn validate_effect_resource(
    effect: usize,
    operation: &Operation,
    resource: &ResourceExpr,
    errors: &mut Vec<ValidationError>,
) {
    validate_resource(effect, resource, errors);
    if resource_has_invalid_identity_fields(resource) {
        errors.push(ValidationError::EmptyResourceIdentity { effect });
    }
    if let Some(identity) = incompatible_resource(operation, resource) {
        errors.push(ValidationError::IncompatibleResourceFamily {
            effect,
            operation: operation.0.clone(),
            identity,
        });
    }
}

fn causal_cardinality_is_legal(
    modality: crate::Modality,
    cardinality: crate::CausalCardinality,
) -> bool {
    if cardinality
        .max
        .is_some_and(|max| cardinality.min > max || max == 0)
    {
        return false;
    }
    match modality {
        crate::Modality::May => cardinality.min == 0,
        crate::Modality::MustOnSuccess => cardinality.min > 0,
    }
}

fn identity_fields_are_invalid(identity: &ResourceIdentity) -> bool {
    if !crate::resource_scope::valid_resource_scope(identity, false) {
        return true;
    }
    if identity
        .infrastructure_values()
        .into_iter()
        .any(resource_has_invalid_identity_fields)
    {
        return true;
    }
    match identity {
        ResourceIdentity::KubernetesResource { kind, name, .. } => {
            kind.is_empty()
                || matches!(name.as_ref(), ResourceExpr::Literal { value } if value.is_empty())
        }
        ResourceIdentity::ManagedInfrastructure {
            tool,
            resource_type,
            address,
            ..
        } => {
            !matches!(tool.as_str(), "terraform" | "tofu")
                || resource_type.as_ref().is_some_and(String::is_empty)
                || address.as_ref().is_some_and(String::is_empty)
                || resource_type.is_some() != address.is_some()
        }
        ResourceIdentity::Artifact {
            endpoint,
            name,
            reference,
            ..
        } => [endpoint.as_ref(), name.as_ref()]
            .into_iter()
            .chain(reference.value())
            .any(|value| !artifact_field_is_valid(value)),
        ResourceIdentity::FsPath { path } => path.is_empty(),
        ResourceIdentity::UserHome { user } => user.is_empty(),
        ResourceIdentity::EnvironmentVariable { name } => name.is_empty(),
        ResourceIdentity::GitRepository {
            worktree,
            git_dir,
            pathspec,
        } => {
            worktree.is_none() && git_dir.is_none()
                || worktree
                    .iter()
                    .chain(git_dir)
                    .chain(pathspec)
                    .any(|expr| resource_has_invalid_identity_fields(expr))
        }
        ResourceIdentity::Process { executable, .. } => executable.is_empty(),
        ResourceIdentity::NetworkEndpoint { host, .. } => host.is_empty(),
        ResourceIdentity::Container {
            runtime,
            name,
            image,
            ..
        } => {
            runtime.is_empty()
                || name.is_none() && image.is_none()
                || container_storage_has_invalid_identity_fields(identity)
        }
        ResourceIdentity::DatabaseTable { table, .. } => table.is_empty(),
        ResourceIdentity::DatabaseSchema {
            server,
            database,
            schema,
        } => server.is_none() && database.is_none() && schema.is_none(),
        ResourceIdentity::ObjectStore { bucket, .. } => bucket.is_empty(),
        ResourceIdentity::CloudResource {
            service, kind, id, ..
        } => service.is_empty() || kind.is_empty() || id.as_ref().is_some_and(String::is_empty),
        ResourceIdentity::MessageTopic { name, .. } => name.is_empty(),
        ResourceIdentity::ServiceUnit { manager, name }
        | ResourceIdentity::StorageVolume { manager, name } => {
            manager.is_empty() || name.is_empty()
        }
        ResourceIdentity::ScheduledJob { scheduler, .. } => scheduler.is_empty(),
        ResourceIdentity::BlockDevice { device } => device.is_empty(),
        ResourceIdentity::CredentialStore { provider, .. } => provider.is_empty(),
        ResourceIdentity::HostSystem {} => false,
    }
}

fn artifact_field_is_valid(value: &ResourceExpr) -> bool {
    match value {
        ResourceExpr::Concrete { .. } => false,
        ResourceExpr::Literal { value } => !value.is_empty(),
        ResourceExpr::Parameter { name } | ResourceExpr::Environment { name } => !name.is_empty(),
        ResourceExpr::Pattern {
            pattern: crate::ResourcePattern::ArtifactField { glob },
        } => !glob.is_empty(),
        ResourceExpr::Pattern { .. } => false,
        ResourceExpr::Unresolved { family } => {
            family.domain() == Some("artifact") || matches!(family.0.as_ref(), "value" | "unknown")
        }
        ResourceExpr::Property { base, name } => !name.is_empty() && artifact_field_is_valid(base),
        ResourceExpr::Join { parts }
        | ResourceExpr::Union {
            alternatives: parts,
        } => !parts.is_empty() && parts.iter().all(artifact_field_is_valid),
    }
}

fn container_storage_has_invalid_identity_fields(identity: &ResourceIdentity) -> bool {
    let ResourceIdentity::Container { storage, .. } = identity else {
        return false;
    };
    storage.iter().any(|storage| match storage {
        ContainerStorage::BindMount {
            host_path,
            container_path,
            ..
        } => {
            resource_has_invalid_identity_fields(host_path)
                || resource_has_invalid_identity_fields(container_path)
        }
        ContainerStorage::Volume {
            name,
            container_path,
        } => name.is_empty() || resource_has_invalid_identity_fields(container_path),
    })
}

fn resource_has_invalid_identity_fields(expr: &ResourceExpr) -> bool {
    match expr {
        ResourceExpr::Concrete { identity } => identity_fields_are_invalid(identity),
        ResourceExpr::Property { base, .. } => resource_has_invalid_identity_fields(base),
        ResourceExpr::Join { parts }
        | ResourceExpr::Union {
            alternatives: parts,
        } => parts.iter().any(resource_has_invalid_identity_fields),
        _ => false,
    }
}

fn identity_matches_operation(op: &Operation, identity: &ResourceIdentity) -> bool {
    if op.spec().is_some() {
        match identity {
            ResourceIdentity::KubernetesResource { .. }
                if !op.as_str().starts_with("container.resource.") =>
            {
                return false;
            }
            ResourceIdentity::Container { .. }
                if op.as_str().starts_with("container.resource.") =>
            {
                return false;
            }
            _ => {}
        }
    }
    op.spec().is_none_or(|spec| {
        spec.families
            .iter()
            .any(|family| family.0 == crate::identity_family(identity))
    })
}

fn git_filesystem_expr_is_compatible(expr: &ResourceExpr) -> bool {
    match expr {
        ResourceExpr::Concrete { identity } => matches!(identity, ResourceIdentity::FsPath { .. }),
        ResourceExpr::Pattern { pattern } => pattern.domain() == "filesystem",
        ResourceExpr::Unresolved { family } => family.domain() == Some("filesystem"),
        ResourceExpr::Literal { .. }
        | ResourceExpr::Parameter { .. }
        | ResourceExpr::Environment { .. } => true,
        ResourceExpr::Property { base, .. } => git_filesystem_expr_is_compatible(base),
        ResourceExpr::Join { parts }
        | ResourceExpr::Union {
            alternatives: parts,
        } => !parts.is_empty() && parts.iter().all(git_filesystem_expr_is_compatible),
    }
}

fn symbolic_child_is_compatible(op: &Operation, expr: &ResourceExpr) -> bool {
    match expr {
        ResourceExpr::Concrete { identity } => identity_matches_operation(op, identity),
        ResourceExpr::Pattern { pattern } => op
            .spec()
            .is_none_or(|spec| spec.accepts_family(&pattern.family())),
        ResourceExpr::Unresolved { family } => match resource_domain(expr) {
            Some(_) => op.spec().is_none_or(|spec| spec.accepts_family(family)),
            None => matches!(
                family.0.as_ref(),
                "other" | "value" | "unknown" | "object" | "callable" | "collection"
            ),
        },
        ResourceExpr::Literal { .. }
        | ResourceExpr::Parameter { .. }
        | ResourceExpr::Environment { .. } => true,
        ResourceExpr::Property { base, .. } => symbolic_child_is_compatible(op, base),
        ResourceExpr::Join { parts }
        | ResourceExpr::Union {
            alternatives: parts,
        } => {
            !parts.is_empty()
                && parts
                    .iter()
                    .all(|part| symbolic_child_is_compatible(op, part))
        }
    }
}

fn root_resource_is_compatible(op: &Operation, expr: &ResourceExpr) -> bool {
    let domain = op.domain();
    match expr {
        ResourceExpr::Concrete { identity } => {
            identity_matches_operation(op, identity)
                && match identity {
                    ResourceIdentity::GitRepository {
                        worktree,
                        git_dir,
                        pathspec,
                    } => worktree
                        .iter()
                        .chain(git_dir)
                        .chain(pathspec)
                        .all(|expr| git_filesystem_expr_is_compatible(expr)),
                    _ => true,
                }
        }
        ResourceExpr::Pattern { pattern } => op
            .spec()
            .is_none_or(|spec| spec.accepts_family(&pattern.family())),
        ResourceExpr::Unresolved { family } => {
            op.spec().is_none_or(|spec| spec.accepts_family(family))
        }
        ResourceExpr::Union { alternatives } => {
            !alternatives.is_empty()
                && alternatives
                    .iter()
                    .all(|alternative| root_resource_is_compatible(op, alternative))
        }
        ResourceExpr::Literal { .. }
        | ResourceExpr::Parameter { .. }
        | ResourceExpr::Environment { .. }
            if !matches!(domain, "environment" | "git") =>
        {
            true
        }
        ResourceExpr::Property { base, .. } if !matches!(domain, "environment" | "git") => {
            symbolic_child_is_compatible(op, base)
        }
        ResourceExpr::Join { parts } if !matches!(domain, "environment" | "git") => {
            !parts.is_empty()
                && parts
                    .iter()
                    .all(|part| symbolic_child_is_compatible(op, part))
        }
        _ => false,
    }
}

/// Returns the incompatible root or typed child family for an effect target.
fn incompatible_resource(op: &Operation, expr: &ResourceExpr) -> Option<&'static str> {
    if op.spec().is_none() || root_resource_is_compatible(op, expr) {
        return None;
    }
    match expr {
        ResourceExpr::Concrete { identity } => Some(identity_name(identity)),
        ResourceExpr::Pattern { .. } => Some("pattern"),
        ResourceExpr::Unresolved { .. } => Some("unresolved"),
        ResourceExpr::Union { .. } => Some("union"),
        ResourceExpr::Literal { .. } => Some("literal"),
        ResourceExpr::Parameter { .. } => Some("parameter"),
        ResourceExpr::Environment { .. } => Some("environment-value"),
        ResourceExpr::Property { .. } => Some("property"),
        ResourceExpr::Join { .. } => Some("join"),
    }
}

fn identity_name(identity: &ResourceIdentity) -> &'static str {
    match identity {
        ResourceIdentity::KubernetesResource { .. } => "kubernetes-resource",
        ResourceIdentity::ManagedInfrastructure { .. } => "managed-infrastructure",
        ResourceIdentity::FsPath { .. } => "filesystem-path",
        ResourceIdentity::UserHome { .. } => "user-home",
        ResourceIdentity::EnvironmentVariable { .. } => "environment-variable",
        ResourceIdentity::Artifact { .. } => "artifact",
        ResourceIdentity::GitRepository { .. } => "git-repository",
        ResourceIdentity::Process { .. } => "process",
        ResourceIdentity::NetworkEndpoint { .. } => "network-endpoint",
        ResourceIdentity::Container { .. } => "container",
        ResourceIdentity::DatabaseTable { .. } => "database-table",
        ResourceIdentity::DatabaseSchema { .. } => "database-schema",
        ResourceIdentity::ObjectStore { .. } => "object-store",
        ResourceIdentity::CloudResource { .. } => "cloud-resource",
        ResourceIdentity::MessageTopic { .. } => "message-topic",
        ResourceIdentity::ServiceUnit { .. } => "service-unit",
        ResourceIdentity::ScheduledJob { .. } => "scheduled-job",
        ResourceIdentity::StorageVolume { .. } => "storage-volume",
        ResourceIdentity::BlockDevice { .. } => "block-device",
        ResourceIdentity::CredentialStore { .. } => "credential-store",
        ResourceIdentity::HostSystem { .. } => "host-system",
    }
}

fn validate_resource(effect: usize, expr: &ResourceExpr, errors: &mut Vec<ValidationError>) {
    if let ResourceExpr::Concrete { identity } = expr {
        for value in identity.infrastructure_values() {
            validate_resource(effect, value, errors);
        }
        if let Some(scope) = identity.scope() {
            for value in scope.values() {
                validate_resource(effect, value, errors);
            }
        }
    }
    match expr {
        ResourceExpr::Concrete { identity } => match identity {
            ResourceIdentity::Artifact {
                endpoint,
                name,
                reference,
                ..
            } => {
                for resource in [endpoint.as_ref(), name.as_ref()]
                    .into_iter()
                    .chain(reference.value())
                {
                    validate_resource(effect, resource, errors);
                }
            }
            ResourceIdentity::Process { argv, cwd, .. } => {
                for arg in argv {
                    validate_resource(effect, arg, errors);
                }
                if let Some(cwd) = cwd {
                    validate_resource(effect, cwd, errors);
                }
            }
            ResourceIdentity::Container { storage, .. } => {
                for storage in storage {
                    match storage {
                        ContainerStorage::BindMount {
                            host_path,
                            container_path,
                            ..
                        } => {
                            validate_resource(effect, host_path, errors);
                            validate_resource(effect, container_path, errors);
                        }
                        ContainerStorage::Volume { container_path, .. } => {
                            validate_resource(effect, container_path, errors)
                        }
                    }
                }
            }
            ResourceIdentity::GitRepository {
                worktree,
                git_dir,
                pathspec,
            } => {
                for resource in worktree.iter().chain(git_dir).chain(pathspec) {
                    validate_resource(effect, resource, errors);
                }
            }
            _ => {}
        },
        ResourceExpr::Literal { .. }
        | ResourceExpr::Parameter { .. }
        | ResourceExpr::Environment { .. }
        | ResourceExpr::Unresolved { .. } => {}
        ResourceExpr::Property { base, .. } => validate_resource(effect, base, errors),
        ResourceExpr::Join { parts }
        | ResourceExpr::Union {
            alternatives: parts,
        } => {
            if parts.is_empty() {
                errors.push(ValidationError::EmptyResourceParts { effect });
            }
            for part in parts {
                validate_resource(effect, part, errors);
            }
        }
        ResourceExpr::Pattern { pattern } => {
            if pattern.is_empty() {
                errors.push(ValidationError::EmptyPattern { effect });
            } else if pattern.validate().is_err() {
                errors.push(ValidationError::InvalidPattern { effect });
            }
            if let crate::ResourcePattern::Process { argv_prefix, .. } = pattern {
                for arg in argv_prefix {
                    validate_resource(effect, arg, errors);
                }
            }
        }
    }
}

fn valid_digest(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("blake3:") else {
        return false;
    };
    hex.len() == 64
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_occurrence_id(id: &OccurrenceId) -> bool {
    id.0.strip_prefix("occurrence:").is_some_and(valid_digest)
}

fn valid_fact_id(id: &FactId) -> bool {
    id.0.strip_prefix("fact:").is_some_and(valid_digest)
}

fn valid_boundary_id(id: &str) -> bool {
    id.strip_prefix("boundary:").is_some_and(valid_digest)
}

fn canonical_path(path: &str) -> bool {
    !path.is_empty()
        && !path.contains('\\')
        && !crate::is_absolute_path(path, crate::PathPlatform::Posix)
        && !crate::is_absolute_path(path, crate::PathPlatform::Windows)
        && !path.split('/').any(|part| matches!(part, "" | "." | ".."))
}

fn valid_scope(scope: &AffectedScope, subjects: &BTreeSet<&str>) -> bool {
    if scope.graphs.is_empty()
        || scope.graphs.windows(2).any(|pair| pair[0] >= pair[1])
        || scope.entrypoints.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return false;
    }
    if scope.all_entrypoints {
        scope.entrypoints.is_empty()
    } else {
        !scope.entrypoints.is_empty()
            && scope
                .entrypoints
                .iter()
                .all(|entrypoint| subjects.contains(entrypoint.as_str()))
    }
}

/// Validate the complete v1 envelope, including identity, ids, DAG references,
/// status evidence, resource/operation invariants, limits, and content hash.
pub fn validate_repo_query(
    envelope: &RepoQueryEnvelope,
) -> Result<(), Vec<RepoQueryValidationError>> {
    let mut errors = Vec::new();
    if envelope.schema != REPO_QUERY_SCHEMA_V1 {
        errors.push(RepoQueryValidationError::WrongSchema {
            found: envelope.schema.clone(),
        });
    }
    for (field, value) in [
        ("snapshot_id", envelope.snapshot_id.as_str()),
        ("analyzer.name", envelope.identity.analyzer.name.as_str()),
        (
            "analyzer.version",
            envelope.identity.analyzer.version.as_str(),
        ),
    ] {
        if value.is_empty() {
            errors.push(RepoQueryValidationError::EmptyField { field });
        }
    }
    for (field, value) in [
        ("snapshot_id", envelope.snapshot_id.as_str()),
        (
            "identity.analyzer.build_digest",
            envelope.identity.analyzer.build_digest.as_str(),
        ),
        (
            "identity.configuration_digest",
            envelope.identity.configuration_digest.as_str(),
        ),
        (
            "identity.model_set_digest",
            envelope.identity.model_set_digest.as_str(),
        ),
    ] {
        if !valid_digest(value) {
            errors.push(RepoQueryValidationError::InvalidDigest {
                field,
                value: value.to_string(),
            });
        }
    }
    let dependencies = &envelope.identity.dependencies;
    let subjects = &envelope.subjects;
    if dependencies.is_empty()
        || dependencies
            .windows(2)
            .any(|pair| pair[0].key >= pair[1].key)
    {
        errors.push(RepoQueryValidationError::InvalidPayload {
            path: "identity.dependencies".to_string(),
        });
    }
    for dependency in dependencies {
        let key_valid = match dependency.kind {
            AnalysisDependencyKind::SourceModule => dependency
                .key
                .strip_prefix("source:")
                .is_some_and(canonical_path),
            AnalysisDependencyKind::SkippedSource => dependency
                .key
                .strip_prefix("skipped-source:")
                .is_some_and(canonical_path),
            AnalysisDependencyKind::EntrypointDiscovery => dependency
                .key
                .strip_prefix("discovery:")
                .is_some_and(canonical_path),
            AnalysisDependencyKind::ResolverConfig => dependency
                .key
                .strip_prefix("resolver:")
                .is_some_and(canonical_path),
            AnalysisDependencyKind::ParserFrontend => dependency
                .key
                .strip_prefix("frontend:")
                .is_some_and(|frontend| !frontend.is_empty()),
            AnalysisDependencyKind::Analyzer => dependency.key == "analyzer",
            AnalysisDependencyKind::ModelSet => dependency.key == "model-set",
            AnalysisDependencyKind::Limit => dependency
                .key
                .strip_prefix("limit:")
                .is_some_and(|limit| !limit.is_empty()),
        };
        if !key_valid || !valid_digest(&dependency.digest) {
            errors.push(RepoQueryValidationError::InvalidPayload {
                path: format!("identity.dependencies.{}", dependency.key),
            });
        }
    }
    let analyzer_dependencies: Vec<_> = dependencies
        .iter()
        .filter(|dependency| dependency.kind == AnalysisDependencyKind::Analyzer)
        .collect();
    if analyzer_dependencies.len() != 1
        || analyzer_dependencies[0].digest != envelope.identity.analyzer.build_digest
    {
        errors.push(RepoQueryValidationError::InvalidPayload {
            path: "identity.analyzer".to_string(),
        });
    }
    let model_dependencies: Vec<_> = dependencies
        .iter()
        .filter(|dependency| dependency.kind == AnalysisDependencyKind::ModelSet)
        .collect();
    if model_dependencies.len() != 1
        || model_dependencies[0].digest != envelope.identity.model_set_digest
    {
        errors.push(RepoQueryValidationError::InvalidPayload {
            path: "identity.model_set_digest".to_string(),
        });
    }
    if subjects
        .windows(2)
        .any(|pair| pair[0].entrypoint >= pair[1].entrypoint)
    {
        errors.push(RepoQueryValidationError::InvalidPayload {
            path: "subjects".to_string(),
        });
    }
    let subject_ids: BTreeSet<&str> = subjects
        .iter()
        .map(|subject| subject.entrypoint.as_str())
        .collect();
    for subject in subjects {
        let source_key = format!("source:{}", subject.source_path);
        if subject.entrypoint.is_empty()
            || !canonical_path(&subject.source_path)
            || !valid_digest(&subject.subject_digest)
            || subject.subject_digest
                != crate::stable_hash("effinterp/analysis-subject/v1", &subject.subject)
            || !dependencies
                .iter()
                .any(|dependency| dependency.key == source_key)
        {
            errors.push(RepoQueryValidationError::InvalidPayload {
                path: format!("subjects.{}", subject.entrypoint),
            });
        }
    }
    match &envelope.status {
        AnalysisStatus::Complete if !envelope.boundaries.is_empty() => {
            errors.push(RepoQueryValidationError::CompleteWithBoundaries)
        }
        AnalysisStatus::Partial { reasons } if reasons.is_empty() => {
            errors.push(RepoQueryValidationError::MissingStatusReasons { status: "partial" })
        }
        AnalysisStatus::Stale { reasons } if reasons.is_empty() => {
            errors.push(RepoQueryValidationError::MissingStatusReasons { status: "stale" })
        }
        _ => {}
    }
    match &envelope.status {
        AnalysisStatus::Partial { reasons } => {
            if reasons.windows(2).any(|pair| {
                serde_json::to_string(&pair[0]).expect("partial reason serializes")
                    >= serde_json::to_string(&pair[1]).expect("partial reason serializes")
            }) {
                errors.push(RepoQueryValidationError::InvalidPayload {
                    path: "status.reasons".to_string(),
                });
            }
            for reason in reasons {
                let (scope, reason_valid) = match reason {
                    PartialReason::UnsupportedEvidence { boundary_id, scope } => {
                        (scope, valid_boundary_id(boundary_id))
                    }
                    PartialReason::UnanalyzedInput { path, scope } => (scope, canonical_path(path)),
                    PartialReason::AnalysisFailure { entrypoint, scope } => {
                        (scope, !entrypoint.is_empty())
                    }
                    PartialReason::LimitReached { limit, scope } => (scope, !limit.is_empty()),
                    PartialReason::Truncated {
                        collection, scope, ..
                    } => (scope, !collection.is_empty()),
                };
                if !reason_valid || !valid_scope(scope, &subject_ids) {
                    errors.push(RepoQueryValidationError::InvalidPayload {
                        path: "status.reasons".to_string(),
                    });
                }
            }
        }
        AnalysisStatus::Stale { reasons } => {
            if reasons.windows(2).any(|pair| {
                serde_json::to_string(&pair[0]).expect("stale reason serializes")
                    >= serde_json::to_string(&pair[1]).expect("stale reason serializes")
            }) {
                errors.push(RepoQueryValidationError::InvalidPayload {
                    path: "status.reasons".to_string(),
                });
            }
            for reason in reasons {
                let (dependency, scope, reason_valid) = match reason {
                    StaleReason::SnapshotSuperseded {
                        current_snapshot_id,
                        scope,
                    } => (None, scope, valid_digest(current_snapshot_id)),
                    StaleReason::InputChanged {
                        dependency,
                        path,
                        scope,
                    }
                    | StaleReason::InputMissing {
                        dependency,
                        path,
                        scope,
                    } => (
                        Some(dependency.as_str()),
                        scope,
                        canonical_path(path) && dependency == &format!("source:{path}"),
                    ),
                    StaleReason::AnalyzerChanged {
                        dependency,
                        current_analyzer_version,
                        scope,
                    } => (
                        Some(dependency.as_str()),
                        scope,
                        !current_analyzer_version.is_empty(),
                    ),
                    StaleReason::ModelSetChanged {
                        dependency,
                        current_model_set_digest,
                        scope,
                    } => (
                        Some(dependency.as_str()),
                        scope,
                        valid_digest(current_model_set_digest),
                    ),
                    StaleReason::ParserChanged {
                        dependency,
                        parser,
                        scope,
                    } => (Some(dependency.as_str()), scope, !parser.is_empty()),
                    StaleReason::ConfigChanged {
                        dependency,
                        path,
                        scope,
                    } => (Some(dependency.as_str()), scope, canonical_path(path)),
                    StaleReason::LimitsChanged {
                        dependency,
                        limit,
                        scope,
                    } => (Some(dependency.as_str()), scope, !limit.is_empty()),
                    StaleReason::UnknownDependency { key, scope } => (
                        None,
                        scope,
                        !key.is_empty()
                            && !dependencies.iter().any(|dependency| dependency.key == *key),
                    ),
                };
                if !reason_valid
                    || !valid_scope(scope, &subject_ids)
                    || dependency.is_some_and(|key| {
                        !dependencies.iter().any(|candidate| candidate.key == key)
                    })
                {
                    errors.push(RepoQueryValidationError::InvalidPayload {
                        path: "status.reasons".to_string(),
                    });
                }
            }
        }
        AnalysisStatus::Complete => {}
    }
    if envelope.coverage.domains.keys().any(String::is_empty)
        || envelope.coverage.domains.contains_key("dataflow")
    {
        errors.push(RepoQueryValidationError::InvalidPayload {
            path: "coverage.domains".to_string(),
        });
    }

    let mut nodes = BTreeSet::new();
    if envelope
        .provenance
        .nodes
        .windows(2)
        .any(|pair| pair[0].id >= pair[1].id)
    {
        errors.push(RepoQueryValidationError::InvalidPayload {
            path: "provenance.nodes".to_string(),
        });
    }
    let reachable = envelope
        .provenance
        .reachable_nodes(&envelope.payload, &envelope.boundaries);
    for node in &envelope.provenance.nodes {
        if !reachable.contains(&node.id) {
            errors.push(RepoQueryValidationError::InvalidPayload {
                path: format!("provenance.nodes.{}", node.id.0),
            });
        }
        if !dependencies
            .iter()
            .any(|d| d.key == format!("source:{}", node.occurrence.origin))
        {
            errors.push(RepoQueryValidationError::InvalidPayload {
                path: format!("provenance.nodes.{}.occurrence.input_digest", node.id.0),
            });
        }
        if !valid_occurrence_id(&node.id)
            || !valid_digest(&node.occurrence.input_digest)
            || node.occurrence.origin.is_empty()
            || node.occurrence.semantic_kind.is_empty()
            || node.id != OccurrenceId::derive(&node.occurrence)
        {
            errors.push(RepoQueryValidationError::InvalidOccurrence {
                id: node.id.0.clone(),
            });
        }
        if !canonical_path(&node.occurrence.origin) {
            errors.push(RepoQueryValidationError::AbsoluteOrigin {
                origin: node.occurrence.origin.clone(),
            });
        }
        if node.occurrence.span.start > node.occurrence.span.end {
            errors.push(RepoQueryValidationError::InvalidOccurrence {
                id: node.id.0.clone(),
            });
        }
        if !nodes.insert(node.id.0.clone()) {
            errors.push(RepoQueryValidationError::DuplicateProvenanceNode {
                id: node.id.0.clone(),
            });
        }
        if let ProtocolProvenanceKind::Dispatch {
            registration_roots,
            dispatch_roots,
            ..
        } = &node.evidence
        {
            if registration_roots.iter().collect::<BTreeSet<_>>().len() != registration_roots.len()
                || dispatch_roots.iter().collect::<BTreeSet<_>>().len() != dispatch_roots.len()
            {
                errors.push(RepoQueryValidationError::InvalidPayload {
                    path: format!("provenance.nodes.{}.evidence", node.id.0),
                });
            }
            for root in registration_roots.iter().chain(dispatch_roots) {
                if !valid_occurrence_id(root) || root == &node.id {
                    errors.push(RepoQueryValidationError::InvalidOccurrence { id: root.0.clone() });
                }
            }
        }
        let evidence_valid = match &node.evidence {
            ProtocolProvenanceKind::Entrypoint { entrypoint } => !entrypoint.is_empty(),
            ProtocolProvenanceKind::Source { evidence } => match evidence {
                crate::SourceEvidence::Span { start, end } => start <= end,
                crate::SourceEvidence::Argument { .. } => true,
                crate::SourceEvidence::Function { name } => !name.is_empty(),
                crate::SourceEvidence::Execution { origin, .. } => {
                    origin.as_deref().is_none_or(canonical_path)
                }
            },
            ProtocolProvenanceKind::ModelApplication {
                declaration_id,
                declaration_digest,
            } => {
                !declaration_id.is_empty()
                    && declaration_digest.as_deref().is_none_or(|digest| {
                        digest.len() == 64
                            && digest
                                .bytes()
                                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                    })
            }
            ProtocolProvenanceKind::CrossFileCall { from, into } => {
                !from.is_empty() && !into.is_empty()
            }
            ProtocolProvenanceKind::Dispatch { model, .. } => !model.is_empty(),
            ProtocolProvenanceKind::Boundary { reason } => reason.is_valid(),
            ProtocolProvenanceKind::CausalOccurrence {
                entrypoint,
                semantic_kind,
            } => !entrypoint.is_empty() && !semantic_kind.is_empty(),
        };
        if !evidence_valid {
            errors.push(RepoQueryValidationError::InvalidPayload {
                path: format!("provenance.nodes.{}.evidence", node.id.0),
            });
        }
    }
    for node in &envelope.provenance.nodes {
        if let ProtocolProvenanceKind::Dispatch {
            registration_roots,
            dispatch_roots,
            ..
        } = &node.evidence
        {
            for root in registration_roots.iter().chain(dispatch_roots) {
                if !nodes.contains(&root.0) {
                    errors.push(RepoQueryValidationError::DanglingProvenanceRef {
                        id: root.0.clone(),
                    });
                }
            }
        }
    }

    let mut graph: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    if envelope.provenance.edges.windows(2).any(|pair| {
        (&pair[0].from, pair[0].kind, &pair[0].to) >= (&pair[1].from, pair[1].kind, &pair[1].to)
    }) {
        errors.push(RepoQueryValidationError::InvalidPayload {
            path: "provenance.edges".to_string(),
        });
    }
    for edge in &envelope.provenance.edges {
        if !nodes.contains(&edge.from.0) {
            errors.push(RepoQueryValidationError::DanglingProvenanceRef {
                id: edge.from.0.clone(),
            });
        }
        if !nodes.contains(&edge.to.0) {
            errors.push(RepoQueryValidationError::DanglingProvenanceRef {
                id: edge.to.0.clone(),
            });
        }
        graph.entry(&edge.from.0).or_default().push(&edge.to.0);
    }
    fn visit<'a>(
        node: &'a str,
        graph: &BTreeMap<&'a str, Vec<&'a str>>,
        visiting: &mut BTreeSet<&'a str>,
        visited: &mut BTreeSet<&'a str>,
    ) -> bool {
        if visited.contains(node) {
            return false;
        }
        if !visiting.insert(node) {
            return true;
        }
        if graph.get(node).is_some_and(|next| {
            next.iter()
                .any(|next| visit(next, graph, visiting, visited))
        }) {
            return true;
        }
        visiting.remove(node);
        visited.insert(node);
        false
    }
    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    if nodes
        .iter()
        .any(|node| visit(node, &graph, &mut visiting, &mut visited))
    {
        errors.push(RepoQueryValidationError::CyclicProvenance);
    }

    let mut boundary_ids = BTreeSet::new();
    if envelope
        .boundaries
        .windows(2)
        .any(|pair| pair[0].id >= pair[1].id)
    {
        errors.push(RepoQueryValidationError::InvalidPayload {
            path: "boundaries".to_string(),
        });
    }
    for boundary in &envelope.boundaries {
        if boundary.id.is_empty()
            || !valid_boundary_id(&boundary.id)
            || boundary.id != boundary.expected_id()
            || !boundary.reason.is_valid()
            || boundary.domains.is_empty()
            || boundary.domains.windows(2).any(|pair| pair[0] >= pair[1])
            || !boundary_ids.insert(boundary.id.clone())
        {
            errors.push(RepoQueryValidationError::InvalidBoundary {
                id: boundary.id.clone(),
            });
        }
        if boundary
            .domains
            .iter()
            .any(|domain| domain != "dataflow" && !DOMAINS.contains(&domain.as_str()))
            || boundary.limit.as_ref().is_some_and(String::is_empty)
            || boundary.reason == BoundaryReason::LIMIT_SATURATED && boundary.limit.is_none()
        {
            errors.push(RepoQueryValidationError::InvalidBoundary {
                id: boundary.id.clone(),
            });
        }
        if let Some(resource) = &boundary.affected_resource {
            let domain = resource_domain(resource);
            let mut resource_errors = Vec::new();
            validate_resource(0, resource, &mut resource_errors);
            if domain.is_none()
                || !boundary
                    .domains
                    .iter()
                    .any(|declared| Some(declared.as_str()) == domain)
                || !resource_errors.is_empty()
                || resource_has_invalid_identity_fields(resource)
                || (crate::normalize_resource(resource.clone(), crate::PathPlatform::Posix)
                    != *resource
                    && crate::normalize_resource(resource.clone(), crate::PathPlatform::Windows)
                        != *resource)
            {
                errors.push(RepoQueryValidationError::InvalidBoundary {
                    id: boundary.id.clone(),
                });
            }
        }
        for root in &boundary.provenance_roots {
            if !nodes.contains(&root.0) {
                errors.push(RepoQueryValidationError::DanglingProvenanceRef { id: root.0.clone() });
            }
        }
        if let Some(dispatch) = &boundary.dispatch {
            if dispatch.model.is_empty()
                || dispatch
                    .registration_roots
                    .iter()
                    .collect::<BTreeSet<_>>()
                    .len()
                    != dispatch.registration_roots.len()
                || dispatch
                    .dispatch_roots
                    .iter()
                    .collect::<BTreeSet<_>>()
                    .len()
                    != dispatch.dispatch_roots.len()
            {
                errors.push(RepoQueryValidationError::InvalidBoundary {
                    id: boundary.id.clone(),
                });
            }
            for root in dispatch
                .registration_roots
                .iter()
                .chain(&dispatch.dispatch_roots)
            {
                if !nodes.contains(&root.0) {
                    errors.push(RepoQueryValidationError::DanglingProvenanceRef {
                        id: root.0.clone(),
                    });
                }
            }
        }
    }
    if let AnalysisStatus::Partial { reasons } = &envelope.status {
        for boundary in &envelope.boundaries {
            let reported = match &boundary.limit {
                Some(limit) => reasons.iter().any(
                    |reason| matches!(reason, PartialReason::LimitReached { limit: have, .. } if have == limit),
                ),
                None => reasons.iter().any(
                    |reason| matches!(reason, PartialReason::UnsupportedEvidence { boundary_id, .. } if boundary_id == &boundary.id),
                ),
            };
            if !reported {
                errors.push(RepoQueryValidationError::InvalidBoundary {
                    id: boundary.id.clone(),
                });
            }
        }
        for reason in reasons {
            if let PartialReason::UnsupportedEvidence { boundary_id, .. } = reason
                && !boundary_ids.contains(boundary_id)
            {
                errors.push(RepoQueryValidationError::InvalidBoundary {
                    id: boundary_id.clone(),
                });
            }
        }
    }

    for (domain, claim) in envelope
        .coverage
        .domains
        .iter()
        .map(|(domain, claim)| (domain.as_str(), claim))
        .chain(
            envelope
                .coverage
                .causality
                .as_ref()
                .map(|claim| ("dataflow", claim)),
        )
    {
        let expected: Vec<String> = envelope
            .boundaries
            .iter()
            .filter(|boundary| boundary.domains.iter().any(|value| value == domain))
            .map(|boundary| boundary.id.clone())
            .collect();
        if claim.gaps != expected || (claim.level == CoverageLevel::Full) != expected.is_empty() {
            errors.push(RepoQueryValidationError::InvalidPayload {
                path: format!("coverage.{domain}"),
            });
        }
    }
    for boundary in &envelope.boundaries {
        for domain in &boundary.domains {
            if !(envelope.coverage.domains.contains_key(domain)
                || (domain == "dataflow" && envelope.coverage.causality.is_some()))
            {
                errors.push(RepoQueryValidationError::InvalidPayload {
                    path: format!("coverage.{domain}"),
                });
            }
        }
    }

    if envelope.payload_kind != envelope.payload.kind() {
        errors.push(RepoQueryValidationError::InvalidPayload {
            path: "payload_kind".into(),
        });
    }
    envelope.payload.validate(
        &payload::EnvelopeRefs {
            nodes: &nodes,
            boundaries: envelope
                .boundaries
                .iter()
                .map(|b| (b.id.clone(), b))
                .collect(),
            subjects: &subject_ids,
            source_paths: dependencies
                .iter()
                .filter(|d| d.kind == AnalysisDependencyKind::SourceModule)
                .filter_map(|d| d.key.strip_prefix("source:"))
                .collect(),
            require_subjects: !matches!(envelope.status, AnalysisStatus::Stale { .. }),
            coverage: &envelope.coverage,
        },
        &mut errors,
    );
    let expected = envelope.expected_content_hash();
    if envelope.content_hash != expected {
        errors.push(RepoQueryValidationError::ContentHashMismatch {
            expected,
            found: envelope.content_hash.clone(),
        });
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// Parse and fully validate an analysis envelope before returning it.
///
/// Admits only duplicate-free canonical repository-query JSON: `input` must
/// equal the bytes [`RepoQueryEnvelope::to_canonical_json`] produces for the
/// parsed envelope, so otherwise valid JSON with different whitespace, field
/// order, or trailing newline fails with [`RepoQueryParseError::NonCanonical`].
/// Parsing does not normalize.
pub fn from_repo_query_json(input: &str) -> Result<RepoQueryEnvelope, RepoQueryParseError> {
    crate::canonical::reject_duplicate_keys(input).map_err(RepoQueryParseError::Json)?;
    let envelope = serde_json::from_str(input).map_err(|error: serde_json::Error| {
        let message = error.to_string();
        if let Some(path) = message
            .strip_prefix("payload")
            .and_then(|message| message.split_once(": ").map(|(path, _)| path))
        {
            RepoQueryParseError::Validation(vec![RepoQueryValidationError::InvalidPayload {
                path: format!("payload{path}"),
            }])
        } else {
            RepoQueryParseError::Json(error)
        }
    })?;
    validate_repo_query(&envelope).map_err(RepoQueryParseError::Validation)?;
    if envelope.to_canonical_json() != input {
        return Err(RepoQueryParseError::NonCanonical);
    }
    Ok(envelope)
}

fn valid_execution_input(node: &crate::ExecutionNode, index: usize) -> bool {
    use crate::{
        ExecutionAssurance, ExecutionContent, ExecutionInputRole, ExecutionPhase,
        ExecutionSelection, ExecutionSelector,
    };
    let Some(input) = &node.input else {
        return true;
    };
    if input.requester.0 as usize >= index || input.requester_component.trim().is_empty() {
        return false;
    }
    if let Some(selected) = &input.selected {
        let mut errors = Vec::new();
        validate_resource(0, selected, &mut errors);
        if !errors.is_empty() || resource_has_invalid_identity_fields(selected) {
            return false;
        }
    }
    match &input.content {
        ExecutionContent::Observed { digest } | ExecutionContent::Predicted { digest } => {
            if !valid_digest(digest) || input.selected.is_none() {
                return false;
            }
        }
        ExecutionContent::Unobserved { reason } => {
            if node.boundary.is_none() {
                return false;
            }
            if matches!(reason, crate::ExecutionInputReason::BudgetRefused { limit } if limit.is_empty())
            {
                return false;
            }
        }
    }
    match &input.selector {
        ExecutionSelector::Environment { variable } if variable.is_empty() => return false,
        ExecutionSelector::RuntimeOption { option } if option.is_empty() => return false,
        ExecutionSelector::Dependency { specifier } if specifier.is_empty() => return false,
        ExecutionSelector::Convention { name } if name.is_empty() => return false,
        _ => {}
    }
    match &input.selection {
        ExecutionSelection::Direct { request } if request.is_empty() => return false,
        ExecutionSelection::Search {
            candidates,
            selected,
        } => {
            if candidates.is_empty() {
                return false;
            }
            let mut unique = std::collections::BTreeSet::new();
            for candidate in candidates {
                let mut errors = Vec::new();
                validate_resource(0, candidate, &mut errors);
                if !errors.is_empty()
                    || resource_has_invalid_identity_fields(candidate)
                    || !unique.insert(crate::canonical_json(candidate))
                {
                    return false;
                }
            }
            if let Some(selected) = selected {
                if candidates.get(*selected as usize) != input.selected.as_ref() {
                    return false;
                }
            } else if let Some(selected) = &input.selected
                && (input.assurance != ExecutionAssurance::Alternatives
                    || !candidates.contains(selected))
            {
                return false;
            }
        }
        _ => {}
    }
    match input.role {
        ExecutionInputRole::ExplicitInvocation => !matches!(
            input.selector,
            ExecutionSelector::Environment { .. } | ExecutionSelector::Dependency { .. }
        ),
        ExecutionInputRole::UnexpectedSelected => {
            input.phase != ExecutionPhase::Main
                && (input.assurance != ExecutionAssurance::Exact || input.selected.is_some())
                && !matches!(
                    input.selector,
                    ExecutionSelector::InvocationPath | ExecutionSelector::Dependency { .. }
                )
        }
        ExecutionInputRole::DependencyRequest => {
            input.phase == ExecutionPhase::Import
                && matches!(input.selector, ExecutionSelector::Dependency { .. })
                && (matches!(
                    input.content,
                    ExecutionContent::Observed { .. } | ExecutionContent::Predicted { .. }
                ) || node.boundary.is_some())
        }
    }
}

/// Validate a query identity, including explicit scope wildcards.
pub fn selector_identity_is_valid(identity: &ResourceIdentity) -> bool {
    if !crate::resource_scope::valid_resource_scope(identity, true) {
        return false;
    }
    let mut identity = identity.clone();
    if let Some(scope) = identity.scope_mut() {
        let unknowns = crate::ResourceScope::<ResourceExpr>::new(scope.kind);
        for (dimension, value) in &mut scope.identity {
            if matches!(value, crate::ScopeValue::Any) {
                *value = unknowns.identity[dimension].clone();
            }
        }
        for value in scope.values() {
            let mut errors = Vec::new();
            validate_resource(0, value, &mut errors);
            if !errors.is_empty() || resource_has_invalid_identity_fields(value) {
                return false;
            }
        }
    }
    for value in identity.infrastructure_values() {
        let mut errors = Vec::new();
        validate_resource(0, value, &mut errors);
        if !errors.is_empty() || resource_has_invalid_identity_fields(value) {
            return false;
        }
    }
    !identity_fields_are_invalid(&identity)
}
