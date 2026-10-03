//! Repository-query envelope validation: the semantic and integrity checks a
//! `RepoQueryEnvelope` must pass, and the canonical-JSON parse that admits
//! one. `payload.rs` validates the envelope's payload.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use super::{
    canonical_path, payload, resource_has_invalid_identity_fields, valid_boundary_id, valid_digest,
    valid_occurrence_id, validate_resource,
};
use crate::analysis::{
    AffectedScope, AnalysisDependencyKind, AnalysisStatus, PartialReason, ProtocolProvenanceKind,
    REPO_QUERY_SCHEMA_V1, RepoQueryEnvelope, StaleReason,
};
use crate::occurrence::OccurrenceId;
use crate::plan::{BoundaryReason, CoverageLevel, DOMAINS};
use crate::resource::resource_domain;

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
