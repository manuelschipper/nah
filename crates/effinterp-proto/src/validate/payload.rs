use super::*;
use crate::payload::*;
use crate::{AnalysisBoundary, AnalysisCoverage, DispatchIdentity, EffectFact, ExecutionRealm};

pub(super) struct EnvelopeRefs<'a> {
    pub nodes: &'a BTreeSet<String>,
    pub boundaries: BTreeMap<String, &'a AnalysisBoundary>,
    pub subjects: &'a BTreeSet<&'a str>,
    pub source_paths: BTreeSet<&'a str>,
    pub require_subjects: bool,
    pub coverage: &'a AnalysisCoverage,
}

fn invalid(errors: &mut Vec<RepoQueryValidationError>, path: impl Into<String>) {
    errors.push(RepoQueryValidationError::InvalidPayload { path: path.into() });
}
fn key(value: impl Serialize) -> String {
    serde_json::to_string(&serde_json::to_value(value).expect("payload key serializes"))
        .expect("payload key serializes")
}
fn ordered<T>(
    rows: &[T],
    path: &str,
    key: impl Fn(&T) -> String,
    errors: &mut Vec<RepoQueryValidationError>,
) {
    if rows.windows(2).any(|pair| key(&pair[0]) >= key(&pair[1])) {
        invalid(errors, path);
    }
}
fn unique<T: Ord>(values: &[T], path: &str, errors: &mut Vec<RepoQueryValidationError>) {
    if values.iter().collect::<BTreeSet<_>>().len() != values.len() {
        invalid(errors, path);
    }
}
fn sorted<T: Ord>(values: &[T], path: &str, errors: &mut Vec<RepoQueryValidationError>) {
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        invalid(errors, path);
    }
}
fn occurrence_evidence(
    count: u32,
    exemplars: &[Vec<String>],
    path: &str,
    errors: &mut Vec<RepoQueryValidationError>,
) {
    if count == 0 {
        invalid(errors, format!("{path}.occurrences"));
    }
    if exemplars.len() > 4
        || exemplars.len() > count as usize
        || exemplars
            .iter()
            .any(|path| path.is_empty() || path.iter().any(String::is_empty))
        || exemplars
            .windows(2)
            .any(|pair| (pair[0].len(), &pair[0]) >= (pair[1].len(), &pair[1]))
    {
        invalid(errors, format!("{path}.exemplar_paths"));
    }
}
fn resource(value: &ResourceExpr, path: &str, errors: &mut Vec<RepoQueryValidationError>) {
    let mut failures = Vec::new();
    validate_resource(0, value, &mut failures);
    if !failures.is_empty()
        || (crate::normalize_resource(value.clone(), crate::PathPlatform::Posix) != *value
            && crate::normalize_resource(value.clone(), crate::PathPlatform::Windows) != *value)
    {
        invalid(errors, path);
    }
}
fn realm(value: &ExecutionRealm, path: &str, errors: &mut Vec<RepoQueryValidationError>) {
    let valid = match value {
        ExecutionRealm::Container { runtime, name } => !runtime.is_empty() && !name.is_empty(),
        ExecutionRealm::Kubernetes { pod, .. } => !pod.is_empty(),
        ExecutionRealm::Remote { endpoint } => !endpoint.is_empty(),
        _ => true,
    };
    if !valid {
        invalid(errors, path);
    }
}
impl EnvelopeRefs<'_> {
    fn entrypoint(
        &self,
        value: &str,
        path: &str,
        require: bool,
        errors: &mut Vec<RepoQueryValidationError>,
    ) {
        if value.is_empty() || (require && self.require_subjects && !self.subjects.contains(value))
        {
            invalid(errors, path);
        }
    }
    fn source(&self, value: &str, path: &str, errors: &mut Vec<RepoQueryValidationError>) {
        if !canonical_path(value) || !self.source_paths.contains(value) {
            invalid(errors, path);
        }
    }
    fn roots(&self, ids: &[OccurrenceId], path: &str, errors: &mut Vec<RepoQueryValidationError>) {
        unique(ids, path, errors);
        for id in ids {
            if !self.nodes.contains(&id.0) {
                errors.push(RepoQueryValidationError::DanglingProvenanceRef { id: id.0.clone() });
            }
        }
    }
    fn dispatch(
        &self,
        dispatch: &Option<DispatchIdentity>,
        path: &str,
        errors: &mut Vec<RepoQueryValidationError>,
    ) {
        if let Some(dispatch) = dispatch {
            self.roots(
                &dispatch.registration_roots,
                &format!("{path}.registration_roots"),
                errors,
            );
            self.roots(
                &dispatch.dispatch_roots,
                &format!("{path}.dispatch_roots"),
                errors,
            );
        }
    }
    fn operation(
        &self,
        operation: &Operation,
        path: &str,
        claim: bool,
        errors: &mut Vec<RepoQueryValidationError>,
    ) {
        if !operation.is_well_formed() {
            invalid(errors, path);
        }
        if claim
            && let Some((domain, _)) = operation.as_str().split_once('.')
            && !self.coverage.domains.contains_key(domain)
        {
            invalid(errors, format!("coverage.domains.{domain}"));
        }
    }
    fn fact(
        &self,
        fact: &EffectFact,
        path: &str,
        facts: &mut BTreeMap<String, EffectFact>,
        errors: &mut Vec<RepoQueryValidationError>,
    ) {
        occurrence_evidence(fact.occurrences, &fact.exemplar_paths, path, errors);
        if fact.request_assurance == crate::RequestAssurance::Exact
            && (fact
                .condition
                .as_ref()
                .is_some_and(crate::Condition::is_widened)
                || fact
                    .assurance
                    .is_some_and(|assurance| assurance != crate::ResolutionAssurance::Exact))
        {
            invalid(errors, format!("{path}.request_assurance"));
        }
        self.entrypoint(
            &fact.entrypoint,
            &format!("{path}.entrypoint"),
            true,
            errors,
        );
        self.operation(&fact.operation, &format!("{path}.operation"), true, errors);
        resource(&fact.resource, &format!("{path}.resource"), errors);
        realm(&fact.realm, &format!("{path}.realm"), errors);
        self.roots(
            &fact.provenance_roots,
            &format!("{path}.provenance_roots"),
            errors,
        );
        self.dispatch(&fact.dispatch, &format!("{path}.dispatch"), errors);
        if let Some(origin) = &fact.origin {
            self.source(
                &origin.source_file,
                &format!("{path}.origin.source_file"),
                errors,
            );
        }
        let seen = facts.insert(
            format!("{}\t{}", fact.fact_id.0, fact.entrypoint),
            fact.clone(),
        );
        if !valid_fact_id(&fact.fact_id)
            || fact.expected_fact_id() != fact.fact_id
            || fact.dispatch.as_ref().is_some_and(|d| d.model.is_empty())
            || seen.is_some_and(|seen| seen != *fact)
        {
            invalid(errors, format!("{path}.fact_id"));
        }
    }
}
fn fact_key(fact: &EffectFact) -> String {
    key(serde_json::json!([
        fact.origin.as_ref().map(|o| &o.source_file),
        fact.entrypoint,
        fact.operation,
        crate::display_resource(&fact.resource),
        fact.realm,
        fact.modality,
        fact.request_assurance,
        fact.dispatch,
        fact.fact_id
    ]))
}
fn facts(
    rows: &[EffectFact],
    path: &str,
    refs: &EnvelopeRefs,
    errors: &mut Vec<RepoQueryValidationError>,
) {
    ordered(rows, path, fact_key, errors);
    let mut seen = BTreeMap::new();
    for (index, fact) in rows.iter().enumerate() {
        refs.fact(fact, &format!("{path}[{index}]"), &mut seen, errors);
    }
}

impl EffectsReport {
    pub(super) fn validate(&self, refs: &EnvelopeRefs, errors: &mut Vec<RepoQueryValidationError>) {
        refs.entrypoint(&self.entrypoint, "payload.entrypoint", true, errors);
        facts(&self.effects, "payload.effects", refs, errors);
        if self.coverage != refs.coverage.domains {
            invalid(errors, "payload.coverage");
        }
        ordered(
            &self.boundaries,
            "payload.boundaries",
            |b| {
                key(serde_json::json!([
                    b.reason,
                    b.domains,
                    b.affected_resource,
                    b.detail,
                    b.limit,
                    b.dispatch,
                    b.boundary_id
                ]))
            },
            errors,
        );
        for (index, b) in self.boundaries.iter().enumerate() {
            let path = format!("payload.boundaries[{index}]");
            b.validate(refs, &path, errors);
        }
    }
}
impl BoundaryRow {
    fn validate(
        &self,
        refs: &EnvelopeRefs,
        path: &str,
        errors: &mut Vec<RepoQueryValidationError>,
    ) {
        occurrence_evidence(self.occurrences, &self.exemplar_paths, path, errors);
        sorted(&self.domains, &format!("{path}.domains"), errors);
        if let Some(r) = &self.affected_resource {
            resource(r, &format!("{path}.affected_resource"), errors);
        }
        refs.roots(
            &self.provenance_roots,
            &format!("{path}.provenance_roots"),
            errors,
        );
        refs.dispatch(&self.dispatch, &format!("{path}.dispatch"), errors);
        if !valid_boundary_id(&self.boundary_id.0)
            || refs.boundaries.get(&self.boundary_id.0).is_none_or(|b| {
                b.reason != self.reason
                    || b.domains != self.domains
                    || b.affected_resource != self.affected_resource
                    || b.detail != self.detail
                    || b.limit != self.limit
                    || b.dispatch != self.dispatch
                    || b.provenance_roots != self.provenance_roots
            })
        {
            invalid(errors, format!("{path}.boundary_id"));
        }
    }
}
impl ReachReport {
    pub(super) fn validate(&self, refs: &EnvelopeRefs, errors: &mut Vec<RepoQueryValidationError>) {
        if self.selector.is_empty() || self.operation.as_ref().is_some_and(String::is_empty) {
            invalid(errors, "payload.selector");
        }
        ordered(
            &self.matches,
            "payload.matches",
            crate::canonical_json,
            errors,
        );
        let mut seen = BTreeMap::new();
        for (i, h) in self.matches.iter().enumerate() {
            if !matches!(h.matched, crate::Match::Satisfied { .. }) {
                invalid(errors, format!("payload.matches[{i}].match"));
            }
            refs.fact(
                &h.fact,
                &format!("payload.matches[{i}].fact"),
                &mut seen,
                errors,
            );
        }
        ordered(
            &self.indeterminate,
            "payload.indeterminate",
            crate::canonical_json,
            errors,
        );
        for (i, b) in self.indeterminate.iter().enumerate() {
            let path = format!("payload.indeterminate[{i}]");
            let b = match b {
                Indeterminate::Effect {
                    fact,
                    domain,
                    matched,
                    ..
                } => {
                    refs.fact(fact, &format!("{path}.fact"), &mut seen, errors);
                    if domain != &self.domain
                        || !matches!(matched, crate::Match::Indeterminate { .. })
                    {
                        invalid(errors, path);
                    }
                    continue;
                }
                Indeterminate::Boundary { evidence } => evidence,
            };
            refs.entrypoint(&b.entrypoint, &format!("{path}.entrypoint"), true, errors);
            refs.source(&b.source_file, &format!("{path}.source_file"), errors);
            refs.roots(
                &b.provenance_roots,
                &format!("{path}.provenance_roots"),
                errors,
            );
            refs.dispatch(&b.dispatch, &format!("{path}.dispatch"), errors);
            if let Some(r) = &b.affected_resource {
                resource(r, &format!("{path}.affected_resource"), errors);
            }
            if !valid_boundary_id(&b.boundary_id.0)
                || refs
                    .boundaries
                    .get(&b.boundary_id.0)
                    .is_none_or(|expected| {
                        expected.reason != b.boundary_reason
                            || !expected.domains.contains(&b.domain)
                            || expected.affected_resource != b.affected_resource
                            || expected.detail != b.boundary_detail
                            || expected.limit != b.limit
                            || expected.dispatch != b.dispatch
                            || expected.provenance_roots != b.provenance_roots
                    })
            {
                invalid(errors, format!("{path}.boundary_id"));
            }
        }
    }
}
impl Payload {
    pub(super) fn validate(&self, refs: &EnvelopeRefs, errors: &mut Vec<RepoQueryValidationError>) {
        match self {
            Self::Effects(r) => r.validate(refs, errors),
            Self::Reach(r) => r.validate(refs, errors),
        }
    }
}
