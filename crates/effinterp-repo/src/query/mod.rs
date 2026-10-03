//! Queries over an entrypoint effect index: forward (effects of an entrypoint,
//! with coverage and boundaries) and reverse (entrypoints that may reach a
//! resource — concrete, symbolic, or indeterminate-due-to-opacity).
//!
//! The reverse query treats an opaque boundary as a possible match: an
//! entrypoint whose analysis went opaque in the queried domain cannot be
//! excluded, so it is reported as indeterminate rather than silently omitted.
//! An empty match list is never proof of safety.

use std::collections::{BTreeMap, BTreeSet};

use effinterp_engine::Assurance;
use effinterp_proto::Payload;
use effinterp_proto::{
    AffectedScope, AnalysisBoundary, AnalysisConfiguration, AnalysisCoverage, AnalysisDependency,
    AnalysisDependencyKind, AnalysisGraph, AnalysisIdentity, AnalysisStatus, AnalysisSubject,
    AnalyzerIdentity, BoundaryReason, ByteSpan, CoverageClaim, CoverageLevel, DispatchIdentity,
    EffectFact, EffectOrigin, FactId, FactIdentity, OccurrenceDescriptor, OccurrenceId, Operation,
    PartialReason, PathPlatform, PayloadKind, ProtocolProvenanceKind, ProtocolProvenanceNode,
    ProvenanceDag, ProvenanceEdge, ProvenanceEdgeKind, RepoQueryEnvelope, ResolutionAssurance,
    ResourceExpr, SourceEvidence,
};
use serde::Serialize;

use crate::dispatch::DispatchVia;
use crate::index::RepoIndex;
use crate::surface::{EffectiveEffect, ProvenanceStep, effective_surface};

mod effects;
mod reach;

pub use effects::effects_of;
pub use reach::reach;

/// Whether an operation matches a query filter: the full operation
/// ("filesystem.delete"), a domain prefix ("filesystem"), or a verb — the
/// final segment or its underscore suffix ("write" matches `*.config_write`).
/// This composes with a resource selector without requiring every operation name.
fn operation_matches(operation: &str, filter: &str) -> bool {
    operation == filter
        || operation
            .strip_prefix(filter)
            .is_some_and(|rest| rest.starts_with('.'))
        || operation.rsplit('.').next().is_some_and(|verb| {
            verb == filter
                || verb
                    .strip_suffix(filter)
                    .is_some_and(|prefix| prefix.ends_with('_'))
        })
}

fn protocol_assurance(assurance: Assurance) -> ResolutionAssurance {
    match assurance {
        Assurance::Exact => ResolutionAssurance::Exact,
        Assurance::Alternatives => ResolutionAssurance::Alternatives,
        Assurance::Heuristic => ResolutionAssurance::Heuristic,
    }
}

fn worst_coverage(a: CoverageLevel, b: CoverageLevel) -> CoverageLevel {
    match (a, b) {
        (CoverageLevel::None, _) | (_, CoverageLevel::None) => CoverageLevel::None,
        (CoverageLevel::Partial, _) | (_, CoverageLevel::Partial) => CoverageLevel::Partial,
        (CoverageLevel::Full, CoverageLevel::Full) => CoverageLevel::Full,
    }
}

fn declared_limits(index: &RepoIndex) -> BTreeMap<String, u64> {
    crate::snapshot::all_limits(&index.limits)
        .into_iter()
        .collect()
}

fn protocol_identity(index: &RepoIndex) -> AnalysisIdentity {
    let dependencies: Vec<AnalysisDependency> = index
        .dependency_manifest
        .records()
        .iter()
        .map(|dependency| AnalysisDependency {
            key: dependency.key.clone(),
            kind: match dependency.kind {
                crate::DependencyKind::SourceModule => AnalysisDependencyKind::SourceModule,
                crate::DependencyKind::SkippedSource => AnalysisDependencyKind::SkippedSource,
                crate::DependencyKind::EntrypointDiscovery => {
                    AnalysisDependencyKind::EntrypointDiscovery
                }
                crate::DependencyKind::ResolverConfig => AnalysisDependencyKind::ResolverConfig,
                crate::DependencyKind::ParserFrontend => AnalysisDependencyKind::ParserFrontend,
                crate::DependencyKind::Analyzer => AnalysisDependencyKind::Analyzer,
                crate::DependencyKind::ModelSet => AnalysisDependencyKind::ModelSet,
                crate::DependencyKind::Limit => AnalysisDependencyKind::Limit,
            },
            digest: dependency.digest.clone(),
        })
        .collect();
    let configuration = AnalysisConfiguration {
        path_platform: PathPlatform::Posix,
        limits: declared_limits(index),
    };
    let build_digest = dependencies
        .iter()
        .find(|dependency| dependency.kind == AnalysisDependencyKind::Analyzer)
        .expect("snapshot carries analyzer identity")
        .digest
        .clone();
    AnalysisIdentity {
        analyzer: AnalyzerIdentity {
            name: "effinterp".to_string(),
            version: index.analyzer.clone(),
            build_digest,
        },
        configuration_digest: configuration.digest(),
        model_set_digest: index
            .model_set
            .strip_prefix("builtin:")
            .unwrap_or(&index.model_set)
            .to_string(),
        dependencies,
    }
}

fn protocol_subjects(index: &RepoIndex) -> Vec<AnalysisSubject> {
    let mut subjects: Vec<_> = index
        .entrypoints
        .iter()
        .map(|entrypoint| AnalysisSubject {
            entrypoint: entrypoint.entrypoint.id.clone(),
            source_path: entrypoint.entrypoint.source_file.clone(),
            subject: entrypoint.entrypoint.subject.clone(),
            subject_digest: effinterp_proto::stable_hash(
                "effinterp/analysis-subject/v1",
                &entrypoint.entrypoint.subject,
            ),
        })
        .collect();
    subjects.sort_by_cached_key(|subject| {
        (
            subject.entrypoint.clone(),
            subject.source_path.clone(),
            subject.subject_digest.clone(),
            serde_json::to_string(&subject.subject).expect("subject serializes"),
        )
    });
    subjects.dedup_by(|left, right| left.entrypoint == right.entrypoint);
    subjects
}

fn all_graphs() -> Vec<AnalysisGraph> {
    vec![
        AnalysisGraph::Effects,
        AnalysisGraph::Execution,
        AnalysisGraph::Occurrences,
        AnalysisGraph::ResourceState,
        AnalysisGraph::Causality,
        AnalysisGraph::Provenance,
    ]
}

fn effect_graphs() -> Vec<AnalysisGraph> {
    vec![
        AnalysisGraph::Effects,
        AnalysisGraph::ResourceState,
        AnalysisGraph::Provenance,
    ]
}

fn origin_file<'a>(index: &RepoIndex, label: &'a str) -> &'a str {
    crate::surface::split_source_label(index, label).0
}

fn protocol_resource(resource: &ResourceExpr) -> ResourceExpr {
    effinterp_proto::normalize_resource(resource.clone(), PathPlatform::Posix)
}

fn protocol_domains(domains: &[String]) -> Vec<String> {
    let mut domains = domains.to_vec();
    domains.sort();
    domains.dedup();
    domains
}

/// Row order readers see. Fact ids are content hashes, so ordering by them
/// would scatter related effects; order by the human-meaningful fields and
/// keep the id only as a tiebreaker.
fn fact_sort_key(fact: &EffectFact) -> String {
    serde_json::to_string(&serde_json::json!([
        fact.origin.as_ref().map(|origin| &origin.source_file),
        fact.entrypoint,
        fact.operation,
        effinterp_proto::display_resource(&fact.resource),
        fact.realm,
        fact.modality,
        fact.request_assurance,
        fact.dispatch,
        fact.fact_id,
    ]))
    .expect("fact key serializes")
}

fn acyclic_provenance_edges(
    nodes: &[ProtocolProvenanceNode],
    mut edges: Vec<ProvenanceEdge>,
) -> Vec<ProvenanceEdge> {
    // Canonical occurrences can be revisited by composed paths. Keep every
    // non-back edge in deterministic order so the emitted graph remains a DAG.
    fn visit(
        node: &OccurrenceId,
        outgoing: &BTreeMap<OccurrenceId, Vec<ProvenanceEdge>>,
        visiting: &mut BTreeSet<OccurrenceId>,
        visited: &mut BTreeSet<OccurrenceId>,
        retained: &mut Vec<ProvenanceEdge>,
    ) {
        visiting.insert(node.clone());
        if let Some(edges) = outgoing.get(node) {
            for edge in edges {
                if visiting.contains(&edge.to) {
                    continue;
                }
                retained.push(edge.clone());
                if !visited.contains(&edge.to) {
                    visit(&edge.to, outgoing, visiting, visited, retained);
                }
            }
        }
        visiting.remove(node);
        visited.insert(node.clone());
    }

    edges.sort_by(|a, b| (&a.from, a.kind, &a.to).cmp(&(&b.from, b.kind, &b.to)));
    edges.dedup();
    let mut outgoing: BTreeMap<OccurrenceId, Vec<ProvenanceEdge>> = BTreeMap::new();
    for edge in edges {
        outgoing.entry(edge.from.clone()).or_default().push(edge);
    }
    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    let mut retained = Vec::new();
    for node in nodes {
        if !visited.contains(&node.id) {
            visit(
                &node.id,
                &outgoing,
                &mut visiting,
                &mut visited,
                &mut retained,
            );
        }
    }
    retained.sort_by(|a, b| (&a.from, a.kind, &a.to).cmp(&(&b.from, b.kind, &b.to)));
    retained
}

struct EnvelopeBuilder<'a> {
    index: &'a RepoIndex,
    entrypoints: Option<BTreeSet<String>>,
    explicit_paths: BTreeSet<String>,
    nodes: Vec<ProtocolProvenanceNode>,
    edges: Vec<ProvenanceEdge>,
    boundaries: Vec<AnalysisBoundary>,
}

impl<'a> EnvelopeBuilder<'a> {
    fn new(index: &'a RepoIndex) -> Self {
        Self {
            index,
            entrypoints: None,
            explicit_paths: BTreeSet::new(),
            nodes: Vec::new(),
            edges: Vec::new(),
            boundaries: Vec::new(),
        }
    }

    fn for_entrypoint(index: &'a RepoIndex, entrypoint: &str) -> Self {
        let mut builder = Self::new(index);
        builder.entrypoints = Some([entrypoint.to_string()].into_iter().collect());
        builder
    }

    fn skip_scope(&self, path: &str) -> Option<AffectedScope> {
        let explicit = self.explicit_paths.contains(path);
        match self.index.skipped_dependencies.get(path) {
            Some(dependents) => {
                let relevant = match &self.entrypoints {
                    Some(selected) => dependents.iter().any(|id| selected.contains(id)),
                    None => true,
                };
                if !explicit && !relevant {
                    return None;
                }
                if dependents.is_empty() {
                    let selected = self.entrypoints.as_ref().filter(|ids| !ids.is_empty());
                    return Some(match selected {
                        Some(ids) => AffectedScope {
                            all_entrypoints: false,
                            entrypoints: ids.iter().cloned().collect(),
                            graphs: all_graphs(),
                        },
                        None => AffectedScope::all(all_graphs()),
                    });
                }
                Some(AffectedScope {
                    all_entrypoints: false,
                    entrypoints: dependents.clone(),
                    graphs: all_graphs(),
                })
            }
            None => Some(AffectedScope::all(all_graphs())),
        }
    }

    fn digest(&self, origin: &str) -> String {
        self.index
            .dependency_manifest
            .source_digest(origin)
            .map(str::to_string)
            .unwrap_or_else(|| {
                panic!("protocol provenance origin {origin:?} is not in the snapshot")
            })
    }

    fn node(
        &mut self,
        origin: &str,
        span: ByteSpan,
        semantic_kind: &str,
        evidence: ProtocolProvenanceKind,
        antecedent: Option<&OccurrenceId>,
        duplicate_ordinal: u32,
    ) -> OccurrenceId {
        #[derive(Serialize)]
        struct OrdinalIdentity<'a> {
            origin: &'a str,
            span: ByteSpan,
            semantic_kind: &'a str,
            evidence: &'a ProtocolProvenanceKind,
            #[serde(skip_serializing_if = "Option::is_none")]
            antecedent: Option<&'a OccurrenceId>,
            #[serde(skip_serializing_if = "is_zero")]
            duplicate_ordinal: u32,
        }
        fn is_zero(value: &u32) -> bool {
            *value == 0
        }
        let input_digest = self.digest(origin);
        let ordinal_input = effinterp_proto::canonical_json(&OrdinalIdentity {
            origin,
            span,
            semantic_kind,
            evidence: &evidence,
            antecedent,
            duplicate_ordinal,
        });
        let ordinal_bytes = blake3::hash(ordinal_input.as_bytes());
        let local_ordinal = u32::from_le_bytes(
            ordinal_bytes.as_bytes()[..4]
                .try_into()
                .expect("BLAKE3 digest has four bytes"),
        );
        let occurrence = OccurrenceDescriptor {
            input_digest,
            origin: origin.to_string(),
            span,
            semantic_kind: semantic_kind.to_string(),
            local_ordinal,
        };
        let id = OccurrenceId::derive(&occurrence);
        if !self.nodes.iter().any(|node| node.id == id) {
            self.nodes.push(ProtocolProvenanceNode {
                id: id.clone(),
                occurrence,
                evidence,
            });
        }
        id
    }

    fn steps(&mut self, steps: &[ProvenanceStep]) -> Vec<OccurrenceId> {
        let mut previous: Option<OccurrenceId> = None;
        let mut duplicate_ordinals = BTreeMap::new();
        for step in steps {
            let (origin, span, semantic_kind, evidence, edge_kind) = match step {
                ProvenanceStep::SourceInput { path, digest } => {
                    let origin = origin_file(self.index, path);
                    if self.index.dependency_manifest.source_digest(origin) != Some(digest.as_str())
                    {
                        continue;
                    }
                    (
                        origin,
                        ByteSpan { start: 0, end: 0 },
                        "source_input",
                        ProtocolProvenanceKind::Source {
                            evidence: SourceEvidence::Span { start: 0, end: 0 },
                        },
                        ProvenanceEdgeKind::DerivedFrom,
                    )
                }
                // Repository analysis supplies no observation channel, and the
                // repository provenance vocabulary has no host-fact kind.
                ProvenanceStep::HostContext { .. }
                | ProvenanceStep::ToolArgument { .. }
                | ProvenanceStep::HostObservation { .. } => continue,
                ProvenanceStep::SourceSpan { file, start, end } => (
                    origin_file(self.index, file),
                    ByteSpan {
                        start: *start,
                        end: *end,
                    },
                    "source_span",
                    ProtocolProvenanceKind::Source {
                        evidence: SourceEvidence::Span {
                            start: *start,
                            end: *end,
                        },
                    },
                    ProvenanceEdgeKind::DerivedFrom,
                ),
                ProvenanceStep::Argument { file, index } => (
                    origin_file(self.index, file),
                    ByteSpan { start: 0, end: 0 },
                    "argument",
                    ProtocolProvenanceKind::Source {
                        evidence: SourceEvidence::Argument { index: *index },
                    },
                    ProvenanceEdgeKind::DerivedFrom,
                ),
                ProvenanceStep::ModelApplication {
                    file,
                    declaration_id,
                    declaration_digest,
                } => (
                    origin_file(self.index, file),
                    ByteSpan { start: 0, end: 0 },
                    "model_application",
                    ProtocolProvenanceKind::ModelApplication {
                        declaration_id: declaration_id.clone(),
                        declaration_digest: declaration_digest.clone(),
                    },
                    ProvenanceEdgeKind::AppliesModel,
                ),
                ProvenanceStep::Execution { file, node, origin } => {
                    let nested_origin = origin.as_deref().and_then(|origin| {
                        let candidate = origin_file(self.index, origin);
                        self.index
                            .dependency_manifest
                            .source_digest(candidate)
                            .is_some()
                            .then(|| candidate.to_string())
                    });
                    (
                        origin_file(self.index, file),
                        ByteSpan { start: 0, end: 0 },
                        "execution",
                        ProtocolProvenanceKind::Source {
                            evidence: SourceEvidence::Execution {
                                node: *node,
                                origin: nested_origin,
                            },
                        },
                        ProvenanceEdgeKind::Calls,
                    )
                }
                ProvenanceStep::Entrypoint { file, function } => (
                    origin_file(self.index, file),
                    ByteSpan { start: 0, end: 0 },
                    "entrypoint",
                    ProtocolProvenanceKind::Entrypoint {
                        entrypoint: match function {
                            Some(function) => format!("{file}:{function}"),
                            None => file.clone(),
                        },
                    },
                    ProvenanceEdgeKind::DerivedFrom,
                ),
                ProvenanceStep::CrossFile { from, into } => {
                    let into_origin = origin_file(self.index, into);
                    let from_origin = origin_file(self.index, from);
                    let into_known = self
                        .index
                        .dependency_manifest
                        .source_digest(into_origin)
                        .is_some();
                    let from_known = self
                        .index
                        .dependency_manifest
                        .source_digest(from_origin)
                        .is_some();
                    if !from_known || !into_known {
                        continue;
                    }
                    (
                        into_origin,
                        ByteSpan { start: 0, end: 0 },
                        "cross_file_call",
                        ProtocolProvenanceKind::CrossFileCall {
                            from: from.clone(),
                            into: into.clone(),
                        },
                        ProvenanceEdgeKind::Calls,
                    )
                }
            };
            let ordinal_key =
                effinterp_proto::canonical_json(&(origin, span, semantic_kind, &evidence));
            // The antecedent keeps equal suffix steps distinct after paths
            // converge. Repeated equal steps in one path also need ordinals.
            let duplicate_ordinal = duplicate_ordinals.entry(ordinal_key).or_insert(0);
            let id = self.node(
                origin,
                span,
                semantic_kind,
                evidence,
                previous.as_ref(),
                *duplicate_ordinal,
            );
            *duplicate_ordinal += 1;
            if let Some(previous) = previous {
                self.edges.push(ProvenanceEdge {
                    from: previous,
                    kind: edge_kind,
                    to: id.clone(),
                });
            }
            previous = Some(id);
        }
        previous.into_iter().collect()
    }

    fn dispatch(
        &mut self,
        via: Option<&DispatchVia>,
        fallback_origin: &str,
        roots: &mut Vec<OccurrenceId>,
    ) -> Option<DispatchIdentity> {
        let via = via?;
        let registration_steps = self.path_steps(&via.registration_path);
        let dispatch_steps = self.path_steps(&via.dispatch_path);
        let registration_roots = self.steps(&registration_steps);
        let dispatch_roots = self.steps(&dispatch_steps);
        let identity = DispatchIdentity {
            model: via.model.clone(),
            registration_roots,
            dispatch_roots,
        };
        let origin = identity
            .dispatch_roots
            .last()
            .or_else(|| identity.registration_roots.last())
            .and_then(|id| {
                self.nodes
                    .iter()
                    .find(|node| &node.id == id)
                    .map(|node| node.occurrence.origin.clone())
            })
            .unwrap_or_else(|| fallback_origin.to_string());
        let dispatch = self.node(
            &origin,
            ByteSpan { start: 0, end: 0 },
            "dispatch",
            ProtocolProvenanceKind::Dispatch {
                model: identity.model.clone(),
                registration_roots: identity.registration_roots.clone(),
                dispatch_roots: identity.dispatch_roots.clone(),
            },
            None,
            0,
        );
        for root in identity
            .registration_roots
            .iter()
            .chain(&identity.dispatch_roots)
        {
            self.edges.push(ProvenanceEdge {
                from: root.clone(),
                kind: ProvenanceEdgeKind::Dispatches,
                to: dispatch.clone(),
            });
        }
        roots.push(dispatch);
        Some(identity)
    }

    fn path_steps(&self, path: &[String]) -> Vec<ProvenanceStep> {
        let source_path: Vec<String> = path
            .iter()
            .filter(|label| {
                let origin = origin_file(self.index, label);
                self.index
                    .dependency_manifest
                    .source_digest(origin)
                    .is_some()
            })
            .cloned()
            .collect();
        let mut steps = cross_file_steps_for_protocol(self.index, &source_path);
        if let Some(file) = source_path
            .last()
            .map(|label| origin_file(self.index, label).to_string())
        {
            steps.extend(path.iter().filter_map(|label| {
                label
                    .strip_prefix("argument:")
                    .and_then(|index| index.parse().ok())
                    .map(|index| ProvenanceStep::Argument {
                        file: file.clone(),
                        index,
                    })
            }));
        }
        steps
    }

    fn fact(&mut self, entrypoint: &str, effect: &EffectiveEffect) -> EffectFact {
        let mut roots = self.steps(&effect.provenance);
        for path in &effect.paths {
            roots.extend(self.steps(&crate::surface::cross_file_steps(self.index, path)));
        }
        roots.sort();
        roots.dedup();
        if roots.is_empty() {
            roots.push(self.node(
                &effect.origin_file,
                ByteSpan { start: 0, end: 0 },
                "effect",
                ProtocolProvenanceKind::Source {
                    evidence: SourceEvidence::Function {
                        name: effect.origin_file.clone(),
                    },
                },
                None,
                0,
            ));
        }
        let dispatch = self.dispatch(
            effect.via_dispatch.as_ref(),
            &effect.origin_file,
            &mut roots,
        );
        let identity = FactIdentity {
            operation: Operation::new(&effect.operation),
            resource: protocol_resource(&effect.resource_expr),
            realm: effect.realm.clone(),
            modality: effect.modality,
            request_assurance: effect.request_assurance,
            attributes: effect.attributes.clone(),
            condition: effect.condition.clone(),
            provenance_roots: roots.clone(),
            dispatch: dispatch.clone(),
        };
        let mut exemplar_paths = effect.paths.clone();
        exemplar_paths.sort_by(|a, b| a.len().cmp(&b.len()).then(a.cmp(b)));
        exemplar_paths.dedup();
        exemplar_paths.truncate(4);
        EffectFact {
            occurrences: effect.occurrences,
            exemplar_paths,
            fact_id: FactId::derive(&identity),
            entrypoint: entrypoint.to_string(),
            operation: identity.operation,
            resource: identity.resource,
            realm: identity.realm,
            modality: identity.modality,
            request_assurance: identity.request_assurance,
            attributes: identity.attributes,
            condition: identity.condition,
            origin: (!effect.origin_file.is_empty()).then(|| EffectOrigin {
                source_file: effect.origin_file.clone(),
                execution_node: effect.execution,
            }),
            assurance: effect.assurance.map(protocol_assurance),
            dispatch,
            provenance_roots: roots,
        }
    }

    fn boundary(
        &mut self,
        boundary: &crate::surface::EffectiveBoundary,
        fallback_origin: &str,
    ) -> (String, Vec<OccurrenceId>, Option<DispatchIdentity>) {
        let mut roots = self.steps(&boundary.provenance);
        for path in &boundary.exemplar_paths {
            roots.extend(self.steps(&crate::surface::cross_file_steps(self.index, path)));
        }
        roots.sort();
        roots.dedup();
        let dispatch = self.dispatch(boundary.via_dispatch.as_ref(), fallback_origin, &mut roots);
        let domains = protocol_domains(&boundary.domains);
        let mut analysis_boundary = AnalysisBoundary {
            class: boundary.class,
            id: String::new(),
            reason: boundary.reason.clone(),
            domains,
            affected_resource: boundary.affected_resource.as_ref().map(protocol_resource),
            detail: boundary.detail.clone(),
            limit: boundary.limit.clone(),
            dispatch: dispatch.clone(),
            provenance_roots: roots.clone(),
        };
        analysis_boundary.id = analysis_boundary.expected_id();
        let id = analysis_boundary.id.clone();
        if !self.boundaries.iter().any(|existing| existing.id == id) {
            self.boundaries.push(analysis_boundary);
        }
        (id, roots, dispatch)
    }

    fn coverage_boundary(
        &mut self,
        domains: Vec<String>,
        scope: &AffectedScope,
        class: effinterp_proto::BoundaryClass,
        reason: BoundaryReason,
        detail: String,
        limit: Option<String>,
    ) {
        if domains.is_empty() {
            return;
        }
        let steps: Vec<_> = self
            .index
            .entrypoints
            .iter()
            .filter(|entry| {
                scope.all_entrypoints || scope.entrypoints.contains(&entry.entrypoint.id)
            })
            .filter(|entry| {
                self.index
                    .dependency_manifest
                    .source_digest(&entry.entrypoint.source_file)
                    .is_some()
            })
            .map(|entry| ProvenanceStep::Entrypoint {
                file: entry.entrypoint.source_file.clone(),
                function: None,
            })
            .collect();
        let mut provenance_roots: Vec<_> = steps
            .iter()
            .flat_map(|step| self.steps(std::slice::from_ref(step)))
            .collect();
        provenance_roots.sort();
        provenance_roots.dedup();
        let mut boundary = AnalysisBoundary {
            id: String::new(),
            class,
            reason,
            domains: protocol_domains(&domains),
            affected_resource: None,
            detail: Some(detail),
            limit,
            dispatch: None,
            provenance_roots,
        };
        boundary.id = boundary.expected_id();
        self.boundaries.push(boundary);
    }

    fn finish(
        mut self,
        payload: Payload,
        mut domains: BTreeMap<String, CoverageLevel>,
        mut causality: Option<CoverageLevel>,
    ) -> RepoQueryEnvelope {
        let payload_kind = payload.kind();
        if let Some(level) = domains.remove("dataflow") {
            causality = Some(causality.map_or(level, |current| worst_coverage(current, level)));
        }
        let selected: Vec<_> = self
            .index
            .entrypoints
            .iter()
            .filter(|entrypoint| {
                self.entrypoints
                    .as_ref()
                    .is_none_or(|ids| ids.contains(&entrypoint.entrypoint.id))
            })
            .collect();
        let surfaces: Vec<_> = selected
            .iter()
            .filter_map(|entrypoint| effective_surface(self.index, &entrypoint.entrypoint.id))
            .collect();
        if payload_kind != PayloadKind::Reach {
            for surface in &surfaces {
                for effect in &surface.effects {
                    if let Some((domain, _)) = effect.operation.split_once('.') {
                        domains
                            .entry(domain.to_string())
                            .or_insert(CoverageLevel::Full);
                    }
                }
            }
        }
        for boundary in &self.boundaries {
            for domain in &boundary.domains {
                if domain == "dataflow" {
                    causality = Some(worst_coverage(
                        causality.unwrap_or(CoverageLevel::Full),
                        CoverageLevel::Partial,
                    ));
                } else {
                    domains
                        .entry(domain.clone())
                        .or_insert(CoverageLevel::Partial);
                }
            }
        }
        if surfaces.is_empty() {
            domains.clear();
        } else {
            for surface in &surfaces {
                let missing: Vec<_> = domains
                    .keys()
                    .filter(|domain| !surface.coverage.contains_key(*domain))
                    .cloned()
                    .collect();
                self.coverage_boundary(
                    missing,
                    &AffectedScope::entrypoint(surface.entrypoint.clone(), effect_graphs()),
                    effinterp_proto::BoundaryClass::Unmodeled,
                    BoundaryReason::FRONTEND_PARTIAL,
                    format!(
                        "entrypoint {} makes no contributing coverage claim",
                        surface.entrypoint
                    ),
                    None,
                );
                for (domain, level) in &mut domains {
                    *level = worst_coverage(
                        *level,
                        surface
                            .coverage
                            .get(domain)
                            .copied()
                            .unwrap_or(CoverageLevel::Partial),
                    );
                }
            }
        }
        self.nodes.sort_by(|a, b| a.id.cmp(&b.id));
        self.edges = acyclic_provenance_edges(&self.nodes, self.edges);
        self.boundaries.sort_by(|a, b| a.id.cmp(&b.id));

        let mut reasons = Vec::new();
        reasons.extend(self.index.skipped.iter().filter_map(|skip| {
            let scope = self.skip_scope(&skip.path)?;
            match skip.category {
                crate::index::SkipCategory::Ignored => self
                    .index
                    .skipped_dependencies
                    .get(&skip.path)
                    .filter(|ids| !ids.is_empty())
                    .map(|_| PartialReason::UnanalyzedInput {
                        path: skip.path.clone(),
                        scope,
                    }),
                crate::index::SkipCategory::Limit => Some(PartialReason::LimitReached {
                    limit: skip.reason.clone(),
                    scope,
                }),
                crate::index::SkipCategory::Failure => Some(PartialReason::UnanalyzedInput {
                    path: skip.path.clone(),
                    scope,
                }),
            }
        }));
        if self.index.skips_truncated && self.entrypoints.is_none() {
            reasons.push(PartialReason::LimitReached {
                limit: "crawl.max_skips".to_string(),
                scope: AffectedScope::all(all_graphs()),
            });
        }
        reasons.extend(
            selected
                .iter()
                .filter_map(|entrypoint| match &entrypoint.outcome {
                    crate::index::EntrypointOutcome::Analyzed { .. } => None,
                    crate::index::EntrypointOutcome::Failed { .. } => {
                        Some(PartialReason::AnalysisFailure {
                            entrypoint: entrypoint.entrypoint.id.clone(),
                            scope: AffectedScope::entrypoint(
                                entrypoint.entrypoint.id.clone(),
                                all_graphs(),
                            ),
                        })
                    }
                    crate::index::EntrypointOutcome::LimitReached { limit } => {
                        Some(PartialReason::LimitReached {
                            limit: limit.clone(),
                            scope: AffectedScope::entrypoint(
                                entrypoint.entrypoint.id.clone(),
                                all_graphs(),
                            ),
                        })
                    }
                }),
        );
        for reason in &reasons {
            let scope = match reason {
                PartialReason::UnsupportedEvidence { scope, .. }
                | PartialReason::UnanalyzedInput { scope, .. }
                | PartialReason::AnalysisFailure { scope, .. }
                | PartialReason::LimitReached { scope, .. }
                | PartialReason::Truncated { scope, .. } => scope,
            };
            let (class, boundary_reason, limit) = match reason {
                PartialReason::UnsupportedEvidence { .. } => continue,
                PartialReason::UnanalyzedInput { .. } => (
                    effinterp_proto::BoundaryClass::Unresolved,
                    BoundaryReason::UNRESOLVED_CALL,
                    None,
                ),
                PartialReason::AnalysisFailure { .. } => (
                    effinterp_proto::BoundaryClass::ParseFailure,
                    BoundaryReason::FRONTEND_PARTIAL,
                    None,
                ),
                PartialReason::LimitReached { limit, .. } => (
                    effinterp_proto::BoundaryClass::Limit,
                    BoundaryReason::LIMIT_SATURATED,
                    Some(limit.clone()),
                ),
                PartialReason::Truncated { collection, .. } => (
                    effinterp_proto::BoundaryClass::Limit,
                    BoundaryReason::FRONTEND_PARTIAL,
                    Some(collection.clone()),
                ),
            };
            let mut affected: Vec<_> = domains.keys().cloned().collect();
            if causality.is_some() {
                affected.push("dataflow".to_string());
            }
            let detail = match reason {
                PartialReason::UnanalyzedInput { path, .. } => {
                    let explanation = self
                        .index
                        .skipped
                        .iter()
                        .find(|skip| skip.path == *path)
                        .map(|skip| skip.reason.as_str())
                        .unwrap_or("snapshot input is unavailable");
                    format!("{path}: {explanation}")
                }
                PartialReason::AnalysisFailure { entrypoint, .. } => {
                    format!("entrypoint analysis failed: {entrypoint}")
                }
                PartialReason::LimitReached { limit, .. } => {
                    format!("analysis limit reached: {limit}")
                }
                PartialReason::Truncated {
                    collection, limit, ..
                } => format!("{collection} truncated at {limit}"),
                PartialReason::UnsupportedEvidence { .. } => unreachable!(),
            };
            self.coverage_boundary(affected, scope, class, boundary_reason, detail, limit);
        }
        self.boundaries.sort_by(|a, b| a.id.cmp(&b.id));
        self.boundaries.dedup_by(|a, b| a.id == b.id);
        let boundary_scope = match &self.entrypoints {
            Some(ids) => AffectedScope {
                all_entrypoints: false,
                entrypoints: ids.iter().cloned().collect(),
                graphs: all_graphs(),
            },
            None => AffectedScope::all(all_graphs()),
        };
        for boundary in &self.boundaries {
            reasons.push(match &boundary.limit {
                Some(limit) => PartialReason::LimitReached {
                    limit: limit.clone(),
                    scope: boundary_scope.clone(),
                },
                None => PartialReason::UnsupportedEvidence {
                    boundary_id: boundary.id.clone(),
                    scope: boundary_scope.clone(),
                },
            });
        }
        self.nodes.sort_by(|a, b| a.id.cmp(&b.id));
        self.edges = acyclic_provenance_edges(&self.nodes, self.edges);
        let claim = |domain: &str, level| {
            let gaps: Vec<_> = self
                .boundaries
                .iter()
                .filter(|boundary| boundary.domains.iter().any(|value| value == domain))
                .map(|boundary| boundary.id.clone())
                .collect();
            CoverageClaim {
                level: if gaps.is_empty() {
                    level
                } else {
                    worst_coverage(level, CoverageLevel::Partial)
                },
                gaps,
            }
        };
        let domains = domains
            .into_iter()
            .map(|(domain, level)| {
                let coverage = claim(&domain, level);
                (domain, coverage)
            })
            .collect();
        let causality = causality.map(|level| claim("dataflow", level));
        reasons.sort_by_key(|reason| {
            serde_json::to_string(reason).expect("partial reason serializes")
        });
        reasons.dedup();
        let status = if reasons.is_empty() {
            AnalysisStatus::Complete
        } else {
            AnalysisStatus::Partial { reasons }
        };
        let mut provenance = ProvenanceDag {
            nodes: std::mem::take(&mut self.nodes),
            edges: std::mem::take(&mut self.edges),
        };
        let reachable = provenance.reachable_nodes(&payload, &self.boundaries);
        provenance.nodes.retain(|node| reachable.contains(&node.id));
        provenance
            .edges
            .retain(|edge| reachable.contains(&edge.from) && reachable.contains(&edge.to));
        let mut keys = BTreeSet::new();
        let subjects: Vec<_> = protocol_subjects(self.index)
            .into_iter()
            .filter(|subject| {
                self.entrypoints
                    .as_ref()
                    .is_none_or(|ids| ids.contains(&subject.entrypoint))
            })
            .collect();
        for subject in &subjects {
            for output in [
                format!("entrypoint:{}", subject.entrypoint),
                format!("composition:{}", subject.entrypoint),
                format!("launch-composition:{}", subject.source_path),
            ] {
                if let Some(dependencies) = self.index.derived_dependencies.get(&output) {
                    keys.extend(dependencies.iter().cloned());
                }
            }
        }
        for node in &provenance.nodes {
            keys.insert(format!("source:{}", node.occurrence.origin));
        }
        for skip in &self.index.skipped {
            if self.skip_scope(&skip.path).is_some() {
                keys.insert(format!("skipped-source:{}", skip.path));
            }
        }
        let mut identity = protocol_identity(self.index);
        identity.dependencies.retain(|dependency| {
            keys.contains(&dependency.key)
                || matches!(
                    dependency.kind,
                    AnalysisDependencyKind::Analyzer
                        | AnalysisDependencyKind::ModelSet
                        | AnalysisDependencyKind::Limit
                )
        });
        RepoQueryEnvelope::new(
            self.index.fingerprint.clone(),
            identity,
            subjects,
            status,
            AnalysisCoverage { domains, causality },
            self.boundaries,
            provenance,
            payload_kind,
            payload,
        )
    }
}

fn cross_file_steps_for_protocol(index: &RepoIndex, path: &[String]) -> Vec<ProvenanceStep> {
    if path.len() < 2 {
        return path
            .iter()
            .map(|file| ProvenanceStep::Entrypoint {
                file: origin_file(index, file).to_string(),
                function: crate::surface::split_source_label(index, file)
                    .1
                    .map(str::to_string),
            })
            .collect();
    }
    path.windows(2)
        .map(|pair| ProvenanceStep::CrossFile {
            from: pair[0].clone(),
            into: pair[1].clone(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provenance_node(id: &str) -> ProtocolProvenanceNode {
        ProtocolProvenanceNode {
            id: OccurrenceId(id.to_string()),
            occurrence: OccurrenceDescriptor {
                input_digest: "digest".to_string(),
                origin: "source".to_string(),
                span: ByteSpan { start: 0, end: 0 },
                semantic_kind: "test".to_string(),
                local_ordinal: 0,
            },
            evidence: ProtocolProvenanceKind::Source {
                evidence: SourceEvidence::Function {
                    name: id.to_string(),
                },
            },
        }
    }

    #[test]
    fn provenance_edges_are_deterministically_acyclic() {
        let a = OccurrenceId("a".to_string());
        let b = OccurrenceId("b".to_string());
        let nodes = vec![provenance_node("a"), provenance_node("b")];
        let edges = vec![
            ProvenanceEdge {
                from: b.clone(),
                kind: ProvenanceEdgeKind::DerivedFrom,
                to: a.clone(),
            },
            ProvenanceEdge {
                from: a.clone(),
                kind: ProvenanceEdgeKind::DerivedFrom,
                to: b.clone(),
            },
            ProvenanceEdge {
                from: a.clone(),
                kind: ProvenanceEdgeKind::DerivedFrom,
                to: a.clone(),
            },
        ];
        let mut reversed = edges.clone();
        reversed.reverse();
        let expected = vec![ProvenanceEdge {
            from: a,
            kind: ProvenanceEdgeKind::DerivedFrom,
            to: b,
        }];
        assert_eq!(acyclic_provenance_edges(&nodes, edges), expected);
        assert_eq!(acyclic_provenance_edges(&nodes, reversed), expected);
    }
}
