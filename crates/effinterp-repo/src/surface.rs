//! The canonical effective surface of an entrypoint.
//!
//! An entrypoint has two sources of effects: the direct effects the engine
//! found in its own file (its `Plan`), and the cross-file effects reached by
//! composing summaries through resolved calls (its `Composition`). Every public
//! query must describe the SAME reachable effect graph, so they all consume the
//! merged, deduplicated surface built here — never one source in isolation. An
//! effect found in the entrypoint file and one reached through a resolved call
//! are indistinguishable in the external contract; only the explanation differs.

use std::collections::{BTreeMap, BTreeSet};

use effinterp_engine::Assurance;
use effinterp_proto::{
    AttrValue, BoundaryReason, Condition, CoverageLevel, Effect, ExecutionRealm, Modality, Plan,
    ProvenanceKind, ProvenanceRef, ResourceExpr, ResourceIdentity, display_resource_with_scope,
};

use crate::dispatch::DispatchVia;
use crate::index::RepoIndex;
use crate::resource::family;

/// One structured provenance step. Both single-file evidence (a source span, an
/// argument, a model application) and cross-file transitions (a resolved call
/// from one file's function into another) are represented, so a composed
/// effect's callee attribution is never reduced to an opaque string.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "step", rename_all = "snake_case")]
pub enum ProvenanceStep {
    SourceInput {
        path: String,
        digest: String,
    },
    HostContext {
        name: String,
    },
    SourceSpan {
        file: String,
        start: u32,
        end: u32,
    },
    Argument {
        file: String,
        index: u32,
    },
    ToolArgument {
        file: String,
        name: String,
    },
    ModelApplication {
        file: String,
        declaration_id: String,
        declaration_digest: Option<String>,
    },
    Execution {
        file: String,
        node: u32,
        origin: Option<String>,
    },
    Entrypoint {
        file: String,
        function: Option<String>,
    },
    /// A resolved call crossing from `from` (file or file:function) into `into`
    /// (file:function) — the cross-file edge that reached the effect.
    CrossFile {
        from: String,
        into: String,
    },
    /// A host answered a question about initial filesystem state.
    HostObservation {
        query: String,
        answer: String,
    },
}

impl ProvenanceStep {
    pub fn render(&self) -> String {
        match self {
            ProvenanceStep::SourceInput { path, digest } => format!("{path}: input {digest}"),
            ProvenanceStep::HostContext { name } => format!("host context env:{name}"),
            ProvenanceStep::SourceSpan { file, start, end } => {
                format!("{file}: source[{start}..{end}]")
            }
            ProvenanceStep::Argument { file, index } => format!("{file}: arg[{index}]"),
            ProvenanceStep::ToolArgument { file, name } => {
                format!("{file}: tool argument {name}")
            }
            ProvenanceStep::ModelApplication {
                file,
                declaration_id,
                declaration_digest,
            } => match declaration_digest {
                Some(digest) => format!("{file}: model {declaration_id}#blake3:{digest}"),
                None => format!("{file}: model {declaration_id}"),
            },
            ProvenanceStep::Execution { file, node, origin } => match origin {
                Some(origin) => {
                    format!(
                        "{file}: execution #{node} ({})",
                        origin.trim_start_matches('/')
                    )
                }
                None => format!("{file}: execution #{node}"),
            },
            ProvenanceStep::Entrypoint { file, function } => match function {
                Some(function) => format!("{file}:{function}"),
                None => file.clone(),
            },
            ProvenanceStep::CrossFile { from, into } => format!("{from} -> {into}"),
            ProvenanceStep::HostObservation { query, answer } => {
                format!("host observation {query}: {answer}")
            }
        }
    }
}

/// An effect on the canonical surface: the effect data plus where it occurs
/// (realm), how it is reached (structured provenance), and whether it is
/// destructive. `family` is the short selector family (fs/proc/db/...).
#[derive(Debug, Clone)]
pub struct EffectiveEffect {
    pub occurrences: u32,
    pub paths: Vec<Vec<String>>,
    pub operation: String,
    pub resource: String,
    pub family: &'static str,
    pub realm: ExecutionRealm,
    pub execution: Option<effinterp_proto::ExecutionNodeRef>,
    pub modality: Modality,
    pub request_assurance: effinterp_proto::RequestAssurance,
    /// Attributes that qualify the effect (e.g. recursive deletion). Part of the
    /// semantic identity — a recursive and a non-recursive delete of the same
    /// path are different conclusions and must not collapse into one.
    pub attributes: std::collections::BTreeMap<String, AttrValue>,
    /// The reachability condition, if the effect is conditional. A conditional
    /// and an unconditional effect on the same resource are distinct.
    pub condition: Option<Condition>,
    pub destructive: bool,
    pub provenance: Vec<ProvenanceStep>,
    /// The file the effect originates in (the entrypoint file for direct
    /// effects, the defining file for composed ones).
    pub origin_file: String,
    /// The raw resource expression, kept for selector matching.
    pub resource_expr: effinterp_proto::ResourceExpr,
    pub assurance: Option<Assurance>,
    pub via_dispatch: Option<DispatchVia>,
}

impl EffectiveEffect {
    /// The dedup identity: the full semantic tuple plus the originating file,
    /// so only effects that agree on realm, operation, structural resource,
    /// modality, attributes, condition, and origin are treated as the same
    /// conclusion (whether found directly or through composition). Origin is
    /// part of the identity because two symbolic effects that render alike
    /// (`filesystem.read <fs:?>`) from different files are different code
    /// sites, not one conclusion.
    fn key(&self) -> String {
        format!(
            "{}\u{1}{}\u{1}{}\u{1}{}\u{1}{}\u{1}{}\u{1}{}\u{1}{:?}\u{1}{:?}",
            realm_key(&self.realm),
            self.operation,
            serde_json::to_string(&self.resource_expr).expect("resource expression serialization"),
            modality_key(self.modality),
            attributes_key(&self.attributes),
            self.condition
                .as_ref()
                .map(|c| c.identity_key())
                .unwrap_or_default(),
            self.origin_file,
            self.via_dispatch,
            self.request_assurance,
        )
    }
}

fn modality_key(m: Modality) -> &'static str {
    match m {
        Modality::May => "may",
        Modality::MustOnSuccess => "must",
    }
}

fn attributes_key(attrs: &std::collections::BTreeMap<String, AttrValue>) -> String {
    // BTreeMap iterates in sorted key order, so this is deterministic.
    attrs
        .iter()
        .map(|(k, v)| match v {
            AttrValue::Bool(b) => format!("{k}={b}"),
            AttrValue::Int(i) => format!("{k}={i}"),
            AttrValue::String(s) => format!("{k}={s}"),
            AttrValue::List(_) => format!("{k}={}", serde_json::to_string(v).unwrap()),
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// A boundary on the canonical surface (direct or from composition).
#[derive(Debug, Clone)]
pub struct EffectiveBoundary {
    pub occurrences: u32,
    pub exemplar_paths: Vec<Vec<String>>,
    pub class: effinterp_proto::BoundaryClass,
    pub reason: BoundaryReason,
    pub domains: Vec<String>,
    pub affected_resource: Option<ResourceExpr>,
    pub detail: Option<String>,
    pub limit: Option<String>,
    pub provenance: Vec<ProvenanceStep>,
    pub via_dispatch: Option<DispatchVia>,
}

/// The merged, deduplicated effect surface of one entrypoint.
#[derive(Debug, Clone)]
pub struct EffectiveSurface {
    pub entrypoint: String,
    pub source_file: String,
    pub effects: Vec<EffectiveEffect>,
    pub boundaries: Vec<EffectiveBoundary>,
    pub coverage: BTreeMap<String, CoverageLevel>,
}

/// A stable string key for a realm, used for dedup and equality. It is lossless:
/// every namespace-disambiguating field (runtime, name, namespace, pod,
/// container, host_root, endpoint) is included, so two realms that differ in any
/// of them get different keys and are never conflated. Pod/namespace/container
/// and container names cannot contain `/`, so the slash-joined fields are
/// unambiguous.
pub(crate) use effinterp_proto::realm_key;

/// Build the canonical effective surface for an entrypoint, merging its direct
/// plan and its cross-file composition and deduplicating overlapping effects.
/// Returns None if the entrypoint is unknown or its analysis failed.
pub fn effective_surface(index: &RepoIndex, entrypoint_id: &str) -> Option<EffectiveSurface> {
    effective_surface_inner(
        index,
        entrypoint_id,
        false,
        true,
        None,
        ExecutionRealm::Host,
        &mut Vec::new(),
    )
}

fn effective_surface_inner(
    index: &RepoIndex,
    entrypoint_id: &str,
    launched_as_file: bool,
    include_plan: bool,
    runtime_cwd: Option<ResourceExpr>,
    runtime_realm: ExecutionRealm,
    launch_stack: &mut Vec<String>,
) -> Option<EffectiveSurface> {
    let analyzed = index.find(entrypoint_id)?;
    let plan = analyzed.plan()?;
    let source_file = analyzed.entrypoint.source_file.clone();
    let runtime_cwd = runtime_cwd.or_else(|| {
        crate::discover::subject_cwd(&analyzed.entrypoint.subject).map(|path| {
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath {
                    path: path.to_string(),
                },
            }
        })
    });
    launch_stack.push(entrypoint_id.to_string());

    let composition = if launched_as_file && analyzed.entrypoint.package_inits.is_empty() {
        index.launch_composition(&source_file)
    } else {
        index.composition(entrypoint_id)
    };
    // The package view is derived when the index is built and stored with it,
    // so a snapshot loaded from disk (which carries no registry) answers with
    // exactly the resolution the live index had.
    let root_effects = analyzed
        .entrypoint
        .registration
        .is_none()
        .then(|| index.go_root_effects.get(&source_file))
        .flatten();
    let resolves_go_root = root_effects.is_some();
    let root_effects: &[crate::index::GoRootEffect] = root_effects.map_or(&[], Vec::as_slice);
    let specialized_root_effects: Vec<Effect> = root_effects
        .iter()
        .map(|entry| entry.resolved.clone())
        .collect();
    // Package-specialized root summaries and direct composition are two views
    // of the Go root function's effects, which the single-file plan already
    // carries as unknowns: the plan sees a package constant as an unresolvable
    // name, while both repository views can substitute its value.
    //
    // A resolved conclusion therefore replaces one plan unknown, counted per
    // occurrence of the root function's own effects and never per operation:
    // the plan also holds the effects of `init` and of package-variable
    // initializers, and an identical unknown raised there is a different
    // conclusion that must survive.
    let mut root_budget: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    for entry in root_effects {
        if is_placeholder(&entry.plan.resource) && !is_placeholder(&entry.resolved.resource) {
            *root_budget
                .entry(effect_shape_key(&entry.plan))
                .or_default() += 1;
        }
    }
    // Composition resolves an argument the package view cannot (a constant
    // reaching `net.Listen`, whose endpoint the frontend never built). It
    // reports no unspecialized counterpart, so each resolved effect it adds
    // beyond its own unknowns covers one still-unresolved root occurrence of
    // that operation.
    let mut composed_budget: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    if resolves_go_root {
        let mut composed_surplus: std::collections::HashMap<String, i64> =
            std::collections::HashMap::new();
        for (effect, _, _) in composition
            .into_iter()
            .flat_map(|composition| composition.effect_evidence())
            .filter(|(_, occurrence, _)| {
                occurrence.is_some_and(|occurrence| occurrence.source_file == source_file)
            })
        {
            let surplus = composed_surplus
                .entry(effect.operation.0.clone())
                .or_default();
            if is_placeholder(&effect.resource) {
                *surplus -= 1;
            } else {
                *surplus += 1;
            }
        }
        for entry in root_effects {
            if !is_placeholder(&entry.plan.resource) || !is_placeholder(&entry.resolved.resource) {
                continue;
            }
            let surplus = composed_surplus
                .entry(entry.plan.operation.0.clone())
                .or_default();
            if *surplus > 0 {
                *surplus -= 1;
                *composed_budget
                    .entry(effect_shape_key(&entry.plan))
                    .or_default() += 1;
            }
        }
    }
    let mut plan_budget = root_budget.clone();
    for (key, count) in &composed_budget {
        *plan_budget.entry(key.clone()).or_default() += count;
    }
    let mut composed_effect_budget = root_budget;

    let mut effects: Vec<EffectiveEffect> = Vec::new();
    let mut seen: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut push = |e: EffectiveEffect, effects: &mut Vec<EffectiveEffect>| {
        let key = e.key();
        if let Some(index) = seen.get(&key).copied() {
            effects[index].assurance = weakest(effects[index].assurance, e.assurance);
            if !e.paths.is_empty() {
                if effects[index].paths.is_empty() {
                    effects[index].occurrences = e.occurrences;
                } else {
                    effects[index].occurrences =
                        effects[index].occurrences.saturating_add(e.occurrences);
                }
                effects[index].paths.extend(e.paths);
            }
        } else {
            seen.insert(key, effects.len());
            effects.push(e);
        }
    };

    // The repository saw the imports the single-file plan could not resolve, so
    // its view of an entrypoint-file occurrence can prove a necessity the plan
    // could not. Publishing both would give one interaction two modalities, so
    // the plan's row carries the repository's conclusion — but only when the
    // repository covered every plan occurrence of that value and proved them
    // all required, so look-alike occurrences are never promoted together.
    let mut repository_necessity: std::collections::HashMap<String, (usize, bool)> =
        std::collections::HashMap::new();
    for effect in specialized_root_effects.iter().chain(
        composition
            .into_iter()
            .flat_map(|composition| &composition.local_necessity),
    ) {
        let entry = repository_necessity
            .entry(occurrence_value_key(effect))
            .or_insert((0, true));
        entry.0 += 1;
        entry.1 &= effect.modality == Modality::MustOnSuccess;
    }
    let mut plan_occurrences: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    for effect in &plan.effects {
        *plan_occurrences
            .entry(occurrence_value_key(effect))
            .or_default() += 1;
    }

    // Direct effects first, so their more specific in-file provenance wins on a
    // tie with a composed duplicate.
    if include_plan {
        for effect in &plan.effects {
            // The plan's half of a resolved occurrence is a bare unknown or the
            // unbound name a repository view has now bound (`lib.Target`).
            if matches!(
                effect.resource,
                ResourceExpr::Unresolved { .. } | ResourceExpr::Parameter { .. }
            ) && let Some(count) = plan_budget.get_mut(&effect_shape_key(effect))
                && *count > 0
            {
                *count -= 1;
                continue;
            }
            let resource_expr = runtime_cwd
                .as_ref()
                .filter(|_| effect.realm == runtime_realm)
                .map(|cwd| bind_cwd(&effect.resource, cwd))
                .unwrap_or_else(|| effect.resource.clone());
            let occurrence = occurrence_value_key(effect);
            let modality = match repository_necessity.get(&occurrence) {
                Some((covered, true)) if *covered >= plan_occurrences[&occurrence] => {
                    Modality::MustOnSuccess
                }
                _ => effect.modality,
            };
            push(
                EffectiveEffect {
                    occurrences: 1,
                    paths: Vec::new(),
                    operation: effect.operation.0.clone(),
                    resource: display_resource_with_scope(&resource_expr),
                    family: family(effect.operation.domain(), &resource_expr),
                    realm: effect.realm.clone(),
                    execution: Some(effect.execution),
                    modality,
                    request_assurance: effect.request_assurance,
                    attributes: effect.attributes.clone(),
                    condition: effect.condition.clone(),
                    destructive: effect.operation.is_destructive(),
                    provenance: local_steps(plan, &effect.provenance, &source_file),
                    origin_file: direct_origin(
                        plan,
                        effect.execution,
                        &effect.provenance,
                        &source_file,
                    ),
                    resource_expr,
                    assurance: None,
                    via_dispatch: None,
                },
                &mut effects,
            );
        }
    }

    let resolved_calls =
        composition.map_or(&[][..], |composition| composition.resolved_calls.as_slice());
    let resolved_decorators = composition.map_or(&[][..], |composition| {
        composition.resolved_decorators.as_slice()
    });
    let mut retracted_domains = BTreeSet::new();
    let mut boundaries: Vec<EffectiveBoundary> = if include_plan {
        plan.boundaries
            .iter()
            // Single-file Go analysis marks interface calls as deferred, and a
            // callable handed to a name it cannot see as escaped. At repository
            // scope the composition below replaces both markers with either
            // bounded targets or its own boundary over the unresolved call.
            .filter(|boundary| {
                boundary.reason.as_str() != "unresolved_interface"
                    && boundary.reason.as_str() != "escaped_callable"
            })
            .filter_map(|b| {
                if b.reason == BoundaryReason::UNRESOLVED_DECORATOR
                    && resolved_decorators.iter().any(|resolved| {
                        resolved.matches_boundary(
                            &source_file,
                            b.callee.as_ref(),
                            b.detail.as_deref(),
                        )
                    })
                {
                    retracted_domains.extend(b.domains.iter().map(|domain| domain.0.clone()));
                    return None;
                }
                if (b.reason == BoundaryReason::UNRESOLVED_CALL
                    || b.reason == BoundaryReason::UNMODELED_IMPORT)
                    && b.callee.as_ref().is_some_and(|callee| {
                        resolved_calls.iter().any(|resolved| {
                            resolved.source_file == source_file && resolved.callee == *callee
                        })
                    })
                {
                    retracted_domains.extend(b.domains.iter().map(|domain| domain.0.clone()));
                    return None;
                }
                let domains = b.domains.iter().map(|domain| domain.0.clone()).collect();
                Some(EffectiveBoundary {
                    occurrences: 1,
                    exemplar_paths: Vec::new(),
                    class: b.class,
                    reason: b.reason.clone(),
                    domains,
                    affected_resource: b.affected_resource.clone(),
                    detail: b.detail.clone(),
                    limit: b.limit.clone(),
                    provenance: local_steps(plan, &b.provenance, &source_file),
                    via_dispatch: None,
                })
            })
            .collect()
    } else {
        Vec::new()
    };

    let mut coverage: BTreeMap<String, CoverageLevel> = if include_plan {
        plan.coverage
            .0
            .iter()
            .map(|(d, claim)| (d.0.clone(), claim.level))
            .collect()
    } else {
        BTreeMap::new()
    };

    if include_plan {
        // A specialized effect whose resource is still a bare name says no more
        // than the plan's own unknown for that call, and the two describe one
        // occurrence: pushing it would report the call twice.
        for effect in specialized_root_effects.iter().filter(|effect| {
            !matches!(
                effect.resource,
                ResourceExpr::Unresolved { .. } | ResourceExpr::Parameter { .. }
            ) && !plan
                .effects
                .iter()
                .any(|plan_effect| same_direct_effect_value(plan_effect, effect))
        }) {
            let resource_expr = runtime_cwd
                .as_ref()
                .filter(|_| effect.realm == runtime_realm)
                .map(|cwd| bind_cwd(&effect.resource, cwd))
                .unwrap_or_else(|| effect.resource.clone());
            push(
                EffectiveEffect {
                    occurrences: 1,
                    paths: Vec::new(),
                    operation: effect.operation.0.clone(),
                    resource: display_resource_with_scope(&resource_expr),
                    family: family(effect.operation.domain(), &resource_expr),
                    realm: effect.realm.clone(),
                    execution: None,
                    modality: effect.modality,
                    request_assurance: effect.request_assurance,
                    attributes: effect.attributes.clone(),
                    condition: effect.condition.clone(),
                    destructive: effect.operation.is_destructive(),
                    provenance: vec![ProvenanceStep::Entrypoint {
                        file: source_file.clone(),
                        function: Some("main".to_string()),
                    }],
                    origin_file: source_file.clone(),
                    resource_expr,
                    assurance: None,
                    via_dispatch: None,
                },
                &mut effects,
            );
        }
    }

    let mut contributor_coverage = Vec::new();
    if include_plan {
        contributor_coverage.push((source_file.clone(), coverage.clone()));
    }

    // Cross-file composition: composed effects, boundaries, and coverage merge
    // into the same surface.
    if let Some(comp) = composition {
        for (effect, occurrence, occurrences) in comp.effect_evidence() {
            let origin_file = occurrence.map(|occurrence| occurrence.source_file.as_str());
            let path = occurrence.map(|occurrence| occurrence.path.as_slice());
            if include_plan
                && resolves_go_root
                && origin_file == Some(source_file.as_str())
                && matches!(effect.resource, ResourceExpr::Unresolved { .. })
                && let Some(count) = composed_effect_budget.get_mut(&effect_shape_key(&effect))
                && *count > 0
            {
                *count -= 1;
                continue;
            }
            if include_plan
                && resolves_go_root
                && origin_file == Some(source_file.as_str())
                && plan.effects.iter().any(|direct| {
                    same_direct_effect_value(direct, &effect)
                        && !matches!(direct.resource, ResourceExpr::Unresolved { .. })
                })
            {
                continue;
            }
            if include_plan
                && resolves_go_root
                && origin_file == Some(source_file.as_str())
                && !matches!(effect.resource, ResourceExpr::Unresolved { .. })
                && specialized_root_effects
                    .iter()
                    .any(|direct| same_direct_effect_value(direct, &effect))
            {
                continue;
            }
            let resource_expr = runtime_cwd
                .as_ref()
                .filter(|_| effect.realm == runtime_realm)
                .map(|cwd| bind_cwd(&effect.resource, cwd))
                .unwrap_or_else(|| effect.resource.clone());
            push(
                EffectiveEffect {
                    occurrences,
                    paths: path.into_iter().map(<[String]>::to_vec).collect(),
                    operation: effect.operation.0.clone(),
                    resource: display_resource_with_scope(&resource_expr),
                    family: family(effect.operation.domain(), &resource_expr),
                    realm: effect.realm.clone(),
                    execution: None,
                    modality: effect.modality,
                    request_assurance: effect.request_assurance,
                    attributes: effect.attributes.clone(),
                    condition: effect.condition.clone(),
                    destructive: effect.operation.is_destructive(),
                    provenance: if let Some(path) = path {
                        cross_file_steps(index, path)
                    } else {
                        vec![ProvenanceStep::Entrypoint {
                            file: source_file.clone(),
                            function: None,
                        }]
                    },
                    origin_file: origin_file.unwrap_or_default().to_string(),
                    resource_expr,
                    assurance: occurrence.map(|occurrence| occurrence.assurance),
                    via_dispatch: occurrence.and_then(|occurrence| occurrence.via_dispatch.clone()),
                },
                &mut effects,
            );
        }
        for cb in &comp.boundaries {
            // Modeled and known-inert calls do not hide facts in any domain,
            // so they are composition evidence rather than protocol boundaries.
            if cb.domains.is_empty() {
                continue;
            }
            // A composed boundary means opacity in its domains reached through
            // a cross-file call, so effective coverage there is not Full — else
            // the surface would claim completeness it does not have.
            for domain in &cb.domains {
                let entry = coverage
                    .entry(domain.clone())
                    .or_insert(CoverageLevel::Partial);
                *entry = worst(*entry, CoverageLevel::Partial);
            }
            // Keep the plan's source span when it already reports the same
            // call site or closed decorator gate in the entry file.
            if include_plan
                && (cb.reason == BoundaryReason::UNRESOLVED_DECORATOR
                    || (cb.reason == BoundaryReason::UNRESOLVED_CALL
                        && cb
                            .callee
                            .as_ref()
                            .is_some_and(|callee| callee.module == "ruby")))
                && cb.source_file.as_deref() == Some(source_file.as_str())
                && plan.boundaries.iter().any(|boundary| {
                    boundary.reason == cb.reason
                        && boundary.callee == cb.callee
                        && boundary.detail.as_deref() == Some(cb.detail.as_str())
                })
            {
                continue;
            }
            boundaries.push(EffectiveBoundary {
                occurrences: cb.occurrences,
                exemplar_paths: cb.exemplar_paths.clone(),
                class: cb.class,
                reason: cb.reason.clone(),
                domains: cb.domains.clone(),
                affected_resource: cb.affected_resource.clone(),
                detail: Some(cb.detail.clone()),
                limit: cb.limit.clone(),
                provenance: cross_file_steps(index, &cb.exemplar_paths[0]),
                via_dispatch: cb.via_dispatch.clone(),
            });
        }
        for (domain, level) in &comp.coverage {
            let entry = coverage.entry(domain.clone()).or_insert(*level);
            *entry = worst(*entry, *level);
        }
    }

    // A wrapper that launches another repository source program reaches
    // everything that program reaches: union the
    // launched surface through the launch edge, keeping each effect's origin
    // and prefixing the wrapper → program step so the explanation reads
    // wrapper → launched program → (include chain →) effect.
    let mut nested_exact_origins = std::collections::HashSet::new();
    for edge in index
        .launch_edges
        .iter()
        .filter(|e| e.wrapper == entrypoint_id && e.launch_entrypoint != entrypoint_id)
    {
        let launch_assurance = if edge.alternative {
            Assurance::Alternatives
        } else {
            Assurance::Exact
        };
        let from = match edge.line {
            Some(line) => format!("{source_file}:{line}"),
            None => source_file.clone(),
        };
        let step = ProvenanceStep::CrossFile {
            from: from.clone(),
            into: edge.launched.clone(),
        };
        let mut launch_steps = vec![step];
        launch_steps.extend(
            edge.process
                .as_ref()
                .map(|process| local_steps(plan, &process.provenance, &source_file))
                .unwrap_or_default(),
        );
        let nested_exact = plan.execution_graph.nodes.iter().any(|node| {
            node.boundary.is_none()
                && node.input.as_ref().is_some_and(|input| matches!(
                    &input.content,
                    effinterp_proto::ExecutionContent::Observed { digest }
                        if index.dependency_manifest.source_digest(edge.launched.trim_start_matches('/')) == Some(digest.as_str())
                ))
                && node
                    .selected_source_path()
                    .map(|origin| origin.trim_start_matches('/'))
                    == Some(edge.launched.trim_start_matches('/'))
        });
        if nested_exact {
            let add_provenance = nested_exact_origins.insert(edge.launched.clone());
            for effect in effects
                .iter_mut()
                .filter(|effect| effect.origin_file == edge.launched)
            {
                effect.assurance = weakest(effect.assurance, Some(launch_assurance));
                if add_provenance {
                    effect.provenance.splice(0..0, launch_steps.clone());
                }
            }
        }
        if launch_stack.contains(&edge.launch_entrypoint) {
            let domains: Vec<_> = effinterp_proto::DOMAINS
                .iter()
                .map(|domain| (*domain).to_string())
                .collect();
            for domain in &domains {
                let entry = coverage
                    .entry(domain.clone())
                    .or_insert(CoverageLevel::Partial);
                *entry = worst(*entry, CoverageLevel::Partial);
            }
            boundaries.push(EffectiveBoundary {
                occurrences: 1,
                exemplar_paths: Vec::new(),
                class: effinterp_proto::BoundaryClass::Unmodeled,
                reason: BoundaryReason::LAUNCH_CYCLE,
                domains,
                affected_resource: None,
                detail: Some(format!(
                    "local launch cycle at {entrypoint_id} -> {}",
                    edge.launched
                )),
                limit: None,
                provenance: launch_steps,
                via_dispatch: None,
            });
            continue;
        }
        let Some(launched) = effective_surface_inner(
            index,
            &edge.launch_entrypoint,
            true,
            !nested_exact,
            edge.process.as_ref().and_then(|process| {
                if let ResourceExpr::Concrete {
                    identity: ResourceIdentity::Process { cwd, .. },
                } = &process.resource
                {
                    cwd.as_deref().cloned()
                } else {
                    None
                }
            }),
            edge.process
                .as_ref()
                .map(|process| process.realm.clone())
                .unwrap_or_else(|| runtime_realm.clone()),
            launch_stack,
        ) else {
            let domains: Vec<_> = effinterp_proto::DOMAINS
                .iter()
                .map(|d| (*d).to_string())
                .collect();
            for domain in &domains {
                let level = coverage
                    .entry(domain.clone())
                    .or_insert(CoverageLevel::Partial);
                *level = worst(*level, CoverageLevel::Partial);
            }
            boundaries.push(EffectiveBoundary {
                occurrences: 1,
                exemplar_paths: Vec::new(),
                class: effinterp_proto::BoundaryClass::Unresolved,
                reason: BoundaryReason::UNCOMPOSED_SUBPROCESS,
                domains,
                affected_resource: edge
                    .process
                    .as_ref()
                    .map(|process| process.resource.clone()),
                detail: Some(format!(
                    "launched surface {} is unavailable",
                    edge.launch_entrypoint
                )),
                limit: None,
                provenance: launch_steps,
                via_dispatch: None,
            });
            continue;
        };
        contributor_coverage.push((launched.source_file.clone(), launched.coverage.clone()));
        for mut e in launched.effects {
            e.assurance = weakest(e.assurance, Some(launch_assurance));
            e.provenance.splice(0..0, launch_steps.clone());
            for path in &mut e.paths {
                path.insert(0, from.clone());
            }
            push(e, &mut effects);
        }
        for mut b in launched.boundaries {
            b.provenance.splice(0..0, launch_steps.clone());
            for path in &mut b.exemplar_paths {
                path.insert(0, from.clone());
            }
            boundaries.push(b);
        }
        for (domain, level) in &launched.coverage {
            let entry = coverage.entry(domain.clone()).or_insert(*level);
            *entry = worst(*entry, *level);
        }
    }

    for domain in retracted_domains {
        if boundaries
            .iter()
            .any(|boundary| boundary.domains.contains(&domain))
        {
            continue;
        }
        // A resolved effect says nothing about closure. Only explicit Full
        // claims from all composed contributors can discharge this domain.
        let claims: Vec<_> = composition
            .into_iter()
            .flat_map(|comp| &comp.coverage)
            .filter(|(claimed, _)| claimed == &domain)
            .map(|(_, level)| *level)
            .collect();
        if coverage.get(&domain) != Some(&CoverageLevel::None)
            && !claims.is_empty()
            && claims.iter().all(|level| *level == CoverageLevel::Full)
        {
            coverage.insert(domain, CoverageLevel::Full);
        }
    }

    for (source, claims) in contributor_coverage {
        let missing: Vec<_> = coverage
            .keys()
            .filter(|domain| !claims.contains_key(*domain))
            .cloned()
            .collect();
        if !missing.is_empty() {
            for domain in &missing {
                coverage.insert(domain.clone(), CoverageLevel::Partial);
            }
            boundaries.push(EffectiveBoundary {
                occurrences: 1,
                exemplar_paths: Vec::new(),
                class: effinterp_proto::BoundaryClass::Unmodeled,
                reason: BoundaryReason::FRONTEND_PARTIAL,
                domains: missing,
                affected_resource: None,
                detail: Some("contributing execution scope makes no coverage claim".to_string()),
                limit: None,
                provenance: vec![ProvenanceStep::Entrypoint {
                    file: source,
                    function: None,
                }],
                via_dispatch: None,
            });
        }
    }

    for (domain, level) in &coverage {
        if *level != CoverageLevel::Full && !boundaries.iter().any(|b| b.domains.contains(domain)) {
            boundaries.push(EffectiveBoundary {
                occurrences: 1,
                exemplar_paths: Vec::new(),
                class: effinterp_proto::BoundaryClass::Unmodeled,
                reason: BoundaryReason::FRONTEND_PARTIAL,
                domains: vec![domain.clone()],
                affected_resource: None,
                detail: Some("execution coverage has no complete contributing claim".to_string()),
                limit: None,
                provenance: vec![ProvenanceStep::Entrypoint {
                    file: source_file.clone(),
                    function: None,
                }],
                via_dispatch: None,
            });
        }
    }

    // Deterministic ordering independent of discovery/registry iteration.
    effects.sort_by(|a, b| {
        (
            &a.origin_file,
            a.request_assurance,
            &a.operation,
            &a.resource,
            realm_key(&a.realm),
            format!("{:?}", a.via_dispatch),
        )
            .cmp(&(
                &b.origin_file,
                b.request_assurance,
                &b.operation,
                &b.resource,
                realm_key(&b.realm),
                format!("{:?}", b.via_dispatch),
            ))
    });
    boundaries.sort_by(|a, b| {
        (
            &a.reason,
            &a.domains,
            serde_json::to_string(&a.affected_resource).expect("boundary resource serializes"),
            &a.detail,
            &a.limit,
            format!("{:?}", a.via_dispatch),
        )
            .cmp(&(
                &b.reason,
                &b.domains,
                serde_json::to_string(&b.affected_resource).expect("boundary resource serializes"),
                &b.detail,
                &b.limit,
                format!("{:?}", b.via_dispatch),
            ))
    });

    let popped = launch_stack.pop();
    debug_assert_eq!(popped.as_deref(), Some(entrypoint_id));
    Some(EffectiveSurface {
        entrypoint: entrypoint_id.to_string(),
        source_file,
        effects,
        boundaries,
        coverage,
    })
}

/// An effect's identity apart from its resource. A repository view states the
/// resource the plan could not, so the two descriptions of one occurrence agree
/// on everything else.
fn effect_shape_key(effect: &Effect) -> String {
    format!(
        "{}\u{1}{:?}\u{1}{:?}\u{1}{:?}\u{1}{:?}\u{1}{:?}",
        effect.operation.0,
        effect.attributes,
        effect.modality,
        effect.condition,
        effect.realm,
        effect.request_assurance,
    )
}

/// One occurrence's value, without the conclusions two views may differ on:
/// modality is what the views disagree about, and the plan's own branch atom
/// has no counterpart in a summary occurrence.
fn occurrence_value_key(effect: &Effect) -> String {
    format!(
        "{}\u{1}{}\u{1}{}\u{1}{}\u{1}{:?}",
        effect.operation.0,
        serde_json::to_string(&effect.resource).expect("resource expression serialization"),
        attributes_key(&effect.attributes),
        realm_key(&effect.realm),
        effect.request_assurance,
    )
}

/// Whether a resource expression names no resource yet: an outright unknown, or
/// a name the analysis that produced it could not bind. The single-file plan
/// renders both as an unknown of the domain's family.
fn is_placeholder(resource: &ResourceExpr) -> bool {
    match resource {
        ResourceExpr::Unresolved { .. } | ResourceExpr::Parameter { .. } => true,
        ResourceExpr::Join { parts } => parts.iter().any(is_placeholder),
        ResourceExpr::Union { alternatives } => alternatives.iter().any(is_placeholder),
        ResourceExpr::Property { base, .. } => is_placeholder(base),
        _ => false,
    }
}

/// Whether two effects describe the same occurrence. Modality is a conclusion
/// about an occurrence, not part of its identity: two views of one interaction
/// that reached different necessity proofs are still one occurrence, and must
/// not both reach the surface.
fn same_effect_value(left: &Effect, right: &Effect) -> bool {
    left.operation == right.operation
        && left.request_assurance == right.request_assurance
        && left.resource == right.resource
        && left.attributes == right.attributes
        && left.condition == right.condition
        && left.realm == right.realm
}

fn same_direct_effect_value(left: &Effect, right: &Effect) -> bool {
    if same_effect_value(left, right) {
        return true;
    }
    left.operation == right.operation
        && left.request_assurance == right.request_assurance
        && left.attributes == right.attributes
        && left.condition == right.condition
        && left.realm == right.realm
        && matches!(
            (&left.resource, &right.resource),
            (
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::Process {
                        executable: left_executable,
                        path: left_path,
                        argv: left_argv,
                        cwd: left_cwd,
                    }
                },
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::Process {
                        executable: right_executable,
                        path: right_path,
                        argv: right_argv,
                        cwd: right_cwd,
                    }
                }
            ) if left_executable == right_executable
                && left_path == right_path
                && left_argv == right_argv
                // Only one view of a spawn knows the working directory it
                // inherits, so an absent cwd matches any. Two stated and
                // different directories are two different spawns.
                && (left_cwd.is_none() || right_cwd.is_none() || left_cwd == right_cwd)
        )
}

fn bind_cwd(expr: &ResourceExpr, cwd: &ResourceExpr) -> ResourceExpr {
    match expr {
        ResourceExpr::Parameter { name } if name == "cwd" => cwd.clone(),
        ResourceExpr::Join { parts } => effinterp_proto::normalize_resource(
            ResourceExpr::Join {
                parts: parts.iter().map(|part| bind_cwd(part, cwd)).collect(),
            },
            effinterp_proto::PathPlatform::Posix,
        ),
        ResourceExpr::Union { alternatives } => ResourceExpr::Union {
            alternatives: alternatives
                .iter()
                .map(|alternative| bind_cwd(alternative, cwd))
                .collect(),
        },
        ResourceExpr::Property { base, name } => ResourceExpr::Property {
            base: Box::new(bind_cwd(base, cwd)),
            name: name.clone(),
        },
        ResourceExpr::Concrete {
            identity:
                ResourceIdentity::Process {
                    executable,
                    path,
                    argv,
                    cwd: process_cwd,
                },
        } => ResourceExpr::Concrete {
            identity: ResourceIdentity::Process {
                executable: executable.clone(),
                path: path.clone(),
                argv: argv
                    .iter()
                    .map(|argument| bind_cwd(argument, cwd))
                    .collect(),
                cwd: process_cwd
                    .as_deref()
                    .map(|process_cwd| Box::new(bind_cwd(process_cwd, cwd))),
            },
        },
        _ => expr.clone(),
    }
}

fn weakest(a: Option<Assurance>, b: Option<Assurance>) -> Option<Assurance> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

pub(crate) fn worst(a: CoverageLevel, b: CoverageLevel) -> CoverageLevel {
    use CoverageLevel::*;
    match (a, b) {
        (None, _) | (_, None) => None,
        (Partial, _) | (_, Partial) => Partial,
        (Full, Full) => Full,
    }
}

/// The repo file a direct effect originates in: the innermost nested
/// invocation on its provenance chain that carries a file origin (the PHP
/// include graph and `php script.php` record these), else the entrypoint file
/// itself. Origins are repo-rooted; the leading slash is trimmed to match
/// repo-relative evidence paths.
fn direct_origin(
    plan: &Plan,
    execution: effinterp_proto::ExecutionNodeRef,
    roots: &[ProvenanceRef],
    source_file: &str,
) -> String {
    let mut seen = std::collections::HashSet::new();
    let mut work = roots.to_vec();
    while let Some(reference) = work.pop() {
        let Some(node) = plan.provenance.get(reference.0 as usize) else {
            continue;
        };
        if !seen.insert(reference) {
            continue;
        }
        if let ProvenanceKind::Execution { node: execution } = node.kind
            && let Some(origin) = plan
                .execution_graph
                .nodes
                .get(execution as usize)
                .and_then(|node| node.selected_source_path())
        {
            return origin.trim_start_matches('/').to_string();
        }
        // The first antecedent is the primary code site; reverse the push so
        // the LIFO walk visits it before value-flow evidence.
        work.extend(node.antecedents.iter().rev().copied());
    }
    plan.execution_graph
        .nodes
        .get(execution.0 as usize)
        .and_then(|node| node.selected_source_path())
        .map(|origin| origin.trim_start_matches('/').to_string())
        .unwrap_or_else(|| source_file.to_string())
}

pub(crate) fn local_steps(
    plan: &Plan,
    roots: &[effinterp_proto::ProvenanceRef],
    file: &str,
) -> Vec<ProvenanceStep> {
    fn walk(
        plan: &Plan,
        reference: ProvenanceRef,
        file: &str,
        visited: &mut [bool],
        out: &mut Vec<ProvenanceStep>,
    ) {
        let index = reference.0 as usize;
        if index >= plan.provenance.len() || visited[index] {
            return;
        }
        visited[index] = true;
        let node = &plan.provenance[index];
        for antecedent in &node.antecedents {
            walk(plan, *antecedent, file, visited, out);
        }
        out.push(match &node.kind {
            ProvenanceKind::SourceInput { path, digest } => ProvenanceStep::SourceInput {
                path: path.clone(),
                digest: digest.clone(),
            },
            ProvenanceKind::HostContext { name } => {
                ProvenanceStep::HostContext { name: name.clone() }
            }
            ProvenanceKind::SourceSpan { start, end } => ProvenanceStep::SourceSpan {
                file: file.to_string(),
                start: *start,
                end: *end,
            },
            ProvenanceKind::Argument { index } => ProvenanceStep::Argument {
                file: file.to_string(),
                index: *index,
            },
            ProvenanceKind::ToolArgument { name } => ProvenanceStep::ToolArgument {
                file: file.to_string(),
                name: name.clone(),
            },
            ProvenanceKind::ModelApplication { model } => {
                let (declaration_id, declaration_digest) = model
                    .rsplit_once("#blake3:")
                    .map(|(id, digest)| (id.to_string(), Some(digest.to_string())))
                    .unwrap_or_else(|| (model.clone(), None));
                ProvenanceStep::ModelApplication {
                    file: file.to_string(),
                    declaration_id,
                    declaration_digest,
                }
            }
            ProvenanceKind::HostObservation { query, outcome } => {
                let (effinterp_proto::ObservationQuery::Path { path }
                | effinterp_proto::ObservationQuery::Listing { path, .. }) = query;
                ProvenanceStep::HostObservation {
                    query: path.clone(),
                    answer: match outcome {
                        effinterp_proto::ObservationOutcome::Refused(refusal) => {
                            format!("unavailable ({})", refusal.code())
                        }
                        effinterp_proto::ObservationOutcome::Path(fact) => {
                            match fact.followed.known() {
                                Some(target) => target.path.clone(),
                                None => "identity unavailable".to_string(),
                            }
                        }
                        effinterp_proto::ObservationOutcome::Listing(fact) => {
                            format!("{} entries", fact.entries.len())
                        }
                    },
                }
            }
            ProvenanceKind::Execution { node } => ProvenanceStep::Execution {
                file: file.to_string(),
                node: *node,
                origin: plan
                    .execution_graph
                    .nodes
                    .get(*node as usize)
                    .and_then(|execution| execution.selected_source_path().map(str::to_string)),
            },
        });
    }

    let mut out = Vec::new();
    let mut visited = vec![false; plan.provenance.len()];
    for root in roots {
        walk(plan, *root, file, &mut visited, &mut out);
    }
    out
}

/// Convert a composed path (`["app.py", "util.py:wipe", ...]`) into cross-file
/// steps between successive nodes.
pub(crate) fn cross_file_steps(index: &RepoIndex, path: &[String]) -> Vec<ProvenanceStep> {
    if path.len() < 2 {
        return path
            .iter()
            .map(|p| ProvenanceStep::Entrypoint {
                file: split_source_label(index, p).0.to_string(),
                function: split_source_label(index, p).1.map(str::to_string),
            })
            .collect();
    }
    path.windows(2)
        .map(|w| ProvenanceStep::CrossFile {
            from: w[0].clone(),
            into: w[1].clone(),
        })
        .collect()
}

/// Resolve composed labels against admitted paths so literal colons stay in filenames.
pub(crate) fn split_source_label<'a>(
    index: &RepoIndex,
    label: &'a str,
) -> (&'a str, Option<&'a str>) {
    let label = label.trim_start_matches('/');
    if index.dependency_manifest.source_digest(label).is_some() {
        return (label, None);
    }
    for (position, _) in label.rmatch_indices(':') {
        let file = &label[..position];
        if index.dependency_manifest.source_digest(file).is_some() {
            return (file, Some(&label[position + 1..]));
        }
    }
    (label, None)
}
