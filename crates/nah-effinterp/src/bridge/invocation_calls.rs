//! Which calls the invocation makes, which engine boundaries and missing
//! translations leave gaps in that understanding, and the coverage claims
//! the evidence publishes from them.

use effinterp_proto::{ExecutionAssurance, ProvenanceKind, ProvenanceRef, ResourceExpr, Subject};
use nah_proto::effects;
use nah_proto::effects::Knowledge::{Known, Unknown};
use nah_proto::labels::hidden_characters::has_hidden_characters;
use nah_proto::tool::ToolCallInput;
use std::collections::{BTreeMap, BTreeSet};

use super::input_selection::command_text;
use super::resource_projection::convert_domain;
use super::{
    ShippedGuardPolicy,
    fact_projection::{effect_attr_bool, effect_attr_text},
};

/// Whether a boundary states what the environment does once the invocation
/// runs rather than missing understanding of the invocation. The engine
/// scopes each boundary where it raises it, and plan validation admits
/// environment scope only for a registered environmental reason on an
/// unmodeled or unresolved boundary that no limit cut short.
fn environment_boundary(boundary: &effinterp_proto::Boundary) -> bool {
    boundary.scope == effinterp_proto::BoundaryScope::Environment
}

/// Whether an unresolved resource belongs to the environment: a configured
/// endpoint, or the unenumerated paths a package's lifecycle scripts reach.
/// The engine ties the effect to an environmental boundary in that domain.
/// Nah already excludes environmental boundaries from invocation gaps, so a
/// translation gap for the same resource reports it twice. A resource left
/// unresolved by a variable, missing source or unmodeled grammar still has a
/// translation gap.
pub(super) fn environmental_resource(
    view: &crate::plan_view::PlanView<'_>,
    effect: &effinterp_proto::Effect,
) -> bool {
    let effinterp_proto::ResourceExpr::Unresolved { family } = &effect.resource else {
        return false;
    };
    view.boundaries_in_domain(&family.0).any(|boundary| {
        (family.0 == "network"
            || family.0 == "filesystem"
                && boundary.reason == effinterp_proto::BoundaryReason::PACKAGE_SCRIPTS)
            && environment_boundary(boundary)
            && boundary
                .provenance
                .iter()
                .any(|root| effect.provenance.contains(root))
    })
}

/// Nah's public gap code for an engine boundary reason: the reason in
/// kebab-case, so a code in a record or `corpus/TRIAGE.md` greps back to its
/// reason in `effinterp_proto::BOUNDARY_REASONS`. A plan carrying a reason
/// outside that registry is refused rather than published under a code
/// nothing names.
fn boundary_gap_code(reason: &effinterp_proto::BoundaryReason) -> Option<String> {
    reason
        .spec()
        .map(|spec| spec.reason.as_str().replace('_', "-"))
}

/// The public graph's calls, the invocation gaps the engine's boundaries
/// leave, and the gaps an unavailable observation leaves.
pub(super) fn project_invocation_calls(
    root: &ToolCallInput,
    view: &crate::plan_view::PlanView<'_>,
) -> Result<effects::EffectGraph, effects::EvidenceError> {
    use effects::*;
    let plan = view.plan();
    let mut graph = EffectGraph {
        calls: vec![],
        resources: vec![],
        facts: vec![],
        occurrences: vec![],
        relations: vec![],
        conditions: vec![],
        coverage: vec![],
        gaps: vec![],
        causality: if plan.causality.graph.is_some() {
            CausalAvailability::Available
        } else {
            CausalAvailability::Unavailable
        },
    };
    // An environmental boundary is what the environment does once the
    // invocation runs, not missing understanding of the invocation, so it is
    // no invocation gap. The engine claim it leaves open stays open.
    let environmental = |index: usize| environment_boundary(&plan.boundaries[index]);
    let mut visible_nested = vec![false; plan.execution_graph.nodes.len()];
    for index in 1..plan.execution_graph.nodes.len() {
        visible_nested[index] = visible_execution_node(view, index, &visible_nested);
    }
    for (index, node) in view.executions() {
        let id = CallId(index as u32);
        let (kind, identity, cwd) = match &node.subject {
            Subject::Shell { cwd, .. } => (InvocationKind::Shell, Unknown, cwd),
            Subject::Exec { cwd, .. } => (
                InvocationKind::Argv,
                match node.argv.first() {
                    Some(effinterp_proto::ResourceExpr::Literal { value }) => Known(value.clone()),
                    _ => Unknown,
                },
                cwd,
            ),
            Subject::Source { language, cwd, .. } => {
                (InvocationKind::VisibleCode, Known(language.clone()), cwd)
            }
            Subject::ToolCall { call, cwd, .. } => {
                (InvocationKind::Native, Known(call.name().to_owned()), cwd)
            }
            Subject::Sql { .. } => (InvocationKind::VisibleCode, Known("sql".into()), &None),
        };
        let visible = index == 0 || visible_nested[index];
        let ordinal = if visible {
            Some((index as u32) % 64)
        } else {
            None
        };
        graph.calls.push(EffectCall {
            // A visible node's argv words are literals the engine folded from
            // the request's own invocation text, so publishing them to a custom
            // guard discloses nothing the raw request did not already carry. A
            // word resolved from a private channel (an environment value, a
            // parameter, bytes read from a file) stays a non-literal expression
            // and is never folded here, so it withholds the whole argv. A
            // non-visible node likewise withholds it: its provenance reaches
            // outside the request text.
            arguments: if kind == InvocationKind::Argv && visible {
                node.argv
                    .iter()
                    .map(|argument| match argument {
                        effinterp_proto::ResourceExpr::Literal { value } => Some(value.clone()),
                        _ => None,
                    })
                    .collect::<Option<Vec<_>>>()
                    .map_or(Unknown, Known)
            } else {
                Unknown
            },
            id,
            parent: view
                .parent_edge(effinterp_proto::ExecutionNodeRef(id.0))
                .map(|edge| CallId(edge.from.0)),
            kind,
            identity: if index == 0 {
                Known(root.tool().to_owned())
            } else {
                identity
            },
            input: (index == 0).then(|| root.clone()),
            hidden_characters: index == 0
                && command_text(&plan.subject).is_some_and(has_hidden_characters),
            cwd: cwd
                .as_ref()
                .and_then(|cwd| {
                    nah_proto::ctx::AbsolutePath::new(view.authority().platform(), cwd).ok()
                })
                .map_or(Unknown, Known),
            payload_group: if visible {
                Known(PayloadGroupId(index as u32 / 64))
            } else {
                Unknown
            },
            visibility_ordinal: ordinal.map_or(Unknown, Known),
            coverage: if !plan.coverage.0.is_empty()
                && plan
                    .coverage
                    .0
                    .values()
                    .all(|claim| claim.level == effinterp_proto::CoverageLevel::Full)
            {
                nah_proto::action::Coverage::Full
            } else {
                nah_proto::action::Coverage::Partial
            },
        });
    }
    if graph.calls.is_empty() {
        return Err(EvidenceError::InvalidPayload);
    }
    for (index, boundary) in view.boundaries() {
        if environmental(index) {
            continue;
        }
        graph.gaps.push(EffectGap {
            id: GapId(index as u32),
            phase: GapPhase::Analysis,
            category: if boundary.limit.is_some() {
                GapCategory::Limit
            } else {
                GapCategory::Unmodeled
            },
            call: CallId(0),
            domain: None,
            code: boundary_gap_code(&boundary.reason).ok_or(EvidenceError::InvalidPayload)?,
        });
    }
    let mut unavailable_effect_paths = BTreeSet::new();
    for index in view.effect_indices_family("filesystem") {
        let effect = &plan.effects[index];
        let annotation = view.annotation(index);
        let Some((path, _)) = crate::observe::observation_bound(&effect.resource) else {
            continue;
        };
        if view.path_unavailable(&path)
            && matches!(
                annotation.path,
                Some(nah_proto::effect_annotation::PathLabel::Unresolved)
            )
            && unavailable_effect_paths.insert((effect.execution.0, path))
        {
            add_gap(
                &mut graph,
                CallId(effect.execution.0),
                Some(Domain::Filesystem),
                GapPhase::Observation,
                "observation-unavailable",
            );
        }
    }
    Ok(graph)
}

/// Name the gap an effect leaves when no typed payload translates it and
/// nothing beside it already states what it does.
pub(super) fn add_untranslated_effect_gap(
    view: &crate::plan_view::PlanView<'_>,
    graph: &mut effects::EffectGraph,
    effect: &effinterp_proto::Effect,
    call: effects::CallId,
    guards: &ShippedGuardPolicy<'_>,
) {
    use effects::*;
    let attr_bool = |key: &str| effect_attr_bool(effect, key);
    let attr_text = |key: &str| effect_attr_text(effect, key);
    // A shipped guard that owns an effect's missing-fact gap names its own
    // gap when its query is indeterminate.
    let declarative_owner = |effect: &effinterp_proto::Effect| guards.owns_effect_gap(effect);
    // An audited request on the same call whose registered outcome is this
    // operation already carries the typed fact, so the plain effect beside
    // it is redundant evidence rather than a translation the bridge is
    // missing.
    let audited = effinterp_proto::OPERATIONS
        .iter()
        .filter(|request| request.outcomes.contains(&effect.operation.as_str()))
        .any(|request| {
            view.effects_exact(request.name)
                .any(|other| other.execution == effect.execution)
        });
    // Actions the engine states in full without qualifiers. A Git
    // configuration write already names both the operation and
    // repository; Nah has no narrower typed fact or guard decision
    // for it. Restarting or
    // starting a unit names the manager and the unit, setting the
    // clock names the host, and a kernel trigger names the file
    // whose write the bridge already translates beside it. The
    // engine emits each only for the action it is carrying out and
    // states no qualifier next to it the way it does for a stop or
    // an enable. Nah has no typed payload for them because no
    // guard decides on them: a restart does not leave a service
    // stopped, and a start leaves nothing lost. Nothing is
    // unavailable, so the effect is published without a gap. A
    // qualifier the engine adds later brings the gap back, which is
    // what a new modeled field should do.
    let complete_without_qualifiers = effect.operation.as_str() == "git.ref_update"
        && attr_bool("delete") != Known(true)
        || effect.attributes.is_empty()
            && matches!(
                effect.operation.as_str(),
                "system.service_restart"
                    | "system.service_start"
                    | "system.clock_set"
                    | "system.kernel_trigger"
                    | "git.config_write"
            )
        // Archiving a 1Password item keeps it intact and restorable; the
        // engine states the move in full, and no guard decides on it.
        || effect.operation.as_str() == "credential.write" && attr_bool("archive") == Known(true);
    // The destruction arms above take a stated dry run out of the
    // typed payload on purpose: a rehearsal destroys nothing, so
    // it must not reach the volume and device guards as a
    // destruction. That decision reads the engine's mode rather
    // than missing it, and the engine named the target kind beside
    // it, so the gap this arm would otherwise raise claims two
    // things are unavailable that the bridge has in hand.
    let stated_rehearsal = (effect.operation.as_str() == "system.storage_destroy"
        || effect.operation.as_str() == "git.remote_sync")
        && attr_bool("dry_run") == Known(true);
    let complete_recovery_summary = effect.operation.as_str() == "git.recovery_destroy"
        && (attr_bool("stash") == Known(true)
            || attr_bool("reflog") == Known(true)
                && attr_text("action") == Known("expire".into())
                && matches!(
                    attr_text("scope"),
                    Known(ref scope) if scope == "whole" || scope == "named"
                ));
    if !audited
        && !complete_without_qualifiers
        && !stated_rehearsal
        && !complete_recovery_summary
        && !declarative_owner(effect)
    {
        add_gap(
            graph,
            call,
            Some(convert_domain(effect.operation.domain())),
            GapPhase::Translation,
            match effect.operation.as_str() {
                "system.storage_destroy" => "storage-target-kind-and-mode-unavailable",
                "container.resource.delete" => "kubernetes-scope-and-selection-unavailable",
                "cloud.resource.delete" => "infrastructure-destruction-mode-unavailable",
                "git.remote_sync" => "git-push-destination-and-lease-details-unavailable",
                "git.worktree_discard" => "git-discard-mode-and-selection-unavailable",
                "git.history_rewrite" => "git-history-active-mode-unavailable",
                "git.recovery_destroy" => "git-recovery-selection-unavailable",
                "git.ref_update" => "git-ref-active-selection-unavailable",
                _ => "semantic-fields-unavailable",
            },
        );
    }
}

/// Name the access semantics each fact still leaves unknown, and return
/// which unknown each of those gaps records, by gap index.
pub(super) fn add_access_semantics_gaps(
    graph: &mut effects::EffectGraph,
    stated_non_content_access: &BTreeSet<effects::FactId>,
) -> BTreeMap<usize, (effects::UnknownKind, Option<effects::ResourceId>)> {
    use effects::*;
    // Access semantics the evidence publishes, after the causal passes have
    // named the purpose of a consumed read and the direction of an answered
    // request. The ports these payloads leave empty are not missing evidence:
    // they are the occurrences bound to the fact.
    let partial_access = graph
        .facts
        .iter()
        .filter_map(|fact| {
            let (domain, kind, resource) = match &fact.payload {
                // Purpose distinguishes disclosure from incidental access for
                // reads and moves. A concrete write can still prove a
                // protected-target match without any disclosure purpose.
                FactPayload::FilesystemAccess {
                    operation: FilesystemOperation::Read | FilesystemOperation::Move,
                    purpose,
                    target,
                    ..
                } => (*purpose == AccessPurpose::Unknown
                    && !stated_non_content_access.contains(&fact.id))
                .then_some((Domain::Filesystem, UnknownKind::Purpose, Some(*target))),
                FactPayload::FilesystemAccess {
                    operation: FilesystemOperation::Write,
                    purpose,
                    target,
                    ..
                } => {
                    let target = &graph.resources[target.0 as usize];
                    let concrete = target.selection == Selection::Exact
                        && target.identity.kind == ResourceKind::HostPath
                        && matches!(
                            &target.identity.details,
                            Known(ResourceDetails::Path { lexical: Known(_) })
                        );
                    (*purpose == AccessPurpose::Unknown
                        && !concrete
                        && !stated_non_content_access.contains(&fact.id))
                    .then_some((Domain::Filesystem, UnknownKind::Purpose, Some(target.id)))
                }
                FactPayload::EnvironmentAccess {
                    names: EnvironmentSelection::Unknown,
                    ..
                } => Some((Domain::Environment, UnknownKind::Selector, None)),
                FactPayload::EnvironmentAccess { purpose, .. } => (*purpose
                    == AccessPurpose::Unknown)
                    .then_some((Domain::Environment, UnknownKind::Purpose, None)),
                // Opening or accepting a connection moves no payload, so it
                // has no transfer direction to be missing; the transfers the
                // engine states over that connection carry their own.
                FactPayload::NetworkAccess {
                    direction,
                    target,
                    operation:
                        NetworkOperation::Request
                        | NetworkOperation::Upload
                        | NetworkOperation::Download
                        | NetworkOperation::Transfer,
                    ..
                } => matches!(direction, Unknown).then_some((
                    Domain::Network,
                    UnknownKind::CausalRoute,
                    Some(*target),
                )),
                _ => None,
            }?;
            Some((fact.call, domain, kind, resource))
        })
        .collect::<Vec<_>>();
    // The gaps added before this point each name one unknown by their code;
    // this one names a different unknown per fact, so record it as it is added.
    let mut access_unknowns = BTreeMap::new();
    for (call, domain, kind, resource) in partial_access {
        access_unknowns.insert(graph.gaps.len(), (kind, resource));
        add_gap(
            graph,
            call,
            Some(domain),
            GapPhase::Translation,
            "access-semantics-partial",
        );
    }
    access_unknowns
}

/// Project the engine's coverage claims, with Nah's own gaps, onto the
/// public graph, and return the attribution the public aggregate reads.
pub(super) fn project_coverage_attribution(
    view: &crate::plan_view::PlanView<'_>,
    graph: &mut effects::EffectGraph,
    access_unknowns: &BTreeMap<usize, (effects::UnknownKind, Option<effects::ResourceId>)>,
) -> effects::CoverageAttribution {
    use effects::*;
    let plan = view.plan();
    let environmental = |index: usize| environment_boundary(&plan.boundaries[index]);
    for (domain, claim) in plan
        .coverage
        .0
        .iter()
        .map(|(domain, claim)| (convert_domain(&domain.0), claim))
        .chain([(Domain::Causal, &plan.causality.coverage)])
    {
        let mut gaps = claim
            .gaps
            .iter()
            .filter(|id| !environmental(id.0 as usize))
            .map(|id| GapId(id.0))
            .collect::<Vec<_>>();
        gaps.extend(
            graph
                .gaps
                .iter()
                .filter(|gap| {
                    matches!(gap.phase, GapPhase::Observation | GapPhase::Translation)
                        && (gap.domain.is_none() || gap.domain == Some(domain))
                })
                .map(|gap| gap.id),
        );
        gaps.sort();
        gaps.dedup();
        let level = match claim.level {
            effinterp_proto::CoverageLevel::Full if gaps.is_empty() => ClaimLevel::Full,
            effinterp_proto::CoverageLevel::None => ClaimLevel::None,
            _ => ClaimLevel::Partial,
        };
        if let Some(existing) = graph.coverage.iter_mut().find(|c| c.domain == domain) {
            existing.gaps.extend(gaps);
            existing.level = ClaimLevel::Partial;
        } else {
            graph.coverage.push(CoverageClaim {
                call: CallId(0),
                domain,
                level,
                gaps,
            });
        }
    }
    // The public aggregate reads these facts, not the claims projected above.
    let engine_claim = |claim: &effinterp_proto::CoverageClaim| EngineClaim {
        level: match claim.level {
            effinterp_proto::CoverageLevel::Full => ClaimLevel::Full,
            effinterp_proto::CoverageLevel::Partial => ClaimLevel::Partial,
            effinterp_proto::CoverageLevel::None => ClaimLevel::None,
        },
        boundaries: claim.gaps.iter().map(|id| BoundaryId(id.0)).collect(),
    };
    CoverageAttribution {
        engine: plan
            .coverage
            .0
            .iter()
            .map(|(domain, claim)| (domain.0.clone(), engine_claim(claim)))
            .collect(),
        causal: engine_claim(&plan.causality.coverage),
        boundaries: plan
            .boundaries
            .iter()
            .enumerate()
            .map(|(index, boundary)| EngineBoundary {
                reason: boundary.reason.as_str().to_owned(),
                environmental: environmental(index),
            })
            .collect(),
        unknowns: graph
            .gaps
            .iter()
            .enumerate()
            .filter(|(_, gap)| gap.phase != GapPhase::Analysis)
            .map(|(index, gap)| {
                let (kind, resource) = access_unknowns
                    .get(&index)
                    .copied()
                    .unwrap_or((unknown_kind(gap), None));
                InvocationUnknown {
                    gap: gap.id,
                    kind,
                    resource,
                }
            })
            .collect(),
    }
}

/// What a gap Nah added leaves unknown, read from its phase and code.
fn unknown_kind(gap: &effects::EffectGap) -> effects::UnknownKind {
    use effects::UnknownKind::*;
    match (gap.phase, gap.code.as_str()) {
        (effects::GapPhase::Observation, "descendant-scan-incomplete") => Descendants,
        (effects::GapPhase::Observation, _) => Realpath,
        (effects::GapPhase::Projection, _) => Visibility,
        (
            _,
            "resource-components-unavailable"
            | "move-destination-unavailable"
            | "network-delete-resource-kind-unavailable"
            | "git-recovery-selection-unavailable",
        ) => Selector,
        (
            _,
            "causal-detail-unavailable"
            | "effect-occurrence-binding-unavailable"
            | "condition-widened",
        ) => CausalRoute,
        // The remaining translation gaps name request controls and modes the
        // payload needs, sometimes together with the selection they qualify.
        _ => ActionControl,
    }
}

fn visible_execution_node(
    view: &crate::plan_view::PlanView<'_>,
    index: usize,
    visible: &[bool],
) -> bool {
    let plan = view.plan();
    if !matches!(plan.subject, Subject::Shell { .. }) {
        return false;
    }
    let node = &plan.execution_graph.nodes[index];
    if node.assurance != ExecutionAssurance::Exact {
        return false;
    }
    if matches!(
        node.subject,
        Subject::Source { .. } | Subject::ToolCall { .. } | Subject::Sql { .. }
    ) {
        return false;
    }
    if matches!(node.subject, Subject::Exec { .. })
        && !node
            .argv
            .iter()
            .all(|argument| matches!(argument, ResourceExpr::Literal { .. }))
    {
        return false;
    }
    let Some(edge) = view.parent_edge(effinterp_proto::ExecutionNodeRef(index as u32)) else {
        return false;
    };
    if edge.from.0 as usize != 0 && !visible[edge.from.0 as usize] {
        return false;
    }
    if !matches!(
        edge.kind,
        effinterp_proto::ExecutionEdgeKind::Launch
            | effinterp_proto::ExecutionEdgeKind::Interpreter
            | effinterp_proto::ExecutionEdgeKind::Script
            | effinterp_proto::ExecutionEdgeKind::ToolModel
            | effinterp_proto::ExecutionEdgeKind::PackageScript
    ) {
        return false;
    }
    provenance_is_visible(plan, node.evidence.iter().chain(edge.evidence.iter()))
}

fn provenance_is_visible<'a>(
    plan: &effinterp_proto::Plan,
    mut roots: impl Iterator<Item = &'a ProvenanceRef>,
) -> bool {
    fn visit(plan: &effinterp_proto::Plan, reference: ProvenanceRef, seen: &mut Vec<bool>) -> bool {
        let index = reference.0 as usize;
        if seen.get(index).copied().unwrap_or(false) {
            return true;
        }
        let Some(node) = plan.provenance.get(index) else {
            return false;
        };
        if let Some(slot) = seen.get_mut(index) {
            *slot = true;
        }
        if !matches!(
            node.kind,
            ProvenanceKind::SourceSpan { .. }
                | ProvenanceKind::Argument { .. }
                | ProvenanceKind::ToolArgument { .. }
                | ProvenanceKind::Execution { .. }
                | ProvenanceKind::ModelApplication { .. }
        ) {
            return false;
        }
        node.antecedents
            .iter()
            .all(|antecedent| visit(plan, *antecedent, seen))
    }

    let mut seen = vec![false; plan.provenance.len()];
    roots.all(|reference| visit(plan, *reference, &mut seen))
}

/// Add a gap Nah names, numbered after every gap already in the graph.
pub(super) fn add_gap(
    graph: &mut effects::EffectGraph,
    call: effects::CallId,
    domain: Option<effects::Domain>,
    phase: effects::GapPhase,
    code: &str,
) {
    graph.gaps.push(effects::EffectGap {
        // Boundary gaps are numbered by their boundary, and an informational
        // one leaves its number unused, so continue past the highest.
        id: effects::GapId(graph.gaps.iter().map(|gap| gap.id.0 + 1).max().unwrap_or(0)),
        phase,
        category: effects::GapCategory::Unmodeled,
        call,
        domain,
        code: code.into(),
    });
}
