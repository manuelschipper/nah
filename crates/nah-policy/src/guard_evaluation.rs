//! Shipped guard evaluation: runs every shipped guard definition's clauses
//! over one engine plan with the matcher, then applies the clause's
//! qualifiers and host rule, and returns the typed matches and the gaps
//! indeterminate guards name.
//!
//! The matcher answers each clause's query. What the query language cannot
//! state stays here as typed Rust, one qualifier per predicate, each saying
//! why a query cannot state it. The bridge supplies labels, per-effect reach
//! and observed paths through [`GuardHostFacts`]; this module does no I/O.

use std::collections::{BTreeMap, BTreeSet};

use effinterp_matcher::{
    Absence, Evaluator, LabelProvider, Outcome, QueryLimits, Selector, Truth, Witness, success_path,
};
use nah_proto::effects::{CallId, EvidenceError, Reach};
use nah_proto::effinterp_proto::{
    ArtifactEcosystem, AttrValue, CausalAssurance, CausalEdge, CausalReason, Effect, EffectId,
    ExecutionAssurance, OccurrenceId, OccurrenceKind, OccurrenceNode, Plan, Port, RequestAssurance,
    ResourceExpr, ResourceIdentity,
};
use nah_proto::guard_host::{
    GuardHostFacts, ReachedHostPath, ShippedGuardGap, ShippedGuardMatches,
};

use crate::filesystem_queries::{HostRule, ReachEndpoint, ReachedPath};
use crate::registry::{GuardDefinition, shipped_guard_definitions};

/// A predicate a guard clause applies to an effect after its query matched,
/// for what the matcher's query language cannot state.
#[derive(Clone, Debug)]
pub enum QueryQualifier {
    GitMetadata,
    DirectPathRestoration,
    GithubRelease,
    /// The effect's condition must not be proven impossible within the
    /// invocation, the rule filesystem guards apply through
    /// [`HostRule::feasible_condition`]: a fallback after `||`, a branch body,
    /// a loop body or a condition too large to decide still reaches the
    /// effect, while a position proven unreachable does not.
    FeasibleCondition,
}

/// The shipped guard registry, built and validated once: the definitions
/// `shipped_guard_definitions` returns, and their ids in name order.
pub struct ShippedGuards {
    definitions: Vec<GuardDefinition>,
    ids: Vec<&'static str>,
    /// Every selector of every clause, with whether its definition names a
    /// gap: what `gap_owners` returns.
    gap_owners: Vec<(bool, Selector)>,
}

impl Default for ShippedGuards {
    fn default() -> Self {
        Self::new()
    }
}

impl ShippedGuards {
    pub fn new() -> Self {
        let definitions = shipped_guard_definitions();
        let mut ids = definitions
            .iter()
            .map(|definition| definition.id)
            .collect::<Vec<_>>();
        ids.sort_unstable();
        let gap_owners = definitions
            .iter()
            .flat_map(|definition| {
                definition.clauses.iter().flat_map(move |clause| {
                    clause
                        .query
                        .effect_selectors()
                        .into_iter()
                        .map(move |selector| (definition.gap_code.is_some(), selector.clone()))
                })
            })
            .collect();
        Self {
            definitions,
            ids,
            gap_owners,
        }
    }

    /// Every shipped guard definition, in evaluation order.
    pub fn definitions(&self) -> &[GuardDefinition] {
        &self.definitions
    }

    /// The shipped guard ids in name order.
    pub fn shipped_guard_ids(&self) -> &[&'static str] {
        &self.ids
    }

    /// The shipped guard definition named `id`.
    pub fn definition(&self, id: &str) -> Option<&GuardDefinition> {
        self.definitions
            .iter()
            .find(|definition| definition.id == id)
    }

    /// Every selector of every clause, with whether its definition names a
    /// gap; the bridge uses it to decide which effects' gaps a guard owns.
    pub fn gap_owners(&self) -> &[(bool, Selector)] {
        &self.gap_owners
    }

    /// Evaluates every shipped guard over `plan`, in definition order, with one
    /// matcher evaluator built for the plan. Each clause is answered against a
    /// scope of the unchanged plan's effects, so effect indices and occurrences
    /// stay those of the whole plan. Absence is conclusive: boundaries are not
    /// consulted, as absent effects are absent among Nah's facts, and an
    /// indeterminate definition names its gap by `gap_code`. A query the
    /// matcher refuses exceeds the evidence limit.
    pub fn evaluate(
        &self,
        plan: &Plan,
        labels: &dyn LabelProvider,
        host: &dyn GuardHostFacts,
    ) -> Result<ShippedGuardMatches, EvidenceError> {
        let index = PlanIndex::new(plan);
        let evaluator = Evaluator::new(
            plan,
            host.matcher_bindings(),
            labels,
            QueryLimits::default(),
        );
        let mut matches = ShippedGuardMatches::default();
        for definition in &self.definitions {
            let mut unknown_calls = BTreeSet::new();
            let mut matched = false;
            'clauses: for clause in &definition.clauses {
                // A clause that binds effects relates one effect to others in
                // the plan, a listener beside a download or a route into an
                // execution, so it is scoped to every effect it may bind and
                // names the effect it bound. These clauses name no gap. The
                // host rule is not a property of one match here: an effect it
                // rejects is never an effect the clause can bind, though
                // another effect it binds can still be related to it.
                if clause.query.binds_effects() {
                    let scope = (0..plan.effects.len())
                        .filter(|&effect| {
                            clause
                                .host
                                .as_ref()
                                .is_none_or(|rule| host_rule_holds(plan, host, rule, effect))
                        })
                        .collect::<Vec<_>>();
                    match evaluator.evaluate_in(&clause.query, &scope, Absence::Conclusive) {
                        Outcome::Match(witness) => {
                            let bound = bound_effect(&witness)
                                .expect("a binding clause's witness names its bound effect");
                            matched = plan.effects.iter().any(|effect| &effect.id == bound);
                            break 'clauses;
                        }
                        Outcome::Refused(_) => return Err(EvidenceError::ExceedsLimit),
                        Outcome::NoMatch | Outcome::Indeterminate(_) => {}
                    }
                    continue;
                }
                // Any other clause is answered once per effect its selectors
                // name, scoped to that effect alone, so each match stays
                // independent of the other effects.
                for effect_index in evaluator.candidate_effects(&clause.query) {
                    let effect = &plan.effects[effect_index];
                    match evaluator.evaluate_in(&clause.query, &[effect_index], Absence::Conclusive)
                    {
                        Outcome::Match(_) => {
                            if !clause
                                .host
                                .as_ref()
                                .is_none_or(|rule| host_rule_holds(plan, host, rule, effect_index))
                            {
                                continue;
                            }
                            match qualify(&index, host, effect_index, &clause.qualifiers) {
                                Qualification::Match => {
                                    matched = true;
                                    break 'clauses;
                                }
                                Qualification::Indeterminate => {
                                    unknown_calls.insert(CallId(effect.execution.0));
                                }
                                Qualification::NoMatch => {}
                            }
                        }
                        Outcome::Indeterminate(_) => {
                            unknown_calls.insert(CallId(effect.execution.0));
                        }
                        Outcome::NoMatch => {}
                        Outcome::Refused(_) => return Err(EvidenceError::ExceedsLimit),
                    }
                }
            }
            if matched {
                matches.matched.push(definition.id);
            } else if let Some(code) = definition.gap_code {
                matches
                    .gaps
                    .extend(unknown_calls.into_iter().map(|call| ShippedGuardGap {
                        call,
                        domain: definition.domain,
                        code,
                    }));
            }
        }
        Ok(matches)
    }
}

/// The plan lookups the qualifiers make, indexed once per evaluation.
struct PlanIndex<'a> {
    plan: &'a Plan,
    /// Causal nodes by id, with their positions in the plan's causal nodes;
    /// a repeated id resolves to its last node.
    nodes: BTreeMap<&'a OccurrenceId, (usize, &'a OccurrenceNode)>,
    outgoing: BTreeMap<&'a OccurrenceId, Vec<(usize, &'a CausalEdge)>>,
}

impl<'a> PlanIndex<'a> {
    fn new(plan: &'a Plan) -> Self {
        let mut nodes = BTreeMap::new();
        let mut outgoing = BTreeMap::<_, Vec<_>>::new();
        if let Some(graph) = &plan.causality.graph {
            for (position, node) in graph.nodes.iter().enumerate() {
                nodes.insert(&node.id, (position, node));
            }
            for (position, edge) in graph.edges.iter().enumerate() {
                outgoing
                    .entry(&edge.from)
                    .or_default()
                    .push((position, edge));
            }
        }
        Self {
            plan,
            nodes,
            outgoing,
        }
    }

    fn outgoing_edges(&self, id: &OccurrenceId) -> impl Iterator<Item = &'a CausalEdge> {
        self.positioned_outgoing_edges(id).map(|(_, edge)| edge)
    }

    fn causal_node(&self, id: &OccurrenceId) -> Option<&'a OccurrenceNode> {
        self.positioned_causal_node(id).map(|(_, node)| node)
    }

    /// Each outgoing edge with its position in the plan's causal edges.
    fn positioned_outgoing_edges(
        &self,
        id: &OccurrenceId,
    ) -> impl Iterator<Item = (usize, &'a CausalEdge)> {
        self.outgoing.get(id).into_iter().flatten().copied()
    }

    /// The causal node with its position in the plan's causal nodes.
    fn positioned_causal_node(&self, id: &OccurrenceId) -> Option<(usize, &'a OccurrenceNode)> {
        self.nodes.get(id).copied()
    }
}

/// The outermost effect a matched binding clause bound, or the effect an
/// unbound alternative beside its bindings selected.
fn bound_effect(witness: &Witness) -> Option<&EffectId> {
    match witness {
        Witness::BindEffect { effect, .. } | Witness::Effect { effect } => Some(effect),
        Witness::Any { witness, .. } => bound_effect(witness),
        Witness::All { witnesses } => witnesses.iter().find_map(bound_effect),
        _ => None,
    }
}

/// Nah's half of a filesystem clause for the plan effect at `effect`, after
/// its engine query matched. Queries cannot state it: the host path catalogs
/// read the bridge's labels of what the effect physically reaches, including
/// a finite selection's members and a move's destination, which no plan
/// resource carries.
fn host_rule_holds(plan: &Plan, host: &dyn GuardHostFacts, rule: &HostRule, effect: usize) -> bool {
    let effect_index = effect;
    let effect = &plan.effects[effect_index];
    if rule.feasible_condition && host.condition_reach(effect_index) == Reach::No {
        return false;
    }
    if effect.operation.domain() == "filesystem" && !host.model_identity_established(effect_index) {
        return false;
    }
    // A clause with no reach requirement is decided by its query alone: a
    // chmod mode that grants world-write grants it whichever file receives it.
    let Some(reach) = &rule.reach else {
        return true;
    };
    // A filesystem request names an identified host target only when its
    // resource is typed: an unresolved or unbound expression leaves the
    // target open, and an open destructive target would read as every root.
    if effect.operation.domain() == "filesystem"
        && (matches!(effect.resource, ResourceExpr::Unresolved { .. })
            || !host.target_identified(effect_index))
    {
        return false;
    }
    let entry = matches!(
        effect.operation.as_str(),
        "filesystem.delete" | "filesystem.move"
    );
    let reached: Vec<ReachedHostPath<'_>> = match reach.endpoint {
        ReachEndpoint::Selected => host.selected_host_paths(effect_index),
        ReachEndpoint::MoveDestination => host.move_destination(effect_index).into_iter().collect(),
    };
    reached.into_iter().any(|reached| {
        reach.holds(&ReachedPath {
            resource: reached.resource,
            entry,
            recursive: reached.recursive,
            device: reached.device,
        })
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Qualification {
    Match,
    NoMatch,
    Indeterminate,
}

/// Applies a clause's qualifiers to the plan effect at `effect`: any `NoMatch`
/// wins, then any `Indeterminate`.
fn qualify(
    index: &PlanIndex<'_>,
    host: &dyn GuardHostFacts,
    effect: usize,
    qualifiers: &[QueryQualifier],
) -> Qualification {
    let effect_index = effect;
    let effect = &index.plan.effects[effect_index];
    let mut outcome = Qualification::Match;
    for qualifier in qualifiers {
        let current = match qualifier {
            QueryQualifier::GitMetadata => git_metadata_qualifies(index, host, effect_index),
            QueryQualifier::DirectPathRestoration => {
                direct_path_restoration_qualifies(index, host, effect)
            }
            QueryQualifier::GithubRelease => github_release_qualifies(effect),
            QueryQualifier::FeasibleCondition => {
                if host.condition_reach(effect_index) == Reach::No {
                    Qualification::NoMatch
                } else {
                    Qualification::Match
                }
            }
        };
        match current {
            Qualification::NoMatch => return Qualification::NoMatch,
            Qualification::Indeterminate => outcome = Qualification::Indeterminate,
            Qualification::Match => {}
        }
    }
    outcome
}

/// A destructive filesystem change selecting durable Git history metadata:
/// the `.git` directory itself, or its `logs`, `objects`, `packed-refs`,
/// `refs` or `worktrees`, directly or through an exact move into one. Queries
/// cannot state it: it reads the observed spellings of each path (as
/// requested, resolved and real), the repository's own `git_dir` from another
/// effect, and a move's causal destination, none of which a resource
/// predicate over one effect sees.
fn git_metadata_qualifies(
    index: &PlanIndex<'_>,
    host: &dyn GuardHostFacts,
    effect_index: usize,
) -> Qualification {
    let effect = &index.plan.effects[effect_index];
    if !matches!(
        effect.operation.as_str(),
        "filesystem.move"
            | "filesystem.write"
            | "filesystem.create"
            | "filesystem.delete"
            | "filesystem.metadata"
    ) || !host.model_identity_established(effect_index)
        || !git_metadata_effect_is_exact(index.plan, effect)
    {
        return Qualification::NoMatch;
    }
    let recursive = host.selects_recursively(effect_index);
    if metadata_resource(
        index.plan,
        host,
        &effect.resource,
        effect.operation.as_str(),
        recursive,
    ) {
        return Qualification::Match;
    }
    if effect.operation.as_str() != "filesystem.move" {
        return Qualification::NoMatch;
    }
    let Some(causality) = &index.plan.causality.graph else {
        return Qualification::Indeterminate;
    };
    // Only a proven success path counts: an unknown answer from the matcher's
    // success-path rule, as for a widened condition, collapses to false.
    let mut saw_source = false;
    for node in causality.nodes.iter().filter(|node| {
        node.execution == Some(effect.execution)
            && node.realm == effect.realm
            && node.condition == effect.condition
            && node.modality == effect.modality
            && node.provenance == effect.provenance
            && matches!(&node.occurrence, OccurrenceKind::ResourceInteraction {
                operation,
                resource,
                attributes,
            } if operation == &effect.operation
                && resource == &effect.resource
                && attributes == &effect.attributes)
    }) {
        saw_source = true;
        for edge in index.outgoing_edges(&node.id).filter(|edge| {
            edge.reason == CausalReason::ResourceTransfer
                && edge.assurance == CausalAssurance::Exact
                && success_path(edge.condition.as_ref(), QueryLimits::default()) == Ok(Truth::True)
        }) {
            let Some(destination) = index.causal_node(&edge.to) else {
                continue;
            };
            let OccurrenceKind::ResourceInteraction {
                operation,
                resource,
                ..
            } = &destination.occurrence
            else {
                continue;
            };
            if destination.realm.is_host()
                && success_path(destination.condition.as_ref(), QueryLimits::default())
                    == Ok(Truth::True)
                && operation.domain() == "filesystem"
                && metadata_resource(index.plan, host, resource, operation.as_str(), false)
            {
                return Qualification::Match;
            }
        }
    }
    if causality.nodes.is_empty() || !saw_source {
        Qualification::Indeterminate
    } else {
        Qualification::NoMatch
    }
}

fn git_metadata_effect_is_exact(plan: &Plan, effect: &Effect) -> bool {
    (effect.request_assurance == RequestAssurance::Exact
        && !matches!(effect.resource, ResourceExpr::Unresolved { .. }))
        || (matches!(effect.resource, ResourceExpr::Concrete { .. })
            && plan.execution_graph.nodes[effect.execution.0 as usize].assurance
                == ExecutionAssurance::Exact)
}

fn metadata_resource(
    plan: &Plan,
    host: &dyn GuardHostFacts,
    resource: &ResourceExpr,
    operation: &str,
    recursive: bool,
) -> bool {
    host.observed_path_spellings(resource)
        .into_iter()
        .any(|path| {
            metadata_path_query(&path, operation == "filesystem.delete", recursive)
                || metadata_repository_path_query(plan, &path)
        })
}

fn metadata_path_query(path: &str, delete: bool, recursive: bool) -> bool {
    let windows = path.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
        && path.as_bytes().get(1) == Some(&b':')
        || path.starts_with("//")
        || path.starts_with(r"\\");
    let folded;
    let path = if windows {
        folded = path.replace('\\', "/").to_ascii_lowercase();
        &folded
    } else {
        path
    };
    let mut components = path.split('/');
    let Some(component) = components.find(|part| *part == ".git" || part.ends_with(".git")) else {
        return false;
    };
    match components.next() {
        None => component == ".git" || delete && recursive,
        Some("logs" | "objects" | "packed-refs" | "refs" | "worktrees" | "*" | "**" | "{*,.*}") => {
            true
        }
        Some(first) => first
            .strip_prefix('{')
            .and_then(|value| value.strip_suffix('}'))
            .is_some_and(|choices| {
                choices.split(',').any(|choice| {
                    matches!(
                        choice,
                        "logs" | "objects" | "packed-refs" | "refs" | "worktrees"
                    )
                })
            }),
    }
}

fn metadata_repository_path_query(plan: &Plan, path: &str) -> bool {
    plan.effects.iter().any(|effect| {
        if !effect.realm.is_host() {
            return false;
        }
        let ResourceExpr::Concrete {
            identity:
                ResourceIdentity::GitRepository {
                    git_dir: Some(git_dir),
                    ..
                },
        } = &effect.resource
        else {
            return false;
        };
        let ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path: git_dir },
        } = git_dir.as_ref()
        else {
            return false;
        };
        let windows = git_dir.as_bytes().get(1) == Some(&b':') || git_dir.starts_with(r"\\");
        let separator = |character| character == '/' || windows && character == '\\';
        path == git_dir
            || path
                .strip_prefix(git_dir)
                .and_then(|tail| tail.strip_prefix(separator))
                .is_some_and(|tail| {
                    tail.split(separator).next().is_some_and(|component| {
                        matches!(
                            component,
                            "logs" | "objects" | "packed-refs" | "refs" | "worktrees"
                        )
                    })
                })
    })
}

/// A historical `git show REV:PATH` whose output the invocation writes back
/// over the same path in its worktree. Queries cannot state it: it joins the
/// read's `object`, `revision` and `path` attributes into one expected host
/// path and follows the read's stdout through the causal graph to an exact
/// write of that path, which no flow endpoint can name.
fn direct_path_restoration_qualifies(
    index: &PlanIndex<'_>,
    host: &dyn GuardHostFacts,
    effect: &Effect,
) -> Qualification {
    let string_attr = |name: &str| match effect.attributes.get(name) {
        Some(AttrValue::String(value)) => Some(value.as_str()),
        _ => None,
    };
    let (Some(object), Some(revision), Some(path)) = (
        string_attr("object"),
        string_attr("revision"),
        string_attr("path"),
    ) else {
        return Qualification::Indeterminate;
    };
    if object != format!("{revision}:{path}") {
        return Qualification::NoMatch;
    }
    let path = path.trim_start_matches("./");
    if path.is_empty() {
        return Qualification::NoMatch;
    }
    let ResourceExpr::Concrete {
        identity:
            ResourceIdentity::GitRepository {
                worktree: Some(worktree),
                ..
            },
    } = &effect.resource
    else {
        return Qualification::Indeterminate;
    };
    let ResourceExpr::Concrete {
        identity: ResourceIdentity::FsPath { path: worktree },
    } = worktree.as_ref()
    else {
        return Qualification::Indeterminate;
    };
    let expected = nah_proto::labels::join(worktree, path, host.platform());
    let Some(causality) = &index.plan.causality.graph else {
        return Qualification::Indeterminate;
    };
    // A route counts unless the conditions of its stdout, edges, stages and
    // write are proven unable to hold together in one run: an `||` fallback,
    // a branch body or an undecided condition still restores the file, while
    // a blob and a write on mutually exclusive branches form no route.
    let mut pending = causality
        .nodes
        .iter()
        .enumerate()
        .filter(|(_, node)| {
            node.execution == Some(effect.execution)
                && node.realm == effect.realm
                && matches!(node.occurrence, OccurrenceKind::Port { port: Port::Stdout })
        })
        .map(|(position, node)| RestorationRoute {
            at: &node.id,
            nodes: vec![position],
            edges: Vec::new(),
            through_stage: false,
        })
        .collect::<Vec<_>>();
    let saw_stdout = !pending.is_empty();
    // The blob may reach the write through a stage that copies its stdin
    // exactly (`git show REV:PATH | tee PATH`), so exact edges are followed
    // through intermediate stdin and stdout ports.
    while let Some(route) = pending.pop() {
        for (edge_position, edge) in
            index
                .positioned_outgoing_edges(route.at)
                .filter(|(_, edge)| {
                    matches!(
                        edge.reason,
                        CausalReason::ValueDependency | CausalReason::ResourceTransfer
                    ) && edge.assurance == CausalAssurance::Exact
                })
        {
            let Some((node_position, destination)) = index.positioned_causal_node(&edge.to) else {
                continue;
            };
            if !destination.realm.is_host() || route.nodes.contains(&node_position) {
                continue;
            }
            let mut nodes = route.nodes.clone();
            nodes.push(node_position);
            let mut edges = route.edges.clone();
            edges.push(edge_position);
            if host.causal_route_reach(&nodes, &edges) == Reach::No {
                continue;
            }
            match &destination.occurrence {
                OccurrenceKind::Port {
                    port: Port::Stdin | Port::Stdout,
                } => pending.push(RestorationRoute {
                    at: &destination.id,
                    nodes,
                    edges,
                    through_stage: true,
                }),
                // A later stage that appends (`| cat >> PATH`) keeps what
                // the file held, so it restores nothing.
                OccurrenceKind::ResourceInteraction {
                    operation,
                    resource:
                        ResourceExpr::Concrete {
                            identity: ResourceIdentity::FsPath { path },
                        },
                    attributes,
                } if operation.as_str() == "filesystem.write"
                    && path == &expected
                    && !(route.through_stage
                        && attributes.get("append") == Some(&AttrValue::Bool(true))) =>
                {
                    return Qualification::Match;
                }
                _ => {}
            }
        }
    }
    if saw_stdout {
        Qualification::NoMatch
    } else {
        Qualification::Indeterminate
    }
}

/// A partial route from a historical blob's stdout toward a write: the
/// positions of the causal nodes and edges it has taken, and whether it has
/// passed through a copying stage.
struct RestorationRoute<'a> {
    at: &'a OccurrenceId,
    nodes: Vec<usize>,
    edges: Vec<usize>,
    through_stage: bool,
}

/// An `artifact.delete` of a GitHub release. Queries cannot state it with the
/// same outcome: a resource predicate on the artifact's ecosystem is unknown
/// for an unresolved resource, which would make the clause indeterminate and
/// name a gap, while this qualifier treats any resource that is not a
/// concrete GitHub release as no match.
fn github_release_qualifies(effect: &Effect) -> Qualification {
    if matches!(
        effect.resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::Artifact {
                ecosystem: ArtifactEcosystem::GithubRelease,
                ..
            }
        }
    ) {
        Qualification::Match
    } else {
        Qualification::NoMatch
    }
}
