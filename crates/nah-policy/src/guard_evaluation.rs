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
    Absence, Evaluator, LabelProvider, Outcome, QueryLimits, Refusal, Selector, Truth, Witness,
    success_path,
};
use nah_proto::effects::{CallId, EvidenceError, Reach};
use nah_proto::effinterp_proto::{
    ArtifactEcosystem, AttrValue, CausalAssurance, CausalEdge, CausalReason, Effect, EffectId,
    ExecutionAssurance, FsEntryKind, OccurrenceId, OccurrenceKind, OccurrenceNode, Plan, Port,
    RequestAssurance, ResourceExpr, ResourceIdentity, ResourcePattern,
};
use nah_proto::guard_host::{
    GuardHostFacts, MatchedPart, ReachedHostPath, ShippedGuardGap, ShippedGuardMatches,
};

use crate::filesystem_guards::{HostRule, ReachEndpoint, ReachedPath};
use crate::registry::{GuardDefinition, shipped_guard_definitions};

/// A predicate a guard clause applies to an effect after its query matched,
/// for what the matcher's query language cannot state.
#[derive(Clone, Debug)]
pub enum QueryQualifier {
    /// The effect is not a read whose bytes reach only a count
    /// ([`crate::secret_guards::only_counted`]). Queries cannot state it: no
    /// selector reads the pipe that joins two executions. A clause that
    /// binds effects never binds one this rejects.
    BeyondCount,
    /// Observed bytes do not prove a recursive literal grep non-matching.
    /// The matcher cannot inspect host content.
    BeyondNonMatchingGrep,
    /// The effect is not a read of a file the bridge observes missing with
    /// nothing else in the invocation that may create it
    /// ([`GuardHostFacts::reads_missing_file`]). The matcher cannot see
    /// whether a host file exists.
    BeyondMissingFile,
    /// The effect is not a read this query establishes as a copy that keeps
    /// its label ([`crate::flow_guards::kept_copy`]). Only a match exempts:
    /// a query left indeterminate by an unobserved destination proves no
    /// such copy, and negating it inside the clause would then drop the
    /// block. A clause that binds effects never binds one this rejects.
    BeyondKeptCopy(Box<effinterp_matcher::Query>),
    GitMetadata,
    /// A write, creation or move selecting what Git runs code from: an entry
    /// of the repository's `hooks` directory or the directory itself, or its
    /// `config` file, or a path in the hook directory the call's repository
    /// configures. Queries cannot state it for the reasons
    /// [`Self::GitMetadata`] names, nor read the configured directory.
    GitCodePath,
    DirectPathRestoration,
    GithubRelease,
    /// The effect's condition must not be proven impossible within the
    /// invocation, the rule filesystem guards apply through
    /// [`HostRule::feasible_condition`]: a fallback after `||`, a branch body,
    /// a loop body or a condition too large to decide still reaches the
    /// effect, while a position proven unreachable does not.
    FeasibleCondition,
    LookalikeHost,
    /// The root call's command text holds characters that make the operator's
    /// display of it differ from what runs. Queries cannot state it: the plan
    /// carries no command text, only the bridge's root-call evidence does.
    HiddenCharacters,
    /// The Git discard the effect requests may lose something: the bridge's
    /// observation of the repository does not establish that it holds no
    /// uncommitted work the discard would take. Queries cannot state it: the
    /// plan carries what the command does, not what the repository holds.
    GitLossPossible,
    /// The Git history rewrite the effect requests may leave commits out of
    /// the reach of every ref and reflog: the bridge's observation of the
    /// repository does not establish that Git keeps the commits it replaces.
    /// Queries cannot state it, for the same reason.
    GitHistoryLossPossible,
    /// The effect is a recursive delete of paths inside the call's project
    /// ([`GuardHostFacts::project_delete`]). Queries cannot state it: where
    /// the project lies is the bridge's observation, not the plan's.
    ProjectFilesDeleted,
    /// The effect deletes recursively, or removes a whole tree, and the engine
    /// left its target unresolved ([`crate::filesystem_guards::unresolved_tree_delete`]).
    /// Queries cannot state it: a resource predicate is unknown, not false,
    /// for an unresolved resource, and no predicate reads selection depth.
    UnresolvedTreeDeleted,
    /// The unresolved target is another program's output in the same call
    /// ([`crate::filesystem_guards::target_from_program_output`]). Queries
    /// cannot state it: no selector follows causal edges back from an
    /// effect to the execution that produced its value.
    TargetFromProgramOutput,
    /// A permission or ownership change must be able to lock the owner out
    /// of what it is applied to. One the bridge establishes keeps the owner's
    /// access (`chmod -R u+w`, a chown to the invoking user) destroys
    /// nothing, and queries cannot state it: whether a mode keeps access
    /// depends on the mode's own grammar and on whether what it is applied
    /// to may be a directory. Any other effect qualifies.
    OwnerAccessLost,
    /// Literal shell text written to a profile downloads and executes remote
    /// content. The bridge supplies a bounded engine plan of those bytes.
    RemoteWrittenContent,
    /// The call types out a credential value the hook's environment holds
    /// ([`GuardHostFacts::call_retypes_credential`]). Queries cannot state it:
    /// the plan carries neither the values nor, for a typed value, any read.
    RetypedCredential,
    /// The call adds a dependency one slip from a package the project has
    /// ([`GuardHostFacts::call_adds_lookalike_dependency`]), with
    /// `same_version` one that also pins that package's version. Queries
    /// cannot state it: the plan holds neither the project's packages nor
    /// how far apart two names are.
    LookalikePackage {
        same_version: bool,
    },
}

/// The shipped guard registry, built and validated once: the definitions
/// `shipped_guard_definitions` returns, and their rule IDs in catalog order.
pub struct ShippedGuards {
    definitions: Vec<GuardDefinition>,
    rules: Vec<&'static str>,
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
        let mut rules = definitions
            .iter()
            .map(|definition| (definition.guard, definition.rule))
            .collect::<Vec<_>>();
        rules.sort_unstable();
        rules.dedup();
        let rules = rules.into_iter().map(|(_, rule)| rule).collect();
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
            rules,
            gap_owners,
        }
    }

    /// Every shipped rule part, in evaluation order.
    pub fn definitions(&self) -> &[GuardDefinition] {
        &self.definitions
    }

    /// The shipped rule IDs, by guard in catalog order and then by name.
    pub fn rule_ids(&self) -> &[&'static str] {
        &self.rules
    }

    /// The parts of the rule `rule`, in evaluation order.
    pub fn parts(&self, rule: &str) -> impl Iterator<Item = &GuardDefinition> {
        self.definitions
            .iter()
            .filter(move |definition| definition.rule == rule)
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
    /// indeterminate definition names its gap by `gap_code`. A clause that
    /// runs out of matcher work leaves its guard in `exceeded` unless another
    /// clause matches. Guards share the evaluator's step budget in definition
    /// order, so one that spends it leaves each later guard only its own
    /// steps; any other refusal is an invalid query and exceeds the evidence
    /// limit.
    pub fn evaluate(
        &self,
        plan: &Plan,
        labels: &dyn LabelProvider,
        host: &dyn GuardHostFacts,
    ) -> Result<ShippedGuardMatches, EvidenceError> {
        self.evaluate_within(plan, labels, host, QueryLimits::default())
    }

    /// [`Self::evaluate`] under the caller's matcher work limits.
    pub fn evaluate_within(
        &self,
        plan: &Plan,
        labels: &dyn LabelProvider,
        host: &dyn GuardHostFacts,
        limits: QueryLimits,
    ) -> Result<ShippedGuardMatches, EvidenceError> {
        let index = PlanIndex::new(plan);
        let evaluator = Evaluator::new(plan, host.matcher_bindings(), labels, limits);
        let mut matches = ShippedGuardMatches::default();
        // The effects each rule that describes every effect matched, across
        // all its parts. Those parts all apply at core, so every part that
        // matched runs whenever the rule does.
        let mut rule_effects = BTreeMap::<&'static str, Vec<usize>>::new();
        for (part, definition) in self.definitions.iter().enumerate() {
            let mut unknown_calls = BTreeSet::new();
            let mut matched = false;
            let mut reason = None;
            let mut exceeded = false;
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
                                && clause.qualifiers.iter().all(|qualifier| match qualifier {
                                    QueryQualifier::BeyondCount => {
                                        !crate::secret_guards::only_counted(plan, effect)
                                    }
                                    QueryQualifier::BeyondNonMatchingGrep => {
                                        !host.grep_matches_no_environment_file(effect)
                                    }
                                    QueryQualifier::BeyondMissingFile => {
                                        !host.reads_missing_file(effect)
                                    }
                                    QueryQualifier::BeyondKeptCopy(copy) => !matches!(
                                        evaluator.evaluate_in(copy, &[effect], Absence::Conclusive),
                                        Outcome::Match(_)
                                    ),
                                    _ => true,
                                })
                        })
                        .collect::<Vec<_>>();
                    match evaluator.evaluate_in(&clause.query, &scope, Absence::Conclusive) {
                        Outcome::Match(witness) => {
                            let bound = bound_effect(&witness)
                                .expect("a binding clause's witness names its bound effect");
                            let bound = plan.effects.iter().position(|effect| &effect.id == bound);
                            matched = bound.is_some();
                            reason = bound.and_then(|effect| {
                                crate::secret_guards::staging_reason(
                                    definition.rule,
                                    plan,
                                    host,
                                    effect,
                                )
                                .or_else(|| {
                                    crate::secret_guards::file_reason(
                                        definition.rule,
                                        plan,
                                        host,
                                        effect,
                                    )
                                })
                            });
                            break 'clauses;
                        }
                        Outcome::Refused(Refusal::WorkLimit) => exceeded = true,
                        Outcome::Refused(_) => return Err(EvidenceError::ExceedsLimit),
                        Outcome::NoMatch | Outcome::Indeterminate(_) => {}
                    }
                    continue;
                }
                // A clause that names no effect states a fact about the call
                // itself, so it is answered once over the plan, and its
                // qualifiers read the call rather than an effect.
                if clause.query.effect_selectors().is_empty() {
                    match evaluator.evaluate_in(&clause.query, &[], Absence::Conclusive) {
                        Outcome::Match(_) if qualify_call(host, &clause.qualifiers) => {
                            matched = true;
                            if clause.qualifiers.iter().any(|qualifier| {
                                matches!(qualifier, QueryQualifier::RetypedCredential)
                            }) {
                                reason =
                                    Some(crate::secret_guards::RETYPED_CREDENTIAL_REASON.into());
                            }
                            break 'clauses;
                        }
                        Outcome::Refused(Refusal::WorkLimit) => exceeded = true,
                        Outcome::Refused(_) => return Err(EvidenceError::ExceedsLimit),
                        _ => {}
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
                                    // Its reason names every effect it
                                    // matched, so the part keeps looking.
                                    if crate::filesystem_guards::describes_every_effect(
                                        definition.rule,
                                    ) {
                                        let effects =
                                            rule_effects.entry(definition.rule).or_default();
                                        if !effects.contains(&effect_index) {
                                            effects.push(effect_index);
                                        }
                                        continue;
                                    }
                                    reason = crate::git_guards::push_reason(
                                        definition.rule,
                                        plan,
                                        effect_index,
                                    )
                                    .or_else(|| {
                                        crate::secret_guards::staging_reason(
                                            definition.rule,
                                            plan,
                                            host,
                                            effect_index,
                                        )
                                    });
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
                        Outcome::Refused(Refusal::WorkLimit) => exceeded = true,
                        Outcome::Refused(_) => return Err(EvidenceError::ExceedsLimit),
                    }
                }
            }
            if matched {
                matches.matched.push(MatchedPart {
                    rule: definition.rule,
                    part,
                    reason,
                });
                continue;
            }
            if exceeded && !matches.exceeded.contains(&definition.rule) {
                matches.exceeded.push(definition.rule);
            }
            if let Some(code) = definition.gap_code {
                matches
                    .gaps
                    .extend(unknown_calls.into_iter().map(|call| ShippedGuardGap {
                        call,
                        domain: definition.domain,
                        code,
                    }));
            }
        }
        for matched in &mut matches.matched {
            if let Some(effects) = rule_effects.get(matched.rule) {
                matched.reason = Some(crate::filesystem_guards::effects_reason(
                    matched.rule,
                    plan,
                    host,
                    effects,
                ));
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
        reach.holds(
            &ReachedPath {
                resource: reached.resource,
                entry,
                recursive: reached.recursive,
                device: reached.device,
                linked_readings: reached.linked_readings.as_deref(),
            },
            host,
        )
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Qualification {
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
            QueryQualifier::BeyondCount => {
                if crate::secret_guards::only_counted(index.plan, effect_index) {
                    Qualification::NoMatch
                } else {
                    Qualification::Match
                }
            }
            // Decided where a binding clause's scope is built, the only place
            // a clause carries it.
            QueryQualifier::BeyondKeptCopy(_) => Qualification::Match,
            QueryQualifier::BeyondNonMatchingGrep => {
                if host.grep_matches_no_environment_file(effect_index) {
                    Qualification::NoMatch
                } else {
                    Qualification::Match
                }
            }
            QueryQualifier::BeyondMissingFile => {
                if host.reads_missing_file(effect_index) {
                    Qualification::NoMatch
                } else {
                    Qualification::Match
                }
            }
            QueryQualifier::RemoteWrittenContent => match host.written_shell_plan(effect_index) {
                Some(plan) => {
                    let evaluator = Evaluator::new(
                        plan,
                        BTreeMap::new(),
                        &effinterp_matcher::NoLabels,
                        QueryLimits::default(),
                    );
                    let query = effinterp_matcher::Query::new(effinterp_matcher::Assertion::Any {
                        assertions: crate::flow_guards::remote_execution_assertions(),
                    });
                    match evaluator.evaluate_in(
                        &query,
                        &(0..plan.effects.len()).collect::<Vec<_>>(),
                        Absence::Conclusive,
                    ) {
                        Outcome::Match(_) => Qualification::Match,
                        Outcome::Indeterminate(_) => Qualification::Indeterminate,
                        _ => Qualification::NoMatch,
                    }
                }
                None => Qualification::NoMatch,
            },
            QueryQualifier::GitMetadata => {
                git_path_qualifies(index, host, effect_index, GitPath::Metadata)
            }
            QueryQualifier::GitCodePath => {
                git_path_qualifies(index, host, effect_index, GitPath::Code)
            }
            QueryQualifier::DirectPathRestoration => {
                direct_path_restoration_qualifies(index, host, effect)
            }
            QueryQualifier::GithubRelease => github_release_qualifies(effect),
            QueryQualifier::LookalikeHost => {
                crate::network_guards::lookalike_host_qualifies(effect)
            }
            QueryQualifier::HiddenCharacters => {
                if host.command_has_hidden_characters() {
                    Qualification::Match
                } else {
                    Qualification::NoMatch
                }
            }
            QueryQualifier::RetypedCredential => {
                if host.call_retypes_credential() {
                    Qualification::Match
                } else {
                    Qualification::NoMatch
                }
            }
            QueryQualifier::LookalikePackage { same_version } => {
                if host.call_adds_lookalike_dependency(*same_version) {
                    Qualification::Match
                } else {
                    Qualification::NoMatch
                }
            }
            QueryQualifier::OwnerAccessLost => {
                if host.permission_change_keeps_owner_access(effect_index) {
                    Qualification::NoMatch
                } else {
                    Qualification::Match
                }
            }
            QueryQualifier::UnresolvedTreeDeleted => {
                if crate::filesystem_guards::unresolved_tree_delete(index.plan, host, effect_index)
                {
                    Qualification::Match
                } else {
                    Qualification::NoMatch
                }
            }
            QueryQualifier::TargetFromProgramOutput => {
                if crate::filesystem_guards::target_from_program_output(index.plan, effect_index) {
                    Qualification::Match
                } else {
                    Qualification::NoMatch
                }
            }
            QueryQualifier::ProjectFilesDeleted => {
                if host.project_delete(effect_index).is_some() {
                    Qualification::Match
                } else {
                    Qualification::NoMatch
                }
            }
            QueryQualifier::GitLossPossible => {
                if host.git_discard_loses_nothing(effect_index) {
                    Qualification::NoMatch
                } else {
                    Qualification::Match
                }
            }
            QueryQualifier::GitHistoryLossPossible => {
                if host.git_rewrite_loses_nothing(effect_index) {
                    Qualification::NoMatch
                } else {
                    Qualification::Match
                }
            }
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

/// Applies a clause's qualifiers to the call, for a clause whose query names
/// no effect: a qualifier about an effect holds of no call.
fn qualify_call(host: &dyn GuardHostFacts, qualifiers: &[QueryQualifier]) -> bool {
    qualifiers.iter().all(|qualifier| match qualifier {
        QueryQualifier::HiddenCharacters => host.command_has_hidden_characters(),
        QueryQualifier::RetypedCredential => host.call_retypes_credential(),
        QueryQualifier::LookalikePackage { same_version } => {
            host.call_adds_lookalike_dependency(*same_version)
        }
        _ => false,
    })
}

/// Which part of a Git directory a filesystem change must select.
#[derive(Clone, Copy)]
enum GitPath {
    /// Durable history metadata: the `.git` directory itself, or its `logs`,
    /// `objects`, `packed-refs`, `refs` or `worktrees`.
    Metadata,
    /// What Git runs code from: the `hooks` directory or an entry in it, the
    /// hook directory the call's repository configures, and the
    /// repository's `config` file, whose settings name commands.
    Code,
}

/// A filesystem change selecting `part` of a Git directory, directly or
/// through an exact move into it. Queries cannot state it: it reads the
/// observed spellings of each path (as requested, resolved and real), the
/// repository's own `git_dir` from another effect, and a move's causal
/// destination, none of which a resource predicate over one effect sees.
fn git_path_qualifies(
    index: &PlanIndex<'_>,
    host: &dyn GuardHostFacts,
    effect_index: usize,
    part: GitPath,
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
        || !git_path_effect_is_exact(index.plan, effect, part)
    {
        return Qualification::NoMatch;
    }
    let recursive = host.selects_recursively(effect_index);
    // Moving an entry out of the hook directory plants nothing: only where a
    // move lands is code Git may run.
    let source_counts =
        !matches!(part, GitPath::Code) || effect.operation.as_str() != "filesystem.move";
    if source_counts
        && (git_path_resource(
            index.plan,
            host,
            &effect.resource,
            effect.operation.as_str(),
            recursive,
            part,
        ) || matches!(part, GitPath::Code)
            && unresolved_write_from_git_directory(index.plan, host, effect))
    {
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
                && git_path_resource(index.plan, host, resource, operation.as_str(), false, part)
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

fn git_path_effect_is_exact(plan: &Plan, effect: &Effect, part: GitPath) -> bool {
    // A hook or config path is protected unless the request provably avoids
    // it, so any exactly executed write counts there, whatever its resource
    // names: a pattern, or a path the shell computes, may name a hook. Which
    // history a write destroys depends on what it names exactly.
    let selected = match effect.resource {
        ResourceExpr::Concrete { .. } => true,
        _ => matches!(part, GitPath::Code),
    };
    (effect.request_assurance == RequestAssurance::Exact
        && !matches!(effect.resource, ResourceExpr::Unresolved { .. }))
        || (selected
            && plan.execution_graph.nodes[effect.execution.0 as usize].assurance
                == ExecutionAssurance::Exact)
}

fn git_path_resource(
    plan: &Plan,
    host: &dyn GuardHostFacts,
    resource: &ResourceExpr,
    operation: &str,
    recursive: bool,
    part: GitPath,
) -> bool {
    host.observed_path_spellings(resource)
        .into_iter()
        .any(|path| match part {
            GitPath::Metadata => {
                metadata_path_query(&path, operation == "filesystem.delete", recursive)
                    || repository_path_query(plan, &path, metadata_component)
            }
            // A recursive write of a directory (`cp -r src/. .`, `rsync -a
            // src/ .`) lands entries at any depth below it, as an extracted
            // subtree does.
            GitPath::Code => {
                names_code_path(plan, &path)
                    || in_hook_directory(host, &path)
                    || recursive
                        && operation == "filesystem.write"
                        && reaches_repository_top(host, &path)
            }
        })
        || matches!(part, GitPath::Code)
            && !matches!(resource, ResourceExpr::Concrete { .. })
            && may_name_code_path(plan, host, resource)
}

/// Whether `path` names what Git runs code from: by its own spelling, or
/// below the `git_dir` a host effect of the plan names.
fn names_code_path(plan: &Plan, path: &str) -> bool {
    code_path_query(path) || repository_path_query(plan, path, code_component)
}

/// Whether `path` lies at or below the hook directory the call's repository
/// runs (`core.hooksPath`), as observed from its working directory.
fn in_hook_directory(host: &dyn GuardHostFacts, path: &str) -> bool {
    host.observed_hook_directory()
        .is_some_and(|hooks| nah_proto::labels::lexically_contains(hooks, path, host.platform()))
}

/// Whether a subtree written at `directory` can reach the hooks or `config`
/// of the repository the call works in: `directory` is the top level of a
/// work tree the observed roots name, whose `.git` an entry of the subtree
/// may replace (an archive member `.git/hooks/pre-commit`). A directory
/// above the top level does not count: only an entry spelled with the
/// repository's own folder name could reach it, and copying a tree into
/// the home directory that holds a checkout is routine.
fn reaches_repository_top(host: &dyn GuardHostFacts, directory: &str) -> bool {
    let spellings = host.observed_path_spellings(&ResourceExpr::Concrete {
        identity: ResourceIdentity::FsPath {
            path: directory.to_owned(),
        },
    });
    host.observed_repository_tops().into_iter().any(|top| {
        std::iter::once(directory)
            .chain(spellings.iter().map(String::as_str))
            .any(|directory| {
                nah_proto::labels::lexical_path::same_path(directory, top, host.platform())
            })
    })
}

/// A write whose whole destination is unknown (a download, an install step)
/// lands where its program puts it, which is mostly its working directory.
/// It may plant a hook when that directory is a Git directory or lies under
/// its hooks (`cd .git/hooks && curl -O "$URL"`) or under the configured
/// hook directory. Anywhere else it stays unjudged: blocking every
/// unresolved write would stop every install.
fn unresolved_write_from_git_directory(
    plan: &Plan,
    host: &dyn GuardHostFacts,
    effect: &Effect,
) -> bool {
    if !matches!(effect.resource, ResourceExpr::Unresolved { .. }) {
        return false;
    }
    let Some(
        cwd @ ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        },
    ) = plan
        .execution_graph
        .nodes
        .get(effect.execution.0 as usize)
        .and_then(|node| node.cwd.as_ref())
    else {
        return false;
    };
    std::iter::once(path.clone())
        .chain(host.observed_path_spellings(cwd))
        .any(|directory| {
            names_code_path(plan, &directory)
                || names_code_path(plan, &format!("{directory}/hooks"))
                || in_hook_directory(host, &directory)
        })
}

/// Whether a destination Nah cannot read as one concrete path may still name
/// what Git runs code from. Nah does not reason about which names a shell
/// pattern or a computed part can produce: a destination with any glob, or
/// with a part the shell computes, may name a hook or config wherever it is
/// spelled. Exempt are a wholly unresolved destination, which spells nothing
/// (a tool's download or install step); a resolved directory's entries
/// (`dir/*`, where a moved or extracted entry lands) or subtree (`dir/**`, or
/// a tool's environment such as `node_modules`), unless `dir` is a Git
/// directory or lies under one's hooks or the configured hook directory,
/// or the subtree reaches the call's repository (`reaches_repository_top`);
/// and a path under the home or temp directory, or a `mktemp` name there,
/// whose spelled rest provably avoids them; and a shell descriptor
/// (`/dev/fd/<n>`), whose file its own redirect names. An archive's subtree
/// can still plant a new repository, bare or nested, with hooks of its own;
/// that is left to the rules on what downloads and archives bring in.
fn may_name_code_path(plan: &Plan, host: &dyn GuardHostFacts, resource: &ResourceExpr) -> bool {
    match resource {
        ResourceExpr::Pattern {
            pattern: ResourcePattern::FsPath { glob, narrowing },
        } => {
            let subtree = glob.strip_suffix("/**");
            let root = subtree.or_else(|| glob.strip_suffix("/*")).unwrap_or(glob);
            // A selection that leaves regular files out (`find . -type d`)
            // writes no hook or config file in the subtree.
            let writes_files =
                narrowing.kinds.is_empty() || narrowing.kinds.contains(&FsEntryKind::File);
            root.contains(['*', '?', '[', '{', '(', '\\'])
                || names_code_path(plan, root)
                || names_code_path(plan, &format!("{root}/hooks"))
                || in_hook_directory(host, root)
                || writes_files && subtree.is_some_and(|root| reaches_repository_top(host, root))
        }
        ResourceExpr::Union { alternatives } => alternatives
            .iter()
            .any(|alternative| may_name_code_path(plan, host, alternative)),
        ResourceExpr::Join { parts } => {
            // The home and temp directories, which the environment names,
            // are not a Git directory, and neither is the `tmp.*` directory
            // `mktemp` makes under the temp directory.
            let mut parts = parts.as_slice();
            let mut text = String::new();
            if let [
                ResourceExpr::Parameter { name } | ResourceExpr::Environment { name },
                rest @ ..,
            ] = parts
                && matches!(name.as_str(), "HOME" | "TMPDIR")
            {
                text.push_str("/environment-root");
                parts = rest;
                if name == "TMPDIR"
                    && let [
                        ResourceExpr::Concrete {
                            identity: ResourceIdentity::FsPath { path: separator },
                        },
                        ResourceExpr::Pattern {
                            pattern: ResourcePattern::FsPath { glob, .. },
                        },
                        rest @ ..,
                    ] = parts
                    && separator == "/"
                    && glob == "tmp.*"
                {
                    text.push_str("/tmp.mktemp");
                    parts = rest;
                }
            }
            let mut computed = false;
            let mut spelled = !text.is_empty();
            for part in parts {
                match part {
                    ResourceExpr::Concrete {
                        identity: ResourceIdentity::FsPath { path },
                    } => text.push_str(path),
                    ResourceExpr::Literal { value } => text.push_str(value),
                    _ => {
                        computed = true;
                        continue;
                    }
                }
                spelled = true;
            }
            // A join of computed parts alone spells nothing, and a computed
            // descriptor under `/dev/fd/` is a file its own redirect named.
            spelled
                && (computed && text != "/dev/fd/"
                    || names_code_path(plan, &text)
                    || in_hook_directory(host, &text))
        }
        _ => false,
    }
}

/// Whether the part of a path after its Git directory, split at its first
/// separator, names history metadata or the directory itself.
fn metadata_component(component: Option<&str>, _rest: Option<&str>) -> bool {
    component.is_none_or(|component| {
        matches!(
            component,
            "logs" | "objects" | "packed-refs" | "refs" | "worktrees"
        )
    })
}

/// Whether the part of a path after its Git directory, split at its first
/// separator, names what Git runs code from: the `hooks` directory or an
/// entry below it, or the `config` file itself.
fn code_component(component: Option<&str>, rest: Option<&str>) -> bool {
    component
        .is_some_and(|component| component == "hooks" || rest.is_none() && component == "config")
}

/// A path spelled with a `.git` (or `<name>.git`) directory, at any depth,
/// whose next components [`code_component`] accepts.
fn code_path_query(path: &str) -> bool {
    let path = windows_folded(path);
    let components = path.split('/').collect::<Vec<_>>();
    components.iter().enumerate().any(|(index, part)| {
        (*part == ".git" || part.ends_with(".git"))
            && code_component(
                components.get(index + 1).copied(),
                components.get(index + 2).copied(),
            )
    })
}

/// A Windows path with its separators as `/` and its case folded, which is
/// how its components compare; any other path as spelled.
fn windows_folded(path: &str) -> std::borrow::Cow<'_, str> {
    let windows = path.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
        && path.as_bytes().get(1) == Some(&b':')
        || path.starts_with("//")
        || path.starts_with(r"\\");
    if windows {
        std::borrow::Cow::Owned(path.replace('\\', "/").to_ascii_lowercase())
    } else {
        std::borrow::Cow::Borrowed(path)
    }
}

/// A path spelled with a `.git` (or `<name>.git`) directory, at any depth,
/// that is the directory itself or names history metadata below it. Every
/// such component counts, so a checkout inside a `<name>.git` folder still
/// has its own `.git` judged.
fn metadata_path_query(path: &str, delete: bool, recursive: bool) -> bool {
    let path = windows_folded(path);
    let components = path.split('/').collect::<Vec<_>>();
    components.iter().enumerate().any(|(index, component)| {
        if *component != ".git" && !component.ends_with(".git") {
            return false;
        }
        match components.get(index + 1).copied() {
            None => *component == ".git" || delete && recursive,
            Some(
                "logs" | "objects" | "packed-refs" | "refs" | "worktrees" | "*" | "**" | "{*,.*}",
            ) => true,
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
    })
}

/// Whether `path` is or lies below the `git_dir` a host effect of the plan
/// names, with `accepts` taking the part below it split at its first
/// separator: `None` for the directory itself.
fn repository_path_query(
    plan: &Plan,
    path: &str,
    accepts: fn(Option<&str>, Option<&str>) -> bool,
) -> bool {
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
        path == git_dir && accepts(None, None)
            || path
                .strip_prefix(git_dir.as_str())
                .and_then(|tail| tail.strip_prefix(separator))
                .is_some_and(|tail| {
                    let mut components = tail.split(separator);
                    let component = components.next();
                    accepts(component, components.next())
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
    let expected = nah_proto::labels::join_lexical_path(worktree, path, host.platform());
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
