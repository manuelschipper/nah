//! Query evaluation: answers a validated query against one plan with a witness,
//! a disproof under the evaluation's absence mode, named unknowns, or a refusal.

use std::cell::{Cell, OnceCell, RefCell};
use std::collections::{BTreeMap, BTreeSet};

use effinterp_proto::{
    ArtifactReference, AttrValue, Bindings, BoundaryClass, BoundaryRef, CausalAssurance,
    CausalEdge, CausalReason, Condition, ConditionAtom, ConditionKind, CoverageLevel, Domain,
    EffectId, EffectTarget, ExecutionNodeRef, KubernetesNamespace, Match, MatchReason,
    OccurrenceId, OccurrenceKind, OccurrenceNode, Plan, Port, ResourceExpr, ResourceFamily,
    ResourceIdentity, ResourcePattern, Subject, ToolCall, resource_domain,
};
use effinterp_trace::{
    DetailUnavailable, Reachability, causal_path_in_graph, causal_path_in_graph_with,
    reachable_pairs,
};

use crate::query::{
    Absence, Assertion, AttributePredicate, AttributeTest, BoundaryDomainsPredicate,
    BoundaryProvenancePredicate, ByteFlowAssurance, ByteFlowEdgeKind, COVERAGE_SCHEMA_VERSION,
    Closure, ConditionPredicate, EffectRelation, EffectRelationship, Endpoint,
    KubernetesNamespacePredicate, LabelId, LabelProvider, LabelResource, LabelSelection,
    LabelStatus, NativeTool, ObservationBinding, Outcome, PathKindStatus, PortKind, PortScope,
    Projection, Query, Refusal, ResourceField, ResourcePredicate, ResourceVariant, RouteProvenance,
    SCHEMA_VERSION, SELECTION_SCHEMA_VERSION, SelectionLabelResource, SelectionShape,
    SelectionTarget, Selector, SubjectKind, TextPredicate, Traversal, Truth, Unknown, Witness,
};
use crate::render;
use crate::validate::{Budget, QueryLimits};

/// Flow endpoint candidates: occurrences with what the endpoint leaves of them.
type Candidates<'a> = Vec<(&'a OccurrenceId, Truth)>;
/// A selector's possible effects, by plan index, each with its selection or
/// the refusal selecting it met.
type Selections = Vec<(usize, Result<Truth, Refusal>)>;
/// Byte-flow reach by source occurrence and traversal.
type ByteReaches<'a> = BTreeMap<
    (&'a OccurrenceId, ByteFlowAssurance, Vec<ByteFlowEdgeKind>),
    std::rc::Rc<BTreeSet<&'a OccurrenceId>>,
>;

struct BindingScope<'a> {
    effect_bindings: &'a BTreeMap<String, usize>,
    depth: usize,
    /// The relationship a candidate must have to one of `effect_bindings`.
    related: Option<&'a EffectRelation>,
}

/// Answers queries against one plan. `bindings` are the explicit context for
/// each owning execution; the evaluator never consults the host. Build it once
/// per plan: [`Evaluator::evaluate_in`] then answers each query against any
/// scope of that plan's effects without rebuilding its indexes.
pub struct Evaluator<'a> {
    plan: &'a Plan,
    bindings: BTreeMap<ExecutionNodeRef, Bindings>,
    label_provider: &'a dyn LabelProvider,
    limits: QueryLimits,
    /// What remains of `limits.shared_steps` for later evaluations.
    shared_steps: Cell<usize>,
    nodes: BTreeMap<&'a OccurrenceId, &'a OccurrenceNode>,
    /// Every causal node by id, in graph order; a repeated id lists each.
    nodes_by_id: BTreeMap<&'a OccurrenceId, Vec<&'a OccurrenceNode>>,
    /// The causality graph's edges by source occurrence, for byte-flow paths.
    edges_from: BTreeMap<&'a OccurrenceId, Vec<&'a CausalEdge>>,
    effect_occurrences: Vec<Option<&'a OccurrenceId>>,
    reachability: OnceCell<Result<Reachability, DetailUnavailable>>,
    /// Whether each resource-transition edge carries state, by the edge's
    /// address in the plan: the answer depends on the edge alone, and every
    /// byte-flow search of every query asks it again.
    state_transitions: RefCell<BTreeMap<*const CausalEdge, bool>>,
    /// What each byte-flow source reaches, by source and traversal; it
    /// depends on the plan alone, so every query shares it.
    byte_reaches: RefCell<ByteReaches<'a>>,
    /// The candidates of each flow endpoint that names no binding, by the
    /// endpoint's address in the query under evaluation, which every binding
    /// of an enclosing effect would otherwise recompute.
    endpoint_candidates: RefCell<BTreeMap<*const Endpoint, Candidates<'a>>>,
    /// The scoped effects each unrelated `BindEffect` selector does not rule
    /// out, by the selector's address in the query under evaluation: a
    /// selection depends on the effect alone, and every binding of an
    /// enclosing effect would otherwise scan the plan again.
    selections: RefCell<BTreeMap<*const Selector, std::rc::Rc<Selections>>>,
    /// The version of the query under evaluation: a schema-3 label keeps its
    /// schema-3 meaning on a selection that is not concrete.
    schema_version: Cell<u32>,
    /// The plan effects, by ascending plan index, that `Effect` and
    /// `BindEffect` may select under the query being evaluated.
    /// Relationships, related bindings and flows still see every effect.
    scope: RefCell<Vec<usize>>,
    /// How the query under evaluation treats the absence of an effect.
    absence: Cell<Absence>,
}

impl<'a> Evaluator<'a> {
    /// Indexes `plan` for evaluation. The plan must already pass
    /// `effinterp_proto::validate_plan`: the constructor does not validate it,
    /// and answers over an invalid plan are unspecified. Each effect is paired
    /// with the first causal occurrence that owns it and no other effect has
    /// claimed; an effect without one has no occurrence for flows.
    pub fn new(
        plan: &'a Plan,
        bindings: BTreeMap<ExecutionNodeRef, Bindings>,
        label_provider: &'a dyn LabelProvider,
        limits: QueryLimits,
    ) -> Self {
        let mut nodes = BTreeMap::new();
        let mut nodes_by_id: BTreeMap<_, Vec<_>> = BTreeMap::new();
        for node in plan.causality.graph.iter().flat_map(|graph| &graph.nodes) {
            nodes.entry(&node.id).or_insert(node);
            nodes_by_id.entry(&node.id).or_default().push(node);
        }
        let mut edges_from: BTreeMap<_, Vec<_>> = BTreeMap::new();
        for edge in plan.causality.graph.iter().flat_map(|graph| &graph.edges) {
            edges_from.entry(&edge.from).or_default().push(edge);
        }
        // Interactions by execution and operation, in graph order, so each
        // effect searches only the occurrences that could own it.
        let mut interactions: BTreeMap<_, Vec<_>> = BTreeMap::new();
        for node in plan.causality.graph.iter().flat_map(|graph| &graph.nodes) {
            if let (Some(execution), OccurrenceKind::ResourceInteraction { operation, .. }) =
                (node.execution, &node.occurrence)
            {
                interactions
                    .entry((execution, operation.0.as_str()))
                    .or_default()
                    .push(node);
            }
        }
        let mut claimed = BTreeSet::new();
        let effect_occurrences = plan
            .effects
            .iter()
            .map(|effect| {
                let occurrence = interactions
                    .get(&(effect.execution, effect.operation.0.as_str()))
                    .into_iter()
                    .flatten()
                    .find(|node| {
                        !claimed.contains(&node.id) && occurrence_owns_effect(node, effect)
                    })
                    .map(|node| &node.id);
                if let Some(id) = occurrence {
                    claimed.insert(id);
                }
                occurrence
            })
            .collect();
        Self {
            plan,
            bindings,
            label_provider,
            limits,
            shared_steps: Cell::new(limits.shared_steps),
            nodes,
            nodes_by_id,
            edges_from,
            effect_occurrences,
            reachability: OnceCell::new(),
            state_transitions: RefCell::new(BTreeMap::new()),
            byte_reaches: RefCell::new(BTreeMap::new()),
            endpoint_candidates: RefCell::new(BTreeMap::new()),
            selections: RefCell::new(BTreeMap::new()),
            schema_version: Cell::new(SCHEMA_VERSION),
            scope: RefCell::new(Vec::new()),
            absence: Cell::new(Absence::Closure),
        }
    }

    /// Answers `query` over the whole plan, with each effect assertion's own
    /// closure deciding when absence is conclusive.
    pub fn evaluate(&self, query: &Query) -> Outcome {
        let scope = (0..self.plan.effects.len()).collect::<Vec<_>>();
        self.evaluate_in(query, &scope, Absence::Closure)
    }

    /// Answers `query` with only the plan effects at `scope`, ascending plan
    /// indices, selectable by `Effect` and `BindEffect`. An effect outside the
    /// scope can still be the related effect of a binding or lie on a flow,
    /// and keeps its plan index and occurrence, but is never selected or bound
    /// itself. `absence` says when finding no selected effect is conclusive.
    ///
    /// The evaluation may spend its own steps and what earlier evaluations
    /// left of the evaluator's shared steps, never more than `max_steps`, and
    /// is refused with [`Refusal::WorkLimit`] when it needs more.
    ///
    /// The query is validated on every call and refused when invalid; the
    /// scope is not. Scope entries must be strictly ascending plan-effect
    /// positions below `plan.effects.len()`, as [`Self::candidate_effects`]
    /// returns them.
    ///
    /// # Panics
    ///
    /// Debug builds panic on an unsorted, duplicated or out-of-range scope.
    /// Release builds panic on an out-of-range scope entry once an `Effect` or
    /// `BindEffect` assertion reads it.
    pub fn evaluate_in(&self, query: &Query, scope: &[usize], absence: Absence) -> Outcome {
        debug_assert!(scope.is_sorted_by(|a, b| a < b));
        debug_assert!(
            scope
                .last()
                .is_none_or(|last| *last < self.plan.effects.len())
        );
        let allowance = self.limits.max_steps.min(
            self.limits
                .own_steps
                .saturating_add(self.shared_steps.get()),
        );
        let mut budget = Budget(allowance);
        self.schema_version.set(query.schema_version);
        self.absence.set(absence);
        let mut current = self.scope.borrow_mut();
        current.clear();
        current.extend_from_slice(scope);
        drop(current);
        self.endpoint_candidates.borrow_mut().clear();
        self.selections.borrow_mut().clear();
        let outcome = query
            .validate_with(self.limits, absence)
            .and_then(|()| self.assertion(&query.assertion, &BTreeMap::new(), 0, &mut budget));
        let drawn = (allowance - budget.0).saturating_sub(self.limits.own_steps);
        self.shared_steps.set(self.shared_steps.get() - drawn);
        outcome.unwrap_or_else(Outcome::Refused)
    }

    /// The plan indices, ascending, of the effects whose operation some
    /// selector of `query` names: the candidates a query that binds no
    /// effect is evaluated against, one scope each, so each match stays
    /// independent of the other effects. Only selector operations are read:
    /// the query is not validated here, so an invalid query still yields
    /// candidates that [`Self::evaluate_in`] then refuses.
    pub fn candidate_effects(&self, query: &Query) -> Vec<usize> {
        let selectors = query.effect_selectors();
        self.plan
            .effects
            .iter()
            .enumerate()
            .filter(|(_, effect)| {
                selectors
                    .iter()
                    .any(|selector| selector.operation.matches(effect.operation.as_str()))
            })
            .map(|(index, _)| index)
            .collect()
    }

    fn assertion(
        &self,
        assertion: &Assertion,
        effect_bindings: &BTreeMap<String, usize>,
        depth: usize,
        budget: &mut Budget,
    ) -> Result<Outcome, Refusal> {
        if depth > self.limits.max_assertion_depth {
            return Err(Refusal::WorkLimit);
        }
        match assertion {
            Assertion::All { assertions } => {
                let mut witnesses = Vec::new();
                let mut unknowns = Vec::new();
                for assertion in assertions {
                    match self.assertion(assertion, effect_bindings, depth + 1, budget)? {
                        Outcome::Match(witness) => witnesses.push(witness),
                        Outcome::NoMatch => return Ok(Outcome::NoMatch),
                        Outcome::Indeterminate(reasons) => unknowns.extend(reasons),
                        Outcome::Refused(refusal) => return Err(refusal),
                    }
                }
                Ok(if unknowns.is_empty() {
                    Outcome::Match(Witness::All { witnesses })
                } else {
                    Outcome::Indeterminate(unknowns)
                })
            }
            Assertion::Any { assertions } => {
                let mut unknowns = Vec::new();
                for (index, assertion) in assertions.iter().enumerate() {
                    match self.assertion(assertion, effect_bindings, depth + 1, budget)? {
                        Outcome::Match(witness) => {
                            return Ok(Outcome::Match(Witness::Any {
                                index,
                                witness: Box::new(witness),
                            }));
                        }
                        Outcome::NoMatch => {}
                        Outcome::Indeterminate(reasons) => unknowns.extend(reasons),
                        Outcome::Refused(refusal) => return Err(refusal),
                    }
                }
                Ok(if unknowns.is_empty() {
                    Outcome::NoMatch
                } else {
                    Outcome::Indeterminate(unknowns)
                })
            }
            Assertion::Not { assertion } => Ok(
                match self.assertion(assertion, effect_bindings, depth + 1, budget)? {
                    Outcome::Match(_) => Outcome::NoMatch,
                    Outcome::NoMatch => Outcome::Match(Witness::Not),
                    Outcome::Indeterminate(unknowns) => Outcome::Indeterminate(unknowns),
                    Outcome::Refused(refusal) => return Err(refusal),
                },
            ),
            Assertion::Effect { selector, closure } => {
                self.effect(selector, closure.as_ref(), budget)
            }
            Assertion::BindEffect {
                name,
                selector,
                closure,
                assertion,
                related,
            } => self.bind_effect(
                name,
                selector,
                closure.as_ref(),
                assertion,
                BindingScope {
                    related: related.as_ref(),
                    effect_bindings,
                    depth,
                },
                budget,
            ),
            Assertion::RelatedEffect {
                binding,
                relationship,
                selector,
                closure,
            } => self.related_effect(
                binding,
                *relationship,
                selector,
                closure.as_ref(),
                effect_bindings,
                budget,
            ),
            Assertion::Flow {
                source,
                destination,
                traversal,
                provenance,
            } => self.flow(
                source,
                destination,
                traversal.clone(),
                *provenance,
                effect_bindings,
                budget,
            ),
            Assertion::SubjectKind { kinds } => Ok(self.subject_kind(kinds)),
            Assertion::Coverage { domain } => {
                Ok(match self.plan.coverage.0.get(&Domain(domain.clone())) {
                    Some(claim) if claim.level == CoverageLevel::Full && claim.gaps.is_empty() => {
                        Outcome::Match(Witness::Coverage {
                            domain: domain.clone(),
                        })
                    }
                    _ => Outcome::NoMatch,
                })
            }
            Assertion::TransferDestinations {
                binding,
                count,
                destination,
            } => self.transfer_destinations(effect_bindings[binding], *count, destination, budget),
            Assertion::Boundary {
                reason,
                class,
                domains,
                detail,
                provenance,
            } => self.boundary(
                reason,
                *class,
                domains.as_ref(),
                detail.as_ref(),
                *provenance,
                budget,
            ),
        }
    }

    fn effect(
        &self,
        selector: &Selector,
        closure: Option<&Closure>,
        budget: &mut Budget,
    ) -> Result<Outcome, Refusal> {
        let mut unknowns = Vec::new();
        for &index in self.scope.borrow().iter() {
            let effect = &self.plan.effects[index];
            // An effect of another operation is never selected, so it is
            // never examined either.
            if !selector.operation.matches(effect.operation.as_str()) {
                continue;
            }
            budget.charge()?;
            match self.select_effect(index, selector)? {
                Truth::True => {
                    return Ok(Outcome::Match(Witness::Effect {
                        effect: effect.id.clone(),
                    }));
                }
                Truth::False => {}
                Truth::Unknown(reasons) => unknowns.extend(reasons),
            }
        }
        Ok(self.effect_absence(closure, unknowns))
    }

    fn bind_effect(
        &self,
        name: &str,
        selector: &Selector,
        closure: Option<&Closure>,
        assertion: &Assertion,
        scope: BindingScope<'_>,
        budget: &mut Budget,
    ) -> Result<Outcome, Refusal> {
        let mut unknowns = Vec::new();
        let cached = scope.related.is_none().then(|| self.selections(selector));
        let indices = match &cached {
            Some(candidates) => candidates.iter().map(|(index, _)| *index).collect(),
            None => self.scope.borrow().clone(),
        };
        for (position, index) in indices.into_iter().enumerate() {
            let selected = match (&cached, scope.related) {
                (Some(candidates), _) => {
                    budget.charge()?;
                    candidates[position].1.clone()?
                }
                (None, Some(related)) => {
                    if !selector
                        .operation
                        .matches(self.plan.effects[index].operation.as_str())
                    {
                        continue;
                    }
                    budget.charge()?;
                    self.relation(
                        scope.effect_bindings[&related.binding],
                        index,
                        related.relationship,
                    )
                    .and(|| self.select_effect(index, selector))?
                }
                (None, None) => unreachable!("an unrelated binding is cached"),
            };
            if selected == Truth::False {
                continue;
            }
            let effect = &self.plan.effects[index];
            let mut nested_bindings = scope.effect_bindings.clone();
            nested_bindings.insert(name.to_owned(), index);
            let nested = self.assertion(assertion, &nested_bindings, scope.depth + 1, budget)?;
            match (selected, nested) {
                (Truth::True, Outcome::Match(witness)) => {
                    return Ok(Outcome::Match(Witness::BindEffect {
                        name: name.to_owned(),
                        effect: effect.id.clone(),
                        witness: Box::new(witness),
                    }));
                }
                (Truth::True, Outcome::NoMatch) | (Truth::Unknown(_), Outcome::NoMatch) => {}
                (Truth::True, Outcome::Indeterminate(reasons)) => unknowns.extend(reasons),
                (Truth::Unknown(reasons), Outcome::Match(_)) => unknowns.extend(reasons),
                (Truth::Unknown(mut reasons), Outcome::Indeterminate(nested)) => {
                    reasons.extend(nested);
                    unknowns.extend(reasons);
                }
                (_, Outcome::Refused(refusal)) => return Err(refusal),
                (Truth::False, _) => unreachable!("false candidates are skipped"),
            }
        }
        Ok(self.effect_absence(closure, unknowns))
    }

    /// The scoped effects `selector` does not rule out, in scope order. The
    /// search costs no steps: a binding charges one for each candidate it
    /// considers, never more than a scan of every effect would.
    fn selections(&self, selector: &Selector) -> std::rc::Rc<Selections> {
        let key = selector as *const Selector;
        if let Some(candidates) = self.selections.borrow().get(&key) {
            return candidates.clone();
        }
        let candidates: std::rc::Rc<Selections> = std::rc::Rc::new(
            self.scope
                .borrow()
                .iter()
                .filter(|&&index| {
                    selector
                        .operation
                        .matches(self.plan.effects[index].operation.as_str())
                })
                .filter_map(|&index| match self.select_effect(index, selector) {
                    Ok(Truth::False) => None,
                    selected => Some((index, selected)),
                })
                .collect(),
        );
        self.selections.borrow_mut().insert(key, candidates.clone());
        candidates
    }

    fn related_effect(
        &self,
        binding: &str,
        relationship: EffectRelationship,
        selector: &Selector,
        closure: Option<&Closure>,
        effect_bindings: &BTreeMap<String, usize>,
        budget: &mut Budget,
    ) -> Result<Outcome, Refusal> {
        let bound = effect_bindings[binding];
        let mut unknowns = Vec::new();
        for (index, effect) in self.plan.effects.iter().enumerate() {
            if !selector.operation.matches(effect.operation.as_str()) {
                continue;
            }
            budget.charge()?;
            match self
                .relation(bound, index, relationship)
                .and(|| self.select_effect(index, selector))?
            {
                Truth::True => {
                    return Ok(Outcome::Match(Witness::RelatedEffect {
                        effect: effect.id.clone(),
                    }));
                }
                Truth::False => {}
                Truth::Unknown(reasons) => unknowns.extend(reasons),
            }
        }
        Ok(self.effect_absence(closure, unknowns))
    }

    /// Whether the effect at `index` stands in `relationship` to the bound
    /// effect at `bound`. Plan order is the order of `plan.effects`.
    fn relation(&self, bound: usize, index: usize, relationship: EffectRelationship) -> Truth {
        let (bound_effect, effect) = (&self.plan.effects[bound], &self.plan.effects[index]);
        if relationship.same_execution && effect.execution != bound_effect.execution
            || relationship.same_realm && effect.realm != bound_effect.realm
            || relationship.after && index <= bound
        {
            Truth::False
        } else if relationship.same_resource {
            same_resource(bound_effect, effect, self.schema_version.get())
        } else {
            Truth::True
        }
    }

    fn select_effect(&self, index: usize, selector: &Selector) -> Result<Truth, Refusal> {
        let effect = &self.plan.effects[index];
        let execution = self
            .plan
            .execution_graph
            .nodes
            .get(effect.execution.0 as usize);
        self.select(
            selector,
            EffectTarget {
                operation: &effect.operation,
                resource: &effect.resource,
                attributes: &effect.attributes,
                realm: &effect.realm,
                modality: Some(effect.modality),
                request_assurance: Some(effect.request_assurance),
                condition: Some(&effect.condition),
                execution_assurance: execution.map(|node| node.assurance),
            },
            Some(effect.execution),
            self.bindings.get(&effect.execution),
            Some(&effect.id),
        )
    }

    /// The resource interactions the bound effect's content is transferred
    /// into, checked against `count` and `destination`.
    fn transfer_destinations(
        &self,
        bound: usize,
        count: u32,
        destination: &ResourcePredicate,
        budget: &mut Budget,
    ) -> Result<Outcome, Refusal> {
        let Some(graph) = &self.plan.causality.graph else {
            return Ok(Outcome::Indeterminate(vec![
                Unknown::CausalDetailUnavailable,
            ]));
        };
        let effect = &self.plan.effects[bound];
        let carriers = graph
            .nodes
            .iter()
            .filter(|node| {
                node.execution == Some(effect.execution)
                    && node.realm == effect.realm
                    && node.condition == effect.condition
                    && node.modality == effect.modality
                    && node.provenance == effect.provenance
                    && matches!(&node.occurrence, OccurrenceKind::ResourceInteraction {
                        resource, ..
                    } if *resource == effect.resource)
            })
            .map(|node| &node.id)
            .collect::<BTreeSet<_>>();
        let mut destinations = Vec::new();
        for edge in &graph.edges {
            budget.charge()?;
            if edge.reason != CausalReason::ResourceTransfer
                || edge.condition != effect.condition
                || !carriers.contains(&edge.from)
            {
                continue;
            }
            if let Some(node) = self.nodes.get(&edge.to)
                && node.condition == effect.condition
                && matches!(node.occurrence, OccurrenceKind::ResourceInteraction { .. })
            {
                destinations.push(*node);
            }
        }
        if destinations.len() != count as usize {
            return Ok(Outcome::NoMatch);
        }
        let mut truth = Truth::True;
        for node in &destinations {
            let OccurrenceKind::ResourceInteraction {
                operation,
                resource,
                attributes,
            } = &node.occurrence
            else {
                unreachable!("destinations are resource interactions");
            };
            truth = truth.and(|| {
                self.resource_predicate(
                    destination,
                    self.occurrence_target(node, operation, resource, attributes),
                    node.execution,
                    node.execution
                        .and_then(|execution| self.bindings.get(&execution)),
                    self.occurrence_effect(&node.id),
                    0,
                )
            })?;
        }
        Ok(match truth {
            Truth::True => Outcome::Match(Witness::TransferDestinations {
                destinations: destinations.iter().map(|node| node.id.clone()).collect(),
            }),
            Truth::False => Outcome::NoMatch,
            Truth::Unknown(unknowns) => Outcome::Indeterminate(unknowns),
        })
    }

    /// The plan effect whose occurrence this is.
    fn occurrence_effect(&self, occurrence: &OccurrenceId) -> Option<&'a EffectId> {
        self.effect_occurrences
            .iter()
            .position(|owned| *owned == Some(occurrence))
            .map(|index| &self.plan.effects[index].id)
    }

    fn occurrence_target<'t>(
        &self,
        node: &'t OccurrenceNode,
        operation: &'t effinterp_proto::Operation,
        resource: &'t ResourceExpr,
        attributes: &'t BTreeMap<String, AttrValue>,
    ) -> EffectTarget<'t> {
        EffectTarget {
            operation,
            resource,
            attributes,
            realm: &node.realm,
            modality: Some(node.modality),
            request_assurance: None,
            condition: Some(&node.condition),
            execution_assurance: node.execution.and_then(|execution| {
                self.plan
                    .execution_graph
                    .nodes
                    .get(execution.0 as usize)
                    .map(|execution| execution.assurance)
            }),
        }
    }

    fn effect_absence(&self, closure: Option<&Closure>, unknowns: Vec<Unknown>) -> Outcome {
        if !unknowns.is_empty() {
            return Outcome::Indeterminate(unknowns);
        }
        let domain = match (self.absence.get(), closure) {
            (Absence::Conclusive, _) => return Outcome::NoMatch,
            (Absence::Closure, Some(Closure::DomainFullOrBoundaryFree { domain })) => domain,
            (Absence::Closure, None) => unreachable!("validation requires a closure"),
        };
        let full = self.plan.coverage.level(&Domain(domain.clone())) == Some(CoverageLevel::Full);
        if full || self.plan.boundaries.is_empty() {
            Outcome::NoMatch
        } else {
            Outcome::Indeterminate(vec![Unknown::DomainNotClosed {
                domain: domain.clone(),
            }])
        }
    }

    fn flow(
        &self,
        source: &Endpoint,
        destination: &Endpoint,
        traversal: Traversal,
        provenance: RouteProvenance,
        effect_bindings: &BTreeMap<String, usize>,
        budget: &mut Budget,
    ) -> Result<Outcome, Refusal> {
        let Some(graph) = &self.plan.causality.graph else {
            return Ok(Outcome::Indeterminate(vec![
                Unknown::CausalDetailUnavailable,
            ]));
        };
        let unavailable = [source, destination]
            .into_iter()
            .filter_map(|endpoint| match endpoint {
                Endpoint::EffectBinding { name } => {
                    let index = effect_bindings[name];
                    self.effect_occurrences[index].is_none().then(|| {
                        Unknown::EffectOccurrenceUnavailable {
                            effect: self.plan.effects[index].id.clone(),
                        }
                    })
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        if !unavailable.is_empty() {
            return Ok(Outcome::Indeterminate(unavailable));
        }
        let mut unknowns = Vec::new();
        let mut incomplete = Vec::new();
        match traversal {
            Traversal::ResourcePairs => {
                let Ok(reachability) = self.reachability.get_or_init(|| reachable_pairs(self.plan))
                else {
                    return Ok(Outcome::Indeterminate(vec![
                        Unknown::CausalDetailUnavailable,
                    ]));
                };
                for reach in reachability.pairs() {
                    budget.charge()?;
                    let from = &reach.from.occurrence_id;
                    let to = &reach.to.occurrence_id;
                    let truth = self
                        .endpoint(source, from, effect_bindings)?
                        .and(|| self.endpoint(destination, to, effect_bindings))?
                        .and(|| Ok(self.route(provenance, &reach.path)))?;
                    match truth {
                        Truth::True => {
                            return Ok(Outcome::Match(Witness::Flow {
                                source: from.clone(),
                                destination: to.clone(),
                                route: reach.path.clone(),
                            }));
                        }
                        Truth::False => {}
                        Truth::Unknown(reasons) => unknowns.extend(reasons),
                    }
                }
                for (id, _) in self.candidates(source, effect_bindings, budget)? {
                    if !reachability.is_complete_from(id) {
                        incomplete.push(id.clone());
                    }
                }
            }
            Traversal::OccurrencePath => {
                let sources = self.candidates(source, effect_bindings, budget)?;
                let destinations = self.candidates(destination, effect_bindings, budget)?;
                for (from, from_truth) in &sources {
                    for (to, to_truth) in &destinations {
                        budget.charge()?;
                        let Some(route) = causal_path_in_graph(graph, from, to) else {
                            continue;
                        };
                        let truth = from_truth
                            .clone()
                            .and(|| Ok(to_truth.clone()))?
                            .and(|| Ok(self.route(provenance, &route)))?;
                        match truth {
                            Truth::True => {
                                return Ok(Outcome::Match(Witness::Flow {
                                    source: (*from).clone(),
                                    destination: (*to).clone(),
                                    route,
                                }));
                            }
                            Truth::False => {}
                            Truth::Unknown(reasons) => unknowns.extend(reasons),
                        }
                    }
                }
            }
            Traversal::ByteFlow { assurance, edges } => {
                let destinations = self.candidates(destination, effect_bindings, budget)?;
                // With nothing to reach, no source is searched.
                let sources = if destinations.is_empty() {
                    Vec::new()
                } else {
                    self.candidates(source, effect_bindings, budget)?
                };
                for (from, from_truth) in &sources {
                    let reached = self.byte_reach(from, assurance, &edges);
                    for (to, to_truth) in &destinations {
                        if !reached.contains(*to) {
                            continue;
                        }
                        budget.charge()?;
                        let Some((route, route_truth)) =
                            self.byte_path(from, to, assurance, &edges)?
                        else {
                            continue;
                        };
                        let truth = from_truth
                            .clone()
                            .and(|| Ok(to_truth.clone()))?
                            .and(|| Ok(route_truth))?
                            .and(|| Ok(self.route(provenance, &route)))?;
                        match truth {
                            Truth::True => {
                                return Ok(Outcome::Match(Witness::Flow {
                                    source: (*from).clone(),
                                    destination: (*to).clone(),
                                    route,
                                }));
                            }
                            Truth::False => {}
                            Truth::Unknown(reasons) => unknowns.extend(reasons),
                        }
                    }
                }
            }
        }
        if self.plan.causality.coverage.level != CoverageLevel::Full {
            unknowns.push(Unknown::CausalCoverageNotFull);
        }
        if !incomplete.is_empty() {
            unknowns.push(Unknown::TraversalIncomplete {
                sources: incomplete,
            });
        }
        Ok(if unknowns.is_empty() {
            Outcome::NoMatch
        } else {
            Outcome::Indeterminate(unknowns)
        })
    }

    fn subject_kind(&self, kinds: &[SubjectKind]) -> Outcome {
        let actual = match &self.plan.subject {
            Subject::Exec { .. } => SubjectKind::Exec,
            Subject::Shell { .. } => SubjectKind::ShellCommand,
            Subject::Sql { .. } => SubjectKind::Sql,
            Subject::Source { .. } => SubjectKind::Source,
            Subject::ToolCall { call, .. } => SubjectKind::NativeTool(match call {
                ToolCall::FileRead(_) => NativeTool::FileRead,
                ToolCall::FileWrite(_) => NativeTool::FileWrite,
                ToolCall::FileTransfer(_) => NativeTool::FileTransfer,
                ToolCall::FileDelete(_) => NativeTool::FileDelete,
                ToolCall::FileEdit(_) => NativeTool::FileEdit,
                ToolCall::FileEditBatch(_) => NativeTool::FileEditBatch,
                ToolCall::FilePatch(_) => NativeTool::FilePatch,
                ToolCall::FsGlob(_) => NativeTool::FsGlob,
                ToolCall::FsFind(_) => NativeTool::FsFind,
                ToolCall::FsGrep(_) => NativeTool::FsGrep,
                ToolCall::FsList(_) => NativeTool::FsList,
                // A typed MCP call is known not to be any native tool.
                ToolCall::McpCall(_) => return Outcome::NoMatch,
                ToolCall::Unknown(_) => {
                    return if kinds
                        .iter()
                        .any(|kind| matches!(kind, SubjectKind::NativeTool(_)))
                    {
                        Outcome::Indeterminate(vec![Unknown::SubjectToolUnavailable])
                    } else {
                        Outcome::NoMatch
                    };
                }
            }),
        };
        if kinds.contains(&actual) {
            Outcome::Match(Witness::SubjectKind { kind: actual })
        } else {
            Outcome::NoMatch
        }
    }

    fn boundary(
        &self,
        reason: &str,
        class: Option<BoundaryClass>,
        domains: Option<&BoundaryDomainsPredicate>,
        detail: Option<&TextPredicate>,
        provenance: Option<BoundaryProvenancePredicate>,
        budget: &mut Budget,
    ) -> Result<Outcome, Refusal> {
        let mut unknowns = Vec::new();
        for (index, boundary) in self.plan.boundaries.iter().enumerate() {
            budget.charge()?;
            let class = class.map_or(Truth::True, |expected| (boundary.class == expected).into());
            let domains = domains.map_or(Truth::True, |expected| {
                expected.matches(&boundary.domains).into()
            });
            let detail = match (detail, boundary.detail.as_deref()) {
                (None, _) => Truth::True,
                (Some(expected), Some(actual)) => expected.matches(actual).into(),
                (Some(_), None) => Truth::Unknown(vec![Unknown::BoundaryDetailUnavailable]),
            };
            let provenance = match (provenance, boundary.provenance.is_empty()) {
                (None, _) => Truth::True,
                (Some(BoundaryProvenancePredicate::Nonempty), false) => Truth::True,
                (Some(BoundaryProvenancePredicate::Nonempty), true) => {
                    Truth::Unknown(vec![Unknown::BoundaryProvenanceUnavailable])
                }
            };
            let truth = Truth::from(boundary.reason.as_str() == reason)
                .and(|| Ok(class))?
                .and(|| Ok(domains))?
                .and(|| Ok(detail))?
                .and(|| Ok(provenance))?;
            match truth {
                Truth::True => {
                    return Ok(Outcome::Match(Witness::Boundary {
                        boundary: BoundaryRef(index as u32),
                    }));
                }
                Truth::False => {}
                Truth::Unknown(reasons) => unknowns.extend(reasons),
            }
        }
        Ok(if unknowns.is_empty() {
            Outcome::NoMatch
        } else {
            Outcome::Indeterminate(unknowns)
        })
    }

    fn select(
        &self,
        selector: &Selector,
        target: EffectTarget<'_>,
        execution: Option<ExecutionNodeRef>,
        bindings: Option<&Bindings>,
        effect: Option<&EffectId>,
    ) -> Result<Truth, Refusal> {
        if !selector.operation.matches(target.operation.as_str()) {
            return Ok(Truth::False);
        }
        let request_assurance = match (selector.request_assurance, target.request_assurance) {
            (None, _) => Truth::True,
            (Some(expected), Some(actual)) => (actual == expected).into(),
            (Some(_), None) => Truth::Unknown(vec![Unknown::RequestAssuranceUnavailable]),
        };
        let condition = match (selector.condition, target.condition) {
            (None, _) => Truth::True,
            (Some(ConditionPredicate::Unconditional), Some(actual)) => actual.is_none().into(),
            (Some(ConditionPredicate::Present), Some(actual)) => actual.is_some().into(),
            (Some(ConditionPredicate::SuccessPath), Some(actual)) => {
                success_path(actual.as_ref(), self.limits)?
            }
            (Some(ConditionPredicate::Complete), Some(None)) => Truth::True,
            (Some(ConditionPredicate::Complete), Some(Some(actual))) => self.complete(actual, 0)?,
            (Some(_), None) => Truth::Unknown(vec![Unknown::ConditionUnavailable]),
        };
        let modality = match (selector.modality, target.modality) {
            (None, _) => Truth::True,
            (Some(expected), Some(actual)) => (actual == expected).into(),
            (Some(_), None) => Truth::Unknown(vec![Unknown::ModalityUnavailable]),
        };
        let execution_assurance = match (selector.execution_assurance, target.execution_assurance) {
            (None, _) => Truth::True,
            (Some(expected), Some(actual)) => (actual == expected).into(),
            (Some(_), None) => Truth::Unknown(vec![Unknown::ExecutionAssuranceUnavailable]),
        };
        let realm = match selector.realm {
            None => Truth::True,
            Some(expected) => expected.matches(target.realm).into(),
        };
        let resource =
            self.resource_predicate(&selector.resource, target, execution, bindings, effect, 0)?;
        let attributes = selector
            .attributes
            .iter()
            .try_fold(Truth::True, |truth, predicate| {
                truth.and(|| Ok(predicate.test(target.attributes)))
            })?;
        request_assurance
            .and(|| Ok(condition))?
            .and(|| Ok(modality))?
            .and(|| Ok(execution_assurance))?
            .and(|| Ok(realm))?
            .and(|| Ok(resource))?
            .and(|| Ok(attributes))
    }

    fn complete(&self, condition: &Condition, depth: usize) -> Result<Truth, Refusal> {
        if depth > self.limits.max_condition_depth {
            return Err(Refusal::WorkLimit);
        }
        match condition {
            Condition::Atom { .. } => Ok(Truth::True),
            Condition::All { conditions } | Condition::Any { conditions } => {
                let mut truth = Truth::True;
                for condition in conditions {
                    truth = truth.and(|| self.complete(condition, depth + 1))?;
                }
                Ok(truth)
            }
            Condition::Widened => Ok(Truth::Unknown(vec![Unknown::ConditionIncomplete])),
        }
    }

    /// Whether a byte route may pass an occurrence or edge under `condition`.
    /// A route stays on the success path; from schema 7 it may also stay
    /// under its source's own condition, so a flow within one branch arm
    /// holds whenever that arm runs. It may also enter the arms its
    /// destination runs in, so a file the condition command of
    /// `if curl -o f URL; then . ./f; fi` writes reaches the body that runs
    /// it: whenever the destination runs, every occurrence on the route has.
    /// A route never joins two arms of one construct.
    fn route_condition(
        &self,
        condition: Option<&Condition>,
        source: Option<&Condition>,
        destination: Option<&Condition>,
    ) -> Result<Truth, Refusal> {
        match condition {
            None => Ok(Truth::True),
            Some(condition)
                if self.schema_version.get() >= SCHEMA_VERSION
                    && (source == Some(condition)
                        || within_route_arms(condition, source, destination)) =>
            {
                Ok(Truth::True)
            }
            Some(condition) => success_path(Some(condition), self.limits),
        }
    }

    fn byte_path(
        &self,
        from: &OccurrenceId,
        to: &OccurrenceId,
        assurance: ByteFlowAssurance,
        edges: &[ByteFlowEdgeKind],
    ) -> Result<Option<(Vec<OccurrenceId>, Truth)>, Refusal> {
        let (Some(source), Some(destination)) = (self.nodes.get(from), self.nodes.get(to)) else {
            return Ok(None);
        };
        if let Some(route) = causal_path_in_graph_with(
            &self.nodes,
            &self.edges_from,
            from,
            to,
            |node| {
                matches!(
                    self.byte_occurrence(node, source, destination),
                    Ok(Truth::True)
                )
            },
            |edge| {
                matches!(
                    self.byte_edge(edge, source, destination, assurance, edges),
                    Ok(Truth::True)
                )
            },
        ) {
            return Ok(Some((route, Truth::True)));
        }
        let possible = causal_path_in_graph_with(
            &self.nodes,
            &self.edges_from,
            from,
            to,
            |node| {
                !matches!(
                    self.byte_occurrence(node, source, destination),
                    Ok(Truth::False)
                )
            },
            |edge| {
                !matches!(
                    self.byte_edge(edge, source, destination, assurance, edges),
                    Ok(Truth::False)
                )
            },
        );
        let Some(route) = possible else {
            return Ok(None);
        };
        let mut truth = Truth::True;
        for id in &route {
            let Some(node) = self.nodes.get(id) else {
                return Ok(None);
            };
            truth = truth.and(|| self.byte_occurrence(node, source, destination))?;
        }
        for pair in route.windows(2) {
            truth = truth.and(|| {
                self.byte_link(&pair[0], &pair[1], source, destination, assurance, edges)
            })?;
        }
        Ok(Some((route, truth)))
    }

    /// The occurrences in `from`'s realm that some chain of byte edges of
    /// the traversal's kinds reaches from it, `from` included, whatever their
    /// conditions, and the code a launch argument among them hands another
    /// realm (see [`Self::launch_argument`]). A byte route needs such a chain, so a destination outside
    /// this set is never searched; one search per source then serves every
    /// destination. Like the route search it narrows, it costs no steps: a
    /// step is charged for each destination it reaches instead.
    fn byte_reach(
        &self,
        from: &'a OccurrenceId,
        assurance: ByteFlowAssurance,
        edges: &[ByteFlowEdgeKind],
    ) -> std::rc::Rc<BTreeSet<&'a OccurrenceId>> {
        let key = (from, assurance, edges.to_vec());
        if let Some(reached) = self.byte_reaches.borrow().get(&key) {
            return reached.clone();
        }
        let mut reached = BTreeSet::new();
        let Some(source) = self.nodes.get(from) else {
            return std::rc::Rc::new(reached);
        };
        let mut pending = vec![from];
        reached.insert(from);
        while let Some(id) = pending.pop() {
            for edge in self.edges_from.get(id).into_iter().flatten() {
                let Some(node) = self.nodes.get(&edge.to) else {
                    continue;
                };
                if self.byte_edge_kind(edge, assurance, edges) == Truth::False {
                    continue;
                }
                // Nothing is followed onward from the other realm.
                if node.realm != source.realm {
                    reached.insert(&edge.to);
                } else if reached.insert(&edge.to) {
                    pending.push(&edge.to);
                }
            }
        }
        let reached = std::rc::Rc::new(reached);
        self.byte_reaches.borrow_mut().insert(key, reached.clone());
        reached
    }

    fn byte_occurrence(
        &self,
        node: &OccurrenceNode,
        source: &OccurrenceNode,
        destination: &OccurrenceNode,
    ) -> Result<Truth, Refusal> {
        // Only the destination may lie in another realm, and only a launch
        // argument edge leads there (`byte_edge_kind`).
        if node.realm != source.realm && node.id != destination.id {
            return Ok(Truth::False);
        }
        self.route_condition(
            node.condition.as_ref(),
            source.condition.as_ref(),
            destination.condition.as_ref(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn byte_link(
        &self,
        from: &OccurrenceId,
        to: &OccurrenceId,
        source: &OccurrenceNode,
        destination: &OccurrenceNode,
        assurance: ByteFlowAssurance,
        edges: &[ByteFlowEdgeKind],
    ) -> Result<Truth, Refusal> {
        let mut truth = Truth::False;
        for edge in self.edges_from.get(from).into_iter().flatten() {
            if edge.to == *to {
                truth = truth.or(|| self.byte_edge(edge, source, destination, assurance, edges))?;
            }
        }
        Ok(truth)
    }

    fn byte_edge(
        &self,
        edge: &CausalEdge,
        source: &OccurrenceNode,
        destination: &OccurrenceNode,
        assurance: ByteFlowAssurance,
        edges: &[ByteFlowEdgeKind],
    ) -> Result<Truth, Refusal> {
        self.byte_edge_kind(edge, assurance, edges).and(|| {
            self.route_condition(
                edge.condition.as_ref(),
                source.condition.as_ref(),
                destination.condition.as_ref(),
            )
        })
    }

    /// Whether `edge` is of a kind the traversal follows, before conditions.
    fn byte_edge_kind(
        &self,
        edge: &CausalEdge,
        assurance: ByteFlowAssurance,
        edges: &[ByteFlowEdgeKind],
    ) -> Truth {
        let realm = |id| self.nodes.get(id).map(|node| &node.realm);
        if realm(&edge.from) != realm(&edge.to) && !self.launch_argument(edge) {
            return Truth::False;
        }
        match edge.reason {
            CausalReason::ValueDependency if edges.contains(&ByteFlowEdgeKind::ValueDependency) => {
                match assurance {
                    ByteFlowAssurance::Exact => (edge.assurance == CausalAssurance::Exact).into(),
                    ByteFlowAssurance::Conservative => Truth::True,
                }
            }
            CausalReason::ResourceTransfer
                if edges.contains(&ByteFlowEdgeKind::ContentPreservingTransfer) =>
            {
                Truth::True
            }
            CausalReason::Alias if edges.contains(&ByteFlowEdgeKind::Alias) => {
                (edge.assurance == CausalAssurance::Exact).into()
            }
            CausalReason::ResourceTransition
                if edges.contains(&ByteFlowEdgeKind::StateTransition) =>
            {
                self.state_transition(edge).into()
            }
            CausalReason::ValueDependency
            | CausalReason::ResourceTransfer
            | CausalReason::Alias
            | CausalReason::ResourceTransition
            | CausalReason::ControlDependency
            | CausalReason::Launch
            | CausalReason::Containment => Truth::False,
        }
    }

    /// A launcher's own argument that the command it starts in another realm
    /// runs as code, as `docker exec box sh -c "$SCRIPT"` hands the script to
    /// the container's shell. Realms keep their resources apart, so a byte
    /// route otherwise stays in its source's realm; these bytes are the one
    /// thing the launch itself carries across, and the plan states both the
    /// launch and the argument the launched command executes.
    fn launch_argument(&self, edge: &CausalEdge) -> bool {
        let (Some(from), Some(to)) = (self.nodes.get(&edge.from), self.nodes.get(&edge.to)) else {
            return false;
        };
        matches!(from.occurrence, OccurrenceKind::Port { port: Port::Arg(_) })
            && occurrence_operation(to) == Some("process.code_execution")
            && occurrence_attribute(to, "source") == Some(&AttrValue::String("argument".into()))
            && from
                .execution
                .zip(to.execution)
                .is_some_and(|(launcher, launched)| {
                    self.plan.execution_graph.edges.iter().any(|launch| {
                        launch.from == launcher && launch.to == launched && !launch.cycle
                    })
                })
    }

    fn state_transition(&self, edge: &CausalEdge) -> bool {
        let key = std::ptr::from_ref(edge);
        if let Some(known) = self.state_transitions.borrow().get(&key) {
            return *known;
        }
        let carries = self.carries_state(edge);
        self.state_transitions.borrow_mut().insert(key, carries);
        carries
    }

    fn carries_state(&self, edge: &CausalEdge) -> bool {
        let Some(from) = self.nodes.get(&edge.from) else {
            return false;
        };
        let Some(to) = self.nodes.get(&edge.to) else {
            return false;
        };
        if from.realm != to.realm
            || occurrence_operation(from) == Some("filesystem.delete")
            || occurrence_operation(to) == Some("filesystem.write")
        {
            return false;
        }
        // A read that follows links takes what they lead to, not the state
        // of the path it names; a later read that does not read through them
        // finds only the links.
        if occurrence_operation(from) == Some("filesystem.read")
            && occurrence_operation(to) == Some("filesystem.read")
            && occurrence_attribute(from, "follow_links") == Some(&AttrValue::Bool(true))
            && !reads_through_links(to)
        {
            return false;
        }
        let edges_from = |id| self.edges_from.get(id).into_iter().flatten();
        let superseded = edges_from(&edge.from).any(|intermediate| {
            intermediate.to != edge.to
                && intermediate.reason == CausalReason::ResourceTransition
                && matches!(self.byte_edge_condition(intermediate), Ok(Truth::True))
                && self
                    .nodes
                    .get(&intermediate.to)
                    .is_some_and(|node| occurrence_operation(node) == Some("filesystem.write"))
                && edges_from(&intermediate.to).any(|later| {
                    later.to == edge.to
                        && later.reason == CausalReason::ResourceTransition
                        && matches!(self.byte_edge_condition(later), Ok(Truth::True))
                })
        });
        if superseded {
            return false;
        }
        match (occurrence_fs_path(from), occurrence_fs_path(to)) {
            (Some(from), Some(to)) => from == to || path_is_descendant(from, to),
            // A write to a path pattern, such as an extraction's target tree,
            // may have written any path it matches.
            (None, Some(to)) => match &from.occurrence {
                OccurrenceKind::ResourceInteraction {
                    resource:
                        ResourceExpr::Pattern {
                            pattern: effinterp_proto::ResourcePattern::FsPath { glob },
                        },
                    ..
                } => effinterp_proto::glob_match(glob, to).unwrap_or(true),
                _ => false,
            },
            _ => false,
        }
    }

    fn byte_edge_condition(&self, edge: &CausalEdge) -> Result<Truth, Refusal> {
        success_path(edge.condition.as_ref(), self.limits)
    }

    fn resource_predicate(
        &self,
        predicate: &ResourcePredicate,
        target: EffectTarget<'_>,
        execution: Option<ExecutionNodeRef>,
        bindings: Option<&Bindings>,
        effect: Option<&EffectId>,
        depth: usize,
    ) -> Result<Truth, Refusal> {
        if depth > self.limits.max_resource_depth {
            return Err(Refusal::WorkLimit);
        }
        Ok(match predicate {
            ResourcePredicate::Any => Truth::True,
            ResourcePredicate::All { predicates } => {
                let mut truth = Truth::True;
                for predicate in predicates {
                    truth = truth.and(|| {
                        self.resource_predicate(
                            predicate,
                            target,
                            execution,
                            bindings,
                            effect,
                            depth + 1,
                        )
                    })?;
                }
                truth
            }
            ResourcePredicate::AnyOf { predicates } => {
                let mut truth = Truth::False;
                for predicate in predicates {
                    truth = truth.or(|| {
                        self.resource_predicate(
                            predicate,
                            target,
                            execution,
                            bindings,
                            effect,
                            depth + 1,
                        )
                    })?;
                }
                truth
            }
            ResourcePredicate::Not { predicate } => self
                .resource_predicate(predicate, target, execution, bindings, effect, depth + 1)?
                .not(),
            ResourcePredicate::Rendered { projection, text } => text
                .matches(&match projection {
                    Projection::RealmScoped => {
                        render::rendered_resource_in_realm(target.realm, target.resource)
                    }
                    Projection::Resource => render::rendered_resource(target.resource),
                })
                .into(),
            ResourcePredicate::Relation(query) => match bindings {
                None => Truth::Unknown(vec![Unknown::BindingsUnavailable { execution }]),
                Some(bindings) => match query.evaluate(target, bindings) {
                    Match::Satisfied { .. } => Truth::True,
                    Match::NotSatisfied => Truth::False,
                    Match::Indeterminate {
                        reason: MatchReason::Limit,
                    } => return Err(Refusal::WorkLimit),
                    Match::Indeterminate {
                        reason: MatchReason::InvalidInput,
                    } => return Err(Refusal::InvalidInput("resource relation")),
                    Match::Indeterminate { reason } => {
                        Truth::Unknown(vec![Unknown::Relation(reason)])
                    }
                },
            },
            ResourcePredicate::Family { family } => resource_family(target.resource, family),
            ResourcePredicate::Variant { variant } => {
                identity(target.resource, variant).map_or_else(|truth| truth, |_| Truth::True)
            }
            ResourcePredicate::Label { label, observation } => match target.resource {
                ResourceExpr::Concrete { identity } => match self.label_provider.labels(
                    observation,
                    LabelResource {
                        realm: target.realm,
                        identity,
                        selection: LabelSelection::Direct,
                        effect,
                    },
                ) {
                    LabelStatus::Known(labels) => labels.contains(label).into(),
                    LabelStatus::Unknown => {
                        Truth::Unknown(vec![Unknown::LabelObservationUnavailable {
                            observation: observation.clone(),
                        }])
                    }
                },
                resource => {
                    match self.selection_label(
                        label,
                        observation,
                        target,
                        LabelSelection::Direct,
                        effect,
                    ) {
                        Some(truth) => truth,
                        None => match resource_domain(resource) {
                            Some(domain) if domain != "filesystem" => Truth::False,
                            _ => Truth::Unknown(vec![Unknown::ResourceIdentityUnavailable {
                                variant: ResourceVariant::FsPath,
                            }]),
                        },
                    }
                }
            },
            ResourcePredicate::InheritedLabel { label, observation } => match target.resource {
                ResourceExpr::Concrete {
                    identity: identity @ ResourceIdentity::FsPath { .. },
                } => match self.label_provider.labels(
                    observation,
                    LabelResource {
                        realm: target.realm,
                        identity,
                        selection: LabelSelection::ResourceOrAncestorDirectory,
                        effect,
                    },
                ) {
                    LabelStatus::Known(labels) => labels.contains(label).into(),
                    LabelStatus::Unknown => {
                        Truth::Unknown(vec![Unknown::LabelObservationUnavailable {
                            observation: observation.clone(),
                        }])
                    }
                },
                ResourceExpr::Concrete { .. } => Truth::False,
                resource => match self.selection_label(
                    label,
                    observation,
                    target,
                    LabelSelection::ResourceOrAncestorDirectory,
                    effect,
                ) {
                    Some(truth) => truth,
                    None => match resource_domain(resource) {
                        Some(domain) if domain != "filesystem" => Truth::False,
                        _ => Truth::Unknown(vec![Unknown::ResourceIdentityUnavailable {
                            variant: ResourceVariant::FsPath,
                        }]),
                    },
                },
            },
            ResourcePredicate::GitTreePathLabel { label, observation } => match target.resource {
                ResourceExpr::Concrete {
                    identity: repository @ ResourceIdentity::GitRepository { .. },
                } => match target.attributes.get("path") {
                    Some(AttrValue::String(path)) => label_truth(
                        label,
                        observation,
                        self.label_provider.selection_labels(
                            observation,
                            SelectionLabelResource {
                                realm: target.realm,
                                target: SelectionTarget::GitTreePath { repository, path },
                                selection: LabelSelection::Direct,
                                effect,
                            },
                        ),
                    ),
                    Some(_) => Truth::False,
                    None => Truth::Unknown(vec![Unknown::AttributeAbsent {
                        name: "path".into(),
                    }]),
                },
                ResourceExpr::Concrete { .. } => Truth::False,
                resource => match resource_domain(resource) {
                    Some(domain) if domain != "git" => Truth::False,
                    _ => Truth::Unknown(vec![Unknown::GitRepositoryUnavailable]),
                },
            },
            ResourcePredicate::ObservedPath { kind, observation } => match target.resource {
                path @ (ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { .. },
                }
                | ResourceExpr::Pattern {
                    pattern: ResourcePattern::FsPath { .. },
                }) => match self
                    .label_provider
                    .path_kind(observation, target.realm, path)
                {
                    PathKindStatus::Known(actual) => (actual == Some(*kind)).into(),
                    PathKindStatus::Unknown => {
                        Truth::Unknown(vec![Unknown::LabelObservationUnavailable {
                            observation: observation.clone(),
                        }])
                    }
                },
                ResourceExpr::Concrete { .. } => Truth::False,
                resource => match resource_domain(resource) {
                    Some(domain) if domain != "filesystem" => Truth::False,
                    _ => Truth::Unknown(vec![Unknown::ResourceIdentityUnavailable {
                        variant: ResourceVariant::FsPath,
                    }]),
                },
            },
            ResourcePredicate::StorageVolume { manager, name } => {
                match identity(target.resource, &ResourceVariant::StorageVolume) {
                    Err(truth) => truth,
                    Ok(ResourceIdentity::StorageVolume {
                        manager: actual_manager,
                        name: actual_name,
                    }) => optional_text(
                        manager.as_ref(),
                        Some(actual_manager),
                        ResourceField::StorageManager,
                    )
                    .and(|| {
                        Ok(optional_text(
                            name.as_ref(),
                            Some(actual_name),
                            ResourceField::StorageName,
                        ))
                    })?,
                    Ok(_) => unreachable!("resource variant checked"),
                }
            }
            ResourcePredicate::KubernetesResource {
                namespace,
                selection,
            } => match identity(target.resource, &ResourceVariant::KubernetesResource) {
                Err(truth) => truth,
                Ok(ResourceIdentity::KubernetesResource {
                    namespace: actual, ..
                }) => {
                    let namespace = match (namespace, actual) {
                        (None, _) => Truth::True,
                        (
                            Some(KubernetesNamespacePredicate::Cluster),
                            KubernetesNamespace::Cluster,
                        ) => Truth::True,
                        (
                            Some(KubernetesNamespacePredicate::Namespaced),
                            KubernetesNamespace::Namespaced { .. },
                        ) => Truth::True,
                        (Some(_), KubernetesNamespace::Unknown { .. }) => {
                            Truth::Unknown(vec![Unknown::ResourceFieldUnavailable {
                                field: ResourceField::KubernetesNamespace,
                            }])
                        }
                        (Some(_), _) => Truth::False,
                    };
                    namespace.and(|| match selection {
                        None => Ok(Truth::True),
                        Some(shape) => Ok(selection_shape(target, *shape, true)),
                    })?
                }
                Ok(_) => unreachable!("resource variant checked"),
            },
            ResourcePredicate::ManagedInfrastructure { whole_stack } => {
                match identity(target.resource, &ResourceVariant::ManagedInfrastructure) {
                    Err(truth) => truth,
                    Ok(_) => match target.attributes.get("whole_stack") {
                        Some(AttrValue::Bool(actual)) => (*actual == *whole_stack).into(),
                        Some(_) => Truth::False,
                        None => Truth::Unknown(vec![Unknown::ResourceFieldUnavailable {
                            field: ResourceField::ManagedWholeStack,
                        }]),
                    },
                }
            }
            ResourcePredicate::CloudResource {
                provider,
                service,
                kind,
            } => match identity(target.resource, &ResourceVariant::CloudResource) {
                Err(truth) => truth,
                Ok(ResourceIdentity::CloudResource {
                    provider: actual_provider,
                    service: actual_service,
                    kind: actual_kind,
                    ..
                }) => optional_text(
                    provider.as_ref(),
                    actual_provider.as_deref(),
                    ResourceField::CloudProvider,
                )
                .and(|| {
                    Ok(optional_text(
                        service.as_ref(),
                        Some(actual_service),
                        ResourceField::CloudService,
                    ))
                })?
                .and(|| {
                    Ok(optional_text(
                        kind.as_ref(),
                        Some(actual_kind),
                        ResourceField::CloudKind,
                    ))
                })?,
                Ok(_) => unreachable!("resource variant checked"),
            },
            ResourcePredicate::Selection { shape } => selection_shape(target, *shape, false),
        })
    }

    /// A schema-4 label on a selection that names no single concrete
    /// identity, answered by the provider for the typed selection. `None`
    /// leaves the schema-3 meaning in place.
    fn selection_label(
        &self,
        label: &LabelId,
        observation: &ObservationBinding,
        target: EffectTarget<'_>,
        selection: LabelSelection,
        effect: Option<&EffectId>,
    ) -> Option<Truth> {
        if self.schema_version.get() < SELECTION_SCHEMA_VERSION {
            return None;
        }
        let selected = match target.resource {
            resource @ (ResourceExpr::Pattern {
                pattern: ResourcePattern::FsPath { .. },
            }
            | ResourceExpr::Union { .. })
                if resource_domain(resource) == Some("filesystem") =>
            {
                SelectionTarget::Filesystem(resource)
            }
            ResourceExpr::Pattern {
                pattern: ResourcePattern::EnvironmentVariable { name_glob },
            } if name_glob == "*" && selection == LabelSelection::Direct => {
                SelectionTarget::EnvironmentAll
            }
            _ => return None,
        };
        Some(label_truth(
            label,
            observation,
            self.label_provider.selection_labels(
                observation,
                SelectionLabelResource {
                    realm: target.realm,
                    target: selected,
                    selection,
                    effect,
                },
            ),
        ))
    }

    fn occurrence(
        &self,
        endpoint: &Endpoint,
        node: &OccurrenceNode,
        effect_bindings: &BTreeMap<String, usize>,
    ) -> Result<Truth, Refusal> {
        match (endpoint, &node.occurrence) {
            (
                Endpoint::Interaction(selector),
                OccurrenceKind::ResourceInteraction {
                    operation,
                    resource,
                    attributes,
                },
            ) => self.select(
                selector,
                self.occurrence_target(node, operation, resource, attributes),
                node.execution,
                node.execution
                    .and_then(|execution| self.bindings.get(&execution)),
                self.occurrence_effect(&node.id),
            ),
            (Endpoint::Value(text), OccurrenceKind::Value { value }) => {
                Ok(text.matches(&render::rendered_resource(value)).into())
            }
            (Endpoint::EffectBinding { name }, OccurrenceKind::ResourceInteraction { .. }) => {
                Ok(self.effect_occurrences[effect_bindings[name]]
                    .is_some_and(|id| *id == node.id)
                    .into())
            }
            (Endpoint::Port { kind, scope }, OccurrenceKind::Port { port }) => {
                self.port(*kind, scope, node, port, effect_bindings)
            }
            _ => Ok(Truth::False),
        }
    }

    fn port(
        &self,
        kind: PortKind,
        scope: &PortScope,
        node: &OccurrenceNode,
        port: &Port,
        effect_bindings: &BTreeMap<String, usize>,
    ) -> Result<Truth, Refusal> {
        let typed = matches!(
            (kind, port),
            (PortKind::Stdout, Port::Stdout)
                | (PortKind::Code, Port::Code)
                | (PortKind::NetworkRequest, Port::HttpRequestBody)
                | (PortKind::NetworkResponse, Port::HttpResponseBody)
                | (PortKind::ConsumedStdin, Port::Stdin)
        );
        if !typed {
            return Ok(Truth::False);
        }
        let Some(execution) = node.execution else {
            return Ok(Truth::Unknown(vec![Unknown::PortExecutionUnavailable {
                occurrence: node.id.clone(),
            }]));
        };
        if let PortScope::SameExecution { binding } = scope
            && self.plan.effects[effect_bindings[binding]].execution != execution
        {
            return Ok(Truth::False);
        }
        if kind != PortKind::ConsumedStdin {
            return Ok(Truth::True);
        }
        let mut consumed = Truth::False;
        for effect in &self.plan.effects {
            if effect.execution == execution
                && effect.operation.as_str() == "process.code_execution"
            {
                let source = AttributePredicate {
                    name: "source".into(),
                    test: AttributeTest::Equals(AttrValue::String("stdin".into())),
                }
                .test(&effect.attributes);
                consumed = consumed.or(|| Ok(source))?;
            }
        }
        Ok(consumed)
    }

    fn endpoint(
        &self,
        endpoint: &Endpoint,
        id: &OccurrenceId,
        effect_bindings: &BTreeMap<String, usize>,
    ) -> Result<Truth, Refusal> {
        self.nodes.get(id).map_or(Ok(Truth::False), |node| {
            self.occurrence(endpoint, node, effect_bindings)
        })
    }

    /// Occurrences the endpoint does not disprove, in graph order. A bound
    /// effect's endpoint is its own occurrence, found without a scan; any
    /// other endpoint that names no binding is scanned once per query.
    fn candidates(
        &self,
        endpoint: &Endpoint,
        effect_bindings: &BTreeMap<String, usize>,
        budget: &mut Budget,
    ) -> Result<Candidates<'a>, Refusal> {
        let bound = match endpoint {
            Endpoint::EffectBinding { name } => {
                budget.charge()?;
                return Ok(self.effect_occurrences[effect_bindings[name]]
                    .and_then(|id| self.nodes_by_id.get(id))
                    .into_iter()
                    .flatten()
                    .filter(|node| {
                        matches!(node.occurrence, OccurrenceKind::ResourceInteraction { .. })
                    })
                    .map(|node| (&node.id, Truth::True))
                    .collect());
            }
            Endpoint::Port {
                scope: PortScope::SameExecution { .. },
                ..
            } => true,
            Endpoint::Interaction(_) | Endpoint::Value(_) | Endpoint::Port { .. } => false,
        };
        let key = std::ptr::from_ref(endpoint);
        if !bound && let Some(candidates) = self.endpoint_candidates.borrow().get(&key) {
            return Ok(candidates.clone());
        }
        let mut out = Vec::new();
        for node in self
            .plan
            .causality
            .graph
            .iter()
            .flat_map(|graph| &graph.nodes)
        {
            budget.charge()?;
            match self.occurrence(endpoint, node, effect_bindings)? {
                Truth::False => {}
                truth => out.push((&node.id, truth)),
            }
        }
        if !bound {
            self.endpoint_candidates
                .borrow_mut()
                .insert(key, out.clone());
        }
        Ok(out)
    }

    fn route(&self, provenance: RouteProvenance, route: &[OccurrenceId]) -> Truth {
        match provenance {
            RouteProvenance::Any => Truth::True,
            RouteProvenance::NonemptyOnEveryOccurrence => route
                .iter()
                .all(|id| {
                    self.nodes
                        .get(id)
                        .is_some_and(|node| !node.provenance.is_empty())
                })
                .into(),
        }
    }
}

impl ResourceVariant {
    fn matches(&self, identity: &ResourceIdentity) -> bool {
        match (self, identity) {
            (Self::Artifact, ResourceIdentity::Artifact { .. })
            | (Self::ServiceUnit, ResourceIdentity::ServiceUnit { .. })
            | (Self::StorageVolume, ResourceIdentity::StorageVolume { .. })
            | (Self::HostSystem, ResourceIdentity::HostSystem { .. })
            | (Self::FsPath, ResourceIdentity::FsPath { .. })
            | (Self::Container, ResourceIdentity::Container { .. })
            | (Self::KubernetesResource, ResourceIdentity::KubernetesResource { .. })
            | (Self::ManagedInfrastructure, ResourceIdentity::ManagedInfrastructure { .. })
            | (Self::ObjectStore, ResourceIdentity::ObjectStore { .. })
            | (Self::CloudResource, ResourceIdentity::CloudResource { .. }) => true,
            (
                Self::CredentialStore { provider },
                ResourceIdentity::CredentialStore {
                    provider: actual, ..
                },
            ) => provider == actual,
            (
                Self::EnvironmentVariable { name },
                ResourceIdentity::EnvironmentVariable { name: actual },
            ) => name == actual,
            _ => false,
        }
    }

    fn domain(&self) -> &'static str {
        match self {
            Self::Artifact => "artifact",
            Self::ServiceUnit | Self::StorageVolume | Self::HostSystem => "system",
            Self::FsPath => "filesystem",
            Self::CredentialStore { .. } => "credential",
            Self::EnvironmentVariable { .. } => "environment",
            Self::Container | Self::KubernetesResource => "container",
            Self::ManagedInfrastructure | Self::CloudResource => "cloud",
            Self::ObjectStore => "object",
        }
    }
}

/// Whether `related` names `bound`'s resource: equal concrete identities in
/// one realm, or from schema 6 one filesystem pattern spelled alike. Any
/// other pattern, union or symbolic resource, or a cloud resource whose ID is
/// unstated, proves neither answer.
fn same_resource(
    bound: &effinterp_proto::Effect,
    related: &effinterp_proto::Effect,
    schema_version: u32,
) -> Truth {
    if bound.realm != related.realm {
        return Truth::False;
    }
    match (&bound.resource, &related.resource) {
        (ResourceExpr::Concrete { identity: bound }, ResourceExpr::Concrete { identity })
            if ![bound, identity].iter().any(|identity| {
                matches!(identity, ResourceIdentity::CloudResource { id: None, .. })
            }) =>
        {
            (bound == identity).into()
        }
        (
            pattern @ ResourceExpr::Pattern {
                pattern: ResourcePattern::FsPath { .. },
            },
            related,
        ) if schema_version >= COVERAGE_SCHEMA_VERSION && pattern == related => Truth::True,
        _ => Truth::Unknown(vec![Unknown::SameResourceUnavailable {
            effect: related.id.clone(),
        }]),
    }
}

fn resource_family(resource: &ResourceExpr, family: &str) -> Truth {
    let expected = ResourceFamily::new(family);
    match resource {
        ResourceExpr::Concrete { identity } => {
            (effinterp_proto::identity_family(identity) == family).into()
        }
        ResourceExpr::Pattern { pattern } => (pattern.family().0.as_ref() == family).into(),
        ResourceExpr::Unresolved { family: actual } => (actual.0.as_ref() == family).into(),
        resource => match (expected.domain(), resource_domain(resource)) {
            (Some(expected), Some(actual)) if actual != expected => Truth::False,
            _ => Truth::Unknown(vec![Unknown::ResourceFamilyUnavailable]),
        },
    }
}

fn identity<'a>(
    resource: &'a ResourceExpr,
    variant: &ResourceVariant,
) -> Result<&'a ResourceIdentity, Truth> {
    match resource {
        ResourceExpr::Concrete { identity } if variant.matches(identity) => Ok(identity),
        ResourceExpr::Concrete { .. } => Err(Truth::False),
        resource => match resource_domain(resource) {
            Some(domain) if domain != variant.domain() => Err(Truth::False),
            _ => Err(Truth::Unknown(vec![Unknown::ResourceIdentityUnavailable {
                variant: variant.clone(),
            }])),
        },
    }
}

fn label_truth(label: &LabelId, observation: &ObservationBinding, status: LabelStatus) -> Truth {
    match status {
        LabelStatus::Known(labels) => labels.contains(label).into(),
        LabelStatus::Unknown => Truth::Unknown(vec![Unknown::LabelObservationUnavailable {
            observation: observation.clone(),
        }]),
    }
}

fn optional_text(
    predicate: Option<&TextPredicate>,
    value: Option<&str>,
    field: ResourceField,
) -> Truth {
    match (predicate, value) {
        (None, _) => Truth::True,
        (Some(predicate), Some(value)) => predicate.matches(value).into(),
        (Some(_), None) => Truth::Unknown(vec![Unknown::ResourceFieldUnavailable { field }]),
    }
}

fn selection_shape(target: EffectTarget<'_>, expected: SelectionShape, required: bool) -> Truth {
    if let Some(value) = target.attributes.get("selection") {
        return match value {
            AttrValue::String(value) => {
                let actual = match value.as_str() {
                    "named" => Some(SelectionShape::NamedSet),
                    "pattern" => Some(SelectionShape::Pattern),
                    "whole" => Some(SelectionShape::Whole),
                    _ => None,
                };
                (actual == Some(expected)).into()
            }
            _ => Truth::False,
        };
    }
    match target.resource {
        ResourceExpr::Pattern { .. } => (expected == SelectionShape::Pattern).into(),
        ResourceExpr::Union { alternatives }
            if !alternatives.is_empty()
                && alternatives
                    .iter()
                    .all(|alternative| matches!(alternative, ResourceExpr::Concrete { .. })) =>
        {
            (expected == SelectionShape::NamedSet).into()
        }
        ResourceExpr::Concrete {
            identity: ResourceIdentity::Artifact { reference, .. },
        } if matches!(reference.as_ref(), ArtifactReference::Whole {}) => {
            (expected == SelectionShape::Whole).into()
        }
        ResourceExpr::Concrete { .. } if required => {
            Truth::Unknown(vec![Unknown::ResourceFieldUnavailable {
                field: ResourceField::KubernetesSelection,
            }])
        }
        ResourceExpr::Concrete { .. } => Truth::False,
        _ => Truth::Unknown(vec![Unknown::SelectionShapeUnavailable]),
    }
}

/// Whether an effect or occurrence under `condition` takes place on its
/// invocation's success path: it has no condition, or every atom of its
/// condition asserts that a preceding command succeeded, as the second command
/// of `a && b` does. A widened condition is unknown. This is the one
/// success-path rule over plan conditions: the `success_path` selector
/// condition and byte-flow routes apply it, and so may a caller that reads
/// plan conditions itself.
pub fn success_path(condition: Option<&Condition>, limits: QueryLimits) -> Result<Truth, Refusal> {
    fn holds(condition: &Condition, limits: QueryLimits, depth: usize) -> Result<Truth, Refusal> {
        if depth > limits.max_condition_depth {
            return Err(Refusal::WorkLimit);
        }
        match condition {
            Condition::Atom { atom } => Ok((atom.origin.kind == ConditionKind::ShortCircuit
                && atom.polarity == Some(true))
            .into()),
            Condition::All { conditions } | Condition::Any { conditions } => {
                let mut truth = Truth::True;
                for condition in conditions {
                    truth = truth.and(|| holds(condition, limits, depth + 1))?;
                }
                Ok(truth)
            }
            Condition::Widened => Ok(Truth::Unknown(vec![Unknown::ConditionIncomplete])),
        }
    }
    condition.map_or(Ok(Truth::True), |condition| holds(condition, limits, 0))
}

/// Whether every atom `condition` conjoins is on the success path or is an
/// arm the route's source or destination runs in. A destination arm must be
/// a branch, loop or short-circuit arm the program selects, not one the
/// source's own construct excludes, nor a callback or execution that may
/// never be dispatched at all.
fn within_route_arms(
    condition: &Condition,
    source: Option<&Condition>,
    destination: Option<&Condition>,
) -> bool {
    fn conjuncts<'a>(condition: &'a Condition, atoms: &mut Vec<&'a ConditionAtom>) -> bool {
        match condition {
            Condition::Atom { atom } => {
                atoms.push(atom);
                true
            }
            Condition::All { conditions } => conditions.iter().all(|c| conjuncts(c, atoms)),
            Condition::Any { .. } | Condition::Widened => false,
        }
    }
    let mut atoms = Vec::new();
    let mut source_arms = Vec::new();
    let mut destination_arms = Vec::new();
    if !conjuncts(condition, &mut atoms) {
        return false;
    }
    if let Some(source) = source {
        conjuncts(source, &mut source_arms);
    }
    if let Some(destination) = destination {
        conjuncts(destination, &mut destination_arms);
    }
    atoms.iter().all(|atom| {
        (atom.origin.kind == ConditionKind::ShortCircuit && atom.polarity == Some(true))
            || source_arms.contains(atom)
            || destination_arms.contains(atom)
                && matches!(
                    atom.origin.kind,
                    ConditionKind::Branch | ConditionKind::Loop | ConditionKind::ShortCircuit
                )
                && !source_arms
                    .iter()
                    .any(|arm| arm.origin == atom.origin && arm.arm != atom.arm)
    })
}

fn occurrence_operation(node: &OccurrenceNode) -> Option<&str> {
    match &node.occurrence {
        OccurrenceKind::ResourceInteraction { operation, .. } => Some(operation.as_str()),
        _ => None,
    }
}

fn occurrence_owns_effect(node: &OccurrenceNode, effect: &effinterp_proto::Effect) -> bool {
    node.execution == Some(effect.execution)
        && node.realm == effect.realm
        && node.modality == effect.modality
        && node.condition == effect.condition
        && node.provenance == effect.provenance
        && matches!(
            &node.occurrence,
            OccurrenceKind::ResourceInteraction {
                operation,
                resource,
                attributes,
            } if operation == &effect.operation
                && resource == &effect.resource
                && attributes == &effect.attributes
        )
}

fn occurrence_attribute<'a>(node: &'a OccurrenceNode, name: &str) -> Option<&'a AttrValue> {
    match &node.occurrence {
        OccurrenceKind::ResourceInteraction { attributes, .. } => attributes.get(name),
        _ => None,
    }
}

/// Whether a read opens what the links it meets lead to: its model says it
/// follows links, or, when the model says nothing, it is a content read that
/// does not recurse, which opens each entry it names. Keep this identical to
/// `reads_through_links` in nah-effinterp's `bridge/label_propagation.rs`.
fn reads_through_links(node: &OccurrenceNode) -> bool {
    match occurrence_attribute(node, "follow_links") {
        Some(AttrValue::Bool(follows)) => *follows,
        _ => {
            occurrence_attribute(node, "access_purpose")
                == Some(&AttrValue::String("program_input".into()))
                && occurrence_attribute(node, "recursive") != Some(&AttrValue::Bool(true))
        }
    }
}

fn occurrence_fs_path(node: &OccurrenceNode) -> Option<&str> {
    match &node.occurrence {
        OccurrenceKind::ResourceInteraction {
            resource:
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path },
                },
            ..
        } => Some(path),
        _ => None,
    }
}

fn path_is_descendant(inner: &str, outer: &str) -> bool {
    let inner = inner.replace('\\', "/");
    let outer = outer.replace('\\', "/");
    inner
        .strip_prefix(outer.trim_end_matches('/'))
        .is_some_and(|rest| rest.starts_with('/'))
}
