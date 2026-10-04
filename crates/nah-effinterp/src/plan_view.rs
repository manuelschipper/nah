//! Immutable indexed access to one validated engine plan and its decision snapshot.
//!
//! The bridge constructs this view once after observation binding. Indexes retain
//! the plan's typed expressions and open vocabularies; they never render resources,
//! inspect the host, or dispatch on guard names.

use std::cell::OnceCell;
use std::collections::{BTreeMap, BTreeSet};

use nah_proto::ctx::{AbsolutePath, Ctx, Platform, PolicyCtx};
use nah_proto::effect_annotation::EffectAnnotation;
use nah_proto::observation::{
    Observation, ObservationQuery, ObservationValue, Observed, PathObservation, Root, RootKind,
};
use nah_proto::runtime_protection::SelfProtectionProjection;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct ResourceId(u32);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum PathSelection {
    Entry,
    FollowedTarget,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum BoundaryClass {
    Unmodeled,
    Unresolved,
    Limit,
    ParseFailure,
    Unsupported,
}

impl From<effinterp_proto::BoundaryClass> for BoundaryClass {
    fn from(value: effinterp_proto::BoundaryClass) -> Self {
        match value {
            effinterp_proto::BoundaryClass::Unmodeled => Self::Unmodeled,
            effinterp_proto::BoundaryClass::Unresolved => Self::Unresolved,
            effinterp_proto::BoundaryClass::Limit => Self::Limit,
            effinterp_proto::BoundaryClass::ParseFailure => Self::ParseFailure,
            effinterp_proto::BoundaryClass::Unsupported => Self::Unsupported,
        }
    }
}

pub(crate) struct IndexedResource<'a> {
    pub(crate) expression: &'a effinterp_proto::ResourceExpr,
    pub(crate) realm: &'a effinterp_proto::ExecutionRealm,
}

pub(crate) struct AuthorityContext {
    platform: Platform,
    home: AbsolutePath,
    workspace_roots: Vec<AbsolutePath>,
    observed_roots: Vec<Root>,
    trusted_roots: Vec<AbsolutePath>,
    critical_paths: Vec<AbsolutePath>,
    installed_executables: Vec<AbsolutePath>,
    policy: PolicyCtx,
}

impl AuthorityContext {
    fn new(
        ctx: &Ctx,
        observation: &Observation,
        self_protection: &SelfProtectionProjection,
    ) -> Result<Self, nah_proto::ctx::CtxError> {
        let observed_roots = crate::annotate::observed_roots(observation);
        let workspace_roots = observed_roots
            .iter()
            .filter(|root| root.kind() == RootKind::Project)
            .map(|root| root.path().clone())
            .collect();
        let trusted_roots = ctx
            .trust()
            .trusted_roots()
            .iter()
            .map(|root| root.path().clone())
            .collect();
        let policy = nah_proto::ctx::derive_policy_ctx(ctx, observation)?
            .policy_ctx()
            .clone();
        Ok(Self {
            platform: ctx.platform(),
            home: ctx.home().clone(),
            workspace_roots,
            observed_roots,
            trusted_roots,
            critical_paths: self_protection.protected_paths().to_vec(),
            installed_executables: self_protection.installed_executables().to_vec(),
            policy,
        })
    }

    pub(crate) const fn platform(&self) -> Platform {
        self.platform
    }

    pub(crate) fn home(&self) -> &AbsolutePath {
        &self.home
    }

    pub(crate) fn observed_roots(&self) -> &[Root] {
        &self.observed_roots
    }

    pub(crate) fn trusted_roots(&self) -> &[AbsolutePath] {
        &self.trusted_roots
    }

    pub(crate) fn critical_paths(&self) -> &[AbsolutePath] {
        &self.critical_paths
    }

    /// The deciding nah executable's own paths; see `SelfProtectionProjection`.
    pub(crate) fn installed_executables(&self) -> &[AbsolutePath] {
        &self.installed_executables
    }

    fn validate_indexes(&self) {
        debug_assert!(self.workspace_roots.iter().all(|workspace| {
            self.observed_roots
                .iter()
                .any(|root| root.kind() == RootKind::Project && root.path() == workspace)
        }));
        debug_assert_eq!(
            self.trusted_roots.iter().collect::<BTreeSet<_>>().len(),
            self.trusted_roots.len()
        );
        debug_assert!(
            self.policy
                .enabled_shipped_guards()
                .windows(2)
                .all(|guards| guards[0] < guards[1])
        );
    }
}

struct EffectIndex {
    exact: BTreeMap<String, Vec<usize>>,
    family: BTreeMap<String, Vec<usize>>,
    executions: BTreeMap<effinterp_proto::ExecutionNodeRef, Vec<usize>>,
}

impl EffectIndex {
    fn new(plan: &effinterp_proto::Plan) -> Self {
        let mut exact = BTreeMap::<String, Vec<usize>>::new();
        let mut family = BTreeMap::<String, Vec<usize>>::new();
        let mut executions = BTreeMap::<effinterp_proto::ExecutionNodeRef, Vec<usize>>::new();
        for (index, effect) in plan.effects.iter().enumerate() {
            let operation = effect.operation.as_str();
            exact.entry(operation.to_owned()).or_default().push(index);
            executions.entry(effect.execution).or_default().push(index);
            let mut end = operation.len();
            loop {
                family
                    .entry(operation[..end].to_owned())
                    .or_default()
                    .push(index);
                let Some(next) = operation[..end].rfind('.') else {
                    break;
                };
                end = next;
            }
        }
        Self {
            exact,
            family,
            executions,
        }
    }
}

struct ResourceIndex<'a> {
    resources: Vec<IndexedResource<'a>>,
    effects: Vec<ResourceId>,
    occurrences: BTreeMap<effinterp_proto::OccurrenceId, ResourceId>,
}

impl<'a> ResourceIndex<'a> {
    fn new(plan: &'a effinterp_proto::Plan) -> Self {
        let mut resources = Vec::new();
        let mut add = |expression: &'a effinterp_proto::ResourceExpr,
                       realm: &'a effinterp_proto::ExecutionRealm| {
            let id = ResourceId(resources.len() as u32);
            resources.push(IndexedResource { expression, realm });
            id
        };
        let effects = plan
            .effects
            .iter()
            .map(|effect| add(&effect.resource, &effect.realm))
            .collect();
        for node in &plan.execution_graph.nodes {
            for expression in node
                .argv
                .iter()
                .chain(node.cwd.iter())
                .chain(node.environment.values().flatten())
            {
                add(expression, &node.realm);
            }
        }
        for boundary in &plan.boundaries {
            if let Some(expression) = &boundary.affected_resource {
                add(expression, &effinterp_proto::ExecutionRealm::Host);
            }
        }
        let mut occurrences = BTreeMap::new();
        if let Some(graph) = &plan.causality.graph {
            for node in &graph.nodes {
                let expression = match &node.occurrence {
                    effinterp_proto::OccurrenceKind::Value { value } => Some(value),
                    effinterp_proto::OccurrenceKind::ResourceInteraction { resource, .. } => {
                        Some(resource)
                    }
                    effinterp_proto::OccurrenceKind::Port { .. }
                    | effinterp_proto::OccurrenceKind::Boundary { .. } => None,
                };
                if let Some(expression) = expression {
                    occurrences.insert(node.id.clone(), add(expression, &node.realm));
                }
            }
        }
        Self {
            resources,
            effects,
            occurrences,
        }
    }
}

pub(crate) struct ExecutionBinding<'a> {
    node: &'a effinterp_proto::ExecutionNode,
    pub(crate) cwd: Option<&'a effinterp_proto::ResourceExpr>,
    pub(crate) environment: &'a BTreeMap<String, Option<effinterp_proto::ResourceExpr>>,
    pub(crate) realm: &'a effinterp_proto::ExecutionRealm,
}

impl std::ops::Deref for ExecutionBinding<'_> {
    type Target = effinterp_proto::ExecutionNode;

    fn deref(&self) -> &Self::Target {
        self.node
    }
}

struct ExecutionIndex<'a> {
    bindings: Vec<ExecutionBinding<'a>>,
    parent_edges: Vec<Option<usize>>,
}

impl<'a> ExecutionIndex<'a> {
    fn new(plan: &'a effinterp_proto::Plan) -> Self {
        let bindings = plan
            .execution_graph
            .nodes
            .iter()
            .map(|node| ExecutionBinding {
                node,
                cwd: node.cwd.as_ref(),
                environment: &node.environment,
                realm: &node.realm,
            })
            .collect();
        let mut parent_edges = vec![None; plan.execution_graph.nodes.len()];
        for (index, edge) in plan.execution_graph.edges.iter().enumerate() {
            if !edge.cycle {
                parent_edges[edge.to.0 as usize].get_or_insert(index);
            }
        }
        Self {
            bindings,
            parent_edges,
        }
    }
}

struct BoundaryIndex {
    class: BTreeMap<BoundaryClass, Vec<usize>>,
    domain: BTreeMap<String, Vec<usize>>,
}

impl BoundaryIndex {
    fn new(plan: &effinterp_proto::Plan) -> Self {
        let mut class = BTreeMap::<BoundaryClass, Vec<usize>>::new();
        let mut domain = BTreeMap::<String, Vec<usize>>::new();
        for (index, boundary) in plan.boundaries.iter().enumerate() {
            class.entry(boundary.class.into()).or_default().push(index);
            for value in &boundary.domains {
                domain.entry(value.0.clone()).or_default().push(index);
            }
        }
        Self { class, domain }
    }
}

struct CausalIndex {
    nodes: BTreeMap<effinterp_proto::OccurrenceId, usize>,
    operations: BTreeMap<String, Vec<usize>>,
    executions: BTreeMap<effinterp_proto::ExecutionNodeRef, Vec<usize>>,
    outgoing: BTreeMap<effinterp_proto::OccurrenceId, Vec<usize>>,
    incoming: BTreeMap<effinterp_proto::OccurrenceId, Vec<usize>>,
}

impl CausalIndex {
    fn new(plan: &effinterp_proto::Plan) -> Self {
        let mut nodes = BTreeMap::new();
        let mut operations = BTreeMap::<String, Vec<usize>>::new();
        let mut executions = BTreeMap::<effinterp_proto::ExecutionNodeRef, Vec<usize>>::new();
        let mut outgoing = BTreeMap::<effinterp_proto::OccurrenceId, Vec<usize>>::new();
        let mut incoming = BTreeMap::<effinterp_proto::OccurrenceId, Vec<usize>>::new();
        if let Some(graph) = &plan.causality.graph {
            for (index, node) in graph.nodes.iter().enumerate() {
                nodes.insert(node.id.clone(), index);
                if let effinterp_proto::OccurrenceKind::ResourceInteraction { operation, .. } =
                    &node.occurrence
                {
                    operations
                        .entry(operation.as_str().to_owned())
                        .or_default()
                        .push(index);
                }
                if let Some(execution) = node.execution {
                    executions.entry(execution).or_default().push(index);
                }
            }
            for (index, edge) in graph.edges.iter().enumerate() {
                outgoing.entry(edge.from.clone()).or_default().push(index);
                incoming.entry(edge.to.clone()).or_default().push(index);
            }
        }
        Self {
            nodes,
            operations,
            executions,
            outgoing,
            incoming,
        }
    }
}

pub(crate) struct PlanView<'a> {
    plan: &'a effinterp_proto::Plan,
    observation: &'a Observation,
    authority: AuthorityContext,
    effects: EffectIndex,
    resources: ResourceIndex<'a>,
    executions: ExecutionIndex<'a>,
    boundaries: BoundaryIndex,
    causality: CausalIndex,
    annotations: Vec<OnceCell<EffectAnnotation>>,
    observed_paths: BTreeMap<&'a str, &'a Observed<PathObservation>>,
}

impl<'a> PlanView<'a> {
    pub(crate) fn new(
        plan: &'a effinterp_proto::Plan,
        observation: &'a Observation,
        context: &'a Ctx,
        self_protection: &SelfProtectionProjection,
    ) -> Result<Self, nah_proto::ctx::CtxError> {
        let authority = AuthorityContext::new(context, observation, self_protection)?;
        let observed_paths = observation
            .facts()
            .iter()
            .filter_map(|fact| match (fact.query(), fact.value()) {
                (ObservationQuery::Path { requested, .. }, ObservationValue::Path { observed }) => {
                    Some((requested.as_str(), observed))
                }
                _ => None,
            })
            .collect();
        authority.validate_indexes();
        let view = Self {
            plan,
            observation,
            authority,
            effects: EffectIndex::new(plan),
            resources: ResourceIndex::new(plan),
            executions: ExecutionIndex::new(plan),
            boundaries: BoundaryIndex::new(plan),
            causality: CausalIndex::new(plan),
            annotations: (0..plan.effects.len()).map(|_| OnceCell::new()).collect(),
            observed_paths,
        };
        view.validate_indexes();
        Ok(view)
    }

    fn validate_indexes(&self) {
        debug_assert_eq!(
            self.effects.exact.values().map(Vec::len).sum::<usize>(),
            self.plan.effects.len()
        );
        debug_assert!(self.effects.family.iter().all(|(family, indices)| {
            indices.iter().all(|index| {
                let operation = self.plan.effects[*index].operation.as_str();
                operation == family
                    || operation
                        .strip_prefix(family)
                        .is_some_and(|rest| rest.starts_with('.'))
            })
        }));
        debug_assert_eq!(
            self.boundaries.class.values().map(Vec::len).sum::<usize>(),
            self.plan.boundaries.len()
        );
        debug_assert!(self.executions.bindings.iter().all(|binding| {
            binding.cwd == binding.node.cwd.as_ref()
                && binding.environment == &binding.node.environment
                && binding.realm == &binding.node.realm
        }));
        debug_assert!(self.observed_paths.len() <= self.observation.facts().len());
        if let Some(graph) = &self.plan.causality.graph {
            debug_assert_eq!(
                self.causality
                    .outgoing
                    .values()
                    .map(Vec::len)
                    .sum::<usize>(),
                graph.edges.len()
            );
            debug_assert_eq!(
                self.causality
                    .incoming
                    .values()
                    .map(Vec::len)
                    .sum::<usize>(),
                graph.edges.len()
            );
            debug_assert!(self.causality.operations.values().flatten().all(|index| {
                matches!(
                    graph.nodes[*index].occurrence,
                    effinterp_proto::OccurrenceKind::ResourceInteraction { .. }
                )
            }));
            if let Some(edge) = graph.edges.first() {
                debug_assert!(
                    effinterp_trace::causal_path_in_graph(graph, &edge.from, &edge.to).is_some()
                );
            }
        }
    }

    pub(crate) fn plan(&self) -> &'a effinterp_proto::Plan {
        self.plan
    }

    pub(crate) fn authority(&self) -> &AuthorityContext {
        &self.authority
    }

    pub(crate) fn effects_exact(
        &self,
        operation: &str,
    ) -> impl Iterator<Item = &'a effinterp_proto::Effect> {
        self.effects
            .exact
            .get(operation)
            .into_iter()
            .flatten()
            .map(|index| &self.plan.effects[*index])
    }

    pub(crate) fn effects(&self) -> impl Iterator<Item = (usize, &'a effinterp_proto::Effect)> {
        self.plan.effects.iter().enumerate()
    }

    pub(crate) fn effect_indices_exact(&self, operation: &str) -> impl Iterator<Item = usize> + '_ {
        self.effects
            .exact
            .get(operation)
            .into_iter()
            .flatten()
            .copied()
    }

    pub(crate) fn effect_indices_family(&self, family: &str) -> impl Iterator<Item = usize> + '_ {
        self.effects
            .family
            .get(family)
            .into_iter()
            .flatten()
            .copied()
    }

    pub(crate) fn effects_for_execution(
        &self,
        execution: effinterp_proto::ExecutionNodeRef,
    ) -> impl Iterator<Item = &'a effinterp_proto::Effect> {
        self.effects
            .executions
            .get(&execution)
            .into_iter()
            .flatten()
            .map(|index| &self.plan.effects[*index])
    }

    pub(crate) fn effect_resource_id(&self, index: usize) -> ResourceId {
        self.resources.effects[index]
    }

    pub(crate) fn resource(&self, id: ResourceId) -> &IndexedResource<'a> {
        &self.resources.resources[id.0 as usize]
    }

    pub(crate) fn occurrence_resource_id(
        &self,
        id: &effinterp_proto::OccurrenceId,
    ) -> Option<ResourceId> {
        self.resources.occurrences.get(id).copied()
    }

    pub(crate) fn execution(&self, id: effinterp_proto::ExecutionNodeRef) -> &ExecutionBinding<'a> {
        &self.executions.bindings[id.0 as usize]
    }

    pub(crate) fn executions(&self) -> impl Iterator<Item = (usize, &ExecutionBinding<'a>)> {
        self.executions.bindings.iter().enumerate()
    }

    pub(crate) fn matcher_bindings(
        &self,
    ) -> BTreeMap<effinterp_proto::ExecutionNodeRef, effinterp_proto::Bindings> {
        self.executions()
            .map(|(index, execution)| {
                let mut bindings = effinterp_proto::Bindings::from_subject(&execution.subject);
                bindings.platform = if self.authority.platform() == Platform::Windows {
                    effinterp_proto::PathPlatform::Windows
                } else {
                    effinterp_proto::PathPlatform::Posix
                };
                (effinterp_proto::ExecutionNodeRef(index as u32), bindings)
            })
            .collect()
    }

    pub(crate) fn parent_edge(
        &self,
        id: effinterp_proto::ExecutionNodeRef,
    ) -> Option<&'a effinterp_proto::ExecutionEdge> {
        self.executions.parent_edges[id.0 as usize]
            .map(|index| &self.plan.execution_graph.edges[index])
    }

    pub(crate) fn boundaries(
        &self,
    ) -> impl Iterator<Item = (usize, &'a effinterp_proto::Boundary)> {
        self.plan.boundaries.iter().enumerate()
    }

    pub(crate) fn boundaries_in_domain(
        &self,
        domain: &str,
    ) -> impl Iterator<Item = &'a effinterp_proto::Boundary> {
        self.boundaries
            .domain
            .get(domain)
            .into_iter()
            .flatten()
            .map(|index| &self.plan.boundaries[*index])
    }

    pub(crate) fn causal_node(
        &self,
        id: &effinterp_proto::OccurrenceId,
    ) -> Option<&'a effinterp_proto::OccurrenceNode> {
        let graph = self.plan.causality.graph.as_ref()?;
        self.causality
            .nodes
            .get(id)
            .map(|index| &graph.nodes[*index])
    }

    pub(crate) fn occurrences_for_execution(
        &self,
        execution: effinterp_proto::ExecutionNodeRef,
    ) -> impl Iterator<Item = &'a effinterp_proto::OccurrenceNode> {
        self.plan.causality.graph.iter().flat_map(move |graph| {
            self.causality
                .executions
                .get(&execution)
                .into_iter()
                .flatten()
                .map(|index| &graph.nodes[*index])
        })
    }

    pub(crate) fn outgoing_edges(
        &self,
        id: &effinterp_proto::OccurrenceId,
    ) -> impl Iterator<Item = &'a effinterp_proto::CausalEdge> {
        self.plan.causality.graph.iter().flat_map(move |graph| {
            self.causality
                .outgoing
                .get(id)
                .into_iter()
                .flatten()
                .map(|index| &graph.edges[*index])
        })
    }

    pub(crate) fn incoming_edges(
        &self,
        id: &effinterp_proto::OccurrenceId,
    ) -> impl Iterator<Item = &'a effinterp_proto::CausalEdge> {
        self.plan.causality.graph.iter().flat_map(move |graph| {
            self.causality
                .incoming
                .get(id)
                .into_iter()
                .flatten()
                .map(|index| &graph.edges[*index])
        })
    }

    pub(crate) fn observed_path(&self, requested: &str) -> Option<&'a PathObservation> {
        match self.observed_paths.get(requested) {
            Some(Observed::Ok { value }) => Some(value),
            Some(Observed::Error { .. }) | None => None,
        }
    }

    /// The observation of the entry at `path`, whether the plan asked for
    /// it by that spelling or by one that resolves to it through a directory
    /// link (`/tmp/x` for `/private/tmp/x`).
    pub(crate) fn observed_entry(&self, path: &str) -> Option<&'a PathObservation> {
        self.observed_path(path).or_else(|| {
            self.observed_paths
                .values()
                .find_map(|observed| match observed {
                    Observed::Ok { value } if value.resolved().as_str() == path => Some(value),
                    _ => None,
                })
        })
    }

    /// Whether some observation shows a directory at `path`, by the
    /// spelling the plan asked for or by where that spelling resolved.
    pub(crate) fn observed_directory(&self, path: &str) -> bool {
        self.observed_paths.iter().any(|(requested, observed)| {
            matches!(observed, Observed::Ok { value }
                if (*requested == path
                    || value.resolved().as_str() == path
                    || value.realpath().is_some_and(|real| real.as_str() == path))
                    && (value.kind() == nah_proto::observation::PathKind::Directory
                        || value.target_kind() == Some(nah_proto::observation::PathKind::Directory)))
        })
    }

    pub(crate) fn path_unavailable(&self, requested: &str) -> bool {
        matches!(
            self.observed_paths.get(requested),
            Some(Observed::Error { .. })
        )
    }

    pub(crate) fn annotation(&self, index: usize) -> &EffectAnnotation {
        self.annotations[index].get_or_init(|| self.compute_annotation(&self.plan.effects[index]))
    }

    /// Every plan effect's annotation, in plan order.
    pub(crate) fn annotations(&self) -> Vec<EffectAnnotation> {
        (0..self.plan.effects.len())
            .map(|index| self.annotation(index).clone())
            .collect()
    }

    pub(crate) fn annotate_synthetic(&self, effect: &effinterp_proto::Effect) -> EffectAnnotation {
        self.compute_annotation(effect)
    }

    fn compute_annotation(&self, effect: &effinterp_proto::Effect) -> EffectAnnotation {
        if !effect.realm.is_host() {
            return EffectAnnotation::default();
        }
        match effect.operation.domain() {
            "filesystem" => {
                let (_, label) = crate::annotate::annotate_path_relation(
                    self.plan,
                    effect,
                    crate::observation_request::observation_bound(&effect.resource)
                        .and_then(|(path, _)| self.observed_path(&path)),
                    self.authority.observed_roots(),
                    crate::annotate::PathLabelContext {
                        platform: self.authority.platform(),
                        home: self.authority.home(),
                        trusted_roots: self.authority.trusted_roots(),
                        critical_paths: self.authority.critical_paths(),
                    },
                    None,
                );
                EffectAnnotation {
                    path: Some(label),
                    runtime_cli: None,
                }
            }
            "process" if effect.operation.as_str() == "process.exec" => EffectAnnotation {
                path: None,
                runtime_cli: crate::annotate::annotate_process_with_authority(
                    self.plan,
                    effect,
                    self.authority.home(),
                    self.authority.platform(),
                ),
            },
            _ => EffectAnnotation::default(),
        }
    }
}
