use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::rc::Rc;

use effinterp_proto::{
    Analysis, AttrValue, Boundary, BoundaryClass, BoundaryReason, BoundaryRef, BoundaryScope,
    Condition, Coverage, CoverageClaim, CoverageLevel, Domain, Effect, ExecutionAssurance,
    ExecutionEdge, ExecutionEdgeKind, ExecutionGraph, ExecutionNode, ExecutionNodeRef,
    ExecutionRealm, ExecutionStreams, OccurrenceKind, Plan, ProvenanceKind, ProvenanceNode,
    ProvenanceRef, ResourceExpr, ResourceIdentity, SCHEMA_V1, Subject, ValidationError,
};

use crate::flow::{Flow, FlowStage, build_causality};
use crate::limits::{
    AnalysisLimits, NODE_BYTES, effect_id_scratch_bytes, execution_node_retained_bytes,
    retained_bytes, transfer_binding_bytes,
};
use crate::nest::{Budget, subject_cwd};
use crate::resource_transfer::TransferBinding;
use crate::value::unresolved_resource;

/// Every effect domain the engine can emit, plus a catch-all. A lost or
/// unmodeled boundary declares opacity across ALL of these (see
/// [`PlanBuilder::global_opacity`]) so a consumer can never infer that a
/// domain is unaffected merely because it is absent from the coverage map.
/// The engine's view of the canonical domain universe (defined once in the
/// protocol) — used wherever the builder must mark every domain opaque.
pub(crate) const KNOWN_DOMAINS: [&str; effinterp_proto::DOMAINS.len()] = effinterp_proto::DOMAINS;

/// Deepest resource-expression tree the builder accepts before widening the
/// whole expression to an unresolved family. Bounds adversarial Join/Union
/// nesting in the serialized plan.
const MAX_RESOURCE_DEPTH: usize = 32;

/// Incrementally assembles a valid plan. Owns provenance indexing, coverage
/// merging (a domain can only get worse), and central saturation of every
/// unbounded plan vector (effects, provenance nodes, boundaries, resource
/// depth), so frontends and models cannot produce a plan that overstates
/// coverage or grows without bound.
pub struct PlanBuilder {
    subject: Subject,
    analysis: Analysis,
    path_platform: effinterp_proto::PathPlatform,
    limits: AnalysisLimits,
    /// The whole-analysis step and retained-byte meters, shared with the
    /// frontends through [`crate::nest::Nest`].
    budget: Rc<Budget>,
    effects: Vec<Effect>,
    execution_nodes: Vec<ExecutionNode>,
    execution_edges: Vec<ExecutionEdge>,
    execution_stack: Vec<ExecutionNodeRef>,
    /// The shell a language runtime selected for each shell it started.
    runtime_shells: BTreeMap<ExecutionNodeRef, RuntimeShell>,
    /// Structural limits that saturated within each execution node.
    execution_saturated: BTreeSet<ExecutionNodeRef>,
    effect_id_subjects: BTreeSet<ExecutionNodeRef>,
    provenance: Vec<ProvenanceNode>,
    /// Host-file byte offset for source spans in the subject currently being analyzed.
    source_span_offsets: Vec<u32>,
    /// The most recent source span minted, used as the location of a budget
    /// saturation charged where no span is in hand (a value walk, a bound
    /// variable, an effect whose provenance is all execution nodes).
    last_source_span: Option<(u32, u32)>,
    /// Structural memo: identical (kind, antecedents) nodes share one entry.
    /// Repeated walks of the same code (shell function calls, re-entered
    /// summaries) would otherwise mint duplicate nodes until
    /// `max_provenance_nodes` saturates and spans degrade to the sentinel.
    provenance_memo: HashMap<ProvenanceNode, ProvenanceRef>,
    boundaries: Vec<Boundary>,
    coverage: BTreeMap<Domain, CoverageLevel>,
    saturated: BTreeMap<&'static str, bool>,
    /// Execution realms entered by nested container/remote transitions.
    /// Every effect added is stamped with the innermost realm.
    realm_stack: Vec<ExecutionRealm>,
    accounted_effect_bytes: u64,
    condition_stack: Vec<Condition>,
    condition_reservations: Vec<crate::guards::ConditionReservation>,
    condition_overflow: usize,
    condition_call: Option<String>,
    /// The dataflow graph accumulated across the whole subject: stage
    /// occurrences in walk order, wiring edges, and the graph's own coverage.
    flow_stages: Vec<FlowStage>,
    flow_edges: Vec<Flow>,
    flow_coverage: CoverageLevel,
    /// Deferred def-use stages/edges (shell variable capture): buffered so a
    /// producer that never reaches a consumer adds nothing to the graph. Only
    /// stages referenced by an edge or listed in `pending_flow_keep`
    /// materialize, in `finish`.
    pending_flow_stages: Vec<FlowStage>,
    pending_flow_edges: Vec<Flow>,
    pending_flow_keep: BTreeSet<u32>,
    environment_value_producers: BTreeMap<ProvenanceRef, Vec<crate::flow::FlowRef>>,
    /// Effect ranges of commands xargs ran, with the argv index xargs filled
    /// from its unrecovered stdin, for `settle_stdin_arguments`, and
    /// whether the stage that supplies that stdin has been settled.
    stdin_arguments: Vec<(std::ops::Range<u32>, u32, bool)>,
    /// Those operands whose stdin is a channel a deferred process writes,
    /// with that channel's stage, until the process has been analyzed.
    channel_arguments: Vec<(u32, std::ops::Range<u32>, u32)>,
    /// NUL-framed path names emitted by an execution, not file contents.
    stdout_paths: Vec<(ExecutionNodeRef, crate::models::PrintedPaths)>,
    /// True only for final, unredirected stdout in the top-level shell.
    pub(crate) stdout_unconsumed: bool,
    /// A bare find listing feeds the next, literal xargs -0 stage directly.
    pub(crate) stdout_paths_to_xargs: bool,
    /// Source-to-destination pairings recorded while lowering transfers, as
    /// slots into `effects`. `build_causality` turns them into
    /// `ResourceTransfer` edges once occurrence identity is final.
    transfer_bindings: Vec<TransferBinding>,
    /// Host file mutations in walk order. Later source reads see these writes
    /// instead of the file content as it existed before the invocation.
    source_writes: Vec<SourceWrite>,
    /// Potentially concurrent/repeated writes, whether they change path identity,
    /// whether background work outlives its enclosing region, and the length
    /// of `source_writes` when the region began.
    source_hazards: Vec<(ResourceExpr, bool, bool, usize)>,
    /// Host `git config` writes in walk order, so a later git invocation in
    /// the same subject reads the configuration they set.
    git_config_writes: Vec<GitConfigWrite>,
    /// Host `git config` writes that the enclosing unordered regions make
    /// concurrently with their reads (`git gc | git config gc.pruneExpire
    /// now`), so a read walked before the writer still sees them as possible.
    /// Each names the pipeline stage it runs in, as a stage-stack depth and
    /// position, when the region is a pipeline: that stage's own reads run
    /// in order with it and see it only once it is recorded.
    git_config_hazards: Vec<(Option<(usize, usize)>, GitConfigWrite)>,
    /// The position of each enclosing pipeline stage being walked,
    /// outermost first.
    pipeline_stages: Vec<usize>,
    /// Every `git submodule foreach` call walked, indexed by its binding id.
    git_foreach_bindings: Vec<GitForeachBinding>,
    /// The ids of the foreach calls whose command is being walked,
    /// innermost last.
    git_foreach_stack: Vec<usize>,
    /// The subject exported a variable whose name is not statically known.
    unknown_environment_names: bool,
    /// Callables being walked, for required-on-success reachability.
    control: crate::control_flow::ControlStack,
}

/// Where the unordered-region hazards stood when a region began.
#[derive(Clone, Copy)]
pub(crate) struct HazardDepth {
    source: usize,
    git_config: usize,
}

/// One setting a `git config` invocation wrote.
#[derive(Clone)]
pub(crate) struct GitConfigWrite {
    /// The configuration file written.
    pub(crate) scope: GitConfigScope,
    /// The repository whose own configuration file was written; `None` for
    /// the system and global files every repository reads, and for a write
    /// redirected to a file any reader may include or select.
    pub(crate) repository: Option<ResourceExpr>,
    /// The key, or `None` when the invocation's key is not statically known.
    pub(crate) key: Option<String>,
    /// The value, or `None` when it is not statically known or was unset.
    pub(crate) value: Option<String>,
    /// The innermost foreach call the write ran in, which binds any
    /// `<git_submodule>` in `repository`.
    pub(crate) binding: Option<usize>,
    /// The pipeline stages the write ran in, outermost first.
    pub(crate) pipeline_stages: Vec<usize>,
}

/// One `git submodule foreach` call: its command runs in each submodule of
/// `superproject`, whose own `<git_submodule>` is bound by `parent`.
pub(crate) struct GitForeachBinding {
    pub(crate) superproject: ResourceExpr,
    pub(crate) parent: Option<usize>,
}

/// git-config(1)'s files, in the order git reads them: a later file
/// overrides an earlier one whatever order they were written in.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum GitConfigScope {
    System,
    Global,
    Local,
    Worktree,
}

struct SourceWrite {
    resource: ResourceExpr,
    changes_identity: bool,
    effect: Option<u32>,
    /// Exact bytes after the mutation, when a model proved them.
    content: Option<Vec<u8>>,
    /// Conditions active at the mutation; `None` when they cannot be compared.
    conditions: Option<Vec<Condition>>,
}

/// What a source read at a host path sees after earlier mutations.
pub(crate) enum WrittenSource {
    /// No earlier mutation reaches the path; the host file is authoritative.
    Host,
    /// Every path to this read passes the write that produced these bytes.
    Exact(Vec<u8>),
    /// A mutation may have replaced the file with bytes the walk cannot name.
    Stale,
    /// The exact write is conditional on a path the read may not take.
    Ambiguous,
}

/// Saved builder state for a speculative walk (e.g. measuring a case arm's
/// budget demand). Every plan vector is append-only during a walk, so a
/// rollback truncates them; the small merge maps are cloned outright.
pub(crate) struct BuilderCheckpoint {
    effects: usize,
    execution_nodes: usize,
    execution_edges: usize,
    execution_stack: usize,
    execution_saturated: BTreeSet<ExecutionNodeRef>,
    effect_id_subjects: BTreeSet<ExecutionNodeRef>,
    provenance: usize,
    boundaries: usize,
    coverage: BTreeMap<Domain, CoverageLevel>,
    saturated: BTreeMap<&'static str, bool>,
    realm_stack: usize,
    accounted_effect_bytes: u64,
    condition_stack: usize,
    condition_overflow: usize,
    flow_stages: usize,
    flow_edges: usize,
    flow_coverage: CoverageLevel,
    pending_flow_stages: usize,
    pending_flow_edges: usize,
    pending_flow_keep: BTreeSet<u32>,
    environment_value_producers: BTreeMap<ProvenanceRef, Vec<crate::flow::FlowRef>>,
    stdin_arguments: usize,
    channel_arguments: usize,
    stdout_paths: usize,
    transfer_bindings: usize,
    source_writes: usize,
    source_hazards: usize,
    git_config_writes: usize,
    git_config_hazards: usize,
    control: crate::control_flow::ControlCheckpoint,
}

/// Whether a mutation of `written` can change the file at `path`: the file
/// itself or a directory containing it.
fn written_path_reaches(written: &str, path: &str) -> bool {
    path.strip_prefix(written)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/') || written.ends_with('/'))
}

/// Unknown targets may alias any source; retain disjointness supplied by typed
/// paths, finite alternatives, and filesystem patterns in reviewed models.
fn source_mutation_reaches(resource: &ResourceExpr, path: &str) -> bool {
    match resource {
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path: written },
        } => written_path_reaches(written, path),
        ResourceExpr::Concrete { .. } => false,
        ResourceExpr::Union { alternatives } => alternatives
            .iter()
            .any(|resource| source_mutation_reaches(resource, path)),
        ResourceExpr::Pattern {
            pattern: effinterp_proto::ResourcePattern::FsPath { glob },
        } => {
            let mut ancestor = path;
            loop {
                if effinterp_proto::glob_match(glob, ancestor).unwrap_or(true) {
                    return true;
                }
                let Some((parent, _)) = ancestor.rsplit_once('/') else {
                    return false;
                };
                if parent.is_empty() {
                    if ancestor == "/" {
                        return false;
                    }
                    ancestor = "/";
                } else {
                    ancestor = parent;
                }
            }
        }
        // A resolver's relative selection and a cwd-relative resource share
        // the invocation cwd even when its absolute value was not supplied.
        ResourceExpr::Join { parts } if !path.starts_with('/') => {
            let mut parts = parts.as_slice();
            if matches!(parts.first(), Some(ResourceExpr::Parameter { name }) if name == "cwd") {
                parts = &parts[1..];
            }
            let Some(parts) = parts
                .iter()
                .map(|part| match part {
                    ResourceExpr::Concrete {
                        identity: ResourceIdentity::FsPath { path },
                    } => Some(path.as_str()),
                    _ => None,
                })
                .collect::<Option<Vec<_>>>()
            else {
                return true;
            };
            written_path_reaches(&crate::paths::normalize_path(&parts.join("/")), path)
        }
        ResourceExpr::Join { parts } => {
            // A symbolic prefix cannot erase a fixed, traversal-free suffix.
            // Check directory ancestors too: mutations may replace a whole tree.
            let suffix = parts
                .iter()
                .rev()
                .take_while(|part| {
                    matches!(
                        part,
                        ResourceExpr::Literal { .. }
                            | ResourceExpr::Concrete {
                                identity: ResourceIdentity::FsPath { .. }
                            }
                    )
                })
                .collect::<Vec<_>>();
            let mut tail = String::new();
            for part in suffix.into_iter().rev() {
                match part {
                    ResourceExpr::Literal { value } => tail.push_str(value),
                    ResourceExpr::Concrete {
                        identity: ResourceIdentity::FsPath { path },
                    } => {
                        if !tail.ends_with('/') && !path.starts_with('/') {
                            tail.push('/');
                        }
                        tail.push_str(path);
                    }
                    _ => unreachable!(),
                }
            }
            if tail.is_empty() || tail.split('/').any(|part| matches!(part, "." | "..")) {
                return true;
            }
            let mut ancestor = path;
            loop {
                if ancestor.ends_with(tail.trim_end_matches('/')) {
                    return true;
                }
                let Some((parent, _)) = ancestor.rsplit_once('/') else {
                    return false;
                };
                if parent.is_empty() {
                    if ancestor == "/" {
                        return false;
                    }
                    ancestor = "/";
                } else {
                    ancestor = parent;
                }
            }
        }
        _ => true,
    }
}

fn worse(a: CoverageLevel, b: CoverageLevel) -> CoverageLevel {
    use CoverageLevel::*;
    match (a, b) {
        (None, _) | (_, None) => None,
        (Partial, _) | (_, Partial) => Partial,
        (Full, Full) => Full,
    }
}

impl PlanBuilder {
    pub fn new(
        subject: Subject,
        engine_version: String,
        model_set: String,
        limits: AnalysisLimits,
    ) -> Self {
        let path_platform = crate::paths::path_platform(subject_cwd(&subject));
        let argv = match &subject {
            Subject::Exec { argv, .. } => argv
                .iter()
                .map(|value| ResourceExpr::Literal {
                    value: value.clone(),
                })
                .collect(),
            _ => Vec::new(),
        };
        let cwd = subject_cwd(&subject).map(|path| ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath {
                path: crate::paths::normalize_cwd(path),
            },
        });
        let root = ExecutionNode {
            subject: subject.clone(),
            boundary: None,
            argv,
            cwd,
            environment: BTreeMap::new(),
            streams: ExecutionStreams::default(),
            mounts: Vec::new(),
            source_span: None,
            realm: ExecutionRealm::Host,
            assurance: ExecutionAssurance::Exact,
            evidence: Vec::new(),
            input: None,
        };
        Self {
            subject,
            analysis: Analysis {
                engine_version,
                model_set,
                limits: limits.to_map(),
                outcome: effinterp_proto::AnalysisOutcome::Complete,
            },
            path_platform,
            budget: Rc::new(Budget::new(&limits)),
            limits,
            effects: Vec::new(),
            execution_nodes: vec![root],
            execution_edges: Vec::new(),
            execution_stack: vec![ExecutionNodeRef(0)],
            runtime_shells: BTreeMap::new(),
            execution_saturated: BTreeSet::new(),
            effect_id_subjects: BTreeSet::new(),
            provenance: Vec::new(),
            source_span_offsets: vec![0],
            last_source_span: None,
            provenance_memo: HashMap::new(),
            boundaries: Vec::new(),
            coverage: BTreeMap::new(),
            saturated: BTreeMap::new(),
            realm_stack: Vec::new(),
            accounted_effect_bytes: 0,
            condition_stack: Vec::new(),
            condition_reservations: Vec::new(),
            condition_overflow: 0,
            condition_call: None,
            flow_stages: Vec::new(),
            flow_edges: Vec::new(),
            flow_coverage: CoverageLevel::Full,
            pending_flow_stages: Vec::new(),
            pending_flow_edges: Vec::new(),
            pending_flow_keep: BTreeSet::new(),
            environment_value_producers: BTreeMap::new(),
            stdin_arguments: Vec::new(),
            channel_arguments: Vec::new(),
            stdout_paths: Vec::new(),
            stdout_unconsumed: false,
            stdout_paths_to_xargs: false,
            transfer_bindings: Vec::new(),
            source_writes: Vec::new(),
            source_hazards: Vec::new(),
            git_config_writes: Vec::new(),
            git_config_hazards: Vec::new(),
            pipeline_stages: Vec::new(),
            git_foreach_bindings: Vec::new(),
            git_foreach_stack: Vec::new(),
            unknown_environment_names: false,
            control: Default::default(),
        }
    }

    /// Snapshot for a speculative walk; undo it with
    /// [`PlanBuilder::rollback`]. Refs handed out after the checkpoint become
    /// dangling on rollback, so the caller must not retain any.
    pub(crate) fn checkpoint(&self) -> BuilderCheckpoint {
        BuilderCheckpoint {
            effects: self.effects.len(),
            execution_nodes: self.execution_nodes.len(),
            execution_edges: self.execution_edges.len(),
            execution_stack: self.execution_stack.len(),
            execution_saturated: self.execution_saturated.clone(),
            effect_id_subjects: self.effect_id_subjects.clone(),
            provenance: self.provenance.len(),
            boundaries: self.boundaries.len(),
            coverage: self.coverage.clone(),
            saturated: self.saturated.clone(),
            realm_stack: self.realm_stack.len(),
            accounted_effect_bytes: self.accounted_effect_bytes,
            condition_stack: self.condition_stack.len(),
            condition_overflow: self.condition_overflow,
            flow_stages: self.flow_stages.len(),
            flow_edges: self.flow_edges.len(),
            flow_coverage: self.flow_coverage,
            pending_flow_stages: self.pending_flow_stages.len(),
            pending_flow_edges: self.pending_flow_edges.len(),
            pending_flow_keep: self.pending_flow_keep.clone(),
            environment_value_producers: self.environment_value_producers.clone(),
            stdin_arguments: self.stdin_arguments.len(),
            channel_arguments: self.channel_arguments.len(),
            stdout_paths: self.stdout_paths.len(),
            transfer_bindings: self.transfer_bindings.len(),
            source_writes: self.source_writes.len(),
            source_hazards: self.source_hazards.len(),
            git_config_writes: self.git_config_writes.len(),
            git_config_hazards: self.git_config_hazards.len(),
            control: self.control.checkpoint(),
        }
    }

    pub(crate) fn rollback(&mut self, cp: BuilderCheckpoint) {
        self.budget
            .release_bytes(self.accounted_effect_bytes - cp.accounted_effect_bytes);
        self.accounted_effect_bytes = cp.accounted_effect_bytes;
        self.effects.truncate(cp.effects);
        self.execution_nodes.truncate(cp.execution_nodes);
        self.execution_edges.truncate(cp.execution_edges);
        self.execution_stack.truncate(cp.execution_stack);
        self.runtime_shells
            .retain(|node, _| (node.0 as usize) < cp.execution_nodes);
        self.execution_saturated = cp.execution_saturated;
        self.effect_id_subjects = cp.effect_id_subjects;
        self.provenance.truncate(cp.provenance);
        self.provenance_memo
            .retain(|_, r| (r.0 as usize) < cp.provenance);
        self.boundaries.truncate(cp.boundaries);
        self.coverage = cp.coverage;
        self.saturated = cp.saturated;
        self.realm_stack.truncate(cp.realm_stack);
        self.condition_stack.truncate(cp.condition_stack);
        self.condition_reservations.truncate(cp.condition_stack);
        self.condition_overflow = cp.condition_overflow;
        self.flow_stages.truncate(cp.flow_stages);
        self.flow_edges.truncate(cp.flow_edges);
        self.flow_coverage = cp.flow_coverage;
        self.pending_flow_stages.truncate(cp.pending_flow_stages);
        self.pending_flow_edges.truncate(cp.pending_flow_edges);
        self.pending_flow_keep = cp.pending_flow_keep;
        self.environment_value_producers = cp.environment_value_producers;
        self.stdin_arguments.truncate(cp.stdin_arguments);
        self.channel_arguments.truncate(cp.channel_arguments);
        self.stdout_paths.truncate(cp.stdout_paths);
        self.transfer_bindings.truncate(cp.transfer_bindings);
        self.source_writes.truncate(cp.source_writes);
        self.source_hazards.truncate(cp.source_hazards);
        self.git_config_writes.truncate(cp.git_config_writes);
        self.git_config_hazards.truncate(cp.git_config_hazards);
        self.control.rollback(cp.control);
    }

    /// Enter an execution realm; effects added until the matching
    /// [`PlanBuilder::pop_realm`] are stamped with it.
    pub fn push_realm(&mut self, realm: ExecutionRealm) {
        self.realm_stack.push(realm);
    }

    pub fn pop_realm(&mut self) {
        self.realm_stack.pop();
    }

    pub(crate) fn current_realm(&self) -> ExecutionRealm {
        self.realm_stack.last().cloned().unwrap_or_default()
    }

    pub(crate) fn is_host_realm(&self) -> bool {
        self.realm_stack.last().is_none_or(ExecutionRealm::is_host)
    }

    /// Rewrite `resource` to what the invocation's own link creations say it
    /// names, and return the creation evidence used. A link can name another
    /// link; the chain is finite because each step consumes one creation this
    /// plan already recorded and a name may not repeat, so `ln -s a b;
    /// ln -s b a` stops instead of walking forever.
    pub(crate) fn follow_created_aliases(&self, resource: &mut ResourceExpr) -> Vec<ProvenanceRef> {
        let mut nodes = Vec::new();
        let mut seen = vec![resource.clone()];
        while let Some((target, provenance)) = self.created_alias_identity(resource) {
            if seen.contains(&target) {
                break;
            }
            seen.push(target.clone());
            *resource = target;
            nodes.extend(provenance);
        }
        nodes
    }

    /// Resolve content through names established by this invocation. A move
    /// carries an already-observed identity, so reaching one also tells the
    /// caller not to query the host's now-obsolete path state.
    pub(crate) fn follow_created_content_identity(
        &self,
        resource: &mut ResourceExpr,
    ) -> (Vec<ProvenanceRef>, bool) {
        let mut nodes = Vec::new();
        let mut seen = vec![resource.clone()];
        loop {
            if let Some((target, provenance)) = self.moved_content_identity(resource) {
                if seen.contains(&target) {
                    return (nodes, true);
                }
                *resource = target;
                nodes.extend(provenance);
                return (nodes, false);
            }
            let Some((target, provenance)) = self.created_alias_identity(resource) else {
                return (nodes, true);
            };
            if seen.contains(&target) {
                return (nodes, true);
            }
            seen.push(target.clone());
            *resource = target;
            nodes.extend(provenance);
        }
    }

    fn moved_content_identity(
        &self,
        resource: &ResourceExpr,
    ) -> Option<(ResourceExpr, Vec<ProvenanceRef>)> {
        if self
            .source_hazards
            .iter()
            .any(|(hazard, changes_identity, _, _)| *changes_identity && hazard == resource)
        {
            return None;
        }
        let current_condition = self.current_condition();
        crate::resource_transfer::moved_content_identity(
            &self.effects,
            &self.execution_nodes,
            &self.transfer_bindings,
            &self.provenance,
            resource,
            self.current_execution(),
            current_condition.as_ref(),
        )
    }

    /// The host path a use of `path` actually reaches, when the invocation
    /// created that name as a link to somewhere else.
    pub(crate) fn created_alias_path(&self, path: &str) -> Option<(String, Vec<ProvenanceRef>)> {
        let mut resource = ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath {
                path: path.to_string(),
            },
        };
        let provenance = self.follow_created_aliases(&mut resource);
        if provenance.is_empty() {
            return None;
        }
        match resource {
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path },
            } => Some((path, provenance)),
            _ => None,
        }
    }

    pub(crate) fn archived_symlink_source(
        &self,
        resource: &ResourceExpr,
    ) -> Option<(ResourceExpr, String, Vec<ProvenanceRef>)> {
        crate::resource_transfer::archived_symlink_source(
            &self.effects,
            &self.execution_nodes,
            resource,
        )
    }

    /// What a path created as a link earlier in this invocation names, from
    /// the plan's own evidence. The host's initial snapshot predates such a
    /// path, so it is the only evidence there is.
    ///
    /// Walk order is that evidence, so a creation the walk cannot place before
    /// this use — background work, or a region a later iteration re-enters —
    /// says nothing about the name this use meets.
    pub(crate) fn created_alias_identity(
        &self,
        resource: &ResourceExpr,
    ) -> Option<(ResourceExpr, Vec<ProvenanceRef>)> {
        let resolve = |candidate: &ResourceExpr| {
            if self
                .source_hazards
                .iter()
                .any(|(hazard, changes_identity, _, _)| *changes_identity && hazard == candidate)
            {
                return None;
            }
            crate::resource_transfer::created_alias_identity(
                &self.effects,
                &self.execution_nodes,
                &self.transfer_bindings,
                candidate,
            )
        };
        if let Some(identity) = resolve(resource) {
            return Some(identity);
        }
        let ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } = resource
        else {
            return None;
        };
        for split in path.match_indices('/').map(|(index, _)| index).rev() {
            if split == 0 {
                continue;
            }
            let parent = ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath {
                    path: path[..split].to_string(),
                },
            };
            let Some((target, provenance)) = resolve(&parent) else {
                continue;
            };
            let ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path: target },
            } = target
            else {
                return None;
            };
            return Some((
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath {
                        path: format!("{}/{}", target.trim_end_matches('/'), &path[split + 1..]),
                    },
                },
                provenance,
            ));
        }
        None
    }

    pub(crate) fn enter_condition_call(&mut self, site: &str) -> Option<String> {
        let next = effinterp_proto::stable_hash(
            effinterp_proto::CONDITION_CALL_HASH_DOMAIN,
            &(&self.condition_call, site),
        );
        self.condition_call.replace(next)
    }

    pub(crate) fn leave_condition_call(&mut self, previous: Option<String>) {
        self.condition_call = previous;
    }

    pub(crate) fn bind_source_condition(&self, condition: &mut Option<Condition>) {
        if let (Some(condition), Some(instance)) = (condition, &self.condition_call) {
            condition.rebind(instance);
        }
    }

    pub(crate) fn current_condition(&self) -> Option<Condition> {
        self.condition_since(0)
    }

    /// Summary inference excludes conditions belonging to its caller.
    pub(crate) fn condition_since(&self, depth: usize) -> Option<Condition> {
        if self.condition_overflow > 0 && self.condition_depth() > depth {
            Some(Condition::Widened)
        } else {
            Condition::compose(self.condition_stack.iter().skip(depth))
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn source_condition(
        &self,
        source: &str,
        span: effinterp_proto::ByteSpan,
        kind: effinterp_proto::ConditionKind,
        arm: u32,
        arms: u32,
        exhaustive: bool,
        boolean: bool,
    ) -> Condition {
        self.source_condition_path(Condition::from_source(
            source, span, kind, arm, arms, exhaustive, boolean,
        ))
    }

    pub(crate) fn source_condition_path(&self, mut condition: Condition) -> Condition {
        let node = &self.execution_nodes[self.current_execution().0 as usize];
        if let Condition::Atom { atom } = &mut condition
            && let effinterp_proto::ConditionEvidence::Source { path, .. } = &mut atom.evidence
        {
            *path = node.selected_source_path().map(str::to_owned);
        }
        condition
    }

    pub(crate) fn push_condition(&mut self, mut condition: Condition) {
        if let Some(instance) = &self.condition_call {
            condition.rebind(instance);
        }
        self.push_bound_condition(condition);
    }

    pub(crate) fn push_bound_condition(&mut self, mut condition: Condition) {
        if self.condition_stack.len() >= effinterp_proto::MAX_CONDITION_DEPTH {
            self.condition_overflow += 1;
            return;
        }
        let mut reservation = crate::guards::ConditionReservation::new(self.budget.clone());
        if !reservation.charge(1, condition.retained_bytes()) {
            condition = Condition::Widened;
        }
        self.condition_stack.push(condition);
        self.condition_reservations.push(reservation);
    }

    /// How deeply the current effect is nested in conditions. Frontends use
    /// it to order the branch atoms they emit, which composition sorts.
    pub(crate) fn condition_depth(&self) -> usize {
        self.condition_stack.len() + self.condition_overflow
    }

    pub(crate) fn pop_condition(&mut self) {
        if self.condition_overflow > 0 {
            self.condition_overflow -= 1;
        } else {
            self.condition_stack.pop();
            self.condition_reservations.pop();
        }
    }

    pub(crate) fn set_deadline(&mut self, deadline: Option<crate::InvocationDeadline>) {
        Rc::get_mut(&mut self.budget)
            .expect("unshared builder budget")
            .deadline = deadline;
    }

    /// Install the caller's observation channel for this analysis. Absent, the
    /// engine demands no host facts at all.
    pub(crate) fn set_observations(
        &mut self,
        observations: Option<std::sync::Arc<dyn crate::ObservationResolver>>,
    ) {
        Rc::get_mut(&mut self.budget)
            .expect("unshared builder budget")
            .observations = observations;
    }

    pub(crate) fn set_cancel_flag(
        &mut self,
        flag: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    ) {
        Rc::get_mut(&mut self.budget)
            .expect("budget is not shared before analysis")
            .cancel = flag;
    }

    /// The shared budget this analysis charges. Handed to the frontends so a
    /// nested walk and the plan vectors draw from one pool.
    pub(crate) fn budget(&self) -> Rc<Budget> {
        self.budget.clone()
    }

    pub(crate) fn path_platform(&self) -> effinterp_proto::PathPlatform {
        self.path_platform
    }

    /// An unfinished invocation can affect effect and causality coverage alike.
    pub(crate) fn note_deadline(&mut self) {
        self.analysis.outcome = effinterp_proto::AnalysisOutcome::Refused {
            kind: effinterp_proto::AnalysisRefusalKind::DeadlineExceeded,
        };
        self.note_saturated_domains("invocation_deadline", &KNOWN_DOMAINS);
        self.note_saturated_domains("invocation_deadline", &["dataflow"]);
    }

    pub(crate) fn control_caps(&self) -> crate::control_flow::ControlCaps {
        crate::control_flow::ControlCaps {
            nodes: self.limits.max_causal_nodes,
            work: self.limits.max_causal_pairs,
        }
    }

    /// Record a limit's saturation once, degrading every known domain to
    /// partial (the overflow could have belonged to any domain). Returns true
    /// the first time a given limit saturates. Pushes the boundary directly to
    /// avoid recursing through the boundary cap.
    pub(crate) fn note_saturated(&mut self, limit: &'static str) -> bool {
        self.note_saturated_domains(limit, &KNOWN_DOMAINS)
    }

    fn note_saturated_domains(&mut self, limit: &'static str, domains: &[&str]) -> bool {
        let limit = if limit == "max_analysis_steps" && self.budget.timed_out() {
            "invocation_deadline"
        } else {
            limit
        };
        if limit == "invocation_deadline" {
            self.analysis.outcome = effinterp_proto::AnalysisOutcome::Refused {
                kind: effinterp_proto::AnalysisRefusalKind::DeadlineExceeded,
            };
        }
        if self.saturated.insert(limit, true).is_some() {
            let boundary = self
                .boundaries
                .iter_mut()
                .find(|boundary| boundary.limit.as_deref() == Some(limit))
                .expect("saturated limit has retained evidence");
            for domain in domains {
                let domain = Domain::new(*domain);
                if !boundary.domains.contains(&domain) {
                    boundary.domains.push(domain);
                }
            }
            for domain in domains {
                self.merge_coverage(Domain::new(*domain), CoverageLevel::Partial);
            }
            return false;
        }
        self.boundaries.push(Boundary {
            reason: BoundaryReason::LIMIT_SATURATED,
            class: BoundaryClass::Limit,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: domains.iter().map(|domain| Domain::new(*domain)).collect(),
            provenance: Vec::new(),
            limit: Some(limit.to_string()),
            detail: None,
        });
        for domain in domains {
            self.merge_coverage(Domain::new(*domain), CoverageLevel::Partial);
        }
        true
    }

    pub(crate) fn note_saturated_detail(&mut self, limit: &'static str, detail: String) {
        self.note_saturated(limit);
        if let Some(boundary) = self
            .boundaries
            .iter_mut()
            .find(|boundary| boundary.limit.as_deref() == Some(limit))
        {
            boundary.detail = Some(detail);
        }
    }

    /// [`PlanBuilder::note_saturated`] plus one source span for the construct
    /// being processed when the budget refused a charge, so a saturated plan
    /// says where the analysis stopped. The span node is minted past
    /// `max_provenance_nodes` — a one-shot reserve, like the boundary itself.
    pub(crate) fn note_saturated_at(
        &mut self,
        limit: &'static str,
        span: Option<(u32, u32)>,
    ) -> bool {
        let limit = if limit == "max_analysis_steps" && self.budget.timed_out() {
            "invocation_deadline"
        } else {
            limit
        };
        if limit == "invocation_deadline" {
            self.analysis.outcome = effinterp_proto::AnalysisOutcome::Refused {
                kind: effinterp_proto::AnalysisRefusalKind::DeadlineExceeded,
            };
        }
        let span = span.or(self.last_source_span);
        let first = self.note_saturated(limit);
        // A refusal charged without a span in hand (a value walk, a bound
        // variable) records the boundary; the next refusal that does have one
        // fills it in, so the boundary always says where analysis stopped.
        if let Some((start, end)) = span
            && let Some(index) = self.boundaries.iter().rposition(|boundary| {
                boundary.reason == BoundaryReason::LIMIT_SATURATED
                    && boundary.limit.as_deref() == Some(limit)
                    && boundary.provenance.is_empty()
            })
        {
            let node = self.reserved_span_node(start, end);
            self.boundaries[index].provenance = vec![node];
        }
        first
    }

    /// The first source span among `provenance`, already offset into the host
    /// file. Spans handed to `note_saturated_at` are re-offset, so this
    /// subtracts the current offset back out.
    fn first_source_span(&self, provenance: &[ProvenanceRef]) -> Option<(u32, u32)> {
        let offset = self.source_span_offsets.last().copied().unwrap_or_default();
        provenance.iter().find_map(|reference| {
            match self.provenance.get(reference.0 as usize)?.kind {
                ProvenanceKind::SourceSpan { start, end } => {
                    Some((start.saturating_sub(offset), end.saturating_sub(offset)))
                }
                _ => None,
            }
        })
    }

    /// Mint one source-span node regardless of `max_provenance_nodes`, so a
    /// budget-saturation boundary always carries its span.
    fn reserved_span_node(&mut self, start: u32, end: u32) -> ProvenanceRef {
        let offset = self.source_span_offsets.last().copied().unwrap_or_default();
        let node = ProvenanceNode {
            kind: ProvenanceKind::SourceSpan {
                start: start + offset,
                end: end + offset,
            },
            antecedents: Vec::new(),
        };
        if let Some(existing) = self.provenance_memo.get(&node) {
            return *existing;
        }
        self.provenance.push(node.clone());
        let reference = ProvenanceRef((self.provenance.len() - 1) as u32);
        self.provenance_memo.insert(node, reference);
        reference
    }

    pub fn node(&mut self, kind: ProvenanceKind, antecedents: &[ProvenanceRef]) -> ProvenanceRef {
        self.node_with_saturation_domains(kind, antecedents, &KNOWN_DOMAINS)
    }

    /// Add provenance whose overflow is known to be confined to one domain.
    pub(crate) fn node_in_domain(
        &mut self,
        kind: ProvenanceKind,
        antecedents: &[ProvenanceRef],
        domain: &'static str,
    ) -> ProvenanceRef {
        self.node_with_saturation_domains(kind, antecedents, &[domain])
    }

    fn node_with_saturation_domains(
        &mut self,
        mut kind: ProvenanceKind,
        antecedents: &[ProvenanceRef],
        domains: &[&str],
    ) -> ProvenanceRef {
        // Captured before the offset is applied: `reserved_span_node` applies
        // the same offset itself.
        let source_span = match kind {
            ProvenanceKind::SourceSpan { start, end } => Some((start, end)),
            _ => None,
        };
        if let Some(source_span) = source_span {
            self.last_source_span = Some(source_span);
        }
        if let ProvenanceKind::SourceSpan { start, end } = &mut kind {
            let offset = self.source_span_offsets.last().copied().unwrap_or_default();
            *start += offset;
            *end += offset;
        }
        let node = ProvenanceNode {
            kind,
            antecedents: antecedents.to_vec(),
        };
        if !self.budget.try_charge_steps(1) {
            self.note_saturated_at("max_analysis_steps", source_span);
        }
        if let Some(existing) = self.provenance_memo.get(&node) {
            return *existing;
        }
        if self.provenance.len() as u64 >= self.limits.max_provenance_nodes {
            // Escape hatch: keep exactly one sentinel node past the limit so
            // every returned ref stays in bounds even when the limit is 0. The
            // saturation boundary marks provenance as incomplete.
            if self.note_saturated_domains("max_provenance_nodes", domains) {
                self.provenance.push(ProvenanceNode {
                    kind: ProvenanceKind::SourceSpan { start: 0, end: 0 },
                    antecedents: Vec::new(),
                });
            }
            return ProvenanceRef((self.provenance.len() - 1) as u32);
        }
        self.provenance.push(node.clone());
        let r = ProvenanceRef((self.provenance.len() - 1) as u32);
        self.provenance_memo.insert(node, r);
        r
    }

    pub(crate) fn nested_stack_depths(&self) -> [usize; 3] {
        [
            self.execution_stack.len(),
            self.realm_stack.len(),
            self.source_span_offsets.len(),
        ]
    }

    pub(crate) fn current_source_span_offset(&self) -> u32 {
        self.source_span_offsets.last().copied().unwrap_or_default()
    }

    pub(crate) fn push_source_span_offset(&mut self, offset: u32) {
        self.source_span_offsets.push(offset);
    }

    pub(crate) fn pop_source_span_offset(&mut self) {
        self.source_span_offsets.pop();
    }

    /// Add an effect, respecting `max_effects`. On saturation the effect is
    /// dropped, one saturation boundary is recorded, and coverage degrades.
    /// The effect's shared step is charged before any normalization work.
    ///
    /// The returned slot is its index in the plan's effect
    /// list, or `None` when the effect was refused (an unregistered operation,
    /// or a saturated limit); a transfer emitter pairs the slots it gets back.
    pub fn effect(&mut self, effect: Effect) -> Option<u32> {
        self.effect_with_saturation_domains(effect, &KNOWN_DOMAINS)
    }

    /// Add an effect whose overflow is known to be confined to one domain.
    pub(crate) fn effect_in_domain(&mut self, effect: Effect, domain: &'static str) -> Option<u32> {
        self.effect_with_saturation_domains(effect, &[domain])
    }

    /// Record that the effect in slot `source` is the source side of one
    /// modeled transfer whose destination side is slot `destination`. Both
    /// slots must already hold an effect; a refused endpoint contributes no
    /// pairing, which is why the emitters pass through
    /// [`crate::TransferBinding`] rather than positions they assumed.
    pub(crate) fn transfer_binding(&mut self, binding: TransferBinding) {
        let slots = self.effects.len() as u32;
        if binding.source >= slots || binding.destination >= slots {
            return;
        }
        if binding.source == binding.destination {
            return;
        }
        if self.transfer_bindings.contains(&binding) {
            return;
        }
        // One binding becomes at most one causal edge, so the graph's own
        // edge bound also bounds how many pairings are retained.
        if self.transfer_bindings.len() as u64 >= self.limits.max_causal_edges {
            self.note_causality_saturated("max_causal_edges");
            return;
        }
        if !self.budget.try_charge_bytes(transfer_binding_bytes()) {
            self.note_saturated_at("max_analysis_bytes", None);
            return;
        }
        self.transfer_bindings.push(binding);
    }

    /// Record every pairing of one operation's source and destination slots.
    pub(crate) fn transfer_bindings(&mut self, bindings: &[TransferBinding]) {
        for binding in bindings {
            self.transfer_binding(*binding);
        }
    }

    fn effect_with_saturation_domains(
        &mut self,
        mut effect: Effect,
        domains: &[&str],
    ) -> Option<u32> {
        if effect.operation.spec().is_none() {
            self.boundary_with_coverage(
                Boundary {
                    reason: BoundaryReason::UNTYPED_RESOURCE,
                    class: BoundaryClass::Unresolved,
                    scope: BoundaryScope::Invocation,
                    domains: vec![Domain::new(effect.operation.domain())],
                    affected_resource: Some(unresolved_resource(effect.operation.domain())),
                    callee: None,
                    provenance: effect.provenance,
                    limit: None,
                    detail: Some(format!(
                        "unregistered_operation: {}",
                        effect.operation.as_str()
                    )),
                },
                CoverageLevel::Partial,
            );
            return None;
        }
        // The effect's own source span explains where the budget ran out.
        let span = self.first_source_span(&effect.provenance);
        if !self.budget.try_charge_steps(1) {
            self.note_saturated_at("max_analysis_steps", span);
            return None;
        }
        if (self.effects.len() as u64) >= self.limits.max_effects {
            self.note_saturated_domains("max_effects", domains);
            return None;
        }
        let depth_limited = bound_resource_depth(
            &mut effect.resource,
            MAX_RESOURCE_DEPTH,
            effect.operation.domain(),
        );
        if depth_limited {
            effect.request_assurance = effinterp_proto::RequestAssurance::Conservative;
        }
        if depth_limited && effect.operation.domain() == "artifact" {
            self.boundary(Boundary {
                reason: BoundaryReason::MODEL_COVERAGE,
                class: BoundaryClass::Unresolved,
                scope: BoundaryScope::Invocation,
                domains: vec![Domain::new("artifact")],
                affected_resource: Some(effect.resource.clone()),
                callee: None,
                provenance: effect.provenance.clone(),
                limit: None,
                detail: Some("artifact field exceeds the bounded resource depth".into()),
            });
        }
        if let ResourceExpr::Pattern {
            pattern: effinterp_proto::ResourcePattern::FsPath { glob },
        } = &mut effect.resource
            && let Some(collapsed) = effinterp_proto::collapse_wildcard_parents(glob)
        {
            let original = std::mem::replace(glob, collapsed);
            self.boundary(Boundary {
                reason: BoundaryReason::OBSERVATION_UNAVAILABLE,
                class: BoundaryClass::Unresolved,
                scope: BoundaryScope::Invocation,
                domains: vec![Domain::new(effect.operation.domain())],
                affected_resource: Some(effect.resource.clone()),
                callee: None,
                provenance: effect.provenance.clone(),
                limit: None,
                detail: Some(format!(
                    "{original}: a parent after a wildcard is read as the wildcard's directory; a match that is a symlink resolves it at its target's parent"
                )),
            });
        }
        effect.resource = effinterp_proto::normalize_resource(effect.resource, self.path_platform);
        let mut alias_resource = None;
        if effect.operation.as_str() == "filesystem.write"
            && let Some((target, provenance)) = self.created_alias_identity(&effect.resource)
        {
            alias_resource = Some(effect.resource.clone());
            effect.resource = target;
            effect.provenance.extend(provenance);
        }
        // `execve` follows the final component too, and a hard link is the
        // same inode, so the program a created name runs is the program its
        // target holds. The spelled name stays in argv and in the execution
        // input; only the executable's identity is the target's.
        if matches!(
            effect.operation.as_str(),
            "process.exec" | "process.code_execution"
        ) && let ResourceExpr::Concrete {
            identity: ResourceIdentity::Process {
                path: Some(path), ..
            },
        } = &effect.resource
            && let Some((target, provenance)) = self.created_alias_path(path)
        {
            if let ResourceExpr::Concrete {
                identity: ResourceIdentity::Process { path, .. },
            } = &mut effect.resource
            {
                *path = Some(target);
            }
            effect.provenance.extend(provenance);
        }
        // `realpath` prints the canonical path of its operand. When the host
        // establishes it, a filesystem effect on the printed path is an
        // effect on that path; otherwise the property stays.
        if effect.operation.domain() == "filesystem"
            && let ResourceExpr::Property { base, name } = &effect.resource
            && name == "realpath"
            && let ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path },
            } = base.as_ref()
            && let Some((canonical, node)) =
                crate::models::common::observed_canonical_path(self, path, &effect.provenance)
        {
            effect.resource = ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path: canonical },
            };
            effect.provenance.push(node);
        }
        // A read of the operand's contents reaches the file its final
        // component points at. Resolve that identity here, before the resource
        // keys a flow frontier or a transfer pairing: a later rewrite of the
        // displayed resource cannot repair an edge already keyed on the
        // lexical spelling. Emitters whose operation names the entry itself —
        // link creation, rename, unlink, metadata — never enter this branch.
        if crate::models::common::reads_operand_contents(&effect) {
            let use_site = effect.provenance.clone();
            let nodes =
                crate::models::common::follow_final_link(self, &mut effect.resource, &use_site);
            effect.provenance.extend(nodes);
        }
        // Whatever this effect changes about filesystem topology invalidates
        // reliance on an initial fact about that entry or anything beneath it.
        if matches!(
            effect.operation.as_str(),
            "filesystem.create" | "filesystem.delete" | "filesystem.move"
        ) {
            self.budget.note_topology_mutation(match &effect.resource {
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path },
                } => Some(path.as_str()),
                _ => None,
            });
        }
        if effect.operation.as_str() == "filesystem.write" && effect.realm.is_host() {
            self.budget.note_write(match &effect.resource {
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path },
                } => Some(path.as_str()),
                _ => None,
            });
        }
        if retract_invalid_scope_values(&mut effect.resource) {
            effect.request_assurance = effinterp_proto::RequestAssurance::Conservative;
            self.boundary(Boundary {
                reason: BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                class: BoundaryClass::Unresolved,
                scope: BoundaryScope::Invocation,
                domains: vec![Domain::new(effect.operation.domain())],
                affected_resource: Some(effect.resource.clone()),
                callee: None,
                provenance: effect.provenance.clone(),
                limit: None,
                detail: Some("invalid resource scope value; affected dimension is unknown".into()),
            });
        }
        let kernel_trigger = effect.operation.as_str() == "filesystem.write"
            && matches!(&effect.resource, ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } } if matches!(path.as_str(), "/proc/sysrq-trigger" | "/proc/sys/kernel/sysrq" | "/sys/power/state"));
        let trigger = kernel_trigger.then(|| {
            let mut trigger = effect.clone();
            trigger.operation =
                effinterp_proto::Operation::new(crate::models::system::KERNEL_TRIGGER);
            trigger.attributes.clear();
            trigger.request_assurance = effinterp_proto::RequestAssurance::Conservative;
            trigger
        });
        let mut errors = Vec::new();
        effinterp_proto::validate_effect_resource(
            self.effects.len(),
            &effect.operation,
            &effect.resource,
            &mut errors,
        );
        if let Some(error) = errors.first() {
            let domain = effect.operation.domain().to_string();
            let replacement = unresolved_resource(domain.as_str());
            let detail = format!(
                "{cause}: {op} on {original}",
                cause = untyped_resource_cause(error),
                op = effect.operation.as_str(),
                original = effinterp_proto::display_resource(&effect.resource),
            );
            self.boundary_with_coverage(
                Boundary {
                    reason: BoundaryReason::UNTYPED_RESOURCE,
                    class: BoundaryClass::Unresolved,
                    scope: BoundaryScope::Invocation,
                    domains: vec![Domain::new(domain)],
                    affected_resource: Some(replacement.clone()),
                    callee: None,
                    provenance: effect.provenance.clone(),
                    limit: None,
                    detail: Some(detail),
                },
                CoverageLevel::Partial,
            );
            effect.resource = replacement;
            effect.request_assurance = effinterp_proto::RequestAssurance::Conservative;
        }
        // Stamp the current realm unless the caller set one explicitly (e.g.
        // an ssh model tagging a remote effect while the stack is still host).
        if effect.realm.is_host() {
            effect.realm = self.current_realm();
        }
        effinterp_proto::qualify_scope_origin(&mut effect.resource, &effect.realm);
        let preset_condition = effect.condition.is_some();
        if self.condition_overflow > 0 {
            effect.condition = Some(Condition::Widened);
        }
        if !self.condition_stack.is_empty() {
            effect.condition =
                Condition::compose(effect.condition.iter().chain(self.condition_stack.iter()));
        }
        if effect.condition.as_ref().is_some_and(Condition::is_widened) {
            effect.modality = effinterp_proto::Modality::May;
            effect.request_assurance = effinterp_proto::RequestAssurance::Conservative;
        }
        if !self
            .execution_stack
            .iter()
            .all(|node| self.execution_is_exact(*node))
            || !effect.provenance.iter().any(|reference| {
                self.provenance
                    .get(reference.0 as usize)
                    .is_some_and(|node| {
                        matches!(node.kind, ProvenanceKind::ModelApplication { .. })
                    })
            })
        {
            effect.request_assurance = effinterp_proto::RequestAssurance::Conservative;
        }
        effect.execution = self.current_execution();
        effect.id = Default::default();
        // Prepay both stamping and validation so saturation can still finalize
        // every retained effect. Subject hashing is reserved once per node.
        let first_subject = !self.effect_id_subjects.contains(&effect.execution);
        let subject_bytes = if first_subject {
            effinterp_proto::canonical_json(
                &self.execution_nodes[effect.execution.0 as usize].subject,
            )
            .len() as u64
                + 4 * NODE_BYTES
        } else {
            0
        };
        if !self
            .budget
            .try_charge_steps(2 + u64::from(first_subject) * 2)
        {
            self.note_saturated_at("max_analysis_steps", span);
            return None;
        }
        // Speculative effects are discarded before finalization; only accepted
        // effects need prepaid identity stamping and validation scratch.
        let bytes = retained_bytes(&effect)
            + if self.budget.measuring() {
                0
            } else {
                effect_id_scratch_bytes(&effect) + subject_bytes
            };
        if !self.budget.try_charge_bytes(bytes) {
            self.note_saturated_at("max_analysis_bytes", span);
            return None;
        }
        self.accounted_effect_bytes += bytes;
        self.effect_id_subjects.insert(effect.execution);
        let slot = self.effects.len() as u32;
        let resource = alias_resource.unwrap_or_else(|| effect.resource.clone());
        // Bytes written to /dev/null are discarded; no file changes.
        let discarded = effect.operation.as_str() == "filesystem.write"
            && matches!(&resource, ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } } if path == "/dev/null");
        if effect.realm.is_host()
            && !discarded
            && matches!(
                effect.operation.as_str(),
                "filesystem.write"
                    | "filesystem.create"
                    | "filesystem.delete"
                    | "filesystem.move"
                    | "filesystem.mount"
                    | "filesystem.unmount"
            )
        {
            self.source_writes.push(SourceWrite {
                resource,
                changes_identity: matches!(
                    effect.operation.as_str(),
                    "filesystem.create"
                        | "filesystem.move"
                        | "filesystem.mount"
                        | "filesystem.unmount"
                ),
                effect: Some(slot),
                content: None,
                conditions: (!preset_condition && self.condition_overflow == 0)
                    .then(|| self.condition_stack.clone()),
            });
        }
        self.effects.push(effect);
        if let Some(trigger) = trigger {
            self.effect_in_domain(trigger, "system");
        }
        Some(slot)
    }

    /// Record the exact bytes a file holds after the write effect in `slot`.
    /// An append is exact only when it extends an exact write made under the
    /// same conditions.
    pub(crate) fn predict_written_content(
        &mut self,
        slot: u32,
        content: &[u8],
        append: bool,
        may_alias: impl Fn(&ResourceExpr, &str) -> bool,
    ) {
        let Some(index) = self
            .source_writes
            .iter()
            .rposition(|write| write.effect == Some(slot))
        else {
            return;
        };
        let ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } = &self.source_writes[index].resource
        else {
            return;
        };
        if !self.sole_region_write(index, path, &may_alias) {
            return;
        }
        if append && self.source_identity_changed(path, index, &may_alias) {
            return;
        }
        let content = if append {
            let write = &self.source_writes[index];
            let Some(prior) = self.source_writes[..index].iter().rev().find(|prior| {
                source_mutation_reaches(&prior.resource, path) || may_alias(&prior.resource, path)
            }) else {
                return;
            };
            match (&prior.content, &prior.conditions) {
                (Some(bytes), Some(conditions))
                    if prior.resource == write.resource
                        && write.conditions.as_ref() == Some(conditions) =>
                {
                    [bytes.as_slice(), content].concat()
                }
                _ => return,
            }
        } else {
            content.to_vec()
        };
        self.source_writes[index].content = Some(content);
    }

    /// Add bytes written later through the descriptor the write in `slot`
    /// opened. They extend its exact content only when no other mutation of
    /// the path came after it and the write happens under the same conditions;
    /// unknown bytes (`None`) leave the content unknown.
    pub(crate) fn extend_written_content(
        &mut self,
        slot: u32,
        content: Option<&[u8]>,
        may_alias: impl Fn(&ResourceExpr, &str) -> bool,
    ) {
        let Some(index) = self
            .source_writes
            .iter()
            .rposition(|write| write.effect == Some(slot))
        else {
            return;
        };
        let write = &self.source_writes[index];
        let ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } = &write.resource
        else {
            return;
        };
        let current = self.condition_overflow == 0
            && write.conditions.as_ref() == Some(&self.condition_stack);
        let later = self.source_writes[index + 1..].iter().any(|later| {
            source_mutation_reaches(&later.resource, path) || may_alias(&later.resource, path)
        });
        let hazard = self.source_hazards.iter().any(|(resource, _, _, _)| {
            source_mutation_reaches(resource, path) || may_alias(resource, path)
        });
        let extended = match (&write.content, content) {
            (Some(bytes), Some(content)) if current && !later && !hazard => {
                Some([bytes.as_slice(), content].concat())
            }
            _ => None,
        };
        self.source_writes[index].content = extended;
    }

    /// Collect mutations and whether they change path identity before rollback.
    pub(crate) fn source_mutations_since(
        &self,
        checkpoint: &BuilderCheckpoint,
    ) -> Vec<(ResourceExpr, bool)> {
        self.source_writes[checkpoint.source_writes..]
            .iter()
            .map(|write| (write.resource.clone(), write.changes_identity))
            .collect()
    }

    /// How many `git config` writes have been recorded.
    pub(crate) fn git_config_write_count(&self) -> usize {
        self.git_config_writes.len()
    }

    /// The `git config` writes recorded from index `start` on.
    pub(crate) fn git_config_writes_from(&self, start: usize) -> Vec<GitConfigWrite> {
        self.git_config_writes[start..].to_vec()
    }

    /// Enter the pipeline stage at `position` of the innermost pipeline.
    pub(crate) fn push_pipeline_stage(&mut self, position: usize) {
        self.pipeline_stages.push(position);
    }

    pub(crate) fn pop_pipeline_stage(&mut self) {
        self.pipeline_stages.pop();
    }

    /// How many pipeline stages enclose the walk; a pipeline that starts
    /// here numbers its stages at this depth.
    pub(crate) fn pipeline_stage_depth(&self) -> usize {
        self.pipeline_stages.len()
    }

    /// Reads cannot assume ordering against concurrent writes or later iterations.
    pub(crate) fn push_source_hazards(
        &mut self,
        mutations: Vec<(ResourceExpr, bool)>,
        git_config_writes: Vec<GitConfigWrite>,
        stage_depth: Option<usize>,
        background: bool,
    ) -> HazardDepth {
        let depth = HazardDepth {
            source: self.source_hazards.len(),
            git_config: self.git_config_hazards.len(),
        };
        let mark = self.source_writes.len();
        self.source_hazards.extend(
            mutations
                .into_iter()
                .map(|(path, changes_identity)| (path, changes_identity, background, mark)),
        );
        self.git_config_hazards
            .extend(git_config_writes.into_iter().map(|write| {
                let stage =
                    stage_depth.and_then(|depth| Some((depth, *write.pipeline_stages.get(depth)?)));
                (stage, write)
            }));
        depth
    }

    /// Whether the write at `index` is the only mutation of `path` that the
    /// enclosing unordered regions can make. A pipeline that writes one file
    /// once still leaves that write's bytes in place when it completes; the
    /// region's own reads keep seeing its hazard.
    fn sole_region_write(
        &self,
        index: usize,
        path: &str,
        may_alias: &impl Fn(&ResourceExpr, &str) -> bool,
    ) -> bool {
        let reaches = |resource: &ResourceExpr| {
            source_mutation_reaches(resource, path) || may_alias(resource, path)
        };
        let mut hazards = self
            .source_hazards
            .iter()
            .filter(|(resource, _, _, _)| reaches(resource));
        let Some((resource, _, background, mark)) = hazards.next() else {
            return true;
        };
        hazards.next().is_none()
            && !background
            && *resource == self.source_writes[index].resource
            && index >= *mark
            && self.source_writes[*mark..]
                .iter()
                .enumerate()
                .all(|(offset, write)| mark + offset == index || !reaches(&write.resource))
    }

    /// End a region's carried `git config` writes. Its own writes are in
    /// `git_config_writes`, in order, and the later commands a background
    /// region raced walk after it and record theirs in order too.
    pub(crate) fn truncate_git_config_hazards(&mut self, depth: HazardDepth) {
        self.git_config_hazards.truncate(depth.git_config);
    }

    pub(crate) fn truncate_source_hazards(&mut self, depth: HazardDepth) {
        self.truncate_git_config_hazards(depth);
        let depth = depth.source;
        // A refused source expansion can hide the writes found by the probe.
        // Keep them as unknown mutations after the region, while background
        // work remains concurrent even with later sequential writes.
        // A hazard the region itself recorded as its one write of that exact
        // resource is already in `source_writes`, in order.
        let hazards = self.source_hazards.split_off(depth);
        let recorded = |resource: &ResourceExpr, mark: usize| {
            hazards
                .iter()
                .filter(|(hazard, ..)| hazard == resource)
                .count()
                == 1
                && self.source_writes[mark..]
                    .iter()
                    .filter(|write| write.effect.is_some() && &write.resource == resource)
                    .count()
                    == 1
        };
        let replay: Vec<bool> = hazards
            .iter()
            .map(|(resource, _, _, mark)| !recorded(resource, *mark))
            .collect();
        for ((resource, changes_identity, background, mark), replay) in
            hazards.into_iter().zip(replay)
        {
            if background {
                self.source_hazards
                    .push((resource, changes_identity, background, mark));
            } else if replay {
                self.source_writes.push(SourceWrite {
                    resource,
                    changes_identity,
                    effect: None,
                    content: None,
                    conditions: None,
                });
            }
        }
    }

    // A newly created link or replaced directory can redirect later writes.
    // Current filesystem metadata cannot prove those future targets disjoint.
    fn source_identity_changed(
        &self,
        path: &str,
        before: usize,
        may_alias: &impl Fn(&ResourceExpr, &str) -> bool,
    ) -> bool {
        self.source_writes[..before].iter().any(|write| {
            write.changes_identity
                && (source_mutation_reaches(&write.resource, path)
                    || may_alias(&write.resource, path))
        }) || self
            .source_hazards
            .iter()
            .any(|(resource, changes_identity, _, _)| {
                *changes_identity
                    && (source_mutation_reaches(resource, path) || may_alias(resource, path))
            })
    }

    fn source_mutation_redirected(
        &self,
        resource: &ResourceExpr,
        before: usize,
        may_alias: &impl Fn(&ResourceExpr, &str) -> bool,
    ) -> bool {
        match resource {
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path },
            } => self.source_identity_changed(path, before, may_alias),
            ResourceExpr::Pattern {
                pattern: effinterp_proto::ResourcePattern::FsPath { glob },
            } if !glob.contains(['*', '?', '[', '{', '\\']) => {
                self.source_identity_changed(glob, before, may_alias)
            }
            ResourceExpr::Union { alternatives } => alternatives
                .iter()
                .any(|resource| self.source_mutation_redirected(resource, before, may_alias)),
            ResourceExpr::Join { parts } => {
                let mut parts = parts.as_slice();
                if matches!(parts.first(), Some(ResourceExpr::Parameter { name }) if name == "cwd")
                {
                    parts = &parts[1..];
                }
                let Some(parts) = parts
                    .iter()
                    .map(|part| match part {
                        ResourceExpr::Concrete {
                            identity: ResourceIdentity::FsPath { path },
                        } => Some(path.as_str()),
                        _ => None,
                    })
                    .collect::<Option<Vec<_>>>()
                else {
                    return false;
                };
                self.source_identity_changed(
                    &crate::paths::normalize_path(&parts.join("/")),
                    before,
                    may_alias,
                )
            }
            _ => false,
        }
    }

    pub(crate) fn record_git_config_write(
        &mut self,
        scope: GitConfigScope,
        repository: Option<ResourceExpr>,
        key: Option<String>,
        value: Option<String>,
    ) {
        if self.is_host_realm() {
            self.git_config_writes.push(GitConfigWrite {
                scope,
                repository,
                key,
                value,
                binding: self.git_foreach_binding(),
                pipeline_stages: self.pipeline_stages.clone(),
            });
        }
    }

    /// Enter the command of a `submodule foreach` call over `superproject`.
    pub(crate) fn push_git_foreach(&mut self, superproject: ResourceExpr) {
        let parent = self.git_foreach_binding();
        self.git_foreach_bindings.push(GitForeachBinding {
            superproject,
            parent,
        });
        self.git_foreach_stack
            .push(self.git_foreach_bindings.len() - 1);
    }

    pub(crate) fn pop_git_foreach(&mut self) {
        self.git_foreach_stack.pop();
    }

    /// The innermost foreach call whose command is being walked.
    pub(crate) fn git_foreach_binding(&self) -> Option<usize> {
        self.git_foreach_stack.last().copied()
    }

    pub(crate) fn git_foreach(&self, binding: usize) -> &GitForeachBinding {
        &self.git_foreach_bindings[binding]
    }

    /// Kept for the rest of the subject: the variable may reach any later
    /// command, and a rolled-back probe only makes this more cautious.
    pub(crate) fn note_unknown_environment_name(&mut self) {
        self.unknown_environment_names = true;
    }

    pub(crate) fn environment_names_unknown(&self) -> bool {
        self.unknown_environment_names
    }

    /// Host `git config` writes made earlier in this subject, oldest first,
    /// then those the enclosing unordered regions may make concurrently,
    /// less those of the pipeline stage being walked.
    pub(crate) fn git_config_writes(&self) -> impl Iterator<Item = &GitConfigWrite> {
        let host = self.is_host_realm();
        let carried = self
            .git_config_hazards
            .iter()
            .filter(|(stage, _)| {
                stage.is_none_or(|(depth, position)| {
                    self.pipeline_stages.get(depth) != Some(&position)
                })
            })
            .map(|(_, write)| write);
        self.git_config_writes
            .iter()
            .chain(carried)
            .filter(move |_| host)
    }

    /// Direct writes invalidate basename-only executable models. A possible
    /// alias alone is insufficient evidence to replace a known command model.
    pub(crate) fn executable_was_written(&self, resource: &ResourceExpr) -> bool {
        self.is_host_realm()
            && self
                .source_writes
                .iter()
                .any(|write| &write.resource == resource)
    }

    /// The content a source read at `path` sees after earlier host mutations.
    pub(crate) fn written_source(
        &self,
        path: &str,
        may_alias: impl Fn(&ResourceExpr, &str) -> bool,
    ) -> WrittenSource {
        if !self.is_host_realm() {
            return WrittenSource::Host;
        }
        if self
            .source_hazards
            .iter()
            .any(|(written, changes_identity, _, _)| {
                source_mutation_reaches(written, path)
                    || may_alias(written, path)
                    || (!changes_identity
                        && self.source_mutation_redirected(
                            written,
                            self.source_writes.len(),
                            &may_alias,
                        ))
            })
        {
            return WrittenSource::Ambiguous;
        }
        let Some((index, write)) =
            self.source_writes
                .iter()
                .enumerate()
                .rev()
                .find(|(index, write)| {
                    source_mutation_reaches(&write.resource, path)
                        || may_alias(&write.resource, path)
                        || self.source_mutation_redirected(&write.resource, *index, &may_alias)
                })
        else {
            return WrittenSource::Host;
        };
        if self.source_mutation_redirected(&write.resource, index, &may_alias)
            && !matches!(&write.resource, ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path: written } } if written == path)
        {
            return WrittenSource::Stale;
        }
        match (&write.content, &write.conditions) {
            (Some(bytes), Some(conditions))
                if matches!(&write.resource, ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path: written } } if written == path)
                    && self.condition_overflow == 0
                    && self.condition_stack.starts_with(conditions) =>
            {
                WrittenSource::Exact(bytes.clone())
            }
            (Some(_), _) if matches!(&write.resource, ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path: written } } if written == path) => {
                WrittenSource::Ambiguous
            }
            _ => WrittenSource::Stale,
        }
    }

    pub(crate) fn selected_input_effects(&mut self, node: &ExecutionNode) {
        use effinterp_proto::{ExecutionContent, Modality, Operation};
        let Some(input) = &node.input else {
            return;
        };
        if !matches!(
            input.content,
            ExecutionContent::Observed { .. } | ExecutionContent::Predicted { .. }
        ) {
            return;
        }
        let Some(path) = node.selected_source_path() else {
            return;
        };
        let read = ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath {
                path: path.to_string(),
            },
        };
        let process = ResourceExpr::Concrete {
            identity: crate::paths::executable_identity(&input.requester_component, None),
        };
        // The selected file is read as the program the execution runs, as a
        // launched script's own read and execution record it.
        for (operation, resource, attribute) in [
            ("filesystem.read", read, ("access_purpose", "program_input")),
            ("process.code_execution", process, ("source", "file")),
        ] {
            if self.effects.iter().any(|effect| {
                effect.execution == self.current_execution()
                    && effect.operation.as_str() == operation
                    && (effect.resource == resource
                        || (operation == "process.code_execution"
                            && !effect.provenance.is_empty()
                            && effect
                                .provenance
                                .iter()
                                .all(|reference| node.evidence.contains(reference))))
            }) {
                continue;
            }
            self.effect(Effect {
                request_assurance: effinterp_proto::RequestAssurance::Conservative,
                id: Default::default(),
                operation: Operation::new(operation),
                resource,
                attributes: BTreeMap::from([(
                    attribute.0.to_string(),
                    AttrValue::String(attribute.1.to_string()),
                )]),
                modality: Modality::May,
                realm: self.current_realm(),
                condition: None,
                execution: self.current_execution(),
                provenance: node.evidence.clone(),
            });
        }
    }

    pub(crate) fn current_execution_component(&self) -> String {
        if let Some(input) = &self.execution_nodes[self.current_execution().0 as usize].input {
            return input.requester_component.clone();
        }
        match &self.execution_nodes[self.current_execution().0 as usize].subject {
            Subject::Exec { argv, .. } => argv[0].clone(),
            Subject::Shell { .. } => "shell".to_string(),
            Subject::Source { language, .. } => language.clone(),
            Subject::Sql { .. } => "sql".to_string(),
            Subject::ToolCall { call, .. } => call.name().to_string(),
        }
    }

    // Follow only dependency requesters: a new script launch owns a separate
    // module cache, even when it selects a file already imported elsewhere.
    fn dependency_launch(&self, mut execution: ExecutionNodeRef) -> ExecutionNodeRef {
        while let Some(input) = &self.execution_nodes[execution.0 as usize].input {
            if input.role != effinterp_proto::ExecutionInputRole::DependencyRequest {
                break;
            }
            execution = input.requester;
        }
        execution
    }

    /// The launch whose dependency graph contains the current execution.
    pub(crate) fn current_dependency_launch(&self) -> ExecutionNodeRef {
        self.dependency_launch(self.current_execution())
    }

    /// Whether code the current launch already ran, in any module of its
    /// dependency graph, may have written the environment variable `name`: a
    /// write names it, or names no single variable.
    pub(crate) fn launch_may_have_written_environment(&self, name: &str) -> bool {
        let launch = self.current_dependency_launch();
        self.effects.iter().any(|effect| {
            effect.operation.as_str() == "environment.write"
                && self.dependency_launch(effect.execution) == launch
                && !matches!(
                    &effect.resource,
                    ResourceExpr::Concrete {
                        identity: ResourceIdentity::EnvironmentVariable { name: written },
                    } if written != name
                )
        })
    }

    pub(crate) fn dependency_source_recorded(&self, path: &str) -> bool {
        let launch = self.dependency_launch(self.current_execution());
        self.execution_nodes
            .iter()
            .enumerate()
            .any(|(index, node)| {
                node.selected_source_path() == Some(path)
                    && self.dependency_launch(ExecutionNodeRef(index as u32)) == launch
                    && node.input.as_ref().is_some_and(|input| {
                        matches!(
                            input.content,
                            effinterp_proto::ExecutionContent::Observed { .. }
                                | effinterp_proto::ExecutionContent::Predicted { .. }
                        )
                    })
            })
    }

    pub(crate) fn current_source_language(&self) -> Option<&str> {
        match &self.execution_nodes[self.current_execution().0 as usize].subject {
            Subject::Source { language, .. } => Some(language),
            _ => None,
        }
    }

    /// The basename of the command whose process runs the current execution:
    /// the nearest enclosing exec, skipping the interpreter source nodes that
    /// inline code and the modules it loads run as inside that process.
    pub(crate) fn launching_command(&self) -> Option<&str> {
        self.execution_stack
            .iter()
            .rev()
            .map(|node| &self.execution_nodes[node.0 as usize].subject)
            .find(|subject| !matches!(subject, Subject::Source { .. }))
            .and_then(|subject| match subject {
                Subject::Exec { argv, .. } => argv.first()?.rsplit('/').next(),
                _ => None,
            })
    }

    pub(crate) fn current_execution_argv(&self) -> &[ResourceExpr] {
        &self.execution_nodes[self.current_execution().0 as usize].argv
    }

    pub(crate) fn current_execution_evidence(&self) -> &[ProvenanceRef] {
        &self.execution_nodes[self.current_execution().0 as usize].evidence
    }

    pub(crate) fn dependency_request_recorded(&self, specifier: &str) -> bool {
        self.execution_nodes.iter().any(|node| node.input.as_ref().is_some_and(|input| {
            input.requester == self.current_execution()
                && matches!(&input.selector, effinterp_proto::ExecutionSelector::Dependency { specifier: prior } if prior == specifier)
        }))
    }

    /// Selected inputs execute once per requesting invocation and phase. The
    /// requester retains every argv/environment selector, including duplicates.
    pub(crate) fn runtime_input_recorded(
        &self,
        path: &str,
        input: &effinterp_proto::ExecutionInput,
    ) -> bool {
        input.role == effinterp_proto::ExecutionInputRole::UnexpectedSelected
            && self.execution_nodes.iter().any(|node| {
                node.selected_source_path() == Some(path)
                    && node.input.as_ref().is_some_and(|prior| {
                        prior.requester == input.requester
                            && prior.phase == input.phase
                            && prior.role == input.role
                            && matches!(
                                prior.content,
                                effinterp_proto::ExecutionContent::Observed { .. }
                                    | effinterp_proto::ExecutionContent::Predicted { .. }
                            )
                    })
            })
    }

    pub(crate) fn current_source_origin(&self) -> Option<String> {
        self.execution_nodes[self.current_execution().0 as usize]
            .selected_source_path()
            .map(str::to_string)
    }

    /// Whether the current execution is a module loaded by a dependency
    /// request. Its declared callables run only where callers reach them.
    pub(crate) fn current_execution_is_dependency(&self) -> bool {
        self.execution_nodes[self.current_execution().0 as usize]
            .input
            .as_ref()
            .is_some_and(|input| {
                input.role == effinterp_proto::ExecutionInputRole::DependencyRequest
            })
    }

    pub(crate) fn current_execution_is_selected_input(&self) -> bool {
        let mut node = &self.execution_nodes[self.current_execution().0 as usize];
        while let Some(input) = &node.input {
            if input.role != effinterp_proto::ExecutionInputRole::DependencyRequest {
                return true;
            }
            node = &self.execution_nodes[input.requester.0 as usize];
        }
        false
    }

    pub(crate) fn current_execution(&self) -> ExecutionNodeRef {
        self.execution_stack.last().copied().unwrap_or_default()
    }

    pub(crate) fn execution_node(&mut self, node: ExecutionNode) -> Option<ExecutionNodeRef> {
        let span = self.first_source_span(&node.evidence);
        if !self
            .budget
            .try_charge_bytes(execution_node_retained_bytes(&node))
        {
            self.note_saturated_at("max_analysis_bytes", span);
            return None;
        }
        let reference = ExecutionNodeRef(self.execution_nodes.len() as u32);
        self.execution_nodes.push(node);
        Some(reference)
    }

    /// The next execution node's reference: a launch nested after this call
    /// takes it unless the launch re-enters an active execution.
    pub(crate) fn next_execution(&self) -> ExecutionNodeRef {
        ExecutionNodeRef(self.execution_nodes.len() as u32)
    }

    pub(crate) fn execution_is_exact(&self, node: ExecutionNodeRef) -> bool {
        self.execution_nodes[node.0 as usize].assurance == ExecutionAssurance::Exact
    }

    pub(crate) fn has_unique_direct_main_input(
        &self,
        requester: ExecutionNodeRef,
        selected: &ResourceExpr,
        provenance: &[ProvenanceRef],
    ) -> bool {
        use effinterp_proto::{
            ExecutionInputRole, ExecutionPhase, ExecutionSelection, ExecutionSelector,
        };
        if !matches!(
            selected,
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { .. }
            }
        ) || provenance.is_empty()
        {
            return false;
        }
        let mut candidates = self.execution_nodes.iter().filter(|node| {
            node.input.as_ref().is_some_and(|input| {
                input.requester == requester
                    && input.role == ExecutionInputRole::ExplicitInvocation
                    && input.phase == ExecutionPhase::Main
                    && input.selected.as_ref() == Some(selected)
            })
        });
        let Some(node) = candidates.next() else {
            return false;
        };
        let input = node.input.as_ref().unwrap();
        candidates.next().is_none()
            && input.assurance == ExecutionAssurance::Exact
            && input.selector == ExecutionSelector::InvocationPath
            && matches!(input.selection, ExecutionSelection::Direct { .. })
            // Unobserved inputs retain their selector but have no source-body
            // evidence. Observed children must corroborate this argument site.
            && (node.evidence.is_empty()
                || provenance.iter().all(|reference| node.evidence.contains(reference)))
    }

    pub(crate) fn execution_environment(
        &self,
        node: ExecutionNodeRef,
    ) -> BTreeMap<String, Option<ResourceExpr>> {
        self.execution_nodes[node.0 as usize].environment.clone()
    }

    pub(crate) fn current_execution_cwd(&self) -> Option<ResourceExpr> {
        self.execution_nodes[self.current_execution().0 as usize]
            .cwd
            .clone()
    }

    pub(crate) fn attach_boundary_to_uncertain_execution(&mut self, boundary: BoundaryRef) {
        let current = self.current_execution().0 as usize;
        if self.execution_nodes[current].assurance != ExecutionAssurance::Exact {
            self.execution_nodes[current].boundary = Some(boundary);
        }
    }

    pub(crate) fn inherited_execution_streams(&self) -> ExecutionStreams {
        let current = self.current_execution();
        let inherited = &self.execution_nodes[current.0 as usize].streams;
        ExecutionStreams {
            stdin: inherited
                .stdin
                .clone()
                .or_else(|| Some(stream_ref(current, effinterp_proto::ExecutionStream::Stdin))),
            stdin_value: None,
            stdout: inherited.stdout.clone().or_else(|| {
                Some(stream_ref(
                    current,
                    effinterp_proto::ExecutionStream::Stdout,
                ))
            }),
            stderr: inherited.stderr.clone().or_else(|| {
                Some(stream_ref(
                    current,
                    effinterp_proto::ExecutionStream::Stderr,
                ))
            }),
        }
    }

    pub(crate) fn active_execution(&self, candidate: &ExecutionNode) -> Option<ExecutionNodeRef> {
        let streams = self.stream_origins(&candidate.streams);
        self.execution_stack.iter().copied().find(|reference| {
            let node = &self.execution_nodes[reference.0 as usize];
            node.subject == candidate.subject
                && node.argv == candidate.argv
                && node.cwd == candidate.cwd
                && node.environment == candidate.environment
                && self.stream_origins(&node.streams) == streams
                && node.mounts == candidate.mounts
                && node.realm == candidate.realm
        })
    }

    /// Inherited stdio, resolved to the execution each stream comes from. A
    /// nested execution names its immediate parent, so a script that runs
    /// itself again reaches the same context under a longer chain of
    /// references; comparing the origins keeps that re-entry recognizable.
    fn stream_origins(&self, streams: &ExecutionStreams) -> ExecutionStreams {
        ExecutionStreams {
            stdin: streams
                .stdin
                .clone()
                .map(|stream| self.stream_origin(stream)),
            stdin_value: streams.stdin_value.clone(),
            stdout: streams
                .stdout
                .clone()
                .map(|stream| self.stream_origin(stream)),
            stderr: streams
                .stderr
                .clone()
                .map(|stream| self.stream_origin(stream)),
        }
    }

    fn stream_origin(
        &self,
        mut reference: effinterp_proto::ExecutionStreamRef,
    ) -> effinterp_proto::ExecutionStreamRef {
        for _ in 0..self.execution_nodes.len() {
            let streams = &self.execution_nodes[reference.node.0 as usize].streams;
            let next = match reference.stream {
                effinterp_proto::ExecutionStream::Stdin => streams.stdin.clone(),
                effinterp_proto::ExecutionStream::Stdout => streams.stdout.clone(),
                effinterp_proto::ExecutionStream::Stderr => streams.stderr.clone(),
            };
            match next {
                Some(next) => reference = next,
                None => break,
            }
        }
        reference
    }

    pub(crate) fn execution_edge(
        &mut self,
        to: ExecutionNodeRef,
        kind: ExecutionEdgeKind,
        cycle: bool,
        evidence: &[ProvenanceRef],
    ) {
        self.execution_edges.push(ExecutionEdge {
            from: self.current_execution(),
            to,
            kind,
            cycle,
            evidence: evidence.to_vec(),
        });
    }

    pub(crate) fn current_execution_is_source(&self) -> bool {
        matches!(
            self.execution_nodes[self.current_execution().0 as usize].subject,
            Subject::Source { .. }
        )
    }

    pub(crate) fn record_runtime_shell(&mut self, node: ExecutionNodeRef, shell: RuntimeShell) {
        self.runtime_shells.insert(node, shell);
    }

    pub(crate) fn push_execution(&mut self, node: ExecutionNodeRef) {
        self.execution_stack.push(node);
    }

    pub(crate) fn pop_execution(&mut self) {
        self.execution_stack.pop();
    }

    pub(crate) fn execution_depth(&self) -> u64 {
        self.execution_stack.len() as u64
    }

    pub(crate) fn execution_fanout(&self) -> u64 {
        let current = self.current_execution();
        self.execution_edges
            .iter()
            .filter(|edge| edge.from == current)
            .count() as u64
    }

    pub(crate) fn execution_saturated(&self) -> bool {
        self.execution_saturated.contains(&self.current_execution())
    }

    pub(crate) fn effects_saturated(&self) -> bool {
        self.saturated.contains_key("max_effects")
    }

    pub(crate) fn note_execution_saturated(&mut self) -> bool {
        self.execution_saturated.insert(self.current_execution())
    }

    pub(crate) fn redirect_execution_stdout(&mut self, execution: ExecutionNodeRef) {
        self.execution_nodes[execution.0 as usize].streams.stdout = None;
    }

    pub(crate) fn set_execution_stdout(
        &mut self,
        execution: ExecutionNodeRef,
        stdout: Option<effinterp_proto::ExecutionStreamRef>,
    ) {
        self.execution_nodes[execution.0 as usize].streams.stdout = stdout;
    }

    /// Point the execution's stdout and stderr at the inherited stream its
    /// descriptor now copies (1 for stdout, 2 for stderr), or disconnect it.
    pub(crate) fn route_execution_outputs(
        &mut self,
        execution: ExecutionNodeRef,
        stdout: Option<u32>,
        stderr: Option<u32>,
    ) {
        let streams = &mut self.execution_nodes[execution.0 as usize].streams;
        let inherited = [streams.stdout.clone(), streams.stderr.clone()];
        let copy =
            |number: Option<u32>| number.and_then(|number| inherited[number as usize - 1].clone());
        streams.stdout = copy(stdout);
        streams.stderr = copy(stderr);
    }

    pub(crate) fn execution_pipe(
        &mut self,
        from: ExecutionNodeRef,
        stream: effinterp_proto::ExecutionStream,
        to: ExecutionNodeRef,
    ) {
        let destination = effinterp_proto::ExecutionStreamRef {
            node: to,
            stream: effinterp_proto::ExecutionStream::Stdin,
        };
        match stream {
            effinterp_proto::ExecutionStream::Stdout => {
                self.execution_nodes[from.0 as usize].streams.stdout = Some(destination)
            }
            effinterp_proto::ExecutionStream::Stderr => {
                self.execution_nodes[from.0 as usize].streams.stderr = Some(destination)
            }
            effinterp_proto::ExecutionStream::Stdin => return,
        }
        self.execution_nodes[to.0 as usize].streams.stdin =
            Some(effinterp_proto::ExecutionStreamRef { node: from, stream });
    }

    pub(crate) fn source_span(&self, roots: &[ProvenanceRef]) -> Option<effinterp_proto::ByteSpan> {
        let mut work = roots.to_vec();
        let mut seen = std::collections::BTreeSet::new();
        while let Some(reference) = work.pop() {
            if !seen.insert(reference) {
                continue;
            }
            let node = self.provenance.get(reference.0 as usize)?;
            if let ProvenanceKind::SourceSpan { start, end } = node.kind {
                return Some(effinterp_proto::ByteSpan { start, end });
            }
            work.extend(node.antecedents.iter().copied());
        }
        None
    }

    /// The number of effects emitted so far. The flow builder snapshots this
    /// around a stage to learn which effect occurrences the stage produced.
    /// Only the analyzed shell or source subject's own outermost callable
    /// publishes required effects; everything else reports to its launcher.
    pub(crate) fn control_allow_roots(&mut self) {
        self.control.allow_roots();
    }

    /// Begin walking a callable whose syntax `build` turns into a graph over
    /// spans of `source`. Capture frames collect summary slots instead of
    /// plan slots.
    pub(crate) fn control_enter(
        &mut self,
        source: &str,
        capture: bool,
        build: impl FnOnce(&mut crate::control_flow::Graph),
    ) {
        let execution = self.current_execution();
        let depth = self.execution_stack.len();
        let budget = self.budget.clone();
        let caps = self.control_caps();
        let effects = self.effects.len();
        self.control.enter(
            source,
            capture,
            execution,
            depth,
            effects,
            Some(budget),
            caps,
            build,
        );
    }

    /// Finish the innermost callable. The analyzed subject's own frame marks
    /// its proven effects required before their identities are derived.
    pub(crate) fn control_leave(&mut self) -> Option<crate::control_flow::Finished> {
        let finished = self.control.leave(self.effects.len())?;
        if let Some(limit) = finished.refused {
            self.note_control_saturated(limit);
        }
        for slot in &finished.promote {
            if let Some(effect) = self.effects.get_mut(*slot as usize)
                && !effect.condition.as_ref().is_some_and(Condition::is_widened)
            {
                effect.modality = effinterp_proto::Modality::MustOnSuccess;
            }
        }
        Some(finished)
    }

    pub(crate) fn control_site(
        &mut self,
        source: &str,
        capture: bool,
        span: crate::control_flow::Span,
        facts: crate::control_flow::SiteFacts,
    ) {
        self.control.register(source, capture, span, facts);
    }

    /// Modeled occurrences in `range` that belong to the innermost callable.
    pub(crate) fn control_own_effects(
        &self,
        range: std::ops::Range<usize>,
    ) -> Vec<crate::control_flow::ControlFact> {
        self.control.own_effects(range)
    }

    pub(crate) fn control_registered(&self) -> usize {
        self.control.registered()
    }

    /// Register a construct's facts minus those its nested constructs claimed.
    pub(crate) fn control_site_since(
        &mut self,
        source: &str,
        capture: bool,
        span: crate::control_flow::Span,
        since: usize,
        facts: crate::control_flow::SiteFacts,
    ) {
        self.control
            .register_since(source, capture, span, since, facts);
    }

    /// Forget runtimes launched before the construct about to run.
    pub(crate) fn control_mark(&mut self) {
        self.control.mark();
    }

    /// Success facts of the one runtime the construct just launched.
    pub(crate) fn control_launched(&mut self) -> Vec<crate::control_flow::ControlFact> {
        self.control.launched(&self.execution_edges)
    }

    pub(crate) fn control_widen(&mut self) {
        self.control.widen();
    }

    pub fn effects_len(&self) -> usize {
        self.effects.len()
    }

    pub(crate) fn boundaries_len(&self) -> usize {
        self.boundaries.len()
    }

    /// The operation string of an emitted effect, for the flow builder to bind
    /// a stage's effects to its ports (e.g. cat's `filesystem.read` → stdout).
    pub fn effect_operation(&self, index: usize) -> Option<&str> {
        self.effects.get(index).map(|e| e.operation.0.as_str())
    }

    pub(crate) fn effect_resource(&self, index: usize) -> Option<&ResourceExpr> {
        self.effects.get(index).map(|effect| &effect.resource)
    }

    pub(crate) fn effect_request_is_exact(&self, index: usize) -> bool {
        self.effects.get(index).is_some_and(|effect| {
            effect.request_assurance == effinterp_proto::RequestAssurance::Exact
        })
    }

    pub(crate) fn effect_provenance(&self, index: usize) -> Option<&[ProvenanceRef]> {
        self.effects
            .get(index)
            .map(|effect| effect.provenance.as_slice())
    }

    pub(crate) fn effect_has_argument(&self, effect: usize, argument: u32) -> bool {
        self.effects.get(effect).is_some_and(|effect| {
            effect.provenance.iter().any(|reference| {
                matches!(
                    self.provenance.get(reference.0 as usize).map(|node| &node.kind),
                    Some(ProvenanceKind::Argument { index }) if *index == argument
                )
            })
        })
    }

    /// The execution that owns an argument provenance node: every argument
    /// node carries its invocation's `Execution` scope node as an antecedent,
    /// so a forwarded argument's root can be attributed to the exact command
    /// that supplied it rather than to any invocation that happens to reuse
    /// the same argv index.
    fn argument_owner(&self, node: ProvenanceRef) -> Option<ExecutionNodeRef> {
        self.provenance
            .get(node.0 as usize)?
            .antecedents
            .iter()
            .find_map(|antecedent| {
                match self
                    .provenance
                    .get(antecedent.0 as usize)
                    .map(|node| &node.kind)
                {
                    Some(ProvenanceKind::Execution { node }) => Some(ExecutionNodeRef(*node)),
                    _ => None,
                }
            })
    }

    /// True when the effect uses a word `owner` forwarded from its `argument`:
    /// the effect's argument traces, through the argument nodes wrappers
    /// forward, to an argument that index owned by `owner`. `timeout 5 sh -c
    /// "$(...)"` runs its shell's code from argument 4. A chain that ends in a
    /// different invocation's argument of the same index is not a forward from
    /// `owner` and does not match.
    pub(crate) fn effect_has_forwarded_argument(
        &self,
        effect: usize,
        argument: u32,
        owner: ExecutionNodeRef,
    ) -> bool {
        let is_argument = |reference: &ProvenanceRef| {
            matches!(
                self.provenance
                    .get(reference.0 as usize)
                    .map(|node| &node.kind),
                Some(ProvenanceKind::Argument { .. })
            )
        };
        let Some(effect) = self.effects.get(effect) else {
            return false;
        };
        let mut pending = effect
            .provenance
            .iter()
            .filter(|reference| is_argument(reference))
            .flat_map(|reference| &self.provenance[reference.0 as usize].antecedents)
            .filter(|reference| is_argument(reference))
            .copied()
            .collect::<Vec<_>>();
        let mut seen = BTreeSet::new();
        while let Some(reference) = pending.pop() {
            if !seen.insert(reference) {
                continue;
            }
            let node = &self.provenance[reference.0 as usize];
            let forwarded = node
                .antecedents
                .iter()
                .filter(|antecedent| is_argument(antecedent))
                .copied()
                .collect::<Vec<_>>();
            if forwarded.is_empty() {
                if node.kind == (ProvenanceKind::Argument { index: argument })
                    && self.argument_owner(reference) == Some(owner)
                {
                    return true;
                }
            } else {
                pending.extend(forwarded);
            }
        }
        false
    }

    pub(crate) fn effect_execution(&self, index: usize) -> Option<ExecutionNodeRef> {
        self.effects.get(index).map(|effect| effect.execution)
    }

    /// The argv of a spawned execution, for reading a nested command a wrapper
    /// launched rather than trusting the outer argv words.
    pub(crate) fn execution_argv(&self, execution: ExecutionNodeRef) -> Option<&[String]> {
        match &self.execution_nodes.get(execution.0 as usize)?.subject {
            Subject::Exec { argv, .. } => Some(argv),
            _ => None,
        }
    }

    /// The `owner` argument a wrapped command's `child_index` was forwarded
    /// from: follow the `Argument` node the effect carries for that index
    /// through the `Argument` antecedents each wrapper appends, to the
    /// outermost one, and return its index only when that root belongs to
    /// `owner`. `None` when the effect carries no such argument or the chain
    /// terminates in another invocation, so an index a different command
    /// happens to reuse never maps onto `owner`'s word.
    pub(crate) fn forwarded_argument_root(
        &self,
        effect: usize,
        child_index: u32,
        owner: ExecutionNodeRef,
    ) -> Option<u32> {
        let argument_index = |reference: &ProvenanceRef| match self
            .provenance
            .get(reference.0 as usize)
            .map(|node| &node.kind)
        {
            Some(ProvenanceKind::Argument { index }) => Some(*index),
            _ => None,
        };
        let mut current = *self
            .effects
            .get(effect)?
            .provenance
            .iter()
            .find(|reference| argument_index(reference) == Some(child_index))?;
        loop {
            let next = self.provenance[current.0 as usize]
                .antecedents
                .iter()
                .find(|antecedent| argument_index(antecedent).is_some());
            match next {
                Some(next) => current = *next,
                None => {
                    return (self.argument_owner(current) == Some(owner))
                        .then(|| argument_index(&current))
                        .flatten();
                }
            }
        }
    }

    /// What interprets the shell source being evaluated: the nearest program
    /// the current script runs under.
    pub(crate) fn script_interpreter(&self) -> ScriptInterpreter<'_> {
        for (depth, execution) in self.execution_stack.iter().enumerate().rev() {
            match &self.execution_nodes[execution.0 as usize].subject {
                Subject::Exec { argv, .. } => {
                    return argv
                        .first()
                        .and_then(|program| program.rsplit('/').next())
                        .map_or(ScriptInterpreter::Unknown, ScriptInterpreter::Program);
                }
                Subject::Shell { .. } if depth == 0 => return ScriptInterpreter::Root,
                // A shell a language runtime started carries the shell it
                // selected; any other nested shell runs under its parent.
                Subject::Shell { .. } => match self.runtime_shells.get(execution) {
                    Some(RuntimeShell::Program(program)) => {
                        return ScriptInterpreter::Program(
                            program.rsplit('/').next().unwrap_or(program),
                        );
                    }
                    Some(RuntimeShell::Unresolved) => return ScriptInterpreter::Unresolved,
                    None => {}
                },
                _ => return ScriptInterpreter::Unknown,
            }
        }
        ScriptInterpreter::Unknown
    }

    pub(crate) fn effect_execution_command(&self, index: usize) -> Option<&str> {
        let execution = self.effects.get(index)?.execution;
        let Subject::Exec { argv, .. } = &self.execution_nodes.get(execution.0 as usize)?.subject
        else {
            return None;
        };
        argv.first()?.rsplit('/').next()
    }

    /// Locate an effect in the source parsed by `root`, even when a wrapper
    /// or nested substitution owns the effect's immediate execution.
    pub(crate) fn effect_source_span_in_execution(
        &self,
        index: usize,
        root: ExecutionNodeRef,
    ) -> Option<effinterp_proto::ByteSpan> {
        let effect = self.effects.get(index)?;
        if effect.execution == root {
            return self.source_span(&effect.provenance);
        }
        self.execution_edges
            .iter()
            .filter(|edge| edge.from == root && !edge.cycle)
            .find(|edge| self.execution_is_within(edge.to, effect.execution))
            .and_then(|edge| self.execution_nodes.get(edge.to.0 as usize)?.source_span)
    }

    /// Whether `candidate` is `root` or was launched beneath it.
    pub(crate) fn execution_is_within(
        &self,
        root: ExecutionNodeRef,
        candidate: ExecutionNodeRef,
    ) -> bool {
        let mut pending = vec![root];
        let mut seen = BTreeSet::new();
        while let Some(node) = pending.pop() {
            if node == candidate {
                return true;
            }
            if !seen.insert(node) {
                continue;
            }
            pending.extend(
                self.execution_edges
                    .iter()
                    .filter(|edge| edge.from == node && !edge.cycle)
                    .map(|edge| edge.to),
            );
        }
        false
    }

    pub(crate) fn effect_has_flow_input(&self, index: u32) -> bool {
        self.flow_stages.iter().any(|stage| {
            stage
                .bindings
                .iter()
                .any(|binding| binding.to == crate::flow::BindEnd::Effect(index))
        })
    }

    pub(crate) fn effect_string_attribute(&self, index: usize, name: &str) -> Option<&str> {
        match self.effects.get(index)?.attributes.get(name)? {
            AttrValue::String(value) => Some(value),
            _ => None,
        }
    }

    pub(crate) fn set_effect_string_attribute(&mut self, index: usize, name: &str, value: &str) {
        if let Some(effect) = self.effects.get_mut(index) {
            let changed = !matches!(
                effect.attributes.get(name),
                Some(AttrValue::String(current)) if current == value
            );
            effect
                .attributes
                .insert(name.to_string(), AttrValue::String(value.to_string()));
            // Flow classification may rewrite a model's source label after
            // observing the actual descriptor wiring. That is new semantic
            // interpretation, so it cannot retain a producer's request proof.
            if changed {
                effect.request_assurance = effinterp_proto::RequestAssurance::Conservative;
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn apply_library_api(
        &mut self,
        first_effect: usize,
        source: &str,
        targets: &[String],
        operation: &str,
        model: &str,
        slash_comments: bool,
        hash_comments: bool,
        rust_lifetimes: bool,
    ) {
        let calls = exact_call_ranges(
            source,
            targets,
            slash_comments,
            hash_comments,
            rust_lifetimes,
        );
        if calls.is_empty() {
            return;
        }
        let execution = self.current_execution();
        let offset = self.source_span_offsets.last().copied().unwrap_or_default() as usize;
        let matches = (first_effect..self.effects.len())
            .filter(|index| {
                let effect = &self.effects[*index];
                effect.operation.0 == operation
                    && effect.execution == execution
                    && self.source_span(&effect.provenance).is_some_and(|span| {
                        calls.iter().any(|call| {
                            call.matches(span.start as usize, span.end as usize, offset)
                        })
                    })
            })
            .collect::<Vec<_>>();
        for index in matches {
            let antecedents = self.effects[index].provenance.clone();
            let model = self.node(
                ProvenanceKind::ModelApplication {
                    model: model.to_string(),
                },
                &antecedents,
            );
            self.effects[index].provenance.push(model);
        }
    }

    /// Record an internal stage occurrence within the causal node budget.
    pub(crate) fn flow_stage(&mut self, stage: FlowStage) -> Option<u32> {
        if self.flow_stages.len() as u64 >= self.limits.max_causal_nodes {
            self.note_causality_saturated("max_causal_nodes");
            return None;
        }
        self.flow_stages.push(stage);
        Some((self.flow_stages.len() - 1) as u32)
    }

    /// Record an internal binding within the causal edge budget.
    pub(crate) fn flow_edge(&mut self, edge: Flow) {
        if self.flow_edges.len() as u64 >= self.limits.max_causal_edges {
            self.note_causality_saturated("max_causal_edges");
            return;
        }
        self.flow_edges.push(edge);
    }

    /// Buffer a deferred def-use flow stage, returning its pending id. Pending
    /// stages materialize in `finish` only when a pending edge references
    /// them or [`PlanBuilder::keep_pending_flow_stage`] pins them, so a
    /// producer with no consumer leaves the graph untouched.
    pub(crate) fn pending_flow_stage(&mut self, stage: FlowStage) -> usize {
        self.pending_flow_stages.push(stage);
        self.pending_flow_stages.len() - 1
    }

    /// The effects a deferred producer stage carries, so a consumer that
    /// holds only the producer's [`crate::flow::FlowRef`] can describe what
    /// the value it supplies discloses.
    pub(crate) fn pending_flow_stage_effects(&self, stage: u32) -> &[u32] {
        self.pending_flow_stages
            .get(stage as usize)
            .map_or(&[], |stage| stage.effects.as_slice())
    }

    /// Carry an exact resource selection emitted on stdout into the effect
    /// attributed to the unquoted substitution that supplied its operand.
    /// The shell still leaves the argv word unresolved because field splitting
    /// may yield any number of fields; only the modeled set identity moves.
    pub(crate) fn apply_exact_argument_selection(
        &mut self,
        producers: &[crate::flow::FlowRef],
        effects: std::ops::Range<u32>,
        argument: u32,
    ) {
        let candidates = producers
            .iter()
            .filter(|producer| producer.port == effinterp_proto::Port::Stdout)
            .filter_map(|producer| self.pending_flow_stages.get(producer.stage as usize))
            .flat_map(|stage| &stage.bindings)
            .filter_map(|binding| {
                (binding.assurance == effinterp_proto::CausalAssurance::Exact
                    && binding.to == crate::flow::BindEnd::Port(effinterp_proto::Port::Stdout))
                .then_some(match binding.from {
                    crate::flow::BindEnd::Effect(effect) => Some(effect),
                    crate::flow::BindEnd::Port(_) => None,
                })
                .flatten()
            })
            .collect::<BTreeSet<_>>();
        let mut candidates = candidates.into_iter();
        let Some(source) = candidates.next() else {
            return;
        };
        if candidates.next().is_some() {
            return;
        }
        self.apply_argument_selection(source, effects, argument);
    }

    pub(crate) fn record_stdout_paths(&mut self, paths: crate::models::PrintedPaths) {
        self.stdout_paths.push((self.current_execution(), paths));
    }

    pub(crate) fn stdout_paths(
        &self,
        execution: ExecutionNodeRef,
    ) -> Option<&crate::models::PrintedPaths> {
        self.stdout_paths
            .iter()
            .find_map(|(owner, paths)| (*owner == execution).then_some(paths))
    }

    /// Record that the effects in `effects` belong to a command whose argv
    /// index `argument` xargs fills from its stdin.
    pub(crate) fn record_stdin_argument(&mut self, effects: std::ops::Range<u32>, argument: u32) {
        self.stdin_arguments.push((effects, argument, false));
    }

    /// Settle the xargs operands within `effects`, whose stage reads its own
    /// stdin rather than the enclosing shell's: when `source` is the exact
    /// selection that stdin carries, it becomes their resource. Either way an
    /// enclosing pipeline's stdin no longer reaches them.
    pub(crate) fn settle_stdin_arguments(
        &mut self,
        source: Option<u32>,
        effects: std::ops::Range<u32>,
    ) {
        let mut arguments = Vec::new();
        for (range, argument, settled) in &mut self.stdin_arguments {
            if !*settled && effects.start <= range.start && range.end <= effects.end {
                *settled = true;
                arguments.push((range.clone(), *argument));
            }
        }
        if let Some(source) = source {
            for (range, argument) in arguments {
                self.apply_argument_selection(source, range, argument);
            }
        }
    }

    /// Hold the xargs operands within `effects`, whose stage reads `channel`,
    /// until the deferred process writing that channel has been analyzed.
    pub(crate) fn defer_channel_arguments(&mut self, channel: u32, effects: std::ops::Range<u32>) {
        for (range, argument, settled) in &mut self.stdin_arguments {
            if !*settled && effects.start <= range.start && range.end <= effects.end {
                *settled = true;
                self.channel_arguments
                    .push((channel, range.clone(), *argument));
            }
        }
    }

    /// Settle the operands that read `channel` once its writer is analyzed:
    /// `source` is the exact selection it printed there, if any.
    pub(crate) fn settle_channel_arguments(&mut self, channel: u32, source: Option<u32>) {
        let mut arguments = Vec::new();
        self.channel_arguments.retain(|(read, range, argument)| {
            if *read == channel {
                arguments.push((range.clone(), *argument));
            }
            *read != channel
        });
        if let Some(source) = source {
            for (range, argument) in arguments {
                self.apply_argument_selection(source, range, argument);
            }
        }
    }

    fn apply_argument_selection(
        &mut self,
        source: u32,
        effects: std::ops::Range<u32>,
        argument: u32,
    ) {
        let Some(Effect {
            resource: ResourceExpr::Pattern { pattern },
            attributes,
            ..
        }) = self.effects.get(source as usize)
        else {
            return;
        };
        let resource = ResourceExpr::Pattern {
            pattern: pattern.clone(),
        };
        let family = pattern.family();
        let selection = ["all", "selection"]
            .into_iter()
            .filter_map(|name| {
                attributes
                    .get(name)
                    .cloned()
                    .map(|value| (name.to_string(), value))
            })
            .collect::<Vec<_>>();
        let targets = effects
            .filter(|effect| {
                self.effect_has_argument(*effect as usize, argument)
                    && matches!(
                        self.effect_resource(*effect as usize),
                        Some(ResourceExpr::Unresolved { family: unresolved })
                            if unresolved == &family
                    )
            })
            .collect::<Vec<_>>();
        for target in targets {
            self.effects[target as usize].resource = resource.clone();
            self.effects[target as usize]
                .attributes
                .extend(selection.iter().cloned());
        }
    }

    /// Associate an environment value's provenance with its deferred data producers.
    pub(crate) fn register_environment_value_producers(
        &mut self,
        node: ProvenanceRef,
        producers: &[crate::flow::FlowRef],
    ) {
        // The overflow sentinel is shared by unrelated values.
        if !producers.is_empty() && (node.0 as u64) < self.limits.max_provenance_nodes {
            self.environment_value_producers
                .insert(node, producers.to_vec());
        }
    }

    /// Only explicit value links count; provenance ancestry also contains control evidence.
    pub(crate) fn environment_value_producers(
        &self,
        provenance: &[ProvenanceRef],
    ) -> Vec<crate::flow::FlowRef> {
        provenance
            .iter()
            .filter_map(|node| self.environment_value_producers.get(node))
            .flatten()
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    /// Feed a disclosed value into its read effect, whose owning stage routes stdout.
    pub(crate) fn bind_environment_value_producers(
        &mut self,
        effect: u32,
        provenance: &[ProvenanceRef],
    ) {
        use crate::flow::{BindEnd, FlowReason, FlowRef, PortBinding};
        use effinterp_proto::Port;
        let producers = self.environment_value_producers(provenance);
        if producers.is_empty() {
            return;
        }
        let consumer = self.pending_flow_stage(FlowStage {
            execution: None,
            effects: vec![effect],
            bindings: vec![PortBinding {
                assurance: effinterp_proto::CausalAssurance::Conservative,
                from: BindEnd::Port(Port::Arg(0)),
                to: BindEnd::Effect(effect),
            }],
            provenance: provenance.to_vec(),
        }) as u32;
        for from in producers {
            self.pending_flow_edge(Flow {
                assurance: effinterp_proto::CausalAssurance::Conservative,
                from,
                to: FlowRef {
                    stage: consumer,
                    port: Port::Arg(0),
                },
                reason: FlowReason::new("environment value"),
                provenance: provenance.to_vec(),
            });
        }
    }

    /// Pin a pending stage so `finish` materializes it even when no pending
    /// edge names it. Pipeline stages use this so a sibling with no pipe edge
    /// still keeps its effect↔port bindings.
    pub(crate) fn keep_pending_flow_stage(&mut self, id: u32) {
        self.pending_flow_keep.insert(id);
    }

    /// Buffer a deferred def-use edge between two pending stage ids.
    pub(crate) fn pending_flow_edge(&mut self, edge: Flow) {
        self.pending_flow_edges.push(edge);
    }

    /// Materialize the deferred def-use wiring: register each pending stage an
    /// edge references or that was kept (respecting the stage cap) and remap
    /// the edges onto the registered ids. Unreferenced, unkept pending stages
    /// are dropped.
    fn commit_pending_flows(&mut self) {
        let keep = std::mem::take(&mut self.pending_flow_keep);
        if self.pending_flow_edges.is_empty() && keep.is_empty() {
            self.pending_flow_stages.clear();
            return;
        }
        let stages = std::mem::take(&mut self.pending_flow_stages);
        let edges = std::mem::take(&mut self.pending_flow_edges);
        let used: BTreeSet<u32> = edges
            .iter()
            .flat_map(|e| [e.from.stage, e.to.stage])
            .chain(keep)
            .collect();
        let mut remap: Vec<Option<u32>> = Vec::with_capacity(stages.len());
        for (i, stage) in stages.into_iter().enumerate() {
            remap.push(if used.contains(&(i as u32)) {
                self.flow_stage(stage)
            } else {
                None
            });
        }
        for mut edge in edges {
            let (Some(from), Some(to)) = (
                remap[edge.from.stage as usize],
                remap[edge.to.stage as usize],
            ) else {
                continue;
            };
            edge.from.stage = from;
            edge.to.stage = to;
            self.flow_edge(edge);
        }
    }

    /// Necessity the budget refused to prove stays possible; the retained
    /// limit evidence names the causal precision that was lost.
    fn note_control_saturated(&mut self, limit: &'static str) {
        self.flow_coverage = CoverageLevel::Partial;
        let dataflow = Domain::new("dataflow");
        if let Some(boundary) = self.boundaries.iter_mut().find(|boundary| {
            boundary.reason == BoundaryReason::LIMIT_SATURATED
                && boundary.limit.as_deref() == Some(limit)
        }) {
            if !boundary.domains.contains(&dataflow) {
                boundary.domains.push(dataflow);
            }
            return;
        }
        self.saturated.insert(limit, true);
        self.boundaries.push(Boundary {
            reason: BoundaryReason::LIMIT_SATURATED,
            class: BoundaryClass::Limit,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: vec![dataflow],
            provenance: Vec::new(),
            limit: Some(limit.to_string()),
            detail: None,
        });
    }

    /// Mark the causality graph truncated without degrading an effect domain.
    pub(crate) fn note_causality_saturated(&mut self, limit: &'static str) {
        self.flow_coverage = CoverageLevel::Partial;
        if self.saturated.insert(limit, true).is_some() {
            return;
        }
        self.boundaries.push(Boundary {
            reason: BoundaryReason::LIMIT_SATURATED,
            class: BoundaryClass::Limit,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: vec![Domain::new("dataflow")],
            provenance: Vec::new(),
            limit: Some(limit.to_string()),
            detail: None,
        });
    }

    pub fn boundary(&mut self, boundary: Boundary) -> BoundaryRef {
        self.boundary_with_coverage(boundary, CoverageLevel::Partial)
    }

    /// Record that a source declared callables but execution entered none of
    /// them. The declaration list is bounded so one diagnostic stays compact.
    pub(crate) fn no_entry_point(
        &mut self,
        declared_callables: &[String],
        domains: &[&str],
        scope: Option<ProvenanceRef>,
    ) -> BoundaryRef {
        let mut detail = format!(
            "no execution root reached; declared callables not executed: {}",
            declared_callables
                .iter()
                .take(8)
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join(", ")
        );
        if declared_callables.len() > 8 {
            detail.push_str(&format!(" (+{} more)", declared_callables.len() - 8));
        }
        self.boundary_with_coverage(
            Boundary {
                reason: BoundaryReason::NO_ENTRY_POINT,
                class: BoundaryClass::Unresolved,
                scope: BoundaryScope::Invocation,
                affected_resource: None,
                callee: None,
                domains: domains.iter().map(|domain| Domain::new(*domain)).collect(),
                provenance: scope.as_slice().to_vec(),
                limit: None,
                detail: Some(detail),
            },
            CoverageLevel::Partial,
        )
    }

    /// Retain a boundary whose overflow is known to be confined to one domain.
    pub(crate) fn boundary_in_domain(
        &mut self,
        boundary: Boundary,
        domain: &'static str,
    ) -> BoundaryRef {
        self.boundary_with_coverage_in_domain(boundary, CoverageLevel::Partial, domain)
    }

    /// Retain one boundary and introduce the non-full coverage it owns as one
    /// operation. `None` remains stronger than the default partial boundary.
    pub fn boundary_with_coverage(
        &mut self,
        boundary: Boundary,
        level: CoverageLevel,
    ) -> BoundaryRef {
        self.boundary_with_coverage_and_saturation_domains(boundary, level, &KNOWN_DOMAINS)
    }

    pub(crate) fn boundary_with_coverage_in_domain(
        &mut self,
        boundary: Boundary,
        level: CoverageLevel,
        domain: &'static str,
    ) -> BoundaryRef {
        self.boundary_with_coverage_and_saturation_domains(boundary, level, &[domain])
    }

    fn boundary_with_coverage_and_saturation_domains(
        &mut self,
        mut boundary: Boundary,
        level: CoverageLevel,
        domains: &[&str],
    ) -> BoundaryRef {
        assert_ne!(level, CoverageLevel::Full);
        // A step the engine cannot model, resolve or read may create or
        // write files, as New-Item, an unknown program or a build target, so
        // later listings are stale. A limit or a parse failure stops the
        // analysis rather than passing a step by.
        if !matches!(
            boundary.class,
            BoundaryClass::Limit | BoundaryClass::ParseFailure
        ) && self.is_host_realm()
            && (boundary.domains.is_empty()
                || boundary
                    .domains
                    .iter()
                    .any(|domain| domain.0 == "filesystem"))
        {
            self.budget.note_unmodeled();
        }
        let family = boundary
            .domains
            .first()
            .map(|domain| domain.0.as_str())
            .unwrap_or("unknown");
        if let Some(resource) = &mut boundary.affected_resource {
            bound_resource_depth(resource, MAX_RESOURCE_DEPTH, family);
            *resource = effinterp_proto::normalize_resource(resource.clone(), self.path_platform);
        }
        for domain in &boundary.domains {
            self.merge_coverage(domain.clone(), level);
        }
        if self.boundaries.len() as u64 >= self.limits.max_boundaries {
            let domains: BTreeSet<&str> = domains
                .iter()
                .copied()
                .chain(boundary.domains.iter().map(|domain| domain.0.as_str()))
                .collect();
            self.note_saturated_domains("max_boundaries", &domains.into_iter().collect::<Vec<_>>());
            // Point at an existing boundary so any Opaque nested resolution
            // referencing this ref stays valid.
            return BoundaryRef(self.boundaries.len().saturating_sub(1) as u32);
        }
        self.boundaries.push(boundary);
        BoundaryRef((self.boundaries.len() - 1) as u32)
    }

    /// Declare opacity across every known effect domain — used by unmodeled
    /// commands and lost nested transitions, whose effects could reach any
    /// domain, not only a fixed few. Absent domains then read as unknown.
    pub fn global_opacity(&mut self, level: CoverageLevel) {
        for domain in KNOWN_DOMAINS {
            self.declare_coverage(Domain::new(domain), level);
        }
    }

    /// Declare coverage for a domain. Merging keeps the worst level declared,
    /// so no caller can restore coverage another caller degraded.
    pub fn declare_coverage(&mut self, domain: Domain, level: CoverageLevel) {
        self.merge_coverage(domain, level);
    }

    /// Assert closure after the root walk, only when no effect boundary remains.
    /// A model's narrow gap domains do not prove other domains unaffected by
    /// omitted behavior. Causal-only gaps do not prevent effect closure.
    pub fn attest_closure(&mut self, domain: Domain) {
        if !self
            .boundaries
            .iter()
            .any(|boundary| boundary.domains.iter().any(|domain| domain.0 != "dataflow"))
        {
            self.merge_coverage(domain, CoverageLevel::Full);
        }
    }

    fn merge_coverage(&mut self, domain: Domain, level: CoverageLevel) {
        if domain.0 == "dataflow" {
            self.flow_coverage = worse(self.flow_coverage, level);
            return;
        }
        self.coverage
            .entry(domain)
            .and_modify(|current| *current = worse(*current, level))
            .or_insert(level);
    }

    pub fn finish(mut self) -> Result<Plan, Vec<ValidationError>> {
        self.commit_pending_flows();
        for node in &mut self.execution_nodes {
            let mut seen = BTreeSet::new();
            node.evidence.retain(|reference| seen.insert(*reference));
        }
        for edge in &mut self.execution_edges {
            let mut seen = BTreeSet::new();
            edge.evidence.retain(|reference| seen.insert(*reference));
        }
        self.execution_edges.sort_by(|a, b| {
            (&a.from, &a.to, a.kind, a.cycle, &a.evidence).cmp(&(
                &b.from,
                &b.to,
                b.kind,
                b.cycle,
                &b.evidence,
            ))
        });
        self.execution_edges.dedup();
        self.flow_edges.sort_by(|a, b| {
            (&a.from, &a.to, &a.reason, &a.provenance).cmp(&(
                &b.from,
                &b.to,
                &b.reason,
                &b.provenance,
            ))
        });
        self.flow_edges.dedup();
        let max_nodes = usize::try_from(self.limits.max_causal_nodes).unwrap_or(usize::MAX);
        let max_edges = usize::try_from(self.limits.max_causal_edges).unwrap_or(usize::MAX);
        let max_depth = usize::try_from(self.limits.max_causal_depth).unwrap_or(usize::MAX);
        let max_pairs = usize::try_from(self.limits.max_causal_pairs).unwrap_or(usize::MAX);
        let mut execution_graph = ExecutionGraph {
            entry: ExecutionNodeRef(0),
            nodes: std::mem::take(&mut self.execution_nodes),
            edges: std::mem::take(&mut self.execution_edges),
        };
        let request_selections = execution_graph.exact_request_selections();
        for effect in &mut self.effects {
            if request_selections.get(effect.execution.0 as usize) != Some(&true)
                || effect.condition.as_ref().is_some_and(Condition::is_widened)
            {
                effect.request_assurance = effinterp_proto::RequestAssurance::Conservative;
            }
        }
        let mut causality = build_causality(
            &self.subject,
            &self.effects,
            &execution_graph,
            &self.provenance,
            &self.boundaries,
            &self.flow_stages,
            &self.flow_edges,
            &self.transfer_bindings,
            self.flow_coverage,
            max_nodes,
            max_edges,
            max_depth,
            max_pairs,
        );
        for node in &causality.graph.as_ref().unwrap().nodes {
            let OccurrenceKind::Boundary {
                reason,
                limit,
                detail,
            } = &node.occurrence
            else {
                continue;
            };
            if self.boundaries.iter().any(|boundary| {
                boundary.reason == *reason && boundary.limit == *limit && boundary.detail == *detail
            }) {
                continue;
            }
            self.boundaries.push(Boundary {
                reason: reason.clone(),
                class: BoundaryClass::Limit,
                scope: BoundaryScope::Invocation,
                affected_resource: None,
                callee: None,
                domains: vec![Domain::new("dataflow")],
                provenance: node.provenance.clone(),
                limit: limit.clone(),
                detail: detail.clone(),
            });
        }
        // Retained plan evidence is authoritative: an emitted effect establishes
        // its domain, while every retained boundary lowers each domain it names.
        // Explicit frontend claims may add domains or lower these levels, but
        // cannot make a boundary-covered domain full through the worst-level merge.
        let effect_domains = self
            .effects
            .iter()
            .map(|effect| Domain::new(effect.operation.domain()))
            .collect::<BTreeSet<_>>();
        for domain in effect_domains {
            self.merge_coverage(domain, CoverageLevel::Full);
        }
        let boundary_domains = self
            .boundaries
            .iter()
            .flat_map(|boundary| boundary.domains.iter().cloned())
            .collect::<BTreeSet<_>>();
        for domain in boundary_domains {
            self.merge_coverage(domain, CoverageLevel::Partial);
        }
        // Claims are retained plan data. A refused charge uses the existing
        // bounded saturation reserve so even the byte limit remains explained.
        let claim_bytes = 3 * NODE_BYTES
            + self
                .coverage
                .keys()
                .map(|domain| 2 * NODE_BYTES + domain.0.len() as u64)
                .sum::<u64>()
            + self
                .boundaries
                .iter()
                .map(|boundary| boundary.domains.len() as u64 * NODE_BYTES)
                .sum::<u64>();
        if !self.budget.try_charge_bytes(claim_bytes) {
            self.note_saturated_at("max_analysis_bytes", None);
            // Do not retain an uncharged, potentially large gap index. Keep
            // one limit boundary covering all discarded gaps, and rebind
            // execution references before deriving the final positional refs.
            let domains = self
                .boundaries
                .iter()
                .flat_map(|boundary| boundary.domains.iter().cloned())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            let index = self
                .boundaries
                .iter()
                .position(|boundary| boundary.limit.as_deref() == Some("max_analysis_bytes"))
                .expect("byte saturation has retained evidence");
            let timeout = self
                .boundaries
                .iter()
                .find(|boundary| boundary.limit.as_deref() == Some("invocation_deadline"))
                .cloned();
            let mut boundary = self.boundaries.remove(index);
            boundary.domains = domains;
            self.boundaries = vec![boundary];
            if let Some(timeout) = timeout {
                self.boundaries.push(timeout);
            }
            for node in &mut execution_graph.nodes {
                if node.boundary.is_some() {
                    node.boundary = Some(BoundaryRef(0));
                }
            }
        }
        let mut gap_counts: BTreeMap<&Domain, usize> = BTreeMap::new();
        for boundary in &self.boundaries {
            for domain in &boundary.domains {
                *gap_counts.entry(domain).or_default() += 1;
            }
        }
        causality.coverage.gaps =
            Vec::with_capacity(*gap_counts.get(&Domain::new("dataflow")).unwrap_or(&0));
        let mut coverage: BTreeMap<Domain, CoverageClaim> = self
            .coverage
            .into_iter()
            .map(|(domain, level)| {
                let gaps = Vec::with_capacity(*gap_counts.get(&domain).unwrap_or(&0));
                (domain, CoverageClaim { level, gaps })
            })
            .collect();
        for (index, boundary) in self.boundaries.iter().enumerate() {
            for domain in &boundary.domains {
                let claim = if domain.0 == "dataflow" {
                    &mut causality.coverage
                } else {
                    coverage
                        .get_mut(domain)
                        .expect("boundary declares coverage")
                };
                let reference = BoundaryRef(index as u32);
                if claim.gaps.last() != Some(&reference) {
                    claim.gaps.push(reference);
                }
            }
        }
        let mut plan = Plan {
            schema: SCHEMA_V1.to_string(),
            subject: self.subject,
            analysis: self.analysis,
            effects: self.effects,
            execution_graph,
            provenance: self.provenance,
            boundaries: self.boundaries,
            coverage: Coverage(coverage),
            causality,
        };
        plan.stamp_effect_ids()?;
        // Readers keep reasons outside the registry, but the engine emits only
        // registered ones: a consumer refuses a reason it has no code for.
        debug_assert!(
            plan.boundaries
                .iter()
                .all(|boundary| boundary.reason.spec().is_some()),
            "unregistered boundary reason in {:?}",
            plan.boundaries
        );
        effinterp_proto::validate_plan(&plan)?;
        Ok(plan)
    }
}

pub(crate) fn exact_call_ranges(
    source: &str,
    targets: &[String],
    slash_comments: bool,
    hash_comments: bool,
    rust_lifetimes: bool,
) -> Vec<ExactCallRange> {
    let code = mask_non_code(source, slash_comments, hash_comments, rust_lifetimes);
    let text = std::str::from_utf8(&code).expect("mask preserves UTF-8 code bytes");
    let mut ranges = Vec::new();
    for target in targets {
        ranges.extend(source.match_indices(target).filter_map(|(start, _)| {
            if text.as_bytes().get(start) != source.as_bytes().get(start) {
                return None;
            }
            let before = text[..start].chars().next_back();
            if before.is_some_and(|character| {
                character.is_alphanumeric() || character == '_' || character == '.'
            }) {
                return None;
            }
            call_range(text, start, start + target.len())
        }));
    }
    ranges.sort_by_key(|range| (range.start, range.end));
    ranges.dedup();
    ranges
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct ExactCallRange {
    pub(crate) start: usize,
    pub(crate) open: usize,
    pub(crate) end: usize,
}

impl ExactCallRange {
    fn matches(self, start: usize, end: usize, offset: usize) -> bool {
        (start == self.start + offset && end == self.end + offset)
            || (start == self.open + offset && end + 1 == self.end + offset)
    }
}

fn call_range(source: &str, start: usize, mut open: usize) -> Option<ExactCallRange> {
    while source
        .as_bytes()
        .get(open)
        .is_some_and(u8::is_ascii_whitespace)
    {
        open += 1;
    }
    if source.as_bytes().get(open) != Some(&b'(') {
        return None;
    }
    let mut depth = 0usize;
    for (offset, byte) in source.as_bytes()[open..].iter().enumerate() {
        match byte {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(ExactCallRange {
                        start,
                        open,
                        end: open + offset + 1,
                    });
                }
            }
            _ => {}
        }
    }
    Some(ExactCallRange {
        start,
        open,
        end: source.len(),
    })
}

fn mask_non_code(
    source: &str,
    slash_comments: bool,
    hash_comments: bool,
    rust_lifetimes: bool,
) -> Vec<u8> {
    #[derive(Clone, Copy)]
    enum Mask {
        Code,
        LineComment,
        BlockComment,
        Quoted { quote: u8, triple: bool },
        Raw { hashes: usize },
    }

    let bytes = source.as_bytes();
    let mut masked = bytes.to_vec();
    let mut state = Mask::Code;
    let mut index = 0;
    while index < bytes.len() {
        match state {
            Mask::Code if slash_comments && bytes[index..].starts_with(b"//") => {
                masked[index] = b' ';
                masked[index + 1] = b' ';
                index += 2;
                state = Mask::LineComment;
            }
            Mask::Code if bytes[index..].starts_with(b"/*") => {
                masked[index] = b' ';
                masked[index + 1] = b' ';
                index += 2;
                state = Mask::BlockComment;
            }
            Mask::Code if hash_comments && bytes[index] == b'#' => {
                masked[index] = b' ';
                index += 1;
                state = Mask::LineComment;
            }
            Mask::Code if bytes[index] == b'r' => {
                let mut quote = index + 1;
                while bytes.get(quote) == Some(&b'#') {
                    quote += 1;
                }
                if bytes.get(quote) == Some(&b'"') {
                    let hashes = quote - index - 1;
                    for byte in &mut masked[index..=quote] {
                        *byte = b' ';
                    }
                    index = quote + 1;
                    state = Mask::Raw { hashes };
                } else {
                    index += 1;
                }
            }
            Mask::Code
                if bytes[index] == b'\'' && rust_lifetimes && rust_lifetime_at(bytes, index) =>
            {
                index += 1;
            }
            Mask::Code if matches!(bytes[index], b'\'' | b'"' | b'`') => {
                let quote = bytes[index];
                let triple = bytes[index..].starts_with(&[quote, quote, quote]);
                let width = if triple { 3 } else { 1 };
                for byte in &mut masked[index..index + width] {
                    *byte = b' ';
                }
                index += width;
                state = Mask::Quoted { quote, triple };
            }
            Mask::Code => index += 1,
            Mask::LineComment if bytes[index] == b'\n' => {
                index += 1;
                state = Mask::Code;
            }
            Mask::LineComment => {
                masked[index] = b' ';
                index += 1;
            }
            Mask::BlockComment if bytes[index..].starts_with(b"*/") => {
                masked[index] = b' ';
                masked[index + 1] = b' ';
                index += 2;
                state = Mask::Code;
            }
            Mask::BlockComment => {
                masked[index] = b' ';
                index += 1;
            }
            Mask::Quoted { quote, triple }
                if triple && bytes[index..].starts_with(&[quote, quote, quote]) =>
            {
                for byte in &mut masked[index..index + 3] {
                    *byte = b' ';
                }
                index += 3;
                state = Mask::Code;
            }
            Mask::Quoted {
                quote,
                triple: false,
            } if bytes[index] == quote => {
                masked[index] = b' ';
                index += 1;
                state = Mask::Code;
            }
            Mask::Quoted { triple: false, .. } if bytes[index] == b'\\' => {
                masked[index] = b' ';
                if index + 1 < bytes.len() {
                    masked[index + 1] = b' ';
                }
                index += 2;
            }
            Mask::Quoted { .. } => {
                masked[index] = b' ';
                index += 1;
            }
            Mask::Raw { hashes } if bytes[index] == b'"' => {
                let end = index + hashes + 1;
                if end <= bytes.len() && bytes[index + 1..end].iter().all(|byte| *byte == b'#') {
                    for byte in &mut masked[index..end] {
                        *byte = b' ';
                    }
                    index = end;
                    state = Mask::Code;
                } else {
                    masked[index] = b' ';
                    index += 1;
                }
            }
            Mask::Raw { .. } => {
                masked[index] = b' ';
                index += 1;
            }
        }
    }
    masked
}

fn rust_lifetime_at(source: &[u8], quote: usize) -> bool {
    let mut end = quote + 1;
    if !source
        .get(end)
        .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
    {
        return false;
    }
    end += 1;
    while source
        .get(end)
        .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
    {
        end += 1;
    }
    source.get(end) != Some(&b'\'')
}

fn stream_ref(
    node: ExecutionNodeRef,
    stream: effinterp_proto::ExecutionStream,
) -> effinterp_proto::ExecutionStreamRef {
    effinterp_proto::ExecutionStreamRef { node, stream }
}

/// Widen any resource subtree deeper than `remaining` to an unresolved family,
/// so an adversarial deeply-nested Join/Union cannot make a plan unbounded.
fn bound_resource_depth(expr: &mut ResourceExpr, remaining: usize, family: &str) -> bool {
    if remaining == 0 {
        *expr = unresolved_resource(family);
        return true;
    }
    let mut widened = false;
    if let ResourceExpr::Concrete { identity } = expr {
        for value in identity.infrastructure_values_mut() {
            widened |= bound_resource_depth(value, remaining - 1, family);
        }
    }
    match expr {
        ResourceExpr::Property { base, .. } => {
            widened |= bound_resource_depth(base, remaining - 1, family);
        }
        ResourceExpr::Pattern {
            pattern: effinterp_proto::ResourcePattern::Process { argv_prefix, .. },
        } => {
            for arg in argv_prefix {
                widened |= bound_resource_depth(arg, remaining - 1, family);
            }
        }
        ResourceExpr::Join { parts }
        | ResourceExpr::Union {
            alternatives: parts,
        } => {
            for part in parts {
                widened |= bound_resource_depth(part, remaining - 1, family);
            }
        }
        ResourceExpr::Concrete { identity } if identity.scope().is_some() => {
            for value in identity.scope_mut().unwrap().values_mut() {
                widened |= bound_resource_depth(value, remaining - 1, family);
            }
        }
        ResourceExpr::Concrete { identity } => match identity {
            effinterp_proto::ResourceIdentity::GitRepository {
                worktree,
                git_dir,
                pathspec,
            } => {
                for resource in worktree.iter_mut().chain(git_dir).chain(pathspec) {
                    widened |= bound_resource_depth(resource, remaining - 1, family);
                }
            }
            effinterp_proto::ResourceIdentity::Artifact {
                endpoint,
                name,
                reference,
                ..
            } => {
                for value in [endpoint.as_mut(), name.as_mut()]
                    .into_iter()
                    .chain(reference.value_mut())
                {
                    widened |= bound_resource_depth(value, remaining - 1, family);
                }
            }
            effinterp_proto::ResourceIdentity::Process { argv, cwd, .. } => {
                for arg in argv {
                    widened |= bound_resource_depth(arg, remaining - 1, family);
                }
                if let Some(cwd) = cwd {
                    widened |= bound_resource_depth(cwd, remaining - 1, family);
                }
            }
            effinterp_proto::ResourceIdentity::Container { storage, .. } => {
                for storage in storage {
                    match storage {
                        effinterp_proto::ContainerStorage::BindMount {
                            host_path,
                            container_path,
                            ..
                        } => {
                            widened |= bound_resource_depth(host_path, remaining - 1, family);
                            widened |= bound_resource_depth(container_path, remaining - 1, family);
                        }
                        effinterp_proto::ContainerStorage::Volume { container_path, .. } => {
                            widened |= bound_resource_depth(container_path, remaining - 1, family)
                        }
                    }
                }
            }
            _ => {}
        },
        ResourceExpr::Literal { .. }
        | ResourceExpr::Parameter { .. }
        | ResourceExpr::Environment { .. }
        | ResourceExpr::Pattern { .. }
        | ResourceExpr::Unresolved { .. } => {}
    }
    widened
}

fn untyped_resource_cause(error: &ValidationError) -> String {
    match error {
        ValidationError::EmptyResourceIdentity { .. } => "empty_resource_identity".to_string(),
        ValidationError::IncompatibleResourceFamily { identity, .. } => {
            format!("incompatible_resource_family:{identity}")
        }
        ValidationError::EmptyResourceParts { .. } => "empty_resource_parts".to_string(),
        ValidationError::InvalidPattern { .. } => "invalid_pattern".to_string(),
        ValidationError::EmptyPattern { .. } => "empty_pattern".to_string(),
        // Future validate_effect_resource error classes still degrade; never
        // panic on the untyped-resource path.
        _ => "invalid_effect_resource".to_string(),
    }
}

// Invalid supplied scope must not erase a known resource name or its other dimensions.
fn retract_invalid_scope_values(resource: &mut ResourceExpr) -> bool {
    let mut retracted = false;
    match resource {
        ResourceExpr::Concrete { identity } => {
            if let Some(scope) = identity.scope_mut() {
                for (dimension, value) in &mut scope.identity {
                    if !scope.kind.valid_scope_value(*dimension, value) {
                        *value = effinterp_proto::ScopeValue::Unknown;
                        retracted = true;
                    }
                }
            }
        }
        ResourceExpr::Union {
            alternatives: parts,
        }
        | ResourceExpr::Join { parts } => {
            for part in parts {
                retracted |= retract_invalid_scope_values(part);
            }
        }
        ResourceExpr::Property { base, .. } => {
            retracted |= retract_invalid_scope_values(base);
        }
        _ => {}
    }
    retracted
}

/// The shell that interprets a script, as far as the execution graph shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ScriptInterpreter<'a> {
    /// The analyzed subject itself: the agent's bash.
    Root,
    /// A program by basename.
    Program(&'a str),
    /// A nested script with no evidence of its interpreter.
    Unknown,
    /// A language runtime's shell, selected by a value Nah cannot recover.
    Unresolved,
}

/// The shell a language runtime selected to run a command string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RuntimeShell {
    /// A literal program: the default `/bin/sh`, or an override such as
    /// Node's `{shell: '/bin/bash'}` or Python's `executable='/bin/bash'`.
    Program(String),
    /// An override whose value is not a literal.
    Unresolved,
}
