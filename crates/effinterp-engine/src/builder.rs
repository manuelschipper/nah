use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::rc::Rc;

use effinterp_proto::{
    Analysis, AttrValue, Boundary, BoundaryClass, BoundaryReason, BoundaryRef, BoundaryScope,
    ByteSpan, Condition, Coverage, CoverageClaim, CoverageLevel, Domain, Effect,
    ExecutionAssurance, ExecutionEdge, ExecutionEdgeKind, ExecutionGraph, ExecutionNode,
    ExecutionNodeRef, ExecutionRealm, ExecutionStreams, OccurrenceKind, Plan, ProvenanceKind,
    ProvenanceNode, ProvenanceRef, ResourceExpr, ResourceIdentity, SCHEMA_V1, Subject,
    ValidationError,
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
    execution_source_authorship: Vec<SourceAuthorship>,
    execution_edges: Vec<ExecutionEdge>,
    /// The launchers of each execution, by the edges into it that are not
    /// cycles, in the order those edges were added.
    execution_launchers: BTreeMap<ExecutionNodeRef, Vec<ExecutionNodeRef>>,
    execution_stack: Vec<ExecutionNodeRef>,
    /// A direct JavaScript eval shares its caller's loader and module cache.
    js_evaluations: BTreeMap<ExecutionNodeRef, (ExecutionNodeRef, bool)>,
    /// Effect counts at which a command model said its program consumes
    /// standard input as program input, as `xargs` and `cat` do: the stage
    /// holding that point reads a redirected file as program input.
    stdin_consumers: Vec<usize>,
    /// The shell a language runtime selected for each shell it started.
    runtime_shells: BTreeMap<ExecutionNodeRef, RuntimeShell>,
    /// Structural limits that saturated within each execution node.
    execution_saturated: BTreeSet<ExecutionNodeRef>,
    effect_id_subjects: BTreeSet<ExecutionNodeRef>,
    provenance: Vec<ProvenanceNode>,
    request_computations: BTreeSet<ProvenanceRef>,
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
    /// Earlier shell chain operands established at the current source read.
    /// They qualify predicted bytes without duplicating conditions on effects.
    source_read_conditions: Vec<Condition>,
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
    /// The exact text a launched process writes to its stdout, by the
    /// process's execution, where a frontend proves the program prints
    /// nothing else (`record_printed_text`).
    printed_texts: Vec<(ExecutionNodeRef, String)>,
    /// True only for final, unredirected stdout in the top-level shell.
    pub(crate) stdout_unconsumed: bool,
    /// The literal xargs stage a bare find listing feeds directly, when that
    /// xargs hands every item it reads to one command as operands.
    pub(crate) stdout_paths_consumer: Option<crate::models::XargsConsumer>,
    /// The executable a host-observed `PATH` search certified for the
    /// invocation whose model is applying, while it applies.
    pub(crate) certified_executable: Option<String>,
    /// Directories whose listing, read while a pipeline was measured, holds
    /// no name `xargs` would cut apart. The measuring walk leaves the
    /// pipeline's own removals behind as changes to the tree, so the walk
    /// that follows cannot repeat the reading and takes the answer from here.
    pub(crate) unsplit_listings: BTreeSet<String>,
    /// Source-to-destination pairings recorded while lowering transfers, as
    /// slots into `effects`. `build_causality` turns them into
    /// `ResourceTransfer` edges once occurrence identity is final.
    transfer_bindings: Vec<TransferBinding>,
    /// Host file mutations in walk order. Later source reads see these writes
    /// instead of the file content as it existed before the invocation.
    source_writes: Vec<SourceWrite>,
    /// Potentially concurrent/repeated writes, whether they change path identity,
    /// whether background work outlives its enclosing region, and the length
    /// of `source_writes` when the region began. Pipeline hazards identify
    /// their stage so that stage's own ordered reads can still resolve source.
    source_hazards: Vec<SourceHazard>,
    /// Files whose bytes a shell read as code while it opened a command's
    /// redirections (a here-string's or a process substitution's capture),
    /// with the index of the here-string's redirection. The command checks
    /// them against the redirection targets the walk expands only after the
    /// command ran (`note_script_reads_rewritten`).
    script_reads: Vec<(String, Option<usize>)>,
    /// Files whose bytes were read as code, in walk order. A process
    /// substitution's body is walked after the script that started it, so
    /// its writes are checked against the reads made since it started
    /// (`code_reads_rewritten`).
    code_reads: Vec<String>,
    /// Whether some effect was named by a resolved path that differs from
    /// its spelling. Until one is, every recorded name is the spelled one,
    /// and a lookup by spelling needs no question to the host.
    renamed_entries: bool,
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
    source_end: usize,
    git_config: usize,
}

/// The hazards of one region, lifted while a walk meets its writes in order.
pub(crate) struct SuspendedHazards {
    source: Vec<SourceHazard>,
    git_config: Vec<(Option<(usize, usize)>, GitConfigWrite)>,
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

pub(crate) type SourceMutation = (ResourceExpr, bool, Vec<usize>);

struct SourceHazard {
    resource: ResourceExpr,
    changes_identity: bool,
    background: bool,
    mark: usize,
    stage: Option<(usize, usize)>,
}

struct SourceWrite {
    resource: ResourceExpr,
    changes_identity: bool,
    effect: Option<u32>,
    /// Exact bytes after the mutation, or a suffix of the initial file named by copied_from.
    content: Option<Vec<u8>>,
    subject_spans: Vec<ByteSpan>,
    /// A redirect or tee preserves an existing mode and creates a missing file
    /// without execute bits. A copy or other write can carry its own mode.
    plain_content_write: bool,
    /// Initial host bytes retained by a copy or append, observed only if needed as source.
    copied_from: Option<String>,
    pipeline_stages: Vec<usize>,
    /// Conditions active at the mutation; `None` when they cannot be compared.
    conditions: Option<Vec<Condition>>,
    /// A create of a name no file held, such as `mktemp`'s: it changes no
    /// existing file's bytes, and the file it makes is empty.
    fresh: bool,
}

/// What a source read at a host path sees after earlier mutations.
pub(crate) enum WrittenSource {
    /// No earlier mutation reaches the path; the host file is authoritative.
    Host,
    /// Every path to this read passes the write that produced these bytes.
    Exact {
        bytes: Vec<u8>,
        subject_spans: Vec<ByteSpan>,
    },
    Appended {
        prefix: String,
        bytes: Vec<u8>,
        subject_spans: Vec<ByteSpan>,
    },
    /// Known top-level JSON members, with the remaining members unobserved.
    JsonFields(String),
    /// A copy retained the initial bytes at this host path.
    Copied(String),
    /// Known bytes on the paths where a conditional write ran. Other paths
    /// still need a boundary rather than a claim about the host's old bytes.
    Conditional {
        source: Box<WrittenSource>,
        condition: Condition,
    },
    /// A mutation may have replaced the file with bytes the walk cannot name.
    Stale,
    /// Concurrent or widened mutations prevent qualifying the source bytes.
    Ambiguous,
}

/// Provenance of the exact source buffer an execution analyzes.
#[derive(Clone)]
pub(crate) enum SourceAuthorship {
    External,
    Subject,
    Mixed(Rc<[ByteSpan]>),
}

impl From<bool> for SourceAuthorship {
    fn from(from_subject: bool) -> Self {
        if from_subject {
            Self::Subject
        } else {
            Self::External
        }
    }
}

impl SourceAuthorship {
    pub(crate) fn is_subject(&self) -> bool {
        matches!(self, Self::Subject)
    }
}

fn record_subject_span(spans: &mut Vec<ByteSpan>, start: usize, end: usize) {
    let (Ok(start), Ok(end)) = (start.try_into(), end.try_into()) else {
        return;
    };
    if start < end {
        if let Some(last) = spans.last_mut().filter(|last| last.end == start) {
            last.end = end;
        } else {
            spans.push(ByteSpan { start, end });
        }
    }
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
    script_reads: usize,
    code_reads: usize,
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
            pattern: effinterp_proto::ResourcePattern::FsPath { glob, .. },
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
            prints_completion: false,
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
            execution_source_authorship: vec![SourceAuthorship::Subject],
            execution_edges: Vec::new(),
            execution_launchers: BTreeMap::new(),
            execution_stack: vec![ExecutionNodeRef(0)],
            js_evaluations: BTreeMap::new(),
            stdin_consumers: Vec::new(),
            runtime_shells: BTreeMap::new(),
            execution_saturated: BTreeSet::new(),
            effect_id_subjects: BTreeSet::new(),
            provenance: Vec::new(),
            request_computations: BTreeSet::new(),
            source_span_offsets: vec![0],
            last_source_span: None,
            provenance_memo: HashMap::new(),
            boundaries: Vec::new(),
            coverage: BTreeMap::new(),
            saturated: BTreeMap::new(),
            realm_stack: Vec::new(),
            accounted_effect_bytes: 0,
            condition_stack: Vec::new(),
            source_read_conditions: Vec::new(),
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
            printed_texts: Vec::new(),
            stdout_unconsumed: false,
            stdout_paths_consumer: None,
            certified_executable: None,
            unsplit_listings: BTreeSet::new(),
            transfer_bindings: Vec::new(),
            source_writes: Vec::new(),
            source_hazards: Vec::new(),
            script_reads: Vec::new(),
            code_reads: Vec::new(),
            renamed_entries: false,
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
            script_reads: self.script_reads.len(),
            code_reads: self.code_reads.len(),
            control: self.control.checkpoint(),
        }
    }

    pub(crate) fn rollback(&mut self, cp: BuilderCheckpoint) {
        self.budget
            .release_bytes(self.accounted_effect_bytes - cp.accounted_effect_bytes);
        self.accounted_effect_bytes = cp.accounted_effect_bytes;
        self.effects.truncate(cp.effects);
        self.stdin_consumers.retain(|at| *at <= cp.effects);
        self.execution_nodes.truncate(cp.execution_nodes);
        self.execution_source_authorship
            .truncate(cp.execution_nodes);
        self.js_evaluations
            .retain(|execution, _| (execution.0 as usize) < cp.execution_nodes);
        // Each removed edge is the last one recorded into its execution.
        for edge in self.execution_edges[cp.execution_edges..].iter().rev() {
            if !edge.cycle
                && let Some(launchers) = self.execution_launchers.get_mut(&edge.to)
            {
                launchers.pop();
            }
        }
        self.execution_edges.truncate(cp.execution_edges);
        self.execution_stack.truncate(cp.execution_stack);
        self.runtime_shells
            .retain(|node, _| (node.0 as usize) < cp.execution_nodes);
        self.execution_saturated = cp.execution_saturated;
        self.effect_id_subjects = cp.effect_id_subjects;
        self.provenance.truncate(cp.provenance);
        self.request_computations
            .retain(|r| (r.0 as usize) < cp.provenance);
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
        self.script_reads.truncate(cp.script_reads);
        self.code_reads.truncate(cp.code_reads);
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
        self.follow_created_aliases_before(resource, self.effects.len())
    }

    fn follow_created_aliases_before(
        &self,
        resource: &mut ResourceExpr,
        end: usize,
    ) -> Vec<ProvenanceRef> {
        let mut nodes = Vec::new();
        let mut seen = vec![resource.clone()];
        while let Some((target, provenance)) = self.created_alias_identity_before(resource, end) {
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
        let resolve = |candidate: &ResourceExpr| {
            if self
                .source_hazards_at_current_stage()
                .any(|hazard| hazard.changes_identity && &hazard.resource == candidate)
            {
                return None;
            }
            let current_condition = self.current_condition();
            crate::resource_transfer::moved_content_identity(
                &self.effects,
                &self.execution_nodes,
                &self.transfer_bindings,
                &self.provenance,
                candidate,
                self.current_execution(),
                current_condition.as_ref(),
            )
        };
        resolve(resource).or_else(|| resolve(&self.entry_named(resource)?))
    }

    /// Whether this plan names host paths by their entries. A Windows plan
    /// keeps the spelling: the host answers a rooted POSIX spelling there
    /// with a drive path, another grammar than the one the command wrote.
    fn names_by_entry(&self) -> bool {
        self.is_host_realm() && self.path_platform == effinterp_proto::PathPlatform::Posix
    }

    /// Rename the host path `resource` spells to the name its entry carries
    /// (`models::common::resolved_entry_name`), a glob by the directory its
    /// literal text spells. Returns the spelling it was renamed from, and
    /// whether that was one concrete path. A selection of several members,
    /// as `find` states a root and everything below it, keeps its spelling:
    /// its members are read together and must stay named alike.
    fn name_by_entry(&mut self, resource: &mut ResourceExpr) -> Option<(String, bool)> {
        use crate::models::common::{resolved_entry_name, resolved_pattern_name};
        let (name, concrete) = match resource {
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path },
            } => (path, true),
            ResourceExpr::Pattern {
                pattern: effinterp_proto::ResourcePattern::FsPath { glob, .. },
            } => (glob, false),
            _ => return None,
        };
        let entry = if concrete {
            resolved_entry_name(&self.budget, name)
        } else {
            resolved_pattern_name(&self.budget, name)
        }
        .filter(|entry| entry != name)?;
        self.renamed_entries = true;
        Some((std::mem::replace(name, entry), concrete))
    }

    /// Record that an effect's resource was renamed from its spelling.
    pub(crate) fn note_renamed_entry(&mut self) {
        self.renamed_entries = true;
    }

    /// The name the plan's effects carry for the host path `path`, when it
    /// differs from the spelling: its entry, every parent directory resolved
    /// (`models::common::resolved_entry_name`). A lookup among recorded
    /// effects and writes by a path as a command spelled it asks this, so
    /// `/tmp/p.sh` finds the write named `/private/tmp/p.sh`.
    fn entry_named_path(&self, path: &str) -> Option<String> {
        if !self.renamed_entries || !self.names_by_entry() {
            return None;
        }
        crate::models::common::resolved_entry_name(&self.budget, path).filter(|entry| entry != path)
    }

    /// [`Self::entry_named_path`] of a concrete filesystem resource.
    fn entry_named(&self, resource: &ResourceExpr) -> Option<ResourceExpr> {
        let ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } = resource
        else {
            return None;
        };
        Some(ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath {
                path: self.entry_named_path(path)?,
            },
        })
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
        let resolve = |candidate: &ResourceExpr| {
            crate::resource_transfer::archived_symlink_source(
                &self.effects,
                &self.execution_nodes,
                candidate,
            )
        };
        resolve(resource).or_else(|| resolve(&self.entry_named(resource)?))
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
        self.created_alias_identity_before(resource, self.effects.len())
    }

    fn created_alias_identity_before(
        &self,
        resource: &ResourceExpr,
        end: usize,
    ) -> Option<(ResourceExpr, Vec<ProvenanceRef>)> {
        self.created_alias_identity_as_named(resource, end)
            .or_else(|| self.created_alias_identity_as_named(&self.entry_named(resource)?, end))
    }

    fn created_alias_identity_as_named(
        &self,
        resource: &ResourceExpr,
        end: usize,
    ) -> Option<(ResourceExpr, Vec<ProvenanceRef>)> {
        let resolve = |candidate: &ResourceExpr| {
            if self
                .source_hazards_at_current_stage()
                .any(|hazard| hazard.changes_identity && &hazard.resource == candidate)
            {
                return None;
            }
            crate::resource_transfer::created_alias_identity(
                &self.effects[..end],
                &self.execution_nodes,
                &self.transfer_bindings,
                candidate,
                &|spelled| self.entry_named(spelled),
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

    pub(crate) fn enter_source_read_conditions(
        &mut self,
        conditions: &[Condition],
    ) -> Vec<Condition> {
        let mut conditions = conditions.to_vec();
        if let Some(instance) = &self.condition_call {
            for condition in &mut conditions {
                condition.rebind(instance);
            }
        }
        let previous = self.source_read_conditions.clone();
        self.source_read_conditions.extend(conditions);
        previous
    }

    pub(crate) fn leave_source_read_conditions(&mut self, previous: Vec<Condition>) {
        self.source_read_conditions = previous;
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

    /// Nested groups past the walker's frame bound. Established effects stay;
    /// the interior is not treated as absent. A deadline already recorded
    /// keeps its own refusal.
    pub(crate) fn note_nesting_limit(&mut self) {
        if self.analysis.outcome == effinterp_proto::AnalysisOutcome::Complete {
            self.analysis.outcome = effinterp_proto::AnalysisOutcome::Refused {
                kind: effinterp_proto::AnalysisRefusalKind::NestingLimit,
            };
        }
    }

    /// A nested execution the walk did not enter for its depth, or a launched
    /// script it could not read for its size. What it runs is unread, not
    /// absent. A measuring walk is rolled back, so only the real walk records
    /// it, and a deadline already recorded keeps its own refusal.
    pub(crate) fn note_executed_input_limit(&mut self) {
        if !self.budget.measuring()
            && self.analysis.outcome == effinterp_proto::AnalysisOutcome::Complete
        {
            self.analysis.outcome = effinterp_proto::AnalysisOutcome::Refused {
                kind: effinterp_proto::AnalysisRefusalKind::ExecutedInputLimit,
            };
        }
    }

    /// Code the shell runs from a file a write of the same command reaches at
    /// a point the walk cannot order: what runs is unknown, not absent.
    /// Recorded like an unread launch.
    pub(crate) fn note_unpinned_source(&mut self) {
        if !self.budget.measuring()
            && self.analysis.outcome == effinterp_proto::AnalysisOutcome::Complete
        {
            self.analysis.outcome = effinterp_proto::AnalysisOutcome::Refused {
                kind: effinterp_proto::AnalysisRefusalKind::UnpinnedSource,
            };
        }
    }

    pub(crate) fn note_step_limit(&mut self) {
        if self.analysis.outcome == effinterp_proto::AnalysisOutcome::Complete {
            self.analysis.outcome = effinterp_proto::AnalysisOutcome::Refused {
                kind: effinterp_proto::AnalysisRefusalKind::StepLimit,
            };
        }
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

    pub(crate) fn recorded_transfers(&self) -> &[TransferBinding] {
        &self.transfer_bindings
    }

    fn effect_with_saturation_domains(
        &mut self,
        mut effect: Effect,
        domains: &[&str],
    ) -> Option<u32> {
        if effect.operation.domain() == "filesystem"
            && let ResourceExpr::Join { parts } = &effect.resource
            && let Some((index, alternatives)) =
                parts.iter().enumerate().find_map(|(index, part)| {
                    if let ResourceExpr::Union { alternatives } = part {
                        alternatives
                            .iter()
                            .any(|alternative| {
                                matches!(
                                    alternative,
                                    ResourceExpr::Literal { .. }
                                        | ResourceExpr::Concrete {
                                            identity: ResourceIdentity::FsPath { .. }
                                        }
                                )
                            })
                            .then_some((index, alternatives))
                    } else {
                        None
                    }
                })
        {
            // A path prefix with several possible values names a complete
            // path for each value, including any known protected member.
            let mut last = None;
            for alternative in alternatives.clone() {
                let mut parts = parts.clone();
                parts[index] = alternative;
                let mut one = effect.clone();
                one.resource = effinterp_proto::normalize_resource(
                    ResourceExpr::Join { parts },
                    self.path_platform,
                );
                if let Some(slot) = self.effect_with_saturation_domains(one, domains) {
                    last = Some(slot);
                }
                if self.budget.exhausted() {
                    break;
                }
            }
            return last;
        }
        if effect.operation.spec().is_some()
            && effect.operation.domain() == "filesystem"
            && matches!(effect.resource, ResourceExpr::Union { .. })
        {
            // Tee, sed, and find emit one effect for a whole path union.
            // A concrete path or a pattern inside it is labeled only once
            // it is its own effect. The unresolved spelling stays beside it.
            let parts = crate::paths::separate_unresolved_path_union(effect.resource.clone());
            if parts.len() > 1 {
                let mut last = None;
                for resource in parts {
                    let mut one = effect.clone();
                    one.resource = resource;
                    if let Some(slot) = self.effect_with_saturation_domains(one, domains) {
                        last = Some(slot);
                    }
                }
                return last;
            }
        }
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
            pattern: effinterp_proto::ResourcePattern::FsPath { glob, .. },
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
        // Every other host filesystem effect names its entry, with the
        // parents resolved as that read resolves them, so a write and a later
        // read of one file carry one name wherever a parent is a link.
        let mut spelled = None;
        if effect.operation.domain() == "filesystem"
            && effect.realm.is_host()
            && self.names_by_entry()
            && !crate::models::common::reads_operand_contents(&effect)
            && let Some((path, concrete)) = self.name_by_entry(&mut effect.resource)
        {
            // Whoever labels the effect judges the spelling as well: a
            // protected directory that is itself a link is protected by the
            // name the command wrote, which the resolved one no longer shows.
            effect.attributes.insert(
                crate::models::common::SPELLED_PATH.into(),
                AttrValue::String(path.clone()),
            );
            spelled = concrete.then_some(path);
        }
        // The naming allowance ran out, so this effect, or a lookup since the
        // last one, kept a spelling the host was not asked about. A read
        // named by another spelling of the same file may not meet it. Only
        // the name is unanswered: what the effect is and what it reaches are
        // stated as they were.
        if self.budget.take_naming_refused() {
            self.boundary_with_coverage(
                Boundary {
                    reason: BoundaryReason::OBSERVATION_UNAVAILABLE,
                    class: BoundaryClass::Limit,
                    scope: BoundaryScope::Invocation,
                    domains: vec![Domain::new("filesystem")],
                    affected_resource: None,
                    callee: None,
                    provenance: effect.provenance.clone(),
                    limit: Some("max_observation_requests".to_string()),
                    detail: Some("path name unresolved: limit".to_string()),
                },
                CoverageLevel::Partial,
            );
        }
        // Whatever this effect changes about filesystem topology invalidates
        // reliance on an initial fact about that entry or anything beneath it.
        if matches!(
            effect.operation.as_str(),
            "filesystem.create" | "filesystem.delete" | "filesystem.move"
        ) {
            let change = match effect.operation.as_str() {
                "filesystem.create"
                    if effect.attributes.get("directory") == Some(&AttrValue::Bool(true)) =>
                {
                    crate::nest::TopologyChange::CreatesDirectory
                }
                "filesystem.delete" => crate::nest::TopologyChange::Removes,
                _ => crate::nest::TopologyChange::Other,
            };
            // A later use may ask about the entry under the spelling this
            // effect was renamed from, and that fact is stale as well.
            if let Some(path) = &spelled {
                self.budget
                    .note_topology_mutation(Some(path.as_str()), change);
            }
            self.budget.note_topology_mutation(
                match &effect.resource {
                    ResourceExpr::Concrete {
                        identity: ResourceIdentity::FsPath { path },
                    } => Some(path.as_str()),
                    _ => None,
                },
                change,
            );
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
            // mkdir cannot replace a file or redirect a later write. Files
            // below it retain their bytes (or their absence) from the host.
            && !(effect.operation.as_str() == "filesystem.create"
                && effect.attributes.get("directory") == Some(&AttrValue::Bool(true)))
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
                subject_spans: Vec::new(),
                plain_content_write: false,
                copied_from: None,
                pipeline_stages: self.pipeline_stages.clone(),
                conditions: (self.condition_overflow == 0).then(|| {
                    if preset_condition {
                        effect.condition.iter().cloned().collect()
                    } else {
                        self.condition_stack.clone()
                    }
                }),
                fresh: false,
            });
        }
        self.effects.push(effect);
        if let Some(trigger) = trigger {
            self.effect_in_domain(trigger, "system");
        }
        Some(slot)
    }

    /// Record the exact bytes a file holds after the write effect in `slot`.
    /// An append retains the initial file or a proven earlier write as its
    /// prefix. `spelled` says every byte written is literal text of
    /// the analyzed subject, which the effect records as
    /// `written_from_subject`.
    pub(crate) fn predict_written_content(
        &mut self,
        slot: u32,
        content: &[u8],
        append: bool,
        spelled: bool,
        may_alias: impl Fn(&ResourceExpr, &str) -> bool,
    ) {
        let bytes = content.len() as u64 + NODE_BYTES + "written_content".len() as u64;
        if !self.budget.try_charge_bytes(bytes) {
            self.note_saturated("max_analysis_bytes");
            return;
        }
        self.accounted_effect_bytes += bytes;
        let attributes = &mut self.effects[slot as usize].attributes;
        attributes.insert(
            "written_content".into(),
            AttrValue::String(
                std::str::from_utf8(content)
                    .expect("predicted shell output is UTF-8")
                    .to_owned(),
            ),
        );
        if spelled {
            attributes.insert("written_from_subject".into(), AttrValue::Bool(true));
        } else {
            attributes.remove("written_from_subject");
        }
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
        let (mut bytes, mut subject_spans, copied_from) = if append {
            let write = &self.source_writes[index];
            let prior = self.source_writes[..index].iter().rev().find(|prior| {
                source_mutation_reaches(&prior.resource, path) || may_alias(&prior.resource, path)
            });
            match prior {
                None => (Vec::new(), Vec::new(), Some(path.clone())),
                Some(prior)
                    if prior.resource == write.resource
                        && prior.conditions.as_ref().is_some_and(|conditions| {
                            write.conditions.as_ref() == Some(conditions)
                                || conditions
                                    .iter()
                                    .all(|condition| self.condition_is_held(condition))
                        })
                        && (prior.content.is_some() || prior.copied_from.is_some()) =>
                {
                    (
                        prior.content.clone().unwrap_or_default(),
                        prior.subject_spans.clone(),
                        prior.copied_from.clone(),
                    )
                }
                _ => return,
            }
        } else {
            (Vec::new(), Vec::new(), None)
        };
        let start = bytes.len();
        bytes.extend_from_slice(content);
        if spelled {
            record_subject_span(&mut subject_spans, start, bytes.len());
        }
        self.source_writes[index].content = Some(bytes);
        self.source_writes[index].subject_spans = subject_spans;
        self.source_writes[index].plain_content_write = true;
        self.source_writes[index].copied_from = copied_from;
    }

    /// Retain known JSON members without claiming complete file bytes.
    pub(crate) fn predict_written_json_fields(&mut self, slot: u32, fields: &str) {
        let bytes = (fields.len() + "written_json_fields".len()) as u64 + NODE_BYTES;
        if !self.budget.try_charge_bytes(bytes) {
            self.note_saturated("max_analysis_bytes");
            return;
        }
        self.accounted_effect_bytes += bytes;
        self.set_effect_string_attribute(slot as usize, "written_json_fields", fields);
    }

    /// Retain the source state a copy read, before the destination was written.
    pub(crate) fn predict_copied_content(
        &mut self,
        slot: u32,
        source_path: String,
        source: WrittenSource,
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
        let (source, condition) = match source {
            WrittenSource::Conditional { source, condition } => (*source, Some(condition)),
            source => (source, None),
        };
        let attribute = match &source {
            WrittenSource::Exact { bytes, .. } => std::str::from_utf8(bytes)
                .ok()
                .map(|content| ("written_content", content)),
            WrittenSource::JsonFields(fields) => Some(("written_json_fields", fields.as_str())),
            _ => None,
        };
        if let Some((name, content)) = attribute {
            let bytes = (content.len() + name.len()) as u64 + NODE_BYTES;
            if !self.budget.try_charge_bytes(bytes) {
                self.note_saturated("max_analysis_bytes");
                return;
            }
            self.accounted_effect_bytes += bytes;
            self.set_effect_string_attribute(slot as usize, name, content);
        }
        let write = &mut self.source_writes[index];
        write.plain_content_write = false;
        if let Some(condition) = condition
            && let Some(conditions) = &mut write.conditions
        {
            conditions.push(condition);
        }
        match source {
            WrittenSource::Host => write.copied_from = Some(source_path),
            WrittenSource::Copied(path) => write.copied_from = Some(path),
            WrittenSource::Exact {
                bytes,
                subject_spans,
            } => {
                write.content = Some(bytes);
                write.subject_spans = subject_spans;
            }
            WrittenSource::Appended {
                prefix,
                bytes,
                subject_spans,
            } => {
                write.copied_from = Some(prefix);
                write.content = Some(bytes);
                write.subject_spans = subject_spans;
            }
            WrittenSource::JsonFields(_)
            | WrittenSource::Stale
            | WrittenSource::Ambiguous
            | WrittenSource::Conditional { .. } => {}
        }
    }

    /// Add bytes written later through the descriptor the write in `slot`
    /// opened. They extend its exact content only when no other mutation of
    /// the path came after it and the write happens under the same conditions;
    /// unknown bytes (`None`) leave the content unknown. The content stays
    /// `written_from_subject` only while every fragment is `spelled`.
    pub(crate) fn extend_written_content(
        &mut self,
        slot: u32,
        content: Option<&[u8]>,
        spelled: bool,
        may_alias: impl Fn(&ResourceExpr, &str) -> bool,
    ) {
        // The inserted fragment is distinct from the resulting file: an append
        // can have known bytes even when the pre-existing file is unobserved.
        let attributes = &mut self.effects[slot as usize].attributes;
        let fragment = attributes.remove("written_content");
        let marked = attributes.remove("written_from_subject").is_some();
        if let (Some(AttrValue::String(mut fragment)), Some(content)) = (fragment, content) {
            let bytes = fragment.len() as u64 + content.len() as u64 + NODE_BYTES;
            if self.budget.try_charge_bytes(bytes) {
                fragment.push_str(
                    std::str::from_utf8(content).expect("predicted shell output is UTF-8"),
                );
                self.accounted_effect_bytes += bytes;
                let attributes = &mut self.effects[slot as usize].attributes;
                attributes.insert("written_content".into(), AttrValue::String(fragment));
                if marked && spelled {
                    attributes.insert("written_from_subject".into(), AttrValue::Bool(true));
                }
            } else {
                self.note_saturated("max_analysis_bytes");
            }
        }
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
        let hazard = self.source_hazards_at_current_stage().any(|hazard| {
            source_mutation_reaches(&hazard.resource, path) || may_alias(&hazard.resource, path)
        });
        let extended = match (&write.content, content) {
            (Some(bytes), Some(content)) if current && !later && !hazard => {
                Some([bytes.as_slice(), content].concat())
            }
            _ => None,
        };
        let write = &mut self.source_writes[index];
        match &extended {
            Some(extended) if spelled => record_subject_span(
                &mut write.subject_spans,
                write.content.as_ref().unwrap().len(),
                extended.len(),
            ),
            None => {
                write.subject_spans.clear();
                write.copied_from = None;
            }
            _ => {}
        }
        write.content = extended;
    }

    /// Collect mutations and whether they change path identity before rollback.
    pub(crate) fn source_mutations_since(
        &self,
        checkpoint: &BuilderCheckpoint,
    ) -> Vec<SourceMutation> {
        self.source_writes[checkpoint.source_writes..]
            .iter()
            .map(|write| {
                (
                    write.resource.clone(),
                    write.changes_identity,
                    write.pipeline_stages.clone(),
                )
            })
            .collect()
    }

    /// Run `read` with the host mutations recorded from index `mark` on set
    /// aside, as a read completed at `mark` saw the files. Hazards stay in
    /// view: a concurrent write may still have reached that read. `read`
    /// records no mutation of its own.
    pub(crate) fn with_source_writes_before<T>(
        &mut self,
        mark: usize,
        read: impl FnOnce(&mut Self) -> T,
    ) -> T {
        let later = self
            .source_writes
            .split_off(mark.min(self.source_writes.len()));
        let result = read(self);
        self.source_writes.extend(later);
        result
    }

    /// Record that the shell read `path` as code while it opened a
    /// command's redirections: at its redirection `redirection` for a
    /// here-string, beside all of them for a process substitution.
    pub(crate) fn note_script_read(&mut self, path: &str, redirection: Option<usize>) {
        self.script_reads.push((path.to_string(), redirection));
    }

    pub(crate) fn script_read_count(&self) -> usize {
        self.script_reads.len()
    }

    /// Record that `path`'s bytes were read as code.
    pub(crate) fn note_code_read(&mut self, path: &str) {
        self.code_reads.push(path.to_string());
    }

    pub(crate) fn code_read_count(&self) -> usize {
        self.code_reads.len()
    }

    /// Whether a host write recorded at an index in `writes` may reach a file
    /// read as code at an index in `reads`.
    pub(crate) fn code_reads_rewritten(
        &self,
        reads: std::ops::Range<usize>,
        writes: std::ops::Range<usize>,
        may_alias: impl Fn(&ResourceExpr, &str) -> bool,
    ) -> bool {
        let reads = reads.start.min(self.code_reads.len())..reads.end.min(self.code_reads.len());
        self.code_reads[reads]
            .iter()
            .any(|path| self.source_written_in(writes.clone(), path, &may_alias))
    }

    /// Mark the host write the effect at `slot` recorded as a create of a
    /// name no file held.
    pub(crate) fn note_fresh_create(&mut self, slot: u32) {
        if let Some(write) = self
            .source_writes
            .iter_mut()
            .rev()
            .find(|write| write.effect == Some(slot))
        {
            write.fresh = true;
        }
    }

    /// Bash expands a command's redirection target words before the command
    /// runs, left to right; the walk expands them afterwards, recording the
    /// writes in `target_writes` by redirection index. A target write that
    /// reaches a file read as code since `reads_from` changed the bytes
    /// before that read, in an order the walk did not follow, so the read
    /// fails closed. A here-string's read follows only the targets before
    /// it; a process substitution's races every target.
    pub(crate) fn note_script_reads_rewritten(
        &mut self,
        reads_from: usize,
        target_writes: &[(usize, std::ops::Range<usize>)],
        may_alias: impl Fn(&ResourceExpr, &str) -> bool,
    ) {
        if self.script_reads[reads_from.min(self.script_reads.len())..]
            .iter()
            .any(|(path, redirection)| {
                target_writes
                    .iter()
                    .filter(|(index, _)| redirection.is_none_or(|read_at| *index < read_at))
                    .any(|(_, range)| self.source_written_in(range.clone(), path, &may_alias))
            })
        {
            self.note_unpinned_source();
        }
    }

    /// How many host file mutations have been recorded.
    pub(crate) fn source_write_count(&self) -> usize {
        self.source_writes.len()
    }

    /// Whether a host file mutation recorded at an index in `range` may reach
    /// the file at `path`: a capture of the file taken at `range.start` no
    /// longer holds the bytes a read after `range.end` would see.
    pub(crate) fn source_written_in(
        &self,
        range: std::ops::Range<usize>,
        path: &str,
        may_alias: impl Fn(&ResourceExpr, &str) -> bool,
    ) -> bool {
        let named = self.entry_named_path(path);
        let path = named.as_deref().unwrap_or(path);
        self.source_writes
            .iter()
            .enumerate()
            .take(range.end)
            .skip(range.start)
            .filter(|(_, write)| !write.fresh)
            .any(|(index, write)| {
                source_mutation_reaches(&write.resource, path)
                    || may_alias(&write.resource, path)
                    || self.source_mutation_redirected(&write.resource, index, &may_alias)
            })
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
        self.budget.enter_stage(position);
    }

    pub(crate) fn pop_pipeline_stage(&mut self) {
        self.pipeline_stages.pop();
        self.budget.leave_stage();
    }

    /// How many pipeline stages enclose the walk; a pipeline that starts
    /// here numbers its stages at this depth.
    pub(crate) fn pipeline_stage_depth(&self) -> usize {
        self.pipeline_stages.len()
    }

    /// Reads cannot assume ordering against concurrent writes or later iterations.
    pub(crate) fn push_source_hazards(
        &mut self,
        mutations: Vec<SourceMutation>,
        git_config_writes: Vec<GitConfigWrite>,
        stage_depth: Option<usize>,
        background: bool,
    ) -> HazardDepth {
        let mut depth = HazardDepth {
            source: self.source_hazards.len(),
            source_end: 0,
            git_config: self.git_config_hazards.len(),
        };
        let mark = self.source_writes.len();
        self.source_hazards.extend(mutations.into_iter().map(
            |(resource, changes_identity, stages)| SourceHazard {
                resource,
                changes_identity,
                background,
                mark,
                stage: stage_depth.and_then(|depth| Some((depth, *stages.get(depth)?))),
            },
        ));
        depth.source_end = self.source_hazards.len();
        self.git_config_hazards
            .extend(git_config_writes.into_iter().map(|write| {
                let stage =
                    stage_depth.and_then(|depth| Some((depth, *write.pipeline_stages.get(depth)?)));
                (stage, write)
            }));
        depth
    }

    /// A stage's own commands run in order; only its peers race its reads.
    fn source_hazards_at_current_stage(&self) -> impl Iterator<Item = &SourceHazard> {
        self.source_hazards.iter().filter(|hazard| {
            hazard.stage.is_none_or(|(depth, writer)| {
                self.pipeline_stages
                    .get(depth)
                    .is_none_or(|reader| *reader != writer)
            })
        })
    }

    /// Whether the write at `index` is the only mutation of `path` that the
    /// enclosing unordered regions can make. A pipeline that writes one file
    /// once still leaves that write's bytes in place when it completes; the
    /// other stages' reads keep seeing its hazard.
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
            .source_hazards_at_current_stage()
            .filter(|hazard| reaches(&hazard.resource));
        let Some(SourceHazard {
            resource,
            background,
            mark,
            ..
        }) = hazards.next()
        else {
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

    /// Future caller writes stop racing the job once its body is analyzed.
    /// Keep hazards introduced by nested background work inside that body.
    pub(crate) fn truncate_background_read_hazards(&mut self, depth: HazardDepth) {
        self.git_config_hazards.truncate(depth.git_config);
        self.source_hazards.drain(depth.source..depth.source_end);
    }

    /// Lift the hazards of the region begun at `depth` for a walk that meets
    /// each of its writes in order, as one iteration of a loop walked once
    /// per iteration does; [`Self::resume_source_hazards`] restores them.
    pub(crate) fn suspend_source_hazards(&mut self, depth: HazardDepth) -> SuspendedHazards {
        SuspendedHazards {
            source: self.source_hazards.split_off(depth.source),
            git_config: self.git_config_hazards.split_off(depth.git_config),
        }
    }

    pub(crate) fn resume_source_hazards(&mut self, suspended: SuspendedHazards) {
        self.source_hazards.extend(suspended.source);
        self.git_config_hazards.extend(suspended.git_config);
    }

    pub(crate) fn truncate_source_hazards(&mut self, depth: HazardDepth) {
        self.git_config_hazards.truncate(depth.git_config);
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
                .filter(|hazard| &hazard.resource == resource)
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
            .map(|hazard| !recorded(&hazard.resource, hazard.mark))
            .collect();
        for (hazard, replay) in hazards.into_iter().zip(replay) {
            if hazard.background {
                self.source_hazards.push(hazard);
            } else if replay {
                self.source_writes.push(SourceWrite {
                    resource: hazard.resource,
                    changes_identity: hazard.changes_identity,
                    effect: None,
                    content: None,
                    subject_spans: Vec::new(),
                    plain_content_write: false,
                    copied_from: None,
                    pipeline_stages: self.pipeline_stages.clone(),
                    conditions: None,
                    fresh: false,
                });
            }
        }
    }

    // A newly created link or replaced directory can redirect later writes.
    // Current filesystem metadata cannot prove those future targets disjoint.
    // A move names the path it vacates, so a later write there makes a new
    // entry and one beneath it fails: a move redirects nothing.
    fn source_identity_changed(
        &self,
        path: &str,
        before: usize,
        may_alias: &impl Fn(&ResourceExpr, &str) -> bool,
    ) -> bool {
        self.source_writes[..before].iter().any(|write| {
            write.changes_identity
                && write.effect.is_none_or(|slot| {
                    self.effects[slot as usize].operation.as_str() != "filesystem.move"
                })
                && (source_mutation_reaches(&write.resource, path)
                    || may_alias(&write.resource, path))
        }) || self.source_hazards_at_current_stage().any(|hazard| {
            hazard.changes_identity
                && (source_mutation_reaches(&hazard.resource, path)
                    || may_alias(&hazard.resource, path))
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
                pattern: effinterp_proto::ResourcePattern::FsPath { glob, .. },
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
    /// A Windows host (`ignore_case`) names a file without regard to case, so
    /// a write of `git.exe` is the file a launch of `GIT.EXE` runs.
    pub(crate) fn executable_was_written(
        &self,
        resource: &ResourceExpr,
        ignore_case: bool,
    ) -> bool {
        let same = |written: &ResourceExpr, launched: &ResourceExpr| {
            written == launched
                || ignore_case
                    && matches!(
                        (written, launched),
                        (
                            ResourceExpr::Concrete {
                                identity: ResourceIdentity::FsPath { path: written },
                            },
                            ResourceExpr::Concrete {
                                identity: ResourceIdentity::FsPath { path: launched },
                            },
                        ) if written.eq_ignore_ascii_case(launched)
                    )
        };
        let named = self.entry_named(resource);
        self.is_host_realm()
            && self.source_writes.iter().any(|write| {
                same(&write.resource, resource)
                    || named
                        .as_ref()
                        .is_some_and(|named| same(&write.resource, named))
            })
    }

    /// Bytes a startup file may contain when a conditional write or an unknown
    /// prefix prevents an exact source read. The caller keeps that boundary.
    pub(crate) fn written_source_fragments(&self, path: &str) -> Vec<String> {
        let named = self.entry_named_path(path);
        let path = named.as_deref().unwrap_or(path);
        let mut fragments = Vec::new();
        let mut sources = Vec::new();
        let retain = |prefix: &str,
                      fragments: &[(&str, bool)],
                      include_conditional: bool,
                      sources: &mut Vec<String>| {
            let selected = fragments
                .iter()
                .rev()
                .filter(|(_, definite)| *definite || include_conditional)
                .map(|(part, _)| *part);
            let bytes = prefix.len() + selected.clone().map(str::len).sum::<usize>();
            if self.budget.try_charge_bytes(bytes as u64) {
                let source = std::iter::once(prefix).chain(selected).collect();
                if !sources.contains(&source) {
                    sources.push(source);
                }
            }
        };
        for write in self
            .source_writes
            .iter()
            .rev()
            .filter(|write| source_mutation_reaches(&write.resource, path))
        {
            if !self.budget.try_charge_steps(1)
                || !matches!(&write.resource, ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path: written } } if written == path)
            {
                break;
            }
            let definite = self.condition_overflow == 0
                && write.conditions.as_ref().is_some_and(|conditions| {
                    conditions
                        .iter()
                        .all(|condition| self.condition_is_held(condition))
                });
            let attributes = write
                .effect
                .map(|effect| &self.effects[effect as usize].attributes);
            let content = write
                .content
                .as_deref()
                .filter(|_| write.copied_from.is_none())
                .and_then(|content| std::str::from_utf8(content).ok())
                .or_else(|| {
                    let attributes = attributes?;
                    match (
                        attributes.get("truncate"),
                        attributes.get("written_content"),
                    ) {
                        (Some(AttrValue::Bool(true)), Some(AttrValue::String(source))) => {
                            Some(source.as_str())
                        }
                        _ => None,
                    }
                });
            if let Some(content) = content {
                retain(content, &fragments, true, &mut sources);
                if fragments.iter().any(|(_, definite)| !definite) {
                    retain(content, &fragments, false, &mut sources);
                }
                // A conditional replacement can be skipped. A held overwrite
                // ends the history; older bytes cannot reach this read.
                if definite {
                    fragments.clear();
                    break;
                }
                continue;
            }
            let Some(attributes) = attributes else { break };
            match (attributes.get("append"), attributes.get("written_content")) {
                (Some(AttrValue::Bool(true)), Some(AttrValue::String(source))) => {
                    fragments.push((source.as_str(), definite))
                }
                _ if !definite => continue,
                _ => break,
            }
        }
        if !fragments.is_empty() {
            retain("", &fragments, true, &mut sources);
            if fragments.iter().any(|(_, definite)| !definite) {
                retain("", &fragments, false, &mut sources);
            }
        }
        sources
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
        // Writes are recorded under the names their effects carry.
        let named = self.entry_named_path(path);
        let path = named.as_deref().unwrap_or(path);
        if self.source_hazards_at_current_stage().any(|hazard| {
            source_mutation_reaches(&hazard.resource, path)
                || may_alias(&hazard.resource, path)
                || (!hazard.changes_identity
                    && self.source_mutation_redirected(
                        &hazard.resource,
                        self.source_writes.len(),
                        &may_alias,
                    ))
        }) {
            return WrittenSource::Ambiguous;
        }
        let Some((index, write)) =
            self.source_writes
                .iter()
                .enumerate()
                .rev()
                .find(|(index, write)| {
                    !write.conditions.as_ref().is_some_and(|conditions| {
                        conditions
                            .iter()
                            .any(|condition| self.condition_is_excluded(condition))
                    }) && (source_mutation_reaches(&write.resource, path)
                        // Creating a link changes its entry, not the bytes of
                        // the target that a later open follows.
                        || !write.changes_identity && may_alias(&write.resource, path)
                        || self.source_mutation_redirected(&write.resource, *index, &may_alias))
                })
        else {
            return WrittenSource::Host;
        };
        if self.source_mutation_redirected(&write.resource, index, &may_alias)
            && !matches!(&write.resource, ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path: written } } if written == path)
        {
            return WrittenSource::Stale;
        }
        let fields = write.effect.and_then(|slot| {
            match self.effects[slot as usize]
                .attributes
                .get("written_json_fields")
            {
                Some(AttrValue::String(fields)) => Some(fields),
                _ => None,
            }
        });
        let stated_content = write.effect.and_then(|slot| {
            let attributes = &self.effects[slot as usize].attributes;
            match (
                attributes.get("truncate"),
                attributes.get("written_content"),
            ) {
                (Some(AttrValue::Bool(true)), Some(AttrValue::String(content))) => Some((
                    content,
                    attributes.get("written_from_subject") == Some(&AttrValue::Bool(true)),
                )),
                _ => None,
            }
        });
        match (&write.content, &write.copied_from, &write.conditions) {
            (content, copied, Some(conditions))
                if (content.is_some()
                    || copied.is_some()
                    || fields.is_some()
                    || stated_content.is_some())
                    && matches!(&write.resource, ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path: written } } if written == path)
                    && self.condition_overflow == 0 =>
            {
                let source = if let (Some(bytes), Some(prefix)) = (content, copied) {
                    WrittenSource::Appended {
                        prefix: prefix.clone(),
                        bytes: bytes.clone(),
                        subject_spans: write.subject_spans.clone(),
                    }
                } else if let Some(bytes) = content {
                    WrittenSource::Exact {
                        bytes: bytes.clone(),
                        subject_spans: write.subject_spans.clone(),
                    }
                } else if let Some((content, written_from_subject)) = stated_content {
                    let mut subject_spans = Vec::new();
                    if written_from_subject {
                        record_subject_span(&mut subject_spans, 0, content.len());
                    }
                    WrittenSource::Exact {
                        bytes: content.as_bytes().to_vec(),
                        subject_spans,
                    }
                } else if let Some(copied) = copied {
                    WrittenSource::Copied(copied.clone())
                } else {
                    WrittenSource::JsonFields(fields.expect("JSON members retained").clone())
                };
                if conditions
                    .iter()
                    .all(|condition| self.condition_is_held(condition))
                {
                    source
                } else if let Some(condition) = Condition::compose(conditions.iter())
                    && !condition.is_widened()
                    && matches!(source, WrittenSource::Exact { .. })
                {
                    WrittenSource::Conditional {
                        source: Box::new(source),
                        condition,
                    }
                } else {
                    WrittenSource::Ambiguous
                }
            }
            (Some(_), _, _) | (_, Some(_), _) if matches!(&write.resource, ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path: written } } if written == path) => {
                WrittenSource::Ambiguous
            }
            _ => WrittenSource::Stale,
        }
    }

    /// Earlier known versions remain possible when the latest write did not
    /// run. Keep the skipped-write conditions so reads inside each version
    /// observe that version rather than a mutually exclusive later write.
    pub(crate) fn earlier_written_sources(
        &self,
        path: &str,
        may_alias: impl Fn(&ResourceExpr, &str) -> bool,
    ) -> Vec<(Vec<u8>, Vec<ByteSpan>, Condition)> {
        let named = self.entry_named_path(path);
        let path = named.as_deref().unwrap_or(path);
        let mut skipped = Vec::new();
        let mut versions = Vec::new();
        for write in self.source_writes.iter().rev().filter(|write| {
            (source_mutation_reaches(&write.resource, path)
                || !write.changes_identity && may_alias(&write.resource, path))
                && !write.conditions.as_ref().is_some_and(|conditions| {
                    conditions
                        .iter()
                        .any(|condition| self.condition_is_excluded(condition))
                })
        }) {
            let Some(conditions) = &write.conditions else {
                break;
            };
            if !skipped.is_empty()
                && matches!(&write.resource, ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path: written } } if written == path)
                && let Some(condition) = Condition::compose(conditions.iter().chain(&skipped))
                && !condition.is_widened()
                && !Self::source_condition_conflicts(&condition)
            {
                let stated = write.effect.and_then(|slot| {
                    let attributes = &self.effects[slot as usize].attributes;
                    (attributes.get("truncate") == Some(&AttrValue::Bool(true)))
                        .then(|| attributes.get("written_content"))
                        .flatten()
                        .and_then(|content| match content {
                            AttrValue::String(content) => Some((
                                content.as_bytes(),
                                attributes.get("written_from_subject")
                                    == Some(&AttrValue::Bool(true)),
                            )),
                            _ => None,
                        })
                });
                if let Some(bytes) = write
                    .content
                    .as_deref()
                    .filter(|_| write.copied_from.is_none())
                {
                    versions.push((bytes.to_vec(), write.subject_spans.clone(), condition));
                } else if let Some((bytes, written_from_subject)) = stated {
                    let mut subject_spans = Vec::new();
                    if written_from_subject {
                        record_subject_span(&mut subject_spans, 0, bytes.len());
                    }
                    versions.push((bytes.to_vec(), subject_spans, condition));
                }
            }
            if conditions
                .iter()
                .all(|condition| self.condition_is_held(condition))
            {
                break;
            }
            let Some(condition) = Condition::compose(conditions.iter()) else {
                break;
            };
            skipped.push(Self::negate_source_condition(&condition));
        }
        versions
    }

    fn negate_source_condition(condition: &Condition) -> Condition {
        match condition {
            Condition::Atom { atom }
                if atom.exhaustive
                    && atom.arms as usize <= effinterp_proto::MAX_CONDITION_NODES =>
            {
                let alternatives = (0..atom.arms)
                    .filter(|arm| *arm != atom.arm)
                    .map(|arm| {
                        let mut atom = atom.clone();
                        atom.arm = arm;
                        atom.polarity = atom.polarity.map(|positive| !positive);
                        Condition::atom(atom)
                    })
                    .collect::<Vec<_>>();
                Condition::disjoin(alternatives.iter()).unwrap_or(Condition::Widened)
            }
            Condition::All { conditions } => Condition::disjoin(
                conditions
                    .iter()
                    .map(Self::negate_source_condition)
                    .collect::<Vec<_>>()
                    .iter(),
            )
            .unwrap_or(Condition::Widened),
            Condition::Any { conditions } => Condition::compose(
                conditions
                    .iter()
                    .map(Self::negate_source_condition)
                    .collect::<Vec<_>>()
                    .iter(),
            )
            .unwrap_or(Condition::Widened),
            _ => Condition::Widened,
        }
    }

    fn source_condition_conflicts(condition: &Condition) -> bool {
        fn conjuncts<'a>(
            condition: &'a Condition,
            atoms: &mut Vec<&'a effinterp_proto::ConditionAtom>,
        ) {
            match condition {
                Condition::Atom { atom } => atoms.push(atom),
                Condition::All { conditions } => conditions
                    .iter()
                    .for_each(|condition| conjuncts(condition, atoms)),
                _ => {}
            }
        }
        let mut atoms = Vec::new();
        conjuncts(condition, &mut atoms);
        atoms.iter().enumerate().any(|(index, atom)| {
            atoms[..index]
                .iter()
                .any(|other| other.origin == atom.origin && other.arm != atom.arm)
        }) || match condition {
            Condition::All { conditions } => {
                conditions.iter().any(Self::source_condition_conflicts)
            }
            Condition::Any { conditions } => {
                conditions.iter().all(Self::source_condition_conflicts)
            }
            _ => false,
        }
    }

    fn condition_is_excluded(&self, required: &Condition) -> bool {
        let negated = Self::negate_source_condition(required);
        self.condition_is_held(&negated)
            || match required {
                Condition::All { conditions } => conditions
                    .iter()
                    .any(|condition| self.condition_is_excluded(condition)),
                Condition::Any { conditions } => conditions
                    .iter()
                    .all(|condition| self.condition_is_excluded(condition)),
                _ => false,
            }
    }

    /// A chmod or mode-carrying write after the last identity change. Only a
    /// plain content write can retain the host's initial mode or create a
    /// missing file without execute bits. Copies and broad chmod selections
    /// cannot establish non-executability from the host's earlier absence.
    pub(crate) fn written_executable_mode(
        &self,
        path: &str,
        proof: &mut Vec<ProvenanceRef>,
    ) -> Option<Option<bool>> {
        let named = self.entry_named_path(path);
        let path = named.as_deref().unwrap_or(path);
        fn reaches_resource(
            builder: &PlanBuilder,
            resource: &ResourceExpr,
            recursive: bool,
            path: &str,
        ) -> bool {
            match resource {
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path: target },
                } => {
                    let named = builder.entry_named_path(target);
                    let target = named.as_deref().unwrap_or(target);
                    target == path || recursive && written_path_reaches(target, path)
                }
                ResourceExpr::Union { alternatives } => alternatives
                    .iter()
                    .any(|resource| reaches_resource(builder, resource, recursive, path)),
                ResourceExpr::Pattern {
                    pattern: effinterp_proto::ResourcePattern::FsPath { glob, .. },
                } if !recursive => effinterp_proto::glob_match(glob, path).unwrap_or(true),
                resource => source_mutation_reaches(resource, path),
            }
        }
        let reaches = |effect: &Effect, path: &str| {
            reaches_resource(
                self,
                &effect.resource,
                effect.attributes.get("recursive") == Some(&AttrValue::Bool(true)),
                path,
            )
        };
        let mode_change = self.source_writes.iter().rev().find(|write| {
            source_mutation_reaches(&write.resource, path)
                && (write.changes_identity || !write.plain_content_write)
        });
        if mode_change.is_some_and(|write| write.effect.is_none()) {
            return Some(None);
        }
        let changed = mode_change
            .and_then(|write| write.effect)
            .map(|slot| slot as usize);
        let start = changed.unwrap_or(0);
        let alias_proof = |index: usize, effect: &Effect| {
            self.effects[..index].iter().find_map(|entry| {
                let ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path: name },
                } = &entry.resource
                else {
                    return None;
                };
                if entry.operation.as_str() != "filesystem.create" || !reaches(effect, name) {
                    return None;
                }
                // Recursive traversal skips symlinks inside a directory;
                // an explicitly named link is a different chmod operand.
                if effect.attributes.get("recursive") == Some(&AttrValue::Bool(true))
                    && entry.attributes.get("symlink") == Some(&AttrValue::Bool(true))
                    && effect.resource != entry.resource
                {
                    return None;
                }
                let mut target = entry.resource.clone();
                let nodes = self.follow_created_aliases_before(&mut target, index);
                (self.entry_named(&target).as_ref().unwrap_or(&target)
                    == &crate::value::fs_path_resource(path))
                    .then_some(nodes)
            })
        };
        let relevant = |(index, effect): &(usize, &Effect)| {
            effect.realm.is_host()
                && effect.operation.as_str() == "filesystem.metadata"
                && effect.attributes.get("action") == Some(&AttrValue::String("chmod".into()))
                && (reaches(effect, path) || alias_proof(*index, effect).is_some())
        };
        let Some((index, effect)) = self
            .effects
            .iter()
            .enumerate()
            .skip(start)
            .rev()
            .find(relevant)
        else {
            if let Some(write) = mode_change
                && write.resource == crate::value::fs_path_resource(path)
                && let Some(effect) = write.effect.map(|slot| &self.effects[slot as usize])
                && let Some(AttrValue::String(mode)) = effect.attributes.get("mode")
            {
                proof.extend(&effect.provenance);
                return Some(
                    effect
                        .condition
                        .as_ref()
                        .is_none_or(|condition| self.condition_is_held(condition))
                        .then(|| crate::models::executable_permission_mode(mode, false))
                        .flatten(),
                );
            }
            return mode_change.map(|_| None);
        };
        // Permission-grant annotations are additional views of the same chmod.
        // Its spec-bearing effect states the actual mode operation.
        let (index, effect) = self
            .effects
            .iter()
            .enumerate()
            .skip(start)
            .rev()
            .filter(relevant)
            .find(|(_, candidate)| {
                candidate.execution == effect.execution
                    && candidate.attributes.contains_key("spec")
                    && candidate.provenance.iter().any(|reference| {
                        effect.provenance.contains(reference)
                            && matches!(
                                self.provenance[reference.0 as usize].kind,
                                ProvenanceKind::ModelApplication { .. }
                            )
                    })
            })
            .unwrap_or((index, effect));
        proof.extend(&effect.provenance);
        proof.extend(alias_proof(index, effect).into_iter().flatten());
        if effect
            .condition
            .as_ref()
            .is_some_and(|condition| !self.condition_is_held(condition))
        {
            return Some(None);
        }
        let Some(AttrValue::String(spec)) = effect.attributes.get("spec") else {
            return Some(None);
        };
        if !matches!(
            &effect.resource,
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { .. }
            } | ResourceExpr::Pattern {
                pattern: effinterp_proto::ResourcePattern::FsPath { .. }
            }
        ) {
            return Some(None);
        }
        if let ResourceExpr::Pattern {
            pattern: effinterp_proto::ResourcePattern::FsPath { glob, .. },
        } = &effect.resource
            && effinterp_proto::glob_match(glob, path).is_err()
        {
            return Some(None);
        }
        Some(crate::models::executable_permission_mode(
            spec,
            effect.attributes.contains_key("execute_umask"),
        ))
    }

    /// The conditions the effects emitted now run under, as a later
    /// `conditions_held` reads them; none past the condition budget.
    pub(crate) fn held_conditions(&self) -> Option<Vec<Condition>> {
        (self.condition_overflow == 0).then(|| self.condition_stack.clone())
    }

    /// Whether every one of `conditions` holds wherever effects emitted now
    /// run.
    pub(crate) fn conditions_held(&self, conditions: &[Condition]) -> bool {
        conditions
            .iter()
            .all(|condition| self.condition_is_held(condition))
    }

    fn condition_is_held(&self, required: &Condition) -> bool {
        fn contains(current: &Condition, required: &Condition) -> bool {
            current == required
                || matches!(current, Condition::All { conditions }
                if conditions.iter().any(|current| contains(current, required)))
        }
        match required {
            Condition::All { conditions } => conditions
                .iter()
                .all(|required| self.condition_is_held(required)),
            Condition::Widened => false,
            _ => self
                .condition_stack
                .iter()
                .chain(&self.source_read_conditions)
                .any(|current| contains(current, required)),
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

    // A new script launch owns a separate module cache, even when it selects
    // a file already imported elsewhere.
    fn dependency_launch(&self, mut execution: ExecutionNodeRef) -> ExecutionNodeRef {
        loop {
            match &self.execution_nodes[execution.0 as usize].input {
                Some(input)
                    if input.role == effinterp_proto::ExecutionInputRole::DependencyRequest =>
                {
                    execution = input.requester;
                }
                None => {
                    let Some((requester, _)) = self.js_evaluations.get(&execution) else {
                        return execution;
                    };
                    execution = *requester;
                }
                Some(_) => return execution,
            }
        }
    }

    /// The launch whose dependency graph contains the current execution.
    pub(crate) fn current_dependency_launch(&self) -> ExecutionNodeRef {
        self.dependency_launch(self.current_execution())
    }

    /// Whether the launch running the current execution runs inline code
    /// (`node -e CODE`) rather than a selected file, so its argv holds no
    /// script after the interpreter.
    pub(crate) fn current_launch_is_inline(&self) -> bool {
        self.execution_nodes[self.current_dependency_launch().0 as usize]
            .input
            .is_none()
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

    pub(crate) fn prints_completion(&self) -> bool {
        self.execution_nodes[self.current_execution().0 as usize].prints_completion
    }

    /// Keep the invoking account only through executables known to preserve
    /// it. An unlisted wrapper may change accounts before its child expands
    /// a substitution; substitutions in the wrapper's caller expand first.
    /// A model can exclude its own execution to check its caller's account.
    pub(crate) fn preserves_invoking_identity(&self, excluding: Option<ExecutionNodeRef>) -> bool {
        let stack = self.execution_stack.as_slice();
        let stack = stack.strip_suffix(excluding.as_slice()).unwrap_or(stack);
        self.is_host_realm()
            && stack.iter().all(
                |node| match &self.execution_nodes[node.0 as usize].subject {
                    Subject::Exec { argv, .. } => argv.first().is_some_and(|name| {
                        matches!(
                            name.rsplit('/').next(),
                            Some(
                                "sh" | "bash"
                                    | "dash"
                                    | "zsh"
                                    | "ash"
                                    | "mksh"
                                    | "env"
                                    | "nice"
                                    | "timeout"
                                    | "xargs"
                                    | "command"
                                    | "exec"
                                    | "nohup"
                                    | "setsid"
                                    | "stdbuf"
                                    | "time"
                                    | "find"
                                    | "parallel"
                                    | "flock"
                                    | "prlimit"
                                    | "eatmydata"
                                    | "dbus-run-session"
                            )
                        )
                    }),
                    _ => true,
                },
            )
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

    /// Whether the current execution is source a launch runs: a selected
    /// input, code a launched process takes from its arguments or stdin
    /// (`node -e CODE`), or a dependency one of those loaded.
    pub(crate) fn current_execution_is_launched_source(&self) -> bool {
        let reference = self.current_dependency_launch();
        self.execution_nodes[reference.0 as usize].input.is_some()
            || self
                .execution_stack
                .iter()
                .rposition(|node| *node == reference)
                .and_then(|position| position.checked_sub(1))
                .is_some_and(|parent| {
                    matches!(
                        self.execution_nodes[self.execution_stack[parent].0 as usize].subject,
                        Subject::Exec { .. }
                    )
                })
    }

    pub(crate) fn current_execution(&self) -> ExecutionNodeRef {
        self.execution_stack.last().copied().unwrap_or_default()
    }

    pub(crate) fn record_js_evaluation(
        &mut self,
        execution: ExecutionNodeRef,
        require_shadowed: bool,
    ) {
        self.js_evaluations
            .insert(execution, (self.current_execution(), require_shadowed));
    }

    pub(crate) fn js_eval_require_shadowed(&self) -> bool {
        self.js_evaluations
            .get(&self.current_execution())
            .is_some_and(|(_, shadowed)| *shadowed)
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
        self.execution_source_authorship
            .push(SourceAuthorship::External);
        Some(reference)
    }

    pub(crate) fn set_source_authorship(
        &mut self,
        node: ExecutionNodeRef,
        authorship: SourceAuthorship,
    ) {
        self.execution_source_authorship[node.0 as usize] = authorship;
    }

    /// Follow the lexical scope of the command. A function body can run in a
    /// different execution from the one that supplied its definition.
    pub(crate) fn source_from_subject(&self, mut scope: Option<ProvenanceRef>) -> bool {
        let mut span = None;
        while let Some(reference) = scope {
            let Some(node) = self.provenance.get(reference.0 as usize) else {
                return false;
            };
            match node.kind {
                ProvenanceKind::SourceSpan { start, end } if span.is_none() => {
                    span = Some(ByteSpan { start, end });
                }
                ProvenanceKind::Execution { node } => {
                    return match &self.execution_source_authorship[node as usize] {
                        SourceAuthorship::Subject => true,
                        SourceAuthorship::External => false,
                        SourceAuthorship::Mixed(ranges) => span.is_some_and(|span| {
                            span.start < span.end
                                && ranges
                                    .iter()
                                    .any(|range| range.start <= span.start && span.end <= range.end)
                        }),
                    };
                }
                _ => {}
            }
            scope = node.antecedents.first().copied();
        }
        self.execution_source_authorship[0].is_subject()
    }

    pub(crate) fn mark_request_computation(&mut self, source: ProvenanceRef) -> bool {
        if self.source_from_subject(Some(source))
            && matches!(self.provenance[source.0 as usize].kind,
                ProvenanceKind::SourceSpan { start, end } if start < end)
        {
            self.request_computations.insert(source);
            true
        } else {
            false
        }
    }

    /// Follow only value antecedents. The execution that received an argument
    /// or environment binding also holds unrelated input and is not part of
    /// that value's proof.
    pub(crate) fn request_computation(&self, roots: &[ProvenanceRef]) -> Option<ProvenanceRef> {
        if self.request_computations.is_empty() || roots.is_empty() {
            return None;
        }
        let mut pending = roots.to_vec();
        let mut seen = BTreeSet::new();
        while let Some(reference) = pending.pop() {
            if self.request_computations.contains(&reference) {
                return Some(reference);
            }
            if seen.insert(reference)
                && let Some(node) = self.provenance.get(reference.0 as usize)
                && matches!(
                    node.kind,
                    ProvenanceKind::Argument { .. } | ProvenanceKind::SourceSpan { .. }
                )
            {
                pending.extend(&node.antecedents);
            }
        }
        None
    }

    /// Whether a node `given` selects supplied the process nearest to
    /// `roots`: antecedents are followed from each root up to the first
    /// execution and no further, so a process that process started is not
    /// reached. The words its command expanded are that execution's own
    /// antecedents or those of its argument nodes.
    pub(crate) fn nearest_execution_given(
        &self,
        roots: &[ProvenanceRef],
        given: impl Fn(&ProvenanceNode) -> bool,
    ) -> bool {
        let given_any = |antecedents: &[ProvenanceRef]| {
            antecedents.iter().any(|antecedent| {
                self.provenance
                    .get(antecedent.0 as usize)
                    .is_some_and(&given)
            })
        };
        let mut pending = roots.to_vec();
        let mut seen = BTreeSet::new();
        while let Some(reference) = pending.pop() {
            let Some(node) = self.provenance.get(reference.0 as usize) else {
                continue;
            };
            if !seen.insert(reference) {
                continue;
            }
            if given(node) {
                return true;
            }
            if matches!(node.kind, ProvenanceKind::Execution { .. }) {
                if given_any(&node.antecedents)
                    || self.provenance.iter().any(|argument| {
                        matches!(argument.kind, ProvenanceKind::Argument { .. })
                            && argument.antecedents.contains(&reference)
                            && given_any(&argument.antecedents)
                    })
                {
                    return true;
                }
                continue;
            }
            pending.extend(&node.antecedents);
        }
        false
    }

    pub(crate) fn computed_command_attributes(
        &mut self,
        from_subject: bool,
        site: ProvenanceRef,
    ) -> BTreeMap<String, AttrValue> {
        if !from_subject {
            self.boundary_in_domain(
                Boundary {
                    reason: BoundaryReason::UNRESOLVED_COMMAND,
                    class: BoundaryClass::Unresolved,
                    scope: BoundaryScope::Invocation,
                    affected_resource: None,
                    callee: None,
                    domains: vec![Domain::new("process")],
                    provenance: vec![site],
                    limit: None,
                    detail: Some(
                        "program or code computed without proven request authorship".into(),
                    ),
                },
                "process",
            );
        }
        [
            (
                "derivation".into(),
                AttrValue::String("unresolved_command".into()),
            ),
            ("source_from_subject".into(), AttrValue::Bool(from_subject)),
        ]
        .into_iter()
        .collect()
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
                && node.prints_completion == candidate.prints_completion
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
        let from = self.current_execution();
        if !cycle {
            self.execution_launchers.entry(to).or_default().push(from);
        }
        self.execution_edges.push(ExecutionEdge {
            from,
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

    /// Record that the command model being applied consumes its standard
    /// input as program input.
    pub(crate) fn note_stdin_consumed(&mut self) {
        self.stdin_consumers.push(self.effects.len());
    }

    /// Whether a model applied after effect `start` and up to `end`, one
    /// stage's range, consumes standard input.
    pub(crate) fn stdin_consumed_within(&self, start: u32, end: u32) -> bool {
        self.stdin_consumers
            .iter()
            .any(|at| (start as usize) < *at && *at <= end as usize)
    }

    pub fn effects_len(&self) -> usize {
        self.effects.len()
    }

    /// An effect every arm of an exhaustive choice states alike, under the
    /// same conditions of its own, takes place whichever arm runs: drop the
    /// choice's atom, which `choice` recognizes, from the first arm's copy of
    /// each such effect, keeping what the arm adds inside it. The other arms'
    /// copies keep the atom, so resource states still never chain from one
    /// arm into a sibling arm.
    pub(crate) fn establish_agreed_effects(
        &mut self,
        arms: &[std::ops::Range<usize>],
        choice: impl Fn(&effinterp_proto::ConditionAtom) -> bool,
    ) {
        let Some(first) = arms.first() else {
            return;
        };
        let outside =
            |condition: &&Condition| !matches!(condition, Condition::Atom { atom } if choice(atom));
        let without_choice = |condition: &Option<Condition>| match condition {
            Some(Condition::All { conditions }) => {
                Condition::compose(conditions.iter().filter(outside))
            }
            Some(single) => Condition::compose(std::iter::once(single).filter(outside)),
            None => None,
        };
        // What an arm adds is compared as the source construct that states
        // it: each arm runs as an execution of its own, which numbers the
        // same construct apart.
        fn construct(condition: &Condition) -> Condition {
            match condition {
                Condition::Atom { atom } => {
                    let mut atom = atom.clone();
                    atom.origin.ordinal = 0;
                    atom.origin.call_instance = None;
                    Condition::Atom { atom }
                }
                Condition::All { conditions } => Condition::All {
                    conditions: conditions.iter().map(construct).collect(),
                },
                Condition::Any { conditions } => Condition::Any {
                    conditions: conditions.iter().map(construct).collect(),
                },
                Condition::Widened => Condition::Widened,
            }
        }
        let alike = |a: &Effect, b: &Effect| {
            a.operation == b.operation
                && a.resource == b.resource
                && a.attributes == b.attributes
                && a.modality == b.modality
                && a.realm == b.realm
                && without_choice(&a.condition).as_ref().map(construct)
                    == without_choice(&b.condition).as_ref().map(construct)
        };
        let agreed = first
            .clone()
            .filter(|&index| {
                arms.iter().all(|arm| {
                    arm.clone()
                        .any(|other| alike(&self.effects[index], &self.effects[other]))
                })
            })
            .collect::<Vec<_>>();
        for index in agreed {
            self.effects[index].condition = without_choice(&self.effects[index].condition);
        }
    }

    pub(crate) fn boundaries_len(&self) -> usize {
        self.boundaries.len()
    }

    pub(crate) fn boundary_at(&self, index: usize) -> Option<&Boundary> {
        self.boundaries.get(index)
    }

    /// Drop the boundaries from `start` on that `drop` selects, unless an
    /// execution refers to one of them, since that would shift its ref. A
    /// dropped boundary must repeat one kept, whose coverage it shares.
    pub(crate) fn drop_boundaries_from(&mut self, start: usize, drop: impl Fn(&Boundary) -> bool) {
        if self.execution_nodes.iter().any(|node| {
            node.boundary
                .is_some_and(|boundary| boundary.0 as usize >= start)
        }) {
            return;
        }
        let mut position = 0;
        self.boundaries.retain(|boundary| {
            let keep = position < start || !drop(boundary);
            position += 1;
            keep
        });
    }

    /// The operation string of an emitted effect, for the flow builder to bind
    /// a stage's effects to its ports (e.g. cat's `filesystem.read` → stdout).
    pub fn effect_operation(&self, index: usize) -> Option<&str> {
        self.effects.get(index).map(|e| e.operation.0.as_str())
    }

    pub(crate) fn effect_resource(&self, index: usize) -> Option<&ResourceExpr> {
        self.effects.get(index).map(|effect| &effect.resource)
    }

    pub(crate) fn effect_at(&self, index: usize) -> Option<&Effect> {
        self.effects.get(index)
    }

    /// Whether the effect at `index` is on `resource` as a command spelled
    /// it: the effect carries the name of the path's entry
    /// ([`Self::entry_named_path`]), which differs from the spelling beneath
    /// a linked directory.
    pub(crate) fn effect_is_on(&self, index: usize, resource: &ResourceExpr) -> bool {
        let Some(recorded) = self.effect_resource(index) else {
            return false;
        };
        recorded == resource || self.entry_named(resource).as_ref() == Some(recorded)
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

    /// Whether two effects name the same argument of the same invocation and
    /// share all other provenance. A filesystem argument also records the cwd
    /// that anchored it; that ancestry does not make it a different selector.
    pub(crate) fn effects_share_argument(&self, left: usize, right: usize) -> bool {
        let left = &self.effects[left];
        let right = &self.effects[right];
        left.execution == right.execution
            && left.provenance.len() == right.provenance.len()
            && left.provenance.iter().zip(&right.provenance).all(|(a, b)| {
                a == b
                    || matches!(
                        (&self.provenance[a.0 as usize].kind, &self.provenance[b.0 as usize].kind),
                        (ProvenanceKind::Argument { index: a }, ProvenanceKind::Argument { index: b })
                            if a == b
                    ) && self.argument_owner(*a).is_some_and(|owner| {
                        self.argument_owner(*b) == Some(owner)
                    })
            })
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
                // The runtime names its shell; an unestablished one may
                // read the source with other rules.
                Subject::Shell { context, .. } if depth == 0 => {
                    return match context.shell {
                        effinterp_proto::CommandShell::Bash => ScriptInterpreter::Root,
                        effinterp_proto::CommandShell::Zsh => ScriptInterpreter::Program("zsh"),
                        effinterp_proto::CommandShell::Unknown => ScriptInterpreter::Unresolved,
                    };
                }
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

    /// Whether `candidate` is `root` or was launched beneath it. The search
    /// climbs from `candidate` through its launchers, which are few, rather
    /// than down from `root`, which may have launched thousands: a pipeline
    /// stage asks this of every effect it holds.
    pub(crate) fn execution_is_within(
        &self,
        root: ExecutionNodeRef,
        candidate: ExecutionNodeRef,
    ) -> bool {
        let mut pending = vec![candidate];
        let mut seen = BTreeSet::new();
        while let Some(node) = pending.pop() {
            if node == root {
                return true;
            }
            if !seen.insert(node) {
                continue;
            }
            let launchers = self
                .execution_launchers
                .get(&node)
                .map_or(&[][..], Vec::as_slice);
            self.budget
                .note_execution_edges_examined(launchers.len() as u64);
            pending.extend(launchers);
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

    /// Record that the process the current code runs in writes exactly
    /// `text` to its stdout. The text belongs to the nearest launched
    /// process on the execution stack, whose stdout a pipe or a command
    /// substitution reads, not to the source node the frontend walks.
    pub(crate) fn record_printed_text(&mut self, text: String) {
        let Some(process) = self.execution_stack.iter().rev().copied().find(|node| {
            matches!(
                self.execution_nodes[node.0 as usize].subject,
                Subject::Exec { .. }
            )
        }) else {
            return;
        };
        self.printed_texts.push((process, text));
    }

    /// The exact text the process `execution` writes to its stdout.
    pub(crate) fn printed_text(&self, execution: ExecutionNodeRef) -> Option<&str> {
        self.printed_texts
            .iter()
            .find_map(|(owner, text)| (*owner == execution).then_some(text.as_str()))
    }

    /// The exact text the one process within `root` that recorded its
    /// stdout writes, when exactly one did.
    pub(crate) fn printed_text_within(&self, root: ExecutionNodeRef) -> Option<&str> {
        let mut within = self
            .printed_texts
            .iter()
            .filter(|(owner, _)| self.execution_is_within(root, *owner));
        let (_, text) = within.next()?;
        within.next().is_none().then_some(text.as_str())
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
    /// The analyzed subject itself, which the runtime runs in bash.
    Root,
    /// A program by basename.
    Program(&'a str),
    /// A nested script with no evidence of its interpreter.
    Unknown,
    /// A language runtime's shell selected by a value Nah cannot recover,
    /// or the analyzed subject's when its runtime may run another than bash.
    Unresolved,
}

/// The shell a language runtime selected to run a command string, or the
/// interpreter a launched script's first line names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RuntimeShell {
    /// A literal program: the default `/bin/sh`, or an override such as
    /// Node's `{shell: '/bin/bash'}` or Python's `executable='/bin/bash'`,
    /// or a script's `#!/bin/zsh`.
    Program(String),
    /// An override whose value is not a literal.
    Unresolved,
}
