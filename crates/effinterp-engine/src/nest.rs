//! Execution-graph infrastructure shared by every frontend and model.
//!
//! A single [`Budget`] bounds total nested work across the whole analysis
//! tree — a model spawning `sh -c`, a shell command substitution, and a
//! subprocess all draw from one pool — so recursion is bounded by depth and
//! total work as the design requires. Every transition that cannot be
//! recovered becomes a typed execution node plus an opaque boundary, never a
//! silently dropped effect.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, BoundaryRef, BoundaryScope, ContainerStorage,
    CoverageLevel, Domain, ExecutionAssurance, ExecutionEdgeKind, ExecutionNode, ExecutionNodeRef,
    ExecutionRealm, ExecutionStreamValue, ExecutionStreams, HostContext, ProvenanceKind,
    ProvenanceRef, ResourceExpr, Subject,
};

use effinterp_proto::{ObservationOutcome, ObservationQuery, ObservationRefusal, PathKind};

use crate::builder::{KNOWN_DOMAINS, PlanBuilder, RuntimeShell, SourceAuthorship};
use crate::limits::AnalysisLimits;
use crate::models::{Catalog, StdinValue};
use crate::shell::captured_file::{CapturedFile, CapturedOperands};
use crate::value::unresolved_resource;
use crate::word::Word;
use crate::{
    SourceNamespace, SourcePurpose, SourceRefusal, SourceRequest, SourceResolver, SourceResponse,
};

pub(crate) mod dependency_sources;

/// Debit `steps` of shared analysis work (a frontend AST node, a value-tree
/// walk). False means the whole-analysis step budget is spent: the caller
/// takes its own cap-exhausted path, and the boundary recorded names
/// `max_analysis_steps` rather than the frontend's private node cap.
pub(crate) fn charge_analysis_steps(
    builder: &mut PlanBuilder,
    budget: &Budget,
    steps: u64,
    span: Option<(u32, u32)>,
) -> bool {
    if budget.try_charge_steps(steps) {
        return true;
    }
    builder.note_saturated_at("max_analysis_steps", span);
    false
}

/// Refusal records the shared byte limit; callers stop retaining state and unwind.
pub(crate) fn charge_analysis_bytes(
    builder: &mut PlanBuilder,
    budget: &Budget,
    bytes: u64,
    span: Option<(u32, u32)>,
) -> bool {
    if budget.try_charge_bytes(bytes) {
        return true;
    }
    builder.note_saturated_at("max_analysis_bytes", span);
    false
}

/// Accounted bytes one retained observation costs, under the same fixed
/// schedule the effect meter uses: every retained string costs its length and
/// every node costs [`crate::limits::NODE_BYTES`].
fn observation_retained_bytes(path: &str, outcome: &ObservationOutcome) -> u64 {
    let answer = match outcome {
        ObservationOutcome::Refused(_) => 0,
        ObservationOutcome::Listing(fact) => {
            fact.directory.len() as u64
                + fact
                    .entries
                    .iter()
                    .map(|entry| crate::limits::NODE_BYTES + entry.path.len() as u64)
                    .sum::<u64>()
        }
        ObservationOutcome::Path(fact) => {
            fact.entry.len() as u64
                + fact
                    .followed
                    .known()
                    .map_or(0, |target| target.path.len() as u64)
        }
    };
    crate::limits::NODE_BYTES * 3 + path.len() as u64 + answer
}

/// Degrade every known domain to partial: a lost nested transition could
/// affect any of them, so none may read as safe by being absent.
pub(crate) fn degrade_nested(builder: &mut PlanBuilder) {
    builder.global_opacity(CoverageLevel::Partial);
}

/// Outcome of charging one execution node against the budget.
pub(crate) enum Charge {
    Ok,
    /// The innermost fair-share window is spent; the global budget is not.
    Starved,
    /// The configured execution-node budget is spent.
    Saturated,
    /// The whole-analysis step budget is spent.
    StepsSaturated,
}

/// Saved budget state around a fair-share window; restored by
/// [`Budget::pop_window`].
pub(crate) struct Window {
    cap: u64,
    starved: bool,
}

/// The filesystem facts as a region found them on entry, before the writes
/// its probe discovered were noted.
pub(crate) struct RegionEntryFilesystem(FilesystemState);

/// What the probe of a pipeline or job noted, sorted by lane: the stage of
/// the region's pipeline at `depth` that noted it, or `None` for a change no
/// stage made, which every lane meets ([`Budget::begin_lane_probe`]).
pub(crate) struct LaneChanges {
    depth: Option<usize>,
    lanes: BTreeMap<Option<usize>, FilesystemState>,
}

/// A pipeline walked for real after its probe: each stage meets what its
/// peers may change while it runs, and its own changes only in the order it
/// makes them ([`Budget::enter_pipeline_lanes`]).
struct LaneRegion {
    /// The stage depth the pipeline numbers its stages at.
    depth: usize,
    entry: FilesystemState,
    lanes: BTreeMap<Option<usize>, FilesystemState>,
    /// What the probe noted for every stage; it holds outside the stages.
    probed: FilesystemState,
    /// What the real walk noted since the pipeline began.
    walked: FilesystemState,
}

/// Leaves the pipeline's lanes when dropped, whichever way its walk ends.
pub(crate) struct PipelineLanes<'a>(&'a Budget);

impl Drop for PipelineLanes<'_> {
    fn drop(&mut self) {
        self.0.lane_regions.borrow_mut().pop();
    }
}

/// What a modeled change does to the topology at its path
/// ([`Budget::note_topology_mutation`]).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum TopologyChange {
    /// A plain directory creation, as `mkdir` makes.
    CreatesDirectory,
    /// A removal, as `rm` makes.
    Removes,
    /// Any other creation, a rename or a link.
    Other,
}

/// Filesystem facts invalidated by the work the current walk has modeled.
#[derive(Clone, Default)]
struct FilesystemState {
    /// Concrete paths whose own entry a modeled operation already created,
    /// renamed, or removed. A later identity that passes through one of them
    /// can no longer rely on the initial observation.
    topology_mutations: BTreeSet<String>,
    /// The changed paths whose only change is a plain directory creation, as
    /// `mkdir` makes: nothing but the new, empty directory is there, so a
    /// path beneath it is resolved through it. A created link or a directory
    /// moved in can lead anywhere and is never one of these.
    created_directories: BTreeSet<String>,
    /// The changed paths whose only change is a removal, as `rm` makes: what
    /// was there is gone or, where the removal fails, still as the host
    /// listed it, and nothing new is there.
    removed_entries: BTreeSet<String>,
    /// A modeled topology change the analysis could not pin to one path.
    topology_unknown: bool,
    /// Concrete paths a modeled write reached. A write can create the entry
    /// it names, so a directory above one no longer holds what its initial
    /// listing says. Path facts keep their own rule: a write to an existing
    /// entry leaves its identity as observed.
    written_paths: BTreeSet<String>,
    /// A modeled write the analysis could not pin to one path.
    written_unknown: bool,
    /// How many steps the analysis could not model on the host filesystem;
    /// any of them may have written anywhere.
    unmodeled_steps: usize,
}

impl FilesystemState {
    /// Also count as changed what `other` noted changed, so neither state's
    /// initial observations are trusted where the other's work reached.
    fn absorb(&mut self, other: FilesystemState) {
        // A path stays a plain created directory only where every state that
        // changed it changed it that way.
        let created_only = |state: &FilesystemState, path: &String| {
            !state.topology_mutations.contains(path) || state.created_directories.contains(path)
        };
        self.created_directories = self
            .created_directories
            .union(&other.created_directories)
            .filter(|path| created_only(self, path) && created_only(&other, path))
            .cloned()
            .collect();
        let removed_only = |state: &FilesystemState, path: &String| {
            !state.topology_mutations.contains(path) || state.removed_entries.contains(path)
        };
        self.removed_entries = self
            .removed_entries
            .union(&other.removed_entries)
            .filter(|path| removed_only(self, path) && removed_only(&other, path))
            .cloned()
            .collect();
        self.topology_mutations.extend(other.topology_mutations);
        self.topology_unknown |= other.topology_unknown;
        self.written_paths.extend(other.written_paths);
        self.written_unknown |= other.written_unknown;
        self.unmodeled_steps = self.unmodeled_steps.max(other.unmodeled_steps);
    }
}

/// Interior-mutable counters spanning the whole nested analysis tree. Passed
/// by shared reference so models holding `&InvocationCtx` can still charge it.
///
/// Independent branches (case arms) each analyze under a fair-share window:
/// a temporary cap granting an equal slice of the remaining budget, so an
/// early branch cannot starve a later one and semantically equivalent
/// reordering of branches yields the same analysis.
pub(crate) struct Budget {
    pub(crate) cancel: Option<Arc<AtomicBool>>,
    pub(crate) deadline: Option<crate::InvocationDeadline>,
    /// Lazy host facts about initial state. None: the engine asks nothing and
    /// draws no observation-backed conclusion.
    pub(crate) observations: Option<Arc<dyn crate::ObservationResolver>>,
    /// Answers already obtained, keyed by the exact query. The host context is
    /// the subject's and the engine demands only in the host realm, so the
    /// query is the whole key. Initial-state evidence, never future state.
    observation_facts: RefCell<BTreeMap<ObservationQuery, effinterp_proto::ObservationOutcome>>,
    observation_requests: Cell<u64>,
    max_observation_requests: u64,
    /// Requests spent naming effects ([`Self::observe_directory_for_naming`]),
    /// counted apart under the same bound. A name is optional evidence, so
    /// asking for one never takes a request from the observations that
    /// establish what a read reaches.
    naming_requests: Cell<u64>,
    /// Set when a naming request was refused for want of that allowance,
    /// until [`Self::take_naming_refused`] reports it.
    naming_refused: Cell<bool>,
    filesystem: RefCell<FilesystemState>,
    /// Each active job accumulates its real mutations against its entry state,
    /// excluding the future writes temporarily visible while that job runs.
    background_filesystems: RefCell<Vec<FilesystemState>>,
    /// The pipeline stage the walk is in at each depth, as the plan builder
    /// numbers them.
    stages: RefCell<Vec<usize>>,
    /// The probe sorting what it notes by lane, if one is running.
    lane_probe: RefCell<Option<LaneChanges>>,
    /// The pipelines being walked for real after their probes, innermost last.
    lane_regions: RefCell<Vec<LaneRegion>>,
    /// What the launching shell holds open on a descriptor, beside the
    /// operand the program being launched names it with (`/dev/fd/3`): what
    /// that program reads when it opens the operand as a file.
    descriptor_sources: RefCell<Vec<(Word, Word)>>,
    captured_operands: RefCell<CapturedOperands>,
    cancelled: Cell<bool>,
    finalizing: Cell<bool>,
    nodes: Cell<u64>,
    heredoc_expansions: Cell<u64>,
    /// Deterministic work units spent by the whole analysis, and the accounted
    /// bytes it retained. Both use a global pool outside fair-share windows.
    /// Speculative work stays charged; dropped guard evidence and discarded
    /// effects release their bytes, including prepaid finalization scratch.
    steps: Cell<u64>,
    retained_bytes: Cell<u64>,
    /// Binding entries walked by whole-environment state scans. Counted, never
    /// refused: it measures how state comparisons scale, not a budget.
    state_scan_entries: Cell<u64>,
    /// Execution edges `PlanBuilder::execution_is_within` examined. Counted,
    /// never refused: it shows whether asking which launches sit under a
    /// root stays proportional to how deep they sit, not to how much the
    /// root launched.
    execution_edges_examined: Cell<u64>,
    max_analysis_steps: u64,
    max_analysis_bytes: u64,
    /// The shell segment being walked, if any.
    segment: Cell<Option<ShellSegment>>,
    /// Pool usage of the segments already walked and of the work before them.
    pool_steps: Cell<u64>,
    pool_bytes: Cell<u64>,
    /// What segments may still be granted beyond the pools, in total.
    reserve_steps: Cell<u64>,
    reserve_bytes: Cell<u64>,
    /// What nested segments may still be granted, within the reserve.
    nested_reserve_steps: Cell<u64>,
    nested_reserve_bytes: Cell<u64>,
    /// Every list item that has begun a segment, by its source and offset,
    /// so a list walked again (a loop body, a function called twice, the
    /// same `eval` text) draws no second grant for the same item.
    segment_items: RefCell<BTreeSet<(std::rc::Rc<str>, u32)>>,
    /// The item that began a segment last.
    segment_item: RefCell<Option<(std::rc::Rc<str>, u32)>>,
    /// Segments that ran out of room. Past `MAX_SATURATED_SEGMENTS` no
    /// segment is granted anything more.
    saturated_segments: Cell<u32>,
    max_heredoc_expansions: u64,
    steps_saturated: Cell<bool>,
    bytes_saturated: Cell<bool>,
    /// Configured execution-node budget.
    limit: u64,
    /// Effective cap on `nodes`: `limit`, lowered inside a window.
    cap: Cell<u64>,
    nodes_saturated: Cell<bool>,
    depth_saturated: Cell<bool>,
    function_depth_saturated: Cell<bool>,
    function_depth_refusals: Cell<u64>,
    /// Whether one remaining source region has explained execution starvation.
    starved_region_recorded: Cell<bool>,
    /// The innermost window has refused a charge.
    window_starved: Cell<bool>,
    /// A speculative demand-measuring walk is in progress (case arm dry
    /// runs). Inner case constructs then walk their arms sequentially instead
    /// of measuring again, which keeps nested cases linear-time.
    measuring: Cell<bool>,
    /// Path observations made inside [`Self::through_removals`].
    removals_kept: Cell<bool>,
}

/// The share of the step and retained-byte limits each top-level shell
/// segment after the first may spend before drawing on the shared pools, so
/// a costly segment cannot starve a later one and cheap padding never drains
/// the pools. At the default limits a segment gets 1024 steps and 64 KiB,
/// which covers a single dangerous command many times over (`rm -rf ~` takes
/// 29 steps and about 19 KiB); `echo y` takes 8 steps and about 80 bytes.
const SEGMENT_STEPS_DIVISOR: u64 = 32;
const SEGMENT_BYTES_DIVISOR: u64 = 512;
/// All segments together are granted at most this many times the step limit
/// and the byte limit, so a whole analysis stays within a fixed bound: about
/// a million steps and 64 MiB at the defaults. That fits the 1 MiB tool input
/// the bridge admits as cheap padding: 104 837 `echo y && ` segments take
/// about 840 000 steps and 8 MiB.
const RESERVE_STEPS_FACTOR: u64 = 32;
const RESERVE_BYTES_FACTOR: u64 = 1;
/// Nested segments, the items of a group, branch, loop, function body or
/// nested shell, share a smaller part of that reserve, an eighth of the step
/// and byte limits: enough for a deletion after a few costly prefixes, while
/// a long script whose commands all sit in functions does not spend the
/// whole reserve walking them.
const NESTED_RESERVE_STEPS_DIVISOR: u64 = 8;
const NESTED_RESERVE_BYTES_DIVISOR: u64 = 8;
/// A segment that runs out of room is refused a charge before it spends its
/// grant, and it may already have done work the budget does not meter (a
/// word expansion, an interpreter parse). Work a segment's own text pays for
/// stays proportional to the input, so a segment at least as long as its
/// step grant may saturate freely. A shorter one that saturates is doing work
/// its text does not pay for, such as expanding an earlier value or calling
/// a function again; granting every later segment again would repeat that
/// work once per segment, so only this many may saturate.
const MAX_SATURATED_SEGMENTS: u32 = 32;

/// A shell segment: one item of a shell list, such as a `;`-separated
/// command, a `&&` operand or a pipeline stage, at any depth: in the analyzed
/// command's own list or nested in a group, subshell, branch, loop, function
/// body, `sh -c`, `eval` or heredoc. It records the steps and retained bytes
/// when it began, what it was granted beyond the pools, and whether its own
/// text pays for saturating them.
#[derive(Clone, Copy)]
struct ShellSegment {
    steps: u64,
    bytes: u64,
    grant_steps: u64,
    grant_bytes: u64,
    paid: bool,
    nested: bool,
}

/// Execution allowances and filesystem state saved around a speculative
/// walk. Analysis work stays charged when [`Budget::restore`] restores them.
pub(crate) struct BudgetSnapshot {
    nodes: u64,
    heredoc_expansions: u64,
    cap: u64,
    nodes_saturated: bool,
    depth_saturated: bool,
    function_depth_saturated: bool,
    function_depth_refusals: u64,
    starved_region_recorded: bool,
    window_starved: bool,
    filesystem: FilesystemState,
}

impl Budget {
    pub(crate) fn new(limits: &AnalysisLimits) -> Self {
        let max = limits.max_execution_nodes;
        Self {
            nodes: Cell::new(0),
            heredoc_expansions: Cell::new(0),
            cancel: None,
            deadline: None,
            observations: None,
            observation_facts: RefCell::new(BTreeMap::new()),
            observation_requests: Cell::new(0),
            max_observation_requests: limits.max_observation_requests,
            naming_requests: Cell::new(0),
            naming_refused: Cell::new(false),
            filesystem: RefCell::default(),
            background_filesystems: RefCell::default(),
            stages: RefCell::default(),
            lane_probe: RefCell::default(),
            lane_regions: RefCell::default(),
            descriptor_sources: RefCell::new(Vec::new()),
            captured_operands: RefCell::default(),
            cancelled: Cell::new(false),
            finalizing: Cell::new(false),
            steps: Cell::new(0),
            retained_bytes: Cell::new(0),
            state_scan_entries: Cell::new(0),
            execution_edges_examined: Cell::new(0),
            max_analysis_steps: limits.max_analysis_steps,
            max_analysis_bytes: limits.max_analysis_bytes,
            segment: Cell::new(None),
            pool_steps: Cell::new(0),
            pool_bytes: Cell::new(0),
            reserve_steps: Cell::new(
                limits
                    .max_analysis_steps
                    .saturating_mul(RESERVE_STEPS_FACTOR),
            ),
            reserve_bytes: Cell::new(
                limits
                    .max_analysis_bytes
                    .saturating_mul(RESERVE_BYTES_FACTOR),
            ),
            nested_reserve_steps: Cell::new(
                limits.max_analysis_steps / NESTED_RESERVE_STEPS_DIVISOR,
            ),
            nested_reserve_bytes: Cell::new(
                limits.max_analysis_bytes / NESTED_RESERVE_BYTES_DIVISOR,
            ),
            segment_items: RefCell::new(BTreeSet::new()),
            segment_item: RefCell::new(None),
            saturated_segments: Cell::new(0),
            max_heredoc_expansions: limits.max_heredoc_expansions,
            steps_saturated: Cell::new(false),
            bytes_saturated: Cell::new(false),
            limit: max,
            cap: Cell::new(max),
            nodes_saturated: Cell::new(false),
            depth_saturated: Cell::new(false),
            function_depth_saturated: Cell::new(false),
            function_depth_refusals: Cell::new(0),
            starved_region_recorded: Cell::new(false),
            window_starved: Cell::new(false),
            measuring: Cell::new(false),
            removals_kept: Cell::new(false),
        }
    }

    pub(crate) fn snapshot(&self) -> BudgetSnapshot {
        BudgetSnapshot {
            nodes: self.nodes.get(),
            heredoc_expansions: self.heredoc_expansions.get(),
            cap: self.cap.get(),
            nodes_saturated: self.nodes_saturated.get(),
            depth_saturated: self.depth_saturated.get(),
            function_depth_saturated: self.function_depth_saturated.get(),
            function_depth_refusals: self.function_depth_refusals.get(),
            starved_region_recorded: self.starved_region_recorded.get(),
            window_starved: self.window_starved.get(),
            filesystem: self.filesystem.borrow().clone(),
        }
    }

    /// Invocations charged since `snap` was taken.
    pub(crate) fn consumed_since(&self, snap: &BudgetSnapshot) -> u64 {
        self.nodes.get() - snap.nodes
    }

    /// Restore filesystem state only for ordered or exclusive probes. A
    /// racing probe's mutations must still invalidate initial observations.
    pub(crate) fn restore(&self, snap: BudgetSnapshot, restore_filesystem: bool) {
        self.nodes.set(snap.nodes);
        self.heredoc_expansions.set(snap.heredoc_expansions);
        self.cap.set(snap.cap);
        self.nodes_saturated.set(snap.nodes_saturated);
        self.depth_saturated.set(snap.depth_saturated);
        self.function_depth_saturated
            .set(snap.function_depth_saturated);
        self.function_depth_refusals
            .set(snap.function_depth_refusals);
        self.starved_region_recorded
            .set(snap.starved_region_recorded);
        self.window_starved.set(snap.window_starved);
        if restore_filesystem {
            self.filesystem.replace(snap.filesystem);
        }
    }

    pub(crate) fn region_entry_filesystem(&self) -> RegionEntryFilesystem {
        RegionEntryFilesystem(self.filesystem.borrow().clone())
    }

    /// Answer `question` against the filesystem facts a region began with.
    pub(crate) fn at_region_entry<T>(
        &self,
        entry: &RegionEntryFilesystem,
        question: impl FnOnce() -> T,
    ) -> T {
        let current = self.filesystem.replace(entry.0.clone());
        let answer = question();
        self.filesystem.replace(current);
        answer
    }

    /// Run `walk` from the filesystem facts a region began with, for a walk
    /// that meets the region's writes in the order they run, as a loop
    /// walked once per iteration does. The region's probe noted the writes of
    /// every iteration, and an iteration must not meet those of the
    /// iterations after it. What the probe noted holds again afterwards,
    /// beside what the walk noted, for the commands after the region.
    pub(crate) fn walk_from_region_entry<T>(
        &self,
        entry: &RegionEntryFilesystem,
        walk: impl FnOnce() -> T,
    ) -> T {
        let probed = self.filesystem.replace(entry.0.clone());
        let walked = walk();
        self.filesystem.borrow_mut().absorb(probed);
        walked
    }

    pub(crate) fn enter_background_filesystem(&self) {
        self.background_filesystems
            .borrow_mut()
            .push(self.filesystem.borrow().clone());
    }

    pub(crate) fn leave_background_filesystem(&self, walked: bool) {
        let real = self
            .background_filesystems
            .borrow_mut()
            .pop()
            .expect("job entered");
        if walked {
            self.filesystem.replace(real);
        }
    }

    fn mutate_filesystem(&self, mutation: impl Fn(&mut FilesystemState)) {
        mutation(&mut self.filesystem.borrow_mut());
        if self.measuring() {
            if let Some(probe) = self.lane_probe.borrow_mut().as_mut() {
                let lane = probe
                    .depth
                    .and_then(|depth| self.stages.borrow().get(depth).copied());
                mutation(probe.lanes.entry(lane).or_default());
            }
        } else {
            for real in self.background_filesystems.borrow_mut().iter_mut() {
                mutation(real);
            }
            for region in self.lane_regions.borrow_mut().iter_mut() {
                mutation(&mut region.walked);
            }
        }
    }

    /// Start sorting what the probe about to run notes into lanes: by the
    /// stage of the pipeline that numbers its stages at `depth`, or, with no
    /// depth, all into one lane.
    pub(crate) fn begin_lane_probe(&self, depth: Option<usize>) {
        self.lane_probe.replace(Some(LaneChanges {
            depth,
            lanes: BTreeMap::new(),
        }));
    }

    pub(crate) fn end_lane_probe(&self) -> Option<LaneChanges> {
        self.lane_probe.take()
    }

    /// Walk a job from the facts it began with and what the commands racing
    /// it may change: its own commands run in order, so a change the job
    /// makes reaches only its uses after that change.
    pub(crate) fn enter_job(&self, entry: RegionEntryFilesystem, racing: LaneChanges) {
        let mut state = entry.0;
        for changes in racing.lanes.into_values() {
            state.absorb(changes);
        }
        self.filesystem.replace(state);
    }

    /// Walk a probed pipeline's stages each against what its peers may
    /// change, as [`LaneRegion`] says, until the returned guard drops.
    pub(crate) fn enter_pipeline_lanes(
        &self,
        entry: RegionEntryFilesystem,
        changes: LaneChanges,
    ) -> Option<PipelineLanes<'_>> {
        let depth = changes.depth?;
        self.lane_regions.borrow_mut().push(LaneRegion {
            depth,
            entry: entry.0,
            lanes: changes.lanes,
            probed: self.filesystem.borrow().clone(),
            walked: FilesystemState::default(),
        });
        Some(PipelineLanes(self))
    }

    /// Enter the stage at `position` of the pipeline numbering its stages at
    /// the current depth.
    pub(crate) fn enter_stage(&self, position: usize) {
        let depth = self.stages.borrow().len();
        self.stages.borrow_mut().push(position);
        if self.measuring() {
            return;
        }
        let regions = self.lane_regions.borrow();
        let Some(region) = regions.last().filter(|region| region.depth == depth) else {
            return;
        };
        let mut state = region.entry.clone();
        for (lane, changes) in &region.lanes {
            if *lane != Some(position) {
                state.absorb(changes.clone());
            }
        }
        state.absorb(region.walked.clone());
        self.filesystem.replace(state);
    }

    /// Leave the current stage: between and after its stages, a pipeline
    /// meets every change its probe noted.
    pub(crate) fn leave_stage(&self) {
        self.stages.borrow_mut().pop();
        if self.measuring() {
            return;
        }
        let depth = self.stages.borrow().len();
        let regions = self.lane_regions.borrow();
        let Some(region) = regions.last().filter(|region| region.depth == depth) else {
            return;
        };
        let mut state = region.probed.clone();
        state.absorb(region.walked.clone());
        self.filesystem.replace(state);
    }

    pub(crate) fn measuring(&self) -> bool {
        self.measuring.get()
    }

    pub(crate) fn set_measuring(&self, on: bool) {
        self.measuring.set(on);
    }

    /// Charge one execution node. A refused charge does not consume
    /// budget, so a starved branch cannot drain siblings' shares.
    pub(crate) fn try_charge(&self) -> Charge {
        if !self.try_charge_steps(1) {
            return Charge::StepsSaturated;
        }
        let next = self.nodes.get() + 1;
        if next > self.limit {
            return Charge::Saturated;
        }
        if next > self.cap.get() {
            return Charge::Starved;
        }
        self.nodes.set(next);
        Charge::Ok
    }

    pub(crate) fn begin_finalization(&self) {
        self.finalizing.set(true);
    }

    pub(crate) fn timed_out(&self) -> bool {
        !self.finalizing.get()
            && self
                .deadline
                .as_ref()
                .is_some_and(crate::InvocationDeadline::expired)
    }

    /// Charge `n` units of analysis work against the whole-run step budget.
    /// False means the budget is spent: the caller records
    /// `max_analysis_steps` saturation and stops descending.
    pub(crate) fn try_charge_steps(&self, n: u64) -> bool {
        if self.timed_out() {
            return false;
        }
        if self
            .cancel
            .as_ref()
            .is_some_and(|flag| flag.load(Ordering::Relaxed))
        {
            self.cancelled.set(true);
            return false;
        }
        if n > self.steps_room() {
            self.steps_saturated.set(true);
            return false;
        }
        self.steps.set(self.steps.get() + n);
        true
    }

    /// Steps still chargeable: what remains of the current segment's grant
    /// plus what remains of the shared pool.
    fn steps_room(&self) -> u64 {
        let (start, grant) = self
            .segment
            .get()
            .map_or((0, 0), |segment| (segment.steps, segment.grant_steps));
        self.max_analysis_steps
            .saturating_add(grant)
            .saturating_sub(self.pool_steps.get() + (self.steps.get() - start))
    }

    /// Retained bytes still chargeable, on the same terms as `steps_room`.
    fn bytes_room(&self) -> u64 {
        let (start, grant) = self
            .segment
            .get()
            .map_or((0, 0), |segment| (segment.bytes, segment.grant_bytes));
        self.max_analysis_bytes
            .saturating_add(grant)
            .saturating_sub(self.pool_bytes.get() + self.retained_bytes.get().saturating_sub(start))
    }

    /// Start a shell segment at `item`, its source and offset, `len` bytes
    /// long: charge what the previous one spent to its grant first and the
    /// pools after, then grant this one its share from what the reserve has
    /// left. A pool a costly earlier segment exhausted stays exhausted, but no
    /// longer stops this segment until its grant is spent too. The first
    /// segment is granted nothing, so a command of one segment keeps exactly
    /// the configured limits. An item walked again continues the segment
    /// under way instead, which its text then no longer pays for.
    pub(crate) fn begin_segment(&self, item: (std::rc::Rc<str>, u32), len: usize, nested: bool) {
        // A group's or branch's first item starts where the compound does,
        // so it continues the compound's segment.
        if self.segment_item.borrow().as_ref() == Some(&item) {
            return;
        }
        let fresh = self.segment_items.borrow_mut().insert(item.clone());
        *self.segment_item.borrow_mut() = Some(item);
        if !fresh {
            // Walking an item again is work no new text pays for.
            if let Some(segment) = self.segment.get() {
                self.segment.set(Some(ShellSegment {
                    paid: false,
                    ..segment
                }));
            }
            return;
        }
        // Once nested segments have no steps left to grant, a nested item
        // keeps the allowance of the segment it sits in: an empty grant
        // would replace that allowance and starve the item.
        if nested && (self.nested_reserve_steps.get() == 0 || self.reserve_steps.get() == 0) {
            return;
        }
        let (grant_steps, grant_bytes) = match self.segment.get() {
            Some(segment) => {
                let steps = self.steps.get() - segment.steps;
                let bytes = self.retained_bytes.get().saturating_sub(segment.bytes);
                let granted_steps = steps.min(segment.grant_steps);
                let granted_bytes = bytes.min(segment.grant_bytes);
                self.pool_steps
                    .set(self.pool_steps.get() + steps - granted_steps);
                self.pool_bytes
                    .set(self.pool_bytes.get() + bytes - granted_bytes);
                self.reserve_steps
                    .set(self.reserve_steps.get() - granted_steps);
                self.reserve_bytes
                    .set(self.reserve_bytes.get() - granted_bytes);
                if segment.nested {
                    self.nested_reserve_steps
                        .set(self.nested_reserve_steps.get() - granted_steps);
                    self.nested_reserve_bytes
                        .set(self.nested_reserve_bytes.get() - granted_bytes);
                }
                if !segment.paid && (self.steps_saturated.get() || self.bytes_saturated.get()) {
                    self.saturated_segments
                        .set(self.saturated_segments.get() + 1);
                }
                if self.saturated_segments.get() >= MAX_SATURATED_SEGMENTS {
                    self.reserve_steps.set(0);
                    self.reserve_bytes.set(0);
                }
                let (reserve_steps, reserve_bytes) = if nested {
                    (
                        self.reserve_steps
                            .get()
                            .min(self.nested_reserve_steps.get()),
                        self.reserve_bytes
                            .get()
                            .min(self.nested_reserve_bytes.get()),
                    )
                } else {
                    (self.reserve_steps.get(), self.reserve_bytes.get())
                };
                (
                    (self.max_analysis_steps / SEGMENT_STEPS_DIVISOR).min(reserve_steps),
                    (self.max_analysis_bytes / SEGMENT_BYTES_DIVISOR).min(reserve_bytes),
                )
            }
            None => {
                self.pool_steps.set(self.steps.get());
                self.pool_bytes.set(self.retained_bytes.get());
                (0, 0)
            }
        };
        self.segment.set(Some(ShellSegment {
            steps: self.steps.get(),
            bytes: self.retained_bytes.get(),
            grant_steps,
            grant_bytes,
            paid: len as u64 >= self.max_analysis_steps / SEGMENT_STEPS_DIVISOR,
            nested,
        }));
        // Only a grant lifts a saturation: without one the walk stops, as
        // it would without segments.
        if grant_steps > 0 {
            self.steps_saturated.set(false);
        }
        if grant_bytes > 0 {
            self.bytes_saturated.set(false);
        }
    }

    pub(crate) fn analysis_steps_remaining(&self) -> u64 {
        self.steps_room()
    }

    pub(crate) fn heredoc_expansions_remaining(&self) -> u64 {
        self.max_heredoc_expansions
            .saturating_sub(self.heredoc_expansions.get())
    }

    pub(crate) fn try_charge_heredoc_expansion(&self) -> bool {
        let next = self.heredoc_expansions.get().saturating_add(1);
        if next > self.max_heredoc_expansions {
            return false;
        }
        self.heredoc_expansions.set(next);
        true
    }

    /// Guard precision may be refused without exhausting the effect walk.
    pub(crate) fn try_charge_condition(&self, steps: u64, bytes: u64) -> bool {
        if steps > self.steps_room() || bytes > self.bytes_room() {
            return false;
        }
        self.steps.set(self.steps.get() + steps);
        self.retained_bytes.set(self.retained_bytes.get() + bytes);
        true
    }

    /// Record that a modeled operation changed the filesystem topology at
    /// `path`, or anywhere when the operation's resource is not one concrete
    /// path. Initial-state identity through a changed entry is no longer
    /// evidence about the state the later operation meets. `change` says
    /// whether it is a plain directory creation or a removal.
    pub(crate) fn note_topology_mutation(&self, path: Option<&str>, change: TopologyChange) {
        self.mutate_filesystem(|state| match path {
            Some(path) => {
                let first = state.topology_mutations.insert(path.to_string());
                for (kind, paths) in [
                    (
                        TopologyChange::CreatesDirectory,
                        &mut state.created_directories,
                    ),
                    (TopologyChange::Removes, &mut state.removed_entries),
                ] {
                    if change != kind {
                        paths.remove(path);
                    } else if first {
                        paths.insert(path.to_string());
                    }
                }
            }
            None => state.topology_unknown = true,
        });
    }

    /// The directory a modeled step created that `path` lies beneath, when
    /// `path` is resolved through it: the host saw nothing there before, so
    /// the creation made a new, empty directory, and no other modeled change
    /// or write lies between it and `path`.
    fn created_directory_above(&self, path: &str) -> Option<String> {
        let above = |ancestor: &str| {
            path.strip_prefix(ancestor.trim_end_matches('/'))
                .is_some_and(|rest| rest.starts_with('/'))
        };
        let filesystem = self.filesystem.borrow();
        let mutations = &filesystem.topology_mutations;
        let created = &filesystem.created_directories;
        let mut changed = mutations
            .iter()
            .filter(|changed| *changed == path || above(changed));
        let directory = changed.next()?;
        // Sets are ordered, so the first changed ancestor is the outermost:
        // one creation, with nothing changed or written beneath it on the
        // way to `path`.
        if changed.next().is_some()
            || !created.contains(directory)
            || !above(directory)
            || self
                .filesystem
                .borrow()
                .written_paths
                .iter()
                .any(|written| {
                    above(written)
                        && written
                            .strip_prefix(directory.trim_end_matches('/'))
                            .is_some_and(|rest| rest.starts_with('/'))
                })
        {
            return None;
        }
        let initial = self.observe_initial(
            ObservationQuery::Path {
                path: directory.clone(),
            },
            &self.observation_requests,
        );
        matches!(initial, ObservationOutcome::Path(fact) if fact.kind == PathKind::Missing)
            .then(|| directory.clone())
    }

    /// Record that a modeled write reached `path`, or an unknown path.
    pub(crate) fn note_write(&self, path: Option<&str>) {
        self.mutate_filesystem(|state| match path {
            Some(path) => {
                state.written_paths.insert(path.to_string());
            }
            None => state.written_unknown = true,
        });
    }

    /// Replace the descriptor contents a launched program inherits,
    /// returning the previous ones for the launcher to restore.
    pub(crate) fn replace_descriptor_sources(
        &self,
        sources: Vec<(Word, Word)>,
    ) -> Vec<(Word, Word)> {
        self.descriptor_sources.replace(sources)
    }

    /// What the launching shell holds open on the descriptor `operand` names.
    pub(crate) fn descriptor_content(&self, operand: &Word) -> Option<Word> {
        self.descriptor_sources
            .borrow()
            .iter()
            .find(|(named, _)| named == operand)
            .map(|(_, content)| content.clone())
    }

    /// The path source resolution names a descriptor operand by. A process
    /// substitution's descriptor number is allocated at run time, so its
    /// operand is not literal text; when the launching shell supplied its
    /// bytes, the allocation's own name stands for the number.
    pub(crate) fn descriptor_operand_path(&self, operand: &Word) -> Option<String> {
        self.descriptor_sources
            .borrow()
            .iter()
            .any(|(named, _)| named == operand)
            .then(|| descriptor_path_text(operand))
            .flatten()
    }

    /// Replace the captured operands of the argv about to be launched,
    /// returning the previous ones for the launcher to restore.
    pub(crate) fn replace_captured_operands(&self, operands: CapturedOperands) -> CapturedOperands {
        self.captured_operands.replace(operands)
    }

    /// The request computation that supplied the operand at `index` of `argv`.
    pub(crate) fn argv_request_computation(
        &self,
        argv: &[Word],
        index: usize,
    ) -> Option<ProvenanceRef> {
        self.captured_operands
            .borrow()
            .request_computation(argv, index)
    }

    /// The `--NAME=` prefix of the option word at `index` of `argv` and the
    /// file whose bytes its attached value captures.
    pub(crate) fn captured_option_value(
        &self,
        argv: &[Word],
        index: usize,
    ) -> Option<(String, CapturedFile)> {
        self.captured_operands
            .borrow()
            .attached(argv, index)
            .cloned()
    }

    /// The file whose bytes the operand at `index` of `argv` captures.
    pub(crate) fn captured_operand(&self, argv: &[Word], index: usize) -> Option<CapturedFile> {
        self.captured_operands
            .borrow()
            .operand(argv, index)
            .cloned()
    }

    /// What the launching shell holds open on the descriptor `path` names.
    fn descriptor_content_at(&self, path: &str) -> Option<Word> {
        self.descriptor_sources
            .borrow()
            .iter()
            .find(|(named, _)| descriptor_path_text(named).as_deref() == Some(path))
            .map(|(_, content)| content.clone())
    }

    /// Record a step the analysis could not model on the host filesystem.
    pub(crate) fn note_unmodeled(&self) {
        self.mutate_filesystem(|state| state.unmodeled_steps += 1);
    }

    /// How many steps so far the analysis could not model on the host
    /// filesystem.
    pub(crate) fn unmodeled_steps(&self) -> usize {
        self.filesystem.borrow().unmodeled_steps
    }

    /// Whether an initial fact about `path` still describes the state a use
    /// meets. Checked on every use, including one answered from the cache.
    fn observation_invalidated(&self, path: &str) -> Option<ObservationRefusal> {
        self.observation_invalidated_keeping(path, false)
    }

    /// [`Self::observation_invalidated`], with removals left out where
    /// `removals_kept`.
    fn observation_invalidated_keeping(
        &self,
        path: &str,
        removals_kept: bool,
    ) -> Option<ObservationRefusal> {
        if self.filesystem.borrow().topology_unknown {
            return Some(ObservationRefusal::Ambiguous);
        }
        let filesystem = self.filesystem.borrow();
        filesystem
            .topology_mutations
            .iter()
            .any(|mutated| {
                !(removals_kept && filesystem.removed_entries.contains(mutated))
                    && (path == mutated
                        || (!filesystem.created_directories.contains(mutated)
                            && path.starts_with(&format!("{}/", mutated.trim_end_matches('/')))))
            })
            .then_some(ObservationRefusal::Stale)
    }

    /// Demand one path fact from the host. Validates the query and the
    /// answer, memoizes by exact query, charges the external-request and
    /// retained-byte budgets, and re-checks initial-state validity on every
    /// use. A refusal is a typed reason the answer is absent, never a fact.
    pub(crate) fn observe_path(&self, path: &str) -> ObservationOutcome {
        self.observe(ObservationQuery::Path {
            path: path.to_string(),
        })
    }

    /// The host's fact about the directory `path` as the invocation found
    /// it, for naming what lies beneath it
    /// (`models::common::resolved_entry_name`). Unlike [`Self::observe_path`]
    /// it stands after a change the analysis could not place, such as a
    /// removal by pattern: the name of a path must be the same before and
    /// after such a step, or a write made before it would not meet the read
    /// made after it, and the name claims no more about the changed state
    /// than the spelling did. A step that changed `path` itself, or an entry
    /// above it, still refuses it.
    ///
    /// The request is charged to the naming allowance, not to the requests
    /// [`Self::observe_path`] spends: a command touching many directories
    /// must not leave a later read of a private key unobserved.
    pub(crate) fn observe_directory_for_naming(&self, path: &str) -> ObservationOutcome {
        let changed = self
            .filesystem
            .borrow()
            .topology_mutations
            .iter()
            .any(|mutated| {
                path == mutated || path.starts_with(&format!("{}/", mutated.trim_end_matches('/')))
            });
        if changed {
            return ObservationOutcome::Refused(ObservationRefusal::Stale);
        }
        let outcome = self.observe_initial(
            ObservationQuery::Path {
                path: path.to_string(),
            },
            &self.naming_requests,
        );
        if matches!(
            outcome,
            ObservationOutcome::Refused(ObservationRefusal::Limit { .. })
        ) {
            self.naming_refused.set(true);
        }
        outcome
    }

    /// Whether a naming request was refused by a limit since the last call,
    /// so an effect kept the spelling the command gave it.
    pub(crate) fn take_naming_refused(&self) -> bool {
        self.naming_refused.replace(false)
    }

    /// Demand every entry beneath one directory, under the rules
    /// [`Self::observe_path`] states. A modeled change beneath the
    /// directory, a write to it, beneath it or to an ancestor, or a write
    /// whose path is unknown, also leaves its initial listing stale: the
    /// write may have created an entry the host never listed. Spellings are
    /// compared first, then the canonical identities the host establishes.
    /// An earlier step the analysis could not model on the filesystem, as
    /// New-Item, may have written anywhere, so it too leaves the listing
    /// stale: the asker passes how many such steps preceded it, since the
    /// gaps it records about itself concern only itself.
    pub(crate) fn observe_listing(
        &self,
        path: &str,
        depth: Option<u32>,
        unmodeled_before: usize,
    ) -> ObservationOutcome {
        self.observe_listing_keeping(path, depth, unmodeled_before, false)
    }

    /// [`Self::observe_listing`] for a reader to whom a listing taken before
    /// a removal still answers: `find`, which acts on each entry it lists as
    /// one it may meet. A removal beneath the directory, by an earlier step
    /// or by a peer in its pipeline (`find . -name x | xargs rm -rf`), takes
    /// entries away or, where it fails, leaves them, and adds none, so the
    /// initial listing still names every entry find can meet there.
    pub(crate) fn observe_listing_through_removals(
        &self,
        path: &str,
        depth: Option<u32>,
        unmodeled_before: usize,
    ) -> ObservationOutcome {
        self.observe_listing_keeping(path, depth, unmodeled_before, true)
    }

    fn observe_listing_keeping(
        &self,
        path: &str,
        depth: Option<u32>,
        unmodeled_before: usize,
        removals_kept: bool,
    ) -> ObservationOutcome {
        if self.listing_changed(path, unmodeled_before, removals_kept) {
            return ObservationOutcome::Refused(ObservationRefusal::Stale);
        }
        if let Some(refusal) =
            self.observation_invalidated_keeping(path.trim_end_matches('/'), removals_kept)
        {
            return ObservationOutcome::Refused(refusal);
        }
        let outcome = self.observe_initial(
            ObservationQuery::Listing {
                path: path.to_string(),
                depth,
            },
            &self.observation_requests,
        );
        if let ObservationOutcome::Listing(fact) = &outcome
            && self.changed_under_another_name_keeping(&fact.directory, removals_kept)
        {
            return ObservationOutcome::Refused(ObservationRefusal::Stale);
        }
        outcome
    }

    /// A change to the directory's identity or contents also invalidates an
    /// initial observation that the directory did not exist.
    pub(crate) fn initial_listing_refusal(
        &self,
        path: &str,
        unmodeled_before: usize,
    ) -> Option<ObservationRefusal> {
        if self.listing_stale(path, unmodeled_before) {
            Some(ObservationRefusal::Stale)
        } else {
            self.observation_invalidated(path.trim_end_matches('/'))
        }
    }

    /// Whether a modeled step so far may have changed what the directory
    /// `path` held initially, as [`Self::observe_listing`] decides it.
    pub(crate) fn listing_stale(&self, path: &str, unmodeled_before: usize) -> bool {
        self.listing_changed(path, unmodeled_before, false)
    }

    /// [`Self::listing_stale`], with removals beneath the directory left out
    /// where `removals_kept`.
    fn listing_changed(&self, path: &str, unmodeled_before: usize, removals_kept: bool) -> bool {
        let beneath = format!("{}/", path.trim_end_matches('/'));
        let filesystem = self.filesystem.borrow();
        filesystem.written_unknown
            || unmodeled_before > 0
            || filesystem.topology_mutations.iter().any(|changed| {
                changed.starts_with(&beneath)
                    && !(removals_kept && filesystem.removed_entries.contains(changed))
            })
            || filesystem.written_paths.iter().any(|written| {
                // A write to the directory itself or an ancestor can be a
                // recursive copy that fills it.
                let written = format!("{}/", written.trim_end_matches('/'));
                beneath.starts_with(&written) || written.starts_with(&beneath)
            })
    }

    /// Whether a modeled write or topology change spelled another way, as
    /// through a link or `/tmp` for `/private/tmp`, reaches the canonical
    /// `directory`, lies beneath it or above it. A path whose canonical
    /// identity the host does not establish counts as reaching it.
    pub(crate) fn changed_under_another_name(&self, directory: &str) -> bool {
        self.changed_under_another_name_keeping(directory, false)
    }

    /// [`Self::changed_under_another_name`], with removals left out where
    /// `removals_kept`.
    fn changed_under_another_name_keeping(&self, directory: &str, removals_kept: bool) -> bool {
        let related = |identity: &str| {
            let (a, b) = (
                format!("{}/", identity.trim_end_matches('/')),
                format!("{}/", directory.trim_end_matches('/')),
            );
            a.starts_with(&b) || b.starts_with(&a)
        };
        // The identities a path's fact establishes: `entry` resolves every
        // parent, and a final link is followed too. `None` when the host
        // does not establish them.
        let identities = |path: &str| match self.observe_path(path) {
            ObservationOutcome::Path(fact) => match fact.followed.known() {
                Some(target) => Some(vec![fact.entry, target.path.clone()]),
                None if fact.kind == PathKind::Symlink => None,
                None => Some(vec![fact.entry]),
            },
            _ => None,
        };
        let reaches = |identities: Option<Vec<String>>| {
            identities.is_none_or(|identities| identities.iter().any(|identity| related(identity)))
        };
        // Where a changed entry lies: a topology change makes its own fact
        // stale, so its parent is asked and the name joined beneath it.
        let changed = |path: &str| {
            let (parent, name) = path.trim_end_matches('/').rsplit_once('/')?;
            let parent = if parent.is_empty() { "/" } else { parent };
            identities(parent).map(|parents| {
                parents
                    .iter()
                    .map(|parent| format!("{}/{name}", parent.trim_end_matches('/')))
                    .collect::<Vec<_>>()
            })
        };
        // A write leaves its path's initial fact standing, so the path itself
        // is asked, unless it lies beneath a directory the analysis created:
        // then it is the rest of the path beneath where that directory lies.
        self.filesystem.borrow().written_paths.iter().any(|path| {
            reaches(match self.created_directory_above(path) {
                Some(directory) => changed(&directory).map(|directories| {
                    let beneath = &path[directory.trim_end_matches('/').len()..];
                    directories
                        .iter()
                        .map(|created| format!("{created}{beneath}"))
                        .collect()
                }),
                None => identities(path),
            })
        }) || self
            .filesystem
            .borrow()
            .topology_mutations
            .iter()
            .filter(|path| {
                !(removals_kept && self.filesystem.borrow().removed_entries.contains(*path))
            })
            .any(|path| reaches(changed(path)))
    }

    fn observe(&self, query: ObservationQuery) -> ObservationOutcome {
        let (ObservationQuery::Path { path } | ObservationQuery::Listing { path, .. }) = &query;
        if !effinterp_proto::valid_observation_query(&query) {
            return ObservationOutcome::Refused(ObservationRefusal::Invalid);
        }
        if let Some(refusal) = self.observation_invalidated_keeping(path, self.removals_kept.get())
        {
            return ObservationOutcome::Refused(refusal);
        }
        self.observe_initial(query, &self.observation_requests)
    }

    /// Run `observe` with path facts that a removal leaves standing, for
    /// `find`'s start path: a removal, by an earlier step or by a peer in
    /// its pipeline (`find dir -print0 | xargs -0 rm -rf`), leaves the entry
    /// as the host found it or takes it away, and find meets the initial
    /// entry or prints nothing there.
    pub(crate) fn through_removals<T>(&self, observe: impl FnOnce() -> T) -> T {
        let kept = self.removals_kept.replace(true);
        let result = observe();
        self.removals_kept.set(kept);
        result
    }

    /// The host's fact about the state the invocation starts from, whatever
    /// modeled steps changed since. Only a caller that accounts for those
    /// changes itself may rely on it. `requests` is the allowance a question
    /// the host has not answered yet is charged to; each is bounded by
    /// `max_observation_requests`.
    fn observe_initial(&self, query: ObservationQuery, requests: &Cell<u64>) -> ObservationOutcome {
        let (ObservationQuery::Path { path } | ObservationQuery::Listing { path, .. }) = &query;
        if !effinterp_proto::valid_observation_query(&query) {
            return ObservationOutcome::Refused(ObservationRefusal::Invalid);
        }
        if !self.try_charge_steps(1) {
            return ObservationOutcome::Refused(ObservationRefusal::Limit {
                limit: "max_analysis_steps".to_string(),
            });
        }
        if let Some(outcome) = self.observation_facts.borrow().get(&query) {
            return outcome.clone();
        }
        let Some(resolver) = self.observations.as_ref() else {
            return ObservationOutcome::Refused(ObservationRefusal::Unobserved);
        };
        if self.timed_out() {
            return ObservationOutcome::Refused(ObservationRefusal::Limit {
                limit: "invocation_deadline".to_string(),
            });
        }
        if requests.get() >= self.max_observation_requests {
            return ObservationOutcome::Refused(ObservationRefusal::Limit {
                limit: "max_observation_requests".to_string(),
            });
        }
        requests.set(requests.get() + 1);
        let outcome = resolver.observe(
            &query,
            crate::ObservationBudget {
                remaining_requests: self.max_observation_requests.saturating_sub(requests.get()),
                remaining_bytes: self.bytes_room(),
                expired: self.timed_out(),
            },
        );
        // A late answer is not evidence: the run already stopped scheduling
        // work, and accepting it would restore a completeness the run lost.
        if self.timed_out() {
            return ObservationOutcome::Refused(ObservationRefusal::Limit {
                limit: "invocation_deadline".to_string(),
            });
        }
        if !effinterp_proto::valid_observation_outcome(&query, &outcome) {
            return ObservationOutcome::Refused(ObservationRefusal::Invalid);
        }
        if !self.try_charge_bytes(observation_retained_bytes(path, &outcome)) {
            return ObservationOutcome::Refused(ObservationRefusal::Limit {
                limit: "max_analysis_bytes".to_string(),
            });
        }
        self.observation_facts
            .borrow_mut()
            .insert(query.clone(), outcome.clone());
        outcome
    }

    pub(crate) fn release_bytes(&self, bytes: u64) {
        self.retained_bytes.set(self.retained_bytes.get() - bytes);
    }

    /// Charge `n` accounted retained bytes against the whole-run byte budget.
    pub(crate) fn try_charge_bytes(&self, n: u64) -> bool {
        if self
            .cancel
            .as_ref()
            .is_some_and(|flag| flag.load(Ordering::Relaxed))
        {
            self.cancelled.set(true);
            return false;
        }
        if n > self.bytes_room() {
            self.bytes_saturated.set(true);
            return false;
        }
        self.retained_bytes.set(self.retained_bytes.get() + n);
        true
    }

    pub(crate) fn cancelled(&self) -> bool {
        self.cancelled.get()
    }

    pub(crate) fn steps(&self) -> u64 {
        self.steps.get()
    }

    pub(crate) fn retained_bytes(&self) -> u64 {
        self.retained_bytes.get()
    }

    pub(crate) fn note_state_scan(&self, entries: u64) {
        self.state_scan_entries
            .set(self.state_scan_entries.get().saturating_add(entries));
    }

    pub(crate) fn state_scan_entries(&self) -> u64 {
        self.state_scan_entries.get()
    }

    pub(crate) fn note_execution_edges_examined(&self, edges: u64) {
        self.execution_edges_examined
            .set(self.execution_edges_examined.get().saturating_add(edges));
    }

    pub(crate) fn execution_edges_examined(&self) -> u64 {
        self.execution_edges_examined.get()
    }

    pub(crate) fn steps_saturated(&self) -> bool {
        self.steps_saturated.get()
    }

    pub(crate) fn bytes_saturated(&self) -> bool {
        self.bytes_saturated.get()
    }

    /// Invocations still chargeable under the effective cap.
    pub(crate) fn remaining(&self) -> u64 {
        self.cap.get().saturating_sub(self.nodes.get())
    }

    /// Enter a fair-share window allowing `share` further invocations
    /// (never more than the enclosing cap allows).
    pub(crate) fn push_window(&self, share: u64) -> Window {
        let prev = Window {
            cap: self.cap.get(),
            starved: self.window_starved.get(),
        };
        self.cap
            .set(self.nodes.get().saturating_add(share).min(prev.cap));
        self.window_starved.set(false);
        prev
    }

    pub(crate) fn pop_window(&self, prev: Window) {
        self.cap.set(prev.cap);
        self.window_starved.set(prev.starved);
    }

    /// Whether further work in the current window would be refused — set
    /// only once a charge has actually been refused (and its boundary
    /// recorded), so callers stop without re-reporting.
    pub(crate) fn exhausted(&self) -> bool {
        self.timed_out()
            || self.nodes_saturated.get()
            || self.window_starved.get()
            || self.steps_saturated.get()
            || self.bytes_saturated.get()
    }

    /// Mark the invocation budget saturated; true the first time only.
    pub(crate) fn note_nodes_saturated(&self) -> bool {
        !self.nodes_saturated.replace(true)
    }

    /// Mark the innermost window starved; true the first time only.
    pub(crate) fn note_window_starved(&self) -> bool {
        !self.window_starved.replace(true)
    }

    /// Mark the depth budget saturated; true the first time only.
    pub(crate) fn note_depth_saturated(&self) -> bool {
        !self.depth_saturated.replace(true)
    }

    /// Mark the shell-function depth budget saturated; true the first time only.
    pub(crate) fn note_function_depth_saturated(&self) -> bool {
        self.function_depth_refusals
            .set(self.function_depth_refusals.get() + 1);
        !self.function_depth_saturated.replace(true)
    }

    pub(crate) fn function_depth_refusals(&self) -> u64 {
        self.function_depth_refusals.get()
    }

    /// Mark the remaining starved source region; true the first time only.
    pub(crate) fn note_starved_region(&self) -> bool {
        !self.starved_region_recorded.replace(true)
    }

    fn exhausted_boundary(&self) -> Option<(BoundaryReason, &'static str)> {
        if self.nodes_saturated.get() {
            Some((BoundaryReason::EXECUTION_LIMIT, "max_execution_nodes"))
        } else if self.window_starved.get() {
            Some((BoundaryReason::BRANCH_STARVED, "max_execution_nodes"))
        } else {
            None
        }
    }
}

pub(crate) struct ProbedSource {
    path: String,
    namespace: SourceNamespace,
    purpose: SourcePurpose,
    requester_language: Option<String>,
    response: SourceResponse,
}

/// The analysis environment threaded through frontends and models: the model
/// catalog, configured limits, and the shared budget.
pub(crate) struct Nest<'a> {
    pub execute_umask_uncertain: std::cell::Cell<bool>,
    pub registration: Option<&'a crate::Registration>,
    pub path_platform: effinterp_proto::PathPlatform,
    pub script_origins: RefCell<Vec<Option<String>>>,
    /// Shell script named by `$0`, retained across sourcing for interpreter self re-reads.
    pub current_script: RefCell<Option<(String, String)>>,
    pub catalog: &'a Catalog,
    pub limits: &'a AnalysisLimits,
    pub budget: &'a Budget,
    /// Caller-supplied file-source access (None: file references stay opaque).
    pub resolver: Option<&'a dyn SourceResolver>,
    /// File origin of the root subject; inline subjects have none.
    pub source_origin: Option<&'a str>,
    /// Inline JavaScript loads every module in that launch, including a
    /// static import at the root. Repository entrypoints leave those
    /// requests to the linker and record no dependency gap.
    pub follow_root_js_dependencies: bool,
    /// The root subject's shell text. A shell reading this same text is
    /// reading the subject's own words, so the bytes they spell out came
    /// from the subject (`Shell::spells_subject`).
    pub subject_source: Option<&'a str>,
    /// Manifest scripts and Make recipes cannot admit files reached from their text.
    pub source_resolution_disabled: Cell<bool>,
    /// The origin and text of the `package.json` whose script is being
    /// followed. A package manager run from that script's text reads the same
    /// manifest when its runtime cwd resolves to it, so that run may reuse it
    /// once; it is cleared while the nested script runs.
    pub package_manifest: RefCell<Option<(String, String)>>,
    /// Postgres routines the SQL inputs of one database client run have
    /// defined so far. The client sets it around each input it nests, so a
    /// routine one `-c` defines is known to the next; None outside a client.
    pub sql_routines: RefCell<Option<Vec<crate::sql::Routine>>>,
    /// Consumer-supplied values available only in the host realm.
    pub context: Option<&'a HostContext>,
    /// Repository source namespace for the subject currently being analyzed.
    /// The empty string is repository root.
    pub source_cwds: RefCell<Vec<Option<String>>>,
    /// Repository namespace of the current runtime cwd. The empty string is
    /// repository root; None means the runtime cwd is unknown.
    pub runtime_cwds: RefCell<Vec<Option<String>>>,
    /// Provenance for the cwd of each nested source analysis.
    pub cwd_nodes: RefCell<Vec<Option<ProvenanceRef>>>,
    /// Mount mappings visible to the current execution node. Each transition
    /// inherits the current mappings unless it enters a new container with an
    /// explicit storage declaration.
    pub mounts: RefCell<Vec<Vec<ContainerStorage>>>,
    /// Effective environment mutations visible to the current execution node.
    pub environments: RefCell<Vec<BTreeMap<String, Option<ResourceExpr>>>>,
    /// Provenance for effective environment values, keyed like `environments`.
    pub environment_nodes: RefCell<Vec<BTreeMap<String, ProvenanceRef>>>,
    /// Names deliberately absent from the effective environment. This keeps
    /// an unset value from being reseeded from the root host context.
    pub environment_unsets: RefCell<Vec<BTreeSet<String>>>,
    /// Exported names whose value was captured from a name-hiding command
    /// substitution. A child shell that imports one keeps it marked so its use
    /// as a command head is still recognized as obfuscated.
    pub environment_concealed: RefCell<Vec<BTreeSet<String>>>,
    /// Whether the inherited environment is a proven finite inventory.
    pub environment_closed: RefCell<Vec<bool>>,
    /// A scheduled program uses the scheduler's environment, whose unbound
    /// names are unknown even when the caller supplies its own environment.
    pub independent_environment: Cell<bool>,
    /// Evidence from admitted buffers, copied into nested execution without
    /// reopening the source.
    pub selected_source_inputs: RefCell<BTreeMap<String, SelectedSourceInput>>,
    /// Distinct invocation-selected source paths admitted during this plan.
    pub resolved_invocation_sources: RefCell<BTreeSet<String>>,
    /// Initial source evidence read by a speculative walk, handed to the
    /// real walk without asking the resolver for the same evidence again.
    pub probed_sources: RefCell<Vec<ProbedSource>>,
    /// Argv words after a `sh -c CODE` script, with their argument nodes:
    /// `$0`, `$1`, ... of the shell about to be analyzed. Set around exactly
    /// one nested shell transition and taken by that shell's analysis.
    pub shell_arguments: RefCell<Option<Vec<(Word, ProvenanceRef)>>>,
    /// Later writes in a launching shell's list, inherited by child shells
    /// so background jobs inside their source see the same races.
    pub shell_background_followup: RefCell<std::rc::Rc<crate::shell::LaterWrites>>,
    /// The shell analyzing the current command entered its cwd physically, so
    /// the PWD a nested shell inherits names the physical directory.
    pub physical_cwd: Cell<bool>,
    /// Import search roots for the next nested Python program. Set around
    /// exactly one Python transition and taken by that program's walk.
    pub python_import_search: RefCell<Option<crate::python::PythonImportSearch>>,
    /// The startup policy Python lends to its in-process pytest model.
    pub python_ignores_startup_environment: Cell<bool>,
    /// Python module lookups and imported function summaries observed during
    /// this invocation, keyed by exact search context and content.
    pub python_imports: crate::python::PythonImportCache,
    /// Dependency sources followed by path and the summaries used to compose
    /// calls into them.
    pub dependency_calls: crate::dependency_calls::DependencyCalls,
}

pub(crate) enum SourceResolution {
    AlreadySelected,
    Source { origin: String, source: String },
    Refused(SourceRefusal),
    UnsupportedEncoding,
    Unavailable,
}

#[derive(Clone)]
pub(crate) struct SelectedSourceInput {
    pub(crate) input: effinterp_proto::ExecutionInput,
    pub(crate) authorship: SourceAuthorship,
}

pub(crate) enum SourceCandidate {
    Source(Vec<u8>),
    Written {
        bytes: Vec<u8>,
        conditional: bool,
        subject_spans: Vec<effinterp_proto::ByteSpan>,
    },
    Refused(SourceRefusal),
    ResolverUnavailable,
}

/// The first observed winner of an ordered source search, read under the
/// invocation budget without recording execution evidence.
pub(crate) enum SourceSearchObservation {
    Found { index: usize, bytes: Vec<u8> },
    Missing,
    Refused(SourceRefusal),
    ResolverUnavailable,
}

/// Whether a nested transition may proceed, or why it was refused.
enum NestedTransitionGuard {
    Proceed,
    Refused,
}

#[derive(Clone)]
struct ResolvedTransition {
    subject: Subject,
    kind: ExecutionEdgeKind,
    argv: Vec<ResourceExpr>,
    cwd: Option<ResourceExpr>,
    cwd_node: Option<ProvenanceRef>,
    environment: BTreeMap<String, Option<ResourceExpr>>,
    streams: ExecutionStreams,
    prints_completion: bool,
    mounts: Vec<ContainerStorage>,
    realm: ExecutionRealm,
    assurance: ExecutionAssurance,
    origin: Option<String>,
    source_authorship: Option<SourceAuthorship>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum EnvironmentInheritance {
    Inherit,
    Reset,
    Independent,
    // A foreign realm starts without host mutations or explicit host unsets.
    Isolated,
}

/// A nested execution request. Unspecified attributes inherit their current scope.
#[derive(Clone)]
pub(crate) struct Transition {
    subject: Subject,
    words: Option<Vec<Word>>,
    argv: Vec<ResourceExpr>,
    kind: ExecutionEdgeKind,
    origin: Option<String>,
    source_authorship: Option<SourceAuthorship>,
    source_cwd: Option<Option<String>>,
    runtime_cwd: Option<Option<String>>,
    cwd: Option<ResourceExpr>,
    cwd_node: Option<ProvenanceRef>,
    environment: BTreeMap<String, Option<ResourceExpr>>,
    environment_nodes: BTreeMap<String, ProvenanceRef>,
    environment_unsets: BTreeSet<String>,
    environment_concealed: BTreeSet<String>,
    inherit_environment: EnvironmentInheritance,
    command_search_path: Option<ResourceExpr>,
    realm: Option<ExecutionRealm>,
    mounts: Option<Vec<ContainerStorage>>,
    streams: Option<ExecutionStreams>,
    prints_completion: bool,
    assurance: ExecutionAssurance,
    source_span_offset: Option<usize>,
    stdin: Option<StdinValue>,
    argv_provenance: Option<Vec<Vec<ProvenanceRef>>>,
    runtime_shell: Option<RuntimeShell>,
    shell_text_executable: bool,
    ignores_execute_bit: bool,
    executable_source: Option<bool>,
    execute_umask_uncertain: Option<bool>,
    js_eval_require_shadowed: Option<bool>,
}

impl Transition {
    pub(crate) fn file(subject: Subject) -> Self {
        let argv = match &subject {
            Subject::Exec { argv, .. } => argv
                .iter()
                .map(|value| ResourceExpr::Literal {
                    value: value.clone(),
                })
                .collect(),
            _ => Vec::new(),
        };
        Self {
            kind: inferred_kind(&subject),
            subject,
            argv,
            words: None,
            origin: None,
            source_authorship: None,
            source_cwd: None,
            runtime_cwd: None,
            cwd: None,
            cwd_node: None,
            environment: BTreeMap::new(),
            environment_nodes: BTreeMap::new(),
            environment_unsets: BTreeSet::new(),
            environment_concealed: BTreeSet::new(),
            inherit_environment: EnvironmentInheritance::Inherit,
            command_search_path: None,
            realm: None,
            mounts: None,
            streams: None,
            prints_completion: false,
            assurance: ExecutionAssurance::Exact,
            source_span_offset: None,
            stdin: None,
            argv_provenance: None,
            runtime_shell: None,
            shell_text_executable: false,
            ignores_execute_bit: false,
            executable_source: None,
            execute_umask_uncertain: None,
            js_eval_require_shadowed: None,
        }
    }

    pub(crate) fn direct_js_eval(mut self, require_shadowed: bool) -> Self {
        self.js_eval_require_shadowed = Some(require_shadowed);
        self
    }

    /// The shell a language runtime selected for this shell subject, when it
    /// overrides the runtime's default `/bin/sh`, or the shell a launched
    /// script's first line names.
    pub(crate) fn runtime_shell(mut self, shell: Option<RuntimeShell>) -> Self {
        self.runtime_shell = shell;
        self
    }

    /// execvp, like a shell launch, interprets executable text on ENOEXEC.
    pub(crate) fn shell_text_executable(mut self) -> Self {
        self.shell_text_executable = true;
        self
    }

    /// The launcher reads the file named by argv[0] and runs it itself, as
    /// sbatch does a job script, so a missing execute bit does not stop it.
    pub(crate) fn ignores_execute_bit(mut self) -> Self {
        self.ignores_execute_bit = true;
        self
    }

    pub(crate) fn argv(mut self, argv: Vec<ResourceExpr>) -> Self {
        self.argv = argv;
        self
    }

    pub(crate) fn prints_completion(mut self, prints: bool) -> Self {
        self.prints_completion = prints;
        self
    }

    pub(crate) fn exec(argv: Vec<ResourceExpr>, display_argv: Vec<Word>) -> Self {
        let mut transition = Self::file(Subject::Exec {
            argv: display_argv.iter().map(Word::render_raw).collect(),
            cwd: None,
            context: Default::default(),
        });
        transition = transition.assurance(
            display_argv
                .first()
                .map(execution_assurance)
                .unwrap_or(ExecutionAssurance::Exact),
        );
        transition.argv = argv;
        transition.words = Some(display_argv);
        transition
    }

    pub(crate) fn kind(mut self, kind: ExecutionEdgeKind) -> Self {
        self.kind = kind;
        self
    }

    pub(crate) fn origin(mut self, origin: String) -> Self {
        self.origin = Some(origin);
        self
    }

    /// Retain the origin of a recovered value instead of inheriting the launcher's source.
    pub(crate) fn source_authorship(mut self, authorship: SourceAuthorship) -> Self {
        self.source_authorship = Some(authorship);
        self
    }

    pub(crate) fn executable_source(mut self, shell_text: Option<bool>) -> Self {
        self.executable_source = shell_text;
        self
    }

    pub(crate) fn execute_umask_uncertain(mut self, value: bool) -> Self {
        self.execute_umask_uncertain = Some(value);
        self
    }

    pub(crate) fn source_cwd(mut self, cwd: Option<&str>) -> Self {
        self.source_cwd = Some(cwd.map(str::to_string));
        self
    }

    pub(crate) fn runtime_cwd(mut self, cwd: Option<&str>) -> Self {
        self.runtime_cwd = Some(cwd.map(str::to_string));
        self
    }

    pub(crate) fn cwd(
        mut self,
        cwd: impl Into<Option<ResourceExpr>>,
        node: Option<ProvenanceRef>,
    ) -> Self {
        self.cwd = cwd.into();
        self.cwd_node = node;
        self
    }

    pub(crate) fn environment(
        mut self,
        values: BTreeMap<String, Option<ResourceExpr>>,
        nodes: BTreeMap<String, ProvenanceRef>,
        unsets: BTreeSet<String>,
    ) -> Self {
        self.environment = values;
        self.environment_nodes = nodes;
        self.environment_unsets = unsets;
        self
    }

    pub(crate) fn environment_concealed(mut self, concealed: BTreeSet<String>) -> Self {
        self.environment_concealed = concealed;
        self
    }

    pub(crate) fn inherit_environment(mut self, inherit: bool) -> Self {
        self.inherit_environment = if inherit {
            EnvironmentInheritance::Inherit
        } else {
            EnvironmentInheritance::Reset
        };
        self
    }

    pub(crate) fn independent_environment(mut self) -> Self {
        self.inherit_environment = EnvironmentInheritance::Independent;
        self
    }

    pub(crate) fn command_search_path(mut self, path: ResourceExpr) -> Self {
        self.command_search_path = Some(path);
        self
    }

    pub(crate) fn realm(mut self, realm: ExecutionRealm) -> Self {
        self.realm = Some(realm);
        self
    }

    pub(crate) fn mounts(mut self, mounts: Vec<ContainerStorage>) -> Self {
        self.mounts = Some(mounts);
        self
    }

    pub(crate) fn streams(mut self, streams: ExecutionStreams) -> Self {
        self.streams = Some(streams);
        self
    }

    pub(crate) fn assurance(mut self, assurance: ExecutionAssurance) -> Self {
        self.assurance = assurance;
        self
    }

    pub(crate) fn source_span_offset(mut self, offset: usize) -> Self {
        self.source_span_offset = Some(offset);
        self
    }

    // Exec subjects keep their display cwd separate from the repository runtime namespace.
    pub(crate) fn exec_cwd(mut self, cwd: Option<&str>) -> Self {
        if let Subject::Exec {
            cwd: subject_cwd, ..
        } = &mut self.subject
        {
            *subject_cwd = cwd.map(str::to_string);
        }
        self
    }

    pub(crate) fn stdin(mut self, stdin: Option<&StdinValue>) -> Self {
        self.stdin = stdin.cloned();
        self
    }

    pub(crate) fn argv_provenance(mut self, provenance: Option<&[Vec<ProvenanceRef>]>) -> Self {
        self.argv_provenance = provenance.map(<[_]>::to_vec);
        self
    }

    pub(crate) fn display_argv(mut self, argv: &[String]) -> Self {
        if let Subject::Exec { argv: display, .. } = &mut self.subject {
            *display = argv.to_vec();
        }
        self
    }

    fn resolve(
        self,
        nest: &Nest,
        builder: &PlanBuilder,
        environment: BTreeMap<String, Option<ResourceExpr>>,
    ) -> ResolvedTransition {
        let mut streams = self.streams.unwrap_or_else(|| {
            let node = builder.current_execution();
            ExecutionStreams {
                stdin: Some(effinterp_proto::ExecutionStreamRef {
                    node,
                    stream: effinterp_proto::ExecutionStream::Stdin,
                }),
                stdout: Some(effinterp_proto::ExecutionStreamRef {
                    node,
                    stream: effinterp_proto::ExecutionStream::Stdout,
                }),
                stderr: Some(effinterp_proto::ExecutionStreamRef {
                    node,
                    stream: effinterp_proto::ExecutionStream::Stderr,
                }),
                stdin_value: None,
            }
        });
        if let Some(stdin) = &self.stdin
            && !stdin.piped
            && stdin.file.is_none()
        {
            streams.stdin = None;
            streams.stdin_value = Some(ExecutionStreamValue {
                value: word_resource(&stdin.word),
                provenance: stdin.provenance.clone(),
            });
        }
        ResolvedTransition {
            cwd: self.cwd.or_else(|| {
                // A Windows cwd such as `C:\work` is absolute on its own
                // platform rather than relative to an unknown POSIX one.
                subject_cwd(&self.subject).map(|cwd| {
                    if crate::paths::path_platform(Some(cwd))
                        == effinterp_proto::PathPlatform::Windows
                    {
                        ResourceExpr::Concrete {
                            identity: effinterp_proto::ResourceIdentity::FsPath {
                                path: crate::paths::normalize_cwd(cwd),
                            },
                        }
                    } else {
                        crate::paths::resolve_fs_path(cwd, None)
                    }
                })
            }),
            subject: self.subject,
            kind: self.kind,
            argv: self.argv,
            cwd_node: self.cwd_node,
            environment,
            streams,
            prints_completion: self.prints_completion,
            mounts: self
                .mounts
                .unwrap_or_else(|| nest.mounts.borrow().last().cloned().unwrap_or_default()),
            realm: self.realm.unwrap_or_else(|| builder.current_realm()),
            assurance: self.assurance,
            origin: self.origin,
            source_authorship: self.source_authorship,
        }
    }
}

/// Owns the stack entries of one admitted transition; callers must end it after analysis.
#[must_use]
pub(crate) struct NestedFrame<'a> {
    nest: &'a Nest<'a>,
    pub(crate) scope: ProvenanceRef,
    pub(crate) execution: ExecutionNodeRef,
    depths: [usize; 10],
    builder_depths: [usize; 3],
    source_condition: bool,
    source_read_conditions: Option<Vec<effinterp_proto::Condition>>,
    execute_umask_before: bool,
    independent_environment_before: bool,
}

impl NestedFrame<'_> {
    pub(crate) fn end(self, builder: &mut PlanBuilder) {
        self.nest
            .execute_umask_uncertain
            .set(self.execute_umask_before);
        self.nest
            .independent_environment
            .set(self.independent_environment_before);
        if self.source_condition {
            builder.pop_condition();
        }
        if let Some(previous) = self.source_read_conditions {
            builder.leave_source_read_conditions(previous);
        }
        debug_assert_eq!(self.nest.stack_depths(), self.depths.map(|depth| depth + 1));
        debug_assert_eq!(
            builder.nested_stack_depths(),
            self.builder_depths.map(|depth| depth + 1)
        );
        builder.pop_source_span_offset();
        self.nest.script_origins.borrow_mut().pop();
        self.nest.cwd_nodes.borrow_mut().pop();
        self.nest.runtime_cwds.borrow_mut().pop();
        self.nest.source_cwds.borrow_mut().pop();
        self.nest.environment_unsets.borrow_mut().pop();
        self.nest.environment_concealed.borrow_mut().pop();
        self.nest.environment_closed.borrow_mut().pop();
        self.nest.environment_nodes.borrow_mut().pop();
        self.nest.environments.borrow_mut().pop();
        self.nest.mounts.borrow_mut().pop();
        builder.pop_realm();
        builder.pop_execution();
        debug_assert_eq!(self.nest.stack_depths(), self.depths);
        debug_assert_eq!(builder.nested_stack_depths(), self.builder_depths);
    }
}

/// The environment values, their provenance, and the exported names a
/// transition passes to the nested execution.
type InheritedEnvironment = (
    BTreeMap<String, Option<ResourceExpr>>,
    BTreeMap<String, ProvenanceRef>,
    BTreeSet<String>,
    BTreeSet<String>,
);

impl<'a> Nest<'a> {
    pub(crate) fn host_environment_context(&self) -> Option<&HostContext> {
        self.context.filter(|_| !self.independent_environment.get())
    }

    /// Whether nested shells must preserve overrides of supplied host values.
    pub(crate) fn tracks_host_context_environment(&self) -> bool {
        self.host_environment_context()
            .is_some_and(|context| !context.env.is_empty() || !context.env_unset.is_empty())
    }

    pub(crate) fn environment_is_closed(&self) -> bool {
        self.environment_closed
            .borrow()
            .last()
            .copied()
            .unwrap_or(false)
    }

    /// The wrapper that injected variables this execution's environment does
    /// not name, such as `doppler run`: a disclosed name the environment binds
    /// no node for may be one it injected.
    pub(crate) fn injected_environment_node(&self) -> Option<ProvenanceRef> {
        self.current_environment_node(INJECTED_ENVIRONMENT)
    }

    /// The injection that may define `name` in this execution: the name is
    /// unbound, or keeps the binding it had in the execution the injection
    /// entered. A name rebound after the injection holds only the later value.
    pub(crate) fn injected_environment_node_for(&self, name: &str) -> Option<ProvenanceRef> {
        let frames = self.environment_nodes.borrow();
        let injection = *frames.last()?.get(INJECTED_ENVIRONMENT)?;
        let injected = frames
            .iter()
            .find(|nodes| nodes.get(INJECTED_ENVIRONMENT) == Some(&injection))?;
        (frames.last()?.get(name) == injected.get(name)).then_some(injection)
    }

    pub(crate) fn current_environment_node(&self, name: &str) -> Option<ProvenanceRef> {
        self.environment_nodes
            .borrow()
            .last()
            .and_then(|nodes| nodes.get(name).copied())
    }

    /// The exact effective environment value visible to the current execution.
    pub(crate) fn environment_value(&self, name: &str) -> Option<ResourceExpr> {
        if self.current_environment_unsets().contains(name) {
            return None;
        }
        if let Some(value) = self
            .environments
            .borrow()
            .last()
            .and_then(|environment| environment.get(name))
        {
            return Some(value.clone().unwrap_or(unresolved_resource("value")));
        }
        self.host_environment_context()
            .and_then(|context| context.env.get(name))
            .map(|value| ResourceExpr::Literal {
                value: value.clone(),
            })
    }

    /// The HOME value or, after an unset, the original host home that an
    /// account-home fallback may still select. This never sets HOME again.
    pub(crate) fn home_directory_value(&self) -> ResourceExpr {
        self.environment_value("HOME")
            .or_else(|| {
                self.context
                    .and_then(|context| context.env.get("HOME"))
                    .map(|value| ResourceExpr::Literal {
                        value: value.clone(),
                    })
            })
            .unwrap_or_else(|| ResourceExpr::Environment {
                name: "HOME".into(),
            })
    }

    /// The host account's home from the initial context, independent of
    /// environment assignments made by the invocation.
    pub(crate) fn account_home(&self) -> Option<&str> {
        self.context
            .and_then(|context| context.env.get("HOME"))
            .filter(|home| !home.is_empty())
            .map(String::as_str)
    }

    /// The names [`Self::environment_value`] can answer for the current
    /// execution: its own bindings and the supplied host values, less the
    /// names it unset.
    pub(crate) fn environment_names(&self) -> BTreeSet<String> {
        let unsets = self.current_environment_unsets();
        self.environments
            .borrow()
            .last()
            .into_iter()
            .flat_map(|environment| environment.keys().cloned())
            .chain(
                self.host_environment_context()
                    .into_iter()
                    .flat_map(|context| context.env.keys().cloned()),
            )
            .filter(|name| !unsets.contains(name))
            .collect()
    }

    pub(crate) fn current_environment_unsets(&self) -> BTreeSet<String> {
        self.environment_unsets
            .borrow()
            .last()
            .cloned()
            .unwrap_or_default()
    }

    pub(crate) fn current_environment_concealed(&self) -> BTreeSet<String> {
        self.environment_concealed
            .borrow()
            .last()
            .cloned()
            .unwrap_or_default()
    }

    pub(crate) fn current_source_cwd(&self) -> Option<String> {
        self.source_cwds.borrow().last().cloned().unwrap_or(None)
    }

    pub(crate) fn current_runtime_cwd(&self) -> Option<String> {
        self.runtime_cwds.borrow().last().cloned().unwrap_or(None)
    }

    pub(crate) fn current_cwd_node(&self) -> Option<ProvenanceRef> {
        self.cwd_nodes.borrow().last().copied().unwrap_or(None)
    }

    /// Resolver paths identify host repository files. A foreign realm can
    /// reach one only through an explicit bind mount; translation retains the
    /// host and container identities on the execution node.
    pub(crate) fn resolve_source(
        &self,
        builder: &mut PlanBuilder,
        path: &str,
        purpose: SourcePurpose,
    ) -> SourceResolution {
        self.resolve_source_file(
            builder,
            path,
            purpose,
            &builder.current_execution_component(),
        )
    }

    pub(crate) fn resolve_source_file(
        &self,
        builder: &mut PlanBuilder,
        path: &str,
        purpose: SourcePurpose,
        component: &str,
    ) -> SourceResolution {
        if self.source_resolution_disabled.get() {
            return SourceResolution::Unavailable;
        }
        let host_path = if builder.is_host_realm() {
            path.to_string()
        } else {
            let Some(mounts) = self.mounts.borrow().last().cloned() else {
                self.record_source_boundary(
                    builder,
                    path,
                    purpose,
                    effinterp_proto::ExecutionContent::Unobserved {
                        reason: effinterp_proto::ExecutionInputReason::NamespaceDenied,
                    },
                    component,
                );
                return SourceResolution::Unavailable;
            };
            let Some(path) = translate_mount(path, &mounts) else {
                self.record_source_boundary(
                    builder,
                    path,
                    purpose,
                    effinterp_proto::ExecutionContent::Unobserved {
                        reason: effinterp_proto::ExecutionInputReason::NamespaceDenied,
                    },
                    component,
                );
                return SourceResolution::Unavailable;
            };
            path
        };
        let namespace = self.source_namespace(&host_path);
        self.resolve_source_selection(builder, host_path, namespace, purpose, component)
    }

    /// The namespace a host path is resolved in: the repository view while a
    /// repository source runs, the host's otherwise.
    fn source_namespace(&self, host_path: &str) -> SourceNamespace {
        let base = self.current_source_cwd();
        if base.as_deref().unwrap_or(host_path).starts_with('/') {
            SourceNamespace::Host
        } else {
            SourceNamespace::Repository
        }
    }

    /// Whether `path` in the host realm resolves to bytes, asked without
    /// recording any evidence. A reader that wants the bytes only when it can
    /// have them asks this first, so a file it cannot read leaves no gap.
    pub(crate) fn host_source_readable(
        &self,
        builder: &PlanBuilder,
        path: &str,
        purpose: SourcePurpose,
    ) -> bool {
        builder.is_host_realm()
            && matches!(
                self.resolve_source_candidate(builder, path, self.source_namespace(path), purpose),
                SourceCandidate::Source(_) | SourceCandidate::Written { .. }
            )
    }

    pub(crate) fn resolve_source_selection(
        &self,
        builder: &mut PlanBuilder,
        path: String,
        namespace: SourceNamespace,
        purpose: SourcePurpose,
        component: &str,
    ) -> SourceResolution {
        let input = self.source_input(
            builder,
            &path,
            purpose,
            effinterp_proto::ExecutionContent::Unobserved {
                reason: effinterp_proto::ExecutionInputReason::ResolverUnavailable,
            },
            component,
        );
        self.resolve_execution_input(builder, path, namespace, purpose, input)
    }

    pub(crate) fn resolve_execution_input(
        &self,
        builder: &mut PlanBuilder,
        path: String,
        namespace: SourceNamespace,
        purpose: SourcePurpose,
        mut input: effinterp_proto::ExecutionInput,
    ) -> SourceResolution {
        use effinterp_proto::ExecutionContent;
        if builder.runtime_input_recorded(&path, &input) {
            return SourceResolution::AlreadySelected;
        }
        match self.resolve_source_candidate(builder, &path, namespace, purpose) {
            candidate @ (SourceCandidate::Source(_) | SourceCandidate::Written { .. }) => {
                builder.note_code_read(&path);
                self.admit_execution_source(
                    builder,
                    path,
                    candidate,
                    input,
                    |builder, path, input| {
                        self.record_input_boundary(builder, path, input);
                    },
                )
            }
            SourceCandidate::Refused(refusal) => {
                note_unread_executed_input(builder, purpose, refusal);
                input.content = ExecutionContent::Unobserved {
                    reason: source_refusal_reason(refusal),
                };
                self.record_input_boundary(builder, &path, input);
                SourceResolution::Refused(refusal)
            }
            SourceCandidate::ResolverUnavailable => {
                self.record_input_boundary(builder, &path, input);
                SourceResolution::Unavailable
            }
        }
    }

    /// Resolve one ordered runtime search without retaining losing candidates
    /// as selected-input nodes. The resolver sees only candidates up to the
    /// first winner.
    pub(crate) fn resolve_execution_search(
        &self,
        builder: &mut PlanBuilder,
        candidates: Vec<(SourceNamespace, String)>,
        purpose: SourcePurpose,
        input: effinterp_proto::ExecutionInput,
        record_missing: bool,
    ) -> (SourceResolution, bool) {
        self.resolve_execution_search_with(
            builder,
            candidates,
            purpose,
            input,
            record_missing,
            |_, _| {},
            |builder, path, input| self.record_input_boundary(builder, path, input),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn resolve_execution_search_with(
        &self,
        builder: &mut PlanBuilder,
        candidates: Vec<(SourceNamespace, String)>,
        purpose: SourcePurpose,
        mut input: effinterp_proto::ExecutionInput,
        record_missing: bool,
        select: impl FnOnce(usize, &mut effinterp_proto::ExecutionInput),
        mut record_gap: impl FnMut(&mut PlanBuilder, &str, effinterp_proto::ExecutionInput),
    ) -> (SourceResolution, bool) {
        use effinterp_proto::{
            ExecutionAssurance, ExecutionContent, ExecutionInputReason, ExecutionSelection,
            ResourceIdentity,
        };
        let resources = candidates
            .iter()
            .map(|(_, path)| ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path: path.clone() },
            })
            .collect::<Vec<_>>();
        input.selected = None;
        input.selection = ExecutionSelection::Search {
            candidates: resources.clone(),
            selected: None,
        };
        // Every earlier candidate missed, so a recorded one here is the file
        // this search selects, and it has already run.
        for (index, (namespace, path)) in candidates.iter().enumerate() {
            if builder.runtime_input_recorded(path, &input)
                || (purpose == SourcePurpose::DependencySource
                    && builder.dependency_source_recorded(path))
            {
                return (SourceResolution::AlreadySelected, false);
            }
            match self.resolve_source_candidate(builder, path, *namespace, purpose) {
                candidate @ (SourceCandidate::Source(_) | SourceCandidate::Written { .. }) => {
                    input.selected = Some(resources[index].clone());
                    input.selection = ExecutionSelection::Search {
                        candidates: resources,
                        selected: Some(index as u32),
                    };
                    select(index, &mut input);
                    return (
                        self.admit_execution_source(
                            builder,
                            path.clone(),
                            candidate,
                            input,
                            record_gap,
                        ),
                        false,
                    );
                }
                SourceCandidate::Refused(SourceRefusal::Unavailable(
                    crate::UnavailableReason::Missing | crate::UnavailableReason::NotAFile,
                )) => {}
                SourceCandidate::Refused(refusal) => {
                    note_unread_executed_input(builder, purpose, refusal);
                    input.assurance = ExecutionAssurance::Widened;
                    input.content = ExecutionContent::Unobserved {
                        reason: source_refusal_reason(refusal),
                    };
                    record_gap(builder, path, input);
                    return (SourceResolution::Refused(refusal), false);
                }
                SourceCandidate::ResolverUnavailable => {
                    input.assurance = ExecutionAssurance::Widened;
                    record_gap(builder, path, input);
                    return (SourceResolution::Unavailable, false);
                }
            }
        }
        if record_missing {
            input.assurance = ExecutionAssurance::Widened;
            input.content = ExecutionContent::Unobserved {
                reason: ExecutionInputReason::Missing,
            };
            let request = candidates.first().map_or_else(
                || input.requester_component.clone(),
                |(_, path)| path.clone(),
            );
            record_gap(builder, &request, input);
        }
        (SourceResolution::Unavailable, true)
    }

    /// Observe an ordered search; missing and non-file candidates fall through.
    /// Callers record the evidence once they know where the search is used.
    pub(crate) fn observe_source_search(
        &self,
        builder: &PlanBuilder,
        candidates: &[(SourceNamespace, String)],
        purpose: SourcePurpose,
    ) -> SourceSearchObservation {
        for (index, (namespace, path)) in candidates.iter().enumerate() {
            match self.resolve_source_candidate(builder, path, *namespace, purpose) {
                SourceCandidate::Source(bytes) => {
                    return SourceSearchObservation::Found { index, bytes };
                }
                SourceCandidate::Written { .. } => {
                    return SourceSearchObservation::Refused(SourceRefusal::Unavailable(
                        crate::UnavailableReason::Stale,
                    ));
                }
                SourceCandidate::Refused(SourceRefusal::Unavailable(
                    crate::UnavailableReason::Missing | crate::UnavailableReason::NotAFile,
                )) => {}
                SourceCandidate::Refused(refusal) => {
                    return SourceSearchObservation::Refused(refusal);
                }
                SourceCandidate::ResolverUnavailable => {
                    return SourceSearchObservation::ResolverUnavailable;
                }
            }
        }
        SourceSearchObservation::Missing
    }

    pub(crate) fn source_mutation_may_alias(&self, resource: &ResourceExpr, path: &str) -> bool {
        if self.budget.timed_out() {
            return true;
        }
        self.resolver.is_none_or(|resolver| {
            !resolver.source_mutation_disjoint(
                resource,
                SourceRequest {
                    path,
                    namespace: if path.starts_with('/') {
                        SourceNamespace::Host
                    } else {
                        SourceNamespace::Repository
                    },
                    purpose: SourcePurpose::InvocationInput,
                    requester_language: None,
                },
            )
        })
    }

    /// Read data under the same admission and mutation rules as source, without
    /// claiming that the file is an executable input. The caller owns any gap.
    pub(crate) fn resolve_data_file(
        &self,
        builder: &PlanBuilder,
        path: &str,
        namespace: SourceNamespace,
    ) -> SourceResolution {
        if !builder.is_host_realm() {
            return SourceResolution::Unavailable;
        }
        self.resolve_host_data_file(builder, path, namespace)
    }

    /// `resolve_data_file` for a path already in the resolver's namespace,
    /// such as one translated through a container's bind mount.
    fn resolve_host_data_file(
        &self,
        builder: &PlanBuilder,
        path: &str,
        namespace: SourceNamespace,
    ) -> SourceResolution {
        match self.resolve_source_candidate(
            builder,
            path,
            namespace,
            SourcePurpose::InvocationInput,
        ) {
            SourceCandidate::Source(bytes)
            | SourceCandidate::Written {
                bytes,
                conditional: false,
                ..
            } => match String::from_utf8(bytes) {
                Ok(source) => SourceResolution::Source {
                    origin: path.into(),
                    source,
                },
                Err(_) => SourceResolution::UnsupportedEncoding,
            },
            SourceCandidate::Written {
                conditional: true, ..
            } => SourceResolution::Refused(SourceRefusal::Unavailable(
                crate::UnavailableReason::Ambiguous,
            )),
            SourceCandidate::Refused(refusal) => SourceResolution::Refused(refusal),
            SourceCandidate::ResolverUnavailable => SourceResolution::Unavailable,
        }
    }

    pub(crate) fn resolve_source_candidate(
        &self,
        builder: &PlanBuilder,
        path: &str,
        namespace: SourceNamespace,
        purpose: SourcePurpose,
    ) -> SourceCandidate {
        if self.source_resolution_disabled.get() {
            return SourceCandidate::ResolverUnavailable;
        }
        // A name this invocation created as a link is not the file the reader
        // opens; the file it points at is. Resolve that first so the mutation
        // history and the resolver are both asked about one path.
        let aliased = (namespace == SourceNamespace::Host)
            .then(|| builder.created_alias_path(path))
            .flatten();
        let path = aliased.as_ref().map_or(path, |(path, _)| path.as_str());
        let refusal = if self.budget.timed_out() {
            Some(SourceRefusal::Limit {
                limit: "invocation_deadline",
            })
        } else if self.budget.remaining() == 0 {
            Some(SourceRefusal::Limit {
                limit: "max_execution_nodes",
            })
        } else if builder.execution_depth() >= self.limits.max_execution_depth {
            Some(SourceRefusal::Limit {
                limit: "max_execution_depth",
            })
        } else if builder.execution_fanout() >= self.limits.max_execution_fanout {
            Some(SourceRefusal::Limit {
                limit: "max_execution_fanout",
            })
        } else if self.budget.exhausted() {
            Some(SourceRefusal::Limit {
                limit: if self.budget.bytes_saturated() {
                    "max_analysis_bytes"
                } else if self.budget.steps_saturated() {
                    "max_analysis_steps"
                } else {
                    "max_execution_nodes"
                },
            })
        } else if !self.resolved_invocation_sources.borrow().contains(path)
            && self.resolved_invocation_sources.borrow().len() as u64
                >= self.limits.max_resolved_source_files
        {
            Some(SourceRefusal::Limit {
                limit: "max_resolved_source_files",
            })
        } else {
            None
        };
        if let Some(refusal) = refusal {
            return SourceCandidate::Refused(refusal);
        }
        // A descriptor path names bytes the launching shell supplied, not a
        // file on the host.
        let inherited = (namespace == SourceNamespace::Host)
            .then(|| self.budget.descriptor_content_at(path))
            .flatten()
            .and_then(|content| content.as_literal().map(str::to_owned))
            .map(|bytes| crate::builder::WrittenSource::Exact {
                bytes: bytes.into_bytes(),
                subject_spans: Vec::new(),
            });
        let written = inherited.unwrap_or_else(|| {
            builder.written_source(path, |resource, path| {
                self.source_mutation_may_alias(resource, path)
            })
        });
        if self.budget.timed_out() {
            return SourceCandidate::Refused(SourceRefusal::Limit {
                limit: "invocation_deadline",
            });
        }
        let (written, conditional) = match written {
            crate::builder::WrittenSource::Conditional { source, .. } => (*source, true),
            source => (source, false),
        };
        let (copied, appended) = match written {
            crate::builder::WrittenSource::Host => (None, None),
            crate::builder::WrittenSource::Copied(path) => (Some(path), None),
            crate::builder::WrittenSource::Appended {
                prefix,
                bytes,
                subject_spans,
            } => (Some(prefix), Some((bytes, subject_spans))),
            crate::builder::WrittenSource::Exact {
                bytes,
                subject_spans,
            } => {
                return if bytes.len() as u64 > self.limits.max_source_bytes {
                    SourceCandidate::Refused(SourceRefusal::Limit {
                        limit: "max_source_bytes",
                    })
                } else if !self.budget.try_charge_bytes(bytes.len() as u64) {
                    SourceCandidate::Refused(SourceRefusal::Limit {
                        limit: "max_analysis_bytes",
                    })
                } else {
                    SourceCandidate::Written {
                        bytes,
                        conditional,
                        subject_spans,
                    }
                };
            }
            crate::builder::WrittenSource::JsonFields(_) | crate::builder::WrittenSource::Stale => {
                return SourceCandidate::Refused(SourceRefusal::Unavailable(
                    crate::UnavailableReason::Stale,
                ));
            }
            crate::builder::WrittenSource::Ambiguous
            | crate::builder::WrittenSource::Conditional { .. } => {
                return SourceCandidate::Refused(SourceRefusal::Unavailable(
                    crate::UnavailableReason::Ambiguous,
                ));
            }
        };
        let Some(resolver) = self.resolver else {
            return SourceCandidate::ResolverUnavailable;
        };
        let observed_path = copied.as_deref().unwrap_or(path);
        self.resolved_invocation_sources
            .borrow_mut()
            .insert(observed_path.to_string());
        let requester_language = builder.current_source_language();
        let cached = self.probed_sources.borrow().iter().position(|source| {
            source.path == observed_path
                && source.namespace == namespace
                && source.purpose == purpose
                && source.requester_language.as_deref() == requester_language
        });
        let response = match cached {
            Some(index) if self.budget.measuring() => {
                self.probed_sources.borrow()[index].response.clone()
            }
            Some(index) => self.probed_sources.borrow_mut().remove(index).response,
            None => resolver.resolve(SourceRequest {
                path: observed_path,
                namespace,
                purpose,
                requester_language,
            }),
        };
        if self.budget.timed_out() {
            return SourceCandidate::Refused(SourceRefusal::Limit {
                limit: "invocation_deadline",
            });
        }
        if cached.is_none() && self.budget.measuring() {
            let bytes = match &response {
                SourceResponse::Source(bytes) => bytes.len() as u64,
                SourceResponse::Refused(_) => 0,
            };
            if bytes <= self.limits.max_source_bytes
                && !matches!(
                    response,
                    SourceResponse::Refused(SourceRefusal::Limit { .. })
                )
            {
                let retained = bytes
                    + observed_path.len() as u64
                    + requester_language.map_or(0, str::len) as u64
                    + std::mem::size_of::<ProbedSource>() as u64;
                if !self.budget.try_charge_bytes(retained) {
                    return SourceCandidate::Refused(SourceRefusal::Limit {
                        limit: "max_analysis_bytes",
                    });
                }
                self.probed_sources.borrow_mut().push(ProbedSource {
                    path: observed_path.to_string(),
                    namespace,
                    purpose,
                    requester_language: requester_language.map(str::to_string),
                    response: response.clone(),
                });
            }
        }
        match response {
            SourceResponse::Source(mut bytes) => {
                let size = bytes
                    .len()
                    .saturating_add(appended.as_ref().map_or(0, |(tail, _)| tail.len()));
                let limit = if size as u64 > self.limits.max_source_bytes {
                    Some("max_source_bytes")
                } else if !self.budget.try_charge_bytes(size as u64) {
                    Some("max_analysis_bytes")
                } else {
                    None
                };
                if let Some(limit) = limit {
                    SourceCandidate::Refused(SourceRefusal::Limit { limit })
                } else if copied.is_some() {
                    let mut subject_spans = Vec::new();
                    if let Some((tail, spans)) = appended {
                        if let Ok(offset) = u32::try_from(bytes.len()) {
                            subject_spans.extend(spans.into_iter().filter_map(|span| {
                                Some(effinterp_proto::ByteSpan {
                                    start: span.start.checked_add(offset)?,
                                    end: span.end.checked_add(offset)?,
                                })
                            }));
                        }
                        bytes.extend(tail);
                    }
                    SourceCandidate::Written {
                        bytes,
                        conditional,
                        subject_spans,
                    }
                } else {
                    SourceCandidate::Source(bytes)
                }
            }
            SourceResponse::Refused(refusal) => SourceCandidate::Refused(refusal),
        }
    }

    fn admit_execution_source(
        &self,
        builder: &mut PlanBuilder,
        path: String,
        candidate: SourceCandidate,
        mut input: effinterp_proto::ExecutionInput,
        mut record_gap: impl FnMut(&mut PlanBuilder, &str, effinterp_proto::ExecutionInput),
    ) -> SourceResolution {
        let (bytes, subject_spans, conditional) = match candidate {
            SourceCandidate::Source(bytes) => (bytes, None, false),
            SourceCandidate::Written {
                bytes,
                conditional,
                subject_spans,
            } => (bytes, Some(subject_spans), conditional),
            _ => unreachable!(),
        };
        if conditional {
            input.content = effinterp_proto::ExecutionContent::Unobserved {
                reason: effinterp_proto::ExecutionInputReason::Ambiguous,
            };
            record_gap(builder, &path, input.clone());
            input.assurance = effinterp_proto::ExecutionAssurance::Widened;
        }
        let authorship = if let Some(spans) = subject_spans {
            set_predicted_source(&mut input, &bytes, spans)
        } else {
            input.content = effinterp_proto::ExecutionContent::Observed {
                digest: effinterp_proto::content_digest(&bytes),
            };
            SourceAuthorship::External
        };
        self.selected_source_inputs.borrow_mut().insert(
            path.clone(),
            SelectedSourceInput {
                input: input.clone(),
                authorship,
            },
        );
        match String::from_utf8(bytes) {
            Ok(source) => SourceResolution::Source {
                origin: path,
                source,
            },
            Err(_) => {
                record_gap(builder, &path, input);
                SourceResolution::UnsupportedEncoding
            }
        }
    }

    pub(crate) fn source_input(
        &self,
        builder: &PlanBuilder,
        path: &str,
        purpose: SourcePurpose,
        content: effinterp_proto::ExecutionContent,
        component: &str,
    ) -> effinterp_proto::ExecutionInput {
        use effinterp_proto::*;
        ExecutionInput {
            role: if purpose == SourcePurpose::DependencySource {
                ExecutionInputRole::DependencyRequest
            } else {
                ExecutionInputRole::ExplicitInvocation
            },
            phase: if purpose == SourcePurpose::DependencySource {
                ExecutionPhase::Import
            } else {
                ExecutionPhase::Main
            },
            selected: Some(ResourceExpr::Concrete {
                identity: effinterp_proto::ResourceIdentity::FsPath {
                    path: path.to_string(),
                },
            }),
            assurance: ExecutionAssurance::Exact,
            selector: if purpose == SourcePurpose::DependencySource {
                ExecutionSelector::Dependency {
                    specifier: path.to_string(),
                }
            } else {
                ExecutionSelector::InvocationPath
            },
            requester: builder.current_execution(),
            requester_component: component.to_string(),
            selection: ExecutionSelection::Direct {
                request: path.to_string(),
            },
            content,
        }
    }

    pub(crate) fn source_authorship(&self, path: &str) -> SourceAuthorship {
        self.selected_source_inputs
            .borrow()
            .get(path)
            .map_or(SourceAuthorship::External, |source| {
                source.authorship.clone()
            })
    }

    pub(crate) fn record_source_boundary(
        &self,
        builder: &mut PlanBuilder,
        path: &str,
        purpose: SourcePurpose,
        content: effinterp_proto::ExecutionContent,
        component: &str,
    ) {
        let input = self.source_input(builder, path, purpose, content, component);
        self.record_input_boundary(builder, path, input);
    }

    pub(crate) fn record_input_boundary(
        &self,
        builder: &mut PlanBuilder,
        path: &str,
        input: effinterp_proto::ExecutionInput,
    ) {
        self.record_input_boundary_scoped(builder, path, input, None);
    }

    /// Limit uncertainty to the supplied domains without degrading nested coverage globally.
    pub(crate) fn record_input_boundary_scoped(
        &self,
        builder: &mut PlanBuilder,
        path: &str,
        input: effinterp_proto::ExecutionInput,
        domains: Option<&[&str]>,
    ) {
        let kind = match input.phase {
            effinterp_proto::ExecutionPhase::Import => ExecutionEdgeKind::Import,
            effinterp_proto::ExecutionPhase::Startup => ExecutionEdgeKind::Startup,
            effinterp_proto::ExecutionPhase::Preload => ExecutionEdgeKind::Preload,
            effinterp_proto::ExecutionPhase::NativeLoader => ExecutionEdgeKind::NativeLoader,
            effinterp_proto::ExecutionPhase::BuildHook => ExecutionEdgeKind::BuildHook,
            effinterp_proto::ExecutionPhase::PackageHook => ExecutionEdgeKind::PackageHook,
            effinterp_proto::ExecutionPhase::VcsHook => ExecutionEdgeKind::VcsHook,
            effinterp_proto::ExecutionPhase::Plugin => ExecutionEdgeKind::Plugin,
            _ => ExecutionEdgeKind::Interpreter,
        };
        let boundary = builder.boundary(Boundary {
            reason: if matches!(
                input.content,
                effinterp_proto::ExecutionContent::Observed { .. }
                    | effinterp_proto::ExecutionContent::Predicted { .. }
            ) {
                BoundaryReason::UNSUPPORTED_SOURCE
            } else {
                BoundaryReason::UNRECOVERABLE_SOURCE
            },
            class: BoundaryClass::Unresolved,
            scope: BoundaryScope::Invocation,
            affected_resource: input.selected.clone(),
            callee: None,
            domains: domains
                .unwrap_or(&KNOWN_DOMAINS)
                .iter()
                .map(|d| Domain::new(*d))
                .collect(),
            provenance: Vec::new(),
            limit: None,
            detail: Some(match &input.content {
                effinterp_proto::ExecutionContent::Observed { .. }
                | effinterp_proto::ExecutionContent::Predicted { .. } => {
                    "unsupported source".to_string()
                }
                effinterp_proto::ExecutionContent::Unobserved { reason } => {
                    format!("execution input unobserved: {reason:?}")
                }
            }),
        });
        let node = ExecutionNode {
            subject: Subject::Exec {
                argv: vec![path.to_string()],
                cwd: None,
                context: Default::default(),
            },
            boundary: Some(boundary),
            argv: Vec::new(),
            cwd: builder.current_execution_cwd(),
            environment: Default::default(),
            streams: Default::default(),
            prints_completion: false,
            mounts: Vec::new(),
            source_span: None,
            realm: builder.current_realm(),
            assurance: input.assurance,
            evidence: Vec::new(),
            input: Some(input),
        };
        builder.selected_input_effects(&node);
        if let Some(node) = builder.execution_node(node) {
            builder.execution_edge(node, kind, false, &[]);
        }
        if domains.is_none() {
            degrade_nested(builder);
        }
    }

    pub(crate) fn record_unsupported_source(&self, builder: &mut PlanBuilder, path: &str) {
        let input = self
            .selected_source_inputs
            .borrow()
            .get(path)
            .map(|source| source.input.clone())
            .expect("resolved source evidence");
        self.record_input_boundary(builder, path, input);
    }

    pub(crate) fn source_siblings(&self, path: &str) -> Option<Vec<String>> {
        if self.source_resolution_disabled.get() || self.budget.timed_out() {
            return None;
        }
        self.resolver?.siblings(path)
    }

    /// Check structural limits and charge the budget for one nested transition. On refusal
    /// the saturation boundary/coverage is recorded once and the transition is
    /// closed as opaque against `subject`.
    fn guard(
        &self,
        builder: &mut PlanBuilder,
        transition: &ResolvedTransition,
        provenance: &[ProvenanceRef],
        depth: u64,
    ) -> NestedTransitionGuard {
        if builder.execution_fanout() >= self.limits.max_execution_fanout {
            if builder.note_execution_saturated() {
                degrade_nested(builder);
                self.record_opaque(
                    builder,
                    transition,
                    provenance,
                    BoundaryReason::EXECUTION_LIMIT,
                    "max_execution_fanout",
                );
            }
            return NestedTransitionGuard::Refused;
        }
        if depth + 1 >= self.limits.max_execution_depth {
            // What the transition would run is unread, so the call fails
            // closed rather than delegating with a gap.
            builder.note_executed_input_limit();
            let first_in_scope = builder.note_execution_saturated();
            if self.budget.note_depth_saturated() {
                degrade_nested(builder);
            }
            if first_in_scope {
                self.record_opaque(
                    builder,
                    transition,
                    provenance,
                    BoundaryReason::EXECUTION_LIMIT,
                    "max_execution_depth",
                );
            }
            return NestedTransitionGuard::Refused;
        }
        match self.budget.try_charge() {
            Charge::Ok => {}
            Charge::Saturated => {
                if self.budget.note_nodes_saturated() {
                    degrade_nested(builder);
                }
                self.record_opaque(
                    builder,
                    transition,
                    provenance,
                    BoundaryReason::EXECUTION_LIMIT,
                    "max_execution_nodes",
                );
                return NestedTransitionGuard::Refused;
            }
            Charge::StepsSaturated => {
                builder.note_saturated_at("max_analysis_steps", None);
                self.record_opaque(
                    builder,
                    transition,
                    provenance,
                    BoundaryReason::EXECUTION_LIMIT,
                    if self.budget.timed_out() {
                        "invocation_deadline"
                    } else {
                        "max_analysis_steps"
                    },
                );
                return NestedTransitionGuard::Refused;
            }
            Charge::Starved => {
                if self.budget.note_window_starved() {
                    degrade_nested(builder);
                }
                self.record_opaque(
                    builder,
                    transition,
                    provenance,
                    BoundaryReason::BRANCH_STARVED,
                    "max_execution_nodes",
                );
                return NestedTransitionGuard::Refused;
            }
        }
        NestedTransitionGuard::Proceed
    }

    /// Record a nested transition that will be analyzed, returning the
    /// provenance node subsequent effects should trace through. `origin` is
    /// the resolved file the subject's source was read from, when file-backed.
    fn record_analyzed(
        &self,
        builder: &mut PlanBuilder,
        transition: ResolvedTransition,
        provenance: &[ProvenanceRef],
        additional_evidence: &[ProvenanceRef],
    ) -> Option<(ExecutionNodeRef, ProvenanceRef)> {
        let kind = transition.kind;
        let source_authorship = if let Some(path) = &transition.origin {
            self.source_authorship(path)
        } else {
            transition.source_authorship.clone().unwrap_or_else(|| {
                builder
                    .source_from_subject(provenance.first().copied())
                    .into()
            })
        };
        let mut evidence = provenance.to_vec();
        evidence.extend(additional_evidence);
        let mut node = execution_node(self, builder, transition, &evidence, None);
        // Environment evidence explains values; the call site owns the span.
        node.source_span = builder.source_span(provenance);
        builder.selected_input_effects(&node);
        let kind = if node
            .input
            .as_ref()
            .is_some_and(|input| input.phase == effinterp_proto::ExecutionPhase::Import)
        {
            ExecutionEdgeKind::Import
        } else {
            kind
        };
        let node = builder.execution_node(node)?;
        builder.set_source_authorship(node, source_authorship);
        builder.execution_edge(node, kind, false, &evidence);
        let scope = builder.node(ProvenanceKind::Execution { node: node.0 }, provenance);
        Some((node, scope))
    }

    fn record_opaque(
        &self,
        builder: &mut PlanBuilder,
        transition: &ResolvedTransition,
        provenance: &[ProvenanceRef],
        reason: BoundaryReason,
        limit_name: &str,
    ) -> Option<ProvenanceRef> {
        let boundary: BoundaryRef = builder.boundary(Boundary {
            reason,
            class: BoundaryClass::Limit,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: KNOWN_DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
            provenance: provenance.to_vec(),
            limit: Some(limit_name.to_string()),
            detail: None,
        });
        let mut node = execution_node(
            self,
            builder,
            transition.clone(),
            provenance,
            Some(boundary),
        );
        node.assurance = ExecutionAssurance::Widened;
        let node = builder.execution_node(node)?;
        builder.execution_edge(node, ExecutionEdgeKind::Widening, false, provenance);
        Some(builder.node(ProvenanceKind::Execution { node: node.0 }, provenance))
    }

    /// Record a site reached after its current execution scope has already
    /// saturated. The caller may still retain source-local command heads, but
    /// the refused nested transition remains explicit in the execution graph.
    pub(crate) fn record_refused_nested_with_cwd(
        &self,
        builder: &mut PlanBuilder,
        subject: Subject,
        provenance: &[ProvenanceRef],
        depth: u64,
        cwd_resource: Option<ResourceExpr>,
        cwd_node: Option<ProvenanceRef>,
    ) -> Option<ProvenanceRef> {
        let (reason, limit_name) = if builder.execution_fanout() >= self.limits.max_execution_fanout
        {
            (BoundaryReason::EXECUTION_LIMIT, "max_execution_fanout")
        } else if depth + 1 >= self.limits.max_execution_depth {
            builder.note_executed_input_limit();
            (BoundaryReason::EXECUTION_LIMIT, "max_execution_depth")
        } else {
            self.budget.exhausted_boundary()?
        };
        let request = Transition::file(subject).cwd(cwd_resource, cwd_node);
        let (environment, _, _, _) = self.inherited_environment(&request);
        let transition = request.resolve(self, builder, environment);
        if self.record_cycle(builder, &transition, provenance) {
            return None;
        }
        self.record_opaque(builder, &transition, provenance, reason, limit_name)
    }

    fn stack_depths(&self) -> [usize; 10] {
        [
            self.script_origins.borrow().len(),
            self.mounts.borrow().len(),
            self.environments.borrow().len(),
            self.environment_nodes.borrow().len(),
            self.environment_unsets.borrow().len(),
            self.environment_concealed.borrow().len(),
            self.environment_closed.borrow().len(),
            self.source_cwds.borrow().len(),
            self.runtime_cwds.borrow().len(),
            self.cwd_nodes.borrow().len(),
        ]
    }

    fn inherited_environment(&self, transition: &Transition) -> InheritedEnvironment {
        let mut environment = if transition.inherit_environment == EnvironmentInheritance::Inherit {
            self.environments
                .borrow()
                .last()
                .cloned()
                .unwrap_or_default()
        } else if transition.inherit_environment == EnvironmentInheritance::Reset {
            self.host_environment_context()
                .map(|context| {
                    context
                        .env
                        .keys()
                        .cloned()
                        .map(|name| (name, None))
                        .collect()
                })
                .unwrap_or_default()
        } else {
            Default::default()
        };
        let mut nodes = if transition.inherit_environment == EnvironmentInheritance::Inherit {
            self.environment_nodes
                .borrow()
                .last()
                .cloned()
                .unwrap_or_default()
        } else {
            BTreeMap::new()
        };
        let mut unsets = if transition.inherit_environment == EnvironmentInheritance::Inherit {
            self.current_environment_unsets()
        } else if transition.inherit_environment == EnvironmentInheritance::Reset {
            self.host_environment_context()
                .map(|context| context.env.keys().cloned().collect())
                .unwrap_or_default()
        } else {
            Default::default()
        };
        let mut concealed = if transition.inherit_environment == EnvironmentInheritance::Inherit {
            self.current_environment_concealed()
        } else {
            BTreeSet::new()
        };
        // An injection may define any name, including one the parent unset:
        // such a name is no longer bound to its absence.
        if transition
            .environment_nodes
            .contains_key(INJECTED_ENVIRONMENT)
        {
            for name in std::mem::take(&mut unsets) {
                environment.remove(&name);
                nodes.remove(&name);
            }
        }
        for name in transition.environment.keys() {
            nodes.remove(name);
            unsets.remove(name);
            // A rebind replaces the prior capture; the transition re-adds the
            // name below only when its new value is itself concealed.
            concealed.remove(name);
        }
        environment.extend(transition.environment.clone());
        nodes.extend(transition.environment_nodes.clone());
        unsets.extend(transition.environment_unsets.clone());
        concealed.extend(transition.environment_concealed.clone());
        (environment, nodes, unsets, concealed)
    }

    /// Refusals return before any stack is pushed. The frame owns every admitted push.
    pub(crate) fn begin(
        &self,
        builder: &mut PlanBuilder,
        mut transition: Transition,
        provenance: &[ProvenanceRef],
        depth: u64,
    ) -> Option<NestedFrame<'_>> {
        if transition.words.as_ref().is_some_and(Vec::is_empty) {
            return None;
        }
        let source_condition = transition.origin.as_ref().and_then(|path| {
            let aliased = builder.created_alias_path(path);
            let source_path = aliased
                .as_ref()
                .map_or(path.as_str(), |(path, _)| path.as_str());
            let crate::builder::WrittenSource::Conditional { condition, .. } = builder
                .written_source(source_path, |resource, path| {
                    self.source_mutation_may_alias(resource, path)
                })
            else {
                return None;
            };
            let versions = builder.earlier_written_sources(source_path, |resource, path| {
                self.source_mutation_may_alias(resource, path)
            });
            // Repeated reads by one caller can select different file versions.
            let selection = builder.effects_len() as u32;
            let choice = |arm| {
                let mut choice = effinterp_proto::Condition::from_source(
                    path,
                    effinterp_proto::ByteSpan {
                        start: 0,
                        end: path.len() as u32,
                    },
                    effinterp_proto::ConditionKind::Branch,
                    arm,
                    versions.len() as u32 + 2,
                    true,
                    false,
                );
                if let effinterp_proto::Condition::Atom { atom } = &mut choice {
                    atom.origin.ordinal = selection;
                }
                choice
            };
            let input = self.selected_source_inputs.borrow().get(path).cloned();
            let arguments = self.shell_arguments.borrow().clone();
            for (index, (bytes, subject_spans, assumptions)) in versions.iter().enumerate() {
                let limit = if bytes.len() as u64 > self.limits.max_source_bytes {
                    Some("max_source_bytes")
                } else if !self.budget.try_charge_bytes(bytes.len() as u64) {
                    Some("max_analysis_bytes")
                } else {
                    None
                };
                if let Some(limit) = limit {
                    self.record_source_boundary(
                        builder,
                        path,
                        SourcePurpose::InvocationInput,
                        effinterp_proto::ExecutionContent::Unobserved {
                            reason: source_refusal_reason(SourceRefusal::Limit { limit }),
                        },
                        &builder.current_execution_component(),
                    );
                    break;
                }
                let source = String::from_utf8(bytes.clone()).expect("written source is UTF-8");
                let mut alternative = transition.clone();
                if let Some(shell_text) = transition.executable_source {
                    let Some((subject, _, interpreter)) = crate::exec::executable_subject(
                        &source,
                        subject_cwd(&transition.subject),
                        shell_text,
                    ) else {
                        continue;
                    };
                    alternative.subject = subject;
                    if let Some(argument) = alternative.argv.first_mut() {
                        *argument = ResourceExpr::Literal { value: interpreter };
                    }
                } else {
                    match &mut alternative.subject {
                        Subject::Shell { source: text, .. }
                        | Subject::Source { source: text, .. } => *text = source,
                        _ => continue,
                    }
                }
                if let Some(mut input) = input.clone() {
                    input.authorship =
                        set_predicted_source(&mut input.input, bytes, subject_spans.clone());
                    self.selected_source_inputs
                        .borrow_mut()
                        .insert(path.clone(), input);
                }
                let previous =
                    builder.enter_source_read_conditions(std::slice::from_ref(assumptions));
                *self.shell_arguments.borrow_mut() = arguments.clone();
                builder.push_condition(choice(index as u32 + 1));
                self.nest(builder, alternative, provenance, depth);
                builder.pop_condition();
                builder.leave_source_read_conditions(previous);
            }
            *self.shell_arguments.borrow_mut() = arguments;
            if let Some(input) = input {
                self.selected_source_inputs
                    .borrow_mut()
                    .insert(path.clone(), input);
            }
            Some((condition, choice(0)))
        });
        let enters_foreign_realm = builder.is_host_realm()
            && transition
                .realm
                .as_ref()
                .is_some_and(|realm| !realm.is_host());
        if enters_foreign_realm && transition.inherit_environment == EnvironmentInheritance::Inherit
        {
            transition.inherit_environment = EnvironmentInheritance::Isolated;
        }
        let (environment, environment_nodes, environment_unsets, environment_concealed) =
            self.inherited_environment(&transition);
        let source_cwd = transition
            .source_cwd
            .take()
            .unwrap_or_else(|| self.current_source_cwd());
        let runtime_cwd = transition
            .runtime_cwd
            .take()
            .unwrap_or_else(|| self.current_runtime_cwd());
        let cwd_node = if transition.words.is_some() {
            self.current_cwd_node()
        } else {
            transition.cwd_node
        };
        let source_span_offset = transition
            .source_span_offset
            .unwrap_or(builder.current_source_span_offset() as usize);
        let additional_evidence = environment_nodes
            .values()
            .copied()
            .chain(
                transition
                    .argv_provenance
                    .iter()
                    .flatten()
                    .flatten()
                    .copied(),
            )
            .collect::<Vec<_>>();
        let environment_closed = match transition.inherit_environment {
            EnvironmentInheritance::Inherit => self.environment_is_closed(),
            EnvironmentInheritance::Reset => true,
            EnvironmentInheritance::Independent | EnvironmentInheritance::Isolated => false,
        };
        let independent_environment =
            transition.inherit_environment == EnvironmentInheritance::Independent;
        // A shell a language runtime starts is `/bin/sh` unless the call
        // selected another.
        let runtime_shell = transition.runtime_shell.take().or_else(|| {
            (matches!(transition.subject, Subject::Shell { .. })
                && builder.current_execution_is_source())
            .then(|| RuntimeShell::Program("/bin/sh".to_string()))
        });
        let execute_umask = transition.execute_umask_uncertain;
        let js_eval_require_shadowed = transition.js_eval_require_shadowed;
        let resolved = transition.resolve(self, builder, environment);
        if self.record_cycle(builder, &resolved, provenance) {
            return None;
        }
        if let NestedTransitionGuard::Refused = self.guard(builder, &resolved, provenance, depth) {
            return None;
        }
        let origin = resolved.origin.clone();
        let target_realm = resolved.realm.clone();
        let target_mounts = resolved.mounts.clone();
        let (execution, scope) =
            self.record_analyzed(builder, resolved, provenance, &additional_evidence)?;
        if let Some(require_shadowed) = js_eval_require_shadowed {
            builder.record_js_evaluation(execution, require_shadowed);
        }
        if let Some(shell) = runtime_shell {
            builder.record_runtime_shell(execution, shell);
        }
        let source_read_conditions = source_condition.as_ref().map(|(assumptions, _)| {
            builder.enter_source_read_conditions(std::slice::from_ref(assumptions))
        });
        let frame = NestedFrame {
            nest: self,
            scope,
            execution,
            depths: self.stack_depths(),
            builder_depths: builder.nested_stack_depths(),
            source_condition: source_condition.is_some(),
            source_read_conditions,
            execute_umask_before: self.execute_umask_uncertain.get(),
            independent_environment_before: self.independent_environment.get(),
        };
        if independent_environment {
            self.independent_environment.set(true);
        }
        if let Some(value) = execute_umask {
            self.execute_umask_uncertain.set(value);
        }
        if let Some((_, condition)) = source_condition {
            builder.push_condition(condition);
        }
        builder.push_execution(execution);
        builder.push_realm(target_realm);
        self.mounts.borrow_mut().push(target_mounts);
        self.environments
            .borrow_mut()
            .push(builder.execution_environment(execution));
        self.environment_nodes.borrow_mut().push(environment_nodes);
        self.environment_closed
            .borrow_mut()
            .push(environment_closed);
        self.environment_unsets
            .borrow_mut()
            .push(environment_unsets);
        self.environment_concealed
            .borrow_mut()
            .push(environment_concealed);
        self.script_origins.borrow_mut().push(origin);
        self.source_cwds.borrow_mut().push(source_cwd);
        self.runtime_cwds.borrow_mut().push(runtime_cwd);
        self.cwd_nodes.borrow_mut().push(cwd_node);
        builder.push_source_span_offset(
            source_span_offset
                .try_into()
                .expect("source span offset fits u32"),
        );
        Some(frame)
    }

    pub(crate) fn nest(
        &self,
        builder: &mut PlanBuilder,
        mut transition: Transition,
        provenance: &[ProvenanceRef],
        depth: u64,
    ) {
        let subject = transition.subject.clone();
        let shell_text_executable = transition.shell_text_executable;
        let ignores_execute_bit = transition.ignores_execute_bit;
        let words = transition.words.clone();
        let stdin = transition.stdin.clone();
        let argv_provenance = transition.argv_provenance.clone();
        let command_search_path = transition.command_search_path.take();
        let cwd_node = transition.cwd_node;
        let runtime_cwd = transition
            .runtime_cwd
            .clone()
            .unwrap_or_else(|| self.current_runtime_cwd());
        if words.is_some() {
            // Exec analysis threads its cwd explicitly; its source stacks retain the caller namespace.
            transition.source_cwd = None;
            transition.runtime_cwd = None;
        } else {
            transition.cwd = transition.cwd.or_else(|| builder.current_execution_cwd());
            transition.source_span_offset.get_or_insert(0);
        }
        let Some(frame) = self.begin(builder, transition, provenance, depth) else {
            return;
        };
        if let Some(words) = words {
            let effect_start = builder.effects_len() as u32;
            let model_eligible = crate::exec::analyze_exec(
                builder,
                self,
                &words,
                stdin.as_ref(),
                crate::exec::UnresolvedHead::Opaque,
                None,
                argv_provenance.as_deref(),
                subject_cwd(&subject),
                runtime_cwd.as_deref(),
                command_search_path,
                shell_text_executable,
                ignores_execute_bit,
                Some(frame.scope),
                cwd_node,
                depth + 1,
            );
            let effect_end = builder.effects_len() as u32;
            let model_bindings = if model_eligible {
                words
                    .first()
                    .and_then(Word::as_literal)
                    .and_then(|name| {
                        self.catalog
                            .find(&crate::models::program_name(name, subject_cwd(&subject)))
                    })
                    .map(|model| model.causal_bindings(&words))
                    .unwrap_or_default()
            } else {
                Vec::new()
            };
            let spec = crate::flow::StageSpec {
                name: words.first().and_then(Word::as_literal).map(str::to_string),
                words,
                argument_producers: Vec::new(),
                unquoted_substitutions: Vec::new(),
                stdin_value: false,
                execution: Some(frame.execution),
                effect_start,
                effect_end,
                redirs: Vec::new(),
                inherited_redirs: Vec::new(),
                descriptor_operands: Vec::new(),
                span_node: None,
                model_bindings,
                stdout_selections: Vec::new(),
            };
            if crate::flow::needs_single_stage(builder, &spec) {
                crate::flow::build_root_exec_stage(builder, spec, vec![frame.scope]);
            }
        } else {
            analyze_subject(
                builder,
                self,
                &subject,
                Some(frame.scope),
                cwd_node,
                depth + 1,
            );
        }
        frame.end(builder);
    }

    fn record_cycle(
        &self,
        builder: &mut PlanBuilder,
        transition: &ResolvedTransition,
        provenance: &[ProvenanceRef],
    ) -> bool {
        let candidate = execution_node(self, builder, transition.clone(), provenance, None);
        let Some(target) = builder.active_execution(&candidate) else {
            return false;
        };
        let self_launch = (transition.kind == ExecutionEdgeKind::Launch)
            .then(|| self.current_script.borrow().clone())
            .flatten()
            .is_some_and(|(origin, source)| {
                let cwd = match &transition.subject {
                    Subject::Exec { cwd, .. } => cwd.as_deref(),
                    _ => None,
                };
                matches!(transition.subject, Subject::Exec { .. })
                    && crate::shell::literal_child_shell_self_launch(&source, &origin, cwd)
            });
        if self_launch {
            builder.effect(effinterp_proto::Effect {
                request_assurance: effinterp_proto::RequestAssurance::Conservative,
                id: Default::default(),
                operation: effinterp_proto::Operation::new("process.code_execution"),
                resource: ResourceExpr::Concrete {
                    identity: crate::paths::process_identity_with_cwd(
                        &[crate::word::Word::literal("sh")],
                        transition.cwd.clone(),
                    ),
                },
                attributes: BTreeMap::from([
                    (
                        "source".into(),
                        effinterp_proto::AttrValue::String("loop".into()),
                    ),
                    (
                        "process_growth".into(),
                        effinterp_proto::AttrValue::String("unbounded_background_recursion".into()),
                    ),
                ]),
                modality: effinterp_proto::Modality::May,
                realm: transition.realm.clone(),
                condition: None,
                execution: effinterp_proto::ExecutionNodeRef(0),
                provenance: provenance.to_vec(),
            });
        }
        builder.execution_edge(target, transition.kind, true, provenance);
        degrade_nested(builder);
        let boundary = builder.boundary(Boundary {
            reason: BoundaryReason::EXECUTION_CYCLE,
            class: BoundaryClass::Limit,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: KNOWN_DOMAINS
                .iter()
                .map(|domain| Domain::new(*domain))
                .collect(),
            provenance: provenance.to_vec(),
            limit: None,
            detail: Some("exact execution context re-entered an active node".to_string()),
        });
        let mut widened = candidate;
        widened.boundary = Some(boundary);
        widened.assurance = ExecutionAssurance::Widened;
        if let Some(widened) = builder.execution_node(widened) {
            builder.execution_edge(widened, ExecutionEdgeKind::Widening, false, provenance);
        }
        true
    }

    pub(crate) fn unresolved_exec(
        &self,
        builder: &mut PlanBuilder,
        words: &[Word],
        provenance: &[ProvenanceRef],
        boundary: BoundaryRef,
        realm: ExecutionRealm,
        kind: ExecutionEdgeKind,
    ) {
        if words.is_empty() {
            return;
        }
        let mut request =
            Transition::exec(words.iter().map(word_resource).collect(), words.to_vec())
                .kind(kind)
                .realm(realm)
                .mounts(Vec::new())
                .streams(builder.inherited_execution_streams())
                .assurance(ExecutionAssurance::Widened);
        if builder.is_host_realm() && request.realm.as_ref().is_some_and(|realm| !realm.is_host()) {
            request.inherit_environment = EnvironmentInheritance::Isolated;
        }
        let (environment, _, _, _) = self.inherited_environment(&request);
        let transition = request.resolve(self, builder, environment);
        let Some(node) = builder.execution_node(execution_node(
            self,
            builder,
            transition,
            provenance,
            Some(boundary),
        )) else {
            return;
        };
        builder.execution_edge(node, kind, false, provenance);
    }
}

fn set_predicted_source(
    input: &mut effinterp_proto::ExecutionInput,
    bytes: &[u8],
    subject_spans: Vec<effinterp_proto::ByteSpan>,
) -> SourceAuthorship {
    let written_from_subject = matches!(subject_spans.as_slice(), [span]
        if span.start == 0 && span.end as usize == bytes.len());
    input.content = effinterp_proto::ExecutionContent::Predicted {
        digest: effinterp_proto::content_digest(bytes),
        written_from_subject,
    };
    if written_from_subject {
        SourceAuthorship::Subject
    } else if subject_spans.is_empty() || bytes.contains(&0) {
        // Shell interpretation drops NUL bytes, so the raw ranges would drift.
        SourceAuthorship::External
    } else {
        SourceAuthorship::Mixed(subject_spans.into())
    }
}

fn inferred_kind(subject: &Subject) -> ExecutionEdgeKind {
    match subject {
        Subject::Exec { .. } => ExecutionEdgeKind::Launch,
        Subject::Sql { .. } => ExecutionEdgeKind::DatabaseClient,
        Subject::Shell { .. } => ExecutionEdgeKind::Script,
        Subject::Source { .. } => ExecutionEdgeKind::Interpreter,
        Subject::ToolCall { .. } => ExecutionEdgeKind::ToolModel,
    }
}

/// The working directory a subject names, if any; SQL subjects have none.
pub(crate) fn subject_cwd(subject: &Subject) -> Option<&str> {
    match subject {
        Subject::Exec { cwd, .. }
        | Subject::Shell { cwd, .. }
        | Subject::Source { cwd, .. }
        | Subject::ToolCall { cwd, .. } => cwd.as_deref(),
        Subject::Sql { .. } => None,
    }
}

fn execution_node(
    nest: &Nest,
    builder: &PlanBuilder,
    transition: ResolvedTransition,
    provenance: &[ProvenanceRef],
    boundary: Option<BoundaryRef>,
) -> ExecutionNode {
    let mut evidence = provenance.to_vec();
    evidence.extend(transition.cwd_node);
    ExecutionNode {
        subject: transition.subject,
        boundary,
        argv: transition.argv,
        cwd: transition.cwd,
        environment: transition.environment,
        streams: transition.streams,
        prints_completion: transition.prints_completion,
        mounts: transition.mounts,
        source_span: builder.source_span(provenance),
        realm: transition.realm,
        assurance: transition.assurance,
        evidence,
        input: transition.origin.as_ref().and_then(|path| {
            nest.selected_source_inputs
                .borrow()
                .get(path)
                .map(|source| source.input.clone())
        }),
    }
}

/// A descriptor path as text: literal parts, with an allocated descriptor
/// spelled by the parameter that stands for its number.
fn descriptor_path_text(word: &Word) -> Option<String> {
    word.parts
        .iter()
        .map(|part| match part {
            crate::word::WordPart::Literal(text) => Some(text.as_str()),
            crate::word::WordPart::Value(ResourceExpr::Parameter { name }) => Some(name.as_str()),
            _ => None,
        })
        .collect()
}

/// Preserve literal and symbolic launch operands when a frontend spawns a process.
pub(crate) fn argument_word(resource: &ResourceExpr) -> Word {
    use crate::word::WordPart;
    match resource {
        ResourceExpr::Literal { value } => Word::literal(value),
        ResourceExpr::Concrete {
            identity: effinterp_proto::ResourceIdentity::FsPath { path },
        } => Word::literal(path),
        ResourceExpr::Environment { name } => Word::new(vec![WordPart::Env(name.clone())]),
        ResourceExpr::Parameter { .. } => Word::new(vec![WordPart::Value(resource.clone())]),
        ResourceExpr::Join { parts } => Word::new(
            parts
                .iter()
                .flat_map(|part| argument_word(part).parts)
                .collect(),
        ),
        ResourceExpr::Union { alternatives } => Word::new(vec![WordPart::Union(
            alternatives.iter().map(argument_word).collect(),
        )]),
        _ => Word::new(vec![WordPart::Unknown]),
    }
}

/// The `environment_nodes` key recording a wrapper that injects variables
/// under names it does not state. No variable is named `*`, and the key is
/// inherited, replaced and cleared with the environment like a named node.
pub(crate) const INJECTED_ENVIRONMENT: &str = "*";

pub(crate) fn word_resource(word: &Word) -> ResourceExpr {
    if let [crate::word::WordPart::Union(alternatives)] = word.parts.as_slice() {
        return ResourceExpr::Union {
            alternatives: alternatives.iter().map(word_resource).collect(),
        };
    }
    let mut parts = word.parts.iter().map(|part| match part {
        crate::word::WordPart::Literal(value) => ResourceExpr::Literal {
            value: value.clone(),
        },
        crate::word::WordPart::Env(name) => ResourceExpr::Environment { name: name.clone() },
        crate::word::WordPart::Value(value) => value.clone(),
        crate::word::WordPart::Glob(pattern) => ResourceExpr::Pattern {
            pattern: effinterp_proto::ResourcePattern::FsPath {
                glob: pattern.clone(),
                narrowing: Default::default(),
            },
        },
        crate::word::WordPart::Union(alternatives) => ResourceExpr::Union {
            alternatives: alternatives.iter().map(word_resource).collect(),
        },
        crate::word::WordPart::Unknown => unresolved_resource("value"),
    });
    let Some(first) = parts.next() else {
        return ResourceExpr::Literal {
            value: String::new(),
        };
    };
    let rest: Vec<_> = parts.collect();
    if rest.is_empty() {
        first
    } else {
        let mut all = vec![first];
        all.extend(rest);
        ResourceExpr::Join { parts: all }
    }
}

fn execution_assurance(word: &Word) -> ExecutionAssurance {
    if word.as_literal().is_some() {
        ExecutionAssurance::Exact
    } else if word
        .parts
        .iter()
        .any(|part| matches!(part, crate::word::WordPart::Unknown))
    {
        ExecutionAssurance::Widened
    } else if word.parts.iter().any(|part| {
        matches!(
            part,
            crate::word::WordPart::Glob(_) | crate::word::WordPart::Union(_)
        )
    }) {
        ExecutionAssurance::Alternatives
    } else {
        ExecutionAssurance::Heuristic
    }
}

fn translate_mount(path: &str, mounts: &[ContainerStorage]) -> Option<String> {
    for mount in mounts {
        let ContainerStorage::BindMount {
            host_path:
                ResourceExpr::Concrete {
                    identity: effinterp_proto::ResourceIdentity::FsPath { path: host },
                },
            container_path:
                ResourceExpr::Concrete {
                    identity: effinterp_proto::ResourceIdentity::FsPath { path: container },
                },
            ..
        } = mount
        else {
            continue;
        };
        if path == container {
            return Some(host.clone());
        }
        if let Some(suffix) = path
            .strip_prefix(container)
            .and_then(|value| value.strip_prefix('/'))
        {
            return Some(effinterp_proto::normalize_path(
                &format!("{host}/{suffix}"),
                effinterp_proto::PathPlatform::Posix,
            ));
        }
    }
    None
}

/// Route a subject to its frontend.
pub(crate) fn analyze_subject(
    builder: &mut PlanBuilder,
    nest: &Nest,
    subject: &Subject,
    scope: Option<ProvenanceRef>,
    cwd_node: Option<ProvenanceRef>,
    depth: u64,
) {
    if nest.budget.timed_out() {
        builder.note_deadline();
        return;
    }
    let first_effect = builder.effects_len();
    match subject {
        Subject::Exec { argv, cwd, .. } => {
            let words: Vec<Word> = argv.iter().map(Word::literal).collect();
            let runtime_cwd = nest.current_runtime_cwd();
            let effect_start = builder.effects_len() as u32;
            let model_eligible = crate::exec::analyze_exec(
                builder,
                nest,
                &words,
                None,
                crate::exec::UnresolvedHead::Opaque,
                None,
                None,
                cwd.as_deref(),
                runtime_cwd.as_deref(),
                None,
                false,
                false,
                scope,
                cwd_node,
                depth,
            );
            let effect_end = builder.effects_len() as u32;
            let name = words
                .first()
                .and_then(Word::as_literal)
                .map(|name| crate::models::program_name(name, cwd.as_deref()))
                .and_then(|name| name.rsplit('/').next().map(str::to_string));
            let model_bindings = if model_eligible {
                {
                    name.as_deref()
                        .and_then(|name| nest.catalog.find(name))
                        .map(|model| model.causal_bindings(&words))
                        .unwrap_or_default()
                }
            } else {
                Default::default()
            };
            let spec = crate::flow::StageSpec {
                name,
                words,
                argument_producers: Vec::new(),
                unquoted_substitutions: Vec::new(),
                stdin_value: false,
                execution: Some(builder.current_execution()),
                effect_start,
                effect_end,
                redirs: Vec::new(),
                inherited_redirs: Vec::new(),
                descriptor_operands: Vec::new(),
                span_node: None,
                model_bindings,
                stdout_selections: Vec::new(),
            };
            if crate::flow::needs_single_stage(builder, &spec) {
                crate::flow::build_root_exec_stage(builder, spec, scope.into_iter().collect());
            }
        }
        Subject::Shell { source, cwd, .. } => {
            crate::shell::analyze_shell(
                builder,
                nest,
                source,
                cwd.as_deref(),
                cwd_node,
                scope,
                depth,
            );
        }
        Subject::Sql {
            source,
            dialect,
            connection,
        } => {
            crate::sql::analyze_sql(builder, nest, source, *dialect, connection, scope, depth);
        }
        Subject::Source {
            language,
            dialect,
            source,
            ..
        } => {
            let source_cwd = nest.current_source_cwd();
            let runtime_cwd = nest.current_runtime_cwd();
            crate::lang::analyze(
                builder,
                nest,
                language,
                *dialect,
                source,
                source_cwd.as_deref(),
                runtime_cwd.as_deref(),
                cwd_node,
                scope,
                depth,
            );
        }
        Subject::ToolCall { .. } => {
            crate::toolcall::analyze_tool_call(builder, nest, subject, depth);
        }
    }
    if !nest.budget.timed_out() {
        nest.catalog
            .apply_library_apis(builder, subject, first_effect);
    }
}

/// An executed input refused at the depth bound may hold any program, however
/// it was reached: launched, sourced, fed on stdin or captured. A size refusal
/// counts only for a launched script, because an executable named by path may
/// be a large binary.
fn note_unread_executed_input(
    builder: &mut PlanBuilder,
    purpose: SourcePurpose,
    refusal: SourceRefusal,
) {
    let unread = match refusal {
        SourceRefusal::Limit {
            limit: "max_execution_depth",
        } => true,
        SourceRefusal::Limit {
            limit: "max_source_bytes",
        } => purpose == SourcePurpose::LaunchedScript,
        _ => false,
    };
    if unread {
        builder.note_executed_input_limit();
    }
}

pub(crate) fn source_refusal_reason(
    refusal: SourceRefusal,
) -> effinterp_proto::ExecutionInputReason {
    use crate::UnavailableReason;
    use effinterp_proto::ExecutionInputReason;
    match refusal {
        SourceRefusal::Limit {
            limit: "max_source_bytes",
        } => ExecutionInputReason::Oversize,
        SourceRefusal::Limit { limit } => ExecutionInputReason::BudgetRefused {
            limit: limit.to_string(),
        },
        SourceRefusal::Unavailable(reason) => match reason {
            UnavailableReason::Missing => ExecutionInputReason::Missing,
            UnavailableReason::Escapes => ExecutionInputReason::Escapes,
            UnavailableReason::NotAFile => ExecutionInputReason::NotAFile,
            UnavailableReason::PermissionDenied => ExecutionInputReason::PermissionDenied,
            UnavailableReason::DependencyDenied => ExecutionInputReason::DependencyNotTraversed,
            UnavailableReason::NamespaceDenied => ExecutionInputReason::NamespaceDenied,
            UnavailableReason::Stale => ExecutionInputReason::Stale,
            UnavailableReason::Mismatched => ExecutionInputReason::Mismatched,
            UnavailableReason::Ambiguous => ExecutionInputReason::Ambiguous,
        },
    }
}
