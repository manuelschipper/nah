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

use crate::builder::{KNOWN_DOMAINS, PlanBuilder, RuntimeShell};
use crate::limits::AnalysisLimits;
use crate::models::{Catalog, StdinValue};
use crate::value::unresolved_resource;
use crate::word::Word;
use crate::{
    SourceNamespace, SourcePurpose, SourceRefusal, SourceRequest, SourceResolver, SourceResponse,
};

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
    /// Concrete paths whose own entry a modeled operation already created,
    /// renamed, or removed. A later identity that passes through one of them
    /// can no longer rely on the initial observation.
    topology_mutations: RefCell<BTreeSet<String>>,
    /// A modeled topology change the analysis could not pin to one path.
    topology_unknown: Cell<bool>,
    /// Concrete paths a modeled write reached. A write can create the entry
    /// it names, so a directory above one no longer holds what its initial
    /// listing says. Path facts keep their own rule: a write to an existing
    /// entry leaves its identity as observed.
    written_paths: RefCell<BTreeSet<String>>,
    /// A modeled write the analysis could not pin to one path.
    written_unknown: Cell<bool>,
    /// How many steps the analysis could not model on the host filesystem;
    /// any of them may have written anywhere.
    unmodeled_steps: Cell<usize>,
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

/// Full budget state, saved around a speculative walk and restored by
/// [`Budget::restore`] so measurement consumes nothing.
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
            topology_mutations: RefCell::new(BTreeSet::new()),
            topology_unknown: Cell::new(false),
            written_paths: RefCell::new(BTreeSet::new()),
            written_unknown: Cell::new(false),
            unmodeled_steps: Cell::new(0),
            cancelled: Cell::new(false),
            finalizing: Cell::new(false),
            steps: Cell::new(0),
            retained_bytes: Cell::new(0),
            state_scan_entries: Cell::new(0),
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
        }
    }

    /// Invocations charged since `snap` was taken.
    pub(crate) fn consumed_since(&self, snap: &BudgetSnapshot) -> u64 {
        self.nodes.get() - snap.nodes
    }

    pub(crate) fn restore(&self, snap: BudgetSnapshot) {
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
    /// evidence about the state the later operation meets.
    pub(crate) fn note_topology_mutation(&self, path: Option<&str>) {
        match path {
            Some(path) => {
                self.topology_mutations
                    .borrow_mut()
                    .insert(path.to_string());
            }
            None => self.topology_unknown.set(true),
        }
    }

    /// Record that a modeled write reached `path`, or an unknown path.
    pub(crate) fn note_write(&self, path: Option<&str>) {
        match path {
            Some(path) => {
                self.written_paths.borrow_mut().insert(path.to_string());
            }
            None => self.written_unknown.set(true),
        }
    }

    /// Record a step the analysis could not model on the host filesystem.
    pub(crate) fn note_unmodeled(&self) {
        self.unmodeled_steps.set(self.unmodeled_steps.get() + 1);
    }

    /// How many steps so far the analysis could not model on the host
    /// filesystem.
    pub(crate) fn unmodeled_steps(&self) -> usize {
        self.unmodeled_steps.get()
    }

    /// Whether an initial fact about `path` still describes the state a use
    /// meets. Checked on every use, including one answered from the cache.
    fn observation_invalidated(&self, path: &str) -> Option<ObservationRefusal> {
        if self.topology_unknown.get() {
            return Some(ObservationRefusal::Ambiguous);
        }
        self.topology_mutations
            .borrow()
            .iter()
            .any(|mutated| {
                path == mutated || path.starts_with(&format!("{}/", mutated.trim_end_matches('/')))
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
        let beneath = format!("{}/", path.trim_end_matches('/'));
        if self.written_unknown.get()
            || unmodeled_before > 0
            || self
                .topology_mutations
                .borrow()
                .iter()
                .any(|changed| changed.starts_with(&beneath))
            || self.written_paths.borrow().iter().any(|written| {
                // A write to the directory itself or an ancestor can be a
                // recursive copy that fills it.
                let written = format!("{}/", written.trim_end_matches('/'));
                beneath.starts_with(&written) || written.starts_with(&beneath)
            })
        {
            return ObservationOutcome::Refused(ObservationRefusal::Stale);
        }
        let outcome = self.observe(ObservationQuery::Listing {
            path: path.to_string(),
            depth,
        });
        if let ObservationOutcome::Listing(fact) = &outcome
            && self.changed_under_another_name(&fact.directory)
        {
            return ObservationOutcome::Refused(ObservationRefusal::Stale);
        }
        outcome
    }

    /// Whether a modeled write or topology change spelled another way, as
    /// through a link or `/tmp` for `/private/tmp`, reaches the canonical
    /// `directory`, lies beneath it or above it. A path whose canonical
    /// identity the host does not establish counts as reaching it.
    fn changed_under_another_name(&self, directory: &str) -> bool {
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
        // A write leaves its path's initial fact standing, so the path itself
        // is asked. A topology change makes that fact stale, so its parent is
        // asked and the name joined beneath it.
        self.written_paths
            .borrow()
            .iter()
            .any(|path| reaches(identities(path)))
            || self.topology_mutations.borrow().iter().any(|path| {
                let Some((parent, name)) = path.trim_end_matches('/').rsplit_once('/') else {
                    return true;
                };
                let parent = if parent.is_empty() { "/" } else { parent };
                reaches(identities(parent).map(|parents| {
                    parents
                        .iter()
                        .map(|parent| format!("{}/{name}", parent.trim_end_matches('/')))
                        .collect()
                }))
            })
    }

    fn observe(&self, query: ObservationQuery) -> ObservationOutcome {
        let (ObservationQuery::Path { path } | ObservationQuery::Listing { path, .. }) = &query;
        if !effinterp_proto::valid_observation_query(&query) {
            return ObservationOutcome::Refused(ObservationRefusal::Invalid);
        }
        if let Some(refusal) = self.observation_invalidated(path) {
            return ObservationOutcome::Refused(refusal);
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
        if self.observation_requests.get() >= self.max_observation_requests {
            return ObservationOutcome::Refused(ObservationRefusal::Limit {
                limit: "max_observation_requests".to_string(),
            });
        }
        self.observation_requests
            .set(self.observation_requests.get() + 1);
        let outcome = resolver.observe(
            &query,
            crate::ObservationBudget {
                remaining_requests: self
                    .max_observation_requests
                    .saturating_sub(self.observation_requests.get()),
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

/// The analysis environment threaded through frontends and models: the model
/// catalog, configured limits, and the shared budget.
pub(crate) struct Nest<'a> {
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
    /// Manifest scripts and Make recipes cannot admit files reached from their text.
    pub source_resolution_disabled: Cell<bool>,
    /// The origin and text of the `package.json` whose script is being
    /// followed. A package manager run from that script's text reads the same
    /// manifest when its runtime cwd resolves to it, so that run may reuse it
    /// once; it is cleared while the nested script runs.
    pub package_manifest: RefCell<Option<(String, String)>>,
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
    /// Evidence from admitted buffers, copied into nested execution without
    /// reopening the source.
    pub selected_source_inputs: RefCell<BTreeMap<String, effinterp_proto::ExecutionInput>>,
    /// Distinct invocation-selected source paths admitted during this plan.
    pub resolved_invocation_sources: RefCell<BTreeSet<String>>,
    /// Argv words after a `sh -c CODE` script, with their argument nodes:
    /// `$0`, `$1`, ... of the shell about to be analyzed. Set around exactly
    /// one nested shell transition and taken by that shell's analysis.
    pub shell_arguments: RefCell<Option<Vec<(Word, ProvenanceRef)>>>,
    /// The shell analyzing the current command entered its cwd physically, so
    /// the PWD a nested shell inherits names the physical directory.
    pub physical_cwd: Cell<bool>,
    /// Import search roots for the next nested Python program. Set around
    /// exactly one Python transition and taken by that program's walk.
    pub python_import_search: RefCell<Option<crate::python::PythonImportSearch>>,
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

enum SourceCandidate {
    Source(Vec<u8>),
    /// Bytes written earlier in this invocation.
    Written(Vec<u8>),
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
    mounts: Vec<ContainerStorage>,
    realm: ExecutionRealm,
    assurance: ExecutionAssurance,
    origin: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum EnvironmentInheritance {
    Inherit,
    Reset,
    // A foreign realm starts without host mutations or explicit host unsets.
    Isolated,
}

/// A nested execution request. Unspecified attributes inherit their current scope.
pub(crate) struct Transition {
    subject: Subject,
    words: Option<Vec<Word>>,
    argv: Vec<ResourceExpr>,
    kind: ExecutionEdgeKind,
    origin: Option<String>,
    source_cwd: Option<Option<String>>,
    runtime_cwd: Option<Option<String>>,
    cwd: Option<ResourceExpr>,
    cwd_node: Option<ProvenanceRef>,
    environment: BTreeMap<String, Option<ResourceExpr>>,
    environment_nodes: BTreeMap<String, ProvenanceRef>,
    environment_unsets: BTreeSet<String>,
    environment_concealed: BTreeSet<String>,
    inherit_environment: EnvironmentInheritance,
    realm: Option<ExecutionRealm>,
    mounts: Option<Vec<ContainerStorage>>,
    streams: Option<ExecutionStreams>,
    assurance: ExecutionAssurance,
    source_span_offset: Option<usize>,
    stdin: Option<StdinValue>,
    argv_provenance: Option<Vec<Vec<ProvenanceRef>>>,
    runtime_shell: Option<RuntimeShell>,
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
            source_cwd: None,
            runtime_cwd: None,
            cwd: None,
            cwd_node: None,
            environment: BTreeMap::new(),
            environment_nodes: BTreeMap::new(),
            environment_unsets: BTreeSet::new(),
            environment_concealed: BTreeSet::new(),
            inherit_environment: EnvironmentInheritance::Inherit,
            realm: None,
            mounts: None,
            streams: None,
            assurance: ExecutionAssurance::Exact,
            source_span_offset: None,
            stdin: None,
            argv_provenance: None,
            runtime_shell: None,
        }
    }

    /// The shell a language runtime selected for this shell subject, when it
    /// overrides the runtime's default `/bin/sh`.
    pub(crate) fn runtime_shell(mut self, shell: Option<RuntimeShell>) -> Self {
        self.runtime_shell = shell;
        self
    }

    pub(crate) fn argv(mut self, argv: Vec<ResourceExpr>) -> Self {
        self.argv = argv;
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
                subject_cwd(&self.subject).map(|cwd| crate::paths::resolve_fs_path(cwd, None))
            }),
            subject: self.subject,
            kind: self.kind,
            argv: self.argv,
            cwd_node: self.cwd_node,
            environment,
            streams,
            mounts: self
                .mounts
                .unwrap_or_else(|| nest.mounts.borrow().last().cloned().unwrap_or_default()),
            realm: self.realm.unwrap_or_else(|| builder.current_realm()),
            assurance: self.assurance,
            origin: self.origin,
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
}

impl NestedFrame<'_> {
    pub(crate) fn end(self, builder: &mut PlanBuilder) {
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
    /// Whether nested shells must preserve overrides of supplied host values.
    pub(crate) fn tracks_host_context_environment(&self) -> bool {
        self.context
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
        self.context
            .and_then(|context| context.env.get(name))
            .map(|value| ResourceExpr::Literal {
                value: value.clone(),
            })
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
                self.context
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
        let namespace = self.current_source_cwd().map_or_else(
            || {
                if host_path.starts_with('/') {
                    SourceNamespace::Host
                } else {
                    SourceNamespace::Repository
                }
            },
            |source_cwd| {
                if source_cwd.starts_with('/') {
                    SourceNamespace::Host
                } else {
                    SourceNamespace::Repository
                }
            },
        );
        self.resolve_source_selection(builder, host_path, namespace, purpose, component)
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
            SourceCandidate::Source(bytes) => {
                self.admit_execution_source(builder, path, bytes, false, input)
            }
            SourceCandidate::Written(bytes) => {
                self.admit_execution_source(builder, path, bytes, true, input)
            }
            SourceCandidate::Refused(refusal) => {
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
        mut input: effinterp_proto::ExecutionInput,
        record_missing: bool,
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
        for (index, (namespace, path)) in candidates.iter().enumerate() {
            if builder.runtime_input_recorded(path, &input)
                || (purpose == SourcePurpose::DependencySource
                    && builder.dependency_source_recorded(path))
            {
                return (SourceResolution::AlreadySelected, false);
            }
            match self.resolve_source_candidate(builder, path, *namespace, purpose) {
                candidate @ (SourceCandidate::Source(_) | SourceCandidate::Written(_)) => {
                    let (bytes, written) = match candidate {
                        SourceCandidate::Source(bytes) => (bytes, false),
                        SourceCandidate::Written(bytes) => (bytes, true),
                        _ => unreachable!(),
                    };
                    input.selected = Some(resources[index].clone());
                    input.selection = ExecutionSelection::Search {
                        candidates: resources,
                        selected: Some(index as u32),
                    };
                    return (
                        self.admit_execution_source(builder, path.clone(), bytes, written, input),
                        false,
                    );
                }
                SourceCandidate::Refused(SourceRefusal::Unavailable(
                    crate::UnavailableReason::Missing | crate::UnavailableReason::NotAFile,
                )) => {}
                SourceCandidate::Refused(refusal) => {
                    input.assurance = ExecutionAssurance::Widened;
                    input.content = ExecutionContent::Unobserved {
                        reason: source_refusal_reason(refusal),
                    };
                    self.record_input_boundary(builder, path, input);
                    return (SourceResolution::Refused(refusal), false);
                }
                SourceCandidate::ResolverUnavailable => {
                    input.assurance = ExecutionAssurance::Widened;
                    self.record_input_boundary(builder, path, input);
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
            self.record_input_boundary(builder, &request, input);
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
                SourceCandidate::Written(_) => {
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

    fn resolve_source_candidate(
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
        let written = builder.written_source(path, |resource, path| {
            self.source_mutation_may_alias(resource, path)
        });
        if self.budget.timed_out() {
            return SourceCandidate::Refused(SourceRefusal::Limit {
                limit: "invocation_deadline",
            });
        }
        match written {
            crate::builder::WrittenSource::Host => {}
            crate::builder::WrittenSource::Exact(bytes) => {
                return if bytes.len() as u64 > self.limits.max_source_bytes {
                    SourceCandidate::Refused(SourceRefusal::Limit {
                        limit: "max_source_bytes",
                    })
                } else if !self.budget.try_charge_bytes(bytes.len() as u64) {
                    SourceCandidate::Refused(SourceRefusal::Limit {
                        limit: "max_analysis_bytes",
                    })
                } else {
                    SourceCandidate::Written(bytes)
                };
            }
            crate::builder::WrittenSource::Stale => {
                return SourceCandidate::Refused(SourceRefusal::Unavailable(
                    crate::UnavailableReason::Stale,
                ));
            }
            crate::builder::WrittenSource::Ambiguous => {
                return SourceCandidate::Refused(SourceRefusal::Unavailable(
                    crate::UnavailableReason::Ambiguous,
                ));
            }
        }
        let Some(resolver) = self.resolver else {
            return SourceCandidate::ResolverUnavailable;
        };
        self.resolved_invocation_sources
            .borrow_mut()
            .insert(path.to_string());
        let response = resolver.resolve(SourceRequest {
            path,
            namespace,
            purpose,
            requester_language: builder.current_source_language(),
        });
        if self.budget.timed_out() {
            return SourceCandidate::Refused(SourceRefusal::Limit {
                limit: "invocation_deadline",
            });
        }
        match response {
            SourceResponse::Source(bytes) => {
                let limit = if bytes.len() as u64 > self.limits.max_source_bytes {
                    Some("max_source_bytes")
                } else if !self.budget.try_charge_bytes(bytes.len() as u64) {
                    Some("max_analysis_bytes")
                } else {
                    None
                };
                if let Some(limit) = limit {
                    SourceCandidate::Refused(SourceRefusal::Limit { limit })
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
        bytes: Vec<u8>,
        written: bool,
        mut input: effinterp_proto::ExecutionInput,
    ) -> SourceResolution {
        let digest = effinterp_proto::content_digest(&bytes);
        input.content = if written {
            effinterp_proto::ExecutionContent::Predicted { digest }
        } else {
            effinterp_proto::ExecutionContent::Observed { digest }
        };
        self.selected_source_inputs
            .borrow_mut()
            .insert(path.clone(), input.clone());
        match String::from_utf8(bytes) {
            Ok(source) => SourceResolution::Source {
                origin: path,
                source,
            },
            Err(_) => {
                self.record_input_boundary(builder, &path, input);
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

    /// Follow explicit dependency paths only in invocation-selected source. Bare
    /// names retain their runtime-search boundary; the index owns module linking.
    pub(crate) fn follow_dependency(
        &self,
        builder: &mut PlanBuilder,
        specifier: &str,
        language: &str,
    ) {
        if !builder.current_execution_is_selected_input() {
            return;
        }
        if self.resolver.is_none()
            || self.source_resolution_disabled.get()
            || !crate::dependency_calls::is_path_specifier(specifier)
        {
            self.record_dependency_request(builder, specifier);
            return;
        }
        let mut paths = vec![specifier.to_string()];
        if std::path::Path::new(specifier).extension().is_none() {
            for suffix in match language {
                "js" => &[".js", ".cjs", ".mjs", ".ts", "/index.js"][..],
                "ruby" => &[".rb"][..],
                _ => &[],
            } {
                paths.push(format!("{specifier}{suffix}"));
            }
        }
        let mut candidates = paths
            .iter()
            .filter_map(|path| {
                crate::paths::join_source_path(self.current_source_cwd().as_deref(), path)
            })
            .collect::<Vec<_>>();
        if !builder.is_host_realm() {
            let mounts = self.mounts.borrow().last().cloned().unwrap_or_default();
            for (namespace, path) in &mut candidates {
                let Some(host_path) = translate_mount(path, &mounts) else {
                    self.record_source_boundary(
                        builder,
                        path,
                        SourcePurpose::DependencySource,
                        effinterp_proto::ExecutionContent::Unobserved {
                            reason: effinterp_proto::ExecutionInputReason::NamespaceDenied,
                        },
                        &builder.current_execution_component(),
                    );
                    return;
                };
                *namespace = if host_path.starts_with('/') {
                    SourceNamespace::Host
                } else {
                    SourceNamespace::Repository
                };
                *path = host_path;
            }
        }
        let input = self.source_input(
            builder,
            specifier,
            SourcePurpose::DependencySource,
            effinterp_proto::ExecutionContent::Unobserved {
                reason: effinterp_proto::ExecutionInputReason::ResolverUnavailable,
            },
            &builder.current_execution_component(),
        );
        let (resolved, _) = self.resolve_execution_search(
            builder,
            candidates,
            SourcePurpose::DependencySource,
            input,
            true,
        );
        if let SourceResolution::Source { origin, source } = resolved {
            let parent = crate::paths::parent_dir(&origin);
            let dialect = (language == "js").then(|| crate::models::nodeexec::js_dialect(&origin));
            self.dependency_calls.record_followed(
                crate::dependency_calls::DependencyRequestKey {
                    source_cwd: self.current_source_cwd(),
                    language: if language == "js" { "js" } else { "ruby" },
                    specifier: specifier.to_string(),
                },
                crate::dependency_calls::FollowedDependency {
                    launch: builder.current_dependency_launch(),
                    path: origin.clone(),
                    digest: effinterp_proto::content_digest(source.as_bytes()),
                    lang: match dialect {
                        Some(dialect) => crate::Lang::Js(dialect),
                        None => crate::Lang::Ruby,
                    },
                    source: source.clone(),
                },
            );
            let argv = builder.current_execution_argv().to_vec();
            let evidence = builder.current_execution_evidence().to_vec();
            let depth = builder.execution_depth() - 1;
            self.nest(
                builder,
                Transition::file(Subject::Source {
                    language: language.to_string(),
                    source,
                    dialect,
                    cwd: self.current_runtime_cwd(),
                    context: Default::default(),
                })
                .kind(ExecutionEdgeKind::Import)
                .origin(origin)
                .source_cwd(Some(&parent))
                .argv(argv),
                &evidence,
                depth,
            );
        }
    }

    pub(crate) fn record_dependency_request(&self, builder: &mut PlanBuilder, specifier: &str) {
        if !builder.current_execution_is_selected_input()
            || builder.dependency_request_recorded(specifier)
        {
            return;
        }
        let mut input = self.source_input(
            builder,
            specifier,
            SourcePurpose::DependencySource,
            effinterp_proto::ExecutionContent::Unobserved {
                reason: effinterp_proto::ExecutionInputReason::DependencyNotTraversed,
            },
            &builder.current_execution_component(),
        );
        // Package names require runtime search. Only a literal path request
        // with an explicit extension identifies a candidate without opening it.
        input.selected = if specifier.starts_with('/')
            || (specifier.starts_with('.') && std::path::Path::new(specifier).extension().is_some())
        {
            crate::paths::join_source_path(self.current_source_cwd().as_deref(), specifier).map(
                |(_, path)| ResourceExpr::Concrete {
                    identity: effinterp_proto::ResourceIdentity::FsPath { path },
                },
            )
        } else {
            None
        };
        self.record_input_boundary(builder, specifier, input);
    }

    pub(crate) fn record_unsupported_source(&self, builder: &mut PlanBuilder, path: &str) {
        let input = self
            .selected_source_inputs
            .borrow()
            .get(path)
            .cloned()
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
            self.context
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
            self.context
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
            EnvironmentInheritance::Isolated => false,
        };
        // A shell a language runtime starts is `/bin/sh` unless the call
        // selected another.
        let runtime_shell = transition.runtime_shell.take().or_else(|| {
            (matches!(transition.subject, Subject::Shell { .. })
                && builder.current_execution_is_source())
            .then(|| RuntimeShell::Program("/bin/sh".to_string()))
        });
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
        if let Some(shell) = runtime_shell {
            builder.record_runtime_shell(execution, shell);
        }
        let frame = NestedFrame {
            nest: self,
            scope,
            execution,
            depths: self.stack_depths(),
            builder_depths: builder.nested_stack_depths(),
        };
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
        let words = transition.words.clone();
        let stdin = transition.stdin.clone();
        let argv_provenance = transition.argv_provenance.clone();
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
                None,
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
        mounts: transition.mounts,
        source_span: builder.source_span(provenance),
        realm: transition.realm,
        assurance: transition.assurance,
        evidence,
        input: transition
            .origin
            .as_ref()
            .and_then(|path| nest.selected_source_inputs.borrow().get(path).cloned()),
    }
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
            UnavailableReason::DependencyDenied => ExecutionInputReason::DependencyNotTraversed,
            UnavailableReason::NamespaceDenied => ExecutionInputReason::NamespaceDenied,
            UnavailableReason::Stale => ExecutionInputReason::Stale,
            UnavailableReason::Mismatched => ExecutionInputReason::Mismatched,
            UnavailableReason::Ambiguous => ExecutionInputReason::Ambiguous,
        },
    }
}
