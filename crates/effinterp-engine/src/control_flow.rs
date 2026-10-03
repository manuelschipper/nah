//! Required-on-success reachability.
//!
//! `must-on-success` means that every modeled normally completing path from
//! the analyzed entry reaches an interaction occurrence. It never means that
//! the operation succeeds, commits, or leaves the resource in any state.
//!
//! Each analyzed callable gets a small effect-directed graph derived from its
//! syntax: an entry, call and sink sites in evaluation order, branch joins,
//! loop backedges, and exits. The frontend's existing walk then registers what
//! it learned at a site's source span: which effect or call occurrences the
//! site produced, whether it may leave through unknown code, and whether it
//! returns at all. A site nothing registered is unknown code, so a missed
//! registration can only lose necessity. A forward must-set fixpoint then
//! intersects the facts over every reachable successful exit.

use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use effinterp_proto::{ExecutionEdge, ExecutionEdgeKind, ExecutionNodeRef};
use serde::{Deserialize, Serialize};

use crate::nest::Budget;

fn is_zero_u32(value: &u32) -> bool {
    *value == 0
}

/// A construct's byte range in the source its callable graph was built from.
pub(crate) type Span = (u32, u32);

/// The node a path reached; `None` means the path does not continue.
pub(crate) type Frontier = Option<u32>;

const NODE_BYTES: u64 = 160;
const FACT_BYTES: u64 = 8;
const MAX_EXN_NAMES: usize = 8;

/// Language of a builtin exception symbol. Bindings are language-local and
/// never consult this table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LangTag {
    Python,
    Ruby,
    Php,
    Java,
}

/// A resolved exception identity: a builtin table entry, or a same-scope binding.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Symbol {
    Builtin { lang: LangTag, name: String },
    Binding { name: String },
}

impl Symbol {
    pub fn py(name: &str) -> Self {
        Self::Builtin {
            lang: LangTag::Python,
            name: name.to_string(),
        }
    }

    pub fn rb(name: &str) -> Self {
        Self::Builtin {
            lang: LangTag::Ruby,
            name: name.to_string(),
        }
    }

    pub fn php(name: &str) -> Self {
        Self::Builtin {
            lang: LangTag::Php,
            name: name.to_string(),
        }
    }

    pub fn java(name: &str) -> Self {
        Self::Builtin {
            lang: LangTag::Java,
            name: name.to_string(),
        }
    }

    pub fn binding(name: &str) -> Self {
        Self::Binding {
            name: name.to_string(),
        }
    }
}

/// What a path throws. `Unknown` is not a mismatch: it is unproved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[derive(Default)]
pub enum Exn {
    #[default]
    Unknown,
    Named {
        names: Vec<Symbol>,
    },
}

impl Exn {
    pub fn is_unknown(&self) -> bool {
        match self {
            Self::Unknown => true,
            Self::Named { names } => names.is_empty(),
        }
    }

    pub fn named(symbol: Symbol) -> Self {
        Self::Named {
            names: vec![symbol],
        }
    }

    pub fn names(mut names: Vec<Symbol>) -> Self {
        names.sort();
        names.dedup();
        if names.is_empty() || names.len() > MAX_EXN_NAMES {
            Self::Unknown
        } else {
            Self::Named { names }
        }
    }

    /// Union of two throw labels. `Unknown` absorbs; too many names widen.
    pub fn join(self, other: Self) -> Self {
        match (self, other) {
            (Self::Unknown, _) | (_, Self::Unknown) => Self::Unknown,
            (Self::Named { names: mut left }, Self::Named { names: right }) => {
                left.extend(right);
                Self::names(left)
            }
        }
    }
}

/// What a handler claims to catch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum Catch {
    Any,
    Unknown,
    Named { names: Vec<Symbol> },
}

impl Catch {
    pub(crate) fn named(symbol: Symbol) -> Self {
        Self::Named {
            names: vec![symbol],
        }
    }

    pub(crate) fn names(mut names: Vec<Symbol>) -> Self {
        names.sort();
        names.dedup();
        if names.is_empty() || names.len() > MAX_EXN_NAMES {
            Self::Unknown
        } else {
            Self::Named { names }
        }
    }
}

/// How a throw relates to a handler. `Maybe` is unknown control: it intersects
/// success but cannot witness that a normal completion exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Match {
    Yes,
    No,
    Maybe,
}

fn builtin_parent(lang: LangTag, name: &str) -> Option<&'static str> {
    match (lang, name) {
        (
            LangTag::Python,
            "RuntimeError" | "ValueError" | "TypeError" | "AttributeError" | "IndexError"
            | "KeyError" | "AssertionError" | "ZeroDivisionError" | "NameError" | "StopIteration"
            | "OSError",
        ) => Some("Exception"),
        (LangTag::Python, "Exception") => Some("BaseException"),
        (LangTag::Python, "SystemExit") => Some("BaseException"),
        (LangTag::Ruby, "RuntimeError" | "ArgumentError") => Some("StandardError"),
        (LangTag::Ruby, "StandardError") => Some("Exception"),
        (LangTag::Php, "ValueError" | "TypeError") => Some("Error"),
        (LangTag::Php, "Error" | "Exception") => Some("Throwable"),
        (LangTag::Java, "NullPointerException") => Some("RuntimeException"),
        (LangTag::Java, "RuntimeException") => Some("Exception"),
        (LangTag::Java, "Exception" | "Error") => Some("Throwable"),
        _ => None,
    }
}

fn is_subtype(lang: LangTag, child: &str, parent: &str) -> bool {
    if child == parent {
        return true;
    }
    let mut cur = child;
    for _ in 0..8 {
        match builtin_parent(lang, cur) {
            Some(next) if next == parent => return true,
            Some(next) if next == cur => return false,
            Some(next) => cur = next,
            None => return false,
        }
    }
    false
}

fn catches_one(thrown: &Symbol, handler: &Symbol) -> Match {
    match (thrown, handler) {
        (
            Symbol::Builtin {
                lang: thrown_lang,
                name: child,
            },
            Symbol::Builtin {
                lang: handler_lang,
                name: parent,
            },
        ) if thrown_lang == handler_lang => {
            if is_subtype(*thrown_lang, child, parent) {
                Match::Yes
            } else {
                Match::No
            }
        }
        _ => Match::Maybe,
    }
}

fn catches(exn: &Exn, catch: &Catch) -> Match {
    match (exn, catch) {
        (_, Catch::Any) => Match::Yes,
        (Exn::Unknown, _) => Match::Maybe,
        (_, Catch::Unknown) => Match::Maybe,
        (Exn::Named { names: thrown }, Catch::Named { names: handlers }) => {
            if thrown.is_empty() || handlers.is_empty() {
                return Match::Maybe;
            }
            let mut all_yes = true;
            let mut all_no = true;
            for thrown in thrown {
                let mut any_yes = false;
                let mut all_handlers_no = true;
                for handler in handlers {
                    match catches_one(thrown, handler) {
                        Match::Yes => {
                            any_yes = true;
                            all_handlers_no = false;
                        }
                        Match::No => {}
                        Match::Maybe => all_handlers_no = false,
                    }
                }
                match (any_yes, all_handlers_no) {
                    (true, _) => all_no = false,
                    (false, true) => all_yes = false,
                    (false, false) => {
                        all_yes = false;
                        all_no = false;
                    }
                }
            }
            if all_yes {
                Match::Yes
            } else if all_no {
                Match::No
            } else {
                Match::Maybe
            }
        }
    }
}

fn stamp_exn(slot: &mut Exn, exn: Exn) {
    if slot.is_unknown() {
        *slot = exn;
    } else if !exn.is_unknown() {
        *slot = slot.clone().join(exn);
    }
}

/// Callee continuation used when recomputing a stored caller graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallContract {
    /// A normal continuation is possible, including unproved handler returns.
    pub returns: bool,
    /// A proven successful completion exists; this is the success witness.
    pub succeeds: bool,
    pub may_exit: bool,
    pub throws: bool,
    pub escaping: Exn,
}

impl CallContract {
    pub fn from_flags(returns: bool, may_exit: bool, throws: bool) -> Self {
        Self {
            returns,
            succeeds: returns,
            may_exit,
            throws,
            escaping: Exn::Unknown,
        }
    }
}

/// An occurrence a site establishes when it is reached, by slot in the
/// enclosing summary or plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlFact {
    Effect(u32),
    Call(u32),
    /// The call completes without an exception on this path.
    CallSuccess(u32),
}

/// How a path leaves the callable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum ControlExit {
    /// A site's exceptional continuation leaves the callable directly.
    Unwind,
    /// An exception escapes the callable; it is not a normal completion.
    Throw,
    /// Normal completion with a successful status.
    Success,
    /// Normal completion with a failing status, such as a shell script whose
    /// last command failed.
    Failure,
    /// Unknown code may complete the invocation successfully here.
    Unknown,
    /// Executing an unresolved import may complete the invocation here. A
    /// repository view that proves the module completes normally discharges it.
    Import { module: String },
    /// A call whose normal continuation depends on its resolved callee.
    Call { slot: u32 },
}

/// A callable's resolved control flow: the syntax graph with the facts its
/// walk registered. Summaries retain it so call substitution and repository
/// composition reuse the same proof instead of reconstructing order.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlFlow {
    nodes: Vec<ControlNode>,
    exits: Vec<(u32, ControlExit)>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    saturated: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct ControlNode {
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    lookup: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    lookup_call: Option<u32>,
    /// This edge follows an exception rather than a normal return.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    exceptional: bool,
    throws: bool,
    #[serde(default, skip_serializing_if = "Exn::is_unknown")]
    exn: Exn,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    catch: Option<Catch>,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    catch_order: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    throw_facts: Vec<ControlFact>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    call_return: bool,
    /// Source site retained for frontends whose effect and edge collectors
    /// are separate walks of the same callable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    site: Option<Span>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    predecessors: Vec<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    facts: Vec<ControlFact>,
    /// Reaching this node does not continue normally.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    blocks: bool,
    /// The normal continuation exists only as an unproved match/return.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    maybe_return: bool,
}

/// What a callable guarantees to the construct that ran it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Requirements {
    /// Facts reached on every exceptional completion.
    pub on_throw: BTreeSet<ControlFact>,
    pub throws: bool,
    /// Facts reached on every successful completion, unknown exits included.
    pub on_success: BTreeSet<ControlFact>,
    /// Facts reached on every normal completion, whatever its status.
    pub on_completion: BTreeSet<ControlFact>,
    /// A successful normal completion is reachable.
    pub succeeds: bool,
    /// A failing normal completion is reachable.
    pub fails: bool,
    /// Unknown code may complete the invocation from inside the callable.
    pub may_exit: bool,
    /// A normal return is possible, including unproved handler matches.
    pub may_return: bool,
    /// Union of exception labels that still escape the callable.
    pub escaping: Exn,
}

impl Requirements {
    /// Nothing is proven and every continuation stays possible.
    pub fn unknown() -> Self {
        Self {
            on_throw: BTreeSet::new(),
            throws: true,
            on_success: BTreeSet::new(),
            on_completion: BTreeSet::new(),
            succeeds: true,
            fails: true,
            may_exit: true,
            may_return: true,
            escaping: Exn::Unknown,
        }
    }
}

impl ControlFlow {
    pub(crate) fn empty_body() -> Self {
        Self {
            nodes: vec![ControlNode::default()],
            exits: vec![(0, ControlExit::Success)],
            saturated: false,
        }
    }

    pub(crate) fn calls_only(&self) -> Self {
        let mut flow = self.clone();
        for node in &mut flow.nodes {
            if !crate::limits::summary_step() {
                return Self::widened();
            }
            node.facts
                .retain(|fact| matches!(fact, ControlFact::Call(_) | ControlFact::CallSuccess(_)));
            node.throw_facts
                .retain(|fact| matches!(fact, ControlFact::Call(_)));
        }
        flow
    }

    pub(crate) fn bind_calls(&mut self, calls: &BTreeMap<Span, u32>) {
        for node in &mut self.nodes {
            if !crate::limits::summary_step() {
                self.saturated = true;
                return;
            }
            if let Some(slot) = node.site.and_then(|site| calls.get(&site)) {
                if node.lookup {
                    node.lookup_call = node.throws.then_some(*slot);
                    continue;
                }
                node.facts.push(ControlFact::Call(*slot));
                node.facts.push(ControlFact::CallSuccess(*slot));
                node.throw_facts.push(ControlFact::Call(*slot));
            }
        }
        for (node, exit) in &mut self.exits {
            if matches!(exit, ControlExit::Unknown)
                && self.nodes[*node as usize].call_return
                && let Some(slot) = self.nodes[*node as usize]
                    .site
                    .and_then(|site| calls.get(&site))
            {
                *exit = ControlExit::Call { slot: *slot };
            }
        }
    }

    /// Substitute a same-file callee's guarantees without merging distinct
    /// source occurrences of its effects.
    pub(crate) fn inline_call(
        &mut self,
        call: u32,
        requirements: &Requirements,
        slots: &[Option<u32>],
    ) {
        for node in &mut self.nodes {
            if !crate::limits::summary_step() {
                self.saturated = true;
                return;
            }
            if node.lookup_call == Some(call) {
                node.throws = false;
                continue;
            }
            if !node.call_return || !node.facts.contains(&ControlFact::Call(call)) {
                continue;
            }
            debug_assert_eq!(
                node.facts
                    .iter()
                    .filter(|fact| matches!(fact, ControlFact::Call(_)))
                    .count(),
                1
            );
            if crate::limits::summary_charge(
                (requirements.on_success.len() + requirements.on_throw.len()) as u64,
            )
            .is_err()
            {
                self.saturated = true;
                return;
            }
            node.facts
                .extend(requirements.on_success.iter().filter_map(|fact| {
                    match fact {
                        ControlFact::Effect(slot) => slots
                            .get(*slot as usize)
                            .copied()
                            .flatten()
                            .map(ControlFact::Effect),
                        _ => None,
                    }
                }));
            node.throws = requirements.throws;
            if requirements.throws {
                stamp_exn(&mut node.exn, requirements.escaping.clone());
            }
            node.throw_facts
                .extend(requirements.on_throw.iter().filter_map(|fact| {
                    match fact {
                        ControlFact::Effect(slot) => slots
                            .get(*slot as usize)
                            .copied()
                            .flatten()
                            .map(ControlFact::Effect),
                        _ => None,
                    }
                }));
            if !requirements.may_exit
                && !requirements.succeeds
                && !requirements.fails
                && !requirements.may_return
            {
                node.blocks = true;
            }
            node.maybe_return = requirements.may_return && !requirements.succeeds;
        }
        self.exits.retain(|(node, exit)| {
            if matches!(exit, ControlExit::Unwind) {
                return true;
            }
            let node = &self.nodes[*node as usize];
            if !node.call_return || !node.facts.contains(&ControlFact::Call(call)) {
                return true;
            }
            !node.blocks
                && (requirements.may_exit
                    || !matches!(exit, ControlExit::Call { slot } if *slot == call))
        });
    }

    pub fn unresolved_calls(&self) -> impl Iterator<Item = u32> + '_ {
        self.exits
            .iter()
            .filter_map(|(_, exit)| match exit {
                ControlExit::Call { slot } => Some(*slot),
                _ => None,
            })
            .chain(self.nodes.iter().filter_map(|node| node.lookup_call))
    }

    /// A retained graph whose shape cannot be trusted proves nothing.
    fn well_formed(&self) -> bool {
        let len = self.nodes.len() as u32;
        len > 0
            && self
                .nodes
                .iter()
                .all(|node| node.predecessors.iter().all(|p| *p < len))
            && self.exits.iter().all(|(node, _)| *node < len)
    }

    /// A graph that proves nothing, for a callable whose facts are provisional.
    pub(crate) fn widened() -> Self {
        Self {
            saturated: true,
            ..Self::default()
        }
    }

    /// Modules whose unresolved import may complete the callable.
    pub fn imports(&self) -> impl Iterator<Item = &str> {
        self.exits.iter().filter_map(|(_, exit)| match exit {
            ControlExit::Import { module } => Some(module.as_str()),
            _ => None,
        })
    }

    pub fn is_saturated(&self) -> bool {
        self.saturated
    }

    /// Effect slots established at a recorded call site. These are usable
    /// only when the caller independently proves that call required.
    pub fn effects_at_calls(&self) -> impl Iterator<Item = (u32, u32)> + '_ {
        self.nodes
            .iter()
            .filter(|_| !self.saturated)
            .flat_map(|node| {
                node.facts
                    .iter()
                    .filter_map(|fact| match fact {
                        ControlFact::Call(slot) => Some(*slot),
                        _ => None,
                    })
                    .flat_map(move |call| {
                        node.facts.iter().filter_map(move |fact| match fact {
                            ControlFact::Effect(effect)
                                if !node.throws || node.throw_facts.contains(fact) =>
                            {
                                Some((*effect, call))
                            }
                            _ => None,
                        })
                    })
            })
    }

    /// Forward must-set fixpoint. An unreached predecessor is lattice top, not
    /// an empty path. Only reachable exits participate, and without one no
    /// fact is required. Every iteration and scratch set is charged; a refused
    /// charge proves nothing.
    pub fn requirements(
        &self,
        discharged: &mut dyn FnMut(&str) -> bool,
        calls: &mut dyn FnMut(u32) -> Option<CallContract>,
        charge: &mut dyn FnMut(u64, u64) -> bool,
    ) -> Requirements {
        if self.saturated || !self.well_formed() {
            return Requirements::unknown();
        }
        let distinct = self
            .nodes
            .iter()
            .flat_map(|node| node.facts.iter().chain(&node.throw_facts))
            .collect::<BTreeSet<_>>()
            .len() as u64;
        let scratch = (self.nodes.len() as u64).saturating_mul(NODE_BYTES + distinct * FACT_BYTES);
        if !charge(1, scratch) {
            return Requirements::unknown();
        }
        let mut states: Vec<Option<BTreeSet<ControlFact>>> = vec![None; self.nodes.len()];
        let mut proven = vec![false; self.nodes.len()];
        let mut maybe = vec![false; self.nodes.len()];
        let mut call_returns = vec![true; self.nodes.len()];
        let mut call_succeeds: Vec<bool> =
            self.nodes.iter().map(|node| !node.maybe_return).collect();
        let mut call_may_exit = vec![true; self.nodes.len()];
        let mut call_throws: Vec<_> = self.nodes.iter().map(|node| node.throws).collect();
        let mut call_escaping: Vec<Option<Exn>> = vec![None; self.nodes.len()];
        for (index, node) in self.nodes.iter().enumerate() {
            if let Some(slot) = node.lookup_call
                && let Some(contract) = calls(slot)
            {
                call_throws[index] = contract.throws;
                if contract.throws {
                    call_escaping[index] = Some(contract.escaping);
                }
            }
        }
        for (node, exit) in &self.exits {
            if let ControlExit::Call { slot } = exit
                && let Some(contract) = calls(*slot)
            {
                call_returns[*node as usize] = contract.returns;
                call_succeeds[*node as usize] = contract.succeeds;
                call_may_exit[*node as usize] = contract.may_exit;
                call_throws[*node as usize] = contract.throws;
                if contract.throws {
                    call_escaping[*node as usize] = Some(contract.escaping);
                }
            }
        }
        // States only descend once assigned, so each node changes at most
        // once per fact plus its first assignment. Proven/maybe bits are
        // monotonic and need a couple of extra rounds.
        let rounds = (distinct + 4).saturating_mul(self.nodes.len() as u64);
        let mut converged = false;
        for _ in 0..=rounds {
            let mut changed = false;
            for (index, node) in self.nodes.iter().enumerate() {
                if !charge(1 + node.predecessors.len() as u64, 0) {
                    return Requirements::unknown();
                }
                let mut next = (index == 0).then(BTreeSet::new);
                let mut next_proven = index == 0;
                let mut next_maybe = false;
                for predecessor in &node.predecessors {
                    let from = &self.nodes[*predecessor as usize];
                    let Some(incoming) = &states[*predecessor as usize] else {
                        continue;
                    };
                    let edge = if node.catch.is_some() {
                        match self.handler_edge(*predecessor, node, &call_escaping, charge) {
                            None | Some(Match::No) => continue,
                            Some(Match::Yes) if self.path_maybe(*predecessor, &proven, &maybe) => {
                                EdgeKind::Maybe
                            }
                            Some(Match::Yes) => EdgeKind::Proven,
                            Some(Match::Maybe) => EdgeKind::Maybe,
                        }
                    } else if node.exceptional {
                        if !call_throws[*predecessor as usize] {
                            continue;
                        }
                        if self.path_maybe(*predecessor, &proven, &maybe) {
                            EdgeKind::Maybe
                        } else {
                            EdgeKind::Throw
                        }
                    } else if from.blocks || !call_returns[*predecessor as usize] {
                        continue;
                    } else if proven[*predecessor as usize] && call_succeeds[*predecessor as usize]
                    {
                        EdgeKind::Proven
                    } else if maybe[*predecessor as usize] || !call_succeeds[*predecessor as usize]
                    {
                        EdgeKind::Maybe
                    } else {
                        // An uncaught throw that entered cleanup is not itself
                        // success, but a later return from that cleanup is a
                        // real normal completion.
                        EdgeKind::Proven
                    };
                    let facts = if node.exceptional {
                        &from.throw_facts
                    } else {
                        &from.facts
                    };
                    match &mut next {
                        None => {
                            let mut incoming = incoming.clone();
                            incoming.extend(facts.iter().copied());
                            next = Some(incoming);
                        }
                        Some(next) => {
                            next.retain(|fact| incoming.contains(fact) || facts.contains(fact))
                        }
                    }
                    match edge {
                        EdgeKind::Proven => next_proven = true,
                        EdgeKind::Maybe => next_maybe = true,
                        EdgeKind::Throw => {}
                    }
                }
                if next != states[index]
                    || next_proven != proven[index]
                    || next_maybe != maybe[index]
                {
                    states[index] = next;
                    proven[index] = next_proven;
                    maybe[index] = next_maybe;
                    changed = true;
                }
            }
            if !changed {
                converged = true;
                break;
            }
        }
        if !converged {
            return Requirements::unknown();
        }
        let mut success: Option<BTreeSet<ControlFact>> = None;
        let mut completion: Option<BTreeSet<ControlFact>> = None;
        let mut thrown: Option<BTreeSet<ControlFact>> = None;
        let mut escaping: Option<Exn> = None;
        let mut requirements = Requirements {
            on_throw: BTreeSet::new(),
            throws: false,
            on_success: BTreeSet::new(),
            on_completion: BTreeSet::new(),
            succeeds: false,
            fails: false,
            may_exit: false,
            may_return: false,
            escaping: Exn::Unknown,
        };
        let mut proven_exits = Vec::new();
        let mut maybe_exits = Vec::new();
        for (node, exit) in &self.exits {
            if !charge(1, 0) {
                return Requirements::unknown();
            }
            if matches!(exit, ControlExit::Call { .. }) && !call_may_exit[*node as usize] {
                continue;
            }
            if matches!(exit, ControlExit::Unwind) && !call_throws[*node as usize] {
                continue;
            }
            if let ControlExit::Import { module } = exit
                && discharged(module)
            {
                continue;
            }
            if !call_returns[*node as usize]
                && matches!(exit, ControlExit::Success | ControlExit::Failure)
            {
                continue;
            }
            let Some(state) = &states[*node as usize] else {
                continue;
            };
            let facts = if matches!(exit, ControlExit::Unwind) {
                &self.nodes[*node as usize].throw_facts
            } else {
                &self.nodes[*node as usize].facts
            };
            match exit {
                ControlExit::Throw | ControlExit::Unwind => {
                    if self.yes_handler_consumes(*node, u32::MAX, &call_escaping, charge) {
                        continue;
                    }
                    requirements.throws = true;
                    let label = self.throw_exn(*node as usize, &call_escaping);
                    escaping = Some(match escaping.take() {
                        None => label,
                        Some(prev) => prev.join(label),
                    });
                    if !intersect(&mut thrown, state, facts, charge) {
                        return Requirements::unknown();
                    }
                }
                // A site that only maybe returns cannot witness a successful
                // completion at its own exit either, exactly as it cannot
                // prove one for the paths that leave it.
                _ if proven[*node as usize] && call_succeeds[*node as usize] => {
                    proven_exits.push((state, facts, exit))
                }
                _ if proven[*node as usize] || maybe[*node as usize] => {
                    maybe_exits.push((state, facts, exit))
                }
                _ => {}
            }
        }
        requirements.may_return = !proven_exits.is_empty() || !maybe_exits.is_empty();
        if !proven_exits.is_empty() {
            for (set_flags, state, facts, exit) in proven_exits
                .iter()
                .map(|(state, facts, exit)| (true, *state, *facts, *exit))
                .chain(
                    maybe_exits
                        .iter()
                        .map(|(state, facts, exit)| (false, *state, *facts, *exit)),
                )
            {
                let successful = match exit {
                    ControlExit::Success => {
                        if set_flags {
                            requirements.succeeds = true;
                        }
                        true
                    }
                    ControlExit::Failure => {
                        if set_flags {
                            requirements.fails = true;
                        }
                        false
                    }
                    ControlExit::Unknown
                    | ControlExit::Import { .. }
                    | ControlExit::Call { .. } => {
                        requirements.may_exit = true;
                        true
                    }
                    ControlExit::Throw | ControlExit::Unwind => unreachable!("classified above"),
                };
                if successful && !intersect(&mut success, state, facts, charge) {
                    return Requirements::unknown();
                }
                if !intersect(&mut completion, state, facts, charge) {
                    return Requirements::unknown();
                }
            }
        }
        requirements.on_success = success.unwrap_or_default();
        requirements.on_completion = completion.unwrap_or_default();
        requirements.on_throw = thrown.unwrap_or_default();
        if requirements.throws {
            requirements.escaping = escaping.unwrap_or(Exn::Unknown);
        }
        requirements
    }

    fn throw_exn(&self, index: usize, overlay: &[Option<Exn>]) -> Exn {
        let node = &self.nodes[index];
        if node.exceptional {
            node.predecessors
                .first()
                .map(|pred| self.node_exn(*pred as usize, overlay))
                .unwrap_or(Exn::Unknown)
        } else {
            self.node_exn(index, overlay)
        }
    }

    fn node_exn(&self, index: usize, overlay: &[Option<Exn>]) -> Exn {
        overlay
            .get(index)
            .cloned()
            .flatten()
            .unwrap_or_else(|| self.nodes[index].exn.clone())
    }

    fn handler_edge(
        &self,
        pred: u32,
        node: &ControlNode,
        overlay: &[Option<Exn>],
        charge: &mut dyn FnMut(u64, u64) -> bool,
    ) -> Option<Match> {
        let catch = node.catch.as_ref()?;
        if self.yes_handler_consumes(pred, node.catch_order, overlay, charge) {
            return Some(Match::No);
        }
        let exn = self.throw_exn(pred as usize, overlay);
        Some(charged_catches(&exn, catch, charge))
    }

    fn path_maybe(&self, pred: u32, proven: &[bool], maybe: &[bool]) -> bool {
        let mut idx = pred as usize;
        for _ in 0..8 {
            if !self.nodes.get(idx).is_some_and(|node| node.exceptional) {
                break;
            }
            match self.nodes[idx].predecessors.first() {
                Some(next) => idx = *next as usize,
                None => break,
            }
        }
        maybe.get(idx).copied().unwrap_or(false) && !proven.get(idx).copied().unwrap_or(false)
    }

    fn yes_handler_consumes(
        &self,
        pred: u32,
        before_order: u32,
        overlay: &[Option<Exn>],
        charge: &mut dyn FnMut(u64, u64) -> bool,
    ) -> bool {
        let exn = self.throw_exn(pred as usize, overlay);
        self.nodes.iter().any(|node| {
            node.catch.as_ref().is_some_and(|catch| {
                node.catch_order < before_order
                    && node.predecessors.contains(&pred)
                    && charged_catches(&exn, catch, charge) == Match::Yes
            })
        })
    }
}

fn charged_catches(exn: &Exn, catch: &Catch, charge: &mut dyn FnMut(u64, u64) -> bool) -> Match {
    let names = match (exn, catch) {
        (Exn::Named { names }, Catch::Named { names: handlers }) => names.len() + handlers.len(),
        _ => 1,
    };
    if !charge(names as u64, 0) {
        return Match::Maybe;
    }
    catches(exn, catch)
}

enum EdgeKind {
    Proven,
    Maybe,
    Throw,
}

fn intersect(
    target: &mut Option<BTreeSet<ControlFact>>,
    state: &BTreeSet<ControlFact>,
    facts: &[ControlFact],
    charge: &mut dyn FnMut(u64, u64) -> bool,
) -> bool {
    let work = match target {
        None => state.len() + facts.len(),
        Some(target) => target.len().saturating_mul(1 + facts.len()),
    };
    if !charge(work as u64, 0) {
        return false;
    }
    match target {
        None => {
            let mut initial = state.clone();
            initial.extend(facts.iter().copied());
            *target = Some(initial);
        }
        Some(target) => target.retain(|fact| state.contains(fact) || facts.contains(fact)),
    }
    true
}

/// Which completion of a site its registered facts describe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Phase {
    /// Resolve the callable before evaluating its arguments.
    Lookup,
    /// The construct was evaluated and control continued past it.
    Evaluate,
    /// A shell command completed with a successful status.
    Success,
}

#[derive(Debug, Clone)]
struct Site {
    span: Span,
    node: u32,
    phase: Phase,
    /// An unregistered site may run unknown code that completes the invocation.
    opaque: bool,
}

/// Where a structured jump transfers control.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Jump {
    Throw,
    Return,
    Break(Option<String>),
    Continue(Option<String>),
}

enum ControlScope {
    Catch {
        thrown: Vec<u32>,
    },
    Loop {
        label: Option<String>,
        /// Switch-like scopes accept `break` but not `continue`.
        continues: bool,
        /// Labeled blocks accept only a `break` that names them.
        unlabeled: bool,
        breaks: Vec<u32>,
        continued: Vec<u32>,
    },
    /// Code that runs whenever control leaves the protected region.
    Cleanup {
        pending: Vec<(u32, Jump)>,
    },
}

/// Charge graph work against its cap and retained bytes against the budget.
fn charge_control(
    budget: &Option<Rc<Budget>>,
    caps: ControlCaps,
    spent: &mut u64,
    work: u64,
    bytes: u64,
) -> Result<(), &'static str> {
    crate::limits::summary_charge(work)?;
    if work > caps.work.saturating_sub(*spent) {
        return Err("max_causal_pairs");
    }
    if let Some(budget) = budget
        && !budget.try_charge_condition(0, bytes)
    {
        return Err("max_analysis_bytes");
    }
    *spent += work;
    Ok(())
}

/// Recursive syntax walks stay far below the native stack limit.
const MAX_GRAPH_DEPTH: u32 = 192;

/// A callable graph under construction from syntax.
pub(crate) struct Graph {
    exceptions: bool,
    flow: ControlFlow,
    sites: Vec<Site>,
    /// Nodes that leave successfully unless the construct at the span is
    /// registered as unable to divert control there.
    guards: Vec<(u32, Span)>,
    scopes: Vec<ControlScope>,
    budget: Option<Rc<Budget>>,
    caps: ControlCaps,
    bytes: u64,
    work: u64,
    depth: u32,
    refused: Option<&'static str>,
    catch_seq: u32,
}

/// Work bounds for one callable. Necessity refines causal cardinality, so it
/// draws on the causal caps rather than the shared step pool: effect discovery
/// already spends that pool on large scripts, and necessity must never cost an
/// effect. Retained graph memory still counts against the analysis bytes.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ControlCaps {
    pub(crate) nodes: u64,
    pub(crate) work: u64,
}

impl Graph {
    fn new(budget: Option<Rc<Budget>>, caps: ControlCaps) -> Self {
        Self {
            exceptions: false,
            flow: ControlFlow::default(),
            sites: Vec::new(),
            guards: Vec::new(),
            scopes: Vec::new(),
            budget,
            caps,
            bytes: 0,
            work: 0,
            depth: 0,
            refused: None,
            catch_seq: 0,
        }
    }

    fn charge(&mut self, work: u64, bytes: u64) -> bool {
        if self.flow.saturated {
            return false;
        }
        match charge_control(&self.budget, self.caps, &mut self.work, work, bytes) {
            Ok(()) => {
                self.bytes += bytes;
                true
            }
            Err(limit) => {
                self.refused = Some(limit);
                self.flow.saturated = true;
                false
            }
        }
    }

    fn node(&mut self, predecessors: Vec<u32>) -> Frontier {
        if self.flow.nodes.len() as u64 >= self.caps.nodes {
            self.refused = Some("max_causal_nodes");
            self.flow.saturated = true;
            return None;
        }
        if !self.charge(1, NODE_BYTES + 4 * predecessors.len() as u64) {
            return None;
        }
        self.flow.nodes.push(ControlNode {
            call_return: false,
            site: None,
            predecessors,
            facts: Vec::new(),
            blocks: false,
            ..Default::default()
        });
        Some(self.flow.nodes.len() as u32 - 1)
    }

    /// The callable's entry; every other node descends from it.
    pub(crate) fn entry(&mut self) -> Frontier {
        if self.flow.nodes.is_empty() {
            self.node(Vec::new())
        } else {
            None
        }
    }

    pub(crate) fn widen(&mut self) {
        self.flow.saturated = true;
    }

    /// Charge auxiliary syntax scans to the same work cap as the proof.
    pub(crate) fn scan_step(&mut self) -> bool {
        self.charge(1, 0)
    }

    /// Bound recursive syntax walks; past the bound the graph proves nothing.
    pub(crate) fn enter(&mut self) -> bool {
        if self.depth >= MAX_GRAPH_DEPTH || self.flow.saturated {
            self.widen();
            return false;
        }
        self.depth += 1;
        true
    }

    pub(crate) fn leave(&mut self) {
        self.depth -= 1;
    }

    /// Paths that meet again. A single live path needs no join node.
    pub(crate) fn join(&mut self, frontiers: &[Frontier]) -> Frontier {
        let mut live: Vec<u32> = frontiers.iter().flatten().copied().collect();
        live.sort_unstable();
        live.dedup();
        match live.as_slice() {
            [] => None,
            [only] => Some(*only),
            _ => self.node(live),
        }
    }

    /// A fresh node that later backedges can target.
    pub(crate) fn header(&mut self, at: Frontier) -> Frontier {
        let at = at?;
        self.node(vec![at])
    }

    pub(crate) fn backedge(&mut self, from: Frontier, to: Frontier) {
        if let (Some(from), Some(to)) = (from, to)
            && self.charge(1, 4)
        {
            self.flow.nodes[to as usize].predecessors.push(from);
        }
    }

    /// A call or sink evaluated at `span`. `opaque` sites that no walk
    /// registers may run unknown code that completes the invocation.
    pub(crate) fn site(&mut self, at: Frontier, span: Span, opaque: bool) -> Frontier {
        let at = self.site_in_phase(at, span, Phase::Evaluate, opaque);
        if self.exceptions
            && opaque
            && let Some(from) = at
        {
            self.exception(from);
        }
        at
    }

    pub(crate) fn enable_exceptions(&mut self) {
        self.exceptions = true;
    }

    pub(crate) fn lookup(&mut self, at: Frontier, span: Span) -> Frontier {
        let at = self.site_in_phase(at, span, Phase::Lookup, false);
        if let Some(from) = at {
            self.flow.nodes[from as usize].lookup = true;
            self.exception(from);
        }
        at
    }

    /// An expression can fail without invoking unknown control, for example
    /// integer division or an array bounds check.
    pub(crate) fn may_throw(&mut self, at: Frontier) -> Frontier {
        self.may_throw_exn(at, Exn::Unknown)
    }

    /// A statically invalid operation has no normal continuation. The extra
    /// edge requires its operands to finish before the exception is raised.
    pub(crate) fn throw_now(&mut self, at: Frontier) -> Frontier {
        self.abort(at, Exn::Unknown)
    }

    /// A statically invalid operation labeled with the exception it raises.
    pub(crate) fn abort(&mut self, at: Frontier, exn: Exn) -> Frontier {
        let at = self.header(at);
        self.throw(at, exn);
        None
    }

    pub(crate) fn throw(&mut self, at: Frontier, exn: Exn) {
        let Some(from) = at else {
            return;
        };
        stamp_exn(&mut self.flow.nodes[from as usize].exn, exn);
        self.jump(Some(from), Jump::Throw);
    }

    pub(crate) fn may_throw_exn(&mut self, at: Frontier, exn: Exn) -> Frontier {
        let from = self.node(vec![at?])?;
        self.flow.nodes[from as usize].throws = true;
        stamp_exn(&mut self.flow.nodes[from as usize].exn, exn);
        self.exception(from);
        Some(from)
    }

    fn exception(&mut self, from: u32) {
        if self.scopes.iter().any(|scope| {
            matches!(
                scope,
                ControlScope::Catch { .. } | ControlScope::Cleanup { .. }
            )
        }) {
            if let Some(thrown) = self.node(vec![from]) {
                self.flow.nodes[thrown as usize].exceptional = true;
                self.jump(Some(thrown), Jump::Throw);
            }
        } else {
            self.exit(Some(from), ControlExit::Unwind);
        }
    }

    pub(crate) fn push_catch(&mut self) {
        self.scopes.push(ControlScope::Catch { thrown: Vec::new() });
    }

    pub(crate) fn pop_catch(&mut self) -> Vec<u32> {
        let Some(ControlScope::Catch { thrown }) = self.scopes.pop() else {
            unreachable!("catch scopes are balanced")
        };
        thrown
    }

    pub(crate) fn catch_handler(&mut self, thrown: &[u32], catch: Catch) -> Frontier {
        if thrown.is_empty() {
            return None;
        }
        let names = match &catch {
            Catch::Named { names } => names.len() as u64,
            _ => 1,
        };
        if !self.charge(names, names * FACT_BYTES) {
            return None;
        }
        let node = self.node(thrown.to_vec())?;
        self.catch_seq = self.catch_seq.saturating_add(1);
        self.flow.nodes[node as usize].catch = Some(catch);
        self.flow.nodes[node as usize].catch_order = self.catch_seq;
        Some(node)
    }

    pub(crate) fn rethrow(&mut self, thrown: &[u32]) {
        for node in thrown {
            self.jump(Some(*node), Jump::Throw);
        }
    }

    /// The successful-status continuation of a shell command at `span`.
    pub(crate) fn success(&mut self, at: Frontier, span: Span) -> Frontier {
        self.site_in_phase(at, span, Phase::Success, false)
    }

    fn site_in_phase(&mut self, at: Frontier, span: Span, phase: Phase, opaque: bool) -> Frontier {
        let at = at?;
        let node = self.node(vec![at])?;
        if matches!(phase, Phase::Evaluate | Phase::Lookup) {
            self.flow.nodes[node as usize].site = Some(span);
        }
        if !self.charge(0, 24) {
            return None;
        }
        self.sites.push(Site {
            span,
            node,
            phase,
            opaque,
        });
        Some(node)
    }

    pub(crate) fn exit(&mut self, at: Frontier, exit: ControlExit) {
        if let Some(at) = at
            && self.charge(1, 16)
        {
            self.flow.exits.push((at, exit));
        }
    }

    /// A normal completion from `at` that skips the rest of the callable,
    /// unless the construct at `span` registers without an exit, such as a
    /// deferred call that cannot recover a panic.
    pub(crate) fn guard(&mut self, at: Frontier, span: Span) {
        if let Some(at) = at
            && self.charge(1, 16)
        {
            self.guards.push((at, span));
        }
    }

    /// Unknown code may complete the invocation here; the path also continues.
    pub(crate) fn unknown(&mut self, at: Frontier) {
        self.exit(at, ControlExit::Unknown);
    }

    /// A normal path that skips everything after `at`, such as an exception
    /// a construct may suppress, leaves the callable successfully.
    pub(crate) fn bypass(&mut self, at: Frontier) {
        self.exit(at, ControlExit::Success);
    }

    pub(crate) fn push_loop(&mut self, label: Option<String>, continues: bool) {
        self.scopes.push(ControlScope::Loop {
            label,
            continues,
            unlabeled: true,
            breaks: Vec::new(),
            continued: Vec::new(),
        });
    }

    /// A labeled statement that is not a loop: only `break label` leaves it.
    pub(crate) fn push_block(&mut self, label: String) {
        self.scopes.push(ControlScope::Loop {
            label: Some(label),
            continues: false,
            unlabeled: false,
            breaks: Vec::new(),
            continued: Vec::new(),
        });
    }

    /// Break and continue sources of the innermost loop scope.
    pub(crate) fn pop_loop(&mut self) -> (Vec<u32>, Vec<u32>) {
        match self.scopes.pop() {
            Some(ControlScope::Loop {
                breaks, continued, ..
            }) => (breaks, continued),
            _ => unreachable!("loop scopes are balanced"),
        }
    }

    pub(crate) fn push_cleanup(&mut self) {
        self.scopes.push(ControlScope::Cleanup {
            pending: Vec::new(),
        });
    }

    /// Jumps that left the protected region and still owe the cleanup.
    pub(crate) fn pop_cleanup(&mut self) -> Vec<(u32, Jump)> {
        match self.scopes.pop() {
            Some(ControlScope::Cleanup { pending }) => pending,
            _ => unreachable!("cleanup scopes are balanced"),
        }
    }

    /// Transfer control structurally. A return outside every scope completes
    /// the callable; a break or continue without a target is unknown control.
    pub(crate) fn jump(&mut self, at: Frontier, jump: Jump) {
        let Some(from) = at else {
            return;
        };
        for scope in self.scopes.iter_mut().rev() {
            match scope {
                ControlScope::Catch { thrown } => {
                    if jump == Jump::Throw {
                        thrown.push(from);
                        return;
                    }
                }
                ControlScope::Cleanup { pending } => {
                    pending.push((from, jump));
                    return;
                }
                ControlScope::Loop {
                    label,
                    continues,
                    unlabeled,
                    breaks,
                    continued,
                } => {
                    let matches = |target: &Option<String>| match target {
                        None => *unlabeled,
                        Some(_) => target == label,
                    };
                    match &jump {
                        Jump::Break(target) if matches(target) => {
                            breaks.push(from);
                            return;
                        }
                        Jump::Continue(target) if *continues && matches(target) => {
                            continued.push(from);
                            return;
                        }
                        _ => {}
                    }
                }
            }
        }
        match jump {
            Jump::Throw => self.exit(at, ControlExit::Throw),
            Jump::Return => self.exit(at, ControlExit::Success),
            Jump::Break(_) | Jump::Continue(_) => self.unknown(at),
        }
    }

    /// Resume the jumps a cleanup deferred, from the cleanup's end.
    pub(crate) fn resume(&mut self, at: Frontier, pending: Vec<(u32, Jump)>) {
        let mut seen = Vec::new();
        let mut throw_exn: Option<Exn> = None;
        for (from, jump) in pending {
            if jump == Jump::Throw {
                let label = self.flow.nodes[from as usize].exn.clone();
                throw_exn = Some(match throw_exn.take() {
                    None => label,
                    Some(prev) => prev.join(label),
                });
                continue;
            }
            if !seen.contains(&jump) {
                self.jump(at, jump.clone());
                seen.push(jump);
            }
        }
        if let Some(exn) = throw_exn {
            self.throw(at, exn);
        }
    }
}

/// One walk's knowledge about a site, registered at its source span.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SiteFacts {
    pub reference_known: bool,
    pub throw_facts: Vec<ControlFact>,
    pub throws: bool,
    /// Only the callee's continuation is unknown, not an additional callback
    /// or opaque mechanism at the containing site.
    pub call_return: bool,
    /// Facts established whenever the construct is evaluated and control
    /// continues past it.
    pub facts: Vec<ControlFact>,
    /// Facts established only when a shell command completes successfully.
    pub success: Vec<ControlFact>,
    /// Whether control can continue past the construct.
    pub returns: bool,
    /// How unknown code inside the construct may complete the invocation.
    pub exit: Option<ControlExit>,
    /// The construct's proof is provisional, so the callable proves nothing.
    pub widen: bool,
    /// Exception labels this site may raise.
    pub thrown: Exn,
    /// A proven successful continuation, not only an unproved match return.
    pub succeeds: bool,
}

impl SiteFacts {
    /// A construct whose evaluation is modeled and which always continues.
    pub(crate) fn known(facts: Vec<ControlFact>) -> Self {
        Self {
            reference_known: true,
            throw_facts: facts.clone(),
            throws: true,
            facts,
            returns: true,
            succeeds: true,
            ..Self::default()
        }
    }

    /// A construct whose continuation is unknown.
    pub(crate) fn unknown() -> Self {
        Self {
            throws: true,
            returns: true,
            succeeds: true,
            exit: Some(ControlExit::Unknown),
            ..Self::default()
        }
    }

    pub(crate) fn widened() -> Self {
        Self {
            widen: true,
            ..Self::unknown()
        }
    }

    /// A callee's guarantees at a call that returns when the callee succeeds.
    pub(crate) fn call(
        requirements: &Requirements,
        map: impl Fn(ControlFact) -> Option<ControlFact>,
    ) -> Self {
        Self {
            throw_facts: requirements
                .on_throw
                .iter()
                .copied()
                .filter_map(&map)
                .collect(),
            reference_known: true,
            throws: requirements.throws,
            facts: requirements
                .on_success
                .iter()
                .copied()
                .filter_map(&map)
                .collect(),
            success: Vec::new(),
            returns: requirements.succeeds || requirements.may_return || requirements.fails,
            succeeds: requirements.succeeds,
            call_return: true,
            exit: requirements.may_exit.then_some(ControlExit::Unknown),
            widen: false,
            thrown: requirements.escaping.clone(),
        }
    }

    /// Several walks reached the same site: they are alternatives, so only
    /// facts every alternative established survive.
    pub(crate) fn merge(&mut self, other: &Self) {
        self.reference_known &= other.reference_known;
        self.throw_facts
            .retain(|fact| other.throw_facts.contains(fact));
        match (self.throws, other.throws) {
            (true, true) => self.thrown = self.thrown.clone().join(other.thrown.clone()),
            (false, true) => self.thrown = other.thrown.clone(),
            _ => {}
        }
        self.throws |= other.throws;
        self.call_return &= other.call_return;
        self.facts.retain(|fact| other.facts.contains(fact));
        self.success.retain(|fact| other.success.contains(fact));
        self.returns |= other.returns;
        self.succeeds |= other.succeeds;
        self.exit = match (self.exit.take(), &other.exit) {
            (None, exit) => exit.clone(),
            (exit, None) => exit,
            (Some(left), Some(right)) if left == *right => Some(left),
            _ => Some(ControlExit::Unknown),
        };
        self.widen |= other.widen;
    }
}

struct ChildRun {
    execution: ExecutionNodeRef,
    requirements: Requirements,
}

struct ControlStackFrame {
    capture: bool,
    root: bool,
    source: (usize, usize),
    execution: ExecutionNodeRef,
    graph: Graph,
    registrations: Vec<(Span, SiteFacts)>,
    children: Vec<ChildRun>,
    /// The plan effect count when the frame began.
    effects_start: usize,
    /// Plan effect ranges emitted by frames nested in this one, such as a
    /// launched runtime's own walk: they belong to that runtime's proof.
    nested: Vec<std::ops::Range<usize>>,
}

/// Restores registrations made by a speculative walk.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct ControlCheckpoint {
    frames: usize,
    registrations: usize,
    children: usize,
    nested: usize,
}

/// The callables currently being walked, innermost last. The plan builder
/// owns it so nested runtimes compose through their launch sites.
#[derive(Default)]
pub(crate) struct ControlStack {
    frames: Vec<ControlStackFrame>,
    /// Whether the outermost frame describes the analyzed subject itself.
    roots: bool,
}

fn source_key(source: &str) -> (usize, usize) {
    (source.as_ptr() as usize, source.len())
}

/// A finished frame: its resolved graph, what it guarantees, and, for the
/// analyzed subject itself, the plan effects proven required.
pub(crate) struct Finished {
    pub flow: ControlFlow,
    pub requirements: Requirements,
    pub refused: Option<&'static str>,
    pub promote: Vec<u32>,
}

impl ControlStack {
    pub(crate) fn allow_roots(&mut self) {
        self.roots = true;
    }

    pub(crate) fn checkpoint(&self) -> ControlCheckpoint {
        ControlCheckpoint {
            frames: self.frames.len(),
            registrations: self
                .frames
                .last()
                .map_or(0, |frame| frame.registrations.len()),
            children: self.frames.last().map_or(0, |frame| frame.children.len()),
            nested: self.frames.last().map_or(0, |frame| frame.nested.len()),
        }
    }

    pub(crate) fn rollback(&mut self, checkpoint: ControlCheckpoint) {
        if self.frames.len() != checkpoint.frames {
            // A speculative walk never leaves a frame open; if it did, the
            // enclosing proof is no longer trustworthy.
            if let Some(frame) = self.frames.get_mut(checkpoint.frames.saturating_sub(1)) {
                frame.graph.widen();
            }
            self.frames.truncate(checkpoint.frames);
        }
        if let Some(frame) = self.frames.last_mut() {
            frame.registrations.truncate(checkpoint.registrations);
            frame.children.truncate(checkpoint.children);
            frame.nested.truncate(checkpoint.nested);
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn enter(
        &mut self,
        source: &str,
        capture: bool,
        execution: ExecutionNodeRef,
        execution_depth: usize,
        effects: usize,
        budget: Option<Rc<Budget>>,
        caps: ControlCaps,
        build: impl FnOnce(&mut Graph),
    ) {
        let root = !capture && self.roots && self.frames.is_empty() && execution_depth == 1;
        let mut graph = Graph::new(budget, caps);
        build(&mut graph);
        self.frames.push(ControlStackFrame {
            capture,
            root,
            source: source_key(source),
            execution,
            graph,
            registrations: Vec::new(),
            children: Vec::new(),
            effects_start: effects,
            nested: Vec::new(),
        });
    }

    /// Plan effect slots in `range` that the innermost frame's own walk
    /// emitted, excluding those of nested frames. A modeled API that launched
    /// a runtime reaches the launch, not whatever that runtime does.
    pub(crate) fn own_effects(&self, range: std::ops::Range<usize>) -> Vec<ControlFact> {
        let nested = self
            .frames
            .last()
            .filter(|frame| !frame.capture)
            .map_or(&[][..], |frame| frame.nested.as_slice());
        range
            .filter(|slot| !nested.iter().any(|inner| inner.contains(slot)))
            .map(|slot| ControlFact::Effect(slot as u32))
            .collect()
    }

    /// Whether registrations from a walk of `source` in this mode apply.
    fn top(&mut self, source: &str, capture: bool) -> Option<&mut ControlStackFrame> {
        self.frames
            .last_mut()
            .filter(|frame| frame.capture == capture && frame.source == source_key(source))
    }

    pub(crate) fn register(&mut self, source: &str, capture: bool, span: Span, facts: SiteFacts) {
        if let Some(frame) = self.top(source, capture)
            && frame.graph.charge(
                1,
                64 + FACT_BYTES * (facts.facts.len() + facts.success.len()) as u64,
            )
        {
            frame.registrations.push((span, facts));
        }
    }

    /// How many registrations the innermost frame holds, so an enclosing
    /// construct can later claim only what its nested constructs did not.
    pub(crate) fn registered(&self) -> usize {
        self.frames
            .last()
            .map_or(0, |frame| frame.registrations.len())
    }

    /// Register `facts` at `span` without the facts nested constructs
    /// registered since `since`: those belong to the nested sites, which may
    /// sit on optional paths inside the construct.
    pub(crate) fn register_since(
        &mut self,
        source: &str,
        capture: bool,
        span: Span,
        since: usize,
        mut facts: SiteFacts,
    ) {
        if let Some(frame) = self.top(source, capture) {
            for (_, nested) in frame.registrations.iter().skip(since) {
                facts
                    .facts
                    .retain(|fact| !nested.facts.contains(fact) && !nested.success.contains(fact));
            }
        }
        self.register(source, capture, span, facts);
    }

    /// What a retained callee graph guarantees, charged to the innermost frame.
    pub(crate) fn requirements(&mut self, flow: &ControlFlow) -> Requirements {
        let Some(frame) = self.frames.last_mut() else {
            return Requirements::unknown();
        };
        let graph = &mut frame.graph;

        flow.requirements(&mut |_| false, &mut |_| None, &mut |work, bytes| {
            graph.charge(work, bytes)
        })
    }

    /// Forget runtimes launched before the construct about to be evaluated,
    /// such as command substitutions in its words.
    pub(crate) fn mark(&mut self) {
        if let Some(frame) = self.frames.last_mut() {
            frame.children.clear();
        }
    }

    /// Success facts of the runtime a shell command launched since the last
    /// mark, when the command's own process is exactly that runtime: its
    /// successful status is then the runtime's successful completion. The
    /// execution structure must show one launch whose only transition is the
    /// interpreter or script run; wrappers, startup code, and repeated or
    /// alternative runs leave the child's facts unproven.
    pub(crate) fn launched(&mut self, edges: &[ExecutionEdge]) -> Vec<ControlFact> {
        let Some(frame) = self.frames.last_mut().filter(|frame| !frame.capture) else {
            return Vec::new();
        };
        let children = std::mem::take(&mut frame.children);
        let [child] = children.as_slice() else {
            return Vec::new();
        };
        let into_child: Vec<_> = edges
            .iter()
            .filter(|edge| edge.to == child.execution)
            .collect();
        let proven = match into_child.as_slice() {
            [run]
                if matches!(
                    run.kind,
                    ExecutionEdgeKind::Interpreter | ExecutionEdgeKind::Script
                ) && !run.cycle =>
            {
                let launch = run.from;
                let outgoing = edges.iter().filter(|edge| edge.from == launch).count();
                let incoming: Vec<_> = edges.iter().filter(|edge| edge.to == launch).collect();
                outgoing == 1
                    && matches!(incoming.as_slice(), [edge]
                        if edge.kind == ExecutionEdgeKind::Launch
                            && edge.from == frame.execution
                            && !edge.cycle)
            }
            _ => false,
        };
        if !proven {
            return Vec::new();
        }
        child
            .requirements
            .on_success
            .iter()
            .copied()
            .filter(|fact| matches!(fact, ControlFact::Effect(_)))
            .collect()
    }
    pub(crate) fn widen(&mut self) {
        if let Some(frame) = self.frames.last_mut() {
            frame.graph.widen();
        }
    }

    /// Resolve the innermost frame. A plan frame hands its guarantees to the
    /// frame that launched it; the analyzed subject's own frame promotes the
    /// plan effects it requires.
    pub(crate) fn leave(&mut self, effects: usize) -> Option<Finished> {
        let ControlStackFrame {
            capture,
            root,
            execution,
            graph,
            registrations,
            effects_start,
            ..
        } = self.frames.pop()?;
        if !capture && let Some(parent) = self.frames.last_mut() {
            parent.nested.push(effects_start..effects);
        }
        let Graph {
            mut flow,
            sites,
            guards,
            budget,
            caps,
            bytes,
            mut work,
            mut refused,
            ..
        } = graph;
        let mut facts: BTreeMap<Span, SiteFacts> = BTreeMap::new();
        for (span, registered) in registrations {
            match facts.get_mut(&span) {
                Some(existing) => existing.merge(&registered),
                None => {
                    facts.insert(span, registered);
                }
            }
        }
        // Exits the syntax attached to a site's node describe control
        // continuing past it; the site's own exits are added below.
        let structural = flow.exits.len();
        for site in &sites {
            let node = &mut flow.nodes[site.node as usize];
            match (facts.get(&site.span), site.phase) {
                (None, Phase::Evaluate) => {
                    if site.opaque {
                        node.throws = true;
                        node.call_return = true;
                        flow.exits.push((site.node, ControlExit::Unknown));
                    }
                }
                (None, Phase::Lookup) => node.throws = true,
                (Some(registered), Phase::Lookup) => {
                    node.throws = !registered.reference_known;
                    if node.throws && registered.call_return {
                        let mut calls = registered.facts.iter().filter_map(|fact| match fact {
                            ControlFact::Call(slot) => Some(*slot),
                            _ => None,
                        });
                        if let (Some(slot), None) = (calls.next(), calls.next()) {
                            node.lookup_call = Some(slot);
                        }
                    }
                }
                (None, Phase::Success) => {}
                (Some(registered), Phase::Evaluate) => {
                    node.throws = registered.throws;
                    if registered.throws {
                        stamp_exn(&mut node.exn, registered.thrown.clone());
                    }
                    node.throw_facts = registered.throw_facts.clone();
                    node.call_return = registered.call_return;
                    flow.saturated |= registered.widen;
                    node.facts = registered.facts.clone();
                    node.facts
                        .extend(registered.facts.iter().filter_map(|fact| match fact {
                            ControlFact::Call(slot) => Some(ControlFact::CallSuccess(*slot)),
                            _ => None,
                        }));
                    node.blocks = !registered.returns;
                    node.maybe_return = registered.returns && !registered.succeeds;
                    if let Some(exit) = &registered.exit {
                        let mut calls = registered.facts.iter().filter_map(|fact| match fact {
                            ControlFact::Call(slot) => Some(*slot),
                            _ => None,
                        });
                        let exit = match (exit, calls.next(), calls.next()) {
                            (ControlExit::Unknown, Some(slot), None) if registered.call_return => {
                                ControlExit::Call { slot }
                            }
                            _ => exit.clone(),
                        };
                        flow.exits.push((site.node, exit));
                    }
                }
                (Some(registered), Phase::Success) => {
                    node.facts = registered.success.clone();
                }
            }
        }
        let mut index = 0;
        flow.exits.retain(|(node, exit)| {
            index += 1;
            index > structural
                || !flow.nodes[*node as usize].blocks
                || matches!(exit, ControlExit::Unwind)
        });
        for (node, span) in guards {
            if !flow.nodes[node as usize].blocks
                && !facts
                    .get(&span)
                    .is_some_and(|registered| registered.exit.is_none() && !registered.widen)
            {
                flow.exits.push((node, ControlExit::Success));
            }
        }
        let mut scratch = 0;
        let requirements = flow.requirements(&mut |_| false, &mut |_| None, &mut |steps, bytes| {
            match charge_control(&budget, caps, &mut work, steps, bytes) {
                Ok(()) => {
                    scratch += bytes;
                    true
                }
                Err(limit) => {
                    refused.get_or_insert(limit);
                    false
                }
            }
        });
        if let Some(budget) = &budget {
            budget.release_bytes(bytes + scratch);
        }
        // Unknown and import exits keep later sites possible, but they are not
        // themselves a modeled successful completion: without a proven one the
        // intersection is vacuous and proves nothing.
        let promote = if root && requirements.succeeds {
            requirements
                .on_success
                .iter()
                .filter_map(|fact| match fact {
                    ControlFact::Effect(slot) => Some(*slot),
                    ControlFact::Call(_) | ControlFact::CallSuccess(_) => None,
                })
                .collect()
        } else {
            Vec::new()
        };
        if !capture
            && let Some(parent) = self.frames.last_mut()
            && !parent.capture
            && parent.execution != execution
        {
            parent.children.push(ChildRun {
                execution,
                requirements: requirements.clone(),
            });
        }
        flow.saturated |= refused.is_some();
        Some(Finished {
            flow,
            requirements,
            refused,
            promote,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UNBOUNDED: ControlCaps = ControlCaps {
        nodes: u64::MAX,
        work: u64::MAX,
    };

    fn required(flow: &ControlFlow) -> BTreeSet<ControlFact> {
        flow.requirements(&mut |_| false, &mut |_| None, &mut |_, _| true)
            .on_success
    }

    fn fill(graph: &mut Graph, facts: &[(u32, ControlFact)]) {
        for (node, fact) in facts {
            graph.flow.nodes[*node as usize].facts.push(*fact);
        }
    }

    #[test]
    fn required_occurrences_respect_joins_unknown_exits_and_loop_backedges() {
        use ControlFact::Effect;
        let mut graph = Graph::new(None, UNBOUNDED);
        let entry = graph.entry();
        let prefix = graph.site(entry, (0, 1), false);
        let yes = graph.site(prefix, (1, 2), false);
        let no = graph.site(prefix, (2, 3), false);
        let join = graph.join(&[yes, no]);
        let tail = graph.site(join, (3, 4), false);
        graph.exit(tail, ControlExit::Success);
        fill(
            &mut graph,
            &[
                (prefix.unwrap(), Effect(0)),
                (yes.unwrap(), Effect(1)),
                (no.unwrap(), Effect(2)),
                (tail.unwrap(), Effect(3)),
            ],
        );
        assert_eq!(
            required(&graph.flow),
            BTreeSet::from([Effect(0), Effect(3)])
        );
        // Unknown code after the prefix may complete without the tail.
        graph.unknown(prefix);
        assert_eq!(required(&graph.flow), BTreeSet::from([Effect(0)]));

        let mut graph = Graph::new(None, UNBOUNDED);
        let entry = graph.entry();
        let header = graph.header(entry);
        let body = graph.site(header, (0, 1), false);
        graph.backedge(body, header);
        fill(&mut graph, &[(body.unwrap(), Effect(0))]);
        // A loop without an exit proves nothing, not everything.
        assert!(required(&graph.flow).is_empty());
        graph.exit(body, ControlExit::Success);
        assert_eq!(required(&graph.flow), BTreeSet::from([Effect(0)]));
        graph.exit(header, ControlExit::Success);
        assert!(required(&graph.flow).is_empty());
        assert!(
            graph
                .flow
                .requirements(&mut |_| false, &mut |_| None, &mut |_, _| false)
                .on_success
                .is_empty()
        );
        graph.widen();
        assert!(required(&graph.flow).is_empty());
    }

    #[test]
    fn builtin_handlers_distinguish_match_mismatch_and_unknown() {
        assert_eq!(
            catches(
                &Exn::named(Symbol::py("RuntimeError")),
                &Catch::named(Symbol::py("Exception"))
            ),
            Match::Yes
        );
        assert_eq!(
            catches(
                &Exn::named(Symbol::py("RuntimeError")),
                &Catch::named(Symbol::py("ValueError"))
            ),
            Match::No
        );
        assert_eq!(
            catches(
                &Exn::named(Symbol::py("SystemExit")),
                &Catch::named(Symbol::py("Exception"))
            ),
            Match::No
        );
        assert_eq!(
            catches(&Exn::Unknown, &Catch::named(Symbol::py("ValueError"))),
            Match::Maybe
        );
        assert_eq!(
            catches(&Exn::named(Symbol::py("RuntimeError")), &Catch::Any),
            Match::Yes
        );
        assert_eq!(
            catches(
                &Exn::named(Symbol::binding("E")),
                &Catch::named(Symbol::binding("E"))
            ),
            Match::Maybe
        );
        assert_eq!(
            catches(
                &Exn::named(Symbol::binding("RuntimeError")),
                &Catch::named(Symbol::py("Exception"))
            ),
            Match::Maybe
        );
    }

    #[test]
    fn blocked_sites_and_discharged_imports_shape_exits() {
        use ControlFact::{Call, Effect};
        let mut graph = Graph::new(None, UNBOUNDED);
        let entry = graph.entry();
        let import = graph.site(entry, (0, 1), true);
        graph.exit(
            import,
            ControlExit::Import {
                module: "helper".into(),
            },
        );
        let call = graph.site(import, (1, 2), true);
        let never = graph.site(call, (2, 3), true);
        let after = graph.site(never, (3, 4), false);
        graph.exit(after, ControlExit::Success);
        fill(
            &mut graph,
            &[(call.unwrap(), Call(0)), (after.unwrap(), Effect(0))],
        );
        graph.flow.nodes[never.unwrap() as usize].blocks = true;
        let flow = &graph.flow;
        let undischarged = flow.requirements(&mut |_| false, &mut |_| None, &mut |_, _| true);
        assert!(
            undischarged.on_success.is_empty() && undischarged.may_exit && !undischarged.succeeds
        );
        let discharged = flow.requirements(
            &mut |module| module == "helper",
            &mut |_| None,
            &mut |_, _| true,
        );
        // The only exit left was never reached: no vacuous requirement.
        assert!(discharged.on_success.is_empty() && !discharged.succeeds && !discharged.may_exit);
        graph.flow.nodes[never.unwrap() as usize].blocks = false;
        let discharged = graph.flow.requirements(
            &mut |module| module == "helper",
            &mut |_| None,
            &mut |_, _| true,
        );
        assert_eq!(discharged.on_success, BTreeSet::from([Call(0), Effect(0)]));
    }
}
