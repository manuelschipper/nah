//! Observed producers: which earlier writes' pending flow values a use of a
//! shell variable observes where it stands. A write under a condition leaves
//! the producers of the writes before it on the paths that skip it, an
//! `&&`/`||` chain establishes which operands certainly ran, and a loop body
//! is walked again while a value it stored reaches a use earlier in it on the
//! next iteration.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::rc::Rc;

use crate::builder::PlanBuilder;
use crate::flow::FlowRef;

use super::lex::{Seg, ShellSpan};
use super::parse::{self, GroupKind, ShellItem};
use super::shell_env::{ArrayValue, ShellEnv, VarEntry};
use super::{Shell, Termination, eval};

/// Whether everything running under `current` also runs under `required`.
pub(in crate::shell) fn condition_implies(
    current: &effinterp_proto::Condition,
    required: &effinterp_proto::Condition,
) -> bool {
    use effinterp_proto::Condition;
    if matches!(current, Condition::Widened) || matches!(required, Condition::Widened) {
        return false;
    }
    if current == required {
        return true;
    }
    if let Condition::All { conditions } = required {
        return conditions
            .iter()
            .all(|required| condition_implies(current, required));
    }
    if let Condition::All { conditions } = current {
        return conditions
            .iter()
            .any(|current| condition_implies(current, required));
    }
    false
}

impl VarEntry {
    /// The producers a use at the builder's current condition observes: those
    /// of the latest write that certainly ran before it, joined with every
    /// later write that may have. A write in another arm of a branch the use
    /// sits in did not run; writes that together cover every path leave
    /// nothing of the value before them. An arm an earlier iteration of a
    /// loop took is another matter: each further iteration `walk_loop` walks
    /// names its conditions as their own instance, so they exclude nothing
    /// of the iteration before.
    ///
    /// `held` names what an `&&`/`||` chain already established where the use
    /// runs, beyond the builder's condition: the operands that certainly ran
    /// before it.
    pub(in crate::shell) fn producers_in_condition(
        &self,
        builder: &PlanBuilder,
        held: &[effinterp_proto::Condition],
    ) -> Vec<FlowRef> {
        let current =
            effinterp_proto::Condition::compose(builder.current_condition().iter().chain(held));
        let mut fixed = Vec::new();
        if let Some(current) = &current {
            condition_atoms(current, &mut fixed);
        }
        let mut observed: Vec<&[FlowRef]> = Vec::new();
        let mut certain = false;
        let mut terms = Vec::new();
        let writes = self
            .earlier_producers
            .iter()
            .map(|(condition, producers)| (condition.as_ref(), producers))
            .chain([(self.producers_condition.as_ref(), &self.producers)]);
        for (condition, producers) in writes {
            let Some(required) = condition else {
                observed = vec![producers];
                certain = true;
                terms.clear();
                continue;
            };
            if current
                .as_ref()
                .is_some_and(|current| condition_implies(current, required))
            {
                observed = vec![producers];
                certain = true;
                terms.clear();
                continue;
            }
            let mut atoms = Vec::new();
            let plain = condition_atoms(required, &mut atoms);
            let exclusive = |atom: &&effinterp_proto::ConditionAtom| {
                matches!(
                    atom.origin.kind,
                    effinterp_proto::ConditionKind::Branch
                        | effinterp_proto::ConditionKind::ShortCircuit
                ) && fixed
                    .iter()
                    .any(|held| held.origin == atom.origin && held.arm != atom.arm)
            };
            if plain && atoms.iter().any(exclusive) {
                continue;
            }
            observed.push(producers);
            // The arms this write still depends on once the use's own are fixed.
            let open = atoms
                .into_iter()
                .filter(|atom| !fixed.iter().any(|held| held == atom))
                .collect::<Vec<_>>();
            if plain
                && open.iter().all(|atom| {
                    atom.exhaustive
                        && matches!(
                            atom.origin.kind,
                            effinterp_proto::ConditionKind::Branch
                                | effinterp_proto::ConditionKind::ShortCircuit
                        )
                })
            {
                terms.push(
                    open.into_iter()
                        .map(|atom| (atom.origin.clone(), (atom.arm, atom.arms)))
                        .collect::<BTreeMap<_, _>>(),
                );
            }
        }
        if certain && observed.len() > 1 && eval::variable_binding::paths_cover(&terms) {
            observed.remove(0);
        }
        let mut producers = observed.concat();
        producers.sort();
        producers.dedup();
        producers
    }

    /// The writes that bound this name's producers, oldest first.
    fn producer_writes(&self) -> Vec<(Option<effinterp_proto::Condition>, Vec<FlowRef>)> {
        let mut writes = self.earlier_producers.clone();
        writes.push((self.producers_condition.clone(), self.producers.clone()));
        writes
    }

    /// This binding as the next iteration of a loop starts with it, given the
    /// writes the name had before the loop. A write the body made ran under
    /// an earlier iteration's conditions, which say nothing about the arms
    /// this iteration takes, so it may have run on any path.
    fn carried_into_next_iteration(
        &self,
        before: &[(Option<effinterp_proto::Condition>, Vec<FlowRef>)],
    ) -> Self {
        let mut writes = self.producer_writes();
        let kept = writes
            .iter()
            .zip(before)
            .take_while(|(now, before)| now == before)
            .count();
        for (condition, _) in &mut writes[kept..] {
            if condition.is_some() {
                *condition = Some(effinterp_proto::Condition::Widened);
            }
        }
        let mut carried = self.clone();
        if let Some((condition, producers)) = writes.pop() {
            carried.producers_condition = condition;
            carried.producers = producers;
        }
        carried.earlier_producers = writes;
        carried
    }
}

/// Collect the atoms a conjunction requires. False when the condition holds
/// anything else (a disjunction or a widened formula), which names no arm.
fn condition_atoms<'a>(
    condition: &'a effinterp_proto::Condition,
    atoms: &mut Vec<&'a effinterp_proto::ConditionAtom>,
) -> bool {
    use effinterp_proto::Condition;
    match condition {
        Condition::Atom { atom } => {
            atoms.push(atom);
            true
        }
        Condition::All { conditions } => conditions
            .iter()
            .fold(true, |plain, inner| condition_atoms(inner, atoms) && plain),
        Condition::Any { .. } | Condition::Widened => false,
    }
}

/// The loop reads of one loop body pass: for each variable name a use in the
/// body expanded, the producers that use observed. A name unbound at its use
/// is recorded with none.
pub(super) type LoopReads = Rc<RefCell<BTreeMap<String, BTreeSet<FlowRef>>>>;

/// Record a loop read: a use of `name` that observed `producers`, where a
/// loop body's first pass is collecting them (`ShellEnv::loop_reads`).
/// `walk_loop` compares them with what the next iteration would observe.
pub(in crate::shell) fn record_loop_read(
    loop_reads: Option<&LoopReads>,
    name: &str,
    producers: &[FlowRef],
) {
    if let Some(reads) = loop_reads {
        reads
            .borrow_mut()
            .entry(name.to_string())
            .or_default()
            .extend(producers.iter().cloned());
    }
}

/// One operand of an `&&`/`||` chain, as the operand after it sees it.
pub(super) struct ChainOperand {
    /// The prefix the operand follows and its operator's polarity; `None` for
    /// a chain's first operand and for one a known status decided.
    step: Option<(ShellSpan, bool)>,
    /// Reached through `&&`, or the chain's first operand.
    positive: bool,
    /// The run conditions of the earlier operands of this chain that
    /// certainly ran before this one, at most `MAX_CHAIN_HELD`.
    held: Vec<effinterp_proto::Condition>,
    /// This operand's run condition and the simpler one its writes are
    /// stated under, as `ShellEnv::chain_alias` holds it.
    alias: Option<Box<(effinterp_proto::Condition, effinterp_proto::Condition)>>,
    /// The operand is an assignment of fixed text, which cannot fail.
    infallible: bool,
    /// What the enclosing list had established, which holds for every item
    /// of this one.
    outer_held: Vec<effinterp_proto::Condition>,
    outer_alias: Option<Box<(effinterp_proto::Condition, effinterp_proto::Condition)>>,
}

/// Cap on the earlier operands a chain keeps as established: a use reads a
/// value written a few operands back, and a long chain must not grow what
/// every operand carries.
const MAX_CHAIN_HELD: usize = 4;

impl ChainOperand {
    /// The state before a list's first item, inside the chain the enclosing
    /// list had established.
    pub(super) fn within(
        outer_held: Vec<effinterp_proto::Condition>,
        outer_alias: Option<Box<(effinterp_proto::Condition, effinterp_proto::Condition)>>,
    ) -> Self {
        Self {
            step: None,
            positive: true,
            held: Vec::new(),
            alias: None,
            infallible: false,
            outer_held,
            outer_alias,
        }
    }
}

/// Cap on the further passes a loop body gets: a value is followed across
/// this many iteration boundaries, and each pass states the body's effects
/// again.
const MAX_LOOP_CARRY_PASSES: u32 = 4;

/// The command that produced a pending flow value: the source span of the
/// effects its stage carries. Producers whose stage carries none (the output
/// of a process substitution a `read` consumes) share one site.
type ProducerSite = Option<(u32, u32)>;

fn producer_site(builder: &PlanBuilder, producer: &FlowRef) -> ProducerSite {
    builder
        .pending_flow_stage_effects(producer.stage)
        .iter()
        .find_map(|effect| {
            let span = builder.source_span(builder.effect_provenance(*effect as usize)?)?;
            Some((span.start, span.end))
        })
}

/// Record a `continue`: what each name holds where the next iteration of the
/// enclosing loops starts from here. A `continue` of an inner loop is
/// recorded for the outer ones too, which only adds to what they consider.
pub(in crate::shell) fn record_loop_continue(builder: &PlanBuilder, env: &ShellEnv) {
    if env.loop_continues.is_empty() {
        return;
    }
    let scalars = env
        .vars
        .iter()
        .map(|(name, entry)| (name, entry.producers_in_condition(builder, &env.chain_held)));
    let arrays = env
        .arrays
        .iter()
        .map(|(name, array)| (name, array.producers()));
    for (name, producers) in scalars.chain(arrays) {
        if producers.is_empty() {
            continue;
        }
        for continues in &env.loop_continues {
            continues
                .borrow_mut()
                .entry(name.clone())
                .or_default()
                .extend(producers.iter().cloned());
        }
    }
}

/// How a loop body's first iteration can be followed by another.
#[derive(PartialEq, Eq)]
enum NextIteration {
    /// The body can reach its end, which starts the next iteration.
    AfterBody,
    /// Every path reaches an unconditional `break`, `exit` or `return`
    /// unless a `continue` ahead of it starts the next iteration.
    AfterContinue,
    /// Every path reaches an unconditional `break`, `exit` or `return`.
    Never,
}

fn next_iteration(items: &[ShellItem], env: &ShellEnv) -> NextIteration {
    fn continues(items: &[ShellItem]) -> bool {
        items.iter().any(|item| match item {
            ShellItem::Pipeline { cmds, .. } => cmds.iter().any(|cmd| {
                cmd.words.first().and_then(parse::literal_text).as_deref() == Some("continue")
            }),
            ShellItem::Group { items, .. } | ShellItem::For { items, .. } => continues(items),
            ShellItem::Alternatives { arms, .. } => arms.iter().any(|arm| continues(arm)),
            _ => false,
        })
    }
    fn ends(item: &ShellItem, env: &ShellEnv) -> bool {
        match item {
            ShellItem::Pipeline {
                cmds,
                conditional: false,
                ..
            } => matches!(cmds.as_slice(), [cmd]
            if cmd.words.first().and_then(parse::literal_text).is_some_and(|name| {
                matches!(name.as_str(), "break" | "exit" | "return") && !env.may_redefine(&name)
            })),
            ShellItem::Group {
                kind: GroupKind::Brace,
                items,
            } => next_iteration(items, env) == NextIteration::Never,
            ShellItem::Alternatives { arms, .. } => arms
                .iter()
                .all(|arm| next_iteration(arm, env) == NextIteration::Never),
            _ => false,
        }
    }
    match items.iter().position(|item| ends(item, env)) {
        None => NextIteration::AfterBody,
        Some(at) if continues(&items[..at]) => NextIteration::AfterContinue,
        Some(_) => NextIteration::Never,
    }
}

impl Shell<'_> {
    /// Record what an `&&`/`||` chain has established when `item` runs, given
    /// the operand before it. `A && B && C` runs `C` only after `B` ran, so a
    /// write in `B` is certain there. After `A && B`, an `||` operand runs at
    /// least whenever `A` failed, and exactly then when `B` is an assignment
    /// of fixed text, which cannot fail.
    #[inline(never)]
    pub(super) fn enter_chain_operand(
        &self,
        builder: &PlanBuilder,
        env: &mut ShellEnv,
        chain: &mut ChainOperand,
        item: &ShellItem,
        selection: Option<(ShellSpan, bool)>,
        selected: Option<bool>,
    ) {
        let runs_when = |(span, positive): (ShellSpan, bool), runs: bool| {
            self.source_condition(
                builder,
                effinterp_proto::ByteSpan {
                    start: span.start,
                    end: span.end,
                },
                effinterp_proto::ConditionKind::ShortCircuit,
                u32::from(positive != runs),
                2,
                true,
                true,
            )
        };
        // An assignment of fixed text always succeeds.
        let infallible = matches!(item, ShellItem::Pipeline { cmds, .. }
        if matches!(cmds.as_slice(), [cmd]
            if cmd.words.is_empty()
                && cmd.redirs.is_empty()
                && !cmd.assignments.is_empty()
                && cmd.assignments.iter().all(|assign| {
                    assign.value.segs.iter().all(|seg| matches!(seg, Seg::Literal { .. }))
                })));
        let previous = (chain.step, chain.positive, chain.infallible);
        chain.infallible = infallible;
        chain.alias = None;
        match selection {
            None => {
                chain.step = None;
                chain.positive = true;
                chain.held.clear();
            }
            Some((span, positive)) => {
                // A known status decides the operand outright, so it names no
                // condition.
                chain.step = selected.is_none().then_some((span, positive));
                chain.positive = positive && selected.is_none();
                if positive && previous.1 {
                    chain
                        .held
                        .extend(previous.0.map(|step| runs_when(step, true)));
                    let excess = chain.held.len().saturating_sub(MAX_CHAIN_HELD);
                    chain.held.drain(..excess);
                } else {
                    chain.held.clear();
                }
                // `A && B || C` runs `C` at least whenever `A` failed, so a
                // write in `C` is stated under that outcome of `A`: with a
                // write `B` makes whenever `A` succeeded, the two cover
                // every path. Only when `B` cannot fail is that also all
                // `C` runs under, which is what its own uses may rely on.
                if !positive
                    && previous.1
                    && let (Some(step), Some(before)) = (chain.step, previous.0)
                {
                    let skipped = runs_when(before, false);
                    if previous.2 {
                        chain.held.push(skipped.clone());
                    }
                    chain.alias = Some(Box::new((runs_when(step, true), skipped)));
                }
            }
        }
        // Most items sit in no chain and leave the enclosing list's as it is.
        if !chain.held.is_empty() || env.chain_held.len() != chain.outer_held.len() {
            env.chain_held = chain
                .outer_held
                .iter()
                .chain(&chain.held)
                .cloned()
                .collect();
        }
        env.chain_alias = chain.alias.clone().or_else(|| chain.outer_alias.clone());
    }

    /// Enter the walk of a loop body's iteration `iteration`, counted from
    /// zero. A later iteration is another run of the body: the arm it takes
    /// of a branch says nothing about the arm an earlier iteration took, so
    /// its conditions name their own instance. Returns what
    /// `PlanBuilder::leave_condition_call` restores, and nothing for the
    /// first iteration, whose conditions stay as written.
    pub(super) fn enter_loop_iteration(
        &self,
        builder: &mut PlanBuilder,
        items: &[ShellItem],
        iteration: u32,
    ) -> Option<Option<String>> {
        let span = parse::items_span(items).filter(|_| iteration > 0)?;
        Some(builder.enter_condition_call(&effinterp_proto::stable_hash(
            effinterp_proto::CONDITION_SITE_HASH_DOMAIN,
            &(self.source_digest.as_ref(), span.start, span.end, iteration),
        )))
    }

    /// Walk a loop body with `pass`, then again while a value the body stored
    /// reaches a use earlier in it on the next iteration: each further pass
    /// starts from the bindings the one before left, so a value that takes
    /// several iterations to arrive (`eval "$x"; x=$z; z=$(curl …)`) is
    /// followed one hop per pass, up to `MAX_LOOP_CARRY_PASSES`. A loop
    /// nested in a further pass is walked once, so nesting adds passes
    /// instead of multiplying them; the enclosing loop's next pass shows what
    /// its own repetition would. A body that always leaves the loop has no
    /// next iteration to walk. One that a `continue` alone repeats is walked
    /// again only when what a name held at such a `continue` reaches an
    /// earlier use; that pass still starts from the bindings the whole body
    /// left, which is wider than the `continue` commands leave.
    pub(super) fn walk_loop(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        items: &[ShellItem],
        pass: impl Fn(&mut PlanBuilder, &mut ShellEnv, bool) -> Option<(Termination, u32)>,
    ) -> Option<(Termination, u32)> {
        let next = next_iteration(items, env);
        if env.loop_carry_pass || next == NextIteration::Never {
            return pass(builder, env, false);
        }
        let before = env
            .vars
            .iter()
            .filter(|(_, entry)| {
                !entry.producers.is_empty()
                    || entry.producers_condition.is_some()
                    || !entry.earlier_producers.is_empty()
            })
            .map(|(name, entry)| (name.clone(), entry.producer_writes()))
            .collect::<HashMap<_, _>>();
        let writes_before = |name: &str| before.get(name).map_or(&[][..], Vec::as_slice);
        // What the body's uses observed, over every pass walked so far, and
        // the commands whose values a pass was already started with.
        let mut reads: BTreeMap<String, BTreeSet<FlowRef>> = BTreeMap::new();
        let mut offered: BTreeMap<String, BTreeSet<ProducerSite>> = BTreeMap::new();
        // The first pass's `continue` commands, for a body they alone repeat.
        let mut continued: Option<BTreeMap<String, BTreeSet<FlowRef>>> = None;
        for carry in 0..=MAX_LOOP_CARRY_PASSES {
            if carry > 0 {
                // The first pass's producers are compared as they are. A
                // further pass states the body's effects again, so its
                // producers are new ones for the same commands and are
                // compared by the command that produced them.
                let by_site = carry > 1;
                let mut reaches_earlier_use = false;
                for (name, seen) in &reads {
                    // Where only a `continue` starts the next iteration, what
                    // the name held there. Otherwise a scalar's binding as
                    // the body left it, and the elements an array of that
                    // name was left with.
                    let next = match &continued {
                        Some(continued) => continued
                            .get(name)
                            .map_or(Vec::new(), |held| held.iter().cloned().collect()),
                        None => {
                            let mut next = env.vars.get(name).map_or(Vec::new(), |entry| {
                                entry
                                    .carried_into_next_iteration(writes_before(name))
                                    .producers_in_condition(builder, &env.chain_held)
                            });
                            next.extend(
                                env.arrays
                                    .get(name)
                                    .map_or(Vec::new(), ArrayValue::producers),
                            );
                            next
                        }
                    };
                    let seen_sites = seen
                        .iter()
                        .map(|producer| producer_site(builder, producer))
                        .collect::<BTreeSet<_>>();
                    let offered = offered.entry(name.clone()).or_default();
                    for producer in next {
                        let site = producer_site(builder, &producer);
                        reaches_earlier_use |= if by_site {
                            !seen_sites.contains(&site) && !offered.contains(&site)
                        } else {
                            !seen.contains(&producer)
                        };
                        offered.insert(site);
                    }
                }
                if !reaches_earlier_use {
                    break;
                }
                let carried = env
                    .vars
                    .iter()
                    .map(|(name, entry)| {
                        (
                            name.clone(),
                            entry.carried_into_next_iteration(writes_before(name)),
                        )
                    })
                    .collect();
                env.vars = carried;
            }
            let outer = env.loop_reads.replace(Rc::default());
            let termination = if carry == 0 {
                if next == NextIteration::AfterContinue {
                    env.loop_continues.push(Rc::default());
                }
                let termination = pass(builder, env, false);
                if next == NextIteration::AfterContinue {
                    continued = env.loop_continues.pop().map(|held| held.take());
                }
                termination
            } else {
                continued = None;
                let iteration = self.enter_loop_iteration(builder, items, carry);
                env.loop_carry_pass = true;
                pass(builder, env, true);
                env.loop_carry_pass = false;
                if let Some(previous) = iteration {
                    builder.leave_condition_call(previous);
                }
                None
            };
            let seen = std::mem::replace(&mut env.loop_reads, outer);
            let seen = seen.map(|reads| reads.take()).unwrap_or_default();
            // The enclosing loop's uses include this one's.
            if let Some(outer) = &env.loop_reads {
                let mut outer = outer.borrow_mut();
                for (name, seen) in &seen {
                    outer
                        .entry(name.clone())
                        .or_default()
                        .extend(seen.iter().cloned());
                }
            }
            for (name, seen) in seen {
                reads.entry(name).or_default().extend(seen);
            }
            if termination.is_some() {
                return termination;
            }
        }
        None
    }
}
