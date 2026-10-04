//! Observed producers: which earlier writes' pending flow values a use of a
//! shell variable observes where it stands. A write under a condition leaves
//! the producers of the writes before it on the paths that skip it, an
//! `&&`/`||` chain establishes which operands certainly ran, and a loop body
//! is walked a second time when a value it stored reaches a use earlier in it
//! on the next iteration.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::rc::Rc;

use crate::builder::PlanBuilder;
use crate::flow::FlowRef;

use super::lex::{Seg, ShellSpan};
use super::parse::{self, GroupKind, ShellItem};
use super::{Shell, ShellEnv, Termination, VarEntry, eval};

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
    /// nothing of the value before them.
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
        // One iteration's arm says nothing about the arm an earlier iteration took.
        let in_loop = fixed
            .iter()
            .any(|atom| atom.origin.kind == effinterp_proto::ConditionKind::Loop);
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
            if plain && !in_loop && atoms.iter().any(exclusive) {
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
    /// This operand's run condition and the simpler one it is equivalent to,
    /// as `ShellEnv::chain_alias` states it.
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

/// Whether every path through a loop body reaches an unconditional `break`,
/// `exit` or `return`, so no iteration follows the first. A `continue` ahead
/// of it starts the next iteration instead.
fn body_ends_loop(items: &[ShellItem], env: &ShellEnv) -> bool {
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
    let ends = |item: &ShellItem| match item {
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
        } => body_ends_loop(items, env),
        ShellItem::Alternatives { arms, .. } => arms.iter().all(|arm| body_ends_loop(arm, env)),
        _ => false,
    };
    items
        .iter()
        .position(ends)
        .is_some_and(|at| !continues(&items[..at]))
}

impl Shell<'_> {
    /// Record what an `&&`/`||` chain has established when `item` runs, given
    /// the operand before it. `A && B && C` runs `C` only after `B` ran, so a
    /// write in `B` is certain there. After `A && x=1`, an `||` operand runs
    /// exactly when `A` failed, since the assignment cannot fail: the two
    /// operands are the two outcomes of `A`.
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
                if !positive
                    && previous.1
                    && previous.2
                    && let (Some(step), Some(before)) = (chain.step, previous.0)
                {
                    let skipped = runs_when(before, false);
                    chain.held.push(skipped.clone());
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

    /// Walk a loop body with `pass`, then once more when a value the body
    /// stored reaches a use earlier in it on the next iteration: the second
    /// pass starts from the bindings the first left. One extra pass follows a
    /// value across one iteration boundary, and a loop nested in a second pass
    /// is walked once, so nesting adds a pass per level instead of doubling.
    /// A body that always leaves the loop has no next iteration to walk.
    pub(super) fn walk_loop(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        items: &[ShellItem],
        pass: impl Fn(&mut PlanBuilder, &mut ShellEnv, bool) -> Option<(Termination, u32)>,
    ) -> Option<(Termination, u32)> {
        if env.loop_carry_pass || body_ends_loop(items, env) {
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
        let outer = env.loop_reads.replace(Rc::default());
        let termination = pass(builder, env, false);
        let reads = std::mem::replace(&mut env.loop_reads, outer);
        let reads = reads.map(|reads| reads.take()).unwrap_or_default();
        // The enclosing loop's uses include this one's.
        if let Some(outer) = &env.loop_reads {
            let mut outer = outer.borrow_mut();
            for (name, seen) in &reads {
                outer
                    .entry(name.clone())
                    .or_default()
                    .extend(seen.iter().cloned());
            }
        }
        if termination.is_some() {
            return termination;
        }
        let writes_before = |name: &str| before.get(name).map_or(&[][..], Vec::as_slice);
        let reaches_earlier_use = reads.iter().any(|(name, seen)| {
            env.vars.get(name).is_some_and(|entry| {
                entry
                    .carried_into_next_iteration(writes_before(name))
                    .producers_in_condition(builder, &env.chain_held)
                    .iter()
                    .any(|producer| !seen.contains(producer))
            })
        });
        if !reaches_earlier_use {
            return None;
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
        env.loop_carry_pass = true;
        pass(builder, env, true);
        env.loop_carry_pass = false;
        None
    }
}
