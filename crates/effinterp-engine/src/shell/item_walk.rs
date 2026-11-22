//! Item walk: the statement-level walker. `walk_items` visits a list of
//! parsed shell items in order (pipelines, groups, subshells, loops,
//! alternatives, function definitions) and dispatches each to the walk that
//! owns its construct, carrying the environment from one item to the next.

use effinterp_proto::{
    AttrValue, BoundaryClass, BoundaryReason, Effect, ExecutionNodeRef, Modality, Operation,
    ResourceExpr,
};
use std::rc::Rc;

use crate::builder::PlanBuilder;
use crate::paths::process_identity_with_cwd;
use crate::word::Word;

use super::loop_values::ForLoopWalk;
use super::observed_producers::ChainOperand;
use super::parse::{GroupKind, ShellItem};
use super::shell_env::ShellEnv;
use super::{
    MAX_SATURATED_FUNCTION_STEPS, MAX_WALK_DEPTH, Shell, Termination, jobs, literal_word_text,
    parse,
};

impl Shell<'_> {
    /// Walk a list of parsed items, collecting each command's effects.
    /// `force_conditional` widens assignments to unknown inside constructs
    /// whose commands run on some paths only.
    pub(super) fn walk(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        items: &[ShellItem],
        force_conditional: bool,
        walk_depth: u32,
    ) -> Option<(Termination, u32)> {
        let depth = builder.condition_depth();
        let chain = (env.chain_held.clone(), env.chain_alias.clone());
        let following = Rc::clone(&env.background_followup);
        let chain_moved_cwd = std::mem::take(&mut env.chain_moved_cwd);
        let termination = self.walk_items(builder, env, items, force_conditional, walk_depth);
        if std::mem::replace(&mut env.chain_moved_cwd, chain_moved_cwd) {
            env.forget_cwd();
        }
        env.background_followup = following;
        (env.chain_held, env.chain_alias) = chain;
        while builder.condition_depth() > depth {
            builder.pop_condition();
        }
        termination
    }

    fn walk_items(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        items: &[ShellItem],
        force_conditional: bool,
        walk_depth: u32,
    ) -> Option<(Termination, u32)> {
        if walk_depth >= MAX_WALK_DEPTH {
            // The frame bound is the same kind of stop as a nest the parser
            // would not enter: the unread interior must not look like a
            // finished plan. The default policy blocks on this refusal.
            builder.note_nesting_limit();
            if let Some(span) = parse::items_span(items) {
                self.opaque_boundary(
                    builder,
                    BoundaryReason::PARTIAL_ANALYSIS,
                    BoundaryClass::Limit,
                    "shell walk depth bound reached",
                    span,
                );
            }
            return None;
        }
        let mut saturated_region_recorded = false;
        // Boxed: `walk_items` recurses once per nested group, so its frame
        // bounds nesting depth.
        let mut chain = Box::new(ChainOperand::within(
            env.chain_held.clone(),
            env.chain_alias.clone(),
        ));
        // Writes after the first background job, probed once for this list.
        let mut later_writes = None;
        let enclosing_writes = Rc::clone(&env.background_followup);
        for (index, item) in items.iter().enumerate() {
            env.background_followup = Rc::clone(&enclosing_writes);
            if self.nest.budget.timed_out() {
                builder.note_deadline();
                return None;
            }
            // Each list item gets its own allowance, so what an earlier item
            // spent cannot starve it, however deeply both are nested. The
            // first item of a nested shell's own source continues the segment
            // of the command that started that shell. Once this scope has
            // no room for another process, no later item can add one, so
            // none is granted more.
            if !self.nest.budget.measuring()
                && !builder.execution_saturated()
                && (self.depth == 0 || walk_depth > 0 || index > 0)
                && let Some(span) = parse::items_span(std::slice::from_ref(item))
            {
                self.nest.budget.begin_segment(
                    (self.source_digest.clone(), span.start),
                    (span.end - span.start) as usize,
                    self.depth > 0 || walk_depth > 0 || !env.active.is_empty(),
                );
            }
            let mut previous = index.checked_sub(1).and_then(|index| items.get(index));
            for _ in 0..effinterp_proto::MAX_CONDITION_DEPTH {
                if let Some(ShellItem::Group {
                    kind: GroupKind::Brace | GroupKind::Redirected,
                    items,
                }) = previous
                {
                    previous = items.last();
                } else {
                    break;
                }
            }
            if let Some(ShellItem::Alternatives { group, end, arms }) = previous {
                let stops = |arm: &Vec<ShellItem>| match arm.last() {
                    Some(ShellItem::Pipeline {
                        cmds,
                        conditional: false,
                        ..
                    }) => cmds
                        .last()
                        .and_then(|cmd| cmd.words.first())
                        .is_some_and(|word| {
                            self.source
                                .get(word.span.start as usize..word.span.end as usize)
                                .is_some_and(|name| {
                                    matches!(name, "return" | "exit" | "break" | "continue")
                                })
                        }),
                    _ => false,
                };
                if arms.iter().any(stops) {
                    let survivors: Vec<_> = arms
                        .iter()
                        .enumerate()
                        .filter(|(_, arm)| !stops(arm))
                        .map(|(arm, _)| {
                            self.source_condition(
                                builder,
                                effinterp_proto::ByteSpan {
                                    start: *group,
                                    end: *end,
                                },
                                effinterp_proto::ConditionKind::Branch,
                                arm as u32,
                                arms.len() as u32,
                                true,
                                arms.len() == 2
                                    && !self.source[*group as usize..].starts_with("case"),
                            )
                        })
                        .collect();
                    builder.push_condition(
                        effinterp_proto::Condition::disjoin(&survivors)
                            .unwrap_or(effinterp_proto::Condition::Widened),
                    );
                }
            }

            if let Some(span) = parse::items_span(std::slice::from_ref(item))
                && !self.charge(builder, 1, 0, span)
            {
                // A function body or a still-unread nested construct must
                // not disappear as ordinary uncertainty. Repeating a shallow
                // loop's leaf command, or walking a flat list, stays partial.
                if self.nest.budget.steps_saturated()
                    && (!env.active.is_empty()
                        || items[index..].iter().any(|item| {
                            matches!(
                                item,
                                ShellItem::Group { .. }
                                    | ShellItem::For { .. }
                                    | ShellItem::Alternatives { .. }
                                    | ShellItem::Function { .. }
                            ) && parse::items_span(std::slice::from_ref(item)).is_some_and(|span| {
                                !env.saturation_memos.borrow().walked_constructs.contains(&(
                                    Rc::clone(&self.source_digest),
                                    span.start,
                                    span.end,
                                ))
                            })
                        }))
                {
                    builder.note_step_limit();
                }
                return None;
            }
            if matches!(
                item,
                ShellItem::Group { .. }
                    | ShellItem::For { .. }
                    | ShellItem::Alternatives { .. }
                    | ShellItem::Function { .. }
            ) && let Some(span) = parse::items_span(std::slice::from_ref(item))
            {
                env.saturation_memos.borrow_mut().walked_constructs.insert((
                    Rc::clone(&self.source_digest),
                    span.start,
                    span.end,
                ));
            }
            // Head recovery cannot add evidence after the effect builder has
            // refused an effect and recorded max_effects saturation.
            if self.structural_saturated(builder, env) && builder.effects_saturated() {
                return None;
            }
            if env.function_heads_only {
                let mut memos = env.saturation_memos.borrow_mut();
                if memos.function_steps >= MAX_SATURATED_FUNCTION_STEPS {
                    return None;
                }
                memos.function_steps += 1;
            }
            if !saturated_region_recorded && self.nest.budget.exhausted() {
                if self.nest.budget.note_starved_region()
                    && let Some(span) = parse::items_span(&items[index..])
                {
                    self.opaque_boundary(
                        builder,
                        BoundaryReason::BRANCH_STARVED,
                        BoundaryClass::Limit,
                        "invocation budget exhausted before this region",
                        span,
                    );
                }
                saturated_region_recorded = true;
            }
            let selection = match item {
                ShellItem::Pipeline { short_circuit, .. } => *short_circuit,
                ShellItem::Group {
                    kind: GroupKind::ShortCircuit(selection),
                    ..
                } => *selection,
                _ => None,
            };
            let selected =
                selection.and_then(|(_, polarity)| env.status.map(|status| status == polarity));
            // A path that skipped the `&&` operand which moved the shell is
            // still in the directory before it once the chain ends.
            if env.chain_moved_cwd && !matches!(selection, Some((_, true))) {
                env.chain_moved_cwd = false;
                env.forget_cwd();
            }
            self.enter_chain_operand(builder, env, &mut chain, item, selection, selected);
            if selected == Some(false) {
                continue;
            }
            let background = matches!(
                item,
                ShellItem::Group {
                    kind: GroupKind::Background,
                    ..
                }
            );
            let scoped_filesystem = background && !self.nest.budget.measuring();
            if scoped_filesystem {
                self.nest.budget.enter_background_filesystem();
            }
            // Held until this item's walk ends.
            let (hazard_depth, background_mutations, entry_filesystem, _pipeline_lanes) = self
                .probe_racing_writes(
                    builder,
                    env,
                    items,
                    index,
                    force_conditional,
                    walk_depth,
                    &mut later_writes,
                    &enclosing_writes,
                );
            if self.nest.budget.timed_out() {
                if scoped_filesystem {
                    self.nest.budget.leave_background_filesystem(false);
                }
                builder.note_deadline();
                return None;
            }
            match item {
                ShellItem::UnwalkedExpansion { span } => {
                    env.status = None;
                    self.unwalked_expansion_boundary(
                        builder,
                        *span,
                        "command-capable expansion in shell header is not analyzed",
                    );
                }
                ShellItem::Unsupported { construct, span } => {
                    env.status = None;
                    if *construct == "nesting limit" {
                        builder.note_nesting_limit();
                    }
                    self.opaque_boundary(
                        builder,
                        BoundaryReason::UNSUPPORTED_SHELL_SYNTAX,
                        BoundaryClass::Unsupported,
                        construct,
                        *span,
                    );
                }
                ShellItem::ParseError { message, span } => {
                    env.status = None;
                    self.opaque_boundary(
                        builder,
                        BoundaryReason::PARSE_ERROR,
                        BoundaryClass::ParseFailure,
                        message,
                        *span,
                    );
                }
                // The loop itself runs the processes: each iteration starts a
                // job the shell never reaps, and the loop never ends.
                ShellItem::UnboundedSpawn { condition, span } => {
                    // A function of the condition's name shadows the builtin
                    // the loop's repetition was read from; its body decides
                    // whether the loop ends, so nothing here is established.
                    if condition
                        .as_ref()
                        .is_some_and(|name| env.functions.contains_key(name))
                    {
                        continue;
                    }
                    let node = self.span_node(builder, *span);
                    builder.effect(Effect {
                        request_assurance: effinterp_proto::RequestAssurance::Conservative,
                        id: Default::default(),
                        operation: Operation::new("process.code_execution"),
                        resource: ResourceExpr::Concrete {
                            identity: process_identity_with_cwd(
                                &[Word::literal("sh")],
                                env.cwd_resource.clone(),
                            ),
                        },
                        attributes: [("source".to_string(), AttrValue::String("loop".to_string()))]
                            .into_iter()
                            .collect(),
                        modality: Modality::May,
                        realm: effinterp_proto::ExecutionRealm::Host,
                        condition: None,
                        execution: ExecutionNodeRef(0),
                        provenance: vec![node],
                    });
                }
                item @ ShellItem::Function { .. } => self.define_function(env, item),
                ShellItem::Pipeline {
                    cmds, conditional, ..
                } => {
                    // `command cd` and `builtin cd` run the same builtin.
                    env.cd_moves_chain = *conditional
                        && !force_conditional
                        && matches!(selection, Some((_, true)))
                        && cmds.len() == 1
                        && cmds[0]
                            .words
                            .iter()
                            .map(literal_word_text)
                            .find(|name| {
                                !name.as_deref().is_some_and(|name| {
                                    matches!(name, "command" | "builtin") && !env.may_redefine(name)
                                })
                            })
                            .flatten()
                            .is_some_and(|name| {
                                matches!(name.as_str(), "cd" | "pushd") && !env.may_redefine(&name)
                            });
                    let termination = self.walk_pipeline(
                        builder,
                        env,
                        item,
                        items.get(index + 1),
                        selected,
                        force_conditional,
                    );
                    env.cd_moves_chain = false;
                    if let Some(termination) = termination {
                        return Some(termination);
                    }
                }
                ShellItem::Group { kind, items } => match kind {
                    GroupKind::Coprocess { name, span } => {
                        self.coprocess(builder, env, name.as_deref(), *span, force_conditional);
                    }
                    // The redirections open before the body runs and are
                    // undone after it, like a function's definition-time
                    // redirections around its call.
                    GroupKind::Redirected => {
                        if let Some(termination) =
                            self.walk_redirected(builder, env, items, force_conditional, walk_depth)
                        {
                            return Some(termination);
                        }
                    }
                    // A brace group runs in the current shell.
                    GroupKind::Brace => {
                        if let Some(termination) =
                            self.walk(builder, env, items, force_conditional, walk_depth + 1)
                        {
                            return Some(termination);
                        }
                    }
                    // Construct bodies run only on some paths.
                    // A loop whose constant condition enters a body that
                    // always reaches its end certainly runs that body once.
                    GroupKind::Conditional {
                        entry: Some(head), ..
                    } if !head
                        .as_ref()
                        .is_some_and(|name| env.functions.contains_key(name)) =>
                    {
                        if let Some(termination) = self.walk_loop(
                            builder,
                            env,
                            items,
                            entry_filesystem.as_deref(),
                            |builder, env, again| {
                                if again {
                                    self.walk_may_region(builder, env, items, walk_depth + 1);
                                    return None;
                                }
                                self.walk(builder, env, items, force_conditional, walk_depth + 1)
                            },
                        ) {
                            if let Some(depth) = hazard_depth {
                                builder.truncate_source_hazards(depth);
                            }
                            return Some(termination);
                        }
                        env.status = None;
                    }
                    GroupKind::Conditional { read_condition, .. } => {
                        // A `while read` over input the request spells
                        // runs its body once per line.
                        if let Some(read) = read_condition
                            .then(|| self.read_loop(builder, env, &items[0]))
                            .flatten()
                        {
                            let termination = self.walk_read_loop(
                                builder,
                                env,
                                items,
                                read,
                                force_conditional,
                                walk_depth,
                                hazard_depth,
                                entry_filesystem.as_deref(),
                            );
                            if termination.is_some() {
                                return termination;
                            }
                        } else {
                            self.walk_loop(
                                builder,
                                env,
                                items,
                                entry_filesystem.as_deref(),
                                |builder, env, _| {
                                    self.walk_may_region(builder, env, items, walk_depth + 1);
                                    None
                                },
                            );
                        }
                        env.status = None;
                    }
                    // Nothing reaches these commands unless the command that
                    // decided so is redefined.
                    GroupKind::Unreachable { head } => {
                        if head.as_ref().is_some_and(|name| env.may_redefine(name)) {
                            self.walk_may_region(builder, env, items, walk_depth + 1);
                            env.status = None;
                        }
                    }
                    GroupKind::ShortCircuit(selection) => {
                        if selected == Some(true) {
                            if let Some(termination) =
                                self.walk(builder, env, items, force_conditional, walk_depth + 1)
                            {
                                return Some(termination);
                            }
                            continue;
                        }
                        self.walk_short_circuit(builder, env, items, *selection, walk_depth + 1);
                    }
                    // The parser runs a compound-first pipeline in a subshell;
                    // with `lastpipe` its final stage runs in this shell, and
                    // the redirected group isolates the stages before it.
                    GroupKind::Subshell
                        if env.lastpipe
                            && matches!(items.as_slice(), [ShellItem::Group {
                                kind: GroupKind::Redirected,
                                items,
                            }] if items.len() > 2) =>
                    {
                        if let Some(termination) =
                            self.walk(builder, env, items, force_conditional, walk_depth + 1)
                        {
                            return Some(termination);
                        }
                    }
                    // A subshell's state changes do not escape.
                    GroupKind::Subshell | GroupKind::Background | GroupKind::CompoundPipeline => {
                        let mut child = self.child_env(env);
                        child.close_coprocess_descriptors();
                        if matches!(kind, GroupKind::Background) {
                            child.background_depth += 1;
                        } else {
                            // A subshell reads the stdin its parent was given.
                            child.stdin = env.stdin.take();
                        }
                        if matches!(kind, GroupKind::CompoundPipeline) {
                            self.walk_compound_pipeline(
                                builder,
                                &mut child,
                                items,
                                force_conditional,
                                walk_depth + 1,
                            );
                        } else {
                            self.walk(
                                builder,
                                &mut child,
                                items,
                                force_conditional,
                                walk_depth + 1,
                            );
                        }
                        self.finish_deferred(builder, &mut child);
                        env.status = match kind {
                            GroupKind::Background => Some(true),
                            // `(( N ))` is a doubled subshell around N.
                            GroupKind::Subshell => {
                                jobs::constant_status(std::slice::from_ref(item)).or(child.status)
                            }
                            _ => None,
                        };
                    }
                },
                ShellItem::Alternatives { group, end, arms } if !arms.is_empty() => {
                    if arms.len() == 2
                        && self.source.get(*group as usize..).is_some_and(|source| {
                            source.starts_with("if") || source.starts_with("elif")
                        })
                        && let Some(status) = env.status
                    {
                        let arm = &arms[usize::from(!status)];
                        if arm.is_empty() {
                            env.status = Some(true);
                        }
                        if let Some(termination) =
                            self.walk(builder, env, arm, force_conditional, walk_depth + 1)
                        {
                            return Some(termination);
                        }
                        continue;
                    }
                    env.status = None;
                    self.walk_alternatives(builder, env, *group, *end, arms, walk_depth);
                }
                ShellItem::Alternatives { .. } => {}
                ShellItem::For { .. } => match self.walk_for_loop(
                    builder,
                    env,
                    item,
                    force_conditional,
                    walk_depth,
                    hazard_depth,
                    entry_filesystem.as_deref(),
                ) {
                    ForLoopWalk::Terminated(termination) => return Some(termination),
                    ForLoopWalk::HazardsSettled => continue,
                    ForLoopWalk::Walked => {}
                },
            }
            if scoped_filesystem {
                self.nest.budget.leave_background_filesystem(true);
            }
            match hazard_depth {
                Some(depth) if background && self.nest.resolver.is_some() => {
                    builder.truncate_background_read_hazards(depth)
                }
                Some(_) if background => {}
                Some(depth) => builder.truncate_source_hazards(depth),
                None => {}
            }
            if let Some(mutations) = background_mutations {
                builder.push_source_hazards(mutations, Vec::new(), None, true);
            }
        }
        None
    }
}
