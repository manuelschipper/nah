//! Item walk: the statement-level walker. `walk_items` visits a list of
//! parsed shell items in order (pipelines, groups, subshells, loops,
//! alternatives, function definitions) and dispatches each to the walk that
//! owns its construct, carrying the environment from one item to the next.

use effinterp_proto::{
    AttrValue, BoundaryClass, BoundaryReason, Effect, ExecutionNodeRef, Modality, Operation,
    ResourceExpr,
};

use crate::builder::PlanBuilder;
use crate::paths::process_identity_with_cwd;
use crate::value::unresolved_resource;
use crate::word::Word;

use super::eval::source_and_eval::note_expanded_assignments;
use super::eval::variable_binding::{bind_for_var, for_list_producers};
use super::for_list_iterations::{body_has_remote_command, body_runs_every_iteration};
use super::lex::{Seg, WordTok};
use super::observed_producers::ChainOperand;
use super::parse::{GroupKind, ShellItem};
use super::shell_env::ShellEnv;
use super::{
    MAX_SATURATED_FUNCTION_STEPS, MAX_WALK_DEPTH, Shell, Termination, eval, jobs,
    literal_word_text, parse,
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
        let termination = self.walk_items(builder, env, items, force_conditional, walk_depth);
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
        // The `git config` writes of each item after the first background
        // job, walked once for every job of this list.
        let mut later_git_config_writes = None;
        for (index, item) in items.iter().enumerate() {
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
                return None;
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
            self.enter_chain_operand(builder, env, &mut chain, item, selection, selected);
            if selected == Some(false) {
                continue;
            }
            // Probe the same models and reachable calls to discover writes that may
            // race this region's reads. Restore evidence and execution-node allocation;
            // analysis steps and elapsed time remain charged to this invocation.
            let background = matches!(
                item,
                ShellItem::Group {
                    kind: GroupKind::Background,
                    ..
                }
            );
            let unordered = background
                || matches!(
                    item,
                    ShellItem::For { .. }
                        | ShellItem::Group {
                            kind: GroupKind::Conditional { .. } | GroupKind::CompoundPipeline,
                            ..
                        }
                )
                || matches!(item, ShellItem::Pipeline { cmds, .. } if cmds.len() > 1)
                // A compound command feeding its consumer runs beside it.
                || matches!(item, ShellItem::Group {
                    kind: GroupKind::Redirected,
                    items,
                } if items.len() > 2);
            let hazard_depth = if unordered && self.nest.resolver.is_none() {
                // With no observed source there is nothing to discover by probing.
                // Still refuse transient source predictions in unordered regions.
                Some(builder.push_source_hazards(
                    vec![(unresolved_resource("filesystem"), true)],
                    Vec::new(),
                    None,
                    background,
                ))
            } else if unordered && !self.nest.budget.measuring() {
                // A pipeline numbers its stages at this depth, so a write it
                // carries stays out of its own stage's earlier reads.
                let stage_depth =
                    (matches!(item, ShellItem::Pipeline { cmds, .. } if cmds.len() > 1)
                        || matches!(
                            item,
                            ShellItem::Group {
                                kind: GroupKind::CompoundPipeline,
                                ..
                            }
                        )
                        || matches!(item, ShellItem::Group {
                        kind: GroupKind::Redirected,
                        items,
                    } if items.len() > 2))
                    .then(|| builder.pipeline_stage_depth());
                let git_config_start = builder.git_config_write_count();
                let cp = builder.checkpoint();
                let snap = self.nest.budget.snapshot();
                self.nest.budget.set_measuring(true);
                let mut probe = env.clone();
                probe.detach_probe_state();
                self.walk(
                    builder,
                    &mut probe,
                    std::slice::from_ref(item),
                    force_conditional,
                    walk_depth,
                );
                let mut mutations = builder.source_mutations_since(&cp);
                if self.nest.budget.exhausted() || builder.effects_saturated() {
                    mutations.push((unresolved_resource("filesystem"), true));
                }
                // A background job races the commands after it, up to a
                // `wait` for it, but runs its own commands in order.
                let git_config_writes = if background {
                    let end = (index + 1..items.len())
                        .find(|&at| waits_for_background(self.source, env, items, at))
                        .unwrap_or(items.len());
                    later_git_config_writes
                        .get_or_insert_with(|| {
                            self.later_git_config_writes(
                                builder,
                                &mut probe,
                                items,
                                index,
                                force_conditional,
                                walk_depth,
                            )
                        })
                        .iter()
                        .filter(|(at, _)| *at > index && *at < end)
                        .map(|(_, write)| write.clone())
                        .collect()
                } else {
                    builder.git_config_writes_from(git_config_start)
                };
                self.nest.budget.set_measuring(false);
                self.nest.budget.restore(snap);
                builder.rollback(cp);
                Some(builder.push_source_hazards(
                    mutations,
                    git_config_writes,
                    stage_depth,
                    background,
                ))
            } else {
                None
            };
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
                ShellItem::Pipeline { .. } => {
                    if let Some(termination) = self.walk_pipeline(
                        builder,
                        env,
                        item,
                        items.get(index + 1),
                        selected,
                        force_conditional,
                    ) {
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
                    GroupKind::Conditional { entry: Some(head) }
                        if !head
                            .as_ref()
                            .is_some_and(|name| env.functions.contains_key(name)) =>
                    {
                        if let Some(termination) =
                            self.walk_loop(builder, env, items, |builder, env, again| {
                                if again {
                                    self.walk_may_region(builder, env, items, walk_depth + 1);
                                    return None;
                                }
                                self.walk(builder, env, items, force_conditional, walk_depth + 1)
                            })
                        {
                            if let Some(depth) = hazard_depth {
                                builder.truncate_source_hazards(depth);
                            }
                            return Some(termination);
                        }
                        env.status = None;
                    }
                    GroupKind::Conditional { .. } => {
                        self.walk_loop(builder, env, items, |builder, env, _| {
                            self.walk_may_region(builder, env, items, walk_depth + 1);
                            None
                        });
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
                ShellItem::For {
                    var,
                    values,
                    arithmetic,
                    items,
                } => {
                    if let Some(values) = values {
                        self.assign_list_defaults(builder, env, values, force_conditional);
                    }
                    if let Some((name, span)) = var {
                        let original_values = values;
                        let mut list_producers = values
                            .as_deref()
                            .map(|values| for_list_producers(builder, env, values))
                            .unwrap_or_default();
                        // The list is expanded whatever the body does with
                        // the variable, and `select` prints it as a menu.
                        note_expanded_assignments(builder, &list_producers);
                        // A command substitution in the list runs once, ahead
                        // of the first iteration, and each iteration binds a
                        // field of its output: the value is not known here,
                        // but what printed it is.
                        let substitutes = values.as_deref().is_some_and(|values| {
                            values.iter().any(|value| {
                                value
                                    .segs
                                    .iter()
                                    .any(|seg| matches!(seg, Seg::CommandSub { .. }))
                            })
                        });
                        if let Some(values) = values.as_deref().filter(|_| substitutes) {
                            let expansion = self.expand_words(builder, env, values, true, false);
                            list_producers.extend(
                                expansion
                                    .variants
                                    .into_iter()
                                    .flatten()
                                    .flat_map(|value| value.producers),
                            );
                            list_producers.sort();
                            list_producers.dedup();
                        }
                        let values = values.as_ref().map(|values| {
                            values
                                .iter()
                                .flat_map(|value| self.brace_words(builder, value))
                                .collect::<Vec<_>>()
                        });
                        let expanded_values = values.as_deref().and_then(|values| {
                            let has_unquoted_env = values.iter().any(|value| {
                                matches!(value.segs.as_slice(), [Seg::Env { quoted: false, .. }])
                            });
                            let unknown = values.iter().any(|value| {
                                matches!(value.segs.as_slice(), [Seg::Special | Seg::ShellPid])
                            });
                            (has_unquoted_env && !unknown && !substitutes).then(|| {
                                self.expand_words(
                                    builder,
                                    env,
                                    original_values.as_deref().unwrap(),
                                    true,
                                    false,
                                )
                            })
                        });
                        if let Some(expansion) = expanded_values {
                            for values in expansion.variants {
                                // A list of fixed words runs the body once
                                // for each: the members are its iterations.
                                // A member that is a pattern or an unknown
                                // value stands for any number of them.
                                let counted =
                                    values.iter().all(|value| value.word.as_literal().is_some());
                                for (iteration, value) in values.into_iter().enumerate() {
                                    bind_for_var(
                                        builder,
                                        env,
                                        name.clone(),
                                        Some(value.word),
                                        *span,
                                        value.producers,
                                    );
                                    let instance =
                                        self.enter_loop_iteration(builder, items, iteration as u32);
                                    if counted {
                                        self.walk_may_region(builder, env, items, walk_depth + 1);
                                    } else {
                                        self.walk_loop(builder, env, items, |builder, env, _| {
                                            self.walk_may_region(
                                                builder,
                                                env,
                                                items,
                                                walk_depth + 1,
                                            );
                                            None
                                        });
                                    }
                                    if let Some(previous) = instance {
                                        builder.leave_condition_call(previous);
                                    }
                                }
                            }
                            if let Some(depth) = hazard_depth {
                                builder.truncate_source_hazards(depth);
                            }
                            continue;
                        }
                        // An unconditional break on the first iteration prevents every
                        // later value from reaching the body or the following command.
                        if let Some(values) = values.as_deref()
                            && !values.is_empty()
                            && values.iter().all(|value| literal_word_text(value).is_some())
                            && !values.iter().any(|value| matches!(value.segs.first(),
                                Some(Seg::Literal { text, quoted: false }) if text.starts_with('~')))
                            && !env.may_redefine("break")
                            && let Some(stop) = items.iter().position(|item| matches!(item,
                                ShellItem::Pipeline { cmds, conditional: false, .. }
                                if cmds.len() == 1 && cmds[0].redirs.is_empty() && cmds[0].assignments.is_empty()
                                    && cmds[0].words.iter().map(parse::literal_text).collect::<Option<Vec<_>>>()
                                        .is_some_and(|words| words == ["break"] || words == ["break", "1"])))
                            && body_runs_every_iteration(&items[..stop])
                        {
                            bind_for_var(builder, env, name.clone(), Some(Word::literal(literal_word_text(&values[0]).unwrap())), *span, Vec::new());
                            let termination = self.walk(builder, env, &items[..stop], force_conditional, walk_depth + 1);
                            if let Some(depth) = hazard_depth { builder.truncate_source_hazards(depth); }
                            if termination.is_some() { return termination; }
                            env.status = Some(true);
                            continue;
                        }
                        if let Some(termination) = self.walk_for_members(
                            builder,
                            env,
                            item,
                            force_conditional,
                            walk_depth,
                            hazard_depth,
                        ) {
                            if termination.is_some() {
                                return termination;
                            }
                            continue;
                        }
                        let (value, fixed) = values
                            .as_deref()
                            .map(|values| self.finite_for_value(builder, env, values))
                            .unwrap_or((None, None));
                        // A fixed literal list with a body that always runs
                        // to its end executes every iteration. Walk each
                        // binding separately so an operand read is an exact
                        // occurrence rather than one conservative union.
                        if let Some(fixed) = fixed
                            && body_runs_every_iteration(items)
                            && !body_has_remote_command(items)
                        {
                            for (iteration, value) in fixed.into_iter().enumerate() {
                                bind_for_var(
                                    builder,
                                    env,
                                    name.clone(),
                                    Some(value),
                                    *span,
                                    Vec::new(),
                                );
                                let instance =
                                    self.enter_loop_iteration(builder, items, iteration as u32);
                                let termination = self.walk(
                                    builder,
                                    env,
                                    items,
                                    force_conditional,
                                    walk_depth + 1,
                                );
                                if let Some(previous) = instance {
                                    builder.leave_condition_call(previous);
                                }
                                if let Some(depth) = hazard_depth {
                                    builder.truncate_source_hazards(depth);
                                }
                                if termination.is_some() {
                                    return termination;
                                }
                            }
                            continue;
                        }
                        bind_for_var(builder, env, name.clone(), value, *span, list_producers);
                    }
                    // A `for (( ))` whose condition holds for its initial
                    // values certainly runs a body that always reaches its end.
                    if arithmetic.is_some_and(|header| {
                        body_runs_every_iteration(items)
                            && self
                                .source
                                .get(header.start as usize..header.end as usize)
                                .is_some_and(eval::arithmetic::arithmetic_for_enters)
                    }) {
                        if let Some(termination) =
                            self.walk_loop(builder, env, items, |builder, env, again| {
                                if again {
                                    self.walk_may_region(builder, env, items, walk_depth + 1);
                                    return None;
                                }
                                self.walk(builder, env, items, force_conditional, walk_depth + 1)
                            })
                        {
                            if let Some(depth) = hazard_depth {
                                builder.truncate_source_hazards(depth);
                            }
                            return Some(termination);
                        }
                    } else {
                        self.walk_loop(builder, env, items, |builder, env, _| {
                            self.walk_may_region(builder, env, items, walk_depth + 1);
                            None
                        });
                    }
                    env.status = None;
                }
            }
            match hazard_depth {
                Some(depth) if background => builder.truncate_git_config_hazards(depth),
                Some(depth) => builder.truncate_source_hazards(depth),
                None => {}
            }
        }
        None
    }

    /// The `git config` writes each item after `job` makes, walked in the
    /// probe `env`, with the index of the item that makes it.
    fn later_git_config_writes(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        items: &[ShellItem],
        job: usize,
        force_conditional: bool,
        walk_depth: u32,
    ) -> Vec<(usize, crate::builder::GitConfigWrite)> {
        let mut writes = Vec::new();
        for (at, item) in items.iter().enumerate().skip(job + 1) {
            let start = builder.git_config_write_count();
            self.walk(
                builder,
                env,
                std::slice::from_ref(item),
                force_conditional,
                walk_depth,
            );
            writes.extend(
                builder
                    .git_config_writes_from(start)
                    .into_iter()
                    .map(|write| (at, write)),
            );
        }
        writes
    }

    /// A `for` list expands once in the current shell, so the `:=` defaults
    /// it assigns persist after the loop. Kept out of line: `walk_items`
    /// recurses once per nested group, so its frame bounds nesting depth.
    #[inline(never)]
    fn assign_list_defaults(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        values: &[WordTok],
        conditional: bool,
    ) {
        let assigning = values
            .iter()
            .filter(|value| eval::assigns_default(value))
            .cloned()
            .collect::<Vec<_>>();
        if assigning.is_empty() {
            return;
        }
        let expansion = self.expand_words(builder, env, &assigning, true, false);
        for mut converted in expansion.variants.into_iter().flatten() {
            self.apply_pending_assigns(builder, env, &mut converted, conditional, false);
        }
    }
}

/// Whether the item at `at` waits for the background job before it: a bare
/// `wait`, or `wait $!` when that job is the only one the list started
/// earlier, since `$!` names only the latest. A `wait` inside a group or
/// branch, or for a saved pid, is not recognized, so the race continues.
fn waits_for_background(source: &str, env: &ShellEnv, items: &[ShellItem], at: usize) -> bool {
    let ShellItem::Pipeline { cmds, .. } = &items[at] else {
        return false;
    };
    let [cmd] = cmds.as_slice() else {
        return false;
    };
    let Some((name, operands)) = cmd.words.split_first() else {
        return false;
    };
    if parse::literal_text(name).as_deref() != Some("wait")
        || env.functions.contains_key("wait")
        || env.aliases.contains_key("wait")
    {
        return false;
    }
    match operands {
        [] => true,
        [operand] => {
            matches!(
                source.get(operand.span.start as usize..operand.span.end as usize),
                Some("$!" | "\"$!\"")
            ) && items[..at]
                .iter()
                .filter(|item| {
                    matches!(
                        item,
                        ShellItem::Group {
                            kind: GroupKind::Background,
                            ..
                        }
                    )
                })
                .count()
                == 1
        }
        _ => false,
    }
}
