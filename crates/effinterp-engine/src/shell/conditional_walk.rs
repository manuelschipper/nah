//! Conditional walk: regions that run on some paths only. `if`/`case` arms
//! (alternatives) and `&&`/`||` operands (short circuit) are each walked under
//! the condition selecting them, share the analysis budget between arms, and
//! leave their assignments and name tables joined for what follows.

use crate::builder::PlanBuilder;

use super::lex::ShellSpan;
use super::name_tables::merge_name_tables;
use super::parse::ShellItem;
use super::shell_env::{ShellEnv, downgrade_script_set, script_set_names};
use super::{Shell, literal_word_text, parse};

impl Shell<'_> {
    /// Walk the arms of an `if`/`case` whose selection is unknown. Kept out
    /// of line: `walk_items` recurses once per nested group, so its frame
    /// size bounds nesting.
    #[inline(never)]
    pub(super) fn walk_alternatives(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        group: u32,
        end: u32,
        arms: &[Vec<ShellItem>],
        walk_depth: u32,
    ) {
        let budget = self.nest.budget;
        let condition_group = group;
        // Each arm starts from the tables before the construct.
        let initial = env.name_tables();
        let mut paths = Vec::with_capacity(arms.len());
        if self.structural_saturated(builder, env) {
            // Once nested model work is unavailable, measure-free
            // arm walks retain source-local command heads in time
            // linear in the bounded source size.
            for (arm_index, arm) in arms.iter().enumerate() {
                env.restore_name_tables(initial.clone());
                self.walk_may_region(builder, env, arm, walk_depth + 1);
                paths.push((
                    env.name_tables(),
                    Some(self.arm_condition(builder, condition_group, end, arm_index, arms.len())),
                ));
            }
            merge_name_tables(env, paths);
            env.status = None;
            return;
        }
        if budget.measuring() {
            // Already inside another alternatives demand measurement:
            // the whole subtree counts toward that arm's demand,
            // so walk sequentially rather than measuring again
            // (keeps nested alternatives linear-time).
            for (arm_index, arm) in arms.iter().enumerate() {
                env.restore_name_tables(initial.clone());
                self.walk_branch_region(
                    builder,
                    env,
                    condition_group,
                    end,
                    arm_index,
                    arms.len(),
                    arm,
                    walk_depth + 1,
                );
                paths.push((
                    env.name_tables(),
                    Some(self.arm_condition(builder, condition_group, end, arm_index, arms.len())),
                ));
            }
            merge_name_tables(env, paths);
            env.status = None;
            return;
        }
        // Every arm is a may-path and must not be starved by an
        // earlier sibling. Dry-run each arm against a clone of
        // the entry env to measure its invocation demand (rolling
        // back all plan and budget state), then water-fill the
        // remaining budget over the demands. The allocation
        // depends only on the demand multiset, so reordering
        // arms cannot change the outcome, and a frugal arm's
        // surplus flows to demanding siblings.
        let mut demands = Vec::with_capacity(arms.len());
        for arm in arms {
            let cp = builder.checkpoint();
            let snap = budget.snapshot();
            budget.set_measuring(true);
            let mut probe = env.clone();
            probe.detach_probe_state();
            self.walk(builder, &mut probe, arm, true, walk_depth + 1);
            budget.set_measuring(false);
            demands.push(budget.consumed_since(&snap));
            budget.restore(snap);
            builder.rollback(cp);
        }
        let allocations = water_fill(&demands, budget.remaining());
        for (arm_index, (arm, alloc)) in arms.iter().zip(allocations).enumerate() {
            env.restore_name_tables(initial.clone());
            let window = budget.push_window(alloc);
            self.walk_branch_region(
                builder,
                env,
                condition_group,
                end,
                arm_index,
                arms.len(),
                arm,
                walk_depth + 1,
            );
            budget.pop_window(window);
            paths.push((
                env.name_tables(),
                Some(self.arm_condition(builder, condition_group, end, arm_index, arms.len())),
            ));
        }
        merge_name_tables(env, paths);
        env.status = None;
    }

    /// Walk `items` as a region that runs only on some paths. Inside it, a
    /// name the region assigns suppresses environment reads (the assignment
    /// precedes the read on every path through the region); afterwards the
    /// region may have been skipped, so the environment's value may still
    /// show through and the suppression is dropped.
    pub(super) fn walk_may_region(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        items: &[ShellItem],
        walk_depth: u32,
    ) {
        let before = script_set_names(env);
        let condition = parse::items_span(items).map(|span| {
            self.source_condition(
                builder,
                effinterp_proto::ByteSpan {
                    start: span.start,
                    end: span.end,
                },
                effinterp_proto::ConditionKind::Loop,
                0,
                2,
                false,
                false,
            )
        });
        // The parser appends the unbounded-spawn statement to the loop it
        // describes. It is a fact *about* the loop -- the shape already
        // established the loop never ends -- not an effect the loop's own
        // repetition conditions, so it is walked outside that condition.
        let (region, spawn) = match items {
            [region @ .., item @ ShellItem::UnboundedSpawn { .. }] => {
                (region, std::slice::from_ref(item))
            }
            _ => (items, &[][..]),
        };
        if let Some(condition) = condition {
            builder.push_condition(condition);
        }
        self.walk(builder, env, region, true, walk_depth);
        if parse::items_span(items).is_some() {
            builder.pop_condition();
        }
        self.walk(builder, env, spawn, true, walk_depth);
        downgrade_script_set(env, &before);
    }

    /// Walk one alternative. The condition names the construct's nesting
    /// depth, the arm, and how many arms the construct has, so a consumer can
    /// recover the branch nesting and tell that the arms together cover every
    /// path through the construct.
    #[allow(clippy::too_many_arguments)]
    fn walk_branch_region(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        group: u32,
        end: u32,
        arm: usize,
        arms: usize,
        items: &[ShellItem],
        walk_depth: u32,
    ) {
        builder.push_condition(self.arm_condition(builder, group, end, arm, arms));
        let before = script_set_names(env);
        let exported_before = env.exported.clone();
        // A branch can change directories before returning.
        // Its cwd cannot replace the captured directory on the surviving path.
        let restores_captured_cwd = env.captured_cwd
            && matches!(items.last(),
            Some(ShellItem::Pipeline { cmds, conditional: false, .. })
            if cmds.len() == 1 && cmds[0].words.first().and_then(literal_word_text)
                .is_some_and(|name| matches!(name.as_str(), "return" | "exit") && !env.functions.contains_key(&name)));
        let saved_cwd = restores_captured_cwd.then(|| {
            (
                env.cwd.clone(),
                env.cwd_resource.clone(),
                env.cwd_node,
                env.source_cwd.clone(),
                env.runtime_cwd.clone(),
                env.cwd_known,
            )
        });
        self.walk(builder, env, items, true, walk_depth);
        if let Some((cwd, resource, node, source, runtime, known)) = saved_cwd {
            env.cwd = cwd;
            env.cwd_resource = resource;
            env.cwd_node = node;
            env.source_cwd = source;
            env.runtime_cwd = runtime;
            env.cwd_known = known;
            env.captured_cwd = true;
        }
        for name in exported_before.symmetric_difference(&env.exported) {
            if let Some(entry) = env.vars.get_mut(name) {
                entry.branches.clear();
            }
        }
        downgrade_script_set(env, &before);
        builder.pop_condition();
    }

    /// The condition selecting one arm of an `if`/`case`.
    fn arm_condition(
        &self,
        builder: &PlanBuilder,
        group: u32,
        end: u32,
        arm: usize,
        arms: usize,
    ) -> effinterp_proto::Condition {
        let boolean = !self
            .source
            .get(group as usize..)
            .is_some_and(|s| s.starts_with("case"));
        self.source_condition(
            builder,
            effinterp_proto::ByteSpan { start: group, end },
            effinterp_proto::ConditionKind::Branch,
            arm as u32,
            arms as u32,
            true,
            boolean,
        )
    }

    /// Walk a `&&`/`||` operand whose selection is unknown: it runs on some
    /// paths only, so the name tables join the path that skips it.
    #[inline(never)]
    pub(super) fn walk_short_circuit(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        items: &[ShellItem],
        selection: Option<(ShellSpan, bool)>,
        walk_depth: u32,
    ) {
        let [condition, skipped] = [true, false].map(|runs| {
            selection
                .map(|(span, positive)| {
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
                })
                .unwrap_or(effinterp_proto::Condition::Widened)
        });
        let initial = env.name_tables();
        builder.push_condition(condition.clone());
        let before = script_set_names(env);
        self.walk(builder, env, items, true, walk_depth);
        downgrade_script_set(env, &before);
        builder.pop_condition();
        let ran = env.name_tables();
        merge_name_tables(env, vec![(initial, Some(skipped)), (ran, Some(condition))]);
        env.status = None;
    }
}

/// Water-fill `budget` over per-arm invocation demands: every arm is capped
/// at a common fill level, chosen as the largest level whose total cost fits
/// the budget. Fully order-symmetric — the result depends only on each arm's
/// own demand and the demand multiset — so reordering arms cannot change
/// which of them complete. When measured demands fit outright, remaining
/// capacity is distributed in proportion to demand so nested branches can
/// consume work that the speculative walk underestimated. Otherwise an
/// integer remainder smaller than the number of unsatisfied arms stays
/// unallocated (splitting it would break symmetry).
fn water_fill(demands: &[u64], budget: u64) -> Vec<u64> {
    let total: u64 = demands.iter().sum();
    if total == 0 {
        return demands.to_vec();
    }
    if total <= budget {
        let slack = budget - total;
        return demands
            .iter()
            .map(|d| d + slack.saturating_mul(*d) / total)
            .collect();
    }
    let mut sorted = demands.to_vec();
    sorted.sort_unstable();
    // Cost of level L is sum(min(d, L)). Walk demands ascending: arms below
    // the level are satisfied in full, the rest each pay the level.
    let mut satisfied = 0u64;
    let mut level = 0u64;
    for (i, d) in sorted.iter().enumerate() {
        let above = (sorted.len() - i) as u64;
        if satisfied + d.saturating_mul(above) <= budget {
            satisfied += d;
            level = *d;
        } else {
            level = (budget - satisfied) / above;
            break;
        }
    }
    demands.iter().map(|d| (*d).min(level)).collect()
}
