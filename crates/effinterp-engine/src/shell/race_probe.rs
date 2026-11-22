//! Race probe: a region whose commands may run out of order with each
//! other or with the commands after it (a pipeline, a background job, a
//! `for`, `while` or `until` loop, a compound command feeding its consumer)
//! is first walked as a probe, in measuring mode, for the writes that race
//! its reads; then it is walked for real against them
//! (`probe_racing_writes`). What the probe finds reaches the real walk in
//! three forms: source hazards on the plan builder
//! (`PlanBuilder::push_source_hazards`, lifted by
//! `truncate_source_hazards`), the filesystem a `for` list or `while read`
//! input expands against (`RegionEntryFilesystem`), and lanes, which let a
//! pipeline stage or a job meet its peers' probed changes but its own only
//! in the order it makes them (`Budget::begin_lane_probe`,
//! `enter_pipeline_lanes`, `enter_job` in `nest.rs`). A job also races the
//! writes of the commands after it up to its `wait` (`LaterWrites`).

use effinterp_proto::{ResourceExpr, ResourceIdentity};
use std::rc::Rc;

use crate::builder::PlanBuilder;
use crate::nest::{RegionEntryFilesystem, TopologyChange};
use crate::value::unresolved_resource;

use super::parse::{GroupKind, ShellItem};
use super::shell_env::ShellEnv;
use super::{MAX_WALK_DEPTH, Shell, parse};

/// The writes of the items after a background job, each with its item's
/// index: what races the job up to the `wait` that ends it. Probed once per
/// list (`later_writes`) and handed to the lists inside a region that
/// starts a job (`ShellEnv::background_followup`).
#[derive(Default)]
pub(crate) struct LaterWrites {
    sources: Vec<(usize, crate::builder::SourceMutation)>,
    git_config: Vec<(usize, crate::builder::GitConfigWrite)>,
}

impl Shell<'_> {
    /// Probe the item at `index` of `items`, when it is a region whose
    /// commands may run out of order with each other or with the commands
    /// after it, for the writes that race its reads, and settle what the
    /// real walk of it meets: the hazard depth to lift after it, a job's
    /// own writes, the filesystem a loop's list expands against, and the
    /// lanes a pipeline's stages are walked in (held until the item's walk
    /// ends). Kept off the recursive statement walk's stack frame: a deeply
    /// nested group must reach the walk bound without exhausting the stack.
    #[inline(never)]
    #[allow(clippy::too_many_arguments, clippy::type_complexity)]
    pub(super) fn probe_racing_writes(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        items: &[ShellItem],
        index: usize,
        force_conditional: bool,
        walk_depth: u32,
        later_writes: &mut Option<LaterWrites>,
        enclosing_writes: &LaterWrites,
    ) -> (
        Option<crate::builder::HazardDepth>,
        Option<Vec<crate::builder::SourceMutation>>,
        Option<Box<RegionEntryFilesystem>>,
        Option<crate::nest::PipelineLanes<'_>>,
    ) {
        let item = &items[index];
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
        let nested_background = !background
            && self.nest.resolver.is_some()
            && !self.nest.budget.measuring()
            && (index + 1 < items.len()
                || !enclosing_writes.sources.is_empty()
                || !enclosing_writes.git_config.is_empty())
            && starts_background(item, env, &mut Default::default(), 0);
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
        let mut background_mutations = None;
        let mut pipeline_lanes = None;
        let hazard_depth = if unordered && self.nest.resolver.is_none() {
            // With no observed source there is nothing to discover by probing.
            // Still refuse transient source predictions in unordered regions.
            Some((
                builder.push_source_hazards(
                    vec![(unresolved_resource("filesystem"), true, Vec::new())],
                    Vec::new(),
                    None,
                    background,
                ),
                None,
            ))
        } else if (unordered || nested_background) && !self.nest.budget.measuring() {
            // A pipeline numbers its stages at this depth, so a write it
            // carries stays out of its own stage's earlier reads.
            let stage_depth = (matches!(item, ShellItem::Pipeline { cmds, .. } if cmds.len() > 1)
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
            // A `for` list expands once, before the body runs, against the
            // state the probe's writes leave noted only for the body. The
            // lines of a `while read` loop, and the one pass of a loop that
            // leaves on its first (`Shell::walk_loop`), are walked from that
            // state too.
            let entry_filesystem = matches!(
                item,
                ShellItem::For { .. }
                    | ShellItem::Group {
                        kind: GroupKind::Conditional { .. },
                        ..
                    }
            )
            .then(|| Box::new(self.nest.budget.region_entry_filesystem()));
            // A job's or a pipeline stage's own commands run in order, so
            // what the probe notes is sorted by who may race whom: a stage's
            // changes race its peers, a job's the commands after it.
            let lane_entry = (unordered && (background || stage_depth.is_some()))
                .then(|| self.nest.budget.region_entry_filesystem());
            if lane_entry.is_some() && !background {
                self.nest.budget.begin_lane_probe(stage_depth);
            }
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
            if self.nest.budget.timed_out() {
                // Keep this reached item's measuring-mode effects, including
                // its source refusal: no real walk follows after expiry.
                self.nest.budget.end_lane_probe();
                self.nest.budget.set_measuring(false);
                self.nest.budget.restore(snap, false);
                return (None, None, None, None);
            }
            if lane_entry.is_some() && background {
                self.nest.budget.begin_lane_probe(None);
            }
            let mut mutations = builder.source_mutations_since(&cp);
            let region_git_config = builder.git_config_writes_from(git_config_start);
            if self.nest.budget.exhausted() || builder.effects_saturated() {
                mutations.push((unresolved_resource("filesystem"), true, Vec::new()));
            }
            // A job races later commands up to its wait, including writes
            // after the construct that starts it.
            let git_config_writes = if background || nested_background {
                let end = (index + 1..items.len())
                    .find(|&at| waits_for_background(self.source, env, items, at))
                    .unwrap_or(items.len());
                let later = later_writes.get_or_insert_with(|| {
                    self.later_writes(
                        builder,
                        &mut probe,
                        items,
                        index,
                        force_conditional,
                        walk_depth,
                    )
                });
                let mut following = LaterWrites {
                    sources: later
                        .sources
                        .iter()
                        .filter(|(at, _)| *at > index && *at < end)
                        .cloned()
                        .collect(),
                    git_config: later
                        .git_config
                        .iter()
                        .filter(|(at, _)| *at > index && *at < end)
                        .cloned()
                        .collect(),
                };
                if end == items.len() {
                    following
                        .sources
                        .extend(enclosing_writes.sources.iter().cloned());
                    following
                        .git_config
                        .extend(enclosing_writes.git_config.iter().cloned());
                }
                if background {
                    // An enclosing ordered probe was rolled back, but its
                    // later writes still race this job's path observations.
                    if end == items.len() {
                        for (_, (resource, changes_identity, _)) in &enclosing_writes.sources {
                            let path = match resource {
                                ResourceExpr::Concrete {
                                    identity: ResourceIdentity::FsPath { path },
                                } => Some(path.as_str()),
                                _ => None,
                            };
                            if *changes_identity {
                                self.nest
                                    .budget
                                    .note_topology_mutation(path, TopologyChange::Other);
                            } else {
                                self.nest.budget.note_write(path);
                            }
                        }
                    }
                    background_mutations = Some(std::mem::take(&mut mutations));
                    mutations.extend(following.sources.into_iter().map(|(_, write)| write));
                    following
                        .git_config
                        .into_iter()
                        .map(|(_, write)| write)
                        .collect()
                } else {
                    env.background_followup = Rc::new(following);
                    region_git_config
                }
            } else {
                region_git_config
            };
            let lane_changes = self.nest.budget.end_lane_probe();
            self.nest.budget.set_measuring(false);
            self.nest.budget.restore(snap, !unordered);
            builder.rollback(cp);
            if let (Some(entry), Some(changes)) = (lane_entry, lane_changes) {
                if background {
                    self.nest.budget.enter_job(entry, changes);
                } else {
                    pipeline_lanes = self.nest.budget.enter_pipeline_lanes(entry, changes);
                }
            }
            unordered
                .then(|| {
                    builder.push_source_hazards(
                        mutations,
                        git_config_writes,
                        stage_depth,
                        background,
                    )
                })
                .map(|depth| (depth, entry_filesystem))
        } else {
            None
        };
        let (hazard_depth, entry_filesystem) = hazard_depth.unzip();
        (
            hazard_depth,
            background_mutations,
            entry_filesystem.flatten(),
            pipeline_lanes,
        )
    }

    /// Writes each item after `job` makes, with the index of that item.
    fn later_writes(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        items: &[ShellItem],
        job: usize,
        force_conditional: bool,
        walk_depth: u32,
    ) -> LaterWrites {
        let mut writes = LaterWrites::default();
        for (at, item) in items.iter().enumerate().skip(job + 1) {
            let checkpoint = builder.checkpoint();
            let start = builder.git_config_write_count();
            self.walk(
                builder,
                env,
                std::slice::from_ref(item),
                force_conditional,
                walk_depth,
            );
            writes.sources.extend(
                builder
                    .source_mutations_since(&checkpoint)
                    .into_iter()
                    .map(|write| (at, write)),
            );
            writes.git_config.extend(
                builder
                    .git_config_writes_from(start)
                    .into_iter()
                    .map(|write| (at, write)),
            );
        }
        writes
    }
}

/// Whether this region can start a job whose reads need the enclosing list's
/// later writes. Calls are inspected only to decide whether to probe; the
/// ordinary walk still decides which jobs actually run.
fn starts_background(
    item: &ShellItem,
    env: &ShellEnv,
    seen: &mut std::collections::HashSet<u64>,
    depth: u32,
) -> bool {
    if depth >= MAX_WALK_DEPTH {
        return true;
    }
    match item {
        ShellItem::Group {
            kind: GroupKind::Background,
            ..
        } => true,
        ShellItem::Group { items, .. } | ShellItem::For { items, .. } => items
            .iter()
            .any(|item| starts_background(item, env, seen, depth + 1)),
        ShellItem::Alternatives { arms, .. } => arms
            .iter()
            .flatten()
            .any(|item| starts_background(item, env, seen, depth + 1)),
        ShellItem::Pipeline { cmds, .. } => cmds.iter().any(|cmd| {
            let name = cmd.words.first().and_then(parse::literal_text);
            match name {
                Some(name) => {
                    // The source these heads read can start jobs beyond the
                    // pre-scan's parsed list; the ordinary walk finds them.
                    matches!(name.as_str(), "eval" | "." | "source" | "sh" | "bash")
                        || env.functions.get(&name).is_some_and(|entry| {
                            seen.insert(entry.id)
                                && entry
                                    .body
                                    .iter()
                                    .any(|item| starts_background(item, env, seen, depth + 1))
                        })
                        || env
                            .aliases
                            .get(&name)
                            .is_some_and(|definition| definition.text.contains('&'))
                }
                None => env.functions.values().any(|entry| {
                    seen.insert(entry.id)
                        && entry
                            .body
                            .iter()
                            .any(|item| starts_background(item, env, seen, depth + 1))
                }),
            }
        }),
        _ => false,
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
