//! Pipeline walk: one `a | b | c` pipeline as flow stages. Each stage is a
//! simple command or a compound command reading the previous stage's output;
//! the walk joins their stdin and stdout, hands `find`'s printed paths to the
//! `xargs` after it, and marks the environment values the last stage prints.

use effinterp_proto::{ResourceExpr, ResourceIdentity};

use crate::builder::PlanBuilder;
use crate::flow::Descriptor;
use crate::models::StdinValue;
use crate::word::Word;

use super::disclosed_environment_reads::mark_disclosed_environment_reads;
use super::parse::{GroupKind, ShellItem};
use super::shell_env::ShellEnv;
use super::{Shell, Termination, eval, jobs, literal_word_text, parse};

/// `source` and `.` run what they read on standard input as code: bind the
/// stage's stdin to every `process.code_execution` effect it states.
fn add_source_causal_binding(
    name: Option<&str>,
    bindings: &mut Vec<crate::models::ModelCausalBinding>,
) {
    if matches!(name, Some("source" | ".")) {
        bindings.push(crate::models::ModelCausalBinding {
            assurance: effinterp_proto::CausalAssurance::Exact,
            from: crate::models::ModelBindingEnd::Port(effinterp_proto::Port::Stdin),
            to: crate::models::ModelBindingEnd::Effect {
                operation: "process.code_execution".into(),
                selection: effinterp_model_schema::EffectSelection::All,
            },
        });
    }
}

impl Shell<'_> {
    /// Walk compound pipeline stages. A command pipeline piped into a
    /// compound command runs like a process substitution: its output is the
    /// channel the compound command's body reads on stdin.
    pub(super) fn walk_compound_pipeline(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        stages: &[ShellItem],
        force_conditional: bool,
        walk_depth: u32,
    ) {
        let inner = |stage: &ShellItem| match stage {
            ShellItem::Group {
                kind: GroupKind::Subshell,
                items,
            } => items.first().filter(|_| items.len() == 1).cloned(),
            _ => None,
        };
        let mut feed = None;
        let mut outer_stdin = env.stdin.take();
        for (index, stage) in stages.iter().enumerate() {
            let feeds_compound = matches!(inner(stage), Some(ShellItem::Pipeline { .. }))
                && matches!(
                    stages.get(index + 1).and_then(inner),
                    Some(
                        ShellItem::Group { .. }
                            | ShellItem::For { .. }
                            | ShellItem::Alternatives { .. }
                    )
                );
            if feeds_compound
                && let Some(span) = parse::items_span(std::slice::from_ref(stage))
                && let source = &self.source[span.start as usize..span.end as usize]
                && let Some(channel) = self.defer_process(builder, env, source, span)
            {
                // The producer is analyzed after its consumer, so text it is
                // known to write is handed over as the consumer's stdin now.
                let written = self
                    .literal_process_output(env, source)
                    .map(|word| StdinValue {
                        paths: None,
                        piped: true,
                        file: None,
                        word,
                        provenance: vec![self.span_node(builder, span)],
                    });
                feed = Some((channel, written));
                continue;
            }
            let fed = feed.take();
            // Only the first stage reads the stdin the pipeline started with.
            env.stdin = match &fed {
                Some((_, written)) => written.clone(),
                None if index == 0 => outer_stdin.take(),
                None => None,
            };
            if let Some((channel, _)) = &fed {
                let channel = *channel;
                env.redirections.push(crate::flow::Redirection {
                    role: crate::flow::RedirRole::Channel {
                        stage: channel,
                        read: true,
                        write: false,
                    },
                    fd: Descriptor::Number(0),
                    dup: None,
                    both: false,
                    read_effect: None,
                    write_effect: None,
                });
            }
            builder.push_pipeline_stage(index);
            self.walk(
                builder,
                env,
                std::slice::from_ref(stage),
                force_conditional,
                walk_depth,
            );
            builder.pop_pipeline_stage();
            env.stdin = None;
            if fed.is_some() {
                env.redirections.pop();
            }
        }
    }

    /// A pipeline item, followed in its list by `next_item`: each command's
    /// effects, then the flows between its stages. Kept out of line:
    /// `walk_items` recurses once per nested group, so its frame size bounds
    /// nesting.
    #[inline(never)]
    pub(super) fn walk_pipeline(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        item: &ShellItem,
        next_item: Option<&ShellItem>,
        selected: Option<bool>,
        force_conditional: bool,
    ) -> Option<(Termination, u32)> {
        let ShellItem::Pipeline {
            cmds,
            conditional,
            short_circuit,
        } = item
        else {
            return None;
        };
        let (conditional, short_circuit) = (*conditional, *short_circuit);
        let guarded = conditional && selected != Some(true);
        let cond = guarded || force_conditional;
        if guarded {
            let condition = short_circuit
                .map(|(span, polarity)| {
                    self.source_condition(
                        builder,
                        effinterp_proto::ByteSpan {
                            start: span.start,
                            end: span.end,
                        },
                        effinterp_proto::ConditionKind::ShortCircuit,
                        u32::from(!polarity),
                        2,
                        true,
                        true,
                    )
                })
                .unwrap_or(effinterp_proto::Condition::Widened);
            builder.push_condition(condition);
        }
        let pipeline = cmds.len() > 1;
        let short_circuit_operand = conditional
            || matches!(
                next_item,
                Some(ShellItem::Pipeline {
                    conditional: true,
                    ..
                }) | Some(ShellItem::Group {
                    kind: GroupKind::ShortCircuit(_),
                    ..
                })
            );
        let mut specs = Vec::with_capacity(cmds.len());
        let mut termination = None;
        let mut piped_stdin = env.stdin.take();
        // The operand values `echo` and `printf` wrote into the pipe so far.
        let mut piped_values = Vec::new();
        for (position, cmd) in cmds.iter().enumerate() {
            let inherited_count = env.redirections.len();
            let mut inherited_redirs = env.redirections.clone();
            let eff_start = builder.effects_len() as u32;
            // Every stage but the last runs in a subshell; with
            // `lastpipe` the final one runs in the current shell.
            let persist = !pipeline || env.lastpipe && position + 1 == cmds.len();
            // A `find` of literal words piped straight into `xargs`, which
            // `sudo` may run; the find model decides which expressions print
            // paths it can name, and what the command xargs runs is passed.
            let previous_paths = builder.stdout_paths_consumer.take();
            if cmd.words.first().and_then(parse::literal_text).as_deref() == Some("find")
                && cmd
                    .words
                    .iter()
                    .all(|word| parse::literal_text(word).is_some())
                && cmd.redirs.is_empty()
                && env.redirections.is_empty()
                && !env.functions.contains_key("find")
                && !env.aliases.contains_key("find")
                && !env.functions.contains_key("xargs")
                && !env.aliases.contains_key("xargs")
                && !env.functions.contains_key("sudo")
                && !env.aliases.contains_key("sudo")
            {
                builder.stdout_paths_consumer = cmds.get(position + 1).and_then(|next| {
                    let words = next
                        .words
                        .iter()
                        .map(parse::literal_text)
                        .collect::<Option<Vec<_>>>()?;
                    // A bare `sudo` hands its stdin to the command it runs.
                    let xargs = match words.as_slice() {
                        [sudo, xargs @ ..] if sudo == "sudo" => xargs,
                        words => words,
                    };
                    if !next.redirs.is_empty() || xargs.first().map(String::as_str) != Some("xargs")
                    {
                        return None;
                    }
                    crate::models::xargs_printed_path_consumer(
                        &xargs.iter().cloned().map(Word::literal).collect::<Vec<_>>(),
                    )
                });
            }
            // A stage in its own subshell keeps the parent's `$$`.
            let pid_is_own = env.pid_is_own;
            env.pid_is_own &= persist;
            if pipeline {
                builder.push_pipeline_stage(position);
            }
            let outcome = self.eval_simple_command(
                builder,
                env,
                cmd,
                persist,
                cond,
                guarded,
                piped_stdin.take(),
                position + 1 != cmds.len() || env.stdout_consumed,
            );
            if pipeline {
                builder.pop_pipeline_stage();
            }
            env.pid_is_own = pid_is_own;
            builder.stdout_paths_consumer = previous_paths;
            inherited_redirs.extend(
                env.redirections[inherited_count..]
                    .iter()
                    .filter(|redir| matches!(redir.role, crate::flow::RedirRole::Channel { .. }))
                    .cloned(),
            );
            env.status = if !guarded
                && !pipeline
                && cmd.redirs.is_empty()
                && !self.source[cmd.span.start as usize..]
                    .trim_start()
                    .starts_with('!')
                && !outcome
                    .name
                    .as_ref()
                    .is_some_and(|name| env.may_redefine(name))
            {
                match outcome.name.as_deref() {
                    Some("true" | ":") if cmd.assignments.is_empty() => Some(true),
                    Some("false" | "") if cmd.assignments.is_empty() => Some(false),
                    // `[` reaches here without a command name.
                    Some("test" | "[[") | None
                        if cmd.words.first().and_then(parse::literal_text).is_some_and(
                            |head| {
                                matches!(head.as_str(), "test" | "[" | "[[")
                                    && !env.may_redefine(&head)
                            },
                        ) =>
                    {
                        jobs::command_status(cmd)
                    }
                    None if cmd.words.is_empty()
                        && cmd.assignments.iter().all(|assign| {
                            literal_word_text(&assign.value).is_some()
                                && env
                                    .reference_target(&assign.name)
                                    .is_some_and(|target| !env.readonly.contains(&target))
                        }) =>
                    {
                        Some(true)
                    }
                    _ => None,
                }
            } else {
                None
            };
            piped_stdin = outcome.stdout;
            if !pipeline && !short_circuit_operand {
                termination = outcome.terminates.map(|kind| (kind, cmd.span.end));
            }
            let eff_end = builder.effects_len() as u32;
            let span_node = self.span_node(builder, cmd.span);
            let redirs = outcome.redirs.flows;
            let model = outcome
                .model_eligible
                .then_some(outcome.name.as_deref())
                .flatten()
                .and_then(|name| self.nest.catalog.find(name));
            let mut model_bindings = model
                .map(|model| model.causal_bindings(&outcome.words))
                .unwrap_or_default();
            if outcome.name.as_deref() == Some("read") {
                model_bindings.push(crate::models::ModelCausalBinding {
                    assurance: effinterp_proto::CausalAssurance::Conservative,
                    from: crate::models::ModelBindingEnd::Port(effinterp_proto::Port::Stdin),
                    to: crate::models::ModelBindingEnd::Effect {
                        operation: "environment.write".into(),
                        selection: effinterp_model_schema::EffectSelection::All,
                    },
                });
            }
            add_source_causal_binding(outcome.name.as_deref(), &mut model_bindings);
            let stdout_selections = model
                .map(|model| model.stdout_value_bindings(&outcome.words))
                .unwrap_or_default();
            // A model names the descriptor an operand of its own
            // grammar means; an operand already written as a
            // descriptor path names one by itself.
            let declared = model
                .map(|model| model.descriptor_operands(&outcome.words))
                .unwrap_or_default();
            let spec = crate::flow::StageSpec {
                name: outcome.name,
                descriptor_operands: outcome
                    .words
                    .iter()
                    .chain(declared.iter().map(|(_, path)| path))
                    .filter_map(|word| {
                        let resource =
                            crate::paths::resolve_fs_word_with_cwd(word, env.cwd_resource.clone());
                        let mut identity = resource.clone();
                        builder.follow_created_aliases(&mut identity);
                        let mut aliased = match &identity {
                            ResourceExpr::Concrete {
                                identity: ResourceIdentity::FsPath { path },
                            } => eval::redirection::descriptor_path(
                                &Word::literal(path.clone()),
                                env,
                            ),
                            _ => None,
                        };
                        if aliased.is_none()
                            && let Some((mut source, suffix, provenance)) =
                                builder.archived_symlink_source(&identity)
                        {
                            let original = source.clone();
                            crate::models::common::follow_final_link(
                                builder,
                                &mut source,
                                &provenance,
                            );
                            if source != original
                                && let ResourceExpr::Concrete {
                                    identity: ResourceIdentity::FsPath { path },
                                } = source
                            {
                                aliased = eval::redirection::descriptor_path(
                                    &Word::literal(format!(
                                        "{}/{}",
                                        path.trim_end_matches('/'),
                                        suffix
                                    )),
                                    env,
                                );
                            }
                        }
                        eval::redirection::descriptor_path(word, env)
                            .or(aliased)
                            .map(|descriptor| (resource, descriptor))
                    })
                    .collect(),
                words: outcome.words,
                argument_producers: outcome.argument_producers,
                unquoted_substitutions: outcome.unquoted_substitutions,
                execution: outcome.execution,
                stdin_value: outcome
                    .stdin
                    .as_ref()
                    .is_some_and(|stdin| !stdin.piped && stdin.file.is_none()),
                effect_start: eff_start,
                effect_end: eff_end,
                redirs,
                inherited_redirs,
                span_node: Some(span_node),
                model_bindings,
                stdout_selections,
            };
            piped_values = mark_disclosed_environment_reads(
                builder,
                env,
                &spec,
                &outcome.stdin_producers,
                outcome.unestablished,
                position + 1 != cmds.len(),
                piped_values,
            );
            specs.push(spec);
        }
        crate::flow::settle_stdin_arguments(builder, &specs);
        for (channel, source) in crate::flow::channel_writers(builder, &specs, env.stdout_channel) {
            // Only a sole writer leaves its selection exact.
            env.channel_selections
                .borrow_mut()
                .entry(channel)
                .and_modify(|selection| *selection = None)
                .or_insert(source);
        }
        if pipeline
            || specs
                .first()
                .is_some_and(|spec| crate::flow::needs_single_stage(builder, spec))
        {
            crate::flow::build_pipeline(builder, specs);
        }
        if guarded {
            builder.pop_condition();
        }
        termination
    }
}
