//! Process execution: a resolved argv run as an external program. The
//! command is analyzed by the shared exec frontend as a nested invocation and
//! its argument producers are wired to the effects it states; a structurally
//! saturated walk keeps only the command head (`record_process_exec`).

use std::collections::{BTreeMap, BTreeSet};

use effinterp_proto::{
    BoundaryClass, BoundaryReason, Effect, ExecutionNodeRef, Modality, Operation, ProvenanceKind,
    ProvenanceRef, ResourceExpr,
};

use crate::builder::PlanBuilder;
use crate::exec::{UnresolvedHead, analyze_exec};
use crate::flow::Descriptor;
use crate::models::StdinValue;
use crate::nest::{Transition, word_resource};
use crate::paths::process_identity_with_cwd;
use crate::shell::lex::{RedirKind, Seg};
use crate::shell::parse::Simple;
use crate::shell::saturation_memos::{CommandHeadKey, resource_key, word_key};
use crate::shell::shell_env::ShellEnv;
use crate::shell::{
    Converted, EFFECTLESS_BUILTINS, MAX_SATURATED_COMMAND_HEADS, MAX_SATURATED_UNRESOLVED_HEADS,
    Shell, parse,
};
use crate::value::unresolved_resource;
use crate::word::{Word, WordPart};

use super::redirection::descriptor_path;
use super::source_and_eval::note_launched_command;
use super::word_expansion::var_node;

impl Shell<'_> {
    /// Analyze `converted` as an external command whose head word is the
    /// program to run; `run_command` calls this once per candidate head. Returns
    /// the nested execution and whether one model was selected for it, which
    /// stage-level bindings need.
    fn run_command_with_head(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        cmd: &Simple,
        converted: &[Converted],
        stdin: Option<&StdinValue>,
    ) -> (Option<ExecutionNodeRef>, bool) {
        // Exported branch values select separate invocations. Only an exhaustive
        // set of exclusive arms can replace the unresolved environment value.
        let choices = env
            .exported
            .iter()
            .filter_map(|name| env.vars.get(name))
            .find(|entry| !entry.nameref && entry.value.is_none() && !entry.branches.is_empty())
            .map(|entry| entry.branches.clone());
        if let Some(choices) = choices
            && let effinterp_proto::Condition::Atom { atom } = &choices[0].condition
            && choices.len() == atom.arms as usize
            && env.exported.iter().filter_map(|name| env.vars.get(name))
                .filter(|entry| !entry.nameref && entry.value.is_none() && !entry.branches.is_empty())
                .all(|entry| entry.branches.len() == choices.len() && entry.branches.iter().all(|branch| {
                    matches!(&branch.condition, effinterp_proto::Condition::Atom { atom: other } if other.origin == atom.origin)
                }))
            && choices.len() as u64 <= self.nest.limits.max_value_cardinality
        {
            for choice in choices {
                let condition = choice.condition;
                if !self.charge(builder, 1, env.vars.len() as u64 * crate::limits::NODE_BYTES, cmd.span) {
                    break;
                }
                let mut child = self.child_env(env);
                child.pid_is_own = env.pid_is_own;
                for name in &env.exported {
                    if let Some(entry) = child.vars.get_mut(name)
                        && entry.value.is_none()
                        && let Some(branch) = entry.branches.iter().find(|branch| branch.condition == condition)
                    {
                        entry.value = Some(branch.value.clone());
                        entry.span = branch.span;
                        entry.node = None;
                        entry.antecedents = branch.antecedents.clone();
                        entry.producers = branch.producers.clone();
                        entry.producers_condition = None;
                        entry.earlier_producers.clear();
                    }
                }
                builder.push_bound_condition(condition);
                self.run_command_with_head(builder, &mut child, cmd, converted, stdin);
                builder.pop_condition();
            }
            return (None, false);
        }
        let span_node = self.span_node(builder, cmd.span);
        let mut antecedents = vec![span_node];
        let tracks_host_context = self.nest.tracks_host_context_environment();
        if !tracks_host_context {
            for c in converted {
                antecedents.extend(&c.assign_nodes);
            }
        }
        let mut process_antecedents = antecedents.clone();
        if tracks_host_context {
            for converted in converted {
                process_antecedents.extend(&converted.assign_nodes);
            }
            process_antecedents.extend(env.cwd_node);
        }
        let words: Vec<Word> = converted.iter().map(|c| c.word.clone()).collect();
        let display_argv: Vec<String> = converted.iter().map(|c| c.raw.clone()).collect();
        if self.structural_saturated(builder, env) {
            // The structural limit stops nested model work, not the command
            // head already recovered from this source walk.
            self.record_process_exec(builder, env, &words, process_antecedents);
            return (None, false);
        }
        let mut environment = BTreeMap::new();
        let mut environment_nodes = BTreeMap::new();
        let mut environment_unsets = env.unexported.clone();
        let mut environment_concealed = BTreeSet::new();
        for name in env.exported.clone() {
            let Some(entry) = env.vars.get_mut(&name) else {
                continue;
            };
            // A concealed captured name (`export X=$(which rm)`) keeps its
            // concealment when the child shell imports the exported value.
            if entry.captured_name_hidden {
                environment_concealed.insert(name.clone());
            }
            let value = entry
                .value
                .clone()
                .map(|value| ResourceExpr::Literal { value })
                .or_else(|| entry.word_in_condition(builder).map(word_resource));
            environment.insert(name.clone(), value);
            environment_nodes.insert(name, var_node(builder, self.scope, entry, &env.chain_held));
        }
        for name in &env.exported_functions {
            let Some(entry) = env.functions.get(name) else {
                continue;
            };
            let environment_name = format!("BASH_FUNC_{name}%%");
            environment.insert(
                environment_name.clone(),
                Some(ResourceExpr::Literal {
                    value: entry.export_value.clone(),
                }),
            );
            if let Some(node) = env
                .exported_function_nodes
                .get(name)
                .copied()
                .or(entry.scope)
            {
                environment_nodes.insert(environment_name.clone(), node);
            }
            environment_unsets.remove(&environment_name);
        }
        for (name, node) in &env.unexported_function_nodes {
            let environment_name = format!("BASH_FUNC_{name}%%");
            environment.insert(environment_name.clone(), None);
            environment_nodes.insert(environment_name.clone(), *node);
            environment_unsets.insert(environment_name);
        }
        for name in &env.unexported {
            environment.insert(name.clone(), None);
            if let Some(node) = env.unexported_nodes.get(name).copied() {
                environment_nodes.insert(name.clone(), node);
            } else if let Some(entry) = env.vars.get_mut(name) {
                environment_nodes.insert(
                    name.clone(),
                    var_node(builder, self.scope, entry, &env.chain_held),
                );
            }
        }
        let mut assigned_command_search_path = None;
        for assignment in &cmd.assignments {
            let value = self.convert(builder, env, &assignment.value, false, true);
            let concealed = value.captured_name_hidden;
            let mut assignment_antecedents = self.scope.iter().copied().collect::<Vec<_>>();
            assignment_antecedents.extend(&value.assign_nodes);
            let node = builder.node(
                ProvenanceKind::SourceSpan {
                    start: assignment.span.start,
                    end: assignment.span.end,
                },
                &assignment_antecedents,
            );
            builder.register_environment_value_producers(node, &value.producers);
            let value = word_resource(&value.word);
            // A prefix assignment through a nameref names the target variable.
            let name = env
                .reference_target(&assignment.name)
                .unwrap_or_else(|| assignment.name.clone());
            environment.insert(name.clone(), Some(value.clone()));
            environment_nodes.insert(name.clone(), node);
            environment_unsets.remove(&name);
            // The prefix value defines the child's name: a concealed capture
            // (`X=$(which rm) sh -c …`) marks it, a transparent value clears an
            // inherited mark (`X=ls sh -c …`).
            if concealed {
                environment_concealed.insert(name.clone());
            } else {
                environment_concealed.remove(&name);
            }
            if name == "PATH" {
                assigned_command_search_path = Some(value);
            }
        }
        let command_search_path = assigned_command_search_path.or_else(|| {
            if env.unset.contains("PATH") {
                Some(unresolved_resource("value"))
            } else {
                env.vars.get_mut("PATH").map(|entry| {
                    entry
                        .value
                        .clone()
                        .map(|value| ResourceExpr::Literal { value })
                        .or_else(|| entry.word_in_condition(builder).map(word_resource))
                        .unwrap_or(unresolved_resource("value"))
                })
            }
        });
        let Some(frame) = self.nest.begin(
            builder,
            Transition::exec(words.iter().map(word_resource).collect(), words.to_vec())
                .exec_cwd(env.cwd.as_deref())
                .cwd(env.cwd_resource.clone(), env.cwd_node)
                .stdin(stdin)
                .environment(environment, environment_nodes, environment_unsets)
                .environment_concealed(environment_concealed)
                .display_argv(&display_argv),
            &antecedents,
            self.depth,
        ) else {
            self.record_process_exec(builder, env, &words, process_antecedents);
            return (None, false);
        };
        let (nested_node, execution) = (frame.scope, frame.execution);
        let eff_start = builder.effects_len();
        let argv_union_groups: Vec<_> = converted
            .iter()
            .map(|converted| {
                matches!(converted.word.parts.as_slice(), [WordPart::Union(_)])
                    .then(|| converted.assign_nodes.last().copied())
                    .flatten()
            })
            .collect();
        let argv_provenance = (tracks_host_context
            || converted.iter().any(|value| {
                !value.producers.is_empty() && crate::models::assignment(&value.word).is_some()
            }))
        .then(|| {
            converted
                .iter()
                .map(|converted| {
                    let mut provenance = converted.assign_nodes.clone();
                    if !converted.producers.is_empty()
                        && crate::models::assignment(&converted.word).is_some()
                    {
                        let node = self.span_node(builder, converted.span);
                        builder.register_environment_value_producers(node, &converted.producers);
                        provenance.push(node);
                    }
                    provenance
                })
                .collect::<Vec<_>>()
        });
        // A program opening `/dev/fd/N` reads the bytes this shell left open
        // on N, such as an `exec N<<<...` here-string or the output of a
        // `<(...)` operand. The command's own redirection of N replaces
        // that: a quoted `N<<<text` supplies its text, and any other leaves
        // the bytes unknown.
        let descriptor_sources = converted
            .iter()
            // An option may take the path attached, as `--input=/dev/fd/3`.
            .flat_map(|word| {
                let attached = word.word.split_assignment().map(|(_, value)| value);
                std::iter::once(word.word.clone()).chain(attached)
            })
            .filter_map(|word| {
                let descriptor = descriptor_path(&word, env)?;
                let own = cmd.redirs.iter().rev().find(|redir| {
                    redir.named_fd.is_none() && redir.fd.map(Descriptor::Number) == Some(descriptor)
                });
                let content = match own {
                    Some(redir) if redir.kind == RedirKind::HereString => {
                        let target = redir.target.as_ref()?;
                        let text = parse::command_name_text(target)
                            .or_else(|| self.fixed_word_text(env, target))?;
                        Word::literal(format!("{text}\n"))
                    }
                    Some(_) => return None,
                    None => env.descriptors.get(&descriptor)?.clone(),
                };
                Some((word, content))
            })
            .collect();
        let descriptor_sources = self
            .nest
            .budget
            .replace_descriptor_sources(descriptor_sources);
        // A shell this command starts inherits a PWD that `cd` resolved.
        let physical_cwd = self.nest.physical_cwd.replace(env.physical_depth.is_some());
        let model_eligible = analyze_exec(
            builder,
            self.nest,
            &words,
            stdin,
            if !converted[0].unresolved_default_override
                && converted[0].alts.is_empty()
                && cmd.words.first().is_some_and(|word| {
                    matches!(
                        word.segs.as_slice(),
                        [Seg::Env { .. }] | [Seg::Positional { .. }]
                    ) || matches!(word.segs.as_slice(), [Seg::Param { default: Some(default), quoted: false, .. }]
                        if default.word.is_empty() && !default.assign)
                })
            {
                UnresolvedHead::LikelyWrapper {
                    condition: self.source_condition(
                        builder,
                        effinterp_proto::ByteSpan {
                            start: converted[0].span.start,
                            end: converted[0].span.end,
                        },
                        effinterp_proto::ConditionKind::UnresolvedExecution,
                        0,
                        2,
                        false,
                        false,
                    ),
                }
            } else {
                UnresolvedHead::Opaque
            },
            Some(&argv_union_groups),
            argv_provenance.as_deref(),
            env.cwd.as_deref(),
            env.runtime_cwd.as_deref(),
            command_search_path,
            Some(nested_node),
            env.cwd_node,
            self.depth + 1,
        );
        self.nest.physical_cwd.set(physical_cwd);
        self.nest
            .budget
            .replace_descriptor_sources(descriptor_sources);
        if cmd
            .words
            .first()
            .and_then(parse::command_name_text)
            .as_deref()
            == Some("exec")
        {
            self.exec_self_reread(builder, env, cmd, converted, nested_node);
        }
        let eff_end = builder.effects_len();
        self.wire_arg_producers(
            builder,
            cmd.span,
            Some(execution),
            converted,
            eff_start,
            eff_end,
        );
        frame.end(builder);
        (Some(execution), model_eligible)
    }

    // An unresolved interpreter can still expose its embedded language through
    // a self re-read and a shebang. Literal ruby is handled by its command model.
    /// A command given `-x` and the running script's own path reads that script
    /// again. When a later `#!` line in the script names the command's program,
    /// the text from that line on is analyzed as that program's script.
    fn exec_self_reread(
        &self,
        builder: &mut PlanBuilder,
        env: &ShellEnv,
        cmd: &Simple,
        converted: &[Converted],
        scope: ProvenanceRef,
    ) {
        let script = self.nest.current_script.borrow().clone();
        let Some((origin, source)) = script else {
            return;
        };
        if !converted.windows(2).any(|words| {
            words[0].word.as_literal() == Some("-x")
                && words[1].word.as_literal() == Some(origin.as_str())
        }) {
            return;
        }
        // A sourced command's span belongs to its library, not the `$0` buffer.
        // In that case search after the caller's initial shell shebang.
        let start = if source == self.source {
            cmd.span.end as usize
        } else {
            source.find('\n').map_or(source.len(), |end| end + 1)
        };
        let Some(offset) = source.get(start..).and_then(|tail| {
            tail.split_inclusive('\n')
                .scan(start, |offset, line| {
                    let start = *offset;
                    *offset += line.len();
                    Some((start, line))
                })
                .find_map(|(offset, line)| line.starts_with("#!").then_some(offset))
        }) else {
            return;
        };
        let remainder = &source[offset..];
        let Some(interpreter) = crate::exec::shebang_interpreter(remainder) else {
            return;
        };
        let interpreter = interpreter.rsplit('/').next().unwrap();
        if converted[0]
            .word
            .as_literal()
            .is_some_and(|head| head.rsplit('/').next() != Some(interpreter))
        {
            return;
        }
        if let Some((subject, kind, _)) =
            crate::exec::shebang_subject(remainder, env.cwd.as_deref())
        {
            if converted[0].word.as_literal().is_none() {
                self.nest.nest(
                    builder,
                    Transition::file(subject)
                        .kind(kind)
                        .origin(origin)
                        .cwd(env.cwd_resource.clone(), env.cwd_node),
                    &[scope],
                    self.depth + 1,
                );
            }
        } else {
            self.opaque_boundary(
                builder,
                BoundaryReason::DYNAMIC_SOURCE,
                BoundaryClass::Unresolved,
                &format!("unsupported interpreter {interpreter} in -x self re-read"),
                cmd.span,
            );
        }
    }

    /// Retain the command head when a structural limit prevents model work.
    fn record_process_exec(
        &self,
        builder: &mut PlanBuilder,
        env: &ShellEnv,
        words: &[Word],
        provenance: Vec<ProvenanceRef>,
    ) {
        let Some(head) = words.first() else {
            return;
        };
        let literal = head.as_literal();
        let mut memos = env.saturation_memos.borrow_mut();
        if literal.is_none() && memos.unresolved_heads >= MAX_SATURATED_UNRESOLVED_HEADS {
            return;
        }
        if env.function_heads_only
            && let Some(node) = provenance.first().copied()
        {
            let key = CommandHeadKey {
                node,
                head: word_key(head),
                cwd: resource_key(env.cwd_resource.as_ref()),
            };
            if memos.function_commands.len() >= MAX_SATURATED_COMMAND_HEADS
                || !memos.function_commands.insert(key)
            {
                return;
            }
        }
        if literal.is_none() {
            memos.unresolved_heads += 1;
        }
        drop(memos);
        let resource = match literal {
            Some(name) if !name.rsplit('/').next().unwrap_or(name).is_empty() => {
                ResourceExpr::Concrete {
                    identity: process_identity_with_cwd(words, env.cwd_resource.clone()),
                }
            }
            _ => unresolved_resource("process"),
        };
        builder.effect(Effect {
            request_assurance: effinterp_proto::RequestAssurance::Conservative,
            id: Default::default(),
            operation: Operation::new("process.exec"),
            resource,
            attributes: Default::default(),
            modality: Modality::May,
            realm: effinterp_proto::ExecutionRealm::Host,
            condition: None,
            execution: effinterp_proto::ExecutionNodeRef(0),
            provenance,
        });
    }

    /// Analyze `converted` as an external command, and state on the files
    /// sourced before it whether the command may read their variables back.
    pub(super) fn run_command(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        cmd: &Simple,
        converted: &[Converted],
        stdin: Option<&StdinValue>,
    ) -> (Option<ExecutionNodeRef>, bool) {
        let begun = builder.effects_len();
        let ran = self.run_command_heads(builder, env, cmd, converted, stdin);
        note_launched_command(builder, begun);
        ran
    }

    /// Analyze `converted` as an external command, trying each possible head
    /// when the first word is a variable that may be one of several literals.
    fn run_command_heads(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        cmd: &Simple,
        converted: &[Converted],
        stdin: Option<&StdinValue>,
    ) -> (Option<ExecutionNodeRef>, bool) {
        let Some(head) = converted.first() else {
            return (None, false);
        };
        if head.word.as_literal().is_none() && !head.alts.is_empty() {
            // A default is a candidate, not proof that the runtime override is absent.
            let mut last = if head.unresolved_default_override {
                self.run_command_with_head(builder, env, cmd, converted, stdin)
            } else {
                (None, false)
            };
            for alt in &head.alts {
                if EFFECTLESS_BUILTINS.contains(&alt.as_str()) {
                    continue;
                }
                let mut words = converted.to_vec();
                words[0].word = Word::literal(alt.clone());
                words[0].raw = alt.clone();
                let candidate = self.run_command_with_head(builder, env, cmd, &words, stdin);
                last.0 = candidate.0.or(last.0);
            }
            // Multiple possible heads do not establish one selected model for
            // stage-level bindings, even when each candidate is modeled.
            last.1 = false;
            return last;
        }
        if head
            .word
            .as_literal()
            .is_some_and(|n| EFFECTLESS_BUILTINS.contains(&n))
        {
            return (None, false);
        }
        self.run_command_with_head(builder, env, cmd, converted, stdin)
    }
}
