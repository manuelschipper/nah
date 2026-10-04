//! The shell `source` (`.`) and `eval` builtins: which file or text they run,
//! how it is followed, and what an unfollowed source leaves unknown.

use std::collections::BTreeSet;
use std::rc::Rc;

use effinterp_proto::{
    AttrValue, BoundaryClass, BoundaryReason, CoverageLevel, Domain, Effect, ExecutionNodeRef,
    Modality, Operation, ProvenanceKind, ProvenanceRef, ResourceExpr, ResourceIdentity, Subject,
};

use crate::builder::PlanBuilder;
use crate::flow::{BindEnd, Descriptor, FlowStage, PortBinding};
use crate::models::StdinValue;
use crate::nest::{SourceResolution, Transition};
use crate::paths::{join_source_path, process_identity_with_cwd};
use crate::shell::lex::{Seg, ShellSpan, Tok, WordTok};
use crate::shell::parse::Simple;
use crate::shell::{
    Converted, Shell, ShellEnv, Termination, analyze_shell_with_env, lex, parse,
    variable_saturation_key,
};
use crate::word::{Word, WordPart};
use crate::{SourcePurpose, SourceRefusal};

use super::redirection::{descriptor_path, descriptor_read_producer};
use super::variable_binding::captured_literal;
use super::{ConditionalShellState, NestedShellMode, substitution_hides_name};

impl Shell<'_> {
    pub(super) fn eval_builtin(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        cmd: &Simple,
        converted: &[Converted],
        persist: bool,
    ) {
        let source_start =
            1 + usize::from(converted.get(1).and_then(|word| word.word.as_literal()) == Some("--"));
        if converted.len() <= source_start {
            return;
        }
        let start = builder.effects_len();
        let node = self.span_node(builder, cmd.span);
        let mut provenance = (source_start..converted.len())
            .map(|index| {
                builder.node(
                    ProvenanceKind::Argument {
                        index: index as u32,
                    },
                    self.scope.as_slice(),
                )
            })
            .collect::<Vec<_>>();
        provenance.push(node);
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
            attributes: [(
                "source".to_string(),
                effinterp_proto::AttrValue::String("argument".to_string()),
            )]
            .into_iter()
            .collect(),
            modality: Modality::May,
            realm: effinterp_proto::ExecutionRealm::Host,
            condition: None,
            execution: effinterp_proto::ExecutionNodeRef(0),
            provenance,
        });
        let producers = converted[source_start..]
            .iter()
            .flat_map(|word| word.producers.iter().cloned())
            .collect::<Vec<_>>();
        self.wire_code_producers(builder, cmd.span, None, &producers, start, start + 1, false);
        let source = converted[source_start..]
            .iter()
            .map(|word| captured_literal(&word.word))
            .collect::<Option<Vec<_>>>()
            .map(|words| words.join(" "));
        match source {
            Some(source) if !source.is_empty() => {
                builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);
                // Text a transform (`tr`, `rev`) prints is code the reader
                // cannot see. The burden is on proving it supplies only data
                // arguments; anything the recovered structure cannot rule out
                // (a dispatcher or non-literal head, a redirection, a command
                // operator, or an alias-expanded head) keeps the fact.
                let mut offset = 0;
                for word in &converted[source_start..] {
                    let len = captured_literal(&word.word).map_or(0, |text| text.len());
                    let transformed = cmd.words.iter().any(|tok| {
                        tok.span == word.span
                            && matches!(tok.segs.as_slice(), [Seg::CommandSub { source, quoted, .. }]
                                if substitution_hides_name(source, *quoted))
                    });
                    if transformed
                        && !transform_is_pure_argument(env, &source, offset..offset + len)
                    {
                        self.emit_hidden_program_effect(builder, env, word.span);
                        break;
                    }
                    offset += len + 1;
                }
                self.nested_shell_source(
                    builder,
                    env,
                    &source,
                    cmd.span,
                    if persist {
                        NestedShellMode::Persist
                    } else {
                        NestedShellMode::Child
                    },
                );
            }
            Some(_) => self.opaque_boundary(
                builder,
                BoundaryReason::UNRECOVERABLE_SOURCE,
                BoundaryClass::Unresolved,
                "eval source resolved to an empty string",
                cmd.span,
            ),
            None => {
                // Unseen code may rebind any script variable, so a later
                // command head spelled from one names a program the source
                // does not show. The values stay as the known candidates.
                if persist {
                    for (name, entry) in &mut env.vars {
                        if entry.script_may_set && !env.readonly.contains(name) {
                            entry.captured_name_hidden = true;
                            entry.transparent_writes.clear();
                        }
                    }
                }
                self.opaque_boundary(
                    builder,
                    BoundaryReason::DYNAMIC_SOURCE,
                    BoundaryClass::Unresolved,
                    "eval source is not statically recoverable",
                    cmd.span,
                );
                self.opaque_boundary(
                    builder,
                    BoundaryReason::UNRECOVERABLE_SOURCE,
                    BoundaryClass::Unresolved,
                    "eval source is not statically recoverable",
                    cmd.span,
                );
            }
        }
        let end = builder.effects_len();
        self.wire_arg_producers(builder, cmd.span, None, converted, start, end);
    }

    /// Follow a literal or bounded source pattern through the caller's resolver. Sourcing mutates the current shell; a pipeline/subshell uses a
    /// child environment, as selected by `persist`.
    pub(super) fn source_file(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        converted: &[Converted],
        stdin: Option<&StdinValue>,
        persist: bool,
        conditional: bool,
    ) -> Option<Termination> {
        let Some(target) = converted.get(1) else {
            self.opaque_boundary(
                builder,
                BoundaryReason::UNRESOLVED_SOURCE,
                BoundaryClass::Unresolved,
                "source without an operand",
                converted[0].span,
            );
            return None;
        };
        // A `/dev/fd/N` operand reads whatever process substitution is open on N.
        let mut producers = target.producers.clone();
        if let Some(producer) = descriptor_path(&target.word, env)
            .and_then(|descriptor| descriptor_read_producer(env.redirections.iter(), descriptor))
            && !producers.contains(&producer)
        {
            producers.push(producer);
        }
        if !producers.is_empty() || target.word.as_literal() == Some("/dev/stdin") {
            let start = builder.effects_len();
            let node = self.span_node(builder, target.span);
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
                attributes: [(
                    "source".to_string(),
                    AttrValue::String(
                        if target.word.as_literal() == Some("/dev/stdin") {
                            "stdin"
                        } else {
                            "file"
                        }
                        .to_string(),
                    ),
                )]
                .into_iter()
                .collect(),
                modality: Modality::May,
                realm: effinterp_proto::ExecutionRealm::Host,
                condition: None,
                execution: ExecutionNodeRef(0),
                provenance: vec![node],
            });
            self.wire_code_producers(
                builder,
                target.span,
                None,
                &producers,
                start,
                start + 1,
                false,
            );
        }
        // `source /dev/fd/N` reads the bytes `exec` left open on N; they are
        // this shell's own here-document, not a file admitted from the host.
        if let Some(content) = descriptor_path(&target.word, env)
            .and_then(|descriptor| env.descriptors.get(&descriptor))
            .and_then(|content| content.as_literal())
            .map(str::to_string)
        {
            let span = target.span;
            self.nested_shell_source(
                builder,
                env,
                &content,
                span,
                if persist {
                    NestedShellMode::Persist
                } else {
                    NestedShellMode::Child
                },
            );
            return None;
        }
        // `source /dev/stdin` reads this command's standard input, so known
        // piped or here-string bytes are the sourced text.
        if (target.word.as_literal() == Some("/dev/stdin")
            || descriptor_path(&target.word, env) == Some(Descriptor::Number(0)))
            && let Some(content) = stdin
                .and_then(|stdin| stdin.word.as_literal())
                .map(str::to_string)
        {
            self.nested_shell_source(
                builder,
                env,
                &content,
                target.span,
                if persist {
                    NestedShellMode::Persist
                } else {
                    NestedShellMode::Child
                },
            );
            return None;
        }
        // Invoked scripts resolve source operands against the runtime cwd.
        let source_cwd = if env.source_uses_runtime_cwd {
            env.runtime_cwd.as_deref()
        } else {
            env.source_cwd.as_deref()
        };
        let literal_path = target
            .word
            .as_literal()
            .and_then(|spec| join_source_path(source_cwd, spec).map(|(_, path)| path));
        if self.nest.resolver.is_none()
            && let Some(spec) = target.word.as_literal()
            && literal_path.as_ref().is_none_or(|path| {
                matches!(
                    builder.written_source(path, |resource, path| {
                        self.nest.source_mutation_may_alias(resource, path)
                    }),
                    crate::builder::WrittenSource::Host
                )
            })
        {
            // No file bytes can be admitted here; retain the existing opaque
            // source evidence without enabling the alternative search path.
            let Some(path) = crate::paths::join_relative_file(env.source_cwd.as_deref(), spec)
            else {
                self.opaque_boundary(
                    builder,
                    BoundaryReason::UNRESOLVED_SOURCE,
                    BoundaryClass::Unresolved,
                    &format!("sourced file {spec}"),
                    target.span,
                );
                invalidate_unobserved_source_variables(env, self.span_node(builder, target.span));
                return None;
            };
            if let SourceResolution::Refused(SourceRefusal::Limit { limit }) = self
                .nest
                .resolve_source_file(builder, &path, SourcePurpose::DependencySource, "shell")
            {
                builder.note_saturated(limit);
            } else {
                self.opaque_boundary(
                    builder,
                    BoundaryReason::UNRESOLVED_SOURCE,
                    BoundaryClass::Unresolved,
                    &format!("sourced file {path}"),
                    target.span,
                );
            }
            invalidate_unobserved_source_variables(env, self.span_node(builder, target.span));
            return None;
        }
        // A bare source operand searches an unobserved PATH before the cwd.
        if env.source_uses_runtime_cwd
            && let Some(spec) = target.word.as_literal().filter(|spec| !spec.contains('/'))
        {
            let mut input = self.nest.source_input(
                builder,
                spec,
                SourcePurpose::InvocationInput,
                effinterp_proto::ExecutionContent::Unobserved {
                    reason: effinterp_proto::ExecutionInputReason::Ambiguous,
                },
                "shell",
            );
            input.selected = None;
            self.nest.record_input_boundary(builder, spec, input);
            invalidate_unobserved_source_variables(env, self.span_node(builder, target.span));
            return None;
        }
        let mut inventory_unavailable = false;
        let paths = if target.word.as_literal().is_some() {
            literal_path.map(|path| vec![path])
        } else if self.nest.resolver.is_some() {
            crate::SourcePattern::from_word(&target.word, source_cwd).and_then(|pattern| {
                let matches = self.nest.resolver?.matching(&pattern);
                inventory_unavailable = matches.is_none();
                matches
            })
        } else {
            None
        };
        let Some(mut paths) = paths.filter(|paths| !paths.is_empty()) else {
            self.opaque_boundary(
                builder,
                BoundaryReason::UNRESOLVED_SOURCE,
                BoundaryClass::Unresolved,
                if inventory_unavailable {
                    "sourced file path is not statically recoverable (bounded inventory max_files)"
                } else {
                    "sourced file path is not statically recoverable"
                },
                target.span,
            );
            invalidate_unobserved_source_variables(env, self.span_node(builder, target.span));
            return None;
        };
        paths.sort();
        paths.dedup();
        if paths.len() as u64 > self.nest.limits.max_source_alternatives {
            builder.note_saturated_detail(
                "max_source_alternatives",
                format!(
                    "source pattern {} matched {} files",
                    target.word.render_raw(),
                    paths.len()
                ),
            );
            invalidate_unobserved_source_variables(env, self.span_node(builder, target.span));
            return None;
        }
        let functions = env.functions.clone();
        let mut candidate_functions = Vec::new();
        // A merged operand can include paths that do not resolve to checkout files.
        // Even one admitted file is conditional when another value remains possible.
        fn has_union(word: &Word) -> bool {
            word.parts
                .iter()
                .any(|part| matches!(part, WordPart::Union(words) if words.len() > 1))
        }
        let condition_arms = paths.len().max(if has_union(&target.word) { 2 } else { 1 });
        let mut termination = None;
        let mut all_terminate = !has_union(&target.word);
        let positional = env.positional.clone();
        let positional_set_changed = env.positional_set_changed;
        let positional_discard_revision = env.positional_discard_revision;
        let mut candidate_positional = Vec::new();
        let merge_state = persist && (condition_arms > 1 || conditional);
        let mut state = merge_state.then(|| ConditionalShellState::new(env));
        for (ordinal, path) in paths.iter().enumerate() {
            if paths.len() > 1 {
                env.functions = functions.clone();
                env.positional = positional.clone();
                env.positional_set_changed = positional_set_changed;
                env.positional_discard_revision = positional_discard_revision;
            }
            if let Some(state) = &state {
                state.reset(env);
            }
            let condition = (condition_arms > 1).then(|| {
                self.source_condition(
                    builder,
                    effinterp_proto::ByteSpan {
                        start: target.span.start,
                        end: target.span.end,
                    },
                    effinterp_proto::ConditionKind::Branch,
                    ordinal as u32,
                    condition_arms as u32,
                    !has_union(&target.word),
                    false,
                )
            });
            if let Some(condition) = &condition {
                builder.push_condition(condition.clone());
            }
            let candidate_termination = self.source_candidate(
                builder,
                env,
                converted,
                path,
                &paths,
                condition.clone(),
                persist,
            );
            if let Some(state) = &mut state {
                state.observe(env);
            }
            all_terminate &= candidate_termination.is_some();
            termination = candidate_termination;
            if paths.len() > 1 && persist {
                candidate_functions.push((env.functions.clone(), condition.clone()));
            }
            if condition.is_some() {
                builder.pop_condition();
                candidate_positional.push((
                    env.positional.clone(),
                    env.positional_set_changed,
                    env.positional_discard_revision,
                ));
            }
        }
        if paths.len() > 1 {
            if persist {
                env.functions = functions.clone();
                let changed: BTreeSet<_> = candidate_functions
                    .iter()
                    .flat_map(|(candidate, _)| {
                        candidate
                            .iter()
                            .filter(|(name, entry)| {
                                !functions
                                    .get(*name)
                                    .is_some_and(|prior| Rc::ptr_eq(prior, entry))
                            })
                            .map(|(name, _)| name.clone())
                    })
                    .collect();
                for name in changed {
                    let mut entries = Vec::new();
                    for (candidate, condition) in &candidate_functions {
                        let Some(entry) = candidate.get(&name) else {
                            continue;
                        };
                        for entry in entry.alternatives.iter().chain(std::iter::once(entry)) {
                            let mut entry = (**entry).clone();
                            entry.alternatives.clear();
                            entry.source_condition = effinterp_proto::Condition::compose(
                                entry.source_condition.iter().chain(condition.iter()),
                            );
                            entries.push(Rc::new(entry));
                        }
                    }
                    let mut entry = (*entries.pop().unwrap()).clone();
                    entry.alternatives = entries;
                    env.functions.insert(name, Rc::new(entry));
                }
            }
            let words = |positionals: &Option<Vec<Converted>>| {
                positionals
                    .as_ref()
                    .map(|args| args.iter().map(|arg| arg.word.clone()).collect::<Vec<_>>())
            };
            env.positional = if candidate_positional
                .iter()
                .all(|args| words(&args.0) == words(&candidate_positional[0].0))
            {
                candidate_positional[0].0.clone()
            } else {
                None
            };
            env.positional_set_changed = if candidate_positional
                .iter()
                .all(|args| args.1 == candidate_positional[0].1)
            {
                candidate_positional[0].1
            } else {
                None
            };
            env.positional_discard_revision = candidate_positional
                .iter()
                .map(|args| args.2)
                .max()
                .unwrap();
        }
        if let Some(state) = state {
            state.merge(env);
        }
        if persist && (conditional || has_union(&target.word)) {
            env.positional = None;
            if env.positional_set_changed != positional_set_changed {
                env.positional_set_changed = None;
            }
            self.opaque_boundary(
                builder,
                BoundaryReason::UNSUPPORTED_SHELL_SYNTAX,
                BoundaryClass::Unsupported,
                "conditional source may change positional parameters",
                target.span,
            );
        }
        termination.filter(|_| all_terminate)
    }

    /// A sourced file the analysis cannot follow is still read and run by
    /// this shell. Record the same program-input read and file execution a
    /// followed file records, so bytes an earlier command wrote to the path
    /// (`curl -o f && . f`) reach the execution.
    fn unfollowed_source_input(&self, builder: &mut PlanBuilder, path: &str, span: ShellSpan) {
        let node = self.span_node(builder, span);
        let effects = [
            (
                "filesystem.read",
                ResourceIdentity::FsPath {
                    path: path.to_string(),
                },
                ("access_purpose", "program_input"),
            ),
            (
                "process.code_execution",
                crate::paths::executable_identity("shell", None),
                ("source", "file"),
            ),
        ]
        .map(|(operation, resource, attribute)| {
            builder.effect(Effect {
                request_assurance: effinterp_proto::RequestAssurance::Conservative,
                id: Default::default(),
                operation: Operation::new(operation),
                resource: ResourceExpr::Concrete { identity: resource },
                attributes: [(
                    attribute.0.to_string(),
                    AttrValue::String(attribute.1.to_string()),
                )]
                .into_iter()
                .collect(),
                modality: Modality::May,
                realm: effinterp_proto::ExecutionRealm::Host,
                condition: None,
                execution: ExecutionNodeRef(0),
                provenance: vec![node],
            })
        });
        if let [Some(read), Some(execution)] = effects {
            builder.flow_stage(FlowStage {
                execution: None,
                effects: vec![read, execution],
                bindings: vec![PortBinding {
                    assurance: effinterp_proto::CausalAssurance::Conservative,
                    from: BindEnd::Effect(read),
                    to: BindEnd::Effect(execution),
                }],
                provenance: vec![node],
            });
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn source_candidate(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        converted: &[Converted],
        path: &str,
        paths: &[String],
        condition: Option<effinterp_proto::Condition>,
        persist: bool,
    ) -> Option<Termination> {
        let target = &converted[1];
        let namespace = if path.starts_with('/') {
            crate::SourceNamespace::Host
        } else {
            crate::SourceNamespace::Repository
        };
        let resolution = if builder.is_host_realm() {
            self.nest.resolve_source_selection(
                builder,
                path.to_string(),
                namespace,
                SourcePurpose::InvocationInput,
                "shell",
            )
        } else {
            self.nest
                .resolve_source_file(builder, path, SourcePurpose::InvocationInput, "shell")
        };
        // The resolver tries a file only with an execution node to spare. A
        // file it cannot follow charges none, so while a branch arm's demand
        // is measured, count that spare node; otherwise the arm is allotted
        // nothing and the real walk refuses `if …; then . ./f; fi` as a limit.
        if self.nest.budget.measuring() && !matches!(resolution, SourceResolution::Source { .. }) {
            let _ = self.nest.budget.try_charge();
        }
        let (origin, source) = match resolution {
            SourceResolution::Source { origin, source } => (origin, source),
            SourceResolution::Refused(SourceRefusal::Limit { limit }) => {
                builder.note_saturated(limit);
                self.unfollowed_source_input(builder, path, target.span);
                invalidate_unobserved_source_variables(env, self.span_node(builder, target.span));
                return None;
            }
            SourceResolution::Refused(SourceRefusal::Unavailable(reason)) => {
                self.unfollowed_source_input(builder, path, target.span);
                self.opaque_boundary(
                    builder,
                    BoundaryReason::UNRESOLVED_SOURCE,
                    BoundaryClass::Unresolved,
                    &format!("sourced file {path}: {}", reason.as_str()),
                    target.span,
                );
                invalidate_unobserved_source_variables(env, self.span_node(builder, target.span));
                return None;
            }
            SourceResolution::UnsupportedEncoding => {
                self.unfollowed_source_input(builder, path, target.span);
                self.opaque_boundary(
                    builder,
                    BoundaryReason::UNRESOLVED_SOURCE,
                    BoundaryClass::Unresolved,
                    &format!("sourced file {path}: source is not valid UTF-8"),
                    target.span,
                );
                invalidate_unobserved_source_variables(env, self.span_node(builder, target.span));
                return None;
            }
            SourceResolution::AlreadySelected => return None,
            SourceResolution::Unavailable => {
                self.unfollowed_source_input(builder, path, target.span);
                self.opaque_boundary(
                    builder,
                    BoundaryReason::UNRESOLVED_SOURCE,
                    BoundaryClass::Unresolved,
                    &format!("sourced file {path}"),
                    target.span,
                );
                invalidate_unobserved_source_variables(env, self.span_node(builder, target.span));
                return None;
            }
        };
        let assurance = if paths.len() > 1 {
            if let Some(input) = self
                .nest
                .selected_source_inputs
                .borrow_mut()
                .get_mut(&origin)
            {
                input.assurance = effinterp_proto::ExecutionAssurance::Alternatives;
                input.selection = effinterp_proto::ExecutionSelection::Search {
                    candidates: paths
                        .iter()
                        .map(|path| ResourceExpr::Concrete {
                            identity: ResourceIdentity::FsPath { path: path.clone() },
                        })
                        .collect(),
                    selected: None,
                };
            }
            effinterp_proto::ExecutionAssurance::Alternatives
        } else {
            effinterp_proto::ExecutionAssurance::Exact
        };
        let node = self.span_node(builder, target.span);
        let subject = Subject::Shell {
            source: source.clone(),
            cwd: env.cwd.clone(),
            context: Default::default(),
        };
        let frame = self.nest.begin(
            builder,
            Transition::file(subject)
                .origin(origin.clone())
                .streams(builder.inherited_execution_streams())
                .assurance(assurance)
                .cwd(env.cwd_resource.clone(), env.cwd_node),
            &[node],
            self.depth,
        )?;
        let scope = frame.scope;
        let previous_source = env.script_source.replace(origin);
        let source_condition = (condition.is_some() || env.source_condition.is_some())
            .then(|| builder.current_condition())
            .flatten();
        let previous_condition = std::mem::replace(&mut env.source_condition, source_condition);
        // Source arguments are restored unless `set` replaces the list outside
        // a function. The changed flag is shell-wide, not saved by nested calls.
        // Without arguments the sourced code shares the caller's list.
        let args = (converted.len() > 2).then(|| converted[2..].to_vec());
        let prior_sourced = std::mem::replace(&mut env.sourced, true);
        let termination = if persist {
            let saved = args.map(|args| env.positional.replace(args));
            let saved_revision = env.positional_discard_revision;
            env.positional_set_changed = Some(false);
            let aliases = env.aliases.clone();
            let termination = analyze_shell_with_env(
                builder,
                self.nest,
                &source,
                env,
                Some(scope),
                self.depth + 1,
            );
            env.anchor_new_aliases(&aliases, converted[converted.len() - 1].span.end);
            if let Some(saved) = saved {
                if env.positional_set_changed.is_none() && env.active.is_empty() {
                    env.positional = None;
                    env.positional_discard_revision += 1;
                    self.opaque_boundary(
                        builder,
                        BoundaryReason::UNSUPPORTED_SHELL_SYNTAX,
                        BoundaryClass::Unsupported,
                        "conditional call may reset sourced positional restoration",
                        target.span,
                    );
                } else if env.positional_set_changed == Some(true) && env.active.is_empty() {
                    // Older Bash leaves the discarded frame on its argument
                    // stack. Enclosing restores cannot assume either version.
                    env.positional_discard_revision += 1;
                } else if env.positional_discard_revision == saved_revision {
                    env.positional = saved;
                } else {
                    env.positional = None;
                    self.opaque_boundary(
                        builder,
                        BoundaryReason::UNSUPPORTED_SHELL_SYNTAX,
                        BoundaryClass::Unsupported,
                        "nested source positional restoration depends on shell version",
                        target.span,
                    );
                }
                env.positional_set_changed = Some(false);
            }
            termination
        } else {
            let mut child = self.child_env(env);
            child.positional_set_changed = Some(false);
            if let Some(args) = args {
                child.positional = Some(args);
            }
            analyze_shell_with_env(
                builder,
                self.nest,
                &source,
                &mut child,
                Some(scope),
                self.depth + 1,
            );
            None
        };
        env.script_source = previous_source;
        env.source_condition = previous_condition;
        env.sourced = prior_sourced;
        frame.end(builder);
        termination
            .map(|(kind, _)| kind)
            .filter(|kind| *kind != Termination::Return)
    }
}

fn invalidate_unobserved_source_variables(env: &mut ShellEnv, source: ProvenanceRef) {
    env.unset.clear();
    for (name, entry) in &mut env.vars {
        if env.readonly.contains(name) {
            continue;
        }
        entry.value = None;
        entry.branches.clear();
        entry.transparent_writes.clear();
        entry.may.clear();
        entry.unresolved_default_override = false;
        entry.word = Some(Word::new(vec![WordPart::Unknown]));
        entry.word_condition = None;
        entry.node = None;
        entry.antecedents.push(source);
        entry.producers.clear();
        entry.producers_condition = None;
        entry.earlier_producers.clear();
        entry.script_set = true;
        entry.script_may_set = true;
        entry.saturation_key =
            variable_saturation_key(None, &entry.may, entry.word.as_ref(), true, false);
    }
}

/// A command name in head position that runs, dispatches, or wraps another
/// program, or a reserved word that leaves the head ahead. A transform after
/// one of these is not proven to be a plain data argument.
/// A command head proven to consume its operands as data, never dispatching
/// or interpreting another program from them. Suppressing the hidden-program
/// fact needs positive evidence like this; absence from a blacklist does not
/// establish it for an arbitrary function, interpreter, or executable path.
fn consumes_operands_as_data(name: &str) -> bool {
    // `printf` is excluded: `printf -v NAME` evaluates an arithmetic subscript
    // in NAME, which can run a command substitution the recovered source hides.
    matches!(name, "echo" | ":" | "true" | "false")
}

/// Whether a word carries a segment that runs or may run code (a command or
/// process substitution, or a parameter expansion whose word hides one).
fn word_executes_code(word: &WordTok) -> bool {
    word.segs.iter().any(|seg| {
        matches!(
            seg,
            Seg::CommandSub { .. }
                | Seg::ProcSub { .. }
                // Arithmetic expansion evaluates its operands, so a nested
                // command substitution inside `$(( ))` runs; the engine does
                // not recover it, so treat any arithmetic segment as executing.
                | Seg::Arith { .. }
                | Seg::UnwalkedParamSub
                | Seg::Param {
                    unwalked_substitution: true,
                    ..
                }
        )
    })
}

/// Whether the transformed span at `range` of a recovered `eval` source is
/// proven to supply only data arguments, so its hidden output is not, and does
/// not launch, the program `eval` runs. The burden is on proving safety: the
/// span must sit after a head that is a proven data-consuming command (not a
/// function, alias, assignment, redirection target, or arbitrary program), and
/// the transformed words themselves must carry no command/process substitution
/// or other code-executing expansion. Active syntax is judged from the lexer's
/// quote state, so quoted punctuation in a data argument is not mistaken for a
/// separator.
fn transform_is_pure_argument(env: &ShellEnv, source: &str, range: std::ops::Range<usize>) -> bool {
    if range.is_empty() {
        return false;
    }
    let lexed = lex::lex(source);
    if lexed.error.is_some() {
        return false;
    }
    let mut have_head = false;
    for tok in &lexed.toks {
        match tok {
            // A command operator could start a new command whose head is the
            // transform, or is active syntax the transform itself reaches.
            Tok::Op(..) => return false,
            // A redirection shifts the head, and its target is lexed as an
            // ordinary word, so a proof over source tokens is not available.
            Tok::Redir { .. } => return false,
            Tok::Word(word) if !have_head => {
                let Some(name) = parse::literal_text(word) else {
                    return false;
                };
                // Only a proven data-consuming head, not shadowed by a function
                // or alias, keeps the transform a data argument.
                if !consumes_operands_as_data(&name)
                    || parse::split_assignment(word).is_some()
                    || env.functions.contains_key(&name)
                    || env.function_alternatives.contains_key(&name)
                {
                    return false;
                }
                if env.expand_aliases
                    && (env.aliases.contains_key(&name)
                        || env.alias_alternatives.contains_key(&name))
                {
                    return false;
                }
                let span = word.span.start as usize..word.span.end as usize;
                // The transform must be an argument, not the head itself.
                if span.start < range.end && range.start < span.end {
                    return false;
                }
                have_head = true;
            }
            // A transformed argument word that itself carries a substitution
            // supplies execution, not data.
            Tok::Word(word) => {
                let span = word.span.start as usize..word.span.end as usize;
                if span.start < range.end && range.start < span.end && word_executes_code(word) {
                    return false;
                }
            }
        }
    }
    have_head
}
