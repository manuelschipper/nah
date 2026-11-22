//! The shell `source` (`.`) and `eval` builtins: which file or text they run,
//! how it is followed, and what an unfollowed source leaves unknown.

use std::collections::BTreeSet;
use std::rc::Rc;

use effinterp_proto::{
    AttrValue, BoundaryClass, BoundaryReason, CoverageLevel, Domain, Effect, ExecutionNodeRef,
    Modality, Operation, Port, ProvenanceKind, ProvenanceRef, ResourceExpr, ResourceIdentity,
    Subject,
};

use crate::builder::{PlanBuilder, ScriptInterpreter, SourceAuthorship};
use crate::flow::{BindEnd, Descriptor, FlowRef, FlowStage, PortBinding};
use crate::models::StdinValue;
use crate::nest::{SourceResolution, Transition};
use crate::paths::{join_source_path, process_identity_with_cwd};
use crate::shell::captured_file::substitution_capture;
use crate::shell::lex::{Seg, ShellSpan, Tok, WordTok};
use crate::shell::parse::{ShellItem, Simple};
use crate::shell::saturation_memos::variable_saturation_key;
use crate::shell::shell_env::ShellEnv;
use crate::shell::{Converted, Shell, Termination, analyze_shell_with_env, lex, parse};
use crate::word::{Word, WordPart};
use crate::{SourcePurpose, SourceRefusal};

use super::command_substitution::spelled_text;
use super::conditional_shell_state::ConditionalShellState;
use super::nested_shell_source::NestedShellMode;
use super::obfuscated_command::substitution_hides_name;
use super::redirection::{descriptor_path, descriptor_read_producer};
use super::variable_binding::captured_literal;

impl Shell<'_> {
    /// Run the body of the special builtin `cmd` (`eval`, `source`) with its
    /// prefix assignments bound. Bash expands them, with any writes their
    /// substitutions make, before the body runs and must be visible while it
    /// runs; it restores those names afterwards, while mutations to other
    /// names made by the body persist.
    pub(super) fn with_prefix_bindings<T>(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        cmd: &Simple,
        conditional: bool,
        guarded: bool,
        body: impl FnOnce(&mut PlanBuilder, &mut ShellEnv) -> T,
    ) -> T {
        let mut prior_bindings = Vec::new();
        for (index, assignment) in cmd.assignments.iter().enumerate() {
            if !cmd.assignments[..index]
                .iter()
                .any(|prior| prior.name == assignment.name)
            {
                prior_bindings.push((
                    assignment.name.clone(),
                    env.vars.get(&assignment.name).cloned(),
                    env.arrays.get(&assignment.name).cloned(),
                    env.exported.contains(&assignment.name),
                    env.unexported.contains(&assignment.name),
                    env.unset.contains(&assignment.name),
                    env.unexported_nodes.get(&assignment.name).copied(),
                ));
            }
            self.assign(builder, env, assignment, conditional, guarded);
            env.exported.insert(assignment.name.clone());
            env.unexported.remove(&assignment.name);
            env.unset.remove(&assignment.name);
            env.unexported_nodes.remove(&assignment.name);
        }
        let result = body(builder, env);
        for (name, variable, array, exported, unexported, unset, unexported_node) in prior_bindings
        {
            match variable {
                Some(variable) => {
                    env.vars.insert(name.clone(), variable);
                }
                None => {
                    env.vars.remove(&name);
                }
            }
            match array {
                Some(array) => {
                    env.arrays.insert(name.clone(), array);
                }
                None => {
                    env.arrays.remove(&name);
                }
            }
            if exported {
                env.exported.insert(name.clone());
            } else {
                env.exported.remove(&name);
            }
            if unexported {
                env.unexported.insert(name.clone());
            } else {
                env.unexported.remove(&name);
            }
            if unset {
                env.unset.insert(name.clone());
            } else {
                env.unset.remove(&name);
            }
            match unexported_node {
                Some(node) => {
                    env.unexported_nodes.insert(name, node);
                }
                None => {
                    env.unexported_nodes.remove(&name);
                }
            }
        }
        result
    }

    /// Run sourced code in this shell with the arguments `source FILE ARGS...`
    /// supplies as its positional parameters. They are restored afterwards
    /// unless `set` replaces the list outside a function; the changed flag is
    /// shell-wide, not saved by nested calls. Without arguments the sourced
    /// code shares the caller's list.
    fn with_sourced_arguments<T>(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        args: Option<Vec<Converted>>,
        span: ShellSpan,
        body: impl FnOnce(&mut PlanBuilder, &mut ShellEnv) -> T,
    ) -> T {
        let saved = args.map(|args| env.positional.replace(args));
        let saved_revision = env.positional_discard_revision;
        env.positional_set_changed = Some(false);
        let result = body(builder, env);
        if let Some(saved) = saved {
            if env.positional_set_changed.is_none() && env.active.is_empty() {
                env.positional = None;
                env.positional_discard_revision += 1;
                self.opaque_boundary(
                    builder,
                    BoundaryReason::UNSUPPORTED_SHELL_SYNTAX,
                    BoundaryClass::Unsupported,
                    "conditional call may reset sourced positional restoration",
                    span,
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
                    span,
                );
            }
            env.positional_set_changed = Some(false);
        }
        result
    }

    /// Run source bytes recovered from a descriptor or stdin as `source` runs
    /// a file: in this shell, or in a child outside it, with the call's
    /// trailing arguments as the positional parameters.
    fn source_recovered(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        converted: &[Converted],
        content: (&str, SourceAuthorship),
        span: ShellSpan,
        persist: bool,
    ) {
        let (content, authorship) = content;
        let args = (converted.len() > 2).then(|| converted[2..].to_vec());
        if persist {
            self.with_sourced_arguments(builder, env, args, span, |builder, env| {
                self.nested_shell_source(
                    builder,
                    env,
                    content,
                    span,
                    NestedShellMode::Persist,
                    Some(authorship),
                );
            });
        } else {
            // The child takes the caller's list; the caller's own stays as it was.
            let caller = args.map(|args| env.positional.replace(args));
            self.nested_shell_source(
                builder,
                env,
                content,
                span,
                NestedShellMode::Child,
                Some(authorship),
            );
            if let Some(caller) = caller {
                env.positional = caller;
            }
        }
    }

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
        let mut observed_captures = Vec::new();
        let mut captured_authorship = None;
        let mut authored = true;
        let source_words = converted[source_start..]
            .iter()
            .map(|word| {
                let tok = cmd.words.iter().find(|tok| tok.span == word.span);
                if let Some(text) = captured_literal(&word.word) {
                    authored &= tok.is_some_and(|tok| {
                        let site = self.span_node(builder, tok.span);
                        builder.source_from_subject(Some(site)) && (
                        spelled_text(tok).is_some() || matches!(tok.segs.as_slice(), [Seg::CommandSub { source, quoted, .. }]
                            if !substitution_hides_name(source, *quoted)))
                    });
                    Some(text)
                } else {
                    let [
                        Seg::CommandSub {
                            source,
                            quoted: true,
                            ..
                        },
                    ] = tok?.segs.as_slice()
                    else {
                        return None;
                    };
                    // Bash expands every word before eval runs any of them.
                    let (source, authorship) =
                        substitution_capture(env, source, word.expanded_writes?)?
                            .text_with_origin(self.nest, builder)?;
                    authored &= authorship.is_subject();
                    if converted.len() == source_start + 1 {
                        captured_authorship = Some(authorship);
                    }
                    observed_captures.push(word.span);
                    Some(source)
                }
            })
            .collect::<Option<Vec<_>>>();
        let source = source_words.as_ref().map(|words| words.join(" "));
        match source {
            Some(source) if !source.is_empty() => {
                builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);
                // Text a transform (`tr`, `rev`) prints is code the reader
                // cannot see. The burden is on proving it supplies only data
                // arguments; anything the recovered structure cannot rule out
                // (a dispatcher or non-literal head, a redirection, a command
                // operator, or an alias-expanded head) keeps the fact.
                let mut offset = 0;
                for (word, text) in converted[source_start..]
                    .iter()
                    .zip(source_words.as_ref().unwrap())
                {
                    let len = text.len();
                    let transformed = !observed_captures.contains(&word.span) && cmd.words.iter().any(|tok| {
                        tok.span == word.span
                            && matches!(tok.segs.as_slice(), [Seg::CommandSub { source, quoted, .. }]
                                if substitution_hides_name(source, *quoted))
                    });
                    if transformed
                        && !transform_is_pure_argument(env, &source, offset..offset + len)
                    {
                        self.emit_hidden_program_effect(builder, env, word.span, None);
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
                    Some(captured_authorship.unwrap_or_else(|| authored.into())),
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
            self.source_recovered(
                builder,
                env,
                converted,
                (&content, SourceAuthorship::External),
                target.span,
                persist,
            );
            return None;
        }
        // `source <(cat FILE)` reads what the substitution prints: FILE's bytes.
        // The `cat` runs beside the rest of the command, so a write the
        // command makes to FILE after starting it, such as a prefix
        // assignment's, races its read: what is sourced is not known.
        if descriptor_path(&target.word, env).is_some()
            && let Some(raw) = self
                .source
                .get(target.span.start as usize..target.span.end as usize)
            && let lexed = lex::lex(raw)
            && lexed.error.is_none()
            && let [Tok::Word(word)] = lexed.toks.as_slice()
            && let [Seg::ProcSub { .. }] = word.segs.as_slice()
            && let Some(inner) = raw.strip_prefix("<(").and_then(|raw| raw.strip_suffix(')'))
            && let Some(mark) = target.expanded_writes
            && let Some(capture) = substitution_capture(env, inner, mark)
        {
            if capture.written_in(self.nest, builder, mark..builder.source_write_count()) {
                builder.note_unpinned_source();
            } else if let Some((content, authorship)) = capture.script_text(self.nest, builder) {
                self.source_recovered(
                    builder,
                    env,
                    converted,
                    (&content, authorship),
                    target.span,
                    persist,
                );
                return None;
            }
        }
        // `source /dev/stdin` reads this command's standard input, so known
        // piped or here-string bytes, or the file redirected to it, are the
        // sourced text.
        if (target.word.as_literal() == Some("/dev/stdin")
            || descriptor_path(&target.word, env) == Some(Descriptor::Number(0)))
            && let Some((content, authorship)) = stdin.and_then(|stdin| {
                stdin.script_text(self.nest, builder, |builder, file| {
                    match self.nest.resolve_source_file(
                        builder,
                        file.as_literal()?,
                        SourcePurpose::InvocationInput,
                        "shell",
                    ) {
                        SourceResolution::Source { source, origin } => {
                            Some((source, self.nest.source_authorship(&origin)))
                        }
                        _ => None,
                    }
                })
            })
        {
            self.source_recovered(
                builder,
                env,
                converted,
                (&content, authorship),
                target.span,
                persist,
            );
            return None;
        }
        // Invoked scripts resolve source operands against the runtime cwd.
        let source_cwd = if env.source_uses_runtime_cwd {
            env.runtime_cwd.as_deref()
        } else {
            env.source_cwd.as_deref()
        }
        .map(str::to_string);
        let literal_path = target
            .word
            .as_literal()
            .and_then(|spec| join_source_path(source_cwd.as_deref(), spec).map(|(_, path)| path));
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
        // A source operand without a slash is searched for; an empty one
        // names no file to search for.
        let mut literal_path = literal_path;
        if let Some(spec) = target
            .word
            .as_literal()
            .filter(|spec| !spec.is_empty() && !spec.contains('/'))
        {
            match self.searched_source(
                builder,
                env,
                converted[0].word.as_literal() == Some("source"),
                spec,
                literal_path.as_deref(),
                target.span,
            ) {
                Some(SearchedSource::Path(path)) => literal_path = Some(path),
                Some(SearchedSource::Cwd) => {}
                None => {
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
                    invalidate_unobserved_source_variables(
                        env,
                        self.span_node(builder, target.span),
                    );
                    return None;
                }
            }
        }
        let mut inventory_unavailable = false;
        let paths = if target.word.as_literal().is_some() {
            literal_path.map(|path| vec![path])
        } else if self.nest.resolver.is_some() {
            crate::SourcePattern::from_word(&target.word, source_cwd.as_deref()).and_then(
                |pattern| {
                    let matches = self.nest.resolver?.matching(&pattern);
                    inventory_unavailable = matches.is_none();
                    matches
                },
            )
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
        // A file that only assigns variables leaves the positional parameters
        // alone, and what it assigned stays tied to its read.
        let only_assigned = paths
            .iter()
            .all(|path| assignments_read(builder, path).is_some());
        // One file walked once ran exactly under the condition here.
        let ran_under = (condition_arms == 1)
            .then(|| builder.current_condition())
            .flatten();
        if let Some(state) = state {
            state.merge(env, only_assigned, ran_under);
        }
        if persist && (conditional || has_union(&target.word)) && !only_assigned {
            if env.positional_set_changed != positional_set_changed {
                env.positional_set_changed = None;
            }
            // A path that skips the file keeps the caller's list. When every
            // walked file left that list as it found it, both paths agree.
            fn words(positionals: &Option<Vec<Converted>>) -> Option<Vec<&Word>> {
                positionals
                    .as_ref()
                    .map(|args| args.iter().map(|arg| &arg.word).collect())
            }
            if words(&env.positional) != words(&positional)
                || env.positional_discard_revision != positional_discard_revision
            {
                env.positional = None;
                self.opaque_boundary(
                    builder,
                    BoundaryReason::UNSUPPORTED_SHELL_SYNTAX,
                    BoundaryClass::Unsupported,
                    "conditional source may change positional parameters",
                    target.span,
                );
            }
        }
        termination.filter(|_| all_terminate)
    }

    /// Which file `source NAME` or `. NAME` reads for a NAME without a
    /// slash. Bash searches PATH and then the cwd; zsh's `source` the cwd and
    /// then PATH; zsh's `.` and POSIX shells PATH alone. Each candidate is
    /// the host's answer, in order; `None` when the host, or a shell Nah
    /// cannot name, leaves the choice open. `cwd_path` is NAME in the cwd.
    fn searched_source(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        source_builtin: bool,
        spec: &str,
        cwd_path: Option<&str>,
        span: ShellSpan,
    ) -> Option<SearchedSource> {
        let node = self.span_node(builder, span);
        let interpreter = builder.script_interpreter();
        let bash = matches!(
            interpreter,
            ScriptInterpreter::Root | ScriptInterpreter::Program("bash")
        );
        // Bash's search under options the script changed, or under the
        // POSIX mode `POSIXLY_CORRECT` turns on, is not read.
        if bash
            && (env.source_search_changed
                || env
                    .vars
                    .get("POSIXLY_CORRECT")
                    .is_some_and(|entry| entry.script_set || entry.script_may_set))
        {
            return None;
        }
        let zsh = interpreter == ScriptInterpreter::Program("zsh");
        // A shell Nah cannot name, such as a runtime's: a choice stands only
        // where bash and zsh agree.
        let either = interpreter == ScriptInterpreter::Unresolved;
        let cwd_first = source_builtin && (zsh || either);
        if zsh && cwd_first && self.source_candidate_exists(builder, cwd_path?, node)? {
            return Some(SearchedSource::Cwd);
        }
        // The search reads PATH, which also asks the host for its value.
        self.env_read(builder, env, "PATH", span);
        let path_value = match env.vars.get("PATH") {
            // A literal the script assigned or the host reported.
            Some(entry) if entry.value.is_some() && (entry.script_set || !entry.script_may_set) => {
                entry.value.clone()
            }
            // The script may have set a value the walk cannot spell.
            Some(entry) if entry.script_set || entry.script_may_set => return None,
            // A PATH the host has not reported leaves a launched script's
            // search open. The call's own command takes it to hold no such
            // file, as its command search does.
            _ if env.source_uses_runtime_cwd => return None,
            _ => None,
        };
        let mut found = None;
        for entry in path_value.iter().flat_map(|value| value.split(':')) {
            let entry = if entry.is_empty() { "." } else { entry };
            let candidate = crate::paths::join_file(
                env.cwd.as_deref(),
                &format!("{}/{spec}", entry.trim_end_matches('/')),
            )
            .filter(|path| path.starts_with('/'))?;
            if self.source_candidate_exists(builder, &candidate, node)? {
                found = Some(candidate);
                break;
            }
        }
        match found {
            // Bash and zsh agree unless the cwd also holds NAME, which zsh's
            // `source` reads first.
            Some(path) if either && cwd_first => (!self
                .source_candidate_exists(builder, cwd_path?, node)?)
            .then_some(SearchedSource::Path(path)),
            Some(path) => Some(SearchedSource::Path(path)),
            None => (bash || cwd_first).then_some(SearchedSource::Cwd),
        }
    }

    /// Whether the host shows a file at `path` that a source search takes.
    /// `None` when it does not answer, the plan changed the path, or it is
    /// something other than a file or nothing.
    fn source_candidate_exists(
        &self,
        builder: &mut PlanBuilder,
        path: &str,
        node: ProvenanceRef,
    ) -> Option<bool> {
        use effinterp_proto::{Fact, ObservationOutcome, ObservationQuery, PathKind};
        if !path.starts_with('/')
            || !builder.is_host_realm()
            || builder.budget().observations.is_none()
            || !matches!(
                builder.written_source(path, |resource, path| {
                    self.nest.source_mutation_may_alias(resource, path)
                }),
                crate::builder::WrittenSource::Host
            )
        {
            return None;
        }
        let outcome = builder.budget().observe_path(path);
        let ObservationOutcome::Path(fact) = &outcome else {
            return None;
        };
        let exists = match (fact.kind, &fact.followed) {
            (PathKind::File, _) => true,
            (PathKind::Missing, _) => false,
            (PathKind::Symlink, Fact::Known(target)) => match target.kind {
                Fact::Known(PathKind::File) => true,
                Fact::Known(PathKind::Missing) => false,
                _ => return None,
            },
            _ => return None,
        };
        // The plan records the host fact the selection rests on.
        builder.node(
            ProvenanceKind::HostObservation {
                query: ObservationQuery::Path {
                    path: path.to_string(),
                },
                outcome,
            },
            &[node],
        );
        Some(exists)
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
                input.input.assurance = effinterp_proto::ExecutionAssurance::Alternatives;
                input.input.selection = effinterp_proto::ExecutionSelection::Search {
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
        let begun = builder.effects_len();
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
        // A traced shell reports each assignment it runs, value and all, and
        // a trap's action may expand what the file assigns.
        let only_assigns =
            persist && !env.observes_later_bindings && only_assigns_variables(env, &source);
        let assigned = sourced_assignments(builder, begun, path, node, only_assigns);
        let previous_assigned = std::mem::replace(&mut env.sourced_assignments, assigned);
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
            self.with_sourced_arguments(builder, env, args, target.span, |builder, env| {
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
                termination
            })
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
        env.sourced_assignments = previous_assigned;
        frame.end(builder);
        termination
            .map(|(kind, _)| kind)
            .filter(|kind| *kind != Termination::Return)
    }
}

/// Whether a sourced file does nothing but bind variables: every statement
/// is a plain `NAME=value` or an `export NAME=value`, as a dotenv file is
/// written. Such a file's bytes go into the variables it sets and nowhere
/// else. A value that runs a substitution, an array, a redirection, or any
/// other command is not one, and neither is `export` once a function or an
/// alias may stand in for it.
fn only_assigns_variables(env: &ShellEnv, source: &str) -> bool {
    let lexed = lex::lex(source);
    if lexed.error.is_some()
        || env.functions.contains_key("export")
        || env.function_alternatives.contains_key("export")
        || env.aliases.contains_key("export")
        || env.alias_alternatives.contains_key("export")
    {
        return false;
    }
    let binds = |word: &WordTok| {
        !word_executes_code(word)
            && !word
                .segs
                .iter()
                .any(|seg| matches!(seg, Seg::ArrayLit { .. }))
    };
    parse::parse_shell_items(&lexed.toks, source.len() as u32)
        .iter()
        .all(|item| {
            let ShellItem::Pipeline {
                cmds,
                conditional: false,
                ..
            } = item
            else {
                return false;
            };
            let [cmd] = cmds.as_slice() else {
                return false;
            };
            if !cmd.redirs.is_empty() || !cmd.assignments.iter().all(|assign| binds(&assign.value))
            {
                return false;
            }
            match cmd.words.as_slice() {
                [] => !cmd.assignments.is_empty(),
                [head, operands @ ..] => {
                    cmd.assignments.is_empty()
                        && parse::literal_text(head).as_deref() == Some("export")
                        && !operands.is_empty()
                        && operands.iter().all(|operand| {
                            binds(operand) && parse::split_assignment(operand).is_some()
                        })
                }
            }
        })
}

/// The attribute a sourced file's read carries when the file only assigns
/// variables: `unexpanded` until a word expands one of them or a launched
/// command may read them back, `expanded` from then on.
const SOURCED_ASSIGNMENTS: &str = "sourced_assignments";

/// The read of `path` that carries [`SOURCED_ASSIGNMENTS`].
fn assignments_read(builder: &PlanBuilder, path: &str) -> Option<u32> {
    (0..builder.effects_len())
        .find(|effect| {
            builder
                .effect_string_attribute(*effect, SOURCED_ASSIGNMENTS)
                .is_some()
                && matches!(
                    builder.effect_resource(*effect),
                    Some(ResourceExpr::Concrete {
                        identity: ResourceIdentity::FsPath { path: read },
                    }) if read == path
                )
        })
        .map(|effect| effect as u32)
}

/// State on the read `source` recorded for `path` since `begun` whether the
/// file only assigns variables (`only_assigns`), and return the pending flow
/// value that carries the read's bytes into each variable the file binds.
/// A file sourced again records no second read: it keeps what the first
/// stated, unless its text now does more than assign.
pub(super) fn sourced_assignments(
    builder: &mut PlanBuilder,
    begun: usize,
    path: &str,
    node: ProvenanceRef,
    only_assigns: bool,
) -> Option<FlowRef> {
    let fresh = (begun..builder.effects_len())
        .find(|effect| builder.effect_operation(*effect) == Some("filesystem.read"));
    let read = match fresh {
        Some(read) if only_assigns => {
            builder.set_effect_string_attribute(read, SOURCED_ASSIGNMENTS, "unexpanded");
            read as u32
        }
        Some(_) => return None,
        None => {
            let read = assignments_read(builder, path)?;
            if !only_assigns {
                builder.set_effect_string_attribute(read as usize, SOURCED_ASSIGNMENTS, "expanded");
                return None;
            }
            read
        }
    };
    let stage = builder.pending_flow_stage(FlowStage {
        execution: None,
        effects: vec![read],
        bindings: vec![PortBinding {
            assurance: effinterp_proto::CausalAssurance::Conservative,
            from: BindEnd::Effect(read),
            to: BindEnd::Port(Port::Value),
        }],
        provenance: vec![node],
    });
    Some(FlowRef {
        stage: stage as u32,
        port: Port::Value,
    })
}

/// State that a word expanded a variable a sourced file assigned: one of
/// `producers` carries that file's read. Where the expanded value goes is not
/// followed here, so the read records only that its bytes were taken out of
/// the variable.
pub(in crate::shell) fn note_expanded_assignments(
    builder: &mut PlanBuilder,
    producers: &[FlowRef],
) {
    for producer in producers {
        for effect in builder.pending_flow_stage_effects(producer.stage).to_vec() {
            if builder
                .effect_string_attribute(effect as usize, SOURCED_ASSIGNMENTS)
                .is_some()
            {
                builder.set_effect_string_attribute(
                    effect as usize,
                    SOURCED_ASSIGNMENTS,
                    "expanded",
                );
            }
        }
    }
}

/// State that every variable a sourced file assigned so far may be expanded
/// by something the walk does not follow.
pub(super) fn expand_sourced_assignments(builder: &mut PlanBuilder) {
    for effect in 0..builder.effects_len() {
        if builder
            .effect_string_attribute(effect, SOURCED_ASSIGNMENTS)
            .is_some()
        {
            builder.set_effect_string_attribute(effect, SOURCED_ASSIGNMENTS, "expanded");
        }
    }
}

/// State on the files sourced before a launched command whether that
/// command may read their variables back. The command stated the effects
/// from `begun` on.
///
/// A launched process holds every exported variable, and a variable a file
/// assigned may have been exported before this shell started. What a process
/// does with its environment is followed for few programs, so a process
/// leaves the files unexpanded only when its model establishes that it does
/// not print its environment (`ls`), or it runs code from a file
/// (`node dist/index.js`, or `npm start` where the manifest was read and its
/// script does the same). A stored program carries no reader in the command
/// itself, and loading a dotenv file for such a program is what the file is
/// for. Every other command is taken to read
/// the variables back, whether it carries the code that does (`node -e`,
/// `awk 'BEGIN{print ENVIRON["K"]}'`), prints environments (`ps e`,
/// `cat /proc/self/environ`) or has unknown environment behavior.
pub(super) fn note_launched_command(builder: &mut PlanBuilder, begun: usize) {
    let stated = |operation: &str| {
        (begun..builder.effects_len())
            .filter(|effect| builder.effect_operation(*effect) == Some(operation))
            .collect::<Vec<_>>()
    };
    let code = stated("process.code_execution");
    let launches = stated("process.exec");
    let keeps_assignments = !launches.is_empty()
        && launches
            .iter()
            .filter(|effect| {
                builder.effect_string_attribute(**effect, "environment_output") != Some("none")
            })
            .count()
            == code.len()
        && code
            .iter()
            .all(|effect| builder.effect_string_attribute(*effect, "source") == Some("file"));
    if !keeps_assignments {
        for effect in 0..begun {
            if builder
                .effect_string_attribute(effect, SOURCED_ASSIGNMENTS)
                .is_some()
            {
                builder.set_effect_string_attribute(effect, SOURCED_ASSIGNMENTS, "expanded");
            }
        }
    }
}

/// The file a source search for a name without a slash selects.
enum SearchedSource {
    /// A PATH directory's file.
    Path(String),
    /// The name in the cwd.
    Cwd,
}

fn invalidate_unobserved_source_variables(env: &mut ShellEnv, source: ProvenanceRef) {
    // The unread file may also run `set` or `shift`.
    env.positional = None;
    env.positional_set_changed = None;
    env.unset.clear();
    env.unread_source = true;
    for (name, entry) in &mut env.vars {
        if env.readonly.contains(name) {
            continue;
        }
        entry.value = None;
        entry.conditional_literal = None;
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
