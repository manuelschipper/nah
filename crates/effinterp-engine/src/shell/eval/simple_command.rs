//! Simple command: one command's prefix assignments, word expansion,
//! redirections and head resolution, up to the argv that `dispatch_argv` runs,
//! and the flow stage the command contributes.

use std::collections::HashMap;
use std::rc::Rc;

use effinterp_proto::{
    BoundaryClass, BoundaryReason, Effect, ExecutionNodeRef, Modality, Operation, ResourceExpr,
    ResourceIdentity,
};

use crate::builder::PlanBuilder;
use crate::control_flow::{ControlFact, SiteFacts};
use crate::flow::Descriptor;
use crate::models::StdinValue;
use crate::shell::lex::{ExpansionBudget, RedirKind, Seg, ShellDupTarget, WordTok};
use crate::shell::parse::Simple;
use crate::shell::shell_env::{ArrayValue, ShellEnv};
use crate::shell::{
    Converted, MAX_ARGV_VARIANTS, MAX_SATURATED_FUNCTION_STEPS, Redirects, Shell, StageOutcome,
    WordExpansion, lex, parse,
};
use crate::word::{Word, WordPart};

use super::command_substitution::one_word_quoted_expansion;
use super::redirection::{
    descriptor_path, predict_descriptor_output, predict_redirected_output, predict_tee_output,
    redirected_descriptors, redirected_file,
};
use super::variable_binding::bind_var;
use super::word_expansion::{effective_ifs, ifs_joined_fields};
use super::{assigns_default, command_wrapper_operand, exec_operands, literal_output};

/// `literal_output` for a stage whose `echo` or `printf` arguments may hold
/// text the shell supplies, kept as unknown parts of the output.
fn literal_output_word(
    name: Option<&str>,
    converted: &[Converted],
    stdin: Option<&StdinValue>,
    max_bytes: u64,
) -> Option<Word> {
    let args = converted
        .get(1..)?
        .iter()
        .map(|word| &word.word)
        .collect::<Vec<_>>();
    literal_output::render_words(
        name,
        &args,
        stdin.and_then(|stdin| stdin.word.as_literal()),
        max_bytes,
    )
}

impl Shell<'_> {
    /// `conditional` marks a command that runs only on some paths (a
    /// `&&`/`||` operand, or anything inside a may-region); `guarded` marks
    /// only the former, where even a read later in the same region cannot
    /// count on the command having run.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::shell) fn eval_simple_command(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        cmd: &Simple,
        persist: bool,
        conditional: bool,
        guarded: bool,
        piped_stdin: Option<StdinValue>,
        stdout_consumed: bool,
    ) -> StageOutcome {
        let initial_effect_start = builder.effects_len();
        // A compound command's redirections stay open for its body, which
        // the walker runs next and then restores.
        let persist_fds = persist
            && (cmd.compound_redirects
                || cmd.words.len() == 1
                    && parse::command_name_text(&cmd.words[0]).as_deref() == Some("exec"));
        // The command name is the literal head word after quote removal; taken
        // from the token (not the converted word) so a glob-like name such as
        // `[` is matched.
        let mut name = cmd.words.first().and_then(parse::command_name_text);
        if name
            .as_ref()
            .is_some_and(|name| env.functions.contains_key(name))
            && self.structural_saturated(builder, env)
        {
            let memos = env.saturation_memos.borrow();
            let function_exhausted = memos.function_steps >= MAX_SATURATED_FUNCTION_STEPS;
            let remaining_args =
                MAX_SATURATED_FUNCTION_STEPS.saturating_sub(memos.function_arg_steps);
            drop(memos);
            let mut variants: usize = 1;
            let mut args_work = 0usize;
            for tok in &cmd.words[1..] {
                let token_work = match tok.segs.as_slice() {
                    [Seg::AllArgs { .. }] if env.positional.is_some() => {
                        env.positional.as_ref().unwrap().len()
                    }
                    [Seg::ArrayAll { name, .. }] => {
                        let candidates: &[Vec<Converted>] = env
                            .arrays
                            .get(name)
                            .map(ArrayValue::candidates)
                            .unwrap_or_default();
                        if candidates.is_empty()
                            || variants.saturating_mul(candidates.len()) > MAX_ARGV_VARIANTS
                        {
                            1
                        } else {
                            variants *= candidates.len();
                            candidates.iter().map(Vec::len).max().unwrap_or_default()
                        }
                    }
                    _ => 1,
                };
                args_work = args_work.saturating_add(token_work);
            }
            args_work = args_work.saturating_sub(1);
            // Reject a wide call before expanding it, but leave unused work
            // available for later cheap function-composed command heads.
            if function_exhausted || args_work > remaining_args {
                return StageOutcome {
                    terminates: None,
                    execution: None,
                    words: name.iter().cloned().map(Word::literal).collect(),
                    argument_producers: Vec::new(),
                    stdin_producers: Vec::new(),
                    unestablished: false,
                    unquoted_substitutions: Vec::new(),
                    name,
                    model_eligible: false,
                    stdin: None,
                    stdout: None,
                    redirs: Redirects::default(),
                };
            }
        }

        // Candidate argv lists: usually one; an ambiguous array splice in the
        // words yields one per possible value.
        let command_redirects = std::mem::replace(
            &mut env.command_redirects,
            redirected_descriptors(&cmd.redirs),
        );
        let WordExpansion {
            mut variants,
            overflowed,
            first_retained_token,
        } = self.expand_words(
            builder,
            env,
            &cmd.words,
            name.as_deref() != Some("[["),
            true,
        );
        env.command_redirects = command_redirects;
        if persist {
            for converted in variants.iter_mut().flatten() {
                self.apply_pending_assigns(builder, env, converted, conditional, guarded);
            }
        }
        // A word spelled from literal text and exactly captured literal output
        // is that text, as `$(printf rm) -rf /` runs `rm` and `git
        // re$(printf set) --hard` runs `git reset --hard`.
        for converted in variants.iter_mut().flatten() {
            if converted.word.as_literal().is_none()
                && let Some(text) = captured_literal_text(&converted.word)
            {
                converted.word = Word::literal(text.clone());
                converted.raw = text;
            }
        }
        // Bash keeps what a `:=` default inside a prefix assignment's value
        // assigns, though the prefix binding itself lasts only for the command.
        if persist
            && variants.iter().any(|variant| !variant.is_empty())
            && cmd
                .assignments
                .iter()
                .any(|assignment| assigns_default(&assignment.value))
        {
            let mut prefix = env.clone();
            let mut defaults = Vec::new();
            for assignment in &cmd.assignments {
                let mut value = self.convert(builder, &mut prefix, &assignment.value, false, true);
                defaults.push(value.clone());
                self.apply_pending_assigns(builder, &mut prefix, &mut value, conditional, guarded);
                bind_var(
                    builder,
                    &mut prefix,
                    assignment.name.clone(),
                    value.word.as_literal().map(str::to_string),
                    conditional,
                    guarded,
                    assignment.span,
                    value.assign_nodes,
                    value.producers,
                );
            }
            for mut value in defaults {
                self.apply_pending_assigns(builder, env, &mut value, conditional, guarded);
            }
        }
        if overflowed && self.nest.limits.max_shell_words == 0 {
            name = None;
        }
        let mut stdin = piped_stdin;
        // Pending values a here-document or here-string feeds to stdin; a
        // program that runs its stdin as code runs their bytes.
        let mut stdin_producers = Vec::new();
        // Inline bytes per redirection, so `exec` can keep them open on the
        // descriptor the redirection names.
        let mut here_contents: HashMap<usize, Word> = HashMap::new();
        // Bash expands a null command's here-bodies without keeping the
        // assignments they make; a command's or a current-shell compound
        // command's here-bodies keep them.
        let assigns = persist
            && (cmd.compound_redirects || variants.iter().any(|variant| !variant.is_empty()));
        for (redir_index, redir) in cmd.redirs.iter().enumerate() {
            let fd = redir.fd.unwrap_or(0);
            match redir.kind {
                RedirKind::HereDoc => {
                    let Some(heredoc) = &redir.heredoc else {
                        continue;
                    };
                    let mut expansion_budget = ExpansionBudget {
                        remaining: self.nest.budget.heredoc_expansions_remaining(),
                    };
                    let available = expansion_budget.remaining;
                    let (token, truncated) =
                        lex::lex_heredoc_body(self.source, heredoc, &mut expansion_budget);
                    for _ in 0..available - expansion_budget.remaining {
                        let charged = self.nest.budget.try_charge_heredoc_expansion();
                        debug_assert!(charged);
                    }
                    let mut converted = self.convert(builder, env, &token, false, true);
                    if assigns {
                        self.apply_pending_assigns(
                            builder,
                            env,
                            &mut converted,
                            conditional,
                            guarded,
                        );
                    }
                    if truncated {
                        converted.word.parts.push(WordPart::Unknown);
                        builder.note_saturated("max_heredoc_expansions");
                    }
                    if fd == 0 && redir.named_fd.is_none() {
                        stdin_producers = converted.producers;
                        let mut provenance = vec![self.span_node(builder, heredoc.body_span)];
                        provenance.extend(converted.assign_nodes);
                        stdin = Some(StdinValue {
                            paths: None,
                            piped: false,
                            file: None,
                            word: converted.word,
                            provenance,
                        });
                    } else {
                        here_contents.insert(redir_index, converted.word);
                    }
                }
                RedirKind::HereString => {
                    if let Some(target) = &redir.target {
                        let mut converted = self.convert(builder, env, target, false, true);
                        if assigns {
                            self.apply_pending_assigns(
                                builder,
                                env,
                                &mut converted,
                                conditional,
                                guarded,
                            );
                        }
                        match converted.word.parts.last_mut() {
                            Some(WordPart::Literal(literal)) => literal.push('\n'),
                            _ => converted
                                .word
                                .parts
                                .push(WordPart::Literal("\n".to_string())),
                        }
                        if fd == 0 && redir.named_fd.is_none() {
                            stdin_producers = converted.producers;
                            let mut provenance = vec![self.span_node(builder, target.span)];
                            provenance.extend(converted.assign_nodes);
                            stdin = Some(StdinValue {
                                paths: None,
                                piped: false,
                                file: None,
                                word: converted.word,
                                provenance,
                            });
                        } else {
                            here_contents.insert(redir_index, converted.word);
                        }
                    }
                }
                RedirKind::In | RedirKind::ReadWrite if fd == 0 && redir.named_fd.is_none() => {
                    stdin_producers.clear();
                    // `read` and `mapfile` store what a process substitution
                    // writes, so its producers must be known when they run;
                    // the redirection reuses this expansion.
                    if matches!(name.as_deref(), Some("read" | "mapfile" | "readarray"))
                        && let Some(target) = &redir.target
                        && matches!(target.segs.as_slice(), [Seg::ProcSub { .. }])
                    {
                        let converted = self.convert(builder, env, target, true, true);
                        stdin_producers = converted.producers.clone();
                        env.dispatch_stdin
                            .converted_targets
                            .insert((target.span.start, target.span.end), converted);
                    }
                    // `read` consumes the file as unknown bytes; any other
                    // command gets the file, which a model that runs stdin
                    // as a script reads.
                    let read = name.as_deref() == Some("read");
                    // `< <(printf ...)` of fixed words supplies known text.
                    let written = redir
                        .target
                        .as_ref()
                        .and_then(|target| match target.segs.as_slice() {
                            [Seg::ProcSub { span }] => {
                                self.source.get(span.start as usize..span.end as usize)
                            }
                            _ => None,
                        })
                        .filter(|raw| raw.starts_with("<(") && raw.ends_with(')'))
                        .and_then(|raw| self.literal_process_output(env, &raw[2..raw.len() - 1]));
                    stdin = Some(StdinValue {
                        paths: None,
                        piped: false,
                        file: (!read).then(|| {
                            redirected_file(redir.target.as_ref(), env.cwd_resource.clone())
                        }),
                        word: written.unwrap_or_else(|| Word::new(vec![WordPart::Unknown])),
                        provenance: vec![self.span_node(builder, redir.span)],
                    });
                }
                // `<&N` reads what the shell left open on N.
                RedirKind::Dup if fd == 0 => {
                    stdin_producers.clear();
                    stdin = match redir.dup {
                        Some(ShellDupTarget::Fd(source) | ShellDupTarget::Move(source)) => env
                            .descriptors
                            .get(&Descriptor::Number(source))
                            .cloned()
                            .map(|word| StdinValue {
                                paths: None,
                                piped: false,
                                file: None,
                                word,
                                provenance: vec![self.span_node(builder, redir.span)],
                            }),
                        _ => None,
                    };
                }
                _ => {}
            }
        }
        // Runtimes launched by expansions so far are not this command's own.
        builder.control_mark();
        let Some(converted) = variants.iter().find(|variant| !variant.is_empty()) else {
            if cmd.compound_redirects
                && let Some(stdin) = stdin
            {
                env.compound_stdin = Some((stdin, stdin_producers));
            }
            // A command with no retained words may still contain assignments.
            // A conditional assignment may not run, so it widens to unknown.
            return self.no_command(
                builder,
                env,
                cmd,
                persist,
                persist_fds,
                conditional,
                guarded,
                &here_contents,
            );
        };
        env.dispatch_stdin.producers = stdin_producers.clone();
        let command_boundaries = builder.boundaries_len();
        // `exec` that replaces no program leaves its redirections on the shell,
        // so they outlive the command however many options precede them.
        let exec_head = command_prefix_len(&cmd.words);
        let persist_fds = persist
            && cmd
                .words
                .get(exec_head)
                .and_then(parse::command_name_text)
                .as_deref()
                == Some("exec")
            && converted
                .get(exec_head..)
                .is_some_and(|words| exec_operands(words).is_none());
        if matches!(
            cmd.words[0].segs.as_slice(),
            [Seg::Env { .. }]
                | [Seg::Positional { .. }]
                | [Seg::Param {
                    transform: Some(_),
                    ..
                }]
        ) || substituted_head(&cmd.words[0])
            || effective_ifs(env)
                .is_some_and(|ifs| ifs_joined_fields(&cmd.words[0], &ifs).is_some())
        {
            name = first_retained_token.and_then(|index| {
                let tok = &cmd.words[index];
                if matches!(
                    tok.segs.as_slice(),
                    [Seg::AllArgs { .. }] | [Seg::ArrayAll { .. }]
                ) {
                    None
                } else {
                    parse::literal_text(tok).or_else(|| {
                        converted
                            .first()
                            .and_then(|converted| head_program_name(&converted.word))
                            .map(str::to_string)
                    })
                }
            });
        }
        // Field splitting can produce different command heads. Dispatch each
        // argv independently so a builtin cannot hide an external alternative.
        self.emit_obfuscated_command_effect(builder, env, cmd, &variants);
        let mut execution = None;
        let mut model_eligible = true;
        let mut dispatched_variants = 0usize;
        let mut terminates = None;
        let mut terminating_variants = 0;
        // What each argv proves about reaching later commands.
        let mut calls = Vec::with_capacity(variants.len());
        // Only the top-level shell's unredirected final stdout is a proven
        // listing sink. Even an ordinary filename can feed a later consumer.
        let stdout_unconsumed = self.depth == 0
            && env.background_depth == 0
            && !stdout_consumed
            && env.redirections.is_empty()
            && cmd.redirs.is_empty()
            && name
                .as_deref()
                .is_some_and(|name| !env.functions.contains_key(name))
            && !env.functions.contains_key("find")
            && !env.aliases.contains_key("find");
        for variant in variants.iter().filter(|variant| !variant.is_empty()) {
            let literal_name =
                first_retained_token.and_then(|index| parse::literal_text(&cmd.words[index]));
            let variant_name = if matches!(
                cmd.words[0].segs.as_slice(),
                [Seg::Env { .. }]
                    | [Seg::Positional { .. }]
                    | [Seg::Param {
                        transform: Some(_),
                        ..
                    }]
            ) || substituted_head(&cmd.words[0])
                || effective_ifs(env)
                    .is_some_and(|ifs| ifs_joined_fields(&cmd.words[0], &ifs).is_some())
            {
                literal_name
                    .as_deref()
                    .or_else(|| head_program_name(&variant[0].word))
            } else {
                name.as_deref()
            };
            let previous_stdout = builder.stdout_unconsumed;
            let previous_consumed = env.stdout_consumed;
            // A listing permission belongs to this find call, run by name,
            // by path or behind a prefix wrapper, never a command invoked by
            // an action such as -exec. Tests and options only decide which
            // names are listed.
            builder.stdout_unconsumed = stdout_unconsumed
                && crate::models::find_only_lists(
                    &variant
                        .iter()
                        .map(|arg| arg.word.clone())
                        .collect::<Vec<_>>(),
                );
            env.stdout_consumed = !builder.stdout_unconsumed;
            let (variant_execution, termination, facts, variant_model_eligible) = self
                .dispatch_argv(
                    builder,
                    env,
                    cmd,
                    variant,
                    variant_name,
                    first_retained_token,
                    stdin.as_ref(),
                    persist,
                    conditional || variants.len() > 1,
                    guarded,
                );
            builder.stdout_unconsumed = previous_stdout;
            env.stdout_consumed = previous_consumed;
            execution = variant_execution.or(execution);
            dispatched_variants += 1;
            model_eligible &= variant_model_eligible;
            terminating_variants += usize::from(termination.is_some());
            terminates = termination;
            calls.push(facts);
        }
        env.dispatch_stdin.producers.clear();
        let unestablished = builder.boundaries_len() != command_boundaries;
        if terminating_variants != variants.len() {
            terminates = None;
        }
        model_eligible &= dispatched_variants == 1;
        self.wire_code_producers(
            builder,
            cmd.span,
            execution,
            &stdin_producers,
            initial_effect_start,
            builder.effects_len(),
            true,
        );
        let call_redirects = env
            .call_redirects
            .take_if(|(source, at, _)| *at == cmd.span && Rc::ptr_eq(source, &self.source_digest))
            .map(|(_, _, redirects)| redirects);
        let redirs = if let Some(redirects) = call_redirects {
            redirects
        } else if self.structural_saturated(builder, env) {
            Redirects::default()
        } else {
            self.redirects(
                builder,
                env,
                cmd,
                persist_fds,
                persist,
                conditional,
                guarded,
                &here_contents,
                execution,
                initial_effect_start,
            )
        };
        let exact_output_builtin = name.as_ref().is_some_and(|name| {
            !env.functions.contains_key(name) && !env.disabled_builtins.contains(name)
        });
        if variants
            .iter()
            .filter(|variant| !variant.is_empty())
            .count()
            == 1
            && exact_output_builtin
        {
            predict_redirected_output(
                builder,
                self.nest,
                cmd,
                name.as_deref(),
                converted,
                stdin.as_ref(),
                &redirs.binds,
            );
            if name.as_deref() == Some("tee") {
                predict_tee_output(
                    builder,
                    self.nest,
                    env,
                    converted,
                    stdin.as_ref(),
                    execution,
                    initial_effect_start,
                );
            }
        }
        if !persist_fds {
            let output = (!conditional
                && !overflowed
                && variants.len() == 1
                && exact_output_builtin
                && matches!(name.as_deref(), Some("echo" | "printf")))
            .then(|| {
                literal_output(
                    name.as_deref(),
                    converted,
                    stdin.as_ref(),
                    self.nest.limits.max_source_bytes,
                )
            })
            .flatten();
            predict_descriptor_output(
                builder,
                self.nest,
                &env.redirections,
                &redirs.flows,
                output.as_deref(),
            );
        }
        let stdout = if !overflowed
            && variants.len() == 1
            && redirs
                .flows
                .iter()
                .chain(&env.redirections)
                .all(|redir| redir.fd != Descriptor::Number(1) && !redir.both)
            && exact_output_builtin
        {
            let (producer, words) = command_operand_producer(name.as_deref(), converted);
            producer
                .filter(|producer| !env.disabled_builtins.contains(*producer))
                .and_then(|producer| {
                    // Supplied text stays an unknown part of the output only
                    // where quoting keeps it within one argument.
                    if cmd.words.iter().all(|word| {
                        word.segs.iter().all(|segment| {
                            matches!(segment, Seg::Literal { .. })
                                || one_word_quoted_expansion(segment)
                        })
                    }) {
                        literal_output_word(
                            Some(producer),
                            words,
                            stdin.as_ref(),
                            self.nest.limits.max_source_bytes,
                        )
                    } else {
                        literal_output(
                            Some(producer),
                            words,
                            stdin.as_ref(),
                            self.nest.limits.max_source_bytes,
                        )
                        .map(Word::literal)
                        .or_else(|| {
                            // Every word before the last is one argument, so
                            // the leading converted words are those arguments
                            // however many words the last one becomes.
                            let (_, before) = cmd.words.split_last()?;
                            let fixed = before
                                .iter()
                                .flat_map(|word| &word.segs)
                                .all(|segment| match segment {
                                    Seg::Literal { text, quoted } => {
                                        *quoted || !text.contains(['*', '?', '[', '{', '~'])
                                    }
                                    segment => one_word_quoted_expansion(segment),
                                })
                                .then(|| {
                                    let wrapper = converted.len() - words.len();
                                    converted.get(wrapper + 1..before.len())
                                })??;
                            literal_output::render_printf_open_tail(
                                Some(producer),
                                &fixed.iter().map(|word| &word.word).collect::<Vec<_>>(),
                                self.nest.limits.max_source_bytes,
                            )
                        })
                    }
                })
                .map(|word| {
                    let mut provenance = vec![self.span_node(builder, cmd.span)];
                    for word in converted {
                        provenance.extend(word.assign_nodes.iter().copied());
                    }
                    if let Some(stdin) = &stdin {
                        provenance.extend(stdin.provenance.iter().copied());
                    }
                    StdinValue {
                        paths: None,
                        piped: true,
                        file: None,
                        word,
                        provenance,
                    }
                })
        } else {
            None
        };
        let stdout = stdout.or_else(|| {
            if overflowed
                || !model_eligible
                || variants.len() != 1
                || !redirs
                    .flows
                    .iter()
                    .chain(&env.redirections)
                    .all(|redir| redir.fd != Descriptor::Number(1) && !redir.both)
            {
                return None;
            }
            // `cat FILE` writes that file's bytes unchanged, so a client
            // that runs its stdin as a script reads the file, as with `< FILE`.
            if exact_output_builtin
                && let [program, operand] = converted.as_slice()
                && program.word.as_literal() == Some("cat")
                && let Some(operand) = operand.word.as_literal()
                && !operand.starts_with('-')
                && let ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path },
                } = crate::paths::resolve_fs_word_with_cwd(
                    &Word::literal(operand),
                    env.cwd_resource.clone(),
                )
            {
                return Some(StdinValue {
                    piped: true,
                    file: Some(Box::new(Word::literal(path))),
                    word: Word::new(vec![WordPart::Unknown]),
                    paths: None,
                    provenance: vec![self.span_node(builder, cmd.span)],
                });
            }
            let paths = builder.stdout_paths(execution?).cloned()?;
            Some(StdinValue {
                piped: true,
                file: None,
                word: Word::new(vec![WordPart::Unknown]),
                paths: Some(paths),
                provenance: vec![self.span_node(builder, cmd.span)],
            })
        });
        // The builtin `exit` and `return` write nothing to stdout, so the
        // bytes a pipe has already carried stay known; a function or alias
        // of that name, or a disabled builtin, may write anything.
        let silent_builtin = exact_output_builtin
            && matches!(name.as_deref(), Some("exit" | "return"))
            && name
                .as_ref()
                .is_some_and(|name| !env.aliases.contains_key(name));
        if !persist_fds
            && !matches!(name.as_deref(), Some("true" | "false" | ":"))
            && !silent_builtin
            && let Some(channel) = crate::flow::descriptor_channel(
                &env.redirections,
                &redirs.flows,
                Descriptor::Number(1),
            )
        {
            let (producer, words) = command_operand_producer(name.as_deref(), converted);
            let output = (!conditional && variants.len() == 1 && exact_output_builtin)
                .then(|| {
                    producer
                        .filter(|producer| !env.disabled_builtins.contains(*producer))
                        .and_then(|producer| {
                            literal_output(
                                Some(producer),
                                words,
                                stdin.as_ref(),
                                self.nest.limits.max_source_bytes,
                            )
                        })
                })
                .flatten()
                .filter(|output| !output.contains('\0'));
            let mut channels = env.channel_bytes.borrow_mut();
            if let Some(bytes) = channels.get_mut(&channel) {
                match (bytes.as_mut(), output) {
                    (Some(bytes), Some(output))
                        if bytes.len().saturating_add(output.len()) as u64
                            <= self.nest.limits.max_source_bytes
                            && self.charge(builder, 1, output.len() as u64, cmd.span) =>
                    {
                        bytes.push_str(&output)
                    }
                    _ => *bytes = None,
                }
            }
        }
        if calls.is_empty() {
            // No argv was dispatched, so nothing about this command is known.
            calls.push(SiteFacts::unknown());
        }
        for facts in calls {
            self.register_control(builder, cmd, &redirs.binds, facts);
        }
        // The stage belongs to the invoked program after a shell builtin
        // removes its own options, so model ports use that program's argv.
        let converted = match name.as_deref() {
            Some("exec") => exec_operands(converted).map(|start| &converted[start..]),
            Some("command") => command_wrapper_operand(converted),
            _ => None,
        }
        .unwrap_or(converted);
        let name = converted
            .first()
            .and_then(|word| word.word.as_literal())
            .map(str::to_string);
        let words: Vec<Word> = converted.iter().map(|c| c.word.clone()).collect();
        // A model names the descriptor an operand of its own grammar means,
        // so its name for it is the one this operand is judged by.
        let declared = model_eligible
            .then_some(name.as_deref())
            .flatten()
            .and_then(|name| self.nest.catalog.find(name))
            .map(|model| model.descriptor_operands(&words))
            .unwrap_or_default();
        for (at, word) in converted.iter().enumerate() {
            let declared_paths = declared
                .iter()
                .filter(|(index, _)| *index as usize == at)
                .map(|(_, path)| path);
            let spelled = matches!(word.word.parts.first(), Some(WordPart::Literal(prefix))
                if ["/dev/fd/", "/proc/self/fd/", "/proc/thread-self/fd/"]
                    .iter().any(|path| prefix.starts_with(path)));
            for path in declared_paths.chain(spelled.then_some(&word.word)) {
                let resource =
                    crate::paths::resolve_fs_word_with_cwd(path, env.cwd_resource.clone());
                let accesses = (initial_effect_start..builder.effects_len())
                    .filter(|effect| {
                        builder.effect_execution(*effect) == execution
                            && builder.effect_resource(*effect) == Some(&resource)
                            && matches!(
                                builder.effect_operation(*effect),
                                Some("filesystem.read" | "filesystem.write")
                            )
                    })
                    .collect::<Vec<_>>();
                let descriptor = descriptor_path(path, env);
                // A descriptor the shell opened on a socket carries the
                // program's reads and writes through it to that endpoint.
                if let (Some(descriptor), Some(execution)) = (descriptor, execution)
                    && !redirs.flows.iter().any(|flow| flow.fd == descriptor)
                    && let Some((socket, attributes, provenance)) =
                        env.socket_fds.get(&descriptor).cloned()
                {
                    builder.push_execution(execution);
                    let mut bindings = Vec::new();
                    for access in &accesses {
                        let mut provenance = provenance.clone();
                        provenance.extend(builder.effect_provenance(*access).unwrap_or_default());
                        provenance.sort_unstable();
                        provenance.dedup();
                        builder.effect(Effect {
                            request_assurance: effinterp_proto::RequestAssurance::Conservative,
                            id: Default::default(),
                            operation: Operation::new(
                                if builder.effect_operation(*access) == Some("filesystem.read") {
                                    "network.download"
                                } else {
                                    "network.upload"
                                },
                            ),
                            resource: socket.clone(),
                            attributes: attributes.clone(),
                            modality: Modality::May,
                            realm: effinterp_proto::ExecutionRealm::Host,
                            condition: None,
                            execution: ExecutionNodeRef(0),
                            provenance,
                        });
                        let transfer = (builder.effects_len() - 1) as u32;
                        let (from, to) =
                            if builder.effect_operation(*access) == Some("filesystem.read") {
                                (transfer, *access as u32)
                            } else {
                                (*access as u32, transfer)
                            };
                        bindings.push(crate::flow::PortBinding {
                            assurance: effinterp_proto::CausalAssurance::Exact,
                            from: crate::flow::BindEnd::Effect(from),
                            to: crate::flow::BindEnd::Effect(to),
                        });
                    }
                    builder.pop_execution();
                    let node = self.span_node(builder, word.span);
                    builder.flow_stage(crate::flow::FlowStage {
                        execution: Some(execution),
                        effects: bindings
                            .iter()
                            .flat_map(|binding| [&binding.from, &binding.to])
                            .filter_map(|end| match end {
                                crate::flow::BindEnd::Effect(effect) => Some(*effect),
                                _ => None,
                            })
                            .collect(),
                        bindings,
                        provenance: vec![node],
                    });
                }
                // A descriptor redirected to copy one of the command's standard
                // streams (`2<&0`) carries the program's reads from and writes
                // to that stream.
                if let (Some(descriptor), Some(execution)) = (descriptor, execution)
                    && let Some(stream) = crate::flow::descriptor_stream(&redirs.flows, descriptor)
                {
                    let bindings = accesses
                        .iter()
                        .filter_map(|access| {
                            let read = builder.effect_operation(*access) == Some("filesystem.read");
                            let access = crate::flow::BindEnd::Effect(*access as u32);
                            let port = match (stream, read) {
                                (0, true) => effinterp_proto::Port::Stdin,
                                (1, false) => effinterp_proto::Port::Stdout,
                                (2, false) => effinterp_proto::Port::Stderr,
                                _ => return None,
                            };
                            let port = crate::flow::BindEnd::Port(port);
                            let (from, to) = if read { (port, access) } else { (access, port) };
                            Some(crate::flow::PortBinding {
                                assurance: effinterp_proto::CausalAssurance::Exact,
                                from,
                                to,
                            })
                        })
                        .collect::<Vec<_>>();
                    if !bindings.is_empty() {
                        let node = self.span_node(builder, word.span);
                        builder.flow_stage(crate::flow::FlowStage {
                            execution: Some(execution),
                            effects: accesses.iter().map(|access| *access as u32).collect(),
                            bindings,
                            provenance: vec![node],
                        });
                    }
                }
                if !accesses.is_empty()
                    && !descriptor.is_some_and(|descriptor| {
                        crate::flow::descriptor_open(&env.redirections, &redirs.flows, descriptor)
                    })
                {
                    self.opaque_boundary(
                        builder,
                        BoundaryReason::UNRESOLVED_SOURCE,
                        BoundaryClass::Unresolved,
                        "descriptor path has no established open descriptor",
                        word.span,
                    );
                }
            }
        }
        // A quoted `"$(…)"` is one field holding every selected identifier:
        // the command acts on the whole selection when it names at most one
        // resource and fails otherwise, so it may act on exactly that
        // selection. Unquoted substitutions are applied with the pipeline.
        if variants
            .iter()
            .filter(|variant| !variant.is_empty())
            .count()
            == 1
        {
            for (argument, word) in converted.iter().enumerate() {
                if word.quoted_substitution {
                    builder.apply_exact_argument_selection(
                        &word.producers,
                        initial_effect_start as u32..builder.effects_len() as u32,
                        argument as u32,
                    );
                }
            }
        }
        StageOutcome {
            terminates,
            execution,
            words,
            argument_producers: converted
                .iter()
                .map(|word| word.producers.clone())
                .collect(),
            stdin_producers,
            unestablished,
            unquoted_substitutions: converted
                .iter()
                .map(|word| word.unquoted_substitution)
                .collect(),
            // Flow bindings follow the program's model, which a system
            // program directory path (`/usr/bin/curl`) selects by basename.
            name: name.map(|name| {
                if crate::exec::established_program(&Word::literal(&name)) {
                    name.rsplit('/').next().unwrap_or(&name).to_string()
                } else {
                    name
                }
            }),
            model_eligible,
            stdin,
            stdout,
            redirs,
        }
    }

    /// Register what this command's evaluation proves. The shell opens the
    /// first redirection before anything else can fail; later ones, and the
    /// command's own work, are only known to have run when it succeeded.
    pub(in crate::shell) fn register_control(
        &self,
        builder: &mut PlanBuilder,
        cmd: &Simple,
        redir_binds: &[(Option<u32>, Option<u32>)],
        mut facts: SiteFacts,
    ) {
        let slots = |bind: &(Option<u32>, Option<u32>)| {
            bind.0
                .into_iter()
                .chain(bind.1)
                .map(ControlFact::Effect)
                .collect::<Vec<_>>()
        };
        if let (Some(first), Some(bind)) = (cmd.redirs.first(), redir_binds.first())
            && matches!(
                first.kind,
                RedirKind::Out | RedirKind::Append | RedirKind::In | RedirKind::ReadWrite
            )
        {
            facts.facts.extend(slots(bind));
        }
        for bind in redir_binds {
            facts.success.extend(slots(bind));
        }
        builder.control_site(self.source, false, (cmd.span.start, cmd.span.end), facts);
    }
}

pub(super) fn captured_program_name(word: &Word) -> Option<&str> {
    match word.parts.as_slice() {
        [WordPart::Value(ResourceExpr::Literal { value })] => Some(value),
        _ => None,
    }
}

/// The program name a resolved head word names, whether a plain literal or a
/// captured substitution value.
fn head_program_name(word: &Word) -> Option<&str> {
    word.as_literal().or_else(|| captured_program_name(word))
}

/// POSIX `command [-p] [-v|-V] [--] name [args...]`.
///
/// Returns the argv to run, or `None` when this is a lookup (`-v`/`-V`) or
/// there is no operand.
/// The program whose output a stage writes: `command` bypasses functions and
/// runs its operand, so the operand's words produce the output.
fn command_operand_producer<'a>(
    mut name: Option<&'a str>,
    mut converted: &'a [Converted],
) -> (Option<&'a str>, &'a [Converted]) {
    while name == Some("command")
        && let Some(operand) = command_wrapper_operand(converted)
    {
        converted = operand;
        name = operand[0].word.as_literal();
    }
    (name, converted)
}

/// The text of a word made only of literal parts and captured output with a
/// literal value.
fn captured_literal_text(word: &Word) -> Option<String> {
    word.parts
        .iter()
        .map(|part| match part {
            WordPart::Literal(text) => Some(text.as_str()),
            WordPart::Value(ResourceExpr::Literal { value }) => Some(value.as_str()),
            _ => None,
        })
        .collect()
}

/// A head token spelled from literal text and command substitutions.
pub(super) fn substituted_head(tok: &WordTok) -> bool {
    tok.segs
        .iter()
        .any(|seg| matches!(seg, Seg::CommandSub { .. }))
        && tok
            .segs
            .iter()
            .all(|seg| matches!(seg, Seg::CommandSub { .. } | Seg::Literal { .. }))
}

/// `exec [-cl] [-a NAME] [COMMAND [ARG...]]`.
///
/// Returns the index where the replaced program's argv begins, or `None` for
/// the form that carries only options and redirections and replaces no
/// program. `-a NAME` renames argv[0] and takes the rest of its own word or
/// the next word; `-c` and `-l` are flags. An option this grammar does not
/// define ends the scan, so the word keeps being read as the command and the
/// exec frontend reports it as unmodeled.
/// The number of leading words that are `command` and its `-p` or `--`
/// options, which run the next word as a builtin in this shell.
fn command_prefix_len(words: &[WordTok]) -> usize {
    let mut index = 0;
    while words.get(index).and_then(parse::literal_text).as_deref() == Some("command") {
        index += 1;
        while let Some(option) = words.get(index).and_then(parse::literal_text) {
            match option.as_str() {
                "-p" => index += 1,
                "--" => {
                    index += 1;
                    break;
                }
                _ => break,
            }
        }
    }
    index
}
