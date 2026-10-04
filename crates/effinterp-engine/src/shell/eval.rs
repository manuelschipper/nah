//! Shell evaluation of one simple command: head resolution, builtin and
//! function dispatch, and process execution. Each child module owns one
//! further question about a command: `word_expansion`, `command_substitution`,
//! `variable_binding`, `redirection`, `directory_change`, `arithmetic`,
//! `source_and_eval`, and `literal_output`.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::rc::Rc;

use effinterp_proto::{
    AttrValue, Boundary, BoundaryClass, BoundaryReason, CoverageLevel, Domain, Effect,
    ExecutionNodeRef, Modality, Operation, Port, ProvenanceKind, ProvenanceRef, ResourceExpr,
    ResourceIdentity, Subject,
};

use crate::builder::{KNOWN_DOMAINS, PlanBuilder, ScriptInterpreter};
use crate::control_flow::{ControlExit, ControlFact, Requirements, SiteFacts};
use crate::exec::{UnresolvedHead, analyze_exec};
use crate::flow::{BindEnd, Descriptor, Flow, FlowReason, FlowRef, FlowStage, PortBinding};
use crate::models::{StdinValue, curl_flow_info, wget_flow_info};
use crate::nest::{Transition, degrade_nested, word_resource};
use crate::paths::{join_cwd, process_identity_with_cwd};
use crate::value::unresolved_resource;
use crate::word::{Word, WordPart};

use super::lex::{ExpansionBudget, RedirKind, Seg, ShellDupTarget, ShellSpan, WordTok};
use super::parse::{ShellItem, Simple};
use super::{
    ArrayValue, CommandHeadKey, Converted, DeferredProcess, EFFECTLESS_BUILTINS, FnEntry,
    FunctionBinding, MAX_ARGV_VARIANTS, MAX_SATURATED_COMMAND_HEADS, MAX_SATURATED_FUNCTION_STEPS,
    MAX_SATURATED_UNRESOLVED_HEADS, MAX_WALK_DEPTH, PathBindings, Redirects, Shell, ShellEnv,
    StageOutcome, Termination, VarEntry, WordExpansion, analyze_shell_at, analyze_shell_with_env,
    downgrade_script_set, expanded_referenced_inputs_bounded, function_head_group_key,
    function_head_key, jobs, lex, parse, referenced_inputs_with_substitutions, resource_key,
    script_set_names, shell_builtin, variable_saturation_key, word_key,
};

pub(super) mod arithmetic;
mod command_substitution;
mod directory_change;
mod literal_output;
pub(super) mod redirection;
mod source_and_eval;
pub(super) mod variable_binding;
mod word_expansion;

use command_substitution::{heredoc_body_expands, one_word_quoted_expansion};
use directory_change::{
    DirectoryChange, directory_change, directory_target, host_runtime_cwd, physical_depth_after,
    pwd_follows_cwd,
};
use redirection::{
    descriptor_path, descriptor_word, predict_descriptor_output, predict_redirected_output,
    predict_tee_output, redirected_descriptors, redirected_file,
};
use variable_binding::{bind_var, entry_definitely_transparent};
use word_expansion::{effective_ifs, ifs_joined_fields, split_ifs_fields, var_node};

/// A shell function's guarantees at its call: its attempt reaches what every
/// return reaches, and a successful status adds what every successful return
/// reaches.
fn call_facts(requirements: &Requirements) -> SiteFacts {
    SiteFacts {
        call_return: false,
        facts: requirements.on_completion.iter().copied().collect(),
        success: requirements.on_success.iter().copied().collect(),
        returns: requirements.succeeds || requirements.fails || requirements.may_return,
        succeeds: requirements.succeeds,
        exit: requirements.may_exit.then_some(ControlExit::Unknown),
        widen: false,
        ..Default::default()
    }
}

/// bash's fallback for a command name it cannot resolve.
const COMMAND_NOT_FOUND_HANDLE: &str = "command_not_found_handle";

/// `unset -f NAME` removes the function NAME on every path where
/// `readonly -f` did not fix it. A conditional unset keeps each such path
/// with and without the function.
fn unset_function(env: &mut ShellEnv, name: &str, conditional: bool) {
    let mut bindings = match env.function_alternatives.remove(name) {
        Some(bindings) => bindings,
        None if env.readonly_functions.contains(name) => return,
        None => match env.functions.get(name) {
            Some(function) => vec![((Some(Rc::clone(function)), false), None)],
            None => return,
        },
    };
    let removed: PathBindings<FunctionBinding> = bindings
        .iter()
        .filter(|((function, readonly), _)| function.is_some() && !*readonly)
        .map(|(_, condition)| ((None, false), condition.clone()))
        .collect();
    if !conditional {
        bindings.retain(|((function, readonly), _)| function.is_none() || *readonly);
    }
    bindings.extend(removed);
    if bindings
        .iter()
        .all(|((function, readonly), _)| function.is_none() && !*readonly)
    {
        env.functions.remove(name);
    } else if let [((function, readonly), _)] = &bindings[..] {
        match function {
            Some(function) => env.functions.insert(name.to_string(), Rc::clone(function)),
            None => env.functions.remove(name),
        };
        if *readonly {
            env.readonly_functions.insert(name.to_string());
        } else {
            env.readonly_functions.remove(name);
        }
    } else {
        env.function_alternatives.insert(name.to_string(), bindings);
    }
}

fn literal_output(
    name: Option<&str>,
    converted: &[Converted],
    stdin: Option<&StdinValue>,
    max_bytes: u64,
) -> Option<String> {
    let args = converted
        .get(1..)?
        .iter()
        .map(|word| word.word.as_literal())
        .collect::<Option<Vec<_>>>()?;
    literal_output::render(
        name,
        &args,
        stdin.and_then(|stdin| stdin.word.as_literal()),
        max_bytes,
    )
}

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

// Sources and conditional function calls share the shell's bindings and cwd.
// Evaluate each possible body from the same state, then widen changed values.
/// Every cwd field a conditional body starts from, in `ShellEnv` declaration order.
type CwdState = (
    Option<String>,
    Option<ResourceExpr>,
    bool,
    Option<ProvenanceRef>,
    Option<String>,
    Option<String>,
    bool,
);

struct ConditionalShellState {
    initial_vars: HashMap<String, VarEntry>,
    initial_cwd: CwdState,
    uncertain_vars: HashMap<String, VarEntry>,
    uncertain_cwd: bool,
}

impl ConditionalShellState {
    fn new(env: &ShellEnv) -> Self {
        Self {
            initial_vars: env.vars.clone(),
            initial_cwd: (
                env.cwd.clone(),
                env.cwd_resource.clone(),
                env.captured_cwd,
                env.cwd_node,
                env.source_cwd.clone(),
                env.runtime_cwd.clone(),
                env.cwd_known,
            ),
            uncertain_vars: HashMap::new(),
            uncertain_cwd: false,
        }
    }

    fn reset(&self, env: &mut ShellEnv) {
        env.vars = self.initial_vars.clone();
        (
            env.cwd,
            env.cwd_resource,
            env.captured_cwd,
            env.cwd_node,
            env.source_cwd,
            env.runtime_cwd,
            env.cwd_known,
        ) = self.initial_cwd.clone();
    }

    fn observe(&mut self, env: &ShellEnv) {
        for (name, entry) in self.initial_vars.iter().chain(env.vars.iter()) {
            if self
                .initial_vars
                .get(name)
                .map(|entry| entry.saturation_key)
                != env.vars.get(name).map(|entry| entry.saturation_key)
            {
                let script_set = self
                    .initial_vars
                    .get(name)
                    .is_some_and(|entry| entry.script_set)
                    && env.vars.get(name).is_some_and(|entry| entry.script_set)
                    && self
                        .uncertain_vars
                        .get(name)
                        .is_none_or(|entry| entry.script_set);
                let mut entry = entry.clone();
                entry.script_set = script_set;
                self.uncertain_vars.insert(name.clone(), entry);
            }
        }
        self.uncertain_cwd |= (
            &env.cwd,
            &env.cwd_resource,
            env.captured_cwd,
            env.cwd_node,
            &env.source_cwd,
            &env.runtime_cwd,
            env.cwd_known,
        ) != (
            &self.initial_cwd.0,
            &self.initial_cwd.1,
            self.initial_cwd.2,
            self.initial_cwd.3,
            &self.initial_cwd.4,
            &self.initial_cwd.5,
            self.initial_cwd.6,
        );
    }

    fn merge(self, env: &mut ShellEnv) {
        env.vars = self.initial_vars;
        for (name, mut entry) in self.uncertain_vars {
            entry.value = None;
            entry.branches.clear();
            entry.transparent_writes.clear();
            entry.may.clear();
            entry.word = Some(Word::new(vec![WordPart::Unknown]));
            entry.word_condition = None;
            entry.producers.clear();
            entry.producers_condition = None;
            entry.earlier_producers.clear();
            entry.script_may_set = true;
            entry.saturation_key = variable_saturation_key(
                None,
                &entry.may,
                entry.word.as_ref(),
                true,
                entry.unresolved_default_override,
            );
            env.vars.insert(name, entry);
        }
        if self.uncertain_cwd {
            env.cwd = None;
            env.cwd_resource = Some(unresolved_resource("filesystem"));
            env.captured_cwd = false;
            env.cwd_node = None;
            env.source_cwd = None;
            env.runtime_cwd = None;
            env.cwd_known = false;
        }
    }
}

impl Shell<'_> {
    /// `conditional` marks a command that runs only on some paths (a
    /// `&&`/`||` operand, or anything inside a may-region); `guarded` marks
    /// only the former, where even a read later in the same region cannot
    /// count on the command having run.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn simple(
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
        // A head spelled from literal text and exactly captured literal output
        // names that command, as `$(printf rm) -rf /` runs `rm`.
        for head in variants
            .iter_mut()
            .filter_map(|variant| variant.first_mut())
        {
            if head.word.as_literal().is_none()
                && let Some(text) = captured_literal_text(&head.word)
            {
                head.word = Word::literal(text.clone());
                head.raw = text;
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
            && name.as_deref() == Some("find")
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
            // A listing permission belongs to this find call, never a command
            // invoked by an action such as -exec or by a runtime wrapper.
            builder.stdout_unconsumed = stdout_unconsumed
                && variant.iter().skip(1).all(|arg| {
                    arg.word.as_literal().is_some_and(|word| {
                        !word.starts_with('-') || matches!(word, "-print" | "-print0" | "-ls")
                    })
                });
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

    fn emit_obfuscated_command_effect(
        &self,
        builder: &mut PlanBuilder,
        env: &ShellEnv,
        cmd: &Simple,
        variants: &[Vec<Converted>],
    ) {
        let transformed_head = matches!(
            cmd.words[0].segs.as_slice(),
            [Seg::Param {
                transform: Some(_),
                ..
            }]
        );
        let custom_split_head = match cmd.words[0].segs.as_slice() {
            [
                Seg::Env {
                    name,
                    quoted: false,
                },
            ] => effective_ifs(env).is_some_and(|ifs| {
                ifs != " \t\n"
                    && env
                        .vars
                        .get(name)
                        .and_then(|entry| entry.value.as_deref())
                        .is_some_and(|value| split_ifs_fields(value, &ifs).len() > 1)
            }),
            _ => false,
        };
        let heads = || variants.iter().filter_map(|variant| variant.first());
        // Pathname expansion of an unquoted variable selects the program from
        // whichever files match, as `TOOL='r*'; $TOOL` does.
        let glob_head = matches!(
            cmd.words[0].segs.as_slice(),
            [Seg::Env { quoted: false, .. }]
        ) && heads()
            .any(|head| matches!(head.word.parts.as_slice(), [WordPart::Glob(_)]));
        // `rm${IFS}-rf${IFS}/` splits the program out of one word, under the
        // default or a custom IFS.
        let ifs_joined_head =
            effective_ifs(env).is_some_and(|ifs| ifs_joined_fields(&cmd.words[0], &ifs).is_some());
        // A command substitution prints the program name, as `$(rev <<< mr)`
        // does, whether or not its output is recovered. A transparent producer
        // (`echo`, `printf`, `cat`) passes a source-visible literal through and
        // does not conceal the name. But an unquoted substitution at the head
        // also undergoes field splitting and pathname/brace expansion: even a
        // transparent producer whose output (`r*`, `a b`) does not survive as a
        // single proven literal hides the real program, so it stays marked.
        let substituted_name = match cmd.words[0].segs.as_slice() {
            [Seg::CommandSub { source, quoted, .. }] => {
                substitution_hides_name(source, *quoted)
                    || (!quoted && heads().any(|head| head.word.as_literal().is_none()))
            }
            _ => false,
        };
        // A lone variable holding a value captured from a name-hiding
        // substitution is the same concealment reached through an assignment
        // (`X=$(which rm); $X`), whether or not the value is recovered to a
        // literal head. A transparent capture (`X=$(echo rm)`) is not.
        let captured_value_head = match cmd.words[0].segs.as_slice() {
            [Seg::Env { name, .. }] => env
                .reference_target(name)
                .and_then(|name| env.vars.get(&name))
                .is_some_and(|entry| {
                    entry.captured_name_hidden && !entry_definitely_transparent(entry)
                }),
            _ => false,
        };
        // A literal pattern spelled as the command name also leaves the
        // program to whichever files match, as `r? -rf /` does. A lone `[`
        // is the test builtin, not a bracket expression.
        let literal_head = parse::literal_text(&cmd.words[0]).is_some_and(|name| {
            let bracket = name
                .find('[')
                .is_some_and(|open| name[open + 1..].find(']').is_some_and(|close| close > 0));
            name.contains(['*', '?']) || bracket
        });
        let has_literal_head = heads().any(|head| head.word.as_literal().is_some());
        let marked = glob_head
            || literal_head
            || substituted_name
            || captured_value_head
            || ((transformed_head || custom_split_head || ifs_joined_head) && has_literal_head);
        if !marked {
            return;
        }
        self.emit_hidden_program_effect(builder, env, cmd.words[0].span);
    }

    /// The exact code execution `exec-obfuscated` matches: a program the
    /// shell computes at run time rather than one the source spells.
    fn emit_hidden_program_effect(
        &self,
        builder: &mut PlanBuilder,
        env: &ShellEnv,
        span: ShellSpan,
    ) {
        let source = self.span_node(builder, span);
        let node = builder.node(
            ProvenanceKind::ModelApplication {
                model: "shell/obfuscated-command@v0".into(),
            },
            &[source],
        );
        builder.effect(Effect {
            request_assurance: effinterp_proto::RequestAssurance::Exact,
            id: Default::default(),
            operation: Operation::new("process.code_execution"),
            resource: ResourceExpr::Concrete {
                identity: process_identity_with_cwd(
                    &[Word::literal("sh")],
                    env.cwd_resource.clone(),
                ),
            },
            attributes: [
                ("source".into(), AttrValue::String("argument".into())),
                (
                    "derivation".into(),
                    AttrValue::String("unresolved_command".into()),
                ),
            ]
            .into_iter()
            .collect(),
            modality: Modality::May,
            realm: effinterp_proto::ExecutionRealm::Host,
            condition: None,
            execution: ExecutionNodeRef(0),
            provenance: vec![node],
        });
    }

    #[allow(clippy::too_many_arguments)]
    fn dispatch_argv(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        cmd: &Simple,
        converted: &[Converted],
        name: Option<&str>,
        first_retained_token: Option<usize>,
        stdin: Option<&StdinValue>,
        persist: bool,
        conditional: bool,
        guarded: bool,
    ) -> (
        Option<ExecutionNodeRef>,
        Option<Termination>,
        SiteFacts,
        bool,
    ) {
        if let Some(name) = name
            && let Some(dispatched) = self.dispatch_path_bindings(
                builder,
                env,
                cmd,
                converted,
                name,
                first_retained_token,
                stdin,
                persist,
                guarded,
            )
        {
            return dispatched;
        }
        // The shell expands an alias while it reads the line, so an aliased
        // head word runs its alias text rather than a function, `builtin`
        // or `command` of that name.
        let aliased = name.is_some_and(|name| {
            !quoted_head(&cmd.words[0]) && self.alias_expansion(env, name, cmd.span).is_some()
        });
        if !aliased
            && env.expand_aliases
            && !quoted_head(&cmd.words[0])
            && name.is_some_and(|name| env.unread_alias_names || env.unread_aliases.contains(name))
        {
            self.opaque_boundary(
                builder,
                BoundaryReason::UNRESOLVED_COMMAND,
                BoundaryClass::Unresolved,
                "alias definition is not statically recoverable",
                cmd.span,
            );
        }
        // `builtin NAME` and `command NAME` skip function lookup. A shell
        // builtin operand runs in this shell, so its state changes persist.
        if !aliased
            && let Some(prefix @ ("builtin" | "command")) = name
            && !env.functions.contains_key(prefix)
            && let Some(rest) = if prefix == "builtin" {
                let start = 1 + usize::from(
                    converted.get(1).and_then(|word| word.word.as_literal()) == Some("--"),
                );
                converted.get(start..).filter(|rest| !rest.is_empty())
            } else {
                command_wrapper_operand(converted)
            }
            && let Some(builtin) = rest[0].word.as_literal()
            && super::shell_builtin(builtin)
            && !env.disabled_builtins.contains(builtin)
        {
            let offset = converted.len() - rest.len();
            let shadow = env.functions.remove(builtin);
            let dispatched = self.dispatch_argv(
                builder,
                env,
                cmd,
                rest,
                Some(builtin),
                first_retained_token.map(|index| index + offset),
                stdin,
                persist,
                conditional,
                guarded,
            );
            if let Some(entry) = shadow {
                env.functions.entry(builtin.to_string()).or_insert(entry);
            }
            return dispatched;
        }
        // A function defined earlier in this script shadows builtins and
        // externals: walk its body at the call site. Unknown names fall
        // through to the builtin/external match below.
        let mut functions = Vec::new();
        let mut pattern_dispatch = false;
        if let Some(fname) = name.or_else(|| {
            self.nest
                .resolver
                .and_then(|_| converted[0].word.as_literal())
        }) {
            if !aliased && let Some(entry) = env.functions.get(fname) {
                functions.push((fname.to_string(), entry.clone()));
            }
        } else if self.nest.resolver.is_some()
            && let Some(pattern) = crate::SourcePattern::from_command_word(&converted[0].word)
        {
            pattern_dispatch = true;
            functions.extend(
                env.functions
                    .iter()
                    .filter(|(name, entry)| entry.source_origin.is_some() && pattern.matches(name))
                    .map(|(name, entry)| (name.clone(), entry.clone())),
            );
            functions.sort_by(|a, b| a.0.cmp(&b.0));
        }
        // bash runs `command_not_found_handle` when a name resolves to no
        // function, builtin, or file. Whether it resolves is not known here,
        // so the handler becomes one dispatch arm beside the command itself.
        // A name with a slash is a pathname, never searched, and a missing
        // one fails without the handler. Neither is a `hash -p` binding or an
        // alias that expands here, unless an earlier branch or a guard left it
        // unsettled.
        let mut handler_dispatch = false;
        if functions.is_empty()
            && let Some(fname) = name
            && !fname.contains('/')
            && !super::shell_builtin(fname)
            && self.nest.catalog.find(fname).is_none()
            && (!env.hashed.contains_key(fname)
                || env.hash_alternatives.contains_key(fname)
                || env.uncertain_bindings.contains(fname))
            && (self.alias_expansion(env, fname, cmd.span).is_none()
                || env.alias_alternatives.contains_key(fname)
                || env.uncertain_bindings.contains(fname))
            && let Some(entry) = env.functions.get(COMMAND_NOT_FOUND_HANDLE).cloned()
        {
            pattern_dispatch = true;
            handler_dispatch = true;
            functions.push((COMMAND_NOT_FOUND_HANDLE.to_string(), entry));
        }
        if !functions.is_empty() {
            let merge_state = persist
                && (pattern_dispatch
                    || functions.iter().any(|(_, entry)| {
                        entry.source_condition.is_some() || !entry.alternatives.is_empty()
                    }));
            let mut state = merge_state.then(|| ConditionalShellState::new(env));
            let mut facts: Option<SiteFacts> = None;
            let mut termination = None;
            let mut all_terminate = true;
            let dispatch_arms = functions.len() as u32 + 1;
            for (ordinal, (fname, entry)) in functions.into_iter().enumerate() {
                if pattern_dispatch {
                    // An unresolved head may select another function or no known name.
                    builder.push_condition(self.source_condition(
                        builder,
                        effinterp_proto::ByteSpan {
                            start: cmd.span.start,
                            end: cmd.span.end,
                        },
                        effinterp_proto::ConditionKind::Dispatch,
                        ordinal as u32,
                        dispatch_arms,
                        false,
                        false,
                    ));
                }
                let mut entries = entry.alternatives.clone();
                entries.push(entry);
                for entry in entries {
                    if let Some(state) = &state {
                        state.reset(env);
                    }
                    let prior_heads_only = env.function_heads_only;
                    let heads_only = prior_heads_only
                        || self.nest.budget.exhausted()
                        || builder.execution_saturated();
                    // Keep distinct argv-forwarded command heads while bounding repeated
                    // input shapes for the same function and first positional argument.
                    let group =
                        heads_only.then(|| function_head_group_key(&entry, &converted[1..]));
                    if heads_only {
                        let mut memos = env.saturation_memos.borrow_mut();
                        if memos.function_steps >= MAX_SATURATED_FUNCTION_STEPS
                            || memos
                                .function_groups
                                .get(group.as_ref().unwrap())
                                .copied()
                                .unwrap_or_default()
                                >= MAX_ARGV_VARIANTS
                        {
                            facts
                                .get_or_insert_with(SiteFacts::unknown)
                                .merge(&SiteFacts::unknown());
                            all_terminate = false;
                            continue;
                        }
                        // Key construction expands reachable variables, so it is
                        // part of the same bounded recovery work as the body walk.
                        memos.function_steps += 1;
                    }
                    let key = if heads_only {
                        let refs = entry.saturated_inputs.get_or_init(|| {
                            referenced_inputs_with_substitutions(
                                &entry.body,
                                self.nest
                                    .limits
                                    .max_execution_depth
                                    .min(MAX_WALK_DEPTH as u64)
                                    as u32,
                            )
                        });
                        let Some(key) = function_head_key(
                            &entry,
                            refs,
                            &converted[1..],
                            env,
                            self.nest
                                .limits
                                .max_shell_function_depth
                                .saturating_sub(env.active.len() as u64 + 1),
                        ) else {
                            facts
                                .get_or_insert_with(SiteFacts::unknown)
                                .merge(&SiteFacts::unknown());
                            all_terminate = false;
                            continue;
                        };
                        Some(key)
                    } else {
                        None
                    };
                    if key
                        .as_ref()
                        .is_some_and(|key| env.saturation_memos.borrow().functions.contains(key))
                    {
                        facts
                            .get_or_insert_with(SiteFacts::unknown)
                            .merge(&SiteFacts::unknown());
                        all_terminate = false;
                        continue;
                    }
                    let refusals = self.nest.budget.function_depth_refusals();
                    env.function_heads_only = heads_only;
                    if let Some(condition) = &entry.source_condition {
                        builder.push_bound_condition(condition.clone());
                    }
                    let recursive = env.active.iter().any(|active| active.0 == fname);
                    // The handler receives the whole command line as its
                    // arguments; a function call drops its own name.
                    let (walked, entry_termination) = self.call_function(
                        builder,
                        env,
                        &fname,
                        &entry,
                        &converted[usize::from(!handler_dispatch)..],
                        cmd,
                        persist,
                        conditional || pattern_dispatch || entry.source_condition.is_some(),
                        guarded,
                    );
                    let entry_facts = match &walked {
                        Some(requirements) => call_facts(requirements),
                        None if recursive => SiteFacts::widened(),
                        None => SiteFacts::unknown(),
                    };
                    if let Some(facts) = &mut facts {
                        facts.merge(&entry_facts);
                    } else {
                        facts = Some(entry_facts);
                    }
                    if let Some(state) = &mut state {
                        state.observe(env);
                    }
                    all_terminate &= entry_termination.is_some();
                    termination = entry_termination;
                    if entry.source_condition.is_some() {
                        builder.pop_condition();
                    }
                    env.function_heads_only = prior_heads_only;
                    if walked.is_some()
                        && refusals == self.nest.budget.function_depth_refusals()
                        && let Some(key) = key
                    {
                        let mut memos = env.saturation_memos.borrow_mut();
                        if memos.functions.insert(key) {
                            *memos.function_groups.entry(group.unwrap()).or_default() += 1;
                        }
                    }
                }
                if pattern_dispatch {
                    builder.pop_condition();
                }
            }
            if let Some(state) = state {
                state.merge(env);
            }
            if pattern_dispatch {
                // Matching functions do not exhaust an unresolved command head.
                builder.push_condition(self.source_condition(
                    builder,
                    effinterp_proto::ByteSpan {
                        start: cmd.span.start,
                        end: cmd.span.end,
                    },
                    effinterp_proto::ConditionKind::Dispatch,
                    dispatch_arms - 1,
                    dispatch_arms,
                    false,
                    false,
                ));
                let (execution, model_eligible) =
                    self.run_command(builder, env, cmd, converted, stdin);
                builder.pop_condition();
                return (execution, None, SiteFacts::unknown(), model_eligible);
            }
            return (
                None,
                termination.filter(|_| all_terminate),
                facts.unwrap_or_else(SiteFacts::unknown),
                false,
            );
        }

        let mut declaration_exports = None;
        let listing_handled = if matches!(name, Some("export" | "declare" | "typeset" | "set")) {
            let command = name.unwrap();
            let mut operands = 1;
            let mut print = false;
            let mut export = false;
            let mut functions = false;
            let mut mutation = false;
            let mut unknown = false;
            if command != "set" {
                while let Some(word) = converted.get(operands) {
                    match word.word.as_literal() {
                        Some("--") => {
                            operands += 1;
                            break;
                        }
                        Some(flag) if flag.starts_with('-') && flag.len() > 1 => {
                            for flag in flag[1..].chars() {
                                match flag {
                                    'p' => print = true,
                                    'x' if command != "export" => export = true,
                                    'f' => functions = true,
                                    'F' if command != "export" => functions = true,
                                    'n' => mutation = true,
                                    'a' | 'A' | 'g' | 'I' | 'i' | 'l' | 'r' | 't' | 'u'
                                        if command != "export" =>
                                    {
                                        mutation = true
                                    }
                                    _ => unknown = true,
                                }
                            }
                            operands += 1;
                        }
                        _ => break,
                    }
                }
            }
            let listing = if command == "set" {
                converted.len() == 1
            } else if command == "export" {
                operands == converted.len()
            } else {
                print || export && operands == converted.len()
            };
            if command == "export"
                && !functions
                && !mutation
                && converted[operands..].iter().any(|target| {
                    target.word.as_literal().is_none() && target.word.split_assignment().is_none()
                })
            {
                self.opaque_boundary(
                    builder,
                    BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                    BoundaryClass::Unresolved,
                    "environment listing operands may expand to no names",
                    cmd.span,
                );
            }
            if !functions && export && matches!(command, "declare" | "typeset") {
                declaration_exports = Some(operands);
            }
            // An exported name the walk cannot read may be one that selects
            // a repository or configuration for the commands that follow.
            if (command == "export" || export)
                && !functions
                && converted[operands..].iter().any(|target| {
                    target.word.as_literal().is_none() && target.word.split_assignment().is_none()
                })
            {
                builder.note_unknown_environment_name();
            }
            if functions {
                false
            } else if unknown {
                self.opaque_boundary(
                    builder,
                    BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                    BoundaryClass::Unresolved,
                    "environment listing options are unresolved",
                    cmd.span,
                );
                false
            } else if listing && !mutation {
                let node = self.span_node(builder, cmd.span);
                if operands < converted.len() {
                    for target in &converted[operands..] {
                        let name = target.word.as_literal();
                        if name.is_some_and(|name| {
                            !name
                                .chars()
                                .next()
                                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
                                || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                                || env.unset.contains(name)
                                || self.nest.environment_is_closed() && !env.vars.contains_key(name)
                        }) {
                            continue;
                        }
                        let mut provenance = vec![node];
                        provenance.extend(target.assign_nodes.iter().copied());
                        if let Some(name) = name {
                            if let Some(entry) = env.vars.get_mut(name) {
                                provenance.push(var_node(
                                    builder,
                                    self.scope,
                                    entry,
                                    &env.chain_held,
                                ));
                            }
                        } else {
                            self.opaque_boundary(
                                builder,
                                BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                                BoundaryClass::Unresolved,
                                "environment listing name is unresolved",
                                target.span,
                            );
                        }
                        crate::models::environment_disclosure(builder, name, provenance);
                    }
                } else if self.nest.environment_is_closed() {
                    for name in env.vars.keys().cloned().collect::<BTreeSet<_>>() {
                        let entry = env.vars.get_mut(&name).unwrap();
                        if !env.unset.contains(&name)
                            && (command == "set"
                                || print && command != "export"
                                || env.exported.contains(&name))
                        {
                            let mut provenance = vec![node];
                            provenance.push(var_node(builder, self.scope, entry, &env.chain_held));
                            provenance.extend(entry.antecedents.iter().copied());
                            crate::models::environment_disclosure(builder, Some(&name), provenance);
                        }
                    }
                } else {
                    let mut provenance = vec![node];
                    for name in env.vars.keys().cloned().collect::<BTreeSet<_>>() {
                        let entry = env.vars.get_mut(&name).unwrap();
                        if !env.unset.contains(&name)
                            && (command == "set"
                                || print && command != "export"
                                || env.exported.contains(&name))
                        {
                            provenance.push(var_node(builder, self.scope, entry, &env.chain_held));
                        }
                    }
                    crate::models::environment_disclosure(builder, None, provenance);
                }
                true
            } else {
                false
            }
        } else {
            false
        };

        let mut terminates = None;
        let mut model_eligible = false;
        let execution = match name {
            _ if listing_handled => None,
            // Alias expansion happens while the shell reads the line, before
            // any function, builtin, or hashed name is considered. A quoted or
            // escaped head word is never an alias.
            Some(aliased)
                if !quoted_head(&cmd.words[0])
                    && self.alias_expansion(env, aliased, cmd.span).is_some() =>
            {
                let (text, mut expanding) = self
                    .alias_chain(env, aliased, cmd.span)
                    .expect("alias expansion");
                let arguments = converted[1..]
                    .iter()
                    .map(|argument| argument.word.as_literal())
                    .collect::<Option<Vec<_>>>();
                match arguments {
                    Some(arguments) => {
                        // An alias ending in a blank makes the next word an
                        // alias candidate too (`alias run='command '`).
                        let mut words = vec![text];
                        let mut expands_next = words[0].ends_with([' ', '\t']);
                        for argument in arguments {
                            let expansion = expands_next
                                .then(|| self.alias_chain(env, argument, cmd.span))
                                .flatten();
                            expands_next = expansion
                                .as_ref()
                                .is_some_and(|(text, _)| text.ends_with([' ', '\t']));
                            words.push(match expansion {
                                Some((text, names)) => {
                                    expanding.extend(names);
                                    text
                                }
                                None => argument.to_string(),
                            });
                        }
                        let source = words.join(" ");
                        // The shell does not expand an alias again inside
                        // the text it is expanding (`alias rm='rm -f'`).
                        let hidden = expanding
                            .iter()
                            .filter_map(|name| env.aliases.remove_entry(name))
                            .collect::<Vec<_>>();
                        let execution = self.nested_shell_source(
                            builder,
                            env,
                            &source,
                            cmd.span,
                            NestedShellMode::Persist,
                        );
                        for (name, definition) in hidden {
                            env.aliases.entry(name).or_insert(definition);
                        }
                        execution
                    }
                    None => {
                        self.opaque_boundary(
                            builder,
                            BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                            BoundaryClass::Unresolved,
                            "alias arguments are not statically recoverable",
                            cmd.span,
                        );
                        None
                    }
                }
            }
            // `hash -p PATH NAME` makes NAME run PATH, unless a builtin of
            // that name is still enabled and runs first.
            Some(hashed)
                if env.hashed.contains_key(hashed)
                    && (!shell_builtin(hashed) || env.disabled_builtins.contains(hashed)) =>
            {
                let mut argv = converted.to_vec();
                argv[0].word = Word::literal(&env.hashed[hashed]);
                let (execution, eligible) = self.run_command(builder, env, cmd, &argv, stdin);
                model_eligible |= eligible;
                execution
            }
            Some("alias") => {
                if persist {
                    for target in &converted[1..] {
                        // A later command of this name runs text Nah could
                        // not read, once expansion is on.
                        let Some(operand) = target.word.as_literal() else {
                            match target.word.literal_prefix().split_once('=') {
                                Some((name, _)) => {
                                    env.aliases.remove(name);
                                    env.alias_alternatives.remove(name);
                                    env.unread_aliases.insert(name.to_string());
                                }
                                None => env.unread_alias_names = true,
                            }
                            continue;
                        };
                        let Some((name, text)) = operand.split_once('=') else {
                            continue;
                        };
                        env.unread_aliases.remove(name);
                        env.aliases
                            .insert(name.to_string(), (text.to_string(), target.span.end));
                        env.alias_alternatives.remove(name);
                        if conditional || guarded {
                            env.uncertain_bindings.insert(name.to_string());
                        } else {
                            env.uncertain_bindings.remove(name);
                        }
                    }
                }
                None
            }
            Some("unalias") => {
                if persist {
                    for target in &converted[1..] {
                        match target.word.as_literal() {
                            Some("-a") => {
                                env.aliases.clear();
                                env.alias_alternatives.clear();
                                env.unread_aliases.clear();
                                env.unread_alias_names = false;
                            }
                            Some(name) => {
                                env.aliases.remove(name);
                                env.alias_alternatives.remove(name);
                                env.unread_aliases.remove(name);
                            }
                            None => {}
                        }
                    }
                }
                None
            }
            Some("hash") => {
                if persist {
                    let mut index = 1;
                    while let Some(target) = converted.get(index) {
                        match target.word.as_literal() {
                            Some("-r") => {
                                env.hashed.clear();
                                env.hash_alternatives.clear();
                            }
                            Some("-d") => {
                                if let Some(name) =
                                    converted.get(index + 1).and_then(|w| w.word.as_literal())
                                {
                                    env.hashed.remove(name);
                                    env.hash_alternatives.remove(name);
                                }
                                index += 1;
                            }
                            Some("-p") => {
                                let path =
                                    converted.get(index + 1).and_then(|w| w.word.as_literal());
                                let name =
                                    converted.get(index + 2).and_then(|w| w.word.as_literal());
                                if let (Some(path), Some(name)) = (path, name) {
                                    env.hashed.insert(name.to_string(), path.to_string());
                                    env.hash_alternatives.remove(name);
                                    if conditional || guarded {
                                        env.uncertain_bindings.insert(name.to_string());
                                    } else {
                                        env.uncertain_bindings.remove(name);
                                    }
                                }
                                index += 2;
                            }
                            _ => {}
                        }
                        index += 1;
                    }
                }
                None
            }
            // `enable -n NAME` turns a builtin off for the rest of the shell.
            Some("enable") => {
                if persist {
                    let disable = converted[1..]
                        .iter()
                        .any(|word| word.word.as_literal() == Some("-n"));
                    for target in &converted[1..] {
                        let Some(name) = target.word.as_literal() else {
                            continue;
                        };
                        if name.starts_with('-') {
                            continue;
                        }
                        if disable {
                            env.disabled_builtins.insert(name.to_string());
                        } else {
                            env.disabled_builtins.remove(name);
                        }
                    }
                }
                None
            }
            // `shopt` only changes shell behavior. Options that change how
            // this analysis must read the script are tracked; the rest stay
            // an explicit gap rather than a silent no-op.
            Some("shopt") => {
                let mut enable = None;
                for target in &converted[1..] {
                    match target.word.as_literal() {
                        Some("-s") => enable = Some(true),
                        Some("-u") => enable = Some(false),
                        Some("-q" | "-o" | "-p") => {}
                        // Only bash has `shopt`; any other shell, including
                        // one Nah cannot name, keeps expanding aliases.
                        Some("expand_aliases") if enable.is_some() => {
                            env.expand_aliases =
                                enable == Some(true) || env.expand_aliases && !env.bash;
                        }
                        Some("nocaseglob") if enable.is_some() => {
                            env.nocaseglob = enable == Some(true);
                        }
                        Some("lastpipe") if enable.is_some() => {
                            env.lastpipe = enable == Some(true);
                        }
                        _ => self.opaque_boundary(
                            builder,
                            BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                            BoundaryClass::Unresolved,
                            "shopt option is not modeled",
                            target.span,
                        ),
                    }
                }
                None
            }
            // `printf -v NAME` writes the formatted output to a variable
            // instead of standard output.
            Some("printf")
                if converted.get(1).and_then(|word| word.word.as_literal()) == Some("-v") =>
            {
                if persist
                    && let Some(target) = converted.get(2)
                    && let Some(name) = target.word.as_literal()
                {
                    let value = converted
                        .get(3..)
                        .and_then(|arguments| {
                            arguments
                                .iter()
                                .map(|argument| argument.word.as_literal())
                                .collect::<Option<Vec<_>>>()
                        })
                        .and_then(|arguments| {
                            literal_output::render(
                                Some("printf"),
                                &arguments,
                                None,
                                self.nest.limits.max_source_bytes,
                            )
                        })
                        .filter(|value| !value.contains('\0'));
                    bind_var(
                        builder,
                        env,
                        name.to_string(),
                        value,
                        conditional,
                        guarded,
                        target.span,
                        Vec::new(),
                        Vec::new(),
                    );
                }
                None
            }
            Some(command @ ("cd" | "pushd")) => {
                if persist {
                    // A conditional directory change may not have run;
                    // subsequent relative paths no longer have a known base.
                    let home;
                    let change = match directory_change(command, &converted[1..], env.physical_cd) {
                        // `cd` with no operand behaves as `cd "$HOME"`.
                        DirectoryChange::Home(physical) => {
                            home = self.convert(
                                builder,
                                env,
                                &WordTok {
                                    segs: vec![Seg::Env {
                                        name: "HOME".into(),
                                        quoted: true,
                                    }],
                                    span: converted[0].span,
                                },
                                false,
                                true,
                            );
                            directory_target(&home, physical)
                        }
                        change => change,
                    };
                    let change = match change {
                        DirectoryChange::Target(target, _) if env.captured_cwd => {
                            DirectoryChange::Captured(target)
                        }
                        change => change,
                    };
                    if !matches!(change, DirectoryChange::Keep) {
                        pwd_follows_cwd(env);
                    }
                    match change {
                        DirectoryChange::Keep => {}
                        DirectoryChange::Captured(target) => {
                            env.captured_cwd = true;
                            let resource = crate::paths::resolve_fs_word_with_cwd_on_platform(
                                &target.word,
                                env.cwd_resource.clone(),
                                self.nest.path_platform,
                            );
                            env.cwd_resource = Some(if conditional {
                                crate::value::SemanticValue::from(ResourceExpr::Union {
                                    alternatives: vec![
                                        env.cwd_resource.clone().unwrap_or(
                                            ResourceExpr::Parameter { name: "cwd".into() },
                                        ),
                                        resource,
                                    ],
                                })
                                .canonicalize(self.nest.limits.value_limits())
                                .lower_resource()
                            } else {
                                resource
                            });
                            // A captured value that is one concrete path is the
                            // directory launched programs start in.
                            env.cwd = match &env.cwd_resource {
                                Some(ResourceExpr::Concrete {
                                    identity: ResourceIdentity::FsPath { path },
                                }) => Some(path.clone()),
                                _ => None,
                            };
                            env.cwd_known = true;
                            env.source_cwd = None;
                            env.runtime_cwd = host_runtime_cwd(
                                env.runtime_cwd.as_deref(),
                                env.cwd.as_deref(),
                                self.nest.path_platform,
                            );
                            let antecedents = self
                                .scope
                                .iter()
                                .copied()
                                .chain(target.assign_nodes.iter().copied())
                                .collect::<Vec<_>>();
                            env.cwd_node = Some(builder.node(
                                ProvenanceKind::SourceSpan {
                                    start: target.span.start,
                                    end: target.span.end,
                                },
                                &antecedents,
                            ));
                        }
                        DirectoryChange::Target(target, physical)
                            if !conditional
                                && env.cwd_known
                                && !(crate::paths::directory_change_uses_cwd(
                                    target.word.as_literal().unwrap(),
                                    self.nest.path_platform,
                                ) && env.physical_depth.is_some_and(|depth| {
                                    physical_depth_after(depth, target.word.as_literal().unwrap())
                                        .is_none()
                                })) =>
                        {
                            let target_text = target.word.as_literal().unwrap();
                            let lexical = crate::paths::resolve_fs_word_with_cwd_on_platform(
                                &target.word,
                                env.cwd_resource.clone(),
                                self.nest.path_platform,
                            );
                            'change: {
                                // A change the host shows must fail leaves the
                                // shell where it was.
                                let Some(resource) = self.directory_destination(
                                    builder,
                                    env,
                                    &cmd.assignments,
                                    target,
                                    lexical.clone(),
                                ) else {
                                    break 'change;
                                };
                                let moved = resource != lexical;
                                // A change CDPATH moved elsewhere is not below the
                                // cwd by the target's spelling.
                                let uses_cwd = crate::paths::directory_change_uses_cwd(
                                    target_text,
                                    self.nest.path_platform,
                                ) && !moved;
                                // A physical change marks a new entry point; a
                                // relative logical one moves below the last.
                                env.physical_depth = if physical {
                                    Some(0)
                                } else if uses_cwd {
                                    env.physical_depth
                                        .and_then(|depth| physical_depth_after(depth, target_text))
                                } else {
                                    None
                                };
                                env.cwd = match &resource {
                                    ResourceExpr::Concrete {
                                        identity: ResourceIdentity::FsPath { path },
                                    } => Some(path.clone()),
                                    _ => None,
                                };
                                env.cwd_resource = Some(resource);
                                let antecedents = self
                                    .scope
                                    .iter()
                                    .copied()
                                    .chain(target.assign_nodes.iter().copied())
                                    .chain((uses_cwd || moved).then_some(env.cwd_node).flatten())
                                    .collect::<Vec<_>>();
                                env.cwd_node =
                                    self.nest.tracks_host_context_environment().then(|| {
                                        builder.node(
                                            ProvenanceKind::SourceSpan {
                                                start: target.span.start,
                                                end: target.span.end,
                                            },
                                            &antecedents,
                                        )
                                    });
                                env.source_cwd = if uses_cwd {
                                    env.source_cwd
                                        .as_deref()
                                        .map(|cwd| join_cwd(cwd, target_text))
                                } else {
                                    None
                                };
                                env.runtime_cwd = if uses_cwd {
                                    env.runtime_cwd
                                        .as_deref()
                                        .map(|cwd| join_cwd(cwd, target_text))
                                } else {
                                    host_runtime_cwd(
                                        env.runtime_cwd.as_deref(),
                                        env.cwd.as_deref(),
                                        self.nest.path_platform,
                                    )
                                };
                            }
                        }
                        DirectoryChange::Target(..)
                        | DirectoryChange::Home(_)
                        | DirectoryChange::Unknown => {
                            env.captured_cwd = false;
                            env.cwd_known = false;
                            env.cwd = None;
                            env.cwd_resource = Some(unresolved_resource("filesystem"));
                            env.cwd_node = None;
                            env.source_cwd = None;
                            env.runtime_cwd = None;
                        }
                    }
                }
                None
            }
            Some("popd") => {
                if persist
                    && !matches!(
                        directory_change("popd", &converted[1..], false),
                        DirectoryChange::Keep
                    )
                {
                    pwd_follows_cwd(env);
                    env.captured_cwd = false;
                    env.cwd_known = false;
                    env.cwd = None;
                    env.cwd_resource = Some(unresolved_resource("filesystem"));
                    env.cwd_node = None;
                    env.source_cwd = None;
                    env.runtime_cwd = None;
                }
                None
            }
            Some("export") => {
                // `export` is a special builtin: a prefix assignment before it
                // persists in the current shell (`X=$(rev <<< mr) export X`
                // makes X the concealed capture; `X=ls export X` overwrites it
                // transparently), carrying its concealment classification.
                if persist {
                    for assignment in &cmd.assignments {
                        self.assign(builder, env, assignment, conditional, guarded);
                    }
                }
                let mut operands = 1;
                let mut functions = false;
                let mut unexport = false;
                while let Some(option) = converted
                    .get(operands)
                    .and_then(|target| target.word.as_literal())
                {
                    if option == "--" {
                        operands += 1;
                        break;
                    }
                    if !option.starts_with('-') || option == "-" {
                        break;
                    }
                    functions |= option[1..].contains('f');
                    unexport |= option[1..].contains('n');
                    operands += 1;
                }
                for target in &converted[operands..] {
                    if functions {
                        let Some(name) = target.word.as_literal() else {
                            self.opaque_boundary(
                                builder,
                                BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                                BoundaryClass::Unresolved,
                                "exported function name is unresolved",
                                target.span,
                            );
                            continue;
                        };
                        if !env.functions.contains_key(name) {
                            continue;
                        }
                        builder.declare_coverage(Domain::new("environment"), CoverageLevel::Full);
                        let node = self.span_node(builder, target.span);
                        builder.effect(Effect {
                            request_assurance: effinterp_proto::RequestAssurance::Conservative,
                            id: Default::default(),
                            operation: Operation::new("environment.write"),
                            resource: ResourceExpr::Concrete {
                                identity: ResourceIdentity::EnvironmentVariable {
                                    name: name.to_string(),
                                },
                            },
                            attributes: Default::default(),
                            modality: Modality::May,
                            realm: effinterp_proto::ExecutionRealm::Host,
                            condition: None,
                            execution: effinterp_proto::ExecutionNodeRef(0),
                            provenance: vec![node],
                        });
                        if persist {
                            if unexport {
                                env.exported_functions.remove(name);
                                env.exported_function_nodes.remove(name);
                                env.unexported_function_nodes.insert(name.to_string(), node);
                            } else {
                                env.exported_functions.insert(name.to_string());
                                env.exported_function_nodes.insert(name.to_string(), node);
                                env.unexported_function_nodes.remove(name);
                            }
                        }
                        continue;
                    }
                    // Flags are not variable names: `export -f name` exports
                    // the named function, not a variable called `-f`.
                    self.export(builder, env, target, persist, conditional, guarded);
                    if persist
                        && let Some(name) = target
                            .word
                            .split_assignment()
                            .map(|(name, _)| name.to_string())
                            .or_else(|| {
                                // A bare `export REF` exports the nameref's target.
                                target
                                    .word
                                    .as_literal()
                                    .and_then(|name| env.reference_target(name))
                            })
                    {
                        let name = name.as_str();
                        let assigned = target.word.split_assignment().is_some();
                        if unexport {
                            env.exported.remove(name);
                            env.unexported.insert(name.to_string());
                            env.unexported_nodes
                                .insert(name.to_string(), self.span_node(builder, target.span));
                        } else {
                            env.exported.insert(name.to_string());
                            if assigned || !env.unset.contains(name) {
                                env.unexported.remove(name);
                                env.unexported_nodes.remove(name);
                            }
                        }
                    }
                }
                None
            }
            // `read` fills shell variables from stdin: a variable write and
            // nothing else. The values are input-dependent, so each named
            // variable becomes statically unknown.
            Some(builtin @ ("read" | "mapfile" | "readarray")) => {
                // The command's own stdin redirection (a here-document,
                // here-string or process substitution) feeds its bytes.
                let mut input_producers = env.dispatch_stdin.producers.clone();
                let has_stdin_producers = !input_producers.is_empty();
                // `read <&N` reads descriptor N as `read -u N` does.
                for redir in &cmd.redirs {
                    if redir.named_fd.is_none()
                        && redir.fd.unwrap_or(0) == 0
                        && redir.kind == RedirKind::Dup
                        && let Some(ShellDupTarget::Fd(source) | ShellDupTarget::Move(source)) =
                            redir.dup
                        && let Some(producer) = self.read_input_producer(
                            builder,
                            env,
                            Descriptor::Number(source),
                            redir.span,
                        )
                    {
                        input_producers.push(producer);
                        continue;
                    }
                    if builtin == "read"
                        && !has_stdin_producers
                        && redir.named_fd.is_none()
                        && redir.fd.unwrap_or(0) == 0
                        && (redir.kind == RedirKind::Dup
                            || matches!(redir.kind, RedirKind::In | RedirKind::ReadWrite)
                                && redir
                                    .target
                                    .as_ref()
                                    .is_some_and(|target| parse::literal_text(target).is_none()))
                    {
                        self.opaque_boundary(
                            builder,
                            BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                            BoundaryClass::Unresolved,
                            "read input redirection is unresolved",
                            redir.span,
                        );
                    }
                }
                // Without its own input redirection, `read` reads the
                // channel the enclosing compound's stdin is, such as the
                // pipe in `producer | { read line; ...; }` or the
                // redirection in `while read line; do ...; done < <(producer)`,
                // whose bytes the compound hands its first command unread.
                if input_producers.is_empty()
                    && stdin.is_none_or(|stdin| stdin.word.as_literal().is_none())
                    && !converted
                        .iter()
                        .any(|word| word.word.as_literal() == Some("-u"))
                    && !cmd.redirs.iter().any(|redir| {
                        redir.named_fd.is_none()
                            && redir.fd.unwrap_or(match redir.kind {
                                RedirKind::Out | RedirKind::Append => 1,
                                _ => 0,
                            }) == 0
                    })
                    && let Some(producer) =
                        self.read_input_producer(builder, env, Descriptor::Number(0), cmd.span)
                {
                    input_producers.push(producer);
                }
                if builtin == "read" {
                    // `IFS= read` splits and strips with the prefix
                    // assignment's value, which lasts only for this command.
                    let ifs = match cmd.assignments.iter().rfind(|a| a.name == "IFS") {
                        Some(assignment) if assignment.value.segs.is_empty() => Some(String::new()),
                        Some(assignment) => parse::command_name_text(&assignment.value),
                        None => effective_ifs(env),
                    };
                    self.read_builtin(
                        builder,
                        env,
                        converted,
                        stdin,
                        input_producers,
                        persist,
                        conditional,
                        ifs.as_deref(),
                    );
                } else {
                    self.mapfile_builtin(
                        builder,
                        env,
                        converted,
                        stdin,
                        input_producers,
                        persist,
                        conditional,
                    );
                }
                None
            }
            // `local`/`declare`/`typeset`/`readonly` operands that look like
            // assignments bind like bare assignments; a bare `local NAME`
            // declares a fresh (non-environment) variable.
            Some("local") | Some("declare") | Some("typeset") | Some("readonly") => {
                // POSIX `readonly` takes only -p; bash also takes -a/-A/-f. Any
                // other option (`readonly -l`, `readonly -i`) fails and binds
                // nothing under these shells. zsh and ksh instead accept
                // attribute options, so apply the rejection only for a shell
                // established to reject them; any other (including an
                // unestablished) dialect falls through to `declare_builtin`,
                // which keeps the assigned value and its modeled attribute
                // visible rather than dropping the evidence.
                let rejects_attribute_options = matches!(
                    builder.script_interpreter(),
                    ScriptInterpreter::Root
                        | ScriptInterpreter::Program("bash" | "sh" | "dash" | "ash")
                );
                let rejected = name == Some("readonly")
                    && rejects_attribute_options
                    && converted[1..]
                        .iter()
                        .map_while(|arg| arg.word.as_literal())
                        .take_while(|text| text.starts_with('-') && *text != "--")
                        .any(|text| text[1..].chars().any(|option| !"aAfp".contains(option)));
                if persist && !rejected {
                    let local = name == Some("local");
                    let fixed = name == Some("readonly");
                    let source_operands = first_retained_token
                        .and_then(|index| cmd.words.get(index + 1..))
                        .unwrap_or_default();
                    self.declare_builtin(
                        builder,
                        env,
                        source_operands,
                        &converted[1..],
                        local,
                        conditional,
                        guarded,
                    );
                    let options = converted[1..]
                        .iter()
                        .map_while(|target| target.word.as_literal())
                        .take_while(|text| text.starts_with('-') && *text != "--");
                    let (mut functions, mut readonly) = (false, fixed);
                    for option in options {
                        functions |= option.contains('f');
                        readonly |= option.contains('r');
                    }
                    if readonly && (fixed || functions) {
                        for target in &converted[1..] {
                            if let Some(name) = target
                                .word
                                .split_assignment()
                                .map(|(name, _)| name)
                                .or_else(|| target.word.as_literal())
                                .filter(|name| !name.starts_with('-'))
                            {
                                if functions {
                                    env.readonly_functions.insert(name.to_string());
                                    for ((_, readonly), _) in env
                                        .function_alternatives
                                        .get_mut(name)
                                        .into_iter()
                                        .flatten()
                                    {
                                        *readonly = true;
                                    }
                                } else {
                                    env.readonly.insert(name.to_string());
                                }
                            }
                        }
                    }
                    if let Some(start) = declaration_exports {
                        for target in &converted[start..] {
                            if let Some(name) = target
                                .word
                                .split_assignment()
                                .map(|(name, _)| name)
                                .or_else(|| target.word.as_literal())
                            {
                                env.exported.insert(name.to_string());
                                if target.word.split_assignment().is_some()
                                    || !env.unset.contains(name)
                                {
                                    env.unexported.remove(name);
                                    env.unexported_nodes.remove(name);
                                }
                            }
                        }
                    }
                }
                None
            }
            // `unset NAME` clears the variable: later reads see the script's
            // (empty) value, not the environment's.
            Some("unset") => {
                // `unset -f` removes a function and leaves the variable of the
                // same name bound; only plain `unset` and `unset -v` clear one.
                let functions_only = converted[1..]
                    .iter()
                    .map_while(|target| target.word.as_literal())
                    .take_while(|text| text.starts_with('-') && *text != "--")
                    .any(|text| text.contains('f') && !text.contains('v'));
                // `unset -n NAME` removes NAME only when it is a nameref, and
                // then the reference itself rather than its target.
                let references_only = converted[1..]
                    .iter()
                    .map_while(|target| target.word.as_literal())
                    .take_while(|text| text.starts_with('-') && *text != "--")
                    .any(|text| text.contains('n'));
                if persist && functions_only {
                    for name in converted[1..]
                        .iter()
                        .filter_map(|target| target.word.as_literal())
                        .filter(|text| !text.starts_with('-'))
                    {
                        unset_function(env, name, conditional);
                    }
                }
                if persist && !functions_only {
                    for target in &converted[1..] {
                        if let Some(text) = target.word.as_literal()
                            && !text.starts_with('-')
                            && !env.readonly.contains(text)
                        {
                            // `unset 'NAME[SUB]'` removes one element, which
                            // leaves the remaining elements' positions unknown.
                            if let Some((name, _)) =
                                text.strip_suffix(']').and_then(|text| text.split_once('['))
                                && env.arrays.contains_key(name)
                            {
                                env.arrays
                                    .insert(name.to_string(), ArrayValue::Unknown(Vec::new()));
                                continue;
                            }
                            if references_only {
                                if env.vars.get(text).is_some_and(|entry| entry.nameref) {
                                    env.vars.remove(text);
                                    env.unset.insert(text.to_string());
                                }
                                continue;
                            }
                            let Some(resolved) = env.reference_target(text) else {
                                self.opaque_boundary(
                                    builder,
                                    BoundaryReason::UNRESOLVED_SOURCE,
                                    BoundaryClass::Unresolved,
                                    "cyclic or unresolved nameref unset destination",
                                    target.span,
                                );
                                continue;
                            };
                            let text = resolved.as_str();
                            // `unset` also drops the attributes `declare` gave.
                            env.value_attributes.remove(text);
                            bind_var(
                                builder,
                                env,
                                text.to_string(),
                                Some(String::new()),
                                conditional,
                                guarded,
                                target.span,
                                Vec::new(),
                                Vec::new(),
                            );
                            env.exported.remove(text);
                            env.unexported.insert(text.to_string());
                            env.unset.insert(text.to_string());
                            env.startup_may_set.remove(text);
                            env.unexported_nodes
                                .insert(text.to_string(), self.span_node(builder, target.span));
                            env.arrays.remove(text);
                        }
                    }
                }
                None
            }
            // `shift [N]` drops leading positional parameters.
            Some("shift") => {
                if persist && let Some(pos) = &mut env.positional {
                    let n: usize = converted
                        .get(1)
                        .and_then(|c| c.word.as_literal())
                        .and_then(|t| t.parse().ok())
                        .unwrap_or(1);
                    pos.drain(..n.min(pos.len()));
                }
                None
            }
            // `set` mostly toggles shell options, but the words from `--` or
            // the first non-option operand on replace the positional
            // parameters.
            Some("set") => {
                if converted
                    .iter()
                    .skip(1)
                    .take_while(|word| word.word.as_literal() != Some("--"))
                    .any(|word| {
                        word.word.as_literal().is_some_and(|text| {
                            text == "noglob" || (text.starts_with(['-', '+']) && text.contains('f'))
                        })
                    })
                {
                    self.opaque_boundary(
                        builder,
                        BoundaryReason::UNSUPPORTED_SHELL_SYNTAX,
                        BoundaryClass::Unsupported,
                        "shell glob options are not modeled",
                        cmd.span,
                    );
                }
                if persist {
                    let words = &converted[1..];
                    let mut i = 0;
                    while let Some(text) = words.get(i).and_then(|c| c.word.as_literal())
                        && text != "--"
                        && (text.starts_with('-') || text.starts_with('+'))
                    {
                        let on = text.starts_with('-');
                        if text[1..].contains('P')
                            || (text.contains('o')
                                && words.get(i + 1).and_then(|c| c.word.as_literal())
                                    == Some("physical"))
                        {
                            env.physical_cd = on;
                        }
                        // Entering POSIX mode turns bash's alias expansion
                        // on. Leaving it may restore an earlier setting, so
                        // expansion stays on, the more protective reading.
                        if on
                            && text.contains('o')
                            && words.get(i + 1).and_then(|c| c.word.as_literal()) == Some("posix")
                        {
                            env.expand_aliases = true;
                        }
                        // `-o OPTION` consumes the next word.
                        i += if text.contains('o') { 2 } else { 1 };
                    }
                    if words.get(i).is_some() {
                        env.positional_set_changed = Some(true);
                    }
                    match words.get(i).map(|c| c.word.as_literal()) {
                        None => {}
                        Some(Some("--")) => env.positional = Some(words[i + 1..].to_vec()),
                        Some(Some(_)) => env.positional = Some(words[i..].to_vec()),
                        // A symbolic word may expand to options or operands.
                        Some(None) => env.positional = None,
                    }
                }
                None
            }
            // `exec [-cl] [-a NAME] CMD` replaces the shell with CMD: analyze
            // CMD as a normal invocation so a wrapper that execs another
            // program nests into it. `exec` with only options and
            // redirections replaces no program and falls through to
            // `redirects`.
            Some("exec") => match exec_operands(converted) {
                Some(start) => {
                    if converted[1..start]
                        .iter()
                        .any(|word| word.word.as_literal().is_some_and(exec_clears_environment))
                    {
                        // The replaced program starts from an empty
                        // environment, so the shell's exported values do not
                        // reach it; that reset is not modeled.
                        let node = self.span_node(builder, cmd.span);
                        builder.boundary_with_coverage(
                            Boundary {
                                reason: BoundaryReason::UNSUPPORTED_SHELL_SYNTAX,
                                class: BoundaryClass::Unsupported,
                                scope: effinterp_proto::BoundaryScope::Invocation,
                                affected_resource: None,
                                callee: None,
                                domains: vec![Domain::new("environment")],
                                provenance: vec![node],
                                limit: None,
                                detail: Some(
                                    "exec -c runs the command with an empty environment".into(),
                                ),
                            },
                            CoverageLevel::Partial,
                        );
                    }
                    terminates = Some(Termination::Exec);
                    let (execution, eligible) =
                        self.run_command(builder, env, cmd, &converted[start..], stdin);
                    model_eligible |= eligible;
                    execution
                }
                None => None,
            },
            Some("exit") => {
                terminates = Some(Termination::Exit);
                None
            }
            Some("return") => {
                if env.sourced || !env.active.is_empty() {
                    terminates = Some(Termination::Return);
                }
                None
            }
            // POSIX `command` suppresses function lookup and runs the operand
            // as an external. `-v`/`-V` only look the name up and do not run it.
            Some("command") => {
                if let Some(rest) = command_wrapper_operand(converted) {
                    // A `hash -p` binding still names the program; only `-p`,
                    // which searches the default PATH, bypasses it.
                    let default_path = converted[1..converted.len() - rest.len()]
                        .iter()
                        .any(|word| word.word.as_literal() == Some("-p"));
                    let mut rest = rest.to_vec();
                    if !default_path
                        && let Some(path) = rest[0]
                            .word
                            .as_literal()
                            .and_then(|name| env.hashed.get(name))
                    {
                        rest[0].word = Word::literal(path);
                    }
                    let (execution, eligible) = if default_path {
                        // bash binds PATH to the standard path while the
                        // operand runs, so neither the script's PATH nor a
                        // prefix assignment selects the program. Like an
                        // unset ambient PATH, the standard one names it.
                        let mut standard = cmd.clone();
                        standard
                            .assignments
                            .retain(|assignment| assignment.name != "PATH");
                        let saved = (
                            env.vars.remove("PATH"),
                            env.unset.remove("PATH"),
                            env.exported.remove("PATH"),
                            env.unexported.remove("PATH"),
                        );
                        let ran = self.run_command(builder, env, &standard, &rest, stdin);
                        if let Some(entry) = saved.0 {
                            env.vars.insert("PATH".to_string(), entry);
                        }
                        for (restore, set) in [
                            (saved.1, &mut env.unset),
                            (saved.2, &mut env.exported),
                            (saved.3, &mut env.unexported),
                        ] {
                            if restore {
                                set.insert("PATH".to_string());
                            }
                        }
                        ran
                    } else {
                        self.run_command(builder, env, cmd, &rest, stdin)
                    };
                    model_eligible |= eligible;
                    execution
                } else {
                    None
                }
            }
            // `source`/`.` runs another file in the current shell environment.
            // Only a caller-admitted repository file may be followed.
            Some("source") | Some(".") => {
                terminates = self.source_file(builder, env, converted, stdin, persist, conditional);
                None
            }
            Some("eval") => {
                // Prefix assignments are part of a special builtin's environment and
                // must be visible while eval runs. Bash restores those bindings after
                // eval, while mutations to other names made by its body persist.
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
                self.eval_builtin(builder, env, cmd, converted, persist);
                for (name, variable, array, exported, unexported, unset, unexported_node) in
                    prior_bindings
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
                None
            }
            // `trap ACTION [SIGNAL...]` defers ACTION — a shell command string —
            // to run when a signal fires. Analyze ACTION as nested shell so a
            // deferred command (`trap 'rm -rf ~' EXIT`) is not dropped. `-` and
            // `''` reset or ignore the trap and carry no effect. A leading `--`
            // ends options, so the action is the word after it.
            Some("trap") => {
                let action_index =
                    if converted.get(1).and_then(|word| word.word.as_literal()) == Some("--") {
                        2
                    } else {
                        1
                    };
                if let Some(action) = converted.get(action_index) {
                    match action.word.as_literal() {
                        Some("-") | Some("") => {}
                        Some(code) => {
                            self.nested_shell_source(
                                builder,
                                env,
                                code,
                                action.span,
                                NestedShellMode::Child,
                            );
                        }
                        None => self.opaque_boundary(
                            builder,
                            BoundaryReason::UNRESOLVED_TRAP_ACTION,
                            BoundaryClass::Unresolved,
                            "trap action not statically recoverable",
                            action.span,
                        ),
                    }
                }
                None
            }
            Some("") => None,
            Some(builtin) if EFFECTLESS_BUILTINS.contains(&builtin) => None,
            _ => {
                let (execution, eligible) = self.run_command(builder, env, cmd, converted, stdin);
                model_eligible |= eligible;
                execution
            }
        };
        // Work the command launched is only known to have run on success.
        let launched = builder.control_launched();
        let facts = SiteFacts {
            success: launched,
            ..SiteFacts::known(Vec::new())
        };
        (execution, terminates, facts, model_eligible)
    }

    /// Run a command whose name earlier branch paths bound differently once
    /// per path, under that path's condition. Alias expansion comes first,
    /// then functions, then `hash -p`; each dispatch resolves the next table.
    #[allow(clippy::too_many_arguments)]
    #[inline(never)]
    fn dispatch_path_bindings(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        cmd: &Simple,
        converted: &[Converted],
        name: &str,
        first_retained_token: Option<usize>,
        stdin: Option<&StdinValue>,
        persist: bool,
        guarded: bool,
    ) -> Option<(
        Option<ExecutionNodeRef>,
        Option<Termination>,
        SiteFacts,
        bool,
    )> {
        let mut dispatch = |builder: &mut PlanBuilder, env: &mut ShellEnv| {
            self.dispatch_argv(
                builder,
                env,
                cmd,
                converted,
                Some(name),
                first_retained_token,
                stdin,
                persist,
                true,
                guarded,
            )
        };
        if let Some(bindings) = env.alias_alternatives.remove(name) {
            let saved = env.aliases.get(name).cloned();
            let dispatched = each_path(
                builder,
                env,
                &bindings,
                persist,
                &mut dispatch,
                |env, alias| {
                    match alias {
                        Some(alias) => env.aliases.insert(name.to_string(), alias.clone()),
                        None => env.aliases.remove(name),
                    };
                },
            );
            match saved {
                Some(alias) => env.aliases.insert(name.to_string(), alias),
                None => env.aliases.remove(name),
            };
            env.alias_alternatives.insert(name.to_string(), bindings);
            return Some(dispatched);
        }
        if let Some(bindings) = env.function_alternatives.remove(name) {
            // A path that leaves the name unbound runs what the name resolves
            // to without the function. A name nothing else resolves to would
            // only fail there, so that path adds no command.
            let resolves = super::shell_builtin(name) || self.nest.catalog.find(name).is_some();
            let mut paths = bindings
                .iter()
                .filter(|((function, _), _)| resolves || function.is_some())
                .cloned()
                .collect::<Vec<_>>();
            if paths.is_empty() {
                paths.clone_from(&bindings);
            }
            let saved = (
                env.functions.get(name).cloned(),
                env.readonly_functions.contains(name),
            );
            let install = |env: &mut ShellEnv, (function, readonly): &FunctionBinding| {
                match function {
                    Some(function) => env.functions.insert(name.to_string(), Rc::clone(function)),
                    None => env.functions.remove(name),
                };
                if *readonly {
                    env.readonly_functions.insert(name.to_string());
                } else {
                    env.readonly_functions.remove(name);
                }
            };
            let dispatched = each_path(builder, env, &paths, persist, &mut dispatch, install);
            install(env, &saved);
            env.function_alternatives.insert(name.to_string(), bindings);
            return Some(dispatched);
        }
        if let Some(bindings) = env.hash_alternatives.remove(name) {
            let saved = env.hashed.get(name).cloned();
            let install = |env: &mut ShellEnv, path: &Option<String>| {
                match path {
                    Some(path) => env.hashed.insert(name.to_string(), path.clone()),
                    None => env.hashed.remove(name),
                };
            };
            let dispatched = each_path(builder, env, &bindings, persist, &mut dispatch, install);
            install(env, &saved);
            env.hash_alternatives.insert(name.to_string(), bindings);
            return Some(dispatched);
        }
        None
    }

    /// Walk a previously defined function's body at this call site with the
    /// call's converted arguments as its positional parameters. Cycles
    /// (the name is already on the walk stack) stop without re-entering but
    /// leave the shell's unbounded re-execution as evidence; deep non-cyclic
    /// chains use the shell function bound.
    #[allow(clippy::too_many_arguments)]
    fn call_function(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        name: &str,
        entry: &FnEntry,
        args: &[Converted],
        call: &Simple,
        persist: bool,
        conditional: bool,
        guarded: bool,
    ) -> (Option<Requirements>, Option<Termination>) {
        let span = call.span;
        if let Some(cycle) = env.active.iter().position(|frame| frame.0 == name) {
            // The body was already walked by the outer call, so only the
            // shell re-entering it is new. Only a cycle crossing a background
            // launch through invariant bodies certifies process growth.
            let node = self.span_node(builder, span);
            let mut attributes = BTreeMap::from([(
                "source".to_string(),
                AttrValue::String("function".to_string()),
            )]);
            if env.background_depth > env.active[cycle].1
                && env.active[cycle..].iter().all(|frame| {
                    jobs::invariant_recursion(&frame.2, &|name| {
                        env.active[cycle..].iter().any(|frame| frame.0 == name)
                    })
                })
            {
                attributes.insert(
                    "process_growth".into(),
                    AttrValue::String("unbounded_background_recursion".into()),
                );
            }
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
                attributes,
                modality: Modality::May,
                realm: effinterp_proto::ExecutionRealm::Host,
                condition: None,
                execution: effinterp_proto::ExecutionNodeRef(0),
                provenance: vec![node],
            });
            degrade_nested(builder);
            builder.boundary(Boundary {
                reason: BoundaryReason::EXECUTION_CYCLE,
                class: BoundaryClass::Limit,
                scope: effinterp_proto::BoundaryScope::Invocation,
                affected_resource: None,
                callee: None,
                domains: KNOWN_DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
                provenance: vec![node],
                limit: None,
                detail: Some(format!("shell function {name:?} re-entered while active")),
            });
            return (None, None);
        }
        if env.active.len() as u64 >= self.nest.limits.max_shell_function_depth {
            if self.nest.budget.note_function_depth_saturated() {
                let node = self.span_node(builder, span);
                degrade_nested(builder);
                builder.boundary(Boundary {
                    reason: BoundaryReason::LIMIT_SATURATED,
                    class: BoundaryClass::Limit,
                    scope: effinterp_proto::BoundaryScope::Invocation,
                    affected_resource: None,
                    callee: None,
                    domains: KNOWN_DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
                    provenance: vec![node],
                    limit: Some("max_shell_function_depth".to_string()),
                    detail: None,
                });
            }
            return (None, None);
        }
        // Spans in the body are relative to the definition's source, which
        // may differ from this call site (e.g. a substitution inheriting
        // functions from the surrounding script).
        let callee = Shell {
            nest: self.nest,
            source: entry.source.as_ref(),
            source_digest: Rc::clone(&entry.source_digest),
            scope: entry.scope,
            depth: self.depth,
        };
        let saved_redirs = env.redirections.clone();
        let saved_sockets = env.socket_fds.clone();
        // `f >dest` opens dest before the body runs, so the body's commands
        // write through it, as they do through the definition's own
        // redirections, which apply after the call's. Here-documents keep
        // their bytes in the calling command, which opens them afterwards.
        let mut redirected = Vec::new();
        // Held out of the environment while the body runs, so a nested call's
        // own redirections cannot take its place; restored on every return.
        let mut call_slot = None;
        if !call.redirs.is_empty()
            && call
                .redirs
                .iter()
                .all(|redir| !matches!(redir.kind, RedirKind::HereDoc | RedirKind::HereString))
        {
            let reuse = env
                .call_redirects
                .as_ref()
                .filter(|(source, at, _)| *at == span && Rc::ptr_eq(source, &self.source_digest))
                .map(|(_, _, redirects)| redirects.clone());
            let redirects = reuse.unwrap_or_else(|| {
                let effect_start = builder.effects_len();
                self.redirects(
                    builder,
                    env,
                    call,
                    false,
                    persist,
                    conditional,
                    guarded,
                    &HashMap::new(),
                    None,
                    effect_start,
                )
            });
            env.redirections.extend(redirects.flows.clone());
            redirected.extend(redirects.flows.clone());
            call_slot = Some((Rc::clone(&self.source_digest), span, redirects));
        }
        redirected.extend(if entry.redirs.is_empty() {
            Vec::new()
        } else {
            let command = Simple {
                assignments: Vec::new(),
                words: Vec::new(),
                redirs: entry.redirs.clone(),
                compound_redirects: false,
                span,
            };
            let effect_start = builder.effects_len();
            let redirects = callee.redirects(
                builder,
                env,
                &command,
                false,
                false,
                conditional,
                false,
                &HashMap::new(),
                None,
                effect_start,
            );
            env.redirections.extend(redirects.flows.clone());
            redirects.flows
        });
        let mut termination = None;
        let functions = super::defined_functions(&entry.body, env);
        builder.control_enter(entry.source.as_ref(), false, |graph| {
            super::control::build(
                graph,
                entry.source.as_ref(),
                &entry.body,
                super::control::Callable::Function,
                &|name| functions.contains(name),
            )
        });
        if persist {
            let previous_source =
                std::mem::replace(&mut env.script_source, entry.source_origin.clone());
            env.active.push((
                name.to_string(),
                env.background_depth,
                Rc::clone(&entry.body),
            ));
            env.local_frames.push(HashMap::new());
            env.attribute_frames.push(HashMap::new());
            let saved = env.positional.replace(args.to_vec());
            let saved_changed = env.positional_set_changed;
            env.positional_set_changed = Some(false);
            let saved_aliases = std::mem::replace(&mut env.aliases, entry.aliases.clone());
            let saved_expand_aliases =
                std::mem::replace(&mut env.expand_aliases, entry.expand_aliases);
            if conditional {
                // The whole call is a may-region: names its body assigns
                // stop suppressing environment reads once it returns.
                let before = script_set_names(env);
                let previous_call = builder.enter_condition_call(&effinterp_proto::stable_hash(
                    effinterp_proto::CONDITION_SITE_HASH_DOMAIN,
                    &(self.source_digest.as_ref(), span.start, span.end),
                ));
                termination = callee.walk(builder, env, &entry.body, true, 0);
                builder.leave_condition_call(previous_call);
                downgrade_script_set(env, &before);
            } else {
                let previous_call = builder.enter_condition_call(&effinterp_proto::stable_hash(
                    effinterp_proto::CONDITION_SITE_HASH_DOMAIN,
                    &(self.source_digest.as_ref(), span.start, span.end),
                ));
                termination = callee.walk(builder, env, &entry.body, false, 0);
                builder.leave_condition_call(previous_call);
            }
            // Aliases the body defined or enabled persist in the caller.
            for (alias, definition) in std::mem::replace(&mut env.aliases, saved_aliases) {
                if entry.aliases.get(&alias) != Some(&definition) {
                    env.aliases.insert(alias, definition);
                }
            }
            if env.expand_aliases == entry.expand_aliases {
                env.expand_aliases = saved_expand_aliases;
            }
            for (name, attributes) in env.attribute_frames.pop().unwrap() {
                match attributes {
                    Some(attributes) => env.value_attributes.insert(name, attributes),
                    None => env.value_attributes.remove(&name),
                };
            }
            for (name, (scalar, array)) in env.local_frames.pop().unwrap() {
                match scalar {
                    Some(entry) => {
                        env.vars.insert(name.clone(), entry);
                    }
                    None => {
                        env.vars.remove(&name);
                    }
                }
                match array {
                    Some(value) => {
                        env.arrays.insert(name, value);
                    }
                    None => {
                        env.arrays.remove(&name);
                    }
                }
            }
            env.positional = saved;
            env.positional_set_changed = if conditional && saved_changed != Some(false) {
                None
            } else {
                Some(false)
            };
            env.active.pop();
            env.script_source = previous_source;
        } else {
            let referenced_inputs = if env.function_heads_only {
                let mut memos = env.saturation_memos.borrow_mut();
                if memos.function_env_clones >= MAX_SATURATED_COMMAND_HEADS {
                    env.redirections = saved_redirs;
                    env.socket_fds = saved_sockets;
                    builder.control_leave();
                    if call_slot.is_some() {
                        env.call_redirects = call_slot;
                    }
                    return (None, None);
                }
                memos.function_env_clones += 1;
                let refs = entry.saturated_inputs.get_or_init(|| {
                    referenced_inputs_with_substitutions(
                        &entry.body,
                        self.nest
                            .limits
                            .max_execution_depth
                            .min(MAX_WALK_DEPTH as u64) as u32,
                    )
                });
                let Some((variables, functions, work)) = expanded_referenced_inputs_bounded(
                    &refs.vars,
                    &refs.calls,
                    &refs.command_vars,
                    &refs.command_head_patterns,
                    env,
                    self.nest
                        .limits
                        .max_shell_function_depth
                        .saturating_sub(env.active.len() as u64 + 1),
                    MAX_SATURATED_FUNCTION_STEPS.saturating_sub(memos.function_steps),
                ) else {
                    memos.function_steps = MAX_SATURATED_FUNCTION_STEPS;
                    drop(memos);
                    env.redirections = saved_redirs;
                    env.socket_fds = saved_sockets;
                    builder.control_leave();
                    if call_slot.is_some() {
                        env.call_redirects = call_slot;
                    }
                    return (None, None);
                };
                memos.function_steps += work;
                Some((variables, functions))
            } else {
                None
            };
            let mut child = match &referenced_inputs {
                Some((variables, functions)) => self.child_env_with_inputs(
                    env,
                    Some(variables),
                    Some(functions),
                    Some(args.to_vec()),
                ),
                None => self.child_env(env),
            };
            // A function runs in the caller's process.
            child.pid_is_own = env.pid_is_own;
            child.script_source = entry.source_origin.clone();
            child.aliases = entry.aliases.clone();
            child.expand_aliases = entry.expand_aliases;
            child.active.push((
                name.to_string(),
                child.background_depth,
                Rc::clone(&entry.body),
            ));
            child.positional_set_changed = Some(false);
            if referenced_inputs.is_none() {
                child.positional = Some(args.to_vec());
            }
            let previous_call = builder.enter_condition_call(&effinterp_proto::stable_hash(
                effinterp_proto::CONDITION_SITE_HASH_DOMAIN,
                &(self.source_digest.as_ref(), span.start, span.end),
            ));
            callee.walk(builder, &mut child, &entry.body, conditional, 0);
            builder.leave_condition_call(previous_call);
        }
        if !redirected.is_empty() {
            env.redirections
                .extend(crate::flow::restore_descriptors(&saved_redirs, &redirected));
            for redir in &redirected {
                if let Some(socket) = saved_sockets.get(&redir.fd) {
                    env.socket_fds.insert(redir.fd, socket.clone());
                } else {
                    env.socket_fds.remove(&redir.fd);
                }
            }
        }
        if call_slot.is_some() {
            env.call_redirects = call_slot;
        }
        let requirements = builder
            .control_leave()
            .map(|finished| finished.requirements);
        (
            requirements,
            termination
                .map(|(kind, _)| kind)
                .filter(|kind| *kind != Termination::Return),
        )
    }

    /// Register what this command's evaluation proves. The shell opens the
    /// first redirection before anything else can fail; later ones, and the
    /// command's own work, are only known to have run when it succeeded.
    pub(super) fn register_control(
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

    fn command(
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
                self.command(builder, &mut child, cmd, converted, stdin);
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

    /// Wire def-use edges for argv words carrying a produced value. Effects
    /// attributed to an argument consume it directly; other same-execution
    /// effects consume it too, except process identities and code execution.
    /// Curl and wget also bind request-body and header arguments onto their
    /// network effects (those are attributed to the URL) and keep TLS and
    /// cookie-file config arguments off that same-execution fallback.
    fn wire_arg_producers(
        &self,
        builder: &mut PlanBuilder,
        span: ShellSpan,
        execution: Option<ExecutionNodeRef>,
        converted: &[Converted],
        eff_start: usize,
        eff_end: usize,
    ) {
        if eff_end <= eff_start {
            return;
        }
        let carrying: Vec<(u32, &Vec<FlowRef>)> = converted
            .iter()
            .enumerate()
            .skip(1)
            .filter(|(_, c)| !c.producers.is_empty())
            .map(|(n, c)| (n as u32, &c.producers))
            .collect();
        if carrying.is_empty() {
            return;
        }
        // The request flow of each curl/wget this command runs, keyed to its
        // own execution. The direct case is the command itself; the nested
        // cases are the invocations wrappers launch, read from the modeled
        // argv and mapped back to the outer words through the forwarding the
        // wrapper recorded, so no wrapper needs its own peeling rule.
        let requests = request_invocations(builder, converted, execution, eff_start, eff_end);
        let consumes_argument = |effect: u32, argument: u32| {
            // Listings consume the selected environment values, not every wrapper argument.
            if crate::flow::environment_stdout_effect(builder, effect) {
                return false;
            }
            let effect_execution = builder.effect_execution(effect as usize);
            let operation = builder.effect_operation(effect as usize);
            let network = operation.is_some_and(|operation| operation.starts_with("network."));
            // Output paths and local configuration filenames are inputs to the
            // transfer, not bytes it sends. Never bind them onto their
            // request's network effect, even though the transfer depends on
            // the file they name and the request reaches this argument through
            // its own forwarding.
            if network
                && requests.iter().any(|request| {
                    request.execution == effect_execution
                        && (request.config.contains(&argument)
                            || request.output.contains(&argument))
                })
            {
                return false;
            }
            // A direct index match only holds within the invocation whose
            // arguments these are; a descendant reuses the same indices for
            // its own words, so it is reached only through the forwarded
            // provenance that traces back to this argument.
            let direct = builder.effect_has_argument(effect as usize, argument)
                && execution.is_none_or(|execution| effect_execution == Some(execution));
            if direct
                || execution.is_some_and(|execution| {
                    builder.effect_has_forwarded_argument(effect as usize, argument, execution)
                })
            {
                return true;
            }
            // A request's body or header substitution binds to that request's
            // own network effect alone; a second, independent invocation's
            // effect must not consume the first's header or body.
            for request in &requests {
                if request.execution != effect_execution {
                    continue;
                }
                if operation == Some("network.upload") && request.body.contains(&argument)
                    || network && request.headers.contains(&argument)
                {
                    return true;
                }
            }
            // Anything else a substitution reaches is bound only within this
            // command's own execution, never a nested invocation whose own
            // words this argument never became. Request config values
            // (certificates, cookie files) configure the transfer and are
            // never carried by any of its effects; output values still reach
            // the local write they name, excluded above only from the network
            // effect.
            let outer_same_execution =
                !matches!(operation, Some("process.exec" | "process.code_execution"))
                    && execution.is_some_and(|execution| effect_execution == Some(execution));
            let outer_config = requests
                .iter()
                .filter(|request| request.execution == execution)
                .any(|request| request.config.contains(&argument));
            outer_same_execution && !outer_config
        };
        let effects: Vec<u32> = (eff_start as u32..eff_end as u32)
            .filter(|effect| {
                carrying
                    .iter()
                    .any(|(arg, _)| consumes_argument(*effect, *arg))
            })
            .collect();
        if effects.is_empty() {
            return;
        }
        let carrying = carrying
            .into_iter()
            .filter(|(arg, _)| {
                effects
                    .iter()
                    .any(|effect| consumes_argument(*effect, *arg))
            })
            .collect::<Vec<_>>();
        let mut bindings = Vec::new();
        for (arg, _) in &carrying {
            for &e in &effects {
                if consumes_argument(e, *arg) {
                    bindings.push(PortBinding {
                        assurance: effinterp_proto::CausalAssurance::Conservative,
                        from: BindEnd::Port(Port::Arg(*arg)),
                        to: BindEnd::Effect(e),
                    });
                }
            }
        }
        let node = self.span_node(builder, span);
        let consumer = builder.pending_flow_stage(FlowStage {
            execution,
            effects,
            bindings,
            provenance: vec![node],
        });
        for (arg, producers) in carrying {
            for producer in producers {
                builder.pending_flow_edge(Flow {
                    assurance: effinterp_proto::CausalAssurance::Exact,
                    from: producer.clone(),
                    to: FlowRef {
                        stage: consumer as u32,
                        port: Port::Arg(arg),
                    },
                    reason: FlowReason::new("data_flow"),
                    provenance: Vec::new(),
                });
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn wire_code_producers(
        &self,
        builder: &mut PlanBuilder,
        span: ShellSpan,
        execution: Option<ExecutionNodeRef>,
        producers: &[FlowRef],
        eff_start: usize,
        eff_end: usize,
        stdin_code_only: bool,
    ) {
        if producers.is_empty() {
            return;
        }
        let effects = (eff_start as u32..eff_end as u32)
            .filter(|effect| {
                builder.effect_operation(*effect as usize) == Some("process.code_execution")
                    && (!stdin_code_only
                        || matches!(
                            builder.effect_string_attribute(*effect as usize, "source"),
                            Some("stdin" | "interactive")
                        ))
            })
            .collect::<Vec<_>>();
        if effects.is_empty() {
            return;
        }
        let bindings = effects
            .iter()
            .map(|effect| PortBinding {
                assurance: effinterp_proto::CausalAssurance::Exact,
                from: BindEnd::Port(Port::Code),
                to: BindEnd::Effect(*effect),
            })
            .collect();
        let node = self.span_node(builder, span);
        let consumer = builder.pending_flow_stage(FlowStage {
            execution,
            effects,
            bindings,
            provenance: vec![node],
        });
        for producer in producers {
            builder.pending_flow_edge(Flow {
                assurance: effinterp_proto::CausalAssurance::Exact,
                from: producer.clone(),
                to: FlowRef {
                    stage: consumer as u32,
                    port: Port::Code,
                },
                reason: FlowReason::new("code input"),
                provenance: Vec::new(),
            });
        }
    }

    /// Analyze `converted` as an external command, trying each possible head
    /// when the first word is a variable that may be one of several literals.
    fn run_command(
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
                self.command(builder, env, cmd, converted, stdin)
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
                let candidate = self.command(builder, env, cmd, &words, stdin);
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
        self.command(builder, env, cmd, converted, stdin)
    }

    /// The text an alias expands to here: aliases are enabled, the name is
    /// aliased, and the shell read the definition on an earlier line.
    fn alias_expansion(&self, env: &ShellEnv, name: &str, span: ShellSpan) -> Option<String> {
        self.alias_chain(env, name, span).map(|(text, _)| text)
    }

    /// The alias text as `alias_expansion` gives it, with the names expanded
    /// to reach it.
    fn alias_chain(
        &self,
        env: &ShellEnv,
        name: &str,
        span: ShellSpan,
    ) -> Option<(String, Vec<String>)> {
        if !env.expand_aliases {
            return None;
        }
        let defined_before = |name: &str| {
            let (text, defined_end) = env.aliases.get(name)?;
            if *defined_end == super::ALIAS_IN_EFFECT {
                return Some(text.clone());
            }
            let between = self
                .source
                .get(*defined_end as usize..span.start as usize)?;
            between.contains('\n').then(|| text.clone())
        };
        // The first word of an expansion is itself expanded, except an alias
        // already being expanded (`alias a=b b='rm -rf /'`).
        let mut text = defined_before(name)?;
        let mut expanding = vec![name.to_string()];
        loop {
            let trimmed = text.trim_start();
            let (head, rest) = trimmed
                .split_once([' ', '\t'])
                .map_or((trimmed, ""), |(head, rest)| (head, rest));
            if expanding.iter().any(|seen| seen == head) {
                return Some((text, expanding));
            }
            let Some(inner) = defined_before(head) else {
                return Some((text, expanding));
            };
            expanding.push(head.to_string());
            text = if trimmed.len() == head.len() {
                inner
            } else {
                format!("{inner} {rest}")
            };
        }
    }

    pub(super) fn defer_process(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        source: &str,
        span: ShellSpan,
    ) -> Option<u32> {
        if !self.charge(builder, 1, source.len() as u64, span)
            || self.structural_saturated(builder, env)
        {
            return None;
        }
        let node = self.span_node(builder, span);
        let stage = builder.pending_flow_stage(FlowStage {
            execution: None,
            effects: Vec::new(),
            bindings: Vec::new(),
            provenance: vec![node],
        }) as u32;
        builder.keep_pending_flow_stage(stage);
        let mut child = self.child_env(env);
        child.capture_stdout();
        child.socket_fds.remove(&Descriptor::Number(0));
        child.redirections.push(crate::flow::Redirection {
            role: crate::flow::RedirRole::Inherited(Descriptor::Number(0)),
            fd: Descriptor::Number(0),
            dup: None,
            both: false,
            read_effect: None,
            write_effect: None,
        });
        child.stdout_channel = Some(stage);
        env.channel_bytes
            .borrow_mut()
            .insert(stage, Some(String::new()));
        env.deferred.push(DeferredProcess {
            source: source.into(),
            span,
            stage,
            child: Box::new(child),
            condition: builder.current_condition(),
        });
        Some(stage)
    }

    pub(super) fn coprocess(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        name: Option<&str>,
        span: ShellSpan,
        conditional: bool,
    ) {
        let source = &self.source[span.start as usize..span.end as usize];
        let Some(stage) = self.defer_process(builder, env, source, span) else {
            return;
        };
        let child = &mut env.deferred.last_mut().unwrap().child;
        child.close_coprocess_descriptors();
        // A coprocess is an asynchronous job, so recursion through it grows
        // processes like a `&` job does.
        child.background_depth += 1;
        let Some(name) = name else {
            for array in env.arrays.values_mut() {
                *array = ArrayValue::Unknown(Vec::new());
            }
            env.channel_bytes.borrow_mut().insert(stage, None);
            self.opaque_boundary(
                builder,
                BoundaryReason::UNRESOLVED_SOURCE,
                BoundaryClass::Unresolved,
                "coprocess descriptor array name is dynamic",
                span,
            );
            return;
        };
        let mut elements = Vec::new();
        for end in ["read", "write"] {
            let span_node = self.span_node(builder, span);
            let node = builder.node(
                ProvenanceKind::ModelApplication {
                    model: format!("shell/coproc/{end}@v0"),
                },
                &[span_node],
            );
            let descriptor = Descriptor::Allocated(node);
            env.coprocess_fds.push(descriptor);
            env.descriptor_values
                .push((descriptor_word(descriptor), descriptor));
            env.redirections.push(crate::flow::Redirection {
                role: crate::flow::RedirRole::Channel {
                    stage,
                    read: end == "read",
                    write: end == "write",
                },
                fd: descriptor,
                dup: None,
                both: false,
                read_effect: None,
                write_effect: None,
            });
            elements.push(Converted {
                word: descriptor_word(descriptor),
                raw: String::new(),
                span,
                assign_nodes: vec![node],
                producers: Vec::new(),
                alts: Vec::new(),
                pending_assigns: Vec::new(),
                unresolved_default_override: false,
                unquoted_substitution: false,
                captured_name_hidden: false,
                quoted_substitution: false,
            });
        }
        if conditional {
            env.arrays
                .insert(name.into(), ArrayValue::Unknown(Vec::new()));
            self.opaque_boundary(
                builder,
                BoundaryReason::UNSUPPORTED_SHELL_SYNTAX,
                BoundaryClass::Unresolved,
                "conditional coprocess descriptors are unresolved",
                span,
            );
        } else {
            env.arrays
                .insert(name.into(), ArrayValue::Definite(elements));
        }
    }

    pub(super) fn finish_deferred(&self, builder: &mut PlanBuilder, env: &mut ShellEnv) {
        for mut process in std::mem::take(&mut env.deferred) {
            let node = self.span_node(builder, process.span);
            if let Some(condition) = &process.condition {
                builder.push_condition(condition.clone());
            }
            let transition = Transition::file(Subject::Shell {
                source: process.source.clone(),
                cwd: process.child.cwd.clone(),
                context: Default::default(),
            })
            .kind(effinterp_proto::ExecutionEdgeKind::Launch)
            .cwd(process.child.cwd_resource.clone(), process.child.cwd_node)
            .streams(effinterp_proto::ExecutionStreams::default());
            if let Some(frame) = self.nest.begin(builder, transition, &[node], self.depth) {
                let content = env
                    .channel_bytes
                    .borrow()
                    .get(&process.stage)
                    .cloned()
                    .flatten();
                process.child.stdin = Some(StdinValue {
                    paths: None,
                    piped: true,
                    file: None,
                    word: content
                        .map(Word::literal)
                        .unwrap_or_else(|| Word::new(vec![WordPart::Unknown])),
                    provenance: vec![node],
                });
                analyze_shell_with_env(
                    builder,
                    self.nest,
                    &process.source,
                    &mut process.child,
                    Some(frame.scope),
                    self.depth + 1,
                );
                let selection = env
                    .channel_selections
                    .borrow()
                    .get(&process.stage)
                    .copied()
                    .flatten();
                builder.settle_channel_arguments(process.stage, selection);
                let child = builder.pending_flow_stage(FlowStage {
                    execution: Some(frame.execution),
                    effects: Vec::new(),
                    bindings: Vec::new(),
                    provenance: vec![node],
                }) as u32;
                for port in [Port::Stdin, Port::Stdout] {
                    let channel = FlowRef {
                        stage: process.stage,
                        port: port.clone(),
                    };
                    let child = FlowRef {
                        stage: child,
                        port: port.clone(),
                    };
                    let (from, to) = if port == Port::Stdin {
                        (channel, child)
                    } else {
                        (child, channel)
                    };
                    builder.pending_flow_edge(Flow {
                        assurance: effinterp_proto::CausalAssurance::Exact,
                        from,
                        to,
                        reason: FlowReason::new("descriptor child"),
                        provenance: vec![node],
                    });
                }
                frame.end(builder);
            }
            if process.condition.is_some() {
                builder.pop_condition();
            }
        }
    }

    fn nested_shell_source(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        source: &str,
        span: ShellSpan,
        mode: NestedShellMode,
    ) -> Option<ExecutionNodeRef> {
        let span_node = self.span_node(builder, span);
        if self.structural_saturated(builder, env) {
            // Retaining heads after saturation still recurses into the
            // substitution body, so the execution depth bound applies here
            // exactly as it does to a charged nested transition.
            if self.depth + 1 >= self.nest.limits.max_execution_depth {
                if !env.saturated_substitution_recorded {
                    env.saturated_substitution_recorded = true;
                    self.nest.record_refused_nested_with_cwd(
                        builder,
                        Subject::Shell {
                            source: source.to_string(),
                            cwd: env.cwd.clone(),
                            context: Default::default(),
                        },
                        &[span_node],
                        self.depth,
                        env.cwd_resource.clone(),
                        env.cwd_node,
                    );
                }
                return None;
            }
            let scope = if self.nest.budget.exhausted() || builder.execution_saturated() {
                if env.saturated_substitution_recorded {
                    Some(span_node)
                } else {
                    env.saturated_substitution_recorded = true;
                    self.nest.record_refused_nested_with_cwd(
                        builder,
                        Subject::Shell {
                            source: source.to_string(),
                            cwd: env.cwd.clone(),
                            context: Default::default(),
                        },
                        &[span_node],
                        self.depth,
                        env.cwd_resource.clone(),
                        env.cwd_node,
                    )
                }
            } else {
                Some(span_node)
            };
            if let Some(scope) = scope {
                let mut child = self.saturated_substitution_env(env, source)?;
                if matches!(mode, NestedShellMode::Capture) {
                    child.capture_stdout();
                }
                analyze_shell_at(
                    builder,
                    self.nest,
                    source,
                    child,
                    Some(scope),
                    self.depth + 1,
                );
            }
            return None;
        }
        let frame = self.nest.begin(
            builder,
            Transition::file(Subject::Shell {
                source: source.to_string(),
                cwd: env.cwd.clone(),
                context: Default::default(),
            })
            .cwd(env.cwd_resource.clone(), env.cwd_node)
            .streams({
                let mut streams = builder.inherited_execution_streams();
                if matches!(mode, NestedShellMode::Capture) {
                    streams.stdout = None;
                }
                streams
            }),
            &[span_node],
            self.depth,
        )?;
        let nested_scope = frame.scope;
        let nested_execution = builder.current_execution();
        if matches!(mode, NestedShellMode::Persist) {
            let aliases = env.aliases.clone();
            analyze_shell_with_env(
                builder,
                self.nest,
                source,
                env,
                Some(nested_scope),
                self.depth + 1,
            );
            env.anchor_new_aliases(&aliases, span.end);
        } else {
            let mut child = self.child_env(env);
            if matches!(mode, NestedShellMode::Capture) {
                child.capture_stdout();
            }
            analyze_shell_with_env(
                builder,
                self.nest,
                source,
                &mut child,
                Some(nested_scope),
                self.depth + 1,
            );
        }
        frame.end(builder);
        Some(nested_execution)
    }
}

enum NestedShellMode {
    Persist,
    Child,
    Capture,
}

fn captured_program_name(word: &Word) -> Option<&str> {
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

/// Whether a word is text already visible in the source: every segment is a
/// literal and no glob or brace metacharacter can expand it to something else.
/// A command substitution, parameter expansion, arithmetic, or process
/// substitution segment makes the word's value depend on runtime state. When
/// the substitution's output is consumed by a quoted head (`"$(printf '%s'
/// {l,s})"`), that head is one word no expansion can split or rewrite, so a
/// metacharacter there is delivered verbatim and stays source-visible.
fn word_is_source_literal(tok: &WordTok, head_quoted: bool) -> bool {
    tok.segs.iter().all(|seg| match seg {
        Seg::Literal { text, quoted } => {
            head_quoted || *quoted || !text.contains(['*', '?', '[', '{', '}'])
        }
        _ => false,
    })
}

/// Whether a command substitution used as a program name hides that name
/// behind a transformation. The only transparent producers pass a
/// source-visible literal through unchanged: `echo`/`printf` with literal
/// argument words, or `cat` of a here-string or heredoc literal. A file read
/// (`cat FILE`, `cat < FILE`), a nested substitution, a multi-stage pipeline,
/// `rev`, `tr`, `which`, `command -v`, or any other producer conceals the name.
/// An unparseable or unrecognized producer is treated as hiding. `head_quoted`
/// is the quoting of the substitution where it is consumed: under a quoted head
/// a producer metacharacter cannot expand, so it does not conceal the name.
fn substitution_hides_name(source: &str, head_quoted: bool) -> bool {
    let lexed = lex::lex(source);
    if lexed.error.is_some() {
        return true;
    }
    let items = parse::parse_shell_items(&lexed.toks, source.len() as u32);
    // A transparent producer is one single-stage pipeline, so a `|` between
    // stages or a `&&`/`||` between commands already conceals the name.
    let [
        ShellItem::Pipeline {
            cmds,
            short_circuit: None,
            ..
        },
    ] = items.as_slice()
    else {
        return true;
    };
    let [cmd] = cmds.as_slice() else {
        return true;
    };
    let Some(name) = cmd.words.first().and_then(parse::literal_text) else {
        return true;
    };
    let transparent = match name.as_str() {
        // Only literal argument words are visible; a nested `$(...)` or a
        // parameter expansion in an argument hides what is printed.
        "echo" | "printf" => cmd.words[1..]
            .iter()
            .all(|word| word_is_source_literal(word, head_quoted)),
        // A here-string or heredoc body is source text; a file operand or an
        // input redirection reads bytes the source never shows.
        "cat" => {
            cmd.words.len() == 1
                && !cmd.redirs.is_empty()
                && cmd.redirs.iter().all(|redir| match redir.kind {
                    RedirKind::HereString => redir
                        .target
                        .as_ref()
                        .is_some_and(|target| word_is_source_literal(target, head_quoted)),
                    // A heredoc body is source-visible only when it cannot
                    // expand: a quoted delimiter, or a body whose `$`/backtick
                    // are all backslash-escaped. `cat <<EOF\n$(which rm)\nEOF`
                    // conceals the name; an escaped `\$(which rm)` is literal.
                    RedirKind::HereDoc => redir
                        .heredoc
                        .as_ref()
                        .is_some_and(|heredoc| !heredoc_body_expands(heredoc)),
                    _ => false,
                })
        }
        _ => false,
    };
    !transparent
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

/// One curl/wget invocation's request-flow argument indices, in the outer
/// command's argv, keyed to the execution whose network effects they bind.
struct RequestInvocation {
    execution: Option<ExecutionNodeRef>,
    body: Vec<u32>,
    headers: Vec<u32>,
    config: Vec<u32>,
    output: Vec<u32>,
}

fn request_flow_name(literal: &str) -> Option<&'static str> {
    match literal.rsplit('/').next() {
        Some("curl") => Some("curl"),
        Some("wget") => Some("wget"),
        _ => None,
    }
}

fn request_flow_indices(name: &str, words: &[Word]) -> (Vec<u32>, Vec<u32>, Vec<u32>, Vec<u32>) {
    match name {
        "wget" => {
            let info = wget_flow_info(words);
            (
                info.body_value_arguments,
                info.header_arguments,
                info.config_arguments,
                info.output_value_arguments,
            )
        }
        _ => {
            let info = curl_flow_info(words);
            (
                info.body_value_arguments,
                info.header_arguments,
                info.config_arguments,
                info.output_value_arguments,
            )
        }
    }
}

/// The curl/wget invocations this command runs: the command itself when it is
/// one, plus every nested invocation a wrapper launched. A nested invocation's
/// indices are read from its own modeled argv and mapped back to the outer
/// words through the forwarding the wrapper recorded, so a body substitution
/// that reaches any of them is bound to that invocation's upload alone.
fn request_invocations(
    builder: &PlanBuilder,
    converted: &[Converted],
    execution: Option<ExecutionNodeRef>,
    eff_start: usize,
    eff_end: usize,
) -> Vec<RequestInvocation> {
    let mut requests = Vec::new();
    if let Some(name) = converted
        .first()
        .and_then(|head| head.word.as_literal())
        .and_then(request_flow_name)
    {
        let words = converted.iter().map(|c| c.word.clone()).collect::<Vec<_>>();
        let (body, headers, config, output) = request_flow_indices(name, &words);
        requests.push(RequestInvocation {
            execution,
            body,
            headers,
            config,
            output,
        });
    }
    // A nested request's indices only map back to the outer words when the
    // outer command has an execution to attribute the forwarding to.
    let Some(outer) = execution else {
        return requests;
    };
    let mut seen = std::collections::BTreeSet::new();
    for effect in eff_start..eff_end {
        if builder.effect_operation(effect) != Some("process.exec") {
            continue;
        }
        let Some(child) = builder.effect_execution(effect) else {
            continue;
        };
        if Some(child) == execution || !seen.insert(child) {
            continue;
        }
        let Some(name) = builder
            .effect_execution_command(effect)
            .and_then(request_flow_name)
        else {
            continue;
        };
        let Some(argv) = builder.execution_argv(child) else {
            continue;
        };
        let words = argv
            .iter()
            .map(|word| Word::literal(word.clone()))
            .collect::<Vec<_>>();
        let (body, headers, config, output) = request_flow_indices(name, &words);
        let map = |indices: Vec<u32>| {
            indices
                .into_iter()
                .filter_map(|index| builder.forwarded_argument_root(effect, index, outer))
                .collect::<Vec<_>>()
        };
        requests.push(RequestInvocation {
            execution: Some(child),
            body: map(body),
            headers: map(headers),
            config: map(config),
            output: map(output),
        });
    }
    requests
}

fn command_wrapper_operand(converted: &[Converted]) -> Option<&[Converted]> {
    let mut i = 1;
    let mut lookup = false;
    while i < converted.len() {
        match converted[i].word.as_literal() {
            Some("-v") | Some("-V") => {
                lookup = true;
                i += 1;
            }
            Some("-p") => i += 1,
            Some("--") => {
                i += 1;
                break;
            }
            _ => break,
        }
    }
    if lookup || i >= converted.len() {
        None
    } else {
        Some(&converted[i..])
    }
}

/// Whether the token expands a `:=`/`=` default, which assigns the variable.
pub(super) fn assigns_default(tok: &WordTok) -> bool {
    tok.segs
        .iter()
        .any(|seg| matches!(seg, Seg::Param { default: Some(default), .. } if default.assign))
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
fn substituted_head(tok: &WordTok) -> bool {
    tok.segs
        .iter()
        .any(|seg| matches!(seg, Seg::CommandSub { .. }))
        && tok
            .segs
            .iter()
            .all(|seg| matches!(seg, Seg::CommandSub { .. } | Seg::Literal { .. }))
}

/// A head word spelled from literal text with some of it quoted or escaped.
fn quoted_head(word: &WordTok) -> bool {
    parse::literal_text(word).is_none() && parse::command_name_text(word).is_some()
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

fn exec_operands(converted: &[Converted]) -> Option<usize> {
    let mut index = 1;
    'options: while let Some(text) = converted.get(index).and_then(|word| word.word.as_literal()) {
        if text == "--" {
            index += 1;
            break;
        }
        if text.len() < 2 || !text.starts_with('-') {
            break;
        }
        let mut flags = text[1..].chars();
        let mut separate_argv0 = false;
        loop {
            match flags.next() {
                Some('c' | 'l') => {}
                // The NAME is attached when this word has more characters.
                Some('a') => {
                    separate_argv0 = flags.as_str().is_empty();
                    break;
                }
                // Not an option this grammar defines: the word is the command.
                Some(_) => break 'options,
                None => break,
            }
        }
        index += 1 + usize::from(separate_argv0);
    }
    (index < converted.len()).then_some(index)
}

/// Dispatch once per path binding, each under its path's condition. Shell
/// state the paths change joins as for conditionally defined functions.
fn each_path<T>(
    builder: &mut PlanBuilder,
    env: &mut ShellEnv,
    bindings: &PathBindings<T>,
    persist: bool,
    dispatch: &mut impl FnMut(
        &mut PlanBuilder,
        &mut ShellEnv,
    ) -> (
        Option<ExecutionNodeRef>,
        Option<Termination>,
        SiteFacts,
        bool,
    ),
    install: impl Fn(&mut ShellEnv, &T),
) -> (
    Option<ExecutionNodeRef>,
    Option<Termination>,
    SiteFacts,
    bool,
) {
    let mut state = persist.then(|| ConditionalShellState::new(env));
    let mut execution = None;
    let mut termination = None;
    let mut all_terminate = true;
    let mut facts: Option<SiteFacts> = None;
    for (binding, condition) in bindings {
        if let Some(state) = &state {
            state.reset(env);
        }
        install(env, binding);
        if let Some(condition) = condition {
            builder.push_bound_condition(condition.clone());
        }
        let (path_execution, path_termination, path_facts, _) = dispatch(builder, env);
        if condition.is_some() {
            builder.pop_condition();
        }
        if let Some(state) = &mut state {
            state.observe(env);
        }
        execution = path_execution.or(execution);
        all_terminate &= path_termination.is_some();
        termination = path_termination;
        match &mut facts {
            Some(facts) => facts.merge(&path_facts),
            None => facts = Some(path_facts),
        }
    }
    if let Some(state) = state {
        state.merge(env);
    }
    (
        execution,
        termination.filter(|_| all_terminate),
        facts.unwrap_or_else(SiteFacts::unknown),
        false,
    )
}

/// Whether one parsed `exec` option word resets the replaced program's
/// environment. Options are single letters, so `-cl` clears too.
fn exec_clears_environment(text: &str) -> bool {
    text.starts_with('-')
        && !text.starts_with("--")
        && text[1..]
            .chars()
            .take_while(|flag| *flag != 'a')
            .any(|flag| flag == 'c')
}
