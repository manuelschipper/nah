//! Shell evaluation of one simple command. This file owns `dispatch_argv`:
//! builtin, alias and function dispatch for a resolved argv. Each child module
//! owns one further question about a command: `simple_command` (expansion and
//! head resolution up to the argv), `word_expansion`, `command_substitution`,
//! `variable_binding`, `redirection`, `directory_change`, `arithmetic`,
//! `source_and_eval`, `literal_output`, `function_call`,
//! `path_binding_dispatch`, `conditional_shell_state`, `process_execution`,
//! `producer_wiring`, `obfuscated_command`, `deferred_process`, and
//! `nested_shell_source`.

use std::collections::BTreeSet;
use std::rc::Rc;

use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, CoverageLevel, Domain, Effect, ExecutionNodeRef,
    Modality, Operation, ProvenanceKind, ResourceExpr, ResourceIdentity,
};

use crate::builder::{PlanBuilder, ScriptInterpreter};
use crate::control_flow::SiteFacts;
use crate::flow::Descriptor;
use crate::models::StdinValue;
use crate::paths::join_cwd;
use crate::value::unresolved_resource;
use crate::word::Word;

use super::lex::{RedirKind, Seg, ShellDupTarget, ShellSpan, WordTok};
use super::name_tables::{FunctionBinding, PathBindings};
use super::parse::Simple;
use super::referenced_inputs::referenced_inputs_with_substitutions;
use super::saturation_memos::{function_head_group_key, function_head_key};
use super::shell_env::{ArrayValue, ShellEnv};
use super::{
    Converted, EFFECTLESS_BUILTINS, MAX_ARGV_VARIANTS, MAX_SATURATED_FUNCTION_STEPS,
    MAX_WALK_DEPTH, Shell, Termination, parse, shell_builtin,
};

pub(super) mod arithmetic;
mod command_substitution;
mod conditional_shell_state;
mod deferred_process;
mod directory_change;
mod function_call;
mod literal_output;
mod nested_shell_source;
mod obfuscated_command;
mod path_binding_dispatch;
mod process_execution;
mod producer_wiring;
pub(super) mod redirection;
mod simple_command;
pub(super) mod source_and_eval;
pub(super) mod variable_binding;
mod word_expansion;

use conditional_shell_state::ConditionalShellState;
use directory_change::{
    DirectoryChange, directory_change, directory_target, host_runtime_cwd, physical_depth_after,
    pwd_follows_cwd,
};
use function_call::function_call_facts;
use nested_shell_source::NestedShellMode;
use variable_binding::bind_var;
use word_expansion::{effective_ifs, var_node};

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

impl Shell<'_> {
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
                        Some(requirements) => function_call_facts(requirements),
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
                state.merge(env, false);
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
        // `readonly` with no name lists the readonly variables.
        let lists_readonly = name == Some("readonly")
            && converted[1..].iter().all(|option| {
                option.word.as_literal().is_some_and(|option| {
                    option == "--"
                        || option.len() > 1
                            && option.starts_with('-')
                            && option[1..].chars().all(|flag| "paA".contains(flag))
                })
            });
        let listing_handled = if matches!(name, Some("export" | "declare" | "typeset" | "set"))
            || lists_readonly
        {
            let command = name.unwrap();
            let mut operands = 1;
            let mut print = false;
            let mut export = false;
            let mut functions = false;
            let mut mutation = false;
            // The listing is filtered by an attribute other than export:
            // the option letters of the attributes it asks for.
            let mut filter = BTreeSet::new();
            if lists_readonly {
                filter.insert('r');
            }
            // `readonly -a` and `-A` keep its listing to the readonly arrays
            // of that kind.
            let mut readonly_kinds = BTreeSet::new();
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
                                    'n' => {
                                        mutation = true;
                                        if command != "export" {
                                            filter.insert(flag);
                                        }
                                    }
                                    'a' | 'A' if command == "readonly" => {
                                        mutation = true;
                                        readonly_kinds.insert(flag);
                                    }
                                    'a' | 'A' | 'g' | 'I' | 'i' | 'l' | 'r' | 't' | 'u'
                                        if command != "export" =>
                                    {
                                        mutation = true;
                                        if flag != 'g' && flag != 'I' {
                                            filter.insert(flag);
                                        }
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
                // Without a name, `declare` lists the variables its options
                // select, and every variable when it has none.
                print || operands == converted.len()
            };
            let attributes = !filter.is_empty();
            // Which variables a listing without names prints. An attribute
            // filter selects the variables bearing any attribute it names. A
            // list assignment makes an indexed array of a name no declaration
            // made associative.
            let bears = |env: &ShellEnv, name: &str| {
                let mut borne = env.attributed.get(name).cloned().unwrap_or_default();
                if env.arrays.contains_key(name) && !borne.contains(&'A') {
                    borne.insert('a');
                }
                !borne.is_disjoint(&filter)
                    && (readonly_kinds.is_empty() || !borne.is_disjoint(&readonly_kinds))
            };
            let selects = |env: &ShellEnv, name: &str| {
                command == "set"
                    || if attributes {
                        bears(env, name) || export && env.exported.contains(name)
                    } else {
                        command != "export" && (print || !export) || env.exported.contains(name)
                    }
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
            } else if listing && (!mutation || operands == converted.len()) {
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
                                || !env.arrays.contains_key(name)
                                    && (env.unset.contains(name)
                                        || self.nest.environment_is_closed()
                                            && !env.vars.contains_key(name))
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
                } else if self.nest.environment_is_closed() || attributes && !export {
                    // Every variable an attribute filter selects is one this
                    // walk saw declared, so each is named even where the
                    // environment's own names are unknown.
                    let mut names = if attributes && !export {
                        env.attributed.keys().cloned().collect::<BTreeSet<_>>()
                    } else {
                        env.vars.keys().cloned().collect()
                    };
                    names.extend(env.arrays.keys().cloned());
                    for name in names {
                        // An observed absence stays in `unset` under an array
                        // assignment, which does set the name.
                        if env.unset.contains(&name) && !env.arrays.contains_key(&name)
                            || !selects(env, &name)
                        {
                            continue;
                        }
                        let mut provenance = vec![node];
                        if let Some(entry) = env.vars.get_mut(&name) {
                            provenance.push(var_node(builder, self.scope, entry, &env.chain_held));
                            provenance.extend(entry.antecedents.iter().copied());
                        }
                        crate::models::environment_disclosure(builder, Some(&name), provenance);
                    }
                } else {
                    let mut provenance = vec![node];
                    for name in env.vars.keys().cloned().collect::<BTreeSet<_>>() {
                        let selected = selects(env, &name);
                        let entry = env.vars.get_mut(&name).unwrap();
                        if !env.unset.contains(&name) && selected {
                            provenance.push(var_node(builder, self.scope, entry, &env.chain_held));
                        }
                    }
                    crate::models::environment_disclosure(builder, None, provenance);
                    // The listing of every variable names none, so each
                    // array it prints is stated beside it: an array's
                    // elements are found by its name.
                    for name in env.arrays.keys().cloned().collect::<BTreeSet<_>>() {
                        if selects(env, &name) {
                            crate::models::environment_disclosure(builder, Some(&name), vec![node]);
                        }
                    }
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
            // `printf -v NAME` (or `-vNAME`) writes the formatted output to a
            // variable instead of standard output.
            Some("printf")
                if converted
                    .get(1)
                    .and_then(|word| word.word.as_literal())
                    .is_some_and(|option| option.starts_with("-v")) =>
            {
                let attached = converted[1].word.as_literal().map(|option| &option[2..]);
                let (target, format) = match attached {
                    Some(name) if !name.is_empty() => (Some((name, converted[1].span)), 2),
                    _ => (
                        converted
                            .get(2)
                            .and_then(|target| Some((target.word.as_literal()?, target.span))),
                        3,
                    ),
                };
                if persist && let Some((name, span)) = target {
                    let arguments = converted.get(format..).unwrap_or_default();
                    let value = arguments
                        .iter()
                        .map(|argument| argument.word.as_literal())
                        .collect::<Option<Vec<_>>>()
                        .and_then(|arguments| {
                            literal_output::render(
                                Some("printf"),
                                &arguments,
                                None,
                                self.nest.limits.max_source_bytes,
                            )
                        })
                        .filter(|value| !value.contains('\0'));
                    // The variable holds the bytes its format and arguments
                    // expanded from, so a later use of it is a use of theirs.
                    let producers = arguments
                        .iter()
                        .flat_map(|argument| argument.producers.iter().cloned())
                        .collect();
                    bind_var(
                        builder,
                        env,
                        name.to_string(),
                        value,
                        conditional,
                        guarded,
                        span,
                        Vec::new(),
                        producers,
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
                        .take_while(|text| text.starts_with(['-', '+']) && *text != "--");
                    let (mut functions, mut readonly) = (false, fixed);
                    // The attributes the declaration gives its names and
                    // takes from them: `+l` clears one, and a case attribute
                    // replaces the other. Nothing clears readonly or makes
                    // an array a scalar again.
                    let mut given = BTreeSet::from_iter(fixed.then_some('r'));
                    let mut taken = BTreeSet::new();
                    for option in options {
                        let gives = option.starts_with('-');
                        functions |= gives && option.contains('f');
                        readonly |= gives && option.contains('r');
                        for attribute in option[1..].chars() {
                            match (gives, attribute) {
                                (true, 'a' | 'A' | 'i' | 'l' | 'n' | 'r' | 't' | 'u') => {
                                    given.insert(attribute);
                                    taken.remove(&attribute);
                                    let replaced = match attribute {
                                        'l' => Some('u'),
                                        'u' => Some('l'),
                                        _ => None,
                                    };
                                    if let Some(replaced) = replaced {
                                        given.remove(&replaced);
                                        taken.insert(replaced);
                                    }
                                }
                                (false, 'i' | 'l' | 'n' | 't' | 'u') => {
                                    given.remove(&attribute);
                                    taken.insert(attribute);
                                }
                                _ => {}
                            }
                        }
                    }
                    if !functions && (!given.is_empty() || !taken.is_empty()) {
                        for target in &converted[1..] {
                            if let Some(name) = target
                                .word
                                .split_assignment()
                                .map(|(name, _)| name)
                                .or_else(|| target.word.as_literal())
                                .filter(|name| !name.starts_with(['-', '+']))
                            {
                                let borne = env.attributed.entry(name.to_string()).or_default();
                                borne.retain(|attribute| !taken.contains(attribute));
                                borne.extend(&given);
                                if borne.is_empty() {
                                    env.attributed.remove(name);
                                }
                            }
                        }
                    }
                    // `local` with no name lists the function's variables,
                    // which this walk does not tell from the others.
                    if local
                        && converted[1..].iter().all(|option| {
                            option
                                .word
                                .as_literal()
                                .is_some_and(|option| option.starts_with('-'))
                        })
                    {
                        source_and_eval::expand_sourced_assignments(builder);
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
                        // Turned off on some paths only, it may still be on.
                        if text[1..].contains('a')
                            || (text.contains('o')
                                && words.get(i + 1).and_then(|c| c.word.as_literal())
                                    == Some("allexport"))
                        {
                            env.allexport = on || conditional && env.allexport;
                        }
                        if on
                            && (text[1..].contains(['x', 'v'])
                                || (text.contains('o')
                                    && matches!(
                                        words.get(i + 1).and_then(|c| c.word.as_literal()),
                                        Some("xtrace" | "verbose")
                                    )))
                        {
                            env.observes_later_bindings = true;
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
                    // The action is walked here, once, but runs later.
                    if persist && !matches!(action.word.as_literal(), Some("-" | "")) {
                        env.observes_later_bindings = true;
                    }
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
            Some("continue") => {
                crate::shell::observed_producers::record_loop_continue(builder, env);
                None
            }
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

/// A head word spelled from literal text with some of it quoted or escaped.
fn quoted_head(word: &WordTok) -> bool {
    parse::literal_text(word).is_none() && parse::command_name_text(word).is_some()
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
