//! Resolves aliases and functions before handing one command to feature composition.

use nah_parse::{Redirect, Substitution, Syntax, Word};

use super::{AliasInvocation, CommandContext, InjectedOrigins, Lowered, Lowerer};
use crate::bash_content::substitution_output;
use crate::bash_lookup::{
    AliasSnapshot, Certainty as LookupCertainty, FunctionPresence, LookupMode, LookupTarget,
    Update as LookupUpdate,
};
use crate::bash_model::ResolvedWord;
use crate::bash_semantics::normalize_program;
use crate::bash_state::BindingAttribute;
use crate::shell_word::{ExpansionContext, referenced_env_names, resolve_word, static_word};

pub(super) fn lexical_alias_name<'a>(
    raw: &'a str,
    substitutions: &[Substitution],
) -> Option<&'a str> {
    (substitutions.is_empty()
        && !raw.is_empty()
        && !raw.bytes().any(|byte| {
            byte.is_ascii_whitespace()
                || matches!(
                    byte,
                    b'\''
                        | b'"'
                        | b'\\'
                        | b'$'
                        | b'`'
                        | b'|'
                        | b'&'
                        | b';'
                        | b'('
                        | b')'
                        | b'<'
                        | b'>'
                )
        }))
    .then_some(raw)
}

pub(super) fn alias_payload_variants(
    aliases: &AliasSnapshot,
    replacement: &str,
    assignments: &[(String, Word)],
    arguments: &[Word],
    redirects: &[Redirect],
) -> Result<Vec<String>, ()> {
    let redirects = redirects
        .iter()
        .map(alias_redirect_source)
        .collect::<Option<Vec<_>>>()
        .ok_or(())?;
    let argument_variants =
        alias_argument_variants(aliases, arguments, replacement.ends_with([' ', '\t']))?;
    let mut payloads = Vec::new();
    for arguments in argument_variants {
        let mut payload = String::new();
        for (name, value) in assignments {
            push_shell_part(&mut payload, &format!("{name}={}", value.raw()));
        }
        push_shell_part(&mut payload, replacement);
        for argument in arguments {
            push_shell_part(&mut payload, &argument);
        }
        for redirect in &redirects {
            push_shell_part(&mut payload, redirect);
        }
        payloads.push(payload);
    }
    Ok(payloads)
}

pub(super) fn alias_argument_variants(
    aliases: &AliasSnapshot,
    arguments: &[Word],
    next_eligible: bool,
) -> Result<Vec<Vec<String>>, ()> {
    const MAX_ALIAS_VARIANTS: usize = 16;
    let mut variants = vec![(Vec::new(), next_eligible)];
    for argument in arguments {
        let mut next = Vec::new();
        for (prefix, eligible) in variants {
            let choices = lexical_alias_name(argument.raw(), argument.substitutions())
                .filter(|_| eligible)
                .map_or_else(
                    || Ok(vec![(argument.raw().to_owned(), false)]),
                    |name| trailing_alias_replacements(aliases, name, &mut Vec::new(), 0),
                )?;
            for (value, trailing) in choices {
                if next.len() == MAX_ALIAS_VARIANTS {
                    return Err(());
                }
                let mut values = prefix.clone();
                values.push(value);
                next.push((values, trailing));
            }
        }
        variants = next;
    }
    Ok(variants.into_iter().map(|(values, _)| values).collect())
}

pub(super) fn trailing_alias_replacements(
    aliases: &AliasSnapshot,
    name: &str,
    active: &mut Vec<String>,
    depth: usize,
) -> Result<Vec<(String, bool)>, ()> {
    const MAX_ALIAS_DEPTH: usize = 32;
    if depth == MAX_ALIAS_DEPTH || active.iter().any(|candidate| candidate == name) {
        return Ok(vec![(name.to_owned(), false)]);
    }
    let resolution = aliases.resolve(name, true);
    if !resolution.variants_complete {
        return Err(());
    }
    if resolution.replacements.is_empty() {
        return Ok(vec![(name.to_owned(), false)]);
    }
    active.push(name.to_owned());
    let mut expanded = Vec::new();
    for replacement in resolution.replacements {
        let trailing = replacement.ends_with([' ', '\t']);
        let trimmed = replacement.trim();
        if lexical_alias_name(trimmed, &[]).is_some() {
            for (nested, nested_trailing) in
                trailing_alias_replacements(aliases, trimmed, active, depth + 1)?
            {
                expanded.push((nested, trailing || nested_trailing));
            }
        } else {
            expanded.push((replacement, trailing));
        }
    }
    active.pop();
    if resolution.unexpanded {
        expanded.push((name.to_owned(), false));
    }
    expanded.sort();
    expanded.dedup();
    Ok(expanded)
}

pub(super) fn alias_redirect_source(redirect: &Redirect) -> Option<String> {
    if redirect.body().is_some() {
        return None;
    }
    Some(format!(
        "{}{}{}",
        redirect.fd().unwrap_or_default(),
        redirect.operator(),
        redirect.target()?
    ))
}

pub(super) fn push_shell_part(payload: &mut String, part: &str) {
    if !payload.is_empty() && !payload.ends_with(|character: char| character.is_ascii_whitespace())
    {
        payload.push(' ');
    }
    payload.push_str(part);
}

impl Lowerer {
    pub(super) fn normalized_program(&mut self, program: &str) -> String {
        if let Some(program) = normalize_program(program, self.platform) {
            return program;
        }
        self.complete = false;
        program.to_owned()
    }

    pub(super) fn update_lookup_builtin(&mut self, program: &str, arguments: &[Word]) {
        let arguments = arguments
            .iter()
            .map(|argument| static_word(argument.raw(), argument.substitutions().is_empty()))
            .collect::<Option<Vec<_>>>();
        let update = match arguments {
            Some(arguments) => self.state.lookup.apply_builtin(program, &arguments),
            None => self.state.lookup.invalidate_builtin(program),
        };
        self.apply_lookup_update(update);
    }

    pub(super) fn apply_lookup_update(&mut self, update: LookupUpdate) {
        match update {
            LookupUpdate::Exact | LookupUpdate::Partial => {}
            LookupUpdate::Refused => {
                self.complete = false;
                self.analysis_refused = true;
            }
        }
    }

    pub(super) fn lookup_variable_change(&self, name: &str) -> LookupCertainty {
        match self
            .state
            .variables
            .iter()
            .find(|binding| binding.name == name)
            .map_or(BindingAttribute::No, |binding| binding.readonly)
        {
            BindingAttribute::Yes => LookupCertainty::No,
            BindingAttribute::No => LookupCertainty::Yes,
            BindingAttribute::Unknown => LookupCertainty::Maybe,
        }
    }

    pub(in crate::bash) fn lower_invocation(
        &mut self,
        name: &str,
        name_substitutions: &[Substitution],
        assignments: &[(String, Word)],
        arguments: &[Word],
        redirects: &[Redirect],
        injected_origins: &InjectedOrigins,
    ) -> Lowered {
        self.refuse_prefix_parameter_assignments(assignments, &[]);
        self.refuse_parameter_assignment_words(
            std::iter::once(name).chain(arguments.iter().map(Word::raw)),
        );
        self.refuse_redirect_parameter_assignments(redirects);
        let mode = self.next_lookup_mode.take().unwrap_or(LookupMode::Normal);
        let alias_eligible = self.next_alias_eligible.take().unwrap_or(true);
        if let Some(alias) = lexical_alias_name(name, name_substitutions)
            && alias_eligible
            && !self
                .active_alias_expansions
                .iter()
                .any(|active| active == alias)
        {
            let aliases = self
                .active_aliases
                .clone()
                .unwrap_or_else(|| self.state.lookup.alias_snapshot());
            let resolution = aliases.resolve(alias, true);
            if !resolution.variants_complete {
                self.complete = false;
                self.analysis_refused = true;
            }
            if !resolution.replacements.is_empty() {
                return self.lower_alias_variants(
                    alias,
                    aliases,
                    resolution.replacements,
                    resolution.unexpanded,
                    mode,
                    AliasInvocation {
                        name,
                        name_substitutions,
                        assignments,
                        arguments,
                        redirects,
                        injected_origins,
                    },
                );
            }
        }
        if assignments.iter().any(|(name, _)| name == "PATH") {
            let changed = self.lookup_variable_change("PATH");
            let update = self.state.lookup.apply_path_change(changed);
            self.apply_lookup_update(update);
        }
        let variables = self.visible_variables();
        let resolved_name = match resolve_word(
            name,
            name_substitutions,
            &variables,
            ExpansionContext::ShellWord,
            substitution_output,
        ) {
            ResolvedWord::Static { value, .. } if !value.is_empty() => value,
            _ => {
                return self.lower_command(
                    name,
                    name_substitutions,
                    assignments,
                    arguments,
                    redirects,
                    CommandContext {
                        injected_origins,
                        exact_target: None,
                        builtin_target: false,
                    },
                );
            }
        };
        let bindings = self
            .state
            .functions
            .iter()
            .filter(|binding| self.function_bodies[binding.body].name == resolved_name)
            .collect::<Vec<_>>();
        let function = if bindings.is_empty() {
            FunctionPresence::Absent
        } else if bindings.iter().any(|binding| binding.name_definite) {
            FunctionPresence::Present
        } else {
            FunctionPresence::Possible
        };
        let resolution = self.state.lookup.resolve(&resolved_name, mode, function);
        if !resolution.variants_complete {
            self.complete = false;
            self.analysis_refused = true;
        }
        let handler_active = self
            .active_function_calls
            .iter()
            .any(|index| self.function_bodies[*index].name == "command_not_found_handle");
        // Bash can recurse through the handler when a command inside it is
        // also absent. The bounded model lowers the handler body once and
        // keeps each inner lexical command's normal PATH effects.
        let handler_possible = resolution.command_not_found_possible
            && !handler_active
            && self.state.functions.iter().any(|binding| {
                self.function_bodies[binding.body].name == "command_not_found_handle"
            });

        let entry = self.state.clone();
        let branched = resolution.targets.len() + usize::from(handler_possible) > 1;
        let mut exits = Vec::new();
        let mut lowered = Lowered::default();
        for target in resolution.targets {
            self.state.clone_from(&entry);
            if branched {
                self.conditional_depth += 1;
            }
            let branch = match target {
                LookupTarget::Function => self.lower_function_target(
                    name,
                    name_substitutions,
                    assignments,
                    arguments,
                    redirects,
                    injected_origins,
                ),
                LookupTarget::Builtin => self.lower_command(
                    name,
                    name_substitutions,
                    assignments,
                    arguments,
                    redirects,
                    CommandContext {
                        injected_origins,
                        exact_target: None,
                        builtin_target: true,
                    },
                ),
                LookupTarget::Hashed(target) => self.lower_command(
                    name,
                    name_substitutions,
                    assignments,
                    arguments,
                    redirects,
                    CommandContext {
                        injected_origins,
                        exact_target: Some(&target),
                        builtin_target: false,
                    },
                ),
                LookupTarget::Path(_) | LookupTarget::DirectPath(_) => self.lower_command(
                    name,
                    name_substitutions,
                    assignments,
                    arguments,
                    redirects,
                    CommandContext {
                        injected_origins,
                        exact_target: None,
                        builtin_target: false,
                    },
                ),
                LookupTarget::MissingBuiltin => Lowered::default(),
            };
            if branched {
                self.conditional_depth -= 1;
            }
            lowered.extend(branch);
            exits.push(self.state.clone());
        }
        if handler_possible {
            self.state.clone_from(&entry);
            if branched {
                self.conditional_depth += 1;
            }
            let handler_arguments = std::iter::once(Word::from_literal(&resolved_name))
                .chain(arguments.iter().cloned())
                .collect::<Vec<_>>();
            lowered.extend(self.lower_function_target(
                "command_not_found_handle",
                &[],
                assignments,
                &handler_arguments,
                redirects,
                &InjectedOrigins::default(),
            ));
            if branched {
                self.conditional_depth -= 1;
            }
            self.state.clone_from(&entry);
            exits.push(entry.clone());
        }
        self.state = if exits.is_empty() {
            entry
        } else {
            self.merged_state(&exits)
        };
        lowered
    }

    pub(super) fn lower_alias_variants(
        &mut self,
        alias: &str,
        aliases: AliasSnapshot,
        replacements: Vec<String>,
        unexpanded: bool,
        mode: LookupMode,
        invocation: AliasInvocation<'_>,
    ) -> Lowered {
        let AliasInvocation {
            name,
            name_substitutions,
            assignments,
            arguments,
            redirects,
            injected_origins,
        } = invocation;
        const MAX_ALIAS_EXPANSIONS: usize = 256;
        const MAX_ALIAS_VARIANTS: usize = 16;
        if self.alias_expansions >= MAX_ALIAS_EXPANSIONS {
            self.complete = false;
            self.analysis_refused = true;
            self.next_lookup_mode = Some(mode);
            self.next_alias_eligible = Some(false);
            return self.lower_invocation(
                name,
                name_substitutions,
                assignments,
                arguments,
                redirects,
                injected_origins,
            );
        }
        self.alias_expansions += 1;

        let mut payloads = Vec::new();
        for replacement in replacements {
            match alias_payload_variants(&aliases, &replacement, assignments, arguments, redirects)
            {
                Ok(variants) => payloads.extend(variants),
                Err(()) => {
                    self.complete = false;
                    self.analysis_refused = true;
                }
            }
            if payloads.len() > MAX_ALIAS_VARIANTS {
                self.complete = false;
                self.analysis_refused = true;
                payloads.truncate(MAX_ALIAS_VARIANTS);
                break;
            }
        }
        payloads.sort();
        payloads.dedup();

        let entry = self.state.clone();
        let branched = payloads.len() + usize::from(unexpanded) > 1;
        let mut lowered = Lowered::default();
        let mut exits = Vec::new();
        for payload in payloads {
            self.state.clone_from(&entry);
            if branched {
                self.conditional_depth += 1;
            }
            self.active_alias_expansions.push(alias.to_owned());
            match nah_parse::normalize(&payload) {
                Ok(syntax) => {
                    self.next_lookup_mode = Some(mode);
                    lowered.extend(self.lower_syntax_with_aliases(&syntax, aliases.clone(), true));
                }
                Err(nah_parse::ParseError::ExceedsLimit(_)) => {
                    self.complete = false;
                    self.analysis_refused = true;
                }
                Err(_) => {
                    self.complete = false;
                    self.analysis_refused = true;
                }
            }
            self.active_alias_expansions.pop();
            if branched {
                self.conditional_depth -= 1;
            }
            exits.push(self.state.clone());
        }
        if unexpanded {
            self.state.clone_from(&entry);
            if branched {
                self.conditional_depth += 1;
            }
            self.next_lookup_mode = Some(mode);
            self.next_alias_eligible = Some(false);
            lowered.extend(self.lower_invocation(
                name,
                name_substitutions,
                assignments,
                arguments,
                redirects,
                injected_origins,
            ));
            if branched {
                self.conditional_depth -= 1;
            }
            exits.push(self.state.clone());
        }
        self.state = if exits.is_empty() {
            entry
        } else {
            self.merged_state(&exits)
        };
        lowered
    }

    pub(super) fn lower_syntax_with_aliases(
        &mut self,
        syntax: &Syntax,
        aliases: AliasSnapshot,
        eligible: bool,
    ) -> Lowered {
        self.detected_fork_bomb |= syntax.fork_bomb();
        let parent_aliases = self.active_aliases.replace(aliases);
        let parent_eligible = self.next_alias_eligible.replace(eligible);
        let lowered = self.lower_statements(syntax.statements());
        self.active_aliases = parent_aliases;
        self.next_alias_eligible = parent_eligible;
        lowered
    }

    pub(super) fn lower_function_target(
        &mut self,
        name: &str,
        name_substitutions: &[Substitution],
        assignments: &[(String, Word)],
        arguments: &[Word],
        redirects: &[Redirect],
        injected_origins: &InjectedOrigins,
    ) -> Lowered {
        let raw_name = name;
        let variables = self.visible_variables();
        let ResolvedWord::Static { value: name, .. } = resolve_word(
            name,
            name_substitutions,
            &variables,
            ExpansionContext::ShellWord,
            substitution_output,
        ) else {
            return Lowered::default();
        };
        if name.is_empty() {
            return Lowered::default();
        }
        let bindings = self
            .state
            .functions
            .iter()
            .filter(|binding| self.function_bodies[binding.body].name == name)
            .copied()
            .collect::<Vec<_>>();
        if bindings.is_empty() {
            return Lowered::default();
        }
        let functions = bindings
            .iter()
            .map(|binding| binding.body)
            .collect::<Vec<_>>();
        for variable in referenced_env_names(raw_name) {
            self.prepare_variable_reference(&variable);
        }

        let entry = self.state.clone();
        let mut lowered = Lowered::default();
        for substitution in name_substitutions {
            let state = self.state.clone();
            lowered.extend(self.lower_statements(substitution.statements()));
            self.state = state;
        }
        lowered.extend(self.lower_assignments(assignments, &[]));
        let mut argument_origins = Vec::with_capacity(arguments.len());
        for (index, argument) in arguments.iter().enumerate() {
            let (argument_lowered, mut origins) = self.lower_word_with_origins(argument);
            lowered.extend(argument_lowered);
            if let Some(injected) = injected_origins.arguments.get(index) {
                origins.extend(injected.iter().copied());
            }
            argument_origins.push(self.bounded_origins(origins));
        }
        let positional_values = self.function_positional_values(arguments, &argument_origins);
        let call_state = self.state.clone();
        let mut exits = Vec::new();
        for index in functions.iter().copied() {
            self.state.clone_from(&call_state);
            const MAX_FUNCTION_DEPTH: usize = 64;
            const MAX_FUNCTION_EXPANSIONS: usize = 256;
            if self.active_function_calls.contains(&index) {
                self.complete = false;
                if self.asynchronous_depth > 0 || self.detected_fork_bomb {
                    self.detected_fork_bomb = true;
                } else {
                    self.analysis_refused = true;
                }
                self.restore_function_assignment_scope(&entry, assignments);
                exits.push(self.state.clone());
                continue;
            }
            if self.active_function_calls.len() >= MAX_FUNCTION_DEPTH
                || self.function_expansions >= MAX_FUNCTION_EXPANSIONS
            {
                self.complete = false;
                self.analysis_refused = true;
                self.restore_function_assignment_scope(&entry, assignments);
                exits.push(self.state.clone());
                continue;
            }
            self.function_expansions += 1;
            let function = self.function_bodies[index].clone();
            let mut function_redirects = function.redirects;
            function_redirects.extend_from_slice(redirects);
            self.active_function_calls.push(index);
            self.function_local_scopes.push(Vec::new());
            self.state.positionals.clone_from(&positional_values);
            let parent_aliases = self.active_aliases.clone();
            self.active_aliases = Some(function.aliases);
            if functions.len() > 1 {
                self.conditional_depth += 1;
            }
            let body = if function_redirects.is_empty() {
                self.lower_statement(&function.body)
            } else {
                self.lower_redirected(&function.body, &function_redirects)
            };
            if functions.len() > 1 {
                self.conditional_depth -= 1;
            }
            self.active_aliases = parent_aliases;
            let local_variables = self
                .function_local_scopes
                .pop()
                .expect("function local scope was pushed");
            self.active_function_calls.pop();
            lowered.extend(body);
            self.state.positionals.clone_from(&call_state.positionals);
            self.restore_function_local_scope(&call_state, &local_variables);
            self.restore_function_assignment_scope(&entry, assignments);
            exits.push(self.state.clone());
        }
        self.state = self.merged_state(&exits);
        lowered
    }
}
