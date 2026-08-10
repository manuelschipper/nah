//! Owns Bash assignment, declaration, and current-shell variable mutations.

use nah_parse::{Redirect, UnmodeledStateExpansion, Word};

use crate::bash_content::substitution_output;
use crate::bash_descriptors::exact_descriptor_alias_name;
use crate::bash_lookup::Certainty as LookupCertainty;
use crate::bash_model::{ProgramDraft, ResolvedWord, VariableValue};
use crate::bash_state::{BindingAttribute, current_pwd, known_cwd};
use crate::paths::resolve_from_cwd;
use crate::shell_word::{
    ExpansionContext, definite_parameter_assignments, here_document_definite_parameter_assignments,
    here_document_parameter_assignment_required, here_document_referenced_env_names,
    parameter_assignment_required, referenced_env_names, resolve_word, static_word,
};

use super::{AssignmentUpdate, Lowered, Lowerer, VisibleStdin};

pub(super) fn declaration_binding_names(
    arguments: &[Word],
    assignments: &[(String, Word)],
) -> Vec<String> {
    let mut names = assignments
        .iter()
        .map(|(name, _)| name.clone())
        .collect::<Vec<_>>();
    let mut options = true;
    for argument in arguments {
        let Some(argument) = static_word(argument.raw(), argument.substitutions().is_empty())
        else {
            continue;
        };
        if options && argument == "--" {
            options = false;
            continue;
        }
        if options && argument.len() > 1 && matches!(argument.as_bytes().first(), Some(b'-' | b'+'))
        {
            continue;
        }
        options = false;
        let name = argument
            .split_once('=')
            .map_or(argument.as_str(), |(name, _)| name);
        if valid_variable_name(name) && !names.iter().any(|existing| existing == name) {
            names.push(name.to_owned());
        }
    }
    names
}

pub(super) fn declaration_enables_nameref(program: &str, arguments: &[Word]) -> bool {
    if !matches!(program, "declare" | "typeset") {
        return false;
    }
    declaration_attributes(arguments)
        .into_iter()
        .filter_map(|(enabled, attribute)| (attribute == 'n').then_some(enabled))
        .next_back()
        .unwrap_or(false)
}

pub(super) fn declaration_nameref_targets_tar_options(
    arguments: &[Word],
    assignments: &[(String, Word)],
) -> bool {
    let mut targets = assignments
        .iter()
        .map(|(_, value)| static_word(value.raw(), value.substitutions().is_empty()))
        .collect::<Vec<_>>();
    let mut options = true;
    for argument in arguments {
        let Some(argument) = static_word(argument.raw(), argument.substitutions().is_empty())
        else {
            return false;
        };
        if options && argument == "--" {
            options = false;
            continue;
        }
        if options && argument.len() > 1 && matches!(argument.as_bytes().first(), Some(b'-' | b'+'))
        {
            continue;
        }
        options = false;
        if let Some((_, target)) = argument.split_once('=') {
            targets.push(Some(target.to_owned()));
        }
    }
    !targets.is_empty()
        && targets
            .iter()
            .all(|target| target.as_deref() == Some("TAR_OPTIONS"))
}

pub(super) fn declaration_has_unmodeled_expansion(
    program: &str,
    arguments: &[Word],
    assignments: &[(String, Word)],
) -> bool {
    if !matches!(program, "declare" | "typeset") {
        return false;
    }
    declaration_attributes(arguments)
        .iter()
        .any(|(_, attribute)| matches!(attribute, 'n' | 'l' | 'u' | 'i' | 'a' | 'A'))
        || assignments
            .iter()
            .any(|(_, value)| contains_unquoted_brace(value.raw()))
        || arguments.iter().any(|argument| {
            static_word(argument.raw(), argument.substitutions().is_empty())
                .and_then(|value| value.split_once('=').map(|_| ()))
                .is_some()
                && contains_unquoted_brace(argument.raw())
        })
}

pub(super) fn declaration_attributes(arguments: &[Word]) -> Vec<(bool, char)> {
    let mut attributes = Vec::new();
    for argument in arguments {
        let Some(argument) = static_word(argument.raw(), argument.substitutions().is_empty())
        else {
            break;
        };
        if argument == "--" {
            break;
        }
        let Some(prefix) = argument.as_bytes().first() else {
            break;
        };
        if argument.len() <= 1 || !matches!(prefix, b'-' | b'+') {
            break;
        }
        let enabled = *prefix == b'-';
        attributes.extend(argument[1..].chars().map(|attribute| (enabled, attribute)));
    }
    attributes
}

pub(super) fn contains_unquoted_brace(raw: &str) -> bool {
    let mut chars = raw.chars();
    let mut quote = None;
    while let Some(character) = chars.next() {
        match (quote, character) {
            (None, '\'') => quote = Some('\''),
            (None, '"') => quote = Some('"'),
            (Some('\''), '\'') | (Some('"'), '"') => quote = None,
            (None | Some('"'), '\\') => {
                chars.next();
            }
            (None, '{' | '}') => return true,
            _ => {}
        }
    }
    false
}

pub(super) fn read_variable_assignment(
    arguments: &[Word],
    visible_stdin: Option<&VisibleStdin>,
) -> Option<(String, String, Vec<usize>)> {
    let name = read_assignment_name(arguments)?;
    if !valid_variable_name(&name) {
        return None;
    }
    let visible = visible_stdin?;
    let input = &visible.value;
    let value = input.split('\n').next().unwrap_or_default();
    if value.contains(['\\', '\t', '\r'])
        || value.trim_matches(|character: char| character.is_ascii_whitespace()) != value
    {
        return None;
    }
    Some((name, value.to_owned(), visible.origins.clone()))
}

pub(super) fn read_assignment_name(arguments: &[Word]) -> Option<String> {
    let mut index = 0;
    let mut names = Vec::new();
    while index < arguments.len() {
        let argument = static_word(
            arguments[index].raw(),
            arguments[index].substitutions().is_empty(),
        )?;
        if argument == "--" {
            index += 1;
            names.extend(
                arguments[index..]
                    .iter()
                    .map(|word| static_word(word.raw(), word.substitutions().is_empty())),
            );
            break;
        }
        if argument == "-u" {
            index += 2;
            continue;
        }
        if argument.starts_with("-u") && argument.len() > 2 {
            index += 1;
            continue;
        }
        if argument == "-r" {
            index += 1;
            continue;
        }
        if argument.starts_with('-') {
            return None;
        }
        names.push(Some(argument));
        index += 1;
    }
    let [Some(name)] = names.as_slice() else {
        return None;
    };
    Some(name.clone())
}

pub(super) fn read_mutated_variables(arguments: &[Word]) -> Option<Vec<String>> {
    let mut index = 0;
    let mut options = true;
    let mut names = Vec::new();
    while index < arguments.len() {
        let raw = arguments[index].raw();
        let value = static_word(raw, arguments[index].substitutions().is_empty());
        if options && value.as_deref() == Some("--") {
            options = false;
            index += 1;
            continue;
        }
        if options && value.as_deref() == Some("-u") {
            index += 2;
            if index > arguments.len() {
                return None;
            }
            continue;
        }
        let unquoted = raw
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .unwrap_or(raw);
        if options
            && unquoted
                .strip_prefix("-u")
                .is_some_and(|descriptor| !descriptor.is_empty())
        {
            index += 1;
            continue;
        }
        let value = value?;
        if options && value == "-r" {
            index += 1;
            continue;
        }
        if options && value.starts_with('-') {
            return None;
        }
        options = false;
        if valid_variable_name(&value) {
            names.push(value);
        } else {
            return None;
        }
        index += 1;
    }
    if names.is_empty() {
        names.push("REPLY".to_owned());
    }
    names.sort();
    names.dedup();
    Some(names)
}

pub(super) fn lastpipe_update(
    program: &ProgramDraft,
    arguments: &[Word],
) -> Option<BindingAttribute> {
    if !matches!(program, ProgramDraft::Static(program) if program == "shopt") {
        return None;
    }
    let values = arguments
        .iter()
        .map(|argument| static_word(argument.raw(), argument.substitutions().is_empty()))
        .collect::<Option<Vec<_>>>()?;
    let (enabled, names) = match values.as_slice() {
        [option, names @ ..] if option == "-s" => (BindingAttribute::Yes, names),
        [option, names @ ..] if option == "-u" => (BindingAttribute::No, names),
        _ => return None,
    };
    names
        .iter()
        .any(|name| name == "lastpipe")
        .then_some(enabled)
}

pub(super) fn valid_variable_name(name: &str) -> bool {
    name.as_bytes()
        .first()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

impl Lowerer {
    pub(in crate::bash) fn refuse_parameter_assignment_words<'a>(
        &mut self,
        words: impl IntoIterator<Item = &'a str>,
    ) {
        let words = words.into_iter().collect::<Vec<_>>();
        let mut names = words
            .iter()
            .flat_map(|word| referenced_env_names(word))
            .collect::<Vec<_>>();
        names.sort();
        names.dedup();
        for name in names {
            self.prepare_variable_reference(&name);
        }
        let mut variables = self.visible_variables();
        let mut required = false;
        let mut assignments = Vec::new();
        for word in words {
            required |= parameter_assignment_required(word, &variables);
            for (name, value) in definite_parameter_assignments(word, &variables) {
                if let Some((_, current)) = variables
                    .iter_mut()
                    .find(|(candidate, _)| candidate == &name)
                {
                    *current = VariableValue::Static(value.clone());
                } else {
                    variables.push((name.clone(), VariableValue::Static(value.clone())));
                }
                assignments.push((name, value));
            }
        }
        if !required {
            return;
        }
        self.refuse_parameter_assignment_state_with(assignments);
    }

    pub(super) fn refuse_prefix_parameter_assignments(
        &mut self,
        assignments: &[(String, Word)],
        unmodeled: &[UnmodeledStateExpansion],
    ) {
        for (_, word) in assignments {
            for name in referenced_env_names(word.raw()) {
                self.prepare_variable_reference(&name);
            }
        }
        for expansion in unmodeled {
            for name in referenced_env_names(expansion.word().raw()) {
                self.prepare_variable_reference(&name);
            }
        }
        let mut variables = self.visible_variables();
        let mut binding_index = 0;
        let mut unmodeled_index = 0;
        while binding_index < assignments.len() || unmodeled_index < unmodeled.len() {
            if unmodeled
                .get(unmodeled_index)
                .is_some_and(|expansion| expansion.preceding_bindings() <= binding_index)
            {
                let expansion = &unmodeled[unmodeled_index];
                if parameter_assignment_required(expansion.word().raw(), &variables) {
                    let assignments =
                        definite_parameter_assignments(expansion.word().raw(), &variables);
                    self.refuse_parameter_assignment_state_with(assignments);
                    return;
                }
                unmodeled_index += 1;
                continue;
            }

            let Some((name, word)) = assignments.get(binding_index) else {
                self.refuse_parameter_assignment_state();
                return;
            };
            if parameter_assignment_required(word.raw(), &variables) {
                let assignments = definite_parameter_assignments(word.raw(), &variables);
                self.refuse_parameter_assignment_state_with(assignments);
                return;
            }
            let value = match resolve_word(
                word.raw(),
                word.substitutions(),
                &variables,
                ExpansionContext::Assignment,
                substitution_output,
            ) {
                ResolvedWord::Absent => VariableValue::Static(String::new()),
                ResolvedWord::Static { value, .. } | ResolvedWord::Pattern { value, .. } => {
                    VariableValue::Static(value)
                }
                ResolvedWord::Unresolved { .. } => VariableValue::Unknown,
            };
            if let Some((_, current)) = variables
                .iter_mut()
                .find(|(candidate, _)| candidate == name)
            {
                *current = value;
            } else {
                variables.push((name.clone(), value));
            }
            binding_index += 1;
        }
    }

    pub(super) fn refuse_redirect_parameter_assignments(&mut self, redirects: &[Redirect]) {
        for redirect in redirects {
            if matches!(redirect.operator(), "<<" | "<<-") {
                let delimiter_quoted = redirect
                    .target()
                    .is_some_and(|delimiter| delimiter.contains(['\'', '"', '\\']));
                if !delimiter_quoted && let Some(body) = redirect.body() {
                    for name in here_document_referenced_env_names(body) {
                        self.prepare_variable_reference(&name);
                    }
                }
            } else if let Some(target) = redirect.target() {
                for name in referenced_env_names(target) {
                    self.prepare_variable_reference(&name);
                }
            }
        }
        let mut variables = self.visible_variables();
        let mut required = false;
        let mut assignments = Vec::new();
        for redirect in redirects {
            if matches!(redirect.operator(), "<<" | "<<-") {
                let delimiter_quoted = redirect
                    .target()
                    .is_some_and(|delimiter| delimiter.contains(['\'', '"', '\\']));
                if !delimiter_quoted && let Some(body) = redirect.body() {
                    required |= here_document_parameter_assignment_required(body, &variables);
                    assignments.extend(here_document_definite_parameter_assignments(
                        body, &variables,
                    ));
                }
            } else if let Some(target) = redirect.target() {
                required |= parameter_assignment_required(target, &variables);
                assignments.extend(definite_parameter_assignments(target, &variables));
            }
            for (name, value) in &assignments {
                if let Some((_, current)) = variables
                    .iter_mut()
                    .find(|(candidate, _)| candidate == name)
                {
                    *current = VariableValue::Static(value.clone());
                } else {
                    variables.push((name.clone(), VariableValue::Static(value.clone())));
                }
            }
        }
        if required {
            self.refuse_parameter_assignment_state_with(assignments);
        }
    }

    pub(super) fn refuse_parameter_assignment_state(&mut self) {
        self.complete = false;
        self.analysis_refused = true;
        self.state.unknown_variables = true;
        for binding in &mut self.state.variables {
            if binding.readonly != BindingAttribute::Yes {
                binding.value = VariableValue::Unknown;
                binding.origins.clear();
            }
        }
        self.state.tar_options.assign(None);
        self.state.lookup.invalidate_all();
    }

    pub(in crate::bash) fn refuse_parameter_assignment_state_with(
        &mut self,
        assignments: Vec<(String, String)>,
    ) {
        self.refuse_parameter_assignment_state();
        for (name, value) in assignments {
            self.set_local_variable(&name, VariableValue::Static(value));
        }
    }

    pub(in crate::bash) fn lower_unmodeled_command_assignments(
        &mut self,
        assignments: &[(String, Word)],
        unmodeled: &[UnmodeledStateExpansion],
    ) -> Lowered {
        if unmodeled.is_empty() {
            return Lowered::default();
        }
        self.refuse_prefix_parameter_assignments(assignments, unmodeled);
        let mut lowered = Lowered::default();
        for expansion in unmodeled {
            let (word, _) = self.lower_word_with_origins(expansion.word());
            lowered.extend(word);
        }
        if unmodeled
            .iter()
            .any(UnmodeledStateExpansion::mutates_current_shell)
        {
            self.refuse_parameter_assignment_state();
        }
        lowered
    }

    pub(super) fn unset_variables(&mut self, arguments: &[Word]) {
        let mut functions = false;
        let mut variables = true;
        let mut options = true;
        let mut names = Vec::new();
        for argument in arguments {
            let Some(argument) = static_word(argument.raw(), argument.substitutions().is_empty())
            else {
                self.complete = false;
                let changed = self.lookup_variable_change("PATH");
                let changed = match changed {
                    LookupCertainty::No => LookupCertainty::No,
                    LookupCertainty::Yes | LookupCertainty::Maybe => LookupCertainty::Maybe,
                };
                let update = self.state.lookup.apply_path_change(changed);
                self.apply_lookup_update(update);
                for binding in &mut self.state.variables {
                    if binding.readonly != BindingAttribute::Yes {
                        binding.value = VariableValue::Unknown;
                    }
                }
                return;
            };
            if options && argument == "--" {
                options = false;
                continue;
            }
            if options && argument.starts_with('-') {
                functions |= argument[1..].contains('f');
                variables |= argument[1..].contains('v');
                if argument[1..].contains('n') {
                    self.complete = false;
                    let changed = self.lookup_variable_change("PATH");
                    let changed = match changed {
                        LookupCertainty::No => LookupCertainty::No,
                        LookupCertainty::Yes | LookupCertainty::Maybe => LookupCertainty::Maybe,
                    };
                    let update = self.state.lookup.apply_path_change(changed);
                    self.apply_lookup_update(update);
                    for binding in &mut self.state.variables {
                        if binding.readonly != BindingAttribute::Yes {
                            binding.value = VariableValue::Unknown;
                        }
                    }
                    return;
                }
                continue;
            }
            names.push(argument);
        }
        if functions
            && !arguments.iter().any(|argument| {
                static_word(argument.raw(), argument.substitutions().is_empty()).is_some_and(
                    |argument| argument.starts_with('-') && argument[1..].contains('v'),
                )
            })
        {
            variables = false;
        }
        if variables {
            for name in names {
                if name == "PATH" {
                    let changed = self.lookup_variable_change("PATH");
                    let update = self.state.lookup.apply_path_change(changed);
                    self.apply_lookup_update(update);
                }
                self.set_local_variable(&name, VariableValue::Unset);
            }
        }
    }

    pub(in crate::bash) fn lower_assignments(
        &mut self,
        bindings: &[(String, Word)],
        unmodeled: &[UnmodeledStateExpansion],
    ) -> Lowered {
        let mut lowered = Lowered::default();
        let mut binding_index = 0;
        for expansion in unmodeled {
            while binding_index < expansion.preceding_bindings() {
                let Some((name, word)) = bindings.get(binding_index) else {
                    self.refuse_parameter_assignment_state();
                    return lowered;
                };
                self.refuse_parameter_assignment_words(std::iter::once(word.raw()));
                let (word_lowered, origins) = self.lower_word_with_origins(word);
                lowered.extend(word_lowered);
                let update = self.assignment_update(word, origins);
                self.apply_assignment_update(name, update, false);
                self.update_descriptor_assignment(name, word.raw());
                binding_index += 1;
            }
            let assignments =
                definite_parameter_assignments(expansion.word().raw(), &self.visible_variables());
            self.refuse_parameter_assignment_words(std::iter::once(expansion.word().raw()));
            let (word_lowered, _) = self.lower_word_with_origins(expansion.word());
            lowered.extend(word_lowered);
            if expansion.mutates_current_shell() {
                self.refuse_parameter_assignment_state_with(assignments);
            }
        }
        for (name, word) in &bindings[binding_index..] {
            self.refuse_parameter_assignment_words(std::iter::once(word.raw()));
            let (word_lowered, origins) = self.lower_word_with_origins(word);
            lowered.extend(word_lowered);
            let update = self.assignment_update(word, origins);
            self.apply_assignment_update(name, update, false);
            self.update_descriptor_assignment(name, word.raw());
        }
        lowered
    }

    pub(super) fn assignment_update(
        &mut self,
        word: &Word,
        origins: Vec<usize>,
    ) -> AssignmentUpdate {
        let expands_tilde = word.raw().starts_with('~');
        let value = match self.word_resolution(word, ExpansionContext::Assignment) {
            ResolvedWord::Static { value, .. } | ResolvedWord::Pattern { value, .. } => {
                if expands_tilde && value.starts_with('~') {
                    resolve_from_cwd(
                        known_cwd(&self.state),
                        current_pwd(&self.state),
                        &value,
                        &self.home,
                        self.platform,
                        true,
                    )
                } else {
                    Some(value)
                }
            }
            ResolvedWord::Absent => Some(String::new()),
            ResolvedWord::Unresolved { .. } => None,
        };
        AssignmentUpdate { value, origins }
    }

    pub(super) fn apply_assignment_updates(
        &mut self,
        bindings: &[(String, Word)],
        updates: Vec<AssignmentUpdate>,
        preserve_tar_options_nameref: bool,
    ) {
        for ((name, word), update) in bindings.iter().zip(updates) {
            self.apply_assignment_update(name, update, preserve_tar_options_nameref);
            self.update_descriptor_assignment(name, word.raw());
        }
    }

    pub(super) fn apply_assignment_update(
        &mut self,
        name: &str,
        update: AssignmentUpdate,
        preserve_tar_options_nameref: bool,
    ) {
        let AssignmentUpdate { value, origins } = update;
        if preserve_tar_options_nameref
            && self
                .state
                .definite_tar_options_aliases
                .iter()
                .any(|alias| alias == name)
        {
            return;
        }
        if name == "PATH" {
            let changed = self.lookup_variable_change(name);
            let update = self.state.lookup.apply_path_change(changed);
            self.apply_lookup_update(update);
        }
        if value.is_none() {
            self.complete = false;
        }
        if name == "TAR_OPTIONS" {
            self.state.tar_options.assign(value.clone());
        } else if let Some(definite) =
            self.update_aliased_tar_options(name, |state| state.assign(value.clone()))
        {
            self.set_local_variable("TAR_OPTIONS", definite.then(|| value.clone()).flatten());
        }
        self.set_local_variable_with_origins(name, VariableValue::from(value), origins);
    }

    pub(super) fn update_descriptor_assignment(&mut self, target: &str, raw: &str) {
        let Some(source) = exact_descriptor_alias_name(raw) else {
            self.state.descriptors.unset_alias(target);
            return;
        };
        match self.state.descriptors.alias_binding(&source) {
            Ok(Some(_)) => {}
            Ok(None) => {
                self.state.descriptors.unset_alias(target);
                return;
            }
            Err(_) => {
                self.complete = false;
                self.analysis_refused = true;
                return;
            }
        }
        if source == target {
            return;
        }
        match self.state.descriptors.copy_alias(target, &source) {
            Ok(crate::bash_descriptor_state::DescriptorUpdate::Exact) => {}
            Ok(crate::bash_descriptor_state::DescriptorUpdate::Uncertain) => {
                self.complete = false;
            }
            Err(_) => {
                self.complete = false;
                self.analysis_refused = true;
            }
        }
    }

    pub(super) fn update_variable_attributes(
        &mut self,
        program: &str,
        arguments: &[Word],
        assignments: &[(String, Word)],
    ) {
        let mut exported = match program {
            "export" => Some(BindingAttribute::Yes),
            _ => None,
        };
        let mut readonly = matches!(program, "readonly").then_some(BindingAttribute::Yes);
        let mut options = true;
        for argument in arguments {
            let Some(argument) = static_word(argument.raw(), argument.substitutions().is_empty())
            else {
                self.complete = false;
                continue;
            };
            if options && argument == "--" {
                options = false;
                continue;
            }
            if options
                && argument.len() > 1
                && matches!(argument.as_bytes().first(), Some(b'-' | b'+'))
            {
                let enabled = argument.starts_with('-');
                for option in argument[1..].chars() {
                    match (program, option) {
                        ("export", 'n') => {
                            exported = Some(if enabled {
                                BindingAttribute::No
                            } else {
                                BindingAttribute::Yes
                            });
                        }
                        ("declare" | "local" | "typeset", 'x') => {
                            exported = Some(if enabled {
                                BindingAttribute::Yes
                            } else {
                                BindingAttribute::No
                            });
                        }
                        ("declare" | "local" | "typeset", 'r') if enabled => {
                            readonly = Some(BindingAttribute::Yes);
                        }
                        ("declare" | "local" | "typeset", 'r') => {
                            self.complete = false;
                        }
                        _ => {}
                    }
                }
                continue;
            }
            options = false;
        }
        let names = declaration_binding_names(arguments, assignments);
        for name in names {
            if !self.is_local_variable(&name) {
                self.set_local_variable(&name, VariableValue::Unset);
            }
            let Some(binding) = self
                .state
                .variables
                .iter_mut()
                .find(|binding| binding.name == name)
            else {
                continue;
            };
            if let Some(exported) = exported {
                binding.exported = exported;
            }
            if readonly == Some(BindingAttribute::Yes) {
                binding.readonly = BindingAttribute::Yes;
            }
        }
    }

    pub(super) fn mutated_local_variables(
        &mut self,
        program: &str,
        arguments: &[Word],
        raw_arguments: &[Word],
    ) -> Vec<String> {
        let active = self
            .state
            .variables
            .iter()
            .map(|binding| binding.name.clone())
            .collect::<Vec<_>>();
        if program == "read" {
            if arguments.len() == raw_arguments.len()
                && let Some(names) = read_mutated_variables(arguments)
            {
                return names;
            }
            self.complete = false;
            self.analysis_refused = true;
            self.state.unknown_variables = true;
            return active;
        }
        if matches!(program, "." | "eval" | "let" | "source") {
            self.complete = false;
            self.state.unknown_variables = true;
            return active;
        }
        if program == "unset" {
            return Vec::new();
        }
        let values = arguments
            .iter()
            .map(|argument| static_word(argument.raw(), argument.substitutions().is_empty()))
            .collect::<Vec<_>>();
        let mut candidates: Vec<Option<String>> = match program {
            "printf" => values
                .windows(2)
                .find_map(|pair| (pair[0].as_deref() == Some("-v")).then(|| pair[1].clone()))
                .into_iter()
                .collect(),
            "mapfile" | "readarray" => values
                .iter()
                .rev()
                .find(|value| value.as_ref().is_none_or(|value| !value.starts_with('-')))
                .cloned()
                .into_iter()
                .collect(),
            "declare" | "export" | "local" | "readonly" | "typeset" => return Vec::new(),
            _ => return Vec::new(),
        };
        if matches!(program, "mapfile" | "readarray") && candidates.is_empty() {
            candidates.push(Some("MAPFILE".to_owned()));
        }
        if arguments.len() != raw_arguments.len() || candidates.iter().any(Option::is_none) {
            self.complete = false;
            self.analysis_refused = true;
            self.state.unknown_variables = true;
            return active;
        }
        let mut mutated = candidates
            .into_iter()
            .flatten()
            .filter(|candidate| !candidate.starts_with('-'))
            .map(|candidate| {
                candidate
                    .split_once('=')
                    .map_or(candidate.as_str(), |value| value.0)
                    .to_owned()
            })
            .filter(|candidate| valid_variable_name(candidate))
            .collect::<Vec<_>>();
        if mutated.is_empty() && matches!(program, "mapfile" | "readarray") {
            mutated.push("MAPFILE".to_owned());
        }
        mutated.sort();
        mutated.dedup();
        mutated
    }
}
