//! Owns function definitions and persistent function attributes in the Bash coordinator.

use nah_parse::{Redirect, Statement, Word};

use crate::bash_state::{BindingAttribute, FunctionBinding, FunctionBody, ShellState};
use crate::shell_word::static_word;

use super::Lowerer;

impl Lowerer {
    pub(in crate::bash) fn define_function(
        &mut self,
        name: &str,
        body: &Statement,
        redirects: &[Redirect],
    ) {
        let bodies = &self.function_bodies;
        let has_matching = self
            .state
            .functions
            .iter()
            .any(|binding| bodies[binding.body].name == name);
        if has_matching
            && self
                .state
                .functions
                .iter()
                .filter(|binding| bodies[binding.body].name == name)
                .all(|binding| binding.name_definite && binding.readonly == BindingAttribute::Yes)
        {
            return;
        }
        for binding in &mut self.state.functions {
            if bodies[binding.body].name == name {
                binding.name_definite = true;
            }
        }
        self.state.functions.retain(|binding| {
            bodies[binding.body].name != name || binding.readonly != BindingAttribute::No
        });
        let index = self.function_bodies.len();
        self.function_bodies.push(FunctionBody {
            name: name.to_owned(),
            body: body.clone(),
            redirects: redirects.to_vec(),
            aliases: self
                .active_aliases
                .clone()
                .unwrap_or_else(|| self.state.lookup.alias_snapshot()),
        });
        self.state.functions.push(FunctionBinding {
            body: index,
            readonly: BindingAttribute::No,
            exported: BindingAttribute::No,
            name_definite: true,
        });
    }

    pub(super) fn restore_function_local_scope(&mut self, entry: &ShellState, names: &[String]) {
        for name in names {
            self.state.variables.retain(|binding| binding.name != *name);
            if let Some(binding) = entry.variables.iter().find(|binding| binding.name == *name) {
                self.state.variables.push(binding.clone());
            }
        }
        if names.iter().any(|name| {
            name == "TAR_OPTIONS"
                || entry.possible_tar_options_aliases.contains(name)
                || entry.definite_tar_options_aliases.contains(name)
        }) {
            self.state.tar_options.clone_from(&entry.tar_options);
        }
        for name in names {
            self.state
                .possible_tar_options_aliases
                .retain(|candidate| candidate != name);
            self.state
                .definite_tar_options_aliases
                .retain(|candidate| candidate != name);
            if entry.possible_tar_options_aliases.contains(name) {
                self.state.possible_tar_options_aliases.push(name.clone());
            }
            if entry.definite_tar_options_aliases.contains(name) {
                self.state.definite_tar_options_aliases.push(name.clone());
            }
        }
    }

    pub(super) fn restore_function_assignment_scope(
        &mut self,
        entry: &ShellState,
        assignments: &[(String, Word)],
    ) {
        let restores_tar_options = assignments.iter().any(|(name, _)| {
            name == "TAR_OPTIONS"
                || entry.possible_tar_options_aliases.contains(name)
                || entry.definite_tar_options_aliases.contains(name)
        });
        for (name, _) in assignments {
            self.state.variables.retain(|binding| binding.name != *name);
            if let Some(binding) = entry.variables.iter().find(|binding| binding.name == *name) {
                self.state.variables.push(binding.clone());
            }
        }
        if restores_tar_options {
            self.state.tar_options.clone_from(&entry.tar_options);
        }
    }

    pub(super) fn unset_functions(&mut self, arguments: &[Word]) {
        let mut functions = false;
        let mut options = true;
        let mut names = Vec::new();
        for argument in arguments {
            let Some(argument) = static_word(argument.raw(), argument.substitutions().is_empty())
            else {
                if functions {
                    self.complete = false;
                }
                return;
            };
            if options && argument == "--" {
                options = false;
                continue;
            }
            if options && argument.starts_with('-') {
                functions |= argument[1..].contains('f');
                continue;
            }
            if functions {
                names.push(argument);
            }
        }
        if names.is_empty() {
            return;
        }
        let bodies = &self.function_bodies;
        self.state.functions.retain_mut(|binding| {
            if !names.contains(&bodies[binding.body].name) {
                return true;
            }
            match binding.readonly {
                BindingAttribute::Yes => true,
                BindingAttribute::No => false,
                BindingAttribute::Unknown => {
                    binding.readonly = BindingAttribute::Yes;
                    binding.name_definite = false;
                    true
                }
            }
        });
    }

    pub(super) fn update_readonly_functions(&mut self, program: &str, arguments: &[Word]) {
        if !matches!(program, "readonly" | "declare" | "typeset") {
            return;
        }
        let mut function_mode = false;
        let mut readonly_mode = program == "readonly";
        let mut options = true;
        let mut names = Vec::new();
        for argument in arguments {
            let Some(argument) = static_word(argument.raw(), argument.substitutions().is_empty())
            else {
                if function_mode {
                    self.complete = false;
                }
                return;
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
                    match option {
                        'f' => function_mode = enabled,
                        'r' if matches!(program, "declare" | "typeset") => {
                            readonly_mode = enabled;
                        }
                        _ => {}
                    }
                }
                continue;
            }
            options = false;
            names.push(
                argument
                    .split_once('=')
                    .map_or(argument.as_str(), |(name, _)| name)
                    .to_owned(),
            );
        }
        if !function_mode || !readonly_mode {
            return;
        }
        let bodies = &self.function_bodies;
        for binding in &mut self.state.functions {
            if names.iter().any(|name| name == &bodies[binding.body].name) {
                binding.readonly = BindingAttribute::Yes;
            }
        }
    }

    pub(super) fn update_exported_functions(&mut self, program: &str, arguments: &[Word]) {
        if !matches!(program, "export" | "declare" | "typeset") {
            return;
        }
        let mut function_mode = false;
        let mut exported = (program == "export").then_some(BindingAttribute::Yes);
        let mut options = true;
        let mut names = Vec::new();
        for argument in arguments {
            let Some(argument) = static_word(argument.raw(), argument.substitutions().is_empty())
            else {
                if function_mode {
                    self.complete = false;
                }
                return;
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
                        (_, 'f') => function_mode = enabled,
                        ("export", 'n') => {
                            exported = Some(if enabled {
                                BindingAttribute::No
                            } else {
                                BindingAttribute::Yes
                            });
                        }
                        ("declare" | "typeset", 'x') => {
                            exported = Some(if enabled {
                                BindingAttribute::Yes
                            } else {
                                BindingAttribute::No
                            });
                        }
                        _ => {}
                    }
                }
                continue;
            }
            options = false;
            names.push(
                argument
                    .split_once('=')
                    .map_or(argument.as_str(), |(name, _)| name)
                    .to_owned(),
            );
        }
        let Some(exported) = exported.filter(|_| function_mode) else {
            return;
        };
        let bodies = &self.function_bodies;
        for binding in &mut self.state.functions {
            if names.iter().any(|name| name == &bodies[binding.body].name) {
                binding.exported = exported;
            }
        }
    }
}
