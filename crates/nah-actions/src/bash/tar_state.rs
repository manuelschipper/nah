//! Owns coordinator state for TAR_OPTIONS aliases and argument variants.

use nah_parse::Word;

use crate::bash_tar::{TarOptionsState, TarOptionsValue, TarOptionsVariant};
use crate::shell_word::static_word;

use super::Lowerer;

impl Lowerer {
    pub(super) fn update_aliased_tar_options(
        &mut self,
        name: &str,
        update: impl FnOnce(&mut TarOptionsState),
    ) -> Option<bool> {
        if !self
            .state
            .possible_tar_options_aliases
            .iter()
            .any(|alias| alias == name)
        {
            return None;
        }
        let definite = self
            .state
            .definite_tar_options_aliases
            .iter()
            .any(|alias| alias == name);
        if definite {
            update(&mut self.state.tar_options);
        } else {
            let original = self.state.tar_options.clone();
            let mut updated = original.clone();
            update(&mut updated);
            self.state.tar_options = TarOptionsState::merge([original, updated]);
        }
        Some(definite)
    }

    pub(super) fn set_tar_options_alias(&mut self, name: &str) {
        if !self
            .state
            .possible_tar_options_aliases
            .iter()
            .any(|alias| alias == name)
        {
            self.state
                .possible_tar_options_aliases
                .push(name.to_owned());
        }
        if !self
            .state
            .definite_tar_options_aliases
            .iter()
            .any(|alias| alias == name)
        {
            self.state
                .definite_tar_options_aliases
                .push(name.to_owned());
        }
    }

    pub(super) fn clear_tar_options_alias(&mut self, name: &str) {
        self.state
            .possible_tar_options_aliases
            .retain(|alias| alias != name);
        self.state
            .definite_tar_options_aliases
            .retain(|alias| alias != name);
    }

    pub(super) fn update_tar_options_state(
        &mut self,
        program: &str,
        assignments: &[(String, Word)],
        arguments: &[Word],
    ) -> bool {
        if !matches!(
            program,
            "declare" | "export" | "readonly" | "typeset" | "unset"
        ) {
            return false;
        }

        let assigned = assignments
            .iter()
            .rev()
            .find(|(name, _)| name == "TAR_OPTIONS")
            .map(|(_, value)| {
                let value = self.resolve_local_argument(value);
                static_word(value.raw(), value.substitutions().is_empty())
            });
        let mut handled = assigned.is_some();
        let mut attributes_target_tar_options = assigned.is_some();
        if let Some(value) = assigned.as_ref() {
            if value.is_none() {
                self.complete = false;
            }
            self.state.tar_options.assign(value.clone());
            self.set_local_variable("TAR_OPTIONS", value.clone());
        }
        let mut option_mode = true;
        let mut functions = false;
        let mut unset_nameref = false;
        let mut declaration_nameref = None;
        let mut export = None;
        let mut print = false;
        let mut names_tar_options = false;
        for argument in arguments {
            let value = self.resolve_local_argument(argument);
            let Some(value) = static_word(value.raw(), value.substitutions().is_empty()) else {
                self.complete = false;
                continue;
            };
            if option_mode && value == "--" {
                option_mode = false;
                continue;
            }
            if option_mode && value.len() > 1 && matches!(value.as_bytes()[0], b'-' | b'+') {
                let enabled = value.starts_with('-');
                for option in value[1..].chars() {
                    match option {
                        'f' | 'F' => functions = enabled,
                        'n' if program == "unset" => unset_nameref = enabled,
                        'n' if program == "export" => export = Some(!enabled),
                        'n' if matches!(program, "declare" | "typeset") => {
                            declaration_nameref = Some(enabled);
                        }
                        'v' if program == "unset" => {}
                        'x' if matches!(program, "declare" | "typeset") => export = Some(enabled),
                        'p' => print = enabled,
                        _ => {}
                    }
                }
                continue;
            }
            option_mode = false;

            let (name, value) = value
                .split_once('=')
                .map_or((value.as_str(), None), |(name, value)| (name, Some(value)));
            if name != "TAR_OPTIONS"
                && matches!(program, "declare" | "typeset")
                && let Some(enabled) = declaration_nameref
            {
                handled = true;
                if enabled && value == Some("TAR_OPTIONS") {
                    self.set_tar_options_alias(name);
                    let value = self.local_variable("TAR_OPTIONS").map(str::to_owned);
                    self.set_local_variable(name, value);
                } else {
                    self.clear_tar_options_alias(name);
                }
                continue;
            }
            if name != "TAR_OPTIONS" {
                let alias = self
                    .state
                    .possible_tar_options_aliases
                    .iter()
                    .any(|alias| alias == name);
                if !alias {
                    continue;
                }
                handled = true;
                attributes_target_tar_options = true;
                if program == "unset" {
                    if functions {
                        continue;
                    }
                    if unset_nameref {
                        self.clear_tar_options_alias(name);
                    } else {
                        self.update_aliased_tar_options(name, TarOptionsState::unset);
                        self.set_local_variable("TAR_OPTIONS", None);
                    }
                } else if let Some(value) = value {
                    let value = Some(value.to_owned());
                    let definite =
                        self.update_aliased_tar_options(name, |state| state.assign(value.clone()));
                    self.set_local_variable(
                        "TAR_OPTIONS",
                        definite
                            .is_some_and(|definite| definite)
                            .then(|| value.clone())
                            .flatten(),
                    );
                }
                continue;
            }
            handled = true;
            attributes_target_tar_options = true;
            names_tar_options = true;
            if let Some(value) = value {
                let value = Some(value.to_owned());
                self.state.tar_options.assign(value.clone());
                self.set_local_variable(name, value);
            }
        }
        for (name, value) in assignments {
            if name == "TAR_OPTIONS" {
                continue;
            }
            let value = self.resolve_local_argument(value);
            let value = static_word(value.raw(), value.substitutions().is_empty());
            if matches!(program, "declare" | "typeset") && declaration_nameref == Some(true) {
                handled = true;
                if value.as_deref() == Some("TAR_OPTIONS") {
                    self.set_tar_options_alias(name);
                    let value = self.local_variable("TAR_OPTIONS").map(str::to_owned);
                    self.set_local_variable(name, value);
                } else {
                    self.clear_tar_options_alias(name);
                }
                continue;
            }
            if self
                .update_aliased_tar_options(name, |state| state.assign(value.clone()))
                .is_some()
            {
                handled = true;
                attributes_target_tar_options = true;
                if value.is_none() {
                    self.complete = false;
                }
            }
        }

        if program == "unset" {
            if names_tar_options && !functions && !unset_nameref {
                self.state.tar_options.unset();
                self.set_local_variable("TAR_OPTIONS", None);
            }
            return handled;
        }

        if !handled {
            return false;
        }
        if functions || print && assigned.is_none() {
            return handled;
        }
        if !attributes_target_tar_options {
            return handled;
        }
        match program {
            "export" => {
                if export == Some(false) {
                    self.state.tar_options.unexport();
                } else {
                    self.state.tar_options.export();
                }
            }
            "declare" | "typeset" if export == Some(true) => self.state.tar_options.export(),
            "declare" | "typeset" if export == Some(false) => self.state.tar_options.unexport(),
            _ => {}
        }
        handled
    }

    pub(super) fn tar_argument_variants(
        &mut self,
        assignments: &[(String, Word)],
        arguments: &[Word],
    ) -> Vec<Vec<Word>> {
        if let Some((_, value)) = assignments.iter().rev().find(|(name, _)| {
            name == "TAR_OPTIONS"
                || self
                    .state
                    .definite_tar_options_aliases
                    .iter()
                    .any(|alias| alias == name)
        }) {
            let Some(mut options) =
                crate::bash_tar::options_arguments(&self.resolve_local_argument(value))
            else {
                self.complete = false;
                return vec![arguments.to_vec()];
            };
            options.extend_from_slice(arguments);
            return vec![options];
        }

        let mut variants = Vec::new();
        let states = self.state.tar_options.variants.clone();
        for state in states {
            let options = match state {
                TarOptionsVariant {
                    exported: true,
                    value: TarOptionsValue::Static(value),
                } => crate::bash_tar::options_value_arguments(&value),
                TarOptionsVariant {
                    exported: true,
                    value: TarOptionsValue::Unknown,
                } => {
                    self.complete = false;
                    None
                }
                _ => Some(Vec::new()),
            };
            let Some(mut options) = options else {
                self.complete = false;
                continue;
            };
            options.extend_from_slice(arguments);
            if !variants.iter().any(|existing: &Vec<Word>| {
                existing
                    .iter()
                    .map(Word::raw)
                    .eq(options.iter().map(Word::raw))
            }) {
                variants.push(options);
            }
        }
        if variants.is_empty() {
            variants.push(arguments.to_vec());
        }
        variants
    }
}
