//! Owns persistent Bash variable, environment, and provenance state.

use nah_parse::Substitution;
use nah_proto::observation::ObservationQuery;

use crate::bash_model::VariableValue;
use crate::bash_state::{
    BindingAttribute, MAX_VARIABLE_ORIGINS, VariableBinding, merge_variable_values,
    variable_binding,
};
use crate::shell_word::{referenced_env_names, referenced_positional_names};

use super::{Lowered, Lowerer};

impl Lowerer {
    pub(super) fn env_key(&mut self, name: &str) -> String {
        if let Some(key) = self.queries.iter().find_map(|query| match query {
            ObservationQuery::Env {
                key,
                name: existing,
            } if existing == name => Some(key.clone()),
            _ => None,
        }) {
            return key;
        }
        let env_count = self
            .queries
            .iter()
            .filter(|query| matches!(query, ObservationQuery::Env { .. }))
            .count();
        let key = format!("env-{env_count}");
        self.queries.push(ObservationQuery::Env {
            key: key.clone(),
            name: name.to_owned(),
        });
        key
    }

    pub(super) fn prepare_variable_reference(&mut self, name: &str) {
        if !self.is_local_variable(name) && self.state.unknown_variables {
            self.state.variables.push(VariableBinding {
                name: name.to_owned(),
                value: VariableValue::Unknown,
                origins: Vec::new(),
                exported: BindingAttribute::Unknown,
                readonly: BindingAttribute::Unknown,
            });
        }
        if !self.is_local_variable(name) {
            self.env_key(name);
        }
    }

    pub(super) fn is_local_variable(&self, name: &str) -> bool {
        self.state
            .variables
            .iter()
            .any(|binding| binding.name == name)
    }

    pub(super) fn is_ambient_variable(&self, name: &str) -> bool {
        self.ambient_variables
            .iter()
            .any(|(ambient, _)| ambient == name)
    }

    pub(super) fn variable_origins(&mut self, raw: &str) -> Vec<usize> {
        let mut origins = referenced_env_names(raw)
            .into_iter()
            .filter_map(|name| variable_binding(&self.state, &name))
            .flat_map(|binding| binding.origins.iter().copied())
            .collect::<Vec<_>>();
        for name in referenced_positional_names(raw) {
            if matches!(name.as_str(), "@" | "*") {
                origins.extend(
                    self.state
                        .positionals
                        .iter()
                        .flat_map(|value| value.origins.iter().copied()),
                );
            } else if name == "0" {
                origins.extend(
                    self.state
                        .positional_zero
                        .iter()
                        .flat_map(|value| value.origins.iter().copied()),
                );
            } else if let Ok(index) = name.parse::<usize>()
                && let Some(value) = index
                    .checked_sub(1)
                    .and_then(|index| self.state.positionals.get(index))
            {
                origins.extend(value.origins.iter().copied());
            }
        }
        self.bounded_origins(origins)
    }

    pub(super) fn expansion_origins(
        &mut self,
        raw: &str,
        substitutions: &[Substitution],
        lowered_substitutions: &[(&Substitution, Lowered)],
    ) -> Vec<usize> {
        let mut origins = self.variable_origins(raw);
        for substitution in substitutions {
            if !matches!(
                substitution,
                Substitution::Command { .. } | Substitution::Backtick { .. }
            ) {
                continue;
            }
            if let Some((_, lowered)) = lowered_substitutions
                .iter()
                .find(|(candidate, _)| std::ptr::eq(*candidate, substitution))
            {
                origins.extend(lowered.outputs.iter().copied());
            }
        }
        self.bounded_origins(origins)
    }

    pub(super) fn visible_variables(&self) -> Vec<(String, VariableValue)> {
        let mut variables = self
            .state
            .variables
            .iter()
            .map(|binding| (binding.name.clone(), binding.value.clone()))
            .collect::<Vec<_>>();
        variables.push((
            "0".to_owned(),
            self.state
                .positional_zero
                .as_ref()
                .map(|value| value.value.clone())
                .unwrap_or(VariableValue::Unset),
        ));
        for index in 1..=self.state.positionals.len().max(9) {
            variables.push((
                index.to_string(),
                self.state
                    .positionals
                    .get(index - 1)
                    .map(|value| value.value.clone())
                    .unwrap_or(VariableValue::Unset),
            ));
        }
        variables.push(("@".to_owned(), VariableValue::Unknown));
        variables.push(("*".to_owned(), self.joined_positionals()));
        for (name, value) in &self.ambient_variables {
            if !self.is_local_variable(name) {
                variables.push((name.clone(), value.clone()));
            }
        }
        variables
    }

    pub(super) fn visible_environment_variables(&self) -> Vec<(String, VariableValue)> {
        // A persistent shell variable changes a child runtime only when the
        // shell exports it; command-prefix assignments are handled separately.
        let mut variables = self
            .state
            .variables
            .iter()
            .filter(|binding| binding.exported != BindingAttribute::No)
            .map(|binding| (binding.name.clone(), binding.value.clone()))
            .collect::<Vec<_>>();
        for (name, value) in &self.ambient_variables {
            if !self.is_local_variable(name) {
                variables.push((name.clone(), value.clone()));
            }
        }
        variables
    }

    pub(super) fn joined_positionals(&self) -> VariableValue {
        let ifs = self
            .state
            .variables
            .iter()
            .find(|binding| binding.name == "IFS")
            .map(|binding| &binding.value)
            .or_else(|| {
                self.ambient_variables
                    .iter()
                    .find_map(|(name, value)| (name == "IFS").then_some(value))
            });
        let separator = match ifs {
            None | Some(VariableValue::Unset) => " ".to_owned(),
            Some(VariableValue::Static(value)) => {
                value.chars().next().map_or_else(String::new, String::from)
            }
            Some(VariableValue::Unknown) => return VariableValue::Unknown,
        };
        let mut joined = String::new();
        for (index, positional) in self.state.positionals.iter().enumerate() {
            let VariableValue::Static(value) = &positional.value else {
                return VariableValue::Unknown;
            };
            if index > 0 {
                joined.push_str(&separator);
            }
            joined.push_str(value);
            if joined.len() > crate::INVOCATION_EVIDENCE_CAP {
                return VariableValue::Unknown;
            }
        }
        VariableValue::Static(joined)
    }

    pub(super) fn local_variable(&self, name: &str) -> Option<&str> {
        self.state
            .variables
            .iter()
            .find(|binding| binding.name == name)
            .map(|binding| &binding.value)
            .and_then(|value| match value {
                VariableValue::Static(value) => Some(value.as_str()),
                VariableValue::Unset | VariableValue::Unknown => None,
            })
    }

    pub(super) fn set_local_variable(&mut self, name: &str, value: impl Into<VariableValue>) {
        self.set_local_variable_with_origins(name, value.into(), Vec::new());
    }

    pub(super) fn set_local_variable_with_origins(
        &mut self,
        name: &str,
        value: VariableValue,
        origins: Vec<usize>,
    ) {
        self.state.descriptors.unset_alias(name);
        self.set_local_variable_preserving_descriptor_alias(name, value, origins);
    }

    pub(super) fn set_local_variable_preserving_descriptor_alias(
        &mut self,
        name: &str,
        value: VariableValue,
        origins: Vec<usize>,
    ) {
        let origins = self.bounded_origins(origins);
        if let Some(existing) = self
            .state
            .variables
            .iter_mut()
            .find(|binding| binding.name == name)
        {
            match existing.readonly {
                BindingAttribute::Yes => {}
                BindingAttribute::No => {
                    existing.value = value;
                    existing.origins = origins;
                }
                BindingAttribute::Unknown => {
                    self.complete = false;
                    existing.value = merge_variable_values(&existing.value, &value);
                    existing.origins.extend(origins);
                    existing.origins.sort_unstable();
                    existing.origins.dedup();
                    if existing.origins.len() > MAX_VARIABLE_ORIGINS {
                        existing.origins.truncate(MAX_VARIABLE_ORIGINS);
                        existing.value = VariableValue::Unknown;
                        self.analysis_refused = true;
                    }
                }
            }
        } else {
            let exported = if self
                .ambient_variables
                .iter()
                .find(|(ambient, _)| ambient == name)
                .is_some_and(|(_, value)| !matches!(value, VariableValue::Unset))
            {
                BindingAttribute::Yes
            } else {
                BindingAttribute::No
            };
            self.state.variables.push(VariableBinding {
                name: name.to_owned(),
                value,
                origins,
                exported,
                readonly: BindingAttribute::No,
            });
        }
    }

    pub(super) fn mark_local_variable_unknown_with_origins(
        &mut self,
        name: &str,
        origins: Vec<usize>,
    ) {
        if let Some(binding) = self
            .state
            .variables
            .iter_mut()
            .find(|binding| binding.name == name)
        {
            if binding.readonly != BindingAttribute::Yes {
                binding.value = VariableValue::Unknown;
                binding.origins = origins;
            }
        } else {
            self.set_local_variable_with_origins(name, VariableValue::Unknown, origins);
        }
    }

    pub(super) fn bounded_origins(&mut self, mut origins: Vec<usize>) -> Vec<usize> {
        origins.sort_unstable();
        origins.dedup();
        if origins.len() > MAX_VARIABLE_ORIGINS {
            origins.truncate(MAX_VARIABLE_ORIGINS);
            self.complete = false;
            self.analysis_refused = true;
        }
        origins
    }
}
