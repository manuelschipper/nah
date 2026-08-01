//! Owns persistent pure Bash state and conservative branch merging.

use nah_parse::{Redirect, Statement};

use crate::bash_descriptor_state::DescriptorState;
use crate::bash_lookup::{AliasSnapshot, LookupState};
use crate::bash_model::VariableValue;
use crate::bash_tar::TarOptionsState;

pub(crate) const MAX_VARIABLE_ORIGINS: usize = 32;
pub(crate) const MAX_POSITIONAL_PARAMETERS: usize = 256;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ShellState {
    pub(crate) cwd: Cwd,
    pub(crate) variables: Vec<VariableBinding>,
    pub(crate) descriptors: DescriptorState,
    pub(crate) tar_options: TarOptionsState,
    pub(crate) possible_tar_options_aliases: Vec<String>,
    pub(crate) definite_tar_options_aliases: Vec<String>,
    pub(crate) functions: Vec<FunctionBinding>,
    pub(crate) positional_zero: Option<PositionalValue>,
    pub(crate) positionals: Vec<PositionalValue>,
    pub(crate) lastpipe: BindingAttribute,
    pub(crate) unknown_variables: bool,
    pub(crate) lookup: LookupState,
}

impl ShellState {
    pub(crate) fn initial(cwd: &str, home: &str) -> Self {
        Self {
            cwd: Cwd::Known(cwd.to_owned()),
            variables: vec![
                VariableBinding {
                    name: "HOME".to_owned(),
                    value: VariableValue::Static(home.to_owned()),
                    origins: Vec::new(),
                    exported: BindingAttribute::Yes,
                    readonly: BindingAttribute::No,
                },
                VariableBinding {
                    name: "PWD".to_owned(),
                    value: VariableValue::Static(cwd.to_owned()),
                    origins: Vec::new(),
                    exported: BindingAttribute::Yes,
                    readonly: BindingAttribute::No,
                },
            ],
            descriptors: DescriptorState::default(),
            tar_options: TarOptionsState::default(),
            possible_tar_options_aliases: Vec::new(),
            definite_tar_options_aliases: Vec::new(),
            functions: Vec::new(),
            positional_zero: None,
            positionals: Vec::new(),
            lastpipe: BindingAttribute::No,
            unknown_variables: false,
            lookup: LookupState::default(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum BindingAttribute {
    No,
    Yes,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VariableBinding {
    pub(crate) name: String,
    pub(crate) value: VariableValue,
    pub(crate) origins: Vec<usize>,
    pub(crate) exported: BindingAttribute,
    pub(crate) readonly: BindingAttribute,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PositionalValue {
    pub(crate) value: VariableValue,
    pub(crate) origins: Vec<usize>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FunctionBody {
    pub(crate) name: String,
    pub(crate) body: Statement,
    pub(crate) redirects: Vec<Redirect>,
    pub(crate) aliases: AliasSnapshot,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct FunctionBinding {
    pub(crate) body: usize,
    pub(crate) readonly: BindingAttribute,
    pub(crate) exported: BindingAttribute,
    pub(crate) name_definite: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Cwd {
    Known(String),
    Unknown,
}

pub(crate) fn merge_states(states: &[ShellState], bodies: &[FunctionBody]) -> (ShellState, bool) {
    let Some(first) = states.first() else {
        return (
            ShellState {
                cwd: Cwd::Unknown,
                variables: Vec::new(),
                descriptors: DescriptorState::default(),
                tar_options: TarOptionsState::default(),
                possible_tar_options_aliases: Vec::new(),
                definite_tar_options_aliases: Vec::new(),
                functions: Vec::new(),
                positional_zero: None,
                positionals: Vec::new(),
                lastpipe: BindingAttribute::No,
                unknown_variables: false,
                lookup: LookupState::default(),
            },
            false,
        );
    };
    let cwd = if states.iter().all(|state| state.cwd == first.cwd) {
        first.cwd.clone()
    } else {
        Cwd::Unknown
    };
    let mut names = Vec::new();
    for state in states {
        for binding in &state.variables {
            if !names.contains(&binding.name) {
                names.push(binding.name.clone());
            }
        }
    }
    let mut origins_saturated = false;
    let variables = names
        .into_iter()
        .map(|name| {
            let first_value = variable_binding(&states[0], &name)
                .map(|binding| &binding.value)
                .unwrap_or(&VariableValue::Unset);
            let value = if states.iter().all(|state| {
                variable_binding(state, &name)
                    .map(|binding| &binding.value)
                    .unwrap_or(&VariableValue::Unset)
                    == first_value
            }) {
                first_value.clone()
            } else {
                VariableValue::Unknown
            };
            let attribute = |field: fn(&VariableBinding) -> BindingAttribute| {
                let first = variable_binding(&states[0], &name).map_or(BindingAttribute::No, field);
                if states.iter().all(|state| {
                    variable_binding(state, &name).map_or(BindingAttribute::No, field) == first
                }) {
                    first
                } else {
                    BindingAttribute::Unknown
                }
            };
            let mut origins = states
                .iter()
                .filter_map(|state| variable_binding(state, &name))
                .flat_map(|binding| binding.origins.iter().copied())
                .collect::<Vec<_>>();
            origins.sort_unstable();
            origins.dedup();
            let binding_saturated = origins.len() > MAX_VARIABLE_ORIGINS;
            if binding_saturated {
                origins.truncate(MAX_VARIABLE_ORIGINS);
                origins_saturated = true;
            }
            let exported = attribute(|binding| binding.exported);
            let readonly = attribute(|binding| binding.readonly);
            VariableBinding {
                name,
                value: if binding_saturated {
                    VariableValue::Unknown
                } else {
                    value
                },
                origins,
                exported,
                readonly,
            }
        })
        .collect();
    let descriptors = match DescriptorState::merge(
        &states
            .iter()
            .map(|state| state.descriptors.clone())
            .collect::<Vec<_>>(),
    ) {
        Ok(descriptors) => descriptors,
        Err(_) => {
            origins_saturated = true;
            DescriptorState::default()
        }
    };
    let tar_options = TarOptionsState::merge(states.iter().map(|state| state.tar_options.clone()));
    let mut possible_tar_options_aliases = states
        .iter()
        .flat_map(|state| state.possible_tar_options_aliases.iter().cloned())
        .collect::<Vec<_>>();
    possible_tar_options_aliases.sort();
    possible_tar_options_aliases.dedup();
    let definite_tar_options_aliases = possible_tar_options_aliases
        .iter()
        .filter(|name| {
            states
                .iter()
                .all(|state| state.definite_tar_options_aliases.contains(name))
        })
        .cloned()
        .collect();
    let mut function_bodies = states
        .iter()
        .flat_map(|state| state.functions.iter().map(|binding| binding.body))
        .collect::<Vec<_>>();
    function_bodies.sort_unstable();
    function_bodies.dedup();
    let functions = function_bodies
        .into_iter()
        .map(|body| {
            let name = &bodies[body].name;
            let attribute = |state: &ShellState| {
                state
                    .functions
                    .iter()
                    .find(|binding| binding.body == body)
                    .map_or(BindingAttribute::No, |binding| binding.exported)
            };
            let first = attribute(&states[0]);
            FunctionBinding {
                body,
                readonly: {
                    let first = states[0]
                        .functions
                        .iter()
                        .find(|binding| binding.body == body)
                        .map_or(BindingAttribute::No, |binding| binding.readonly);
                    if states.iter().all(|state| {
                        state
                            .functions
                            .iter()
                            .find(|binding| binding.body == body)
                            .map_or(BindingAttribute::No, |binding| binding.readonly)
                            == first
                    }) {
                        first
                    } else {
                        BindingAttribute::Unknown
                    }
                },
                exported: if states.iter().all(|state| attribute(state) == first) {
                    first
                } else {
                    BindingAttribute::Unknown
                },
                name_definite: states.iter().all(|state| {
                    state
                        .functions
                        .iter()
                        .any(|binding| binding.name_definite && bodies[binding.body].name == *name)
                }),
            }
        })
        .collect();
    let positional_zero = merge_positional_slot(
        states.iter().map(|state| state.positional_zero.as_ref()),
        &mut origins_saturated,
    );
    let positional_len = states
        .iter()
        .map(|state| state.positionals.len())
        .max()
        .unwrap_or_default();
    let positionals = (0..positional_len)
        .filter_map(|index| {
            merge_positional_slot(
                states.iter().map(|state| state.positionals.get(index)),
                &mut origins_saturated,
            )
        })
        .collect();
    let lastpipe = if states.iter().all(|state| state.lastpipe == first.lastpipe) {
        first.lastpipe
    } else {
        BindingAttribute::Unknown
    };
    let unknown_variables = states.iter().any(|state| state.unknown_variables);
    let lookup = match LookupState::merge(
        &states
            .iter()
            .map(|state| state.lookup.clone())
            .collect::<Vec<_>>(),
    ) {
        Ok(lookup) => lookup,
        Err(()) => {
            origins_saturated = true;
            let mut lookup = first.lookup.clone();
            lookup.invalidate_all();
            lookup
        }
    };
    (
        ShellState {
            cwd,
            variables,
            descriptors,
            tar_options,
            possible_tar_options_aliases,
            definite_tar_options_aliases,
            functions,
            positional_zero,
            positionals,
            lastpipe,
            unknown_variables,
            lookup,
        },
        origins_saturated,
    )
}

fn merge_positional_slot<'a>(
    values: impl Iterator<Item = Option<&'a PositionalValue>>,
    origins_saturated: &mut bool,
) -> Option<PositionalValue> {
    let values = values.collect::<Vec<_>>();
    if values.iter().all(|value| value.is_none()) {
        return None;
    }
    let first = values[0]
        .map(|value| &value.value)
        .unwrap_or(&VariableValue::Unset);
    let value = if values.iter().all(|value| {
        value
            .map(|value| &value.value)
            .unwrap_or(&VariableValue::Unset)
            == first
    }) {
        first.clone()
    } else {
        *origins_saturated = true;
        VariableValue::Unknown
    };
    let mut origins = values
        .into_iter()
        .flatten()
        .flat_map(|value| value.origins.iter().copied())
        .collect::<Vec<_>>();
    origins.sort_unstable();
    origins.dedup();
    if origins.len() > MAX_VARIABLE_ORIGINS {
        origins.truncate(MAX_VARIABLE_ORIGINS);
        *origins_saturated = true;
        return Some(PositionalValue {
            value: VariableValue::Unknown,
            origins,
        });
    }
    Some(PositionalValue { value, origins })
}

pub(crate) fn variable_binding<'a>(
    state: &'a ShellState,
    name: &str,
) -> Option<&'a VariableBinding> {
    state.variables.iter().find(|binding| binding.name == name)
}

pub(crate) fn merge_variable_values(left: &VariableValue, right: &VariableValue) -> VariableValue {
    if left == right {
        left.clone()
    } else {
        VariableValue::Unknown
    }
}

pub(crate) fn known_cwd(state: &ShellState) -> Option<&str> {
    match &state.cwd {
        Cwd::Known(cwd) => Some(cwd),
        Cwd::Unknown => None,
    }
}

pub(crate) fn current_pwd(state: &ShellState) -> Option<&str> {
    match state
        .variables
        .iter()
        .find(|binding| binding.name == "PWD")
        .map(|binding| &binding.value)
    {
        Some(value) => value.as_static(),
        None => known_cwd(state),
    }
}
