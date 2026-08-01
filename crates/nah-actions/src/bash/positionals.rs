//! Owns positional-parameter expansion and state transitions in the Bash coordinator.

use nah_parse::{Statement, Substitution, Syntax, Word};

use crate::bash_child_startup::ChildShell;
use crate::bash_model::{ResolvedWord, VariableValue};
use crate::bash_state::{MAX_POSITIONAL_PARAMETERS, PositionalValue};
use crate::shell_word::{ExpansionContext, contains_shell_pattern, static_word};

use super::{InjectedOrigins, Lowerer, PositionalCommand, PositionalExpansion};

pub(super) fn syntax_sets_positionals(syntax: &Syntax) -> bool {
    syntax.statements().iter().any(statement_sets_positionals)
}

pub(super) fn statement_sets_positionals(statement: &Statement) -> bool {
    match statement {
        Statement::Command {
            name,
            name_substitutions,
            arguments,
            ..
        } => {
            name == "set"
                && name_substitutions.is_empty()
                && arguments.iter().any(|argument| {
                    static_word(argument.raw(), argument.substitutions().is_empty()).as_deref()
                        == Some("--")
                })
        }
        Statement::Pipeline { stages, .. } => stages.iter().any(statement_sets_positionals),
        Statement::Chain { items, .. } => items.iter().any(statement_sets_positionals),
        Statement::Redirected { body, .. } => statement_sets_positionals(body),
        Statement::Subshell { statements } | Statement::Group { statements } => {
            statements.iter().any(statement_sets_positionals)
        }
        Statement::If {
            branches,
            else_body,
        } => {
            branches.iter().any(|branch| {
                branch
                    .condition()
                    .iter()
                    .chain(branch.body())
                    .any(statement_sets_positionals)
            }) || else_body.iter().any(statement_sets_positionals)
        }
        Statement::Loop {
            condition, body, ..
        } => condition.iter().chain(body).any(statement_sets_positionals),
        Statement::For { body, .. } => body.iter().any(statement_sets_positionals),
        Statement::FunctionDefinition { .. } => false,
        Statement::Coprocess { body, .. } => statement_sets_positionals(body),
        Statement::Case { arms, .. } => arms
            .iter()
            .flat_map(|arm| arm.body())
            .any(statement_sets_positionals),
        Statement::Assignments { .. }
        | Statement::RedirectOnly { .. }
        | Statement::LoopControl { .. }
        | Statement::UnmodeledStateMutation { .. }
        | Statement::Unsupported { .. } => false,
    }
}

impl Lowerer {
    pub(super) fn function_positional_values(
        &mut self,
        arguments: &[Word],
        argument_origins: &[Vec<usize>],
    ) -> Vec<PositionalValue> {
        let mut values = Vec::new();
        for (argument, origins) in arguments.iter().zip(argument_origins) {
            match self.positional_expansion(argument, origins) {
                PositionalExpansion::Exact(expanded) => {
                    for value in expanded {
                        if values.len() == MAX_POSITIONAL_PARAMETERS {
                            self.complete = false;
                            self.analysis_refused = true;
                            return values;
                        }
                        values.push(value);
                    }
                    continue;
                }
                PositionalExpansion::Unresolved => {
                    if values.len() == MAX_POSITIONAL_PARAMETERS {
                        self.complete = false;
                        self.analysis_refused = true;
                        return values;
                    }
                    values.push(PositionalValue {
                        value: VariableValue::Unknown,
                        origins: origins.clone(),
                    });
                    continue;
                }
                PositionalExpansion::NotPositional => {}
            }
            let resolution = self.word_resolution(argument, ExpansionContext::ShellWord);
            let value = match resolution {
                ResolvedWord::Absent => continue,
                ResolvedWord::Static { value, .. } => VariableValue::Static(value),
                ResolvedWord::Pattern { .. } | ResolvedWord::Unresolved { .. } => {
                    self.complete = false;
                    VariableValue::Unknown
                }
            };
            if values.len() == MAX_POSITIONAL_PARAMETERS {
                self.complete = false;
                self.analysis_refused = true;
                break;
            }
            values.push(PositionalValue {
                value,
                origins: origins.clone(),
            });
        }
        values
    }

    pub(super) fn positional_expansion(
        &mut self,
        argument: &Word,
        origins: &[usize],
    ) -> PositionalExpansion {
        if !argument.substitutions().is_empty() {
            return PositionalExpansion::NotPositional;
        }
        let quoted = matches!(argument.raw(), "\"$@\"" | "\"${@}\"");
        let unquoted = matches!(argument.raw(), "$@" | "${@}");
        if !quoted && !unquoted {
            return PositionalExpansion::NotPositional;
        }
        let positionals = self.state.positionals.clone();
        let mut values = Vec::with_capacity(positionals.len());
        for positional in positionals {
            let VariableValue::Static(value) = &positional.value else {
                self.complete = false;
                return PositionalExpansion::Unresolved;
            };
            if unquoted {
                if !self.unquoted_positional_is_exact(value) {
                    self.complete = false;
                    return PositionalExpansion::Unresolved;
                }
                if value.is_empty() {
                    continue;
                }
            }
            let mut value_origins = positional.origins;
            value_origins.extend_from_slice(origins);
            values.push(PositionalValue {
                value: VariableValue::Static(value.clone()),
                origins: self.bounded_origins(value_origins),
            });
        }
        PositionalExpansion::Exact(values)
    }

    pub(super) fn unquoted_positional_is_exact(&self, value: &str) -> bool {
        if contains_shell_pattern(value) {
            return false;
        }
        match self
            .state
            .variables
            .iter()
            .find(|binding| binding.name == "IFS")
            .map(|binding| &binding.value)
            .or_else(|| {
                self.ambient_variables
                    .iter()
                    .find_map(|(name, value)| (name == "IFS").then_some(value))
            }) {
            None | Some(VariableValue::Unset) => {
                !value.bytes().any(|byte| byte.is_ascii_whitespace())
            }
            Some(VariableValue::Static(ifs)) => {
                ifs.is_empty() || !value.chars().any(|character| ifs.contains(character))
            }
            Some(VariableValue::Unknown) => value.is_empty(),
        }
    }

    pub(super) fn positional_command(
        &mut self,
        name: &str,
        substitutions: &[Substitution],
        arguments: &[Word],
    ) -> Option<PositionalCommand> {
        if !matches!(name, "\"$@\"" | "\"${@}\"" | "$@" | "${@}") || !substitutions.is_empty() {
            return None;
        }
        if matches!(name, "$@" | "${@}")
            && self
                .state
                .positionals
                .iter()
                .any(|value| match &value.value {
                    VariableValue::Static(value) => !self.unquoted_positional_is_exact(value),
                    VariableValue::Unset | VariableValue::Unknown => true,
                })
        {
            self.complete = false;
            return None;
        }
        let unquoted = matches!(name, "$@" | "${@}");
        let frame = self
            .state
            .positionals
            .iter()
            .filter(|positional| {
                !unquoted
                    || !matches!(&positional.value, VariableValue::Static(value) if value.is_empty())
            })
            .collect::<Vec<_>>();
        let mut frame = frame.into_iter();
        let program = frame.next()?;
        let VariableValue::Static(program_value) = &program.value else {
            self.complete = false;
            return None;
        };
        let mut expanded_arguments = Vec::new();
        let mut argument_origins = Vec::new();
        for positional in frame {
            let VariableValue::Static(value) = &positional.value else {
                self.complete = false;
                return None;
            };
            expanded_arguments.push(Word::from_literal(value));
            argument_origins.push(positional.origins.clone());
        }
        expanded_arguments.extend_from_slice(arguments);
        argument_origins.resize(expanded_arguments.len(), Vec::new());
        Some(PositionalCommand {
            name: program_value.clone(),
            arguments: expanded_arguments,
            origins: InjectedOrigins {
                name: program.origins.clone(),
                arguments: argument_origins,
            },
        })
    }

    pub(super) fn update_positional_state(
        &mut self,
        program: &str,
        arguments: &[Word],
        argument_origins: &[Vec<usize>],
    ) {
        match program {
            "set" => self.update_set_positionals(arguments, argument_origins),
            "shift" => self.update_shift_positionals(arguments),
            _ => {}
        }
    }

    pub(super) fn update_set_positionals(
        &mut self,
        arguments: &[Word],
        argument_origins: &[Vec<usize>],
    ) {
        if arguments.is_empty() {
            return;
        }
        let values = self.function_positional_values(arguments, argument_origins);
        let mut index = 0;
        let mut explicit_separator = false;
        while let Some(value) = values.get(index) {
            let VariableValue::Static(value) = &value.value else {
                self.mark_positionals_unknown(&values);
                return;
            };
            if value == "--" {
                index += 1;
                explicit_separator = true;
                break;
            }
            if matches!(value.as_str(), "-" | "+") {
                index += 1;
                continue;
            }
            if value.len() > 1 && value.starts_with(['-', '+']) {
                let options = &value[1..];
                if !options
                    .chars()
                    .all(|option| "abefhkmnptuvxBCEHPTcsoO".contains(option))
                {
                    return;
                }
                index += 1;
                if options.contains('o') || options.contains('O') {
                    let Some(option_name) = values.get(index) else {
                        return;
                    };
                    if !matches!(option_name.value, VariableValue::Static(_)) {
                        self.complete = false;
                        self.analysis_refused = true;
                        return;
                    }
                    index += 1;
                }
                continue;
            }
            break;
        }
        if index == values.len() && !explicit_separator {
            return;
        }
        self.state.positionals = values[index..].to_vec();
    }

    pub(super) fn update_shift_positionals(&mut self, arguments: &[Word]) {
        let count = match arguments {
            [] => 1,
            [count] => {
                let Some(count) = static_word(count.raw(), count.substitutions().is_empty()) else {
                    self.mark_positionals_unknown(&[]);
                    return;
                };
                if count.bytes().all(|byte| byte.is_ascii_digit()) {
                    let Ok(count) = count.parse::<usize>() else {
                        return;
                    };
                    count
                } else if count.strip_prefix('-').is_some_and(|count| {
                    !count.is_empty() && count.bytes().all(|byte| byte.is_ascii_digit())
                }) {
                    return;
                } else {
                    self.mark_positionals_unknown(&[]);
                    return;
                }
            }
            _ => return,
        };
        if count <= self.state.positionals.len() {
            self.state.positionals.drain(..count);
        }
    }

    pub(super) fn mark_positionals_unknown(&mut self, candidates: &[PositionalValue]) {
        self.complete = false;
        self.analysis_refused = true;
        self.set_positionals_unknown(candidates);
    }

    pub(super) fn set_positionals_unknown(&mut self, candidates: &[PositionalValue]) {
        let mut origins = self
            .state
            .positionals
            .iter()
            .chain(candidates)
            .flat_map(|value| value.origins.iter().copied())
            .collect::<Vec<_>>();
        origins = self.bounded_origins(origins);
        let len = self
            .state
            .positionals
            .len()
            .max(candidates.len())
            .clamp(9, MAX_POSITIONAL_PARAMETERS);
        self.state.positionals = (0..len)
            .map(|_| PositionalValue {
                value: VariableValue::Unknown,
                origins: origins.clone(),
            })
            .collect();
    }

    pub(super) fn prepare_child_positionals(
        &mut self,
        child: &ChildShell,
        argument_origins: &[Vec<usize>],
    ) {
        self.state.positional_zero = Some(PositionalValue {
            value: child
                .argv0
                .clone()
                .map_or(VariableValue::Unknown, VariableValue::Static),
            origins: child
                .argv0_argument
                .and_then(|index| argument_origins.get(index))
                .cloned()
                .unwrap_or_default(),
        });
        self.state.positionals = child
            .positionals
            .iter()
            .zip(&child.positional_arguments)
            .map(|(value, index)| PositionalValue {
                value: value
                    .clone()
                    .map_or(VariableValue::Unknown, VariableValue::Static),
                origins: argument_origins.get(*index).cloned().unwrap_or_default(),
            })
            .collect();
    }
}
