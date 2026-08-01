//! Lowers Bash branches and loops while conservatively merging shell state.

use nah_parse::{
    CaseArm, CaseTermination, ConditionalBranch, LoopControlKind, LoopKind, Statement, Word,
};
use nah_proto::ctx::{AbsolutePath, Platform};

use crate::bash_model::{ProgramDraft, VariableValue};
use crate::bash_state::{Cwd, ShellState, current_pwd, known_cwd};
use crate::bash_tar::TarOptionsState;
use crate::paths::resolve_from_cwd;
use crate::shell_word::{contains_shell_pattern, static_word};

use super::{Lowered, Lowerer};

pub(super) fn condition_has_precise_cwd_outcome(
    condition: &[Statement],
    platform: Platform,
) -> bool {
    let [
        Statement::Command {
            name,
            name_substitutions,
            arguments,
            ..
        },
    ] = condition
    else {
        return false;
    };
    if name != "cd" || !name_substitutions.is_empty() {
        return false;
    }
    match arguments.as_slice() {
        [] => true,
        [target] if target.substitutions().is_empty() => {
            let expand_tilde = target.raw().starts_with('~');
            static_word(target.raw(), true)
                .is_some_and(|target| cd_target_ignores_cdpath(&target, expand_tilde, platform))
        }
        _ => false,
    }
}

pub(super) fn cd_target_ignores_cdpath(
    target: &str,
    expand_tilde: bool,
    platform: Platform,
) -> bool {
    target == "-"
        || matches!(target, "." | "..")
        || target.starts_with("./")
        || target.starts_with("../")
        || (platform == Platform::Windows
            && (target.starts_with(".\\") || target.starts_with("..\\")))
        || (expand_tilde && target.starts_with('~'))
        || AbsolutePath::new(platform, target).is_ok()
}

pub(super) fn condition_repeats_forever(kind: LoopKind, condition: &[Statement]) -> bool {
    matches!(
        (kind, condition),
        (
            LoopKind::While,
            [Statement::Command {
                name,
                name_substitutions,
                assignments,
                unmodeled_assignments,
                arguments,
                redirects,
            }]
        ) if matches!(name.as_str(), ":" | "true")
            && name_substitutions.is_empty()
            && assignments.is_empty()
            && unmodeled_assignments.is_empty()
            && arguments.is_empty()
            && redirects.is_empty()
    ) || matches!(
        (kind, condition),
        (
            LoopKind::Until,
            [Statement::Command {
                name,
                name_substitutions,
                assignments,
                unmodeled_assignments,
                arguments,
                redirects,
            }]
        ) if name == "false"
            && name_substitutions.is_empty()
            && assignments.is_empty()
            && unmodeled_assignments.is_empty()
            && arguments.is_empty()
            && redirects.is_empty()
    )
}

pub(super) fn has_unconditional_parent_break(statements: &[Statement]) -> bool {
    matches!(
        unconditional_parent_control(statements),
        Some(LoopControlKind::Break)
    )
}

pub(super) fn unconditional_parent_control(statements: &[Statement]) -> Option<LoopControlKind> {
    for statement in statements {
        match statement {
            Statement::LoopControl {
                kind,
                arguments,
                redirects,
            } if redirects.is_empty() && valid_loop_control_arguments(arguments) => {
                return Some(*kind);
            }
            Statement::Group { statements } => {
                if let Some(kind) = unconditional_parent_control(statements) {
                    return Some(kind);
                }
            }
            Statement::If { .. }
            | Statement::Loop { .. }
            | Statement::For { .. }
            | Statement::Case { .. }
            | Statement::Chain { .. }
            | Statement::Redirected { .. }
            | Statement::Assignments { .. }
            | Statement::Unsupported { .. } => return None,
            _ => {}
        }
    }
    None
}

pub(super) fn valid_loop_control_arguments(arguments: &[Word]) -> bool {
    match arguments {
        [] => true,
        [levels] => static_word(levels.raw(), levels.substitutions().is_empty())
            .and_then(|levels| levels.parse::<usize>().ok())
            .is_some_and(|levels| levels > 0),
        _ => false,
    }
}

pub(super) fn contains_loop_control(statements: &[Statement]) -> bool {
    statements.iter().any(|statement| match statement {
        Statement::LoopControl { .. } => true,
        Statement::Chain { items, .. } => contains_loop_control(items),
        Statement::Redirected { body, .. } => {
            contains_loop_control(std::slice::from_ref(body.as_ref()))
        }
        Statement::Coprocess { body, .. } => {
            contains_loop_control(std::slice::from_ref(body.as_ref()))
        }
        Statement::Group { statements } => contains_loop_control(statements),
        Statement::If {
            branches,
            else_body,
        } => {
            branches.iter().any(|branch| {
                contains_loop_control(branch.condition()) || contains_loop_control(branch.body())
            }) || contains_loop_control(else_body)
        }
        Statement::Loop {
            condition, body, ..
        } => contains_loop_control(condition) || contains_loop_control(body),
        Statement::For { body, .. } => contains_loop_control(body),
        Statement::Case { arms, .. } => arms.iter().any(|arm| contains_loop_control(arm.body())),
        Statement::Pipeline { .. }
        | Statement::Subshell { .. }
        | Statement::Command { .. }
        | Statement::Assignments { .. }
        | Statement::RedirectOnly { .. }
        | Statement::FunctionDefinition { .. }
        | Statement::UnmodeledStateMutation { .. }
        | Statement::Unsupported { .. } => false,
    })
}

impl Lowerer {
    pub(super) fn update_cd_state(
        &mut self,
        program: &ProgramDraft,
        arguments: &[Word],
        local_arguments: &[Word],
    ) {
        if !matches!(program, ProgramDraft::Static(program) if program == "cd") {
            return;
        }
        match local_arguments {
            [] => self.state.cwd = Cwd::Known(self.home.clone()),
            [target] if target.substitutions().is_empty() => {
                let expand_tilde = arguments[0].raw().starts_with('~');
                if let Some(target) = static_word(target.raw(), true) {
                    if target == "-" {
                        // OLDPWD is runtime shell state that nah does not
                        // observe. The invocation is still understood;
                        // only subsequent relative paths lose precision.
                        self.state.cwd = Cwd::Unknown;
                    } else if !cd_target_ignores_cdpath(&target, expand_tilde, self.platform) {
                        // A bare relative operand can be resolved through
                        // CDPATH instead of beneath the current directory.
                        self.complete = false;
                        self.state.cwd = Cwd::Unknown;
                    } else if let Some(cwd) = resolve_from_cwd(
                        known_cwd(&self.state),
                        current_pwd(&self.state),
                        &target,
                        &self.home,
                        self.platform,
                        expand_tilde,
                    ) {
                        self.state.cwd = Cwd::Known(cwd);
                    } else {
                        self.complete = false;
                        self.state.cwd = Cwd::Unknown;
                    }
                } else {
                    self.complete = false;
                    self.state.cwd = Cwd::Unknown;
                }
            }
            _ => {
                self.complete = false;
                self.state.cwd = Cwd::Unknown;
            }
        }
        if self.is_local_variable("PWD") {
            let pwd = known_cwd(&self.state).map(str::to_owned);
            self.set_local_variable("PWD", pwd);
        }
    }

    pub(super) fn lower_if(
        &mut self,
        branches: &[ConditionalBranch],
        else_body: &[Statement],
    ) -> Lowered {
        let entry = self.state.clone();
        let mut lowered = Lowered::default();
        let mut exits = Vec::new();
        let mut failure_state = entry.clone();
        for branch in branches {
            self.state.clone_from(&failure_state);
            let condition_entry = self.state.clone();
            let condition = self.lower_optional_statements(branch.condition());
            lowered.extend(condition);
            let condition_success = self.state.clone();
            let precise_cwd = condition_has_precise_cwd_outcome(branch.condition(), self.platform);
            if condition_success.cwd != condition_entry.cwd && !precise_cwd {
                self.state.cwd = Cwd::Unknown;
            }
            lowered.extend(self.lower_optional_statements(branch.body()));
            exits.push(self.state.clone());
            failure_state = if precise_cwd || condition_success.cwd == condition_entry.cwd {
                condition_entry
            } else {
                ShellState {
                    cwd: Cwd::Unknown,
                    variables: condition_entry.variables,
                    descriptors: condition_entry.descriptors,
                    tar_options: condition_entry.tar_options,
                    possible_tar_options_aliases: condition_entry.possible_tar_options_aliases,
                    definite_tar_options_aliases: condition_entry.definite_tar_options_aliases,
                    functions: condition_entry.functions,
                    positional_zero: condition_entry.positional_zero,
                    positionals: condition_entry.positionals,
                    lastpipe: condition_entry.lastpipe,
                    unknown_variables: condition_entry.unknown_variables,
                    lookup: condition_entry.lookup,
                }
            };
        }
        self.state.clone_from(&failure_state);
        if else_body.is_empty() {
            exits.push(self.state.clone());
        } else {
            lowered.extend(self.lower_optional_statements(else_body));
            exits.push(self.state.clone());
        }
        self.state = self.merged_state(&exits);
        lowered
    }

    pub(super) fn lower_loop(
        &mut self,
        kind: LoopKind,
        condition: &[Statement],
        body: &[Statement],
    ) -> Lowered {
        let entry = self.state.clone();
        let mut lowered = self.lower_statements(condition);
        let condition_state = self.state.clone();
        self.loop_depth += 1;
        lowered.extend(self.lower_optional_statements(body));
        self.loop_depth -= 1;
        if self.state != condition_state {
            // A later iteration starts from a state this single lowering did
            // not use, so relative effects in subsequent iterations are not
            // fully represented.
            self.complete = false;
        }
        if condition_repeats_forever(kind, condition) && !has_unconditional_parent_break(body) {
            self.complete = false;
        }
        self.state = self.merged_state(&[entry, condition_state, self.state.clone()]);
        lowered
    }

    pub(super) fn lower_for(
        &mut self,
        variable: &str,
        values: &[Word],
        body: &[Statement],
    ) -> Lowered {
        let mut lowered = self.lower_words(values);
        let static_values = values
            .iter()
            .map(|value| {
                let expands_tilde = value.raw().starts_with('~');
                let value =
                    static_word(value.raw(), value.substitutions().is_empty()).filter(|value| {
                        !contains_shell_pattern(value) && !value.contains(['{', '}'])
                    })?;
                if value.starts_with('~') && expands_tilde {
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
            })
            .collect::<Option<Vec<_>>>();
        let Some(static_values) = static_values.filter(|values| !values.is_empty()) else {
            self.complete = false;
            self.set_local_variable(variable, VariableValue::Unknown);
            self.loop_depth += 1;
            lowered.extend(self.lower_optional_statements(body));
            self.loop_depth -= 1;
            return lowered;
        };
        let value_count = static_values.len();
        let mut reachable_tar_options = vec![self.state.tar_options.clone()];
        for (index, value) in static_values.into_iter().enumerate() {
            self.set_local_variable(variable, VariableValue::Static(value));
            let body_entry = self.state.clone();
            self.loop_depth += 1;
            lowered.extend(self.lower_statements(body));
            self.loop_depth -= 1;
            reachable_tar_options.push(self.state.tar_options.clone());
            if index + 1 < value_count && self.state != body_entry {
                // A later iteration may start after a failed state change.
                // Keep all visible effects, but do not report exact coverage.
                self.complete = false;
                if self.state.cwd != body_entry.cwd {
                    self.state.cwd = Cwd::Unknown;
                }
            }
        }
        if contains_loop_control(body) {
            self.complete = false;
            for binding in &mut self.state.variables {
                binding.value = VariableValue::Unknown;
            }
            self.state.tar_options = TarOptionsState::merge(reachable_tar_options);
        }
        lowered
    }

    pub(super) fn lower_case(&mut self, value: &Word, arms: &[CaseArm]) -> Lowered {
        let entry = self.state.clone();
        let mut lowered = self.lower_words(std::slice::from_ref(value));
        let mut exits = vec![entry.clone()];
        for (index, arm) in arms.iter().enumerate() {
            self.state.clone_from(&entry);
            lowered.extend(self.lower_words(arm.patterns()));
            lowered.extend(self.lower_optional_statements(arm.body()));
            if index + 1 < arms.len()
                && arm.termination() != CaseTermination::Break
                && self.state != entry
            {
                // Fallthrough can feed this state into a later arm. Keep the
                // common read-only case full, but fail closed when the arm
                // changes cwd and later relative effects could resolve
                // differently.
                self.complete = false;
            }
            exits.push(self.state.clone());
        }
        self.state = self.merged_state(&exits);
        lowered
    }
}
