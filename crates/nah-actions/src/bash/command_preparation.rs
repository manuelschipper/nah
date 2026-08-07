//! Performs order-sensitive current-shell preparation before effect lowering.

use nah_parse::{Redirect, Substitution, Word};

use super::assignments::declaration_binding_names;
use super::{AssignmentUpdate, CommandContext, Lowered, Lowerer};
use crate::bash_child_startup::env_requires_refusal;
use crate::bash_content::substitution_output;
use crate::bash_descriptors::RedirectProvenance;
use crate::bash_execution::execution_spec;
use crate::bash_filesystem::terminal_program_help;
use crate::bash_git_config::{AliasAnalysis, alias_analysis};
use crate::bash_invocation::static_argv;
use crate::bash_model::{ProgramDraft, ResolvedWord, UnresolvedCause};
use crate::bash_self_protection::cargo_install_command;
use crate::bash_semantics::normalize_arguments;
use crate::bash_state::known_cwd;
use crate::bash_symlinks::{creates_descriptor_symlink, transformed_descriptor_symlink_source};
use crate::shell_word::{
    ExpansionContext, contains_unquoted_pattern, exact_env_name, referenced_env_names, resolve_word,
};

fn unresolved_execution_operand(
    program: &str,
    arguments: &[Word],
    resolutions: &[ResolvedWord],
    builtin_target: bool,
) -> bool {
    let transformed = |index: usize| {
        matches!(
            resolutions.get(index),
            Some(ResolvedWord::Unresolved {
                cause: UnresolvedCause::ShellTransformation,
                ..
            })
        )
    };
    if builtin_target && program == "eval" {
        return (0..resolutions.len()).any(transformed);
    }
    if builtin_target && program == "trap" {
        return transformed(usize::from(arguments.first().map(Word::raw) == Some("--")));
    }
    execution_spec(program, arguments)
        .and_then(|execution| execution.transformed_operand_index)
        .is_some_and(transformed)
}

pub(super) struct PreparedCommand<'a> {
    pub(super) name: &'a str,
    pub(super) assignments: &'a [(String, Word)],
    pub(super) arguments: &'a [Word],
    pub(super) redirects: Vec<Redirect>,
    pub(super) redirect_provenance: Vec<RedirectProvenance>,
    pub(super) builtin_target: bool,
    pub(super) invocation_cwd: Option<String>,
    pub(super) pattern_program: bool,
    pub(super) lowered_substitutions: Vec<(&'a Substitution, Lowered)>,
    pub(super) assignment_updates: Vec<AssignmentUpdate>,
    pub(super) invocation_origins: Vec<usize>,
    pub(super) command_argument_origins: Vec<Vec<usize>>,
    pub(super) program: ProgramDraft,
    pub(super) lexical_program: Option<String>,
    pub(super) words: Vec<String>,
    pub(super) argv: Option<Vec<String>>,
    pub(super) local_arguments: Vec<Word>,
    pub(super) handled_tar_options_state: bool,
    pub(super) tar_argument_variants: Option<Vec<Vec<Word>>>,
    pub(super) git_alias: Option<AliasAnalysis>,
    pub(super) terminal_help: bool,
    pub(super) direct_program: Option<String>,
}

impl Lowerer {
    pub(super) fn prepare_command<'a>(
        &mut self,
        name: &'a str,
        name_substitutions: &'a [Substitution],
        assignments: &'a [(String, Word)],
        arguments: &'a [Word],
        redirects: &'a [Redirect],
        context: CommandContext<'_>,
    ) -> PreparedCommand<'a> {
        let CommandContext {
            injected_origins,
            exact_target,
            builtin_target,
        } = context;
        let invocation_cwd = known_cwd(&self.state).map(str::to_owned);
        let mut pattern_program = contains_unquoted_pattern(name);
        let mut substitutions = Vec::new();
        substitutions.extend(name_substitutions);
        for (_, value) in assignments {
            substitutions.extend(value.substitutions());
        }
        for argument in arguments {
            substitutions.extend(argument.substitutions());
        }
        for redirect in redirects {
            substitutions.extend(redirect.target_substitutions());
            substitutions.extend(redirect.body_substitutions());
        }
        let lowered_substitutions = substitutions
            .into_iter()
            .map(|substitution| {
                let parent_state = self.state.clone();
                let stages = self.lower_statements(substitution.statements());
                self.state = parent_state;
                (substitution, stages)
            })
            .collect::<Vec<_>>();
        let mut assignment_updates = Vec::with_capacity(assignments.len());
        for (_, word) in assignments {
            let origins =
                self.expansion_origins(word.raw(), word.substitutions(), &lowered_substitutions);
            assignment_updates.push(self.assignment_update(word, origins));
        }
        let mut invocation_origins =
            self.expansion_origins(name, name_substitutions, &lowered_substitutions);
        invocation_origins.extend(injected_origins.name.iter().copied());
        let mut command_argument_origins = Vec::with_capacity(arguments.len());
        for (index, argument) in arguments.iter().enumerate() {
            let mut origins = self.expansion_origins(
                argument.raw(),
                argument.substitutions(),
                &lowered_substitutions,
            );
            if let Some(injected) = injected_origins.arguments.get(index) {
                origins.extend(injected.iter().copied());
            }
            let origins = self.bounded_origins(origins);
            invocation_origins.extend(origins.iter().copied());
            command_argument_origins.push(origins);
        }
        for redirect in redirects {
            if let Some(target) = redirect.target() {
                invocation_origins.extend(self.expansion_origins(
                    target,
                    redirect.target_substitutions(),
                    &lowered_substitutions,
                ));
            }
            if let Some(body) = redirect.body() {
                invocation_origins.extend(self.expansion_origins(
                    body,
                    redirect.body_substitutions(),
                    &lowered_substitutions,
                ));
            }
        }
        invocation_origins = self.bounded_origins(invocation_origins);

        for raw in assignments
            .iter()
            .map(|(_, value)| value.raw())
            .chain(arguments.iter().map(Word::raw))
            .chain(
                redirects
                    .iter()
                    .flat_map(|redirect| [redirect.target(), redirect.body()])
                    .flatten(),
            )
        {
            for name in referenced_env_names(raw) {
                self.prepare_variable_reference(&name);
            }
        }
        for variable in referenced_env_names(name) {
            self.prepare_variable_reference(&variable);
        }
        let mut direct_program = None;
        let mut lexical_program = None;
        let variables = self.visible_variables();
        let program_resolution = resolve_word(
            name,
            name_substitutions,
            &variables,
            ExpansionContext::ShellWord,
            substitution_output,
        );
        let program = match program_resolution {
            ResolvedWord::Static { value, .. } if !value.is_empty() => {
                lexical_program = Some(value.clone());
                let target = exact_target.unwrap_or(&value);
                if target.contains(['/', '\\']) {
                    direct_program = Some(target.to_owned());
                }
                ProgramDraft::Static(self.normalized_program(target))
            }
            ResolvedWord::Pattern { value, .. } if !value.is_empty() => {
                pattern_program = true;
                lexical_program = Some(value.clone());
                let target = exact_target.unwrap_or(&value);
                if target.contains(['/', '\\']) {
                    direct_program = Some(target.to_owned());
                }
                ProgramDraft::Static(self.normalized_program(target))
            }
            ResolvedWord::Unresolved { .. }
                if name_substitutions.is_empty()
                    && exact_env_name(name).is_some_and(|name| {
                        !self.is_local_variable(name) && !self.is_ambient_variable(name)
                    }) =>
            {
                ProgramDraft::Env {
                    key: self
                        .env_key(exact_env_name(name).expect("checked exact environment name")),
                }
            }
            ResolvedWord::Absent
            | ResolvedWord::Static { .. }
            | ResolvedWord::Pattern { .. }
            | ResolvedWord::Unresolved { .. } => {
                self.complete = false;
                ProgramDraft::Unresolved
            }
        };
        let (resolved_arguments, argument_resolutions) = self.resolved_arguments(arguments);
        let redirect_provenance = self.redirect_provenance(redirects, &lowered_substitutions);
        let resolved_redirects = self.resolved_redirects(redirects);
        let words = std::iter::once(name.to_owned())
            .chain(arguments.iter().map(|argument| argument.raw().to_owned()))
            .collect::<Vec<_>>();
        let argv = lexical_program
            .as_deref()
            .and_then(|program| static_argv(program, &resolved_arguments));
        let mut local_arguments = match &program {
            ProgramDraft::Static(program) => {
                normalize_arguments(program, &resolved_arguments, self.platform)
            }
            ProgramDraft::Env { .. } | ProgramDraft::Unresolved => resolved_arguments,
        };
        if matches!(&program, ProgramDraft::Static(program) if program == "cargo")
            && cargo_install_command(&local_arguments)
        {
            self.prepare_variable_reference("CARGO_HOME");
        }
        if matches!(&program, ProgramDraft::Static(program)
        if unresolved_execution_operand(
            program,
            &local_arguments,
            &argument_resolutions,
            builtin_target,
        )) {
            self.analysis_refused = true;
        }
        if matches!(&program, ProgramDraft::Static(program)
            if env_requires_refusal(program, &local_arguments))
        {
            self.complete = false;
            self.analysis_refused = true;
        }
        let handled_tar_options_state =
            if builtin_target && let ProgramDraft::Static(program) = &program {
                self.update_tar_options_state(program, assignments, arguments)
            } else {
                false
            };
        let tar_argument_variants =
            matches!(&program, ProgramDraft::Static(program) if program == "tar")
                .then(|| self.tar_argument_variants(assignments, &local_arguments));
        if let Some(arguments) = tar_argument_variants
            .as_ref()
            .and_then(|variants| variants.first())
        {
            local_arguments.clone_from(arguments);
        }
        if matches!(&program, ProgramDraft::Static(program) if program == "tar")
            && let Some(archive) = assignments
                .iter()
                .rev()
                .find(|(name, _)| name == "TAPE")
                .and_then(|(_, value)| {
                    crate::bash_tar::tape_archive_argument(
                        &self.resolve_local_argument(value),
                        &local_arguments,
                    )
                })
        {
            local_arguments.insert(0, archive);
        }
        if builtin_target && let ProgramDraft::Static(program) = &program {
            self.update_readonly_functions(program, &local_arguments);
            self.update_exported_functions(program, &local_arguments);
        }
        if builtin_target && matches!(&program, ProgramDraft::Static(program) if program == "unset")
        {
            self.unset_functions(&local_arguments);
            self.unset_variables(&local_arguments);
        }
        if builtin_target && matches!(&program, ProgramDraft::Static(program) if program == "local")
        {
            let names = declaration_binding_names(&local_arguments, assignments);
            if let Some(scope) = self.function_local_scopes.last_mut() {
                for name in names {
                    if !scope.contains(&name) {
                        scope.push(name);
                    }
                }
            } else {
                self.complete = false;
            }
        }
        let git_alias = matches!(&program, ProgramDraft::Static(program) if program == "git")
            .then(|| alias_analysis(&local_arguments));
        if git_alias
            .as_ref()
            .is_some_and(|analysis| !analysis.complete)
        {
            self.complete = false;
        }
        let terminal_help = match &program {
            ProgramDraft::Static(program) => tar_argument_variants.as_ref().map_or_else(
                || terminal_program_help(program, &local_arguments, self.platform),
                |variants| {
                    variants
                        .iter()
                        .all(|arguments| terminal_program_help(program, arguments, self.platform))
                },
            ),
            ProgramDraft::Env { .. } | ProgramDraft::Unresolved => false,
        };
        if !terminal_help
            && matches!(&program, ProgramDraft::Static(program)
            if creates_descriptor_symlink(program, &local_arguments)
                || transformed_descriptor_symlink_source(
                    program,
                    &local_arguments,
                    &argument_resolutions,
                )
                || tar_argument_variants.as_ref().is_some_and(|variants| {
                    variants
                        .iter()
                        .any(|arguments| {
                            creates_descriptor_symlink(program, arguments)
                                || transformed_descriptor_symlink_source(
                                    program,
                                    arguments,
                                    &argument_resolutions,
                                )
                        })
                }))
        {
            self.complete = false;
            self.analysis_refused = true;
        }
        if matches!(&program, ProgramDraft::Static(program) if program == "coproc") {
            self.complete = false;
        }

        PreparedCommand {
            name,
            assignments,
            arguments,
            redirects: resolved_redirects,
            redirect_provenance,
            builtin_target,
            invocation_cwd,
            pattern_program,
            lowered_substitutions,
            assignment_updates,
            invocation_origins,
            command_argument_origins,
            program,
            lexical_program,
            words,
            argv,
            local_arguments,
            handled_tar_options_state,
            tar_argument_variants,
            git_alias,
            terminal_help,
            direct_program,
        }
    }
}
