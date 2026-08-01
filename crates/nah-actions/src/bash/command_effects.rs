//! Projects prepared command inputs into one typed stage draft.

use nah_parse::{Redirect, Substitution, Word};
use nah_proto::action::SemanticCode;

use super::assignments::lastpipe_update;
use super::command_builtins::BuiltinEffects;
use super::command_classification::CommandClassifications;
use super::command_descriptors::CommandDescriptorEffects;
use super::command_payload::CommandPayloads;
use super::command_preparation::PreparedCommand;
use super::command_resources::CommandResources;
use super::{AssignmentUpdate, Lowered, Lowerer};
use crate::bash_descriptors::{DescriptorRedirectPlan, shell_attached_to_dev_socket};
use crate::bash_flow::redirects_stdin;
use crate::bash_invocation::invocation;
use crate::bash_logical_storage::models_logical_storage_command;
use crate::bash_model::{InvocationDraft, ProgramDraft, StageDraft, StdoutDraft};
use crate::bash_self_protection::{
    EnvironmentVariables, environment_operation as nah_environment_operation,
    hardlink_operation as nah_hardlink_operation, inspection_operation as nah_inspection_operation,
    operation as nah_mutation_operation, protected_access_control_operation,
    protected_cargo_install_operation, protected_git_operation,
};
use crate::bash_state::{BindingAttribute, known_cwd};
use crate::bash_wrappers::hides_deferred_code;
use crate::shell_word::static_word;

pub(super) struct AnalyzedCommand<'a> {
    pub(super) assignments: &'a [(String, Word)],
    pub(super) arguments: &'a [Word],
    pub(super) redirects: Vec<Redirect>,
    pub(super) builtin_target: bool,
    pub(super) program: ProgramDraft,
    pub(super) local_arguments: Vec<Word>,
    pub(super) lowered_substitutions: Vec<(&'a Substitution, Lowered)>,
    pub(super) assignment_updates: Vec<AssignmentUpdate>,
    pub(super) invocation_origins: Vec<usize>,
    pub(super) command_argument_origins: Vec<Vec<usize>>,
    pub(super) stage: usize,
    pub(super) stage_draft: StageDraft,
    pub(super) descriptor_plan: DescriptorRedirectPlan,
    pub(super) descriptor_flows: Vec<(usize, usize)>,
    pub(super) lowered_startup: Lowered,
    pub(super) lowered_payload: Option<(Lowered, bool)>,
    pub(super) lowered_executors: Vec<(Lowered, bool)>,
    pub(super) exact_variable_write: Option<(String, String, Vec<usize>)>,
    pub(super) current_shell_eval: bool,
    pub(super) current_shell_source: bool,
    pub(super) execution: Option<crate::bash_execution::Lowering>,
    pub(super) lastpipe_update: Option<BindingAttribute>,
}

impl Lowerer {
    pub(super) fn lower_command_effects<'a>(
        &mut self,
        command: PreparedCommand<'a>,
    ) -> AnalyzedCommand<'a> {
        let PreparedCommand {
            name,
            assignments,
            arguments,
            redirects,
            redirect_provenance,
            builtin_target,
            invocation_cwd,
            pattern_program,
            lowered_substitutions,
            assignment_updates,
            mut invocation_origins,
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
        } = command;
        let CommandPayloads {
            producer,
            content_writes,
            lowered_startup,
            lowered_payload,
            lowered_executors,
        } = self.lower_command_payloads(
            name,
            &program,
            assignments,
            &local_arguments,
            &redirects,
            builtin_target,
            terminal_help,
            git_alias.as_ref(),
            tar_argument_variants.as_deref(),
            &assignment_updates,
            &command_argument_origins,
        );
        let stage = self.stages.len();
        let CommandDescriptorEffects {
            producer,
            content_writes,
            plan: descriptor_plan,
            filesystems: filesystem_drafts,
            mut network_endpoints,
            flows: mut descriptor_flows,
            read: descriptor_read,
        } = self.lower_command_descriptors(
            &program,
            &local_arguments,
            &redirects,
            &redirect_provenance,
            builtin_target,
            stage,
            producer,
            content_writes,
        );
        let redirected_descriptors = &descriptor_plan.command;
        let BuiltinEffects {
            exact_variable_write,
            current_shell_eval,
            current_shell_source,
        } = self.lower_builtin_effects(
            &program,
            arguments,
            &local_arguments,
            assignments,
            &assignment_updates,
            descriptor_read.as_ref(),
            builtin_target,
            handled_tar_options_state,
            lowered_payload.as_ref(),
        );
        if let Some((_, _, origins)) = &exact_variable_write {
            invocation_origins.extend(origins.iter().copied());
            invocation_origins = self.bounded_origins(invocation_origins);
        }
        let classifications = self.classify_command(
            &program,
            &local_arguments,
            redirected_descriptors,
            builtin_target,
            terminal_help,
            direct_program.as_ref(),
            tar_argument_variants.as_deref(),
            lowered_payload.is_some(),
        );
        if let Some(execution) = &classifications.execution {
            network_endpoints.extend(execution.network_endpoints.iter().cloned());
            descriptor_flows.extend(
                execution
                    .descriptor_sources
                    .iter()
                    .copied()
                    .map(|source| (source, stage)),
            );
            descriptor_flows.extend(
                execution
                    .descriptor_sinks
                    .iter()
                    .copied()
                    .map(|sink| (stage, sink)),
            );
        }
        let nah_mutation = if let ProgramDraft::Static(program) = &program {
            let environment_assignments = assignments
                .iter()
                .zip(&assignment_updates)
                .map(|((name, _), update)| (name.clone(), update.value.clone()))
                .collect::<Vec<_>>();
            let environment_words = local_arguments
                .iter()
                .filter_map(|word| static_word(word.raw(), word.substitutions().is_empty()))
                .collect::<Vec<_>>();
            nah_mutation_operation(program, &local_arguments, &self.home, self.platform)
                .or_else(|| {
                    protected_cargo_install_operation(
                        program,
                        &local_arguments,
                        &environment_assignments,
                        EnvironmentVariables {
                            visible: &self.visible_environment_variables(),
                            runtime: &self.runtime_variables,
                        },
                        known_cwd(&self.state),
                        &self.home,
                        &self.critical_paths,
                        self.platform,
                    )
                })
                .or_else(|| {
                    protected_git_operation(
                        program,
                        &local_arguments,
                        known_cwd(&self.state),
                        &self.home,
                        &self.critical_paths,
                        self.platform,
                    )
                })
                .or_else(|| {
                    protected_access_control_operation(
                        program,
                        &local_arguments,
                        known_cwd(&self.state),
                        &self.home,
                        &self.critical_paths,
                        self.platform,
                    )
                })
                .or_else(|| {
                    nah_environment_operation(
                        program,
                        &environment_words,
                        &environment_assignments,
                        EnvironmentVariables {
                            visible: &self.visible_environment_variables(),
                            runtime: &self.runtime_variables,
                        },
                        &self.home,
                        &self.critical_paths,
                        self.platform,
                    )
                })
                .or_else(|| {
                    nah_hardlink_operation(
                        program,
                        &local_arguments,
                        known_cwd(&self.state),
                        &self.home,
                        &self.critical_paths,
                        self.platform,
                    )
                })
        } else {
            None
        };
        let nah_inspection = if let ProgramDraft::Static(program) = &program {
            nah_inspection_operation(program, &local_arguments)
        } else {
            None
        };
        let network_shell_redirect = matches!(&program, ProgramDraft::Static(program)
            if shell_attached_to_dev_socket(program, &local_arguments, &network_endpoints));
        let CommandResources {
            filesystems: filesystem_drafts,
            network_endpoints,
            descriptor_flows,
            system_states,
            git_operations,
        } = self.lower_command_resources(
            &program,
            &local_arguments,
            tar_argument_variants.as_deref(),
            terminal_help,
            redirected_descriptors,
            stage,
            &classifications,
            filesystem_drafts,
            network_endpoints,
            descriptor_flows,
        );
        let CommandClassifications {
            local_utility,
            project,
            git,
            execution,
            direct_execution,
        } = classifications;
        let mut invocation = invocation(
            &program,
            lexical_program.as_deref(),
            &local_arguments,
            words,
            argv,
            local_utility
                .as_ref()
                .is_some_and(|lowering| lowering.complete),
            nah_mutation
                .or_else(|| {
                    project
                        .as_ref()
                        .filter(|lowering| lowering.complete)
                        .map(|lowering| lowering.operation)
                })
                .or_else(|| {
                    git.as_ref()
                        .filter(|lowering| lowering.complete)
                        .map(|lowering| lowering.operation)
                })
                .or_else(|| execution.as_ref().and_then(|lowering| lowering.operation))
                .or(network_shell_redirect.then_some("network-shell"))
                .or(nah_inspection),
            matches!(&program, ProgramDraft::Static(program) if program == "eval")
                && lowered_substitutions.iter().any(|(substitution, _)| {
                    matches!(
                        substitution,
                        Substitution::Command { .. } | Substitution::Backtick { .. }
                    )
                }),
            direct_execution,
            pattern_program,
        );
        if let Some(descriptor_code) = execution
            .as_ref()
            .and_then(|execution| execution.descriptor_code.clone())
            && let InvocationDraft::CodeExecution { source, code, .. } = &mut invocation
            && (*source == SemanticCode::DIRECT_FILE
                || *source == SemanticCode::SHELL_FILE
                || *source == SemanticCode::INTERPRETER_FILE
                || *source == SemanticCode::SHELL_STDIN
                || *source == SemanticCode::INTERPRETER_STDIN)
            && code.is_none()
        {
            *code = Some(descriptor_code);
        }
        if !redirects_stdin(&redirects)
            && let Some(visible) = self.visible_stdin.as_ref()
            && let InvocationDraft::CodeExecution { source, code, .. } = &mut invocation
            && (*source == SemanticCode::SHELL_STDIN || *source == SemanticCode::INTERPRETER_STDIN)
            && code.is_none()
        {
            *code = Some(visible.value.clone());
            invocation_origins.extend(visible.origins.iter().copied());
            invocation_origins = self.bounded_origins(invocation_origins);
        }
        crate::bash_self_protection::reclassify_inline(
            &mut invocation,
            &self.home,
            &self.critical_paths,
            self.platform,
            &self.runtime_variables,
        );
        let recognized_command = terminal_help
            || local_utility.is_some()
            || project.is_some()
            || git.is_some()
            || !git_operations.is_empty()
            || execution.is_some()
            || !matches!(&producer.stdout, StdoutDraft::Unknown)
            || !filesystem_drafts.is_empty()
            || !system_states.is_empty()
            || matches!(&program, ProgramDraft::Static(program)
                if models_logical_storage_command(program));
        if matches!(invocation, InvocationDraft::Opaque { .. })
            && lowered_payload.is_none()
            && lowered_executors.is_empty()
            && (!recognized_command && self.arguments_may_run_a_command(&local_arguments)
                || matches!(&program, ProgramDraft::Static(program)
                    if hides_deferred_code(program, &local_arguments)))
        {
            self.complete = false;
            self.analysis_refused = true;
        }
        let fifo_paths = match &program {
            ProgramDraft::Static(program) if program == "socat" => {
                crate::bash_socat::socat_fifo_creations(&local_arguments, &self.visible_variables())
            }
            _ => Vec::new(),
        };
        let fifo_creations = fifo_paths
            .into_iter()
            .filter_map(|path| self.resolve_requested(&path))
            .collect();
        let lastpipe_update = builtin_target
            .then(|| lastpipe_update(&program, &local_arguments))
            .flatten();
        let stage_draft = StageDraft {
            invocation,
            invocation_cwd,
            filesystems: filesystem_drafts,
            git_operations,
            git_project_scoped: git.as_ref().is_some_and(|git| git.project_scoped),
            network_outbound: git.as_ref().is_some_and(|git| git.network_outbound)
                || execution
                    .as_ref()
                    .is_some_and(|execution| execution.network_outbound),
            network_endpoints,
            system_states,
            fifo_creations,
            stdout: producer.stdout,
            content_writes,
            payload_depth: self.payload_depth,
            conditional_depth: self.conditional_depth,
            execution_dominators: Vec::new(),
        };
        AnalyzedCommand {
            assignments,
            arguments,
            redirects,
            builtin_target,
            program,
            local_arguments,
            lowered_substitutions,
            assignment_updates,
            invocation_origins,
            command_argument_origins,
            stage,
            stage_draft,
            descriptor_plan,
            descriptor_flows,
            lowered_startup,
            lowered_payload,
            lowered_executors,
            exact_variable_write,
            current_shell_eval,
            current_shell_source,
            execution,
            lastpipe_update,
        }
    }
}
