//! Commits an analyzed command to shell state, flows, and stream boundaries.

use nah_parse::{Redirect, Substitution};

use super::command_effects::AnalyzedCommand;
use super::filesystem::allocated_descriptor_variable;
use super::{Lowered, Lowerer};
use crate::bash_flow::{redirects_stdin, redirects_stdout};
use crate::bash_lookup::LookupState;
use crate::bash_model::{InvocationDraft, ProgramDraft, VariableValue};
use crate::bash_wrappers::{command_exec_has_no_command, exec_has_no_command};

impl Lowerer {
    pub(super) fn commit_command(&mut self, command: AnalyzedCommand<'_>) -> Lowered {
        let AnalyzedCommand {
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
        } = command;
        let inline_state = matches!(
            &stage_draft.invocation,
            InvocationDraft::CodeExecution { program, .. } if nah_inline::supports(program)
        )
        .then(|| {
            let parent_state = self.state.clone();
            let parent_ambient_variables = self.ambient_variables.clone();
            let parent_complete = self.complete;
            let parent_lookup_mode = self.next_lookup_mode;
            let parent_aliases = self.active_aliases.clone();
            self.prepare_isolated_environment(
                &program,
                &local_arguments,
                assignments,
                &assignment_updates,
            );
            self.state.functions.clear();
            self.state.lookup = LookupState::default();
            self.active_aliases = None;
            let visible = super::VisibleExecutionState {
                stage,
                state: self.state.clone(),
                ambient_variables: self.ambient_variables.clone(),
            };
            self.state = parent_state;
            self.ambient_variables = parent_ambient_variables;
            self.complete = parent_complete;
            self.next_lookup_mode = parent_lookup_mode;
            self.active_aliases = parent_aliases;
            visible
        });
        let mut lowered_source = Lowered::default();
        self.stages.push(stage_draft);
        if let Some(mut visible) = self.pending_visible_child_state.take() {
            visible.stage = stage;
            self.visible_execution_states.push(visible);
        }
        for origin in invocation_origins
            .into_iter()
            .filter(|origin| *origin != stage)
        {
            self.flows.push((origin, stage));
        }
        self.flows.extend(descriptor_flows);
        if !current_shell_source
            && !current_shell_eval
            && (matches!(
                self.stages[stage].invocation,
                InvocationDraft::CodeExecution { code: None, .. }
            ) || matches!(
                &self.stages[stage].invocation,
                InvocationDraft::CodeExecution { source, .. }
                    if source == &nah_proto::action::SemanticCode::SHELL_STDIN
            ))
        {
            self.resolve_visible_execution_at_boundary(stage);
        }
        if let Some(inline_state) = inline_state {
            self.analyze_inline_stage(inline_state);
        }
        if current_shell_source {
            if let Some(payload) = self.visible_execution_payload(stage) {
                lowered_source = self.lower_source_payload(
                    stage,
                    &payload,
                    assignments,
                    &assignment_updates,
                    arguments,
                    &command_argument_origins,
                );
            } else {
                self.invalidate_unknown_current_shell_code(stage);
            }
        } else if current_shell_eval && lowered_payload.is_none() {
            self.invalidate_unknown_current_shell_code(stage);
        }
        if let Some((name, value, _)) = exact_variable_write {
            self.set_local_variable_with_origins(&name, VariableValue::Static(value), vec![stage]);
        }
        if let Some(lastpipe) = lastpipe_update {
            self.state.lastpipe = lastpipe;
        }
        if builtin_target && let ProgramDraft::Static(program) = &program {
            self.update_positional_state(program, arguments, &command_argument_origins);
        }
        if builtin_target && let ProgramDraft::Static(program) = &program {
            self.update_lookup_builtin(program, &local_arguments);
        }
        if matches!(&program, ProgramDraft::Static(program) if program == "socat") {
            let executor_flows = crate::bash_socat::socat_executor_flows(
                &local_arguments,
                &self.visible_variables(),
            );
            for (executor, _) in &lowered_executors {
                if executor_flows.all_stages_to_parent {
                    for source in &executor.stages {
                        self.flows.push((*source, stage));
                    }
                } else if executor_flows.outputs_to_parent {
                    for output in &executor.outputs {
                        self.flows.push((*output, stage));
                    }
                }
                if executor_flows.parent_to_inputs {
                    for input in &executor.inputs {
                        self.flows.push((stage, *input));
                    }
                }
            }
        }
        let persistent_exec_redirects = builtin_target
            && matches!(&program,
                ProgramDraft::Static(program) if
                    (program == "exec" && exec_has_no_command(&local_arguments))
                    || (program == "command"
                        && command_exec_has_no_command(&local_arguments))
            );
        if persistent_exec_redirects {
            self.state.descriptors = descriptor_plan.command;
        } else if descriptor_plan.persists {
            self.state.descriptors = descriptor_plan.persistent;
        }
        for name in redirects
            .iter()
            .filter_map(|redirect| allocated_descriptor_variable(redirect.fd()))
        {
            self.set_local_variable_preserving_descriptor_alias(
                name,
                VariableValue::Unknown,
                Vec::new(),
            );
        }
        if let Some((payload, true)) = &lowered_payload {
            if redirects_stdout(&redirects) {
                for output in &payload.outputs {
                    self.flows.push((*output, stage));
                }
            }
            if redirects_stdin(&redirects) {
                for input in &payload.inputs {
                    self.flows.push((stage, *input));
                }
            }
        }

        self.connect_command_substitution_flows(stage, &lowered_substitutions);
        if builtin_target {
            self.update_cd_state(&program, arguments, &local_arguments);
        }

        Self::finish_command_lowering(
            stage,
            &redirects,
            lowered_startup,
            lowered_substitutions,
            lowered_payload,
            lowered_source,
            lowered_executors,
            execution.as_ref(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn finish_command_lowering(
        stage: usize,
        redirects: &[Redirect],
        lowered_startup: Lowered,
        lowered_substitutions: Vec<(&Substitution, Lowered)>,
        lowered_payload: Option<(Lowered, bool)>,
        lowered_source: Lowered,
        lowered_executors: Vec<(Lowered, bool)>,
        execution: Option<&crate::bash_execution::Lowering>,
    ) -> Lowered {
        let mut stages = lowered_startup.stages;
        stages.extend(
            lowered_substitutions
                .into_iter()
                .flat_map(|(_, nested)| nested.stages),
        );
        if let Some((payload, _)) = &lowered_payload {
            stages.extend(payload.stages.iter().copied());
        }
        stages.extend(lowered_source.stages);
        let executor_inputs = lowered_executors
            .iter()
            .filter(|(_, substitutes_command)| *substitutes_command)
            .flat_map(|(executor, _)| executor.stages.iter().copied())
            .collect::<Vec<_>>();
        for (executor, _) in lowered_executors {
            stages.extend(executor.stages);
        }
        stages.push(stage);
        let transparent_payload = lowered_payload
            .as_ref()
            .filter(|(_, transparent)| *transparent)
            .map(|(payload, _)| payload);
        Lowered {
            stages,
            inputs: transparent_payload
                .map(|payload| {
                    if redirects_stdin(redirects) {
                        Vec::new()
                    } else {
                        payload.inputs.clone()
                    }
                })
                .unwrap_or_else(|| {
                    if redirects_stdin(redirects) {
                        Vec::new()
                    } else if !executor_inputs.is_empty() {
                        executor_inputs
                    } else {
                        execution
                            .is_none_or(|execution| execution.stdin_flows)
                            .then_some(stage)
                            .into_iter()
                            .collect()
                    }
                }),
            outputs: transparent_payload
                .map(|payload| {
                    if redirects_stdout(redirects) {
                        Vec::new()
                    } else {
                        payload.outputs.clone()
                    }
                })
                .unwrap_or_else(|| {
                    (!redirects_stdout(redirects)
                        && execution.is_none_or(|execution| execution.stdout_flows))
                    .then_some(stage)
                    .into_iter()
                    .collect()
                }),
        }
    }
}
