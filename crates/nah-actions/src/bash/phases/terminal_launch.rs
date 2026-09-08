//! Lowers static terminal launches without caller variables, paths, or receiver observations.

use nah_parse::Statement;
use nah_proto::action::SemanticCode;
use nah_proto::ctx::AbsolutePath;

use super::{Lowered, Lowerer};
use crate::bash_descriptor_state::DescriptorState;
use crate::bash_model::{ProgramDraft, StageDraft, StdoutDraft};
use crate::bash_wrappers::{shell_payload, wrapper_payload};
use crate::shell_word::{contains_unquoted_pattern, static_word};

impl Lowerer {
    pub(super) fn lower_terminal_launch(&mut self, source: &str) -> Lowered {
        if source.len() > 16_384 || self.payload_depth >= 8 || !self.enter_payload(source.len()) {
            return Lowered::default();
        }
        let mut lowered = Lowered::default();
        if let Ok(syntax) = nah_parse::normalize(source) {
            for statement in syntax.statements() {
                lowered.extend(self.lower_terminal_statement(statement));
            }
        }
        self.payload_depth -= 1;
        lowered
    }

    fn lower_terminal_statement(&mut self, statement: &Statement) -> Lowered {
        match statement {
            Statement::Chain { items, .. } => {
                let mut lowered = Lowered::default();
                for item in items {
                    lowered.extend(self.lower_terminal_statement(item));
                }
                lowered
            }
            Statement::Pipeline { stages, operators } => {
                let stages = stages
                    .iter()
                    .map(|stage| self.lower_terminal_statement(stage))
                    .collect::<Vec<_>>();
                for (pair, operator) in stages.windows(2).zip(operators) {
                    if matches!(operator.as_str(), "|" | "|&") {
                        for from in &pair[0].outputs {
                            for to in &pair[1].inputs {
                                self.flows.push((*from, *to));
                            }
                        }
                    }
                }
                Lowered {
                    inputs: stages
                        .first()
                        .map_or_else(Vec::new, |stage| stage.inputs.clone()),
                    outputs: stages
                        .last()
                        .map_or_else(Vec::new, |stage| stage.outputs.clone()),
                    stages: stages.into_iter().flat_map(|stage| stage.stages).collect(),
                }
            }
            Statement::Command {
                name,
                name_substitutions,
                arguments,
                assignments,
                unmodeled_assignments,
                redirects,
            } => {
                // Only shared static command positions are established for the unknown
                // server shell. Expansion, redirection and shell state remain incomplete.
                if !assignments.is_empty()
                    || !unmodeled_assignments.is_empty()
                    || !redirects.is_empty()
                {
                    return Lowered::default();
                }
                let Some(program) = static_word(name, name_substitutions.is_empty()) else {
                    return Lowered::default();
                };
                if program.contains(['/', '\\']) || contains_unquoted_pattern(name) {
                    return Lowered::default();
                }
                let Some(values) = arguments
                    .iter()
                    .map(|word| static_word(word.raw(), word.substitutions().is_empty()))
                    .collect::<Option<Vec<_>>>()
                else {
                    return Lowered::default();
                };
                if let Some(payload) = shell_payload(&program, arguments, &[])
                    .or_else(|| wrapper_payload(&program, arguments))
                {
                    return self.lower_terminal_launch(&payload);
                }
                if crate::bash_filesystem::terminal_program_help(&program, arguments, self.platform)
                {
                    return Lowered::default();
                }
                let local = crate::bash_local_utilities::lower(&program, arguments);
                let project = crate::bash_project::lower(&program, arguments);
                let execution = crate::bash_execution::lower(
                    &program,
                    arguments,
                    &DescriptorState::default(),
                    &[],
                    None,
                );
                let operation =
                    crate::bash_self_protection::operation_for_values(&program, &values)
                        .or_else(|| {
                            local
                                .as_ref()
                                .filter(|model| model.complete)
                                .and_then(|model| model.operation)
                        })
                        .or_else(|| {
                            project
                                .as_ref()
                                .filter(|model| model.complete)
                                .map(|model| model.operation)
                        })
                        .or_else(|| execution.as_ref().and_then(|model| model.operation))
                        .map(|operation| SemanticCode::new(operation).expect("modeled operation"));
                let mut argv = vec![program.clone()];
                argv.extend(values);
                let invocation = crate::bash_invocation::invocation(
                    &ProgramDraft::Static(program.clone()),
                    None,
                    arguments,
                    std::iter::once(name.clone())
                        .chain(arguments.iter().map(|word| word.raw().to_owned()))
                        .collect(),
                    Some(argv),
                    false,
                    operation,
                    false,
                    false,
                    false,
                );
                let specs = crate::bash_filesystem::command_filesystems(&program, arguments)
                    .unwrap_or_default()
                    .into_iter()
                    .chain(
                        local
                            .as_ref()
                            .into_iter()
                            .flat_map(|model| model.filesystems.clone()),
                    )
                    .chain(
                        project
                            .as_ref()
                            .into_iter()
                            .flat_map(|model| model.filesystems.clone()),
                    )
                    .chain(
                        execution
                            .as_ref()
                            .into_iter()
                            .flat_map(|model| model.filesystems.clone()),
                    );
                let mut filesystems = Vec::new();
                for (target, operation, recursive) in specs {
                    // Absolute lexical intent survives without asking the caller's
                    // filesystem to resolve receiver aliases, patterns, home or cwd.
                    if AbsolutePath::new(self.platform, &target).is_err()
                        || arguments
                            .iter()
                            .any(|word| contains_unquoted_pattern(word.raw()))
                    {
                        continue;
                    }
                    let mut filesystem = super::filesystem::unresolved_read(&target);
                    filesystem.operation = operation;
                    filesystem.recursive = recursive;
                    filesystem.unresolved_selection = false;
                    if !filesystems.contains(&filesystem) {
                        filesystems.push(filesystem);
                    }
                }
                let stage = self.stages.len();
                // Generic visible-source lowering has caller context; this stage must
                // remain in the isolated terminal analyzer even if an artifact matches.
                self.prelowered_visible_stages.insert(stage);
                self.stages.push(StageDraft {
                    language_safety_only: false,
                    invocation,
                    invocation_cwd: None,
                    child_cwd_keys: Vec::new(),
                    filesystems,
                    root_move_destination_key: None,
                    git_operations: crate::bash_git::git_command_operations(&program, arguments)
                        .into_iter()
                        .map(|operation| {
                            SemanticCode::new(operation).expect("modeled Git operation")
                        })
                        .collect(),
                    git_project_scoped: false,
                    network_outbound: execution
                        .as_ref()
                        .is_some_and(|model| model.network_outbound),
                    network_endpoints: execution
                        .as_ref()
                        .map_or_else(Vec::new, |model| model.network_endpoints.clone()),
                    system_states: local
                        .as_ref()
                        .map_or_else(Vec::new, |model| model.system_states.clone()),
                    fifo_creations: Vec::new(),
                    stdout: StdoutDraft::Unknown,
                    content_writes: Vec::new(),
                    payload_depth: self.payload_depth,
                    conditional_depth: self.conditional_depth,
                    execution_dominators: Vec::new(),
                });
                Lowered {
                    stages: vec![stage],
                    inputs: if execution.as_ref().is_none_or(|model| model.stdin_flows) {
                        vec![stage]
                    } else {
                        Vec::new()
                    },
                    outputs: if execution.as_ref().is_none_or(|model| model.stdout_flows) {
                        vec![stage]
                    } else {
                        Vec::new()
                    },
                }
            }
            _ => Lowered::default(),
        }
    }
}
