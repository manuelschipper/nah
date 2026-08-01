//! Selects feature-specific command analyzers and direct executable fallback.

use nah_parse::Word;
use nah_proto::action::FilesystemOperation;

use super::Lowerer;
use crate::bash_descriptor_state::DescriptorState;
use crate::bash_execution::{self, lower as lower_execution};
use crate::bash_filesystem::command_filesystems;
use crate::bash_git_operations::{self, lower as lower_git};
use crate::bash_local_utilities::{self, lower as lower_local_utility};
use crate::bash_model::ProgramDraft;
use crate::bash_project::{self, lower as lower_project};
use crate::bash_state::{Cwd, known_cwd};

pub(super) struct CommandClassifications {
    pub(super) local_utility: Option<bash_local_utilities::Lowering>,
    pub(super) project: Option<bash_project::Lowering>,
    pub(super) git: Option<bash_git_operations::Lowering>,
    pub(super) execution: Option<bash_execution::Lowering>,
    pub(super) direct_execution: bool,
}

impl Lowerer {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn classify_command(
        &self,
        program: &ProgramDraft,
        arguments: &[Word],
        descriptors: &DescriptorState,
        builtin_target: bool,
        terminal_help: bool,
        direct_program: Option<&String>,
        tar_argument_variants: Option<&[Vec<Word>]>,
        lowered_payload_present: bool,
    ) -> CommandClassifications {
        let local_utility = if let ProgramDraft::Static(program) = program {
            lower_local_utility(program, arguments)
        } else {
            None
        };
        let project = if terminal_help {
            None
        } else if let ProgramDraft::Static(program) = program {
            lower_project(program, arguments)
        } else {
            None
        };
        let git = if matches!(&self.state.cwd, Cwd::Known(cwd) if cwd == &self.initial_cwd) {
            if let ProgramDraft::Static(program) = program {
                lower_git(program, arguments)
            } else {
                None
            }
        } else {
            None
        };
        let mut execution = if let ProgramDraft::Static(program) = program
            && (builtin_target || !matches!(program.as_str(), "." | "source"))
        {
            lower_execution(
                program,
                arguments,
                descriptors,
                &self.visible_variables(),
                known_cwd(&self.state),
            )
        } else {
            None
        };
        if let ProgramDraft::Static(program) = program
            && let Some(variants) = tar_argument_variants
        {
            for arguments in variants.iter().skip(1) {
                let Some(other) = lower_execution(
                    program,
                    arguments,
                    descriptors,
                    &self.visible_variables(),
                    known_cwd(&self.state),
                ) else {
                    continue;
                };
                if let Some(execution) = &mut execution {
                    execution.complete &= other.complete;
                    if other.operation == Some("network-transfer") {
                        execution.operation = other.operation;
                    }
                    for filesystem in other.filesystems {
                        if !execution.filesystems.contains(&filesystem) {
                            execution.filesystems.push(filesystem);
                        }
                    }
                    execution.network_outbound |= other.network_outbound;
                    execution.stdin_flows |= other.stdin_flows;
                    execution.stdout_flows |= other.stdout_flows;
                    for endpoint in other.network_endpoints {
                        if !execution.network_endpoints.contains(&endpoint) {
                            execution.network_endpoints.push(endpoint);
                        }
                    }
                    for source in other.descriptor_sources {
                        if !execution.descriptor_sources.contains(&source) {
                            execution.descriptor_sources.push(source);
                        }
                    }
                    for sink in other.descriptor_sinks {
                        if !execution.descriptor_sinks.contains(&sink) {
                            execution.descriptor_sinks.push(sink);
                        }
                    }
                } else {
                    execution = Some(other);
                }
            }
        }
        let explicit_direct = direct_program.is_some_and(|program| {
            ["./", "../", r".\", r"..\"]
                .iter()
                .any(|prefix| program.starts_with(prefix))
        });
        let modeled_filesystem_program = direct_program.is_some()
            && matches!(program, ProgramDraft::Static(program)
                if command_filesystems(program, arguments).is_some());
        let direct_execution = explicit_direct
            || execution.is_none()
                && local_utility.is_none()
                && project.is_none()
                && git.is_none()
                && !lowered_payload_present
                && !modeled_filesystem_program
                && !matches!(program, ProgramDraft::Static(program) if matches!(program.as_str(), "git" | "nah"))
                && direct_program.is_some();
        if explicit_direct && let Some(execution) = &mut execution {
            execution.filesystems.push((
                direct_program.cloned().expect("explicit direct path"),
                FilesystemOperation::Read,
                false,
            ));
        }
        if direct_execution && execution.is_none() {
            execution = direct_program.map(|target| bash_execution::Lowering {
                complete: true,
                operation: None,
                filesystems: vec![(target.clone(), FilesystemOperation::Read, false)],
                network_outbound: false,
                stdin_flows: false,
                stdout_flows: true,
                network_endpoints: Vec::new(),
                descriptor_sources: Vec::new(),
                descriptor_sinks: Vec::new(),
                descriptor_code: None,
            });
        }
        CommandClassifications {
            local_utility,
            project,
            git,
            execution,
            direct_execution,
        }
    }
}
