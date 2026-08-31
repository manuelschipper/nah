//! Projects one classified command into filesystem, network, and system resources.

use nah_parse::Word;
use nah_proto::action::{FilesystemOperation, NetworkDirection, SemanticCode};
use nah_proto::observation::SymlinkTraversal;

use super::Lowerer;
use super::command_classification::CommandClassifications;
use super::filesystem::unresolved_read;
use crate::bash_descriptor_paths::descriptor_reference_path_from_cwd;
use crate::bash_descriptor_state::{DescriptorFlow, DescriptorState, NetworkEndpoint};
use crate::bash_descriptors::descriptor_reference_binding_from_cwd;
use crate::bash_git::{command_operation as git_command_operation, metadata_mutation};
use crate::bash_infrastructure::Classification as InfrastructureClassification;
use crate::bash_logical_storage::logical_storage_destroy;
use crate::bash_model::{FilesystemDraft, ProgramDraft};
use crate::bash_registry::Classification as RegistryClassification;
use crate::bash_startup_persistence::operation as startup_management_operation;
use crate::bash_state::known_cwd;
use crate::bash_symlinks::{
    has_dynamic_content_selection, has_unresolved_selection, pattern_symlink_traversal,
    pattern_targets, recursive_symlink_traversal,
};
use crate::paths::cwd_relative;
use crate::shell_word::static_word;

pub(super) struct CommandResources {
    pub(super) filesystems: Vec<FilesystemDraft>,
    pub(super) root_move_destination_key: Option<String>,
    pub(super) network_endpoints: Vec<NetworkEndpoint>,
    pub(super) descriptor_flows: Vec<DescriptorFlow>,
    pub(super) system_states: Vec<SemanticCode>,
    pub(super) git_operations: Vec<SemanticCode>,
}

impl Lowerer {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn lower_command_resources(
        &mut self,
        program: &ProgramDraft,
        arguments: &[Word],
        tar_argument_variants: Option<&[Vec<Word>]>,
        terminal_help: bool,
        redirected_descriptors: &DescriptorState,
        stage: usize,
        classifications: &CommandClassifications,
        infrastructure: Option<&InfrastructureClassification>,
        registry: Option<&RegistryClassification>,
        git_environment_override: bool,
        remote_repository_delete: bool,
        mut filesystem_drafts: Vec<FilesystemDraft>,
        mut network_endpoints: Vec<NetworkEndpoint>,
        mut descriptor_flows: Vec<DescriptorFlow>,
    ) -> CommandResources {
        let mut system_states = Vec::new();
        let mut root_move_destination_key = None;
        let git_command_guard = match program {
            _ if git_environment_override => None,
            ProgramDraft::Static(program) => git_command_operation(program, arguments),
            ProgramDraft::Env { .. } | ProgramDraft::Unresolved => None,
        };
        // The shell expands these targets before the command runs, so their
        // effects stay bounded by the literal prefix instead of naming a path.
        let mut patterns = pattern_targets(arguments);
        if let Some(variants) = tar_argument_variants {
            for arguments in variants.iter().skip(1) {
                for pattern in pattern_targets(arguments) {
                    if !patterns.contains(&pattern) {
                        patterns.push(pattern);
                    }
                }
            }
        }
        if let Some(local_utility) = &classifications.local_utility {
            if !local_utility.complete {
                self.complete = false;
            }
            let first = filesystem_drafts.len();
            self.lower_filesystem_specs(
                &local_utility.filesystems,
                &patterns,
                &mut filesystem_drafts,
            );
            if matches!(program, ProgramDraft::Static(program) if program == "stat") {
                for filesystem in &mut filesystem_drafts[first..] {
                    filesystem.content_access = false;
                }
            }
            system_states.extend(local_utility.system_states.iter().cloned());
        } else if let Some(project) = &classifications.project {
            if !project.complete {
                self.complete = false;
            }
            let first = filesystem_drafts.len();
            self.lower_filesystem_specs(&project.filesystems, &patterns, &mut filesystem_drafts);
            root_move_destination_key = project
                .root_move_destination
                .and_then(|index| filesystem_drafts.get(first + index))
                .and_then(|filesystem| filesystem.key.clone());
            if matches!(program, ProgramDraft::Static(program) if program == "touch") {
                for filesystem in &mut filesystem_drafts[first..] {
                    filesystem.content_access = false;
                }
            } else if matches!(program, ProgramDraft::Static(program) if program == "cp")
                && arguments.iter().any(|argument| {
                    static_word(argument.raw(), argument.substitutions().is_empty()).as_deref()
                        == Some("--attributes-only")
                })
            {
                for filesystem in &mut filesystem_drafts[first..] {
                    if filesystem.operation == FilesystemOperation::Read {
                        filesystem.content_access = false;
                    }
                }
            }
        } else if !terminal_help
            && classifications.git.is_none()
            && !git_environment_override
            && let ProgramDraft::Static(program) = program
        {
            self.lower_command_filesystems(program, arguments, &patterns, &mut filesystem_drafts);
            if let Some(variants) = tar_argument_variants {
                for arguments in variants.iter().skip(1) {
                    self.lower_command_filesystems(
                        program,
                        arguments,
                        &patterns,
                        &mut filesystem_drafts,
                    );
                }
            }
        }
        if let Some(git) = &classifications.git {
            for target in &git.filesystems {
                let Some(requested) = self.resolve_requested(target) else {
                    continue;
                };
                self.add_filesystem(
                    &requested,
                    FilesystemOperation::Read,
                    false,
                    cwd_relative(target, self.platform),
                    &mut filesystem_drafts,
                );
            }
            for target in &git.written_filesystems {
                let Some(requested) = self.resolve_requested(target) else {
                    continue;
                };
                self.add_filesystem(
                    &requested,
                    FilesystemOperation::Write,
                    false,
                    cwd_relative(target, self.platform),
                    &mut filesystem_drafts,
                );
                if let Some(filesystem) = filesystem_drafts.last_mut() {
                    filesystem.git_guard = Some(SemanticCode::WORKTREE_DISCARD);
                }
            }
            for target in &git.deleted_filesystems {
                let Some(requested) = self.resolve_requested(target) else {
                    continue;
                };
                self.add_filesystem(
                    &requested,
                    FilesystemOperation::Delete,
                    false,
                    cwd_relative(target, self.platform),
                    &mut filesystem_drafts,
                );
                if git_command_guard == Some(SemanticCode::CLEAN_FORCE.as_str())
                    && let Some(filesystem) = filesystem_drafts.last_mut()
                {
                    filesystem.git_guard = Some(SemanticCode::CLEAN_FORCE);
                }
            }
            for target in &git.existing_filesystems {
                let Some(requested) = self.resolve_requested(target) else {
                    continue;
                };
                self.add_existing_file(
                    &requested,
                    cwd_relative(target, self.platform),
                    &mut filesystem_drafts,
                );
            }
        }
        if git_environment_override {
            self.complete = false;
        }
        if let Some(execution) = &classifications.execution {
            if !execution.complete {
                self.complete = false;
            }
            self.lower_filesystem_specs(&execution.filesystems, &patterns, &mut filesystem_drafts);
        }
        if let ProgramDraft::Static(program) = program
            && (has_dynamic_content_selection(program, arguments)
                || tar_argument_variants.is_some_and(|variants| {
                    variants
                        .iter()
                        .skip(1)
                        .any(|arguments| has_dynamic_content_selection(program, arguments))
                }))
        {
            self.complete = false;
            let (endpoints, flows) =
                self.conservative_descriptor_effects(redirected_descriptors, stage);
            network_endpoints.extend(endpoints);
            descriptor_flows.extend(flows);
            filesystem_drafts.push(unresolved_read(
                known_cwd(&self.state).unwrap_or(&self.initial_cwd),
            ));
        }
        if let ProgramDraft::Static(program) = program
            && crate::bash_network::has_dynamic_file_source(
                program,
                arguments,
                &self.visible_variables(),
            )
        {
            self.complete = false;
            if matches!(program.as_str(), "scp" | "rsync") {
                let (endpoints, flows) =
                    self.conservative_descriptor_effects(redirected_descriptors, stage);
                network_endpoints.extend(endpoints);
                descriptor_flows.extend(flows);
            }
            filesystem_drafts.push(unresolved_read(
                known_cwd(&self.state).unwrap_or(&self.initial_cwd),
            ));
        }
        if let ProgramDraft::Static(program) = program
            && (has_unresolved_selection(program, arguments)
                || tar_argument_variants.is_some_and(|variants| {
                    variants
                        .iter()
                        .skip(1)
                        .any(|arguments| has_unresolved_selection(program, arguments))
                }))
        {
            self.complete = false;
            let mut unresolved =
                unresolved_read(known_cwd(&self.state).unwrap_or(&self.initial_cwd));
            unresolved.recursive = true;
            unresolved.symlink_traversal = SymlinkTraversal::All;
            filesystem_drafts.push(unresolved);
        }
        if let ProgramDraft::Static(program) = program {
            let traversal = tar_argument_variants.map_or_else(
                || recursive_symlink_traversal(program, arguments),
                |variants| {
                    variants
                        .iter()
                        .fold(SymlinkTraversal::None, |current, arguments| {
                            current.max(recursive_symlink_traversal(program, arguments))
                        })
                },
            );
            for filesystem in &mut filesystem_drafts {
                if traversal != SymlinkTraversal::None
                    && filesystem.operation == FilesystemOperation::Read
                    && filesystem.recursive
                {
                    filesystem.symlink_traversal = traversal;
                }
            }
        }
        if let ProgramDraft::Static(program) = program {
            let traversal = tar_argument_variants.map_or_else(
                || pattern_symlink_traversal(program, arguments),
                |variants| {
                    variants
                        .iter()
                        .fold(SymlinkTraversal::None, |current, arguments| {
                            current.max(pattern_symlink_traversal(program, arguments))
                        })
                },
            );
            for filesystem in &mut filesystem_drafts {
                if filesystem.operation == FilesystemOperation::Read && filesystem.pattern {
                    filesystem.symlink_traversal = filesystem.symlink_traversal.max(traversal);
                }
            }
        }
        if let ProgramDraft::Static(program) = program
            && logical_storage_destroy(program, arguments)
        {
            self.complete = false;
            system_states.push(SemanticCode::LOGICAL_STORAGE_DESTROY);
        }
        if let ProgramDraft::Static(program) = program
            && let Some(operation) = startup_management_operation(program, arguments, self.platform)
        {
            system_states.push(operation);
        }
        if let Some(infrastructure) = infrastructure {
            self.complete &= infrastructure.complete;
            if let Some(operation) = &infrastructure.system_state {
                system_states.push(operation.clone());
            }
        }
        if let Some(registry) = registry {
            self.complete &= registry.complete;
            if let Some(operation) = &registry.system_state {
                system_states.push(operation.clone());
            }
        }
        let (filesystem_endpoints, filesystem_flows) =
            self.descriptor_filesystem_effects(&filesystem_drafts, redirected_descriptors, stage);
        network_endpoints.extend(filesystem_endpoints);
        descriptor_flows.extend(filesystem_flows);
        if let ProgramDraft::Static(program) = program
            && matches!(program.as_str(), "tar" | "bsdtar")
            && (crate::bash_tar::analyze(program, arguments)
                .is_some_and(|analysis| analysis.remote_archive_inbound)
                || tar_argument_variants.is_some_and(|variants| {
                    variants.iter().skip(1).any(|arguments| {
                        crate::bash_tar::analyze(program, arguments)
                            .is_some_and(|analysis| analysis.remote_archive_inbound)
                    })
                }))
        {
            network_endpoints.push((NetworkDirection::Inbound, String::new()));
        }
        if let ProgramDraft::Static(program) = program
            && matches!(program.as_str(), "tar" | "bsdtar")
        {
            let mut argument_sets = vec![arguments];
            if let Some(variants) = tar_argument_variants {
                argument_sets.extend(variants.iter().skip(1).map(Vec::as_slice));
            }
            for arguments in argument_sets {
                let Some(analysis) = crate::bash_tar::analyze(program, arguments) else {
                    continue;
                };
                let Some(archive) = analysis.archive_target else {
                    continue;
                };
                if archive.static_path.is_some() {
                    continue;
                }
                let facts = match descriptor_reference_binding_from_cwd(
                    redirected_descriptors,
                    &archive.raw,
                    &self.visible_variables(),
                    known_cwd(&self.state),
                ) {
                    Ok(Some((_, facts))) => facts,
                    Ok(None) => continue,
                    Err(_) => {
                        self.complete = false;
                        self.analysis_refused = true;
                        continue;
                    }
                };
                network_endpoints.extend(
                    facts
                        .hosts()
                        .iter()
                        .cloned()
                        .map(|host| (NetworkDirection::Outbound, host)),
                );
                descriptor_flows.extend(
                    facts
                        .consumer_sinks()
                        .iter()
                        .copied()
                        .map(|sink| (stage, sink)),
                );
            }
        }
        filesystem_drafts.retain(|filesystem| {
            descriptor_reference_path_from_cwd(&filesystem.requested, known_cwd(&self.state))
                .is_none()
        });
        network_endpoints.sort();
        network_endpoints.dedup();
        let mut git_operations = filesystem_drafts
            .iter()
            .filter(|filesystem| filesystem.git_guard.is_none())
            .filter(|filesystem| {
                metadata_mutation(
                    &filesystem.requested,
                    filesystem.operation,
                    filesystem.recursive,
                    self.platform,
                )
            })
            .map(|_| SemanticCode::METADATA_MUTATION)
            .collect::<Vec<_>>();
        if let Some(operation) = git_command_guard
            && operation != SemanticCode::CLEAN_FORCE.as_str()
        {
            git_operations.push(
                SemanticCode::new(operation).expect("Git operations are validated constants"),
            );
        }
        if remote_repository_delete {
            git_operations.push(SemanticCode::GIT_REMOTE_DELETE);
        }
        if !git_operations.is_empty() {
            self.complete = false;
        }
        if let Some(git) = &classifications.git {
            if !git.complete {
                self.complete = false;
            }
            git_operations.push(
                SemanticCode::new(git.operation).expect("Git operations are validated constants"),
            );
        }
        git_operations.sort_unstable();
        git_operations.dedup();
        CommandResources {
            filesystems: filesystem_drafts,
            root_move_destination_key,
            network_endpoints,
            descriptor_flows,
            system_states,
            git_operations,
        }
    }
}
