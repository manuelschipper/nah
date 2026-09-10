//! Lowers static terminal launches without caller variables, paths, or receiver observations.

use nah_parse::{Redirect, Statement};
use nah_proto::action::SemanticCode;
use nah_proto::ctx::AbsolutePath;

use super::{Lowered, Lowerer};
use crate::bash_descriptor_state::DescriptorState;
use crate::bash_model::{FilesystemDraft, ProgramDraft, StageDraft, StdoutDraft};
use crate::bash_wrappers::{
    executor_payloads, shell_payload, shell_string_wrapper_payload, wrapper_payload,
};
use crate::shell_word::{contains_unquoted_pattern, static_word};

impl Lowerer {
    pub(super) fn lower_terminal_launch(&mut self, source: &str) -> Lowered {
        if source.len() > 16_384 || self.payload_depth >= 8 || !self.enter_payload(source.len()) {
            return Lowered::default();
        }
        let mut lowered = Lowered::default();
        if let Ok(syntax) = nah_parse::normalize(source) {
            self.detected_fork_bomb |= syntax.fork_bomb();
            for statement in syntax.statements() {
                lowered.extend(self.lower_terminal_statement(statement));
            }
        }
        self.payload_depth -= 1;
        lowered
    }

    fn lower_terminal_statement(&mut self, statement: &Statement) -> Lowered {
        match statement {
            Statement::Chain { items, .. }
            | Statement::Subshell { statements: items }
            | Statement::Group { statements: items } => {
                let mut lowered = Lowered::default();
                for item in items {
                    lowered.extend(self.lower_terminal_statement(item));
                }
                lowered
            }
            Statement::Coprocess { body, .. } => self.lower_terminal_statement(body),
            Statement::Redirected { body, redirects } => {
                let mut lowered = self.lower_terminal_statement(body);
                lowered.extend(self.lower_terminal_redirects(redirects));
                lowered.inputs.clear();
                lowered.outputs.clear();
                lowered
            }
            Statement::RedirectOnly { redirects, .. } => self.lower_terminal_redirects(redirects),
            Statement::If {
                branches,
                else_body,
            } => {
                let mut lowered = Lowered::default();
                for statement in branches
                    .iter()
                    .flat_map(|branch| branch.condition().iter().chain(branch.body()))
                    .chain(else_body)
                {
                    lowered.extend(self.lower_terminal_statement(statement));
                }
                lowered
            }
            Statement::Loop {
                condition, body, ..
            } => {
                let mut lowered = Lowered::default();
                for statement in condition.iter().chain(body) {
                    lowered.extend(self.lower_terminal_statement(statement));
                }
                lowered
            }
            Statement::For { body, .. } => {
                let mut lowered = Lowered::default();
                for statement in body {
                    lowered.extend(self.lower_terminal_statement(statement));
                }
                lowered
            }
            Statement::Case { arms, .. } => {
                let mut lowered = Lowered::default();
                for statement in arms.iter().flat_map(|arm| arm.body()) {
                    lowered.extend(self.lower_terminal_statement(statement));
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
                redirects,
                assignments,
                ..
            } => {
                // Assignments and descriptor state remain unmodeled, but do not erase
                // independently visible argv intent. Never expand receiver variables.
                let Some(lexical_program) = static_word(name, name_substitutions.is_empty()) else {
                    return self.lower_terminal_redirects(redirects);
                };
                if contains_unquoted_pattern(name) {
                    return self.lower_terminal_redirects(redirects);
                }
                let program = self.normalized_program(&lexical_program);
                let Some(values) = arguments
                    .iter()
                    .map(|word| static_word(word.raw(), word.substitutions().is_empty()))
                    .collect::<Option<Vec<_>>>()
                else {
                    return self.lower_terminal_redirects(redirects);
                };
                let source_arguments = arguments;
                let normalized_arguments =
                    crate::bash_semantics::normalize_arguments(&program, arguments, self.platform);
                let arguments = normalized_arguments.as_slice();
                if let Some(payload) = shell_payload(&program, arguments, &[])
                    .or_else(|| wrapper_payload(&program, arguments))
                    .or_else(|| {
                        (program == "tmux")
                            .then(|| crate::bash_terminal_control::tmux_launch(arguments))
                            .flatten()
                    })
                    .or_else(|| {
                        (program == "watch")
                            .then(|| {
                                shell_string_wrapper_payload(&program, arguments)
                                    .ok()
                                    .flatten()
                            })
                            .flatten()
                            .map(|(payload, _)| payload)
                    })
                {
                    let mut lowered = self.lower_terminal_launch(&payload);
                    if !redirects.is_empty() {
                        lowered.inputs.clear();
                        lowered.outputs.clear();
                    }
                    lowered.extend(self.lower_terminal_redirects(redirects));
                    return lowered;
                }
                if crate::bash_filesystem::terminal_program_help(&program, arguments, self.platform)
                {
                    return self.lower_terminal_redirects(redirects);
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
                let qualified = lexical_program != program;
                let secret_store = crate::bash_secret_store::classify(
                    &program,
                    arguments,
                    assignments,
                    false,
                    qualified,
                );
                let host_power = crate::bash_host_power::operation(
                    &program,
                    arguments,
                    assignments.iter().any(|(name, _)| name == "PATH"),
                    qualified,
                    arguments
                        .iter()
                        .any(|word| contains_unquoted_pattern(word.raw())),
                );
                let mut system_states = local
                    .as_ref()
                    .map_or_else(Vec::new, |model| model.system_states.clone());
                system_states.extend(
                    secret_store
                        .as_ref()
                        .and_then(|model| model.system_state.clone()),
                );
                system_states.extend(
                    crate::bash_registry::classify(
                        &program,
                        arguments,
                        assignments,
                        false,
                        qualified,
                    )
                    .and_then(|model| model.system_state),
                );
                system_states.extend(
                    crate::bash_storage::classify(
                        &program,
                        arguments,
                        assignments,
                        false,
                        qualified,
                    )
                    .and_then(|model| model.system_state),
                );
                system_states.extend(
                    crate::bash_infrastructure::classify(
                        &program,
                        arguments,
                        assignments,
                        &[],
                        false,
                        qualified,
                    )
                    .and_then(|model| model.system_state),
                );
                if let Some(model) = crate::bash_kubernetes::classify(
                    &program,
                    arguments,
                    assignments,
                    false,
                    qualified,
                ) {
                    system_states.extend(model.system_states);
                }
                if crate::bash_logical_storage::logical_storage_destroy(&program, arguments) {
                    system_states.push(SemanticCode::LOGICAL_STORAGE_DESTROY);
                }
                system_states.extend(crate::bash_startup_persistence::operation(
                    &program,
                    arguments,
                    self.platform,
                ));
                let environment_disclosure = crate::bash_environment_disclosure::operation(
                    &program,
                    arguments,
                    source_arguments,
                    !assignments.is_empty(),
                    &[],
                    &[],
                );
                let operation =
                    crate::bash_self_protection::operation_for_values(&program, &values)
                        .or(environment_disclosure)
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
                let mut argv = vec![lexical_program.clone()];
                argv.extend(values);
                let invocation = crate::bash_invocation::invocation(
                    &ProgramDraft::Static(program.clone()),
                    Some(&lexical_program),
                    arguments,
                    std::iter::once(name.clone())
                        .chain(source_arguments.iter().map(|word| word.raw().to_owned()))
                        .collect(),
                    (!arguments
                        .iter()
                        .any(|word| contains_unquoted_pattern(word.raw())))
                    .then_some(argv),
                    false,
                    host_power
                        .or_else(|| {
                            secret_store
                                .as_ref()
                                .and_then(|model| model.known_invocation.clone())
                        })
                        .or(operation),
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
                let mut filesystems = self.terminal_redirect_filesystems(redirects);
                let patterns = crate::bash_symlinks::pattern_targets(arguments);
                for (target, operation, recursive) in specs {
                    // Absolute lexical intent survives without asking the caller's
                    // filesystem to resolve receiver aliases, patterns, home or cwd.
                    if AbsolutePath::new(self.platform, &target).is_err() {
                        continue;
                    }
                    let mut filesystem = super::filesystem::unresolved_read(&target);
                    filesystem.command_operand = true;
                    filesystem.operation = operation;
                    filesystem.recursive = recursive;
                    filesystem.unresolved_selection = false;
                    filesystem.pattern = patterns.contains(&target);
                    if !filesystems.contains(&filesystem) {
                        filesystems.push(filesystem);
                    }
                }
                let mut git_operations =
                    crate::bash_git::git_command_operations(&program, arguments)
                        .into_iter()
                        // Clean requires observed project-root selection, unavailable in the receiver.
                        .filter(|operation| *operation != SemanticCode::CLEAN_FORCE.as_str())
                        .map(|operation| {
                            SemanticCode::new(operation).expect("modeled Git operation")
                        })
                        .collect::<Vec<_>>();
                if let Some(deletion) =
                    crate::bash_remote_source_control::classify_remote_deletion(&program, arguments)
                {
                    git_operations.push(match deletion {
                        crate::bash_remote_source_control::RemoteDeletion::Repository => {
                            SemanticCode::GIT_REMOTE_REPO_DELETE
                        }
                        crate::bash_remote_source_control::RemoteDeletion::Resource => {
                            SemanticCode::GIT_REMOTE_RESOURCE_DELETE
                        }
                    });
                }
                let stage = self.stages.len();
                // Generic visible-source lowering has caller context; this stage must
                // remain in the isolated terminal analyzer even if an artifact matches.
                self.prelowered_visible_stages.insert(stage);
                self.stages.push(StageDraft {
                    permission_grants: if program == "chmod" {
                        crate::bash_filesystem::chmod_permission_grants(arguments)
                    } else {
                        None
                    },
                    language_safety_only: false,
                    invocation,
                    invocation_cwd: None,
                    child_cwd_keys: Vec::new(),
                    filesystems,
                    root_move_destination_key: None,
                    git_operations,
                    git_project_scoped: false,
                    network_outbound: execution
                        .as_ref()
                        .is_some_and(|model| model.network_outbound),
                    network_endpoints: execution
                        .as_ref()
                        .map_or_else(Vec::new, |model| model.network_endpoints.clone()),
                    system_states,
                    fifo_creations: Vec::new(),
                    stdout: StdoutDraft::Unknown,
                    content_writes: Vec::new(),
                    payload_depth: self.payload_depth,
                    conditional_depth: self.conditional_depth,
                    execution_dominators: Vec::new(),
                });
                let mut lowered = Lowered {
                    stages: vec![stage],
                    // Unmodeled redirects cannot establish pipe connectivity.
                    inputs: if redirects.is_empty()
                        && execution.as_ref().is_none_or(|model| model.stdin_flows)
                    {
                        vec![stage]
                    } else {
                        Vec::new()
                    },
                    outputs: if redirects.is_empty()
                        && execution.as_ref().is_none_or(|model| model.stdout_flows)
                    {
                        vec![stage]
                    } else {
                        Vec::new()
                    },
                };
                // Only reviewed local executors participate; remote payloads remain excluded.
                if matches!(program.as_str(), "xargs" | "find" | "tar" | "bsdtar") {
                    for executor in executor_payloads(&program, arguments, &[], None) {
                        let nested = self.lower_terminal_launch(&executor.payload);
                        if executor.substitutes_command && redirects.is_empty() {
                            lowered.inputs.extend(nested.stages.iter().copied());
                        }
                        lowered.stages.extend(nested.stages);
                    }
                }
                lowered
            }
            Statement::Unsupported { statements, .. }
            | Statement::UnmodeledStateMutation { statements, .. } => {
                self.complete = false;
                let mut lowered = Lowered::default();
                for statement in statements {
                    lowered.extend(self.lower_terminal_statement(statement));
                }
                lowered
            }
            Statement::Assignments { .. }
            | Statement::FunctionDefinition { .. }
            | Statement::LoopControl { .. } => Lowered::default(),
        }
    }

    fn terminal_redirect_filesystems(&self, redirects: &[Redirect]) -> Vec<FilesystemDraft> {
        let mut filesystems = Vec::new();
        for redirect in redirects {
            let Some(raw) = redirect.target() else {
                continue;
            };
            let Some(target) = static_word(raw, redirect.target_substitutions().is_empty()) else {
                continue;
            };
            if AbsolutePath::new(self.platform, &target).is_err()
                || contains_unquoted_pattern(raw)
                || target.starts_with("/dev/tcp/")
                || target.starts_with("/dev/udp/")
            {
                continue;
            }
            for operation in super::filesystem::redirect_operations(
                redirect.fd(),
                redirect.operator(),
                redirect.target(),
            )
            .unwrap_or_default()
            {
                let mut filesystem = super::filesystem::unresolved_read(&target);
                filesystem.operation = operation;
                filesystem.unresolved_selection = false;
                filesystems.push(filesystem);
            }
        }
        filesystems
    }

    fn lower_terminal_redirects(&mut self, redirects: &[Redirect]) -> Lowered {
        if redirects.is_empty() {
            return Lowered::default();
        }
        // A redirect-only shell statement performs the null command.
        self.lower_terminal_statement(&Statement::Command {
            name: ":".into(),
            name_substitutions: Vec::new(),
            assignments: Vec::new(),
            unmodeled_assignments: Vec::new(),
            arguments: Vec::new(),
            redirects: redirects.to_vec(),
        })
    }
}
