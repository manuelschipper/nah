//! Lowers nested payloads, child startup, and exact command output before effect composition.

use std::collections::BTreeSet;

use nah_parse::{Redirect, Word};
use nah_proto::action::{FilesystemOperation, SemanticCode};

use super::{
    AssignmentUpdate, CommandContext, InjectedOrigins, Lowered, Lowerer, PayloadExecution,
};
use crate::bash_child_startup::child_shell;
use crate::bash_content::{eval_payload, producer, redirect_content_target, tee_content_targets};
use crate::bash_git_config::AliasAnalysis;
use crate::bash_lookup::{LookupMode, LookupState};
use crate::bash_model::{InvocationDraft, ProgramDraft, StdoutDraft, VariableValue};
use crate::bash_state::{Cwd, current_pwd, known_cwd};
use crate::bash_wrappers::{
    crontab_payload, executor_payloads, shell_payload, shell_string_wrapper_payload,
    wrapper_clears_environment, wrapper_payload,
};
use crate::paths::resolve_from_cwd;
use crate::shell_word::static_word;

fn starts_a_command(argument: &Word) -> bool {
    static_word(argument.raw(), argument.substitutions().is_empty()).is_some_and(|word| {
        !word.is_empty() && !word.starts_with('-') && !word.contains(['/', '\\'])
    })
}

pub(super) struct CommandPayloads {
    pub(super) producer: crate::bash_content::Producer,
    pub(super) content_writes: Vec<String>,
    pub(super) lowered_startup: Lowered,
    pub(super) lowered_payload: Option<(Lowered, bool)>,
    pub(super) lowered_executors: Vec<(Lowered, bool)>,
}

impl Lowerer {
    /// Checks whether an otherwise opaque program may be treating one of its
    /// argument runs as a nested command.
    pub(super) fn arguments_may_run_a_command(&self, arguments: &[Word]) -> bool {
        if self.speculative {
            return false;
        }
        (0..arguments.len())
            .filter(|start| starts_a_command(&arguments[*start]))
            .any(|start| {
                let mut lowerer = Lowerer {
                    complete: true,
                    stages: Vec::new(),
                    flows: Vec::new(),
                    queries: Vec::new(),
                    state: self.state.clone(),
                    ambient_variables: self.ambient_variables.clone(),
                    runtime_variables: self.runtime_variables.clone(),
                    initial_cwd: self.initial_cwd.clone(),
                    loop_depth: 0,
                    home: self.home.clone(),
                    critical_paths: self.critical_paths.clone(),
                    platform: self.platform,
                    payload_depth: 0,
                    conditional_depth: self.conditional_depth,
                    analysis_refused: false,
                    function_bodies: self.function_bodies.clone(),
                    active_function_calls: Vec::new(),
                    function_local_scopes: Vec::new(),
                    next_lookup_mode: None,
                    active_aliases: self.active_aliases.clone(),
                    next_alias_eligible: None,
                    active_alias_expansions: Vec::new(),
                    alias_expansions: 0,
                    function_expansions: 0,
                    asynchronous_depth: 0,
                    detected_fork_bomb: false,
                    visible_stdin: None,
                    visible_execution_states: Vec::new(),
                    inline_child_stages: BTreeSet::new(),
                    inline_child_cwds: Vec::new(),
                    inline_report: nah_inline::InlineReport::default(),
                    inline_failed: false,
                    inline_child_count: 0,
                    inline_child_bytes: 0,
                    prelowered_visible_stages: BTreeSet::new(),
                    unresolved_current_shell_stages: BTreeSet::new(),
                    tracked_execution_stream_stages: BTreeSet::new(),
                    pending_visible_child_state: None,
                    suppress_bash_startup: self.suppress_bash_startup,
                    next_descriptor_id: self.next_descriptor_id,
                    speculative: true,
                };
                lowerer.lower_command(
                    arguments[start].raw(),
                    &[],
                    &[],
                    &arguments[start + 1..],
                    &[],
                    CommandContext {
                        injected_origins: &InjectedOrigins::default(),
                        exact_target: None,
                        builtin_target: false,
                    },
                );
                lowerer.stages.iter().any(|stage| {
                    !stage.filesystems.is_empty()
                        || !stage.git_operations.is_empty()
                        || stage.network_outbound
                        || !stage.network_endpoints.is_empty()
                        || !stage.system_states.is_empty()
                })
            })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn lower_command_payloads(
        &mut self,
        name: &str,
        program: &ProgramDraft,
        assignments: &[(String, Word)],
        local_arguments: &[Word],
        redirects: &[Redirect],
        builtin_target: bool,
        terminal_help: bool,
        qualified_program: bool,
        git_alias: Option<&AliasAnalysis>,
        tar_argument_variants: Option<&[Vec<Word>]>,
        assignment_updates: &[AssignmentUpdate],
        command_argument_origins: &[Vec<usize>],
    ) -> CommandPayloads {
        let producer = match program {
            ProgramDraft::Static(program) if !terminal_help => {
                producer(program, local_arguments, redirects)
            }
            _ => crate::bash_content::Producer {
                stdout: StdoutDraft::Unknown,
                complete: true,
            },
        };
        self.complete &= producer.complete;
        let mut content_writes = redirect_content_target(redirects)
            .and_then(|target| self.resolve_requested(&target))
            .into_iter()
            .collect::<Vec<_>>();
        if !matches!(producer.stdout, StdoutDraft::Unknown)
            && matches!(program, ProgramDraft::Static(program) if program == "tee")
            && let Some(targets) = tee_content_targets(local_arguments)
        {
            for target in targets {
                if let Some(target) = self.resolve_requested(&target) {
                    content_writes.push(target);
                }
            }
        }
        content_writes.sort();
        content_writes.dedup();
        let direct_child = match program {
            ProgramDraft::Static(program) => child_shell(program, local_arguments),
            ProgramDraft::Env { .. } | ProgramDraft::Unresolved => None,
        };
        let shell_string_wrapper = match program {
            ProgramDraft::Static(program) => {
                match shell_string_wrapper_payload(program, local_arguments) {
                    Ok(payload) => payload,
                    Err(()) => {
                        self.complete = false;
                        self.analysis_refused = true;
                        None
                    }
                }
            }
            ProgramDraft::Env { .. } | ProgramDraft::Unresolved => None,
        };
        let wrapper_identity_uncertain = matches!(program, ProgramDraft::Static(program)
        if !qualified_program
            && wrapper_clears_environment(program, local_arguments, "PATH")
            && (assignments.iter().any(|(name, _)| name == "PATH")
                || self.state.variables.iter().any(|binding| {
                    binding.name == "PATH"
                        && !matches!(binding.value, VariableValue::Unset)
                })));
        if wrapper_identity_uncertain {
            self.complete = false;
        }
        let payload_program = if wrapper_identity_uncertain {
            None
        } else {
            match program {
                ProgramDraft::Static(program) => Some(program.as_str()),
                ProgramDraft::Env { .. } | ProgramDraft::Unresolved => None,
            }
        };
        let payload = payload_program.and_then(|program| {
            let shell_payload = if matches!(program, "eval" | "trap") && !builtin_target {
                None
            } else {
                shell_payload(program, local_arguments, redirects)
            };
            match program {
                "eval" if builtin_target => shell_payload
                    .or_else(|| eval_payload(local_arguments))
                    .map(|payload| (payload, false, PayloadExecution::CurrentShell)),
                "eval" => None,
                "trap" if builtin_target => shell_payload
                    .map(|payload| (payload, false, PayloadExecution::IsolatedWithFunctions)),
                "trap" => None,
                "time" if name == "time" => wrapper_payload(program, local_arguments)
                    .map(|payload| (payload, true, PayloadExecution::CurrentShell)),
                "time" => None,
                "command" if builtin_target => {
                    let execution = if local_arguments.first().map(Word::raw) == Some("-p") {
                        PayloadExecution::CurrentShellDefaultPath
                    } else {
                        PayloadExecution::CurrentShellCommand
                    };
                    wrapper_payload(program, local_arguments)
                        .map(|payload| (payload, true, execution))
                }
                "builtin" if builtin_target => wrapper_payload(program, local_arguments)
                    .map(|payload| (payload, true, PayloadExecution::CurrentShellBuiltin)),
                "command" | "builtin" => None,
                "coproc" if name == "coproc" => wrapper_payload(program, local_arguments)
                    .map(|payload| (payload, false, PayloadExecution::IsolatedWithFunctions)),
                "coproc" => None,
                _ => shell_payload
                    .map(|payload| (payload, false, PayloadExecution::Isolated))
                    .or_else(|| {
                        shell_string_wrapper.clone().map(|(payload, transparent)| {
                            (payload, transparent, PayloadExecution::Isolated)
                        })
                    })
                    .or_else(|| {
                        wrapper_payload(program, local_arguments)
                            .map(|payload| (payload, true, PayloadExecution::Isolated))
                    })
                    .or_else(|| {
                        if program == "crontab" {
                            crontab_payload(
                                local_arguments,
                                self.visible_stdin
                                    .as_ref()
                                    .map(|visible| visible.value.as_str()),
                            )
                            .map(|payload| (payload, false, PayloadExecution::Isolated))
                        } else {
                            None
                        }
                    }),
            }
            .or_else(|| {
                git_alias
                    .as_ref()
                    .and_then(|analysis| analysis.payload.clone())
                    .map(|payload| (payload, true, PayloadExecution::Isolated))
            })
        });
        let payload = payload.map(|(payload, transparent, execution)| {
            (
                self.payload_with_environment_assignments(
                    program,
                    local_arguments,
                    assignments,
                    payload,
                ),
                transparent,
                execution,
            )
        });
        let lowered_startup = if payload.is_none() {
            direct_child
                .as_ref()
                .map_or_else(Lowered::default, |child| {
                    self.lower_isolated_bash_env_startup(
                        program,
                        local_arguments,
                        assignments,
                        assignment_updates,
                        child,
                        command_argument_origins,
                    )
                })
        } else {
            Lowered::default()
        };
        let lowered_payload = payload.and_then(|(payload, transparent, execution)| {
            if !self.enter_payload(payload.len()) {
                return None;
            }
            let lowered = match nah_parse::normalize(&payload) {
                Ok(syntax) => {
                    let parent_state = self.state.clone();
                    let parent_ambient_variables = self.ambient_variables.clone();
                    let parent_lookup_mode = self.next_lookup_mode;
                    let parsed_aliases = self
                        .active_aliases
                        .clone()
                        .unwrap_or_else(|| self.state.lookup.alias_snapshot());
                    let static_program = match program {
                        ProgramDraft::Static(program) => Some(program.as_str()),
                        ProgramDraft::Env { .. } | ProgramDraft::Unresolved => None,
                    };
                    let child = direct_child.clone();
                    let transparent_wrapper = execution == PayloadExecution::Isolated
                        && transparent
                        && static_program != Some("git");
                    let scoped_path_assignments = execution.persists_state()
                        && execution != PayloadExecution::CurrentShellDefaultPath;
                    if !execution.persists_state() {
                        self.prepare_isolated_environment(
                            program,
                            local_arguments,
                            assignments,
                            assignment_updates,
                        );
                    } else if scoped_path_assignments {
                        for ((name, _), update) in assignments.iter().zip(assignment_updates.iter())
                        {
                            if name == "PATH" {
                                self.apply_assignment_update(name, update.clone(), false);
                            }
                        }
                    }
                    if execution == PayloadExecution::Isolated {
                        self.state.lookup = LookupState::default();
                        self.prepare_child_functions(
                            static_program.unwrap_or_default(),
                            local_arguments,
                            child.as_ref(),
                            transparent_wrapper,
                        );
                        if let Some(child) = &child {
                            self.prepare_child_positionals(child, command_argument_origins);
                        }
                    }
                    self.next_lookup_mode = if transparent_wrapper {
                        Some(if static_program == Some("env") {
                            LookupMode::Command
                        } else {
                            LookupMode::External
                        })
                    } else {
                        execution.lookup_mode()
                    };
                    let mut lowered = if execution == PayloadExecution::Isolated {
                        child.as_ref().map_or_else(Lowered::default, |child| {
                            self.lower_bash_env_startup(child)
                        })
                    } else {
                        Lowered::default()
                    };
                    if transparent {
                        lowered.extend(self.lower_syntax_with_aliases(
                            &syntax,
                            parsed_aliases,
                            static_program == Some("time"),
                        ));
                    } else {
                        lowered.extend(self.lower_syntax(&syntax));
                    }
                    self.next_lookup_mode = parent_lookup_mode;
                    if !execution.persists_state() {
                        self.state = parent_state;
                        self.ambient_variables = parent_ambient_variables;
                    } else if scoped_path_assignments {
                        let path_assignments = assignments
                            .iter()
                            .filter(|(name, _)| name == "PATH")
                            .cloned()
                            .collect::<Vec<_>>();
                        self.restore_function_assignment_scope(&parent_state, &path_assignments);
                    }
                    Some((lowered, transparent))
                }
                Err(nah_parse::ParseError::ExceedsLimit(_)) => {
                    self.complete = false;
                    self.analysis_refused = true;
                    None
                }
                Err(_) => {
                    self.complete = false;
                    None
                }
            };
            self.payload_depth -= 1;
            lowered
        });
        let variables = self.visible_variables();
        let mut executor_candidates = match program {
            ProgramDraft::Static(program) => executor_payloads(
                program,
                local_arguments,
                &variables,
                self.visible_stdin
                    .as_ref()
                    .map(|visible| visible.value.as_str()),
            ),
            ProgramDraft::Env { .. } | ProgramDraft::Unresolved => Vec::new(),
        };
        if let ProgramDraft::Static(program) = &program
            && let Some(variants) = &tar_argument_variants
        {
            for arguments in variants.iter().skip(1) {
                for candidate in executor_payloads(
                    program,
                    arguments,
                    &variables,
                    self.visible_stdin
                        .as_ref()
                        .map(|visible| visible.value.as_str()),
                ) {
                    if !executor_candidates.contains(&candidate) {
                        executor_candidates.push(candidate);
                    }
                }
            }
        }
        let lowered_executors = executor_candidates
            .into_iter()
            .filter_map(
                |(payload, unknown_cwd, substitutes_command, recursive_target)| {
                    if !self.enter_payload(payload.len()) {
                        return None;
                    }
                    let lowered = match nah_parse::normalize(&payload) {
                        Ok(syntax) => {
                            let parent_state = self.state.clone();
                            let parent_ambient_variables = self.ambient_variables.clone();
                            let parent_lookup_mode = self.next_lookup_mode;
                            let recursive_target = recursive_target.and_then(|target| {
                                resolve_from_cwd(
                                    known_cwd(&parent_state),
                                    current_pwd(&parent_state),
                                    &target,
                                    &self.home,
                                    self.platform,
                                    target.starts_with('~'),
                                )
                            });
                            if unknown_cwd {
                                self.state.cwd = Cwd::Unknown;
                            }
                            self.prepare_isolated_environment(
                                program,
                                local_arguments,
                                assignments,
                                assignment_updates,
                            );
                            self.state.functions.clear();
                            self.next_lookup_mode = None;
                            let lowered = self.lower_syntax(&syntax);
                            self.next_lookup_mode = parent_lookup_mode;
                            self.state = parent_state;
                            self.ambient_variables = parent_ambient_variables;
                            if let Some(target) = recursive_target {
                                for stage in &lowered.stages {
                                    let permission_change = matches!(
                                        &self.stages[*stage].invocation,
                                        InvocationDraft::Known { operation, .. }
                                            if operation == &SemanticCode::PERMISSION_CHANGE
                                    );
                                    if permission_change {
                                        for filesystem in &mut self.stages[*stage].filesystems {
                                            if filesystem.operation == FilesystemOperation::Write
                                                && filesystem.requested == target
                                            {
                                                filesystem.recursive = true;
                                            }
                                        }
                                    }
                                }
                            }
                            Some((lowered, substitutes_command))
                        }
                        Err(nah_parse::ParseError::ExceedsLimit(_)) => {
                            self.complete = false;
                            self.analysis_refused = true;
                            None
                        }
                        Err(_) => {
                            self.complete = false;
                            None
                        }
                    };
                    self.payload_depth -= 1;
                    lowered
                },
            )
            .collect::<Vec<_>>();
        CommandPayloads {
            producer,
            content_writes,
            lowered_startup,
            lowered_payload,
            lowered_executors,
        }
    }
}
