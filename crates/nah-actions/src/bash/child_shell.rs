//! Builds the bounded environment and startup state inherited by child Bash payloads.

use nah_parse::{Statement, Word};
use nah_proto::ctx::AbsolutePath;

use crate::bash_child_startup::{ChildShell, EnvOperation, env_overlay};
use crate::bash_model::{ProgramDraft, ResolvedWord, VariableValue};
use crate::bash_state::{BindingAttribute, current_pwd, known_cwd};
use crate::bash_wrappers::wrapper_clears_environment;
use crate::paths::resolve_from_cwd;
use crate::shell_word::{ExpansionContext, resolve_word};

use super::{
    AssignmentUpdate, CommandContext, InjectedOrigins, Lowered, Lowerer, VisibleExecutionState,
};

impl Lowerer {
    pub(super) fn prepare_isolated_environment(
        &mut self,
        program: &ProgramDraft,
        arguments: &[Word],
        assignments: &[(String, Word)],
        updates: &[AssignmentUpdate],
    ) {
        let program = match program {
            ProgramDraft::Static(program) => Some(program.as_str()),
            ProgramDraft::Env { .. } | ProgramDraft::Unresolved => None,
        };
        let mut uncertain_export = false;
        self.state.variables.retain(|binding| {
            let retained = binding.exported != BindingAttribute::No
                && program.is_none_or(|program| {
                    !wrapper_clears_environment(program, arguments, &binding.name)
                });
            uncertain_export |= retained && binding.exported == BindingAttribute::Unknown;
            retained
        });
        self.ambient_variables.retain(|(name, _)| {
            program.is_none_or(|program| !wrapper_clears_environment(program, arguments, name))
        });
        if program.is_some_and(|program| {
            wrapper_clears_environment(program, arguments, "__NAH_UNKNOWN_VARIABLE")
        }) {
            self.state.unknown_variables = false;
        }
        if uncertain_export {
            self.complete = false;
        }
        self.state.positional_zero = None;
        self.state.positionals.clear();
        for ((name, word), update) in assignments.iter().zip(updates.iter().cloned()) {
            self.apply_assignment_update(name, update, false);
            self.update_descriptor_assignment(name, word.raw());
            if let Some(binding) = self
                .state
                .variables
                .iter_mut()
                .find(|binding| binding.name == *name)
            {
                binding.exported = BindingAttribute::Yes;
            }
        }
    }

    pub(super) fn prepare_child_functions(
        &mut self,
        program: &str,
        arguments: &[Word],
        child: Option<&ChildShell>,
        transparent_wrapper: bool,
    ) {
        let mut uncertain_export = false;
        self.state.functions.retain(|binding| {
            let retained = binding.exported != BindingAttribute::No
                && !wrapper_clears_environment(
                    program,
                    arguments,
                    &crate::bash_child_startup::bash_function_wire_name(
                        &self.function_bodies[binding.body].name,
                    ),
                );
            uncertain_export |= retained && binding.exported == BindingAttribute::Unknown;
            retained
        });
        if uncertain_export {
            self.complete = false;
        }

        let overlay = env_overlay(program, arguments);
        self.complete &= overlay.complete;
        self.analysis_refused |= overlay.analysis_refused;
        for operation in overlay.operations {
            match operation {
                EnvOperation::Clear => self.state.functions.clear(),
                EnvOperation::Unset(name) => {
                    let bodies = &self.function_bodies;
                    self.state.functions.retain(|binding| {
                        crate::bash_child_startup::bash_function_wire_name(
                            &bodies[binding.body].name,
                        ) != name
                    });
                }
                EnvOperation::Function { name, definition } => {
                    self.define_exported_function(&name, &definition);
                }
            }
        }

        if !transparent_wrapper && child.is_none_or(|child| !child.imports_bash_environment) {
            self.state.functions.clear();
        }
    }

    pub(super) fn define_exported_function(&mut self, name: &str, definition: &str) {
        let Ok(syntax) = nah_parse::normalize(definition) else {
            self.complete = false;
            self.analysis_refused = true;
            return;
        };
        let [
            Statement::FunctionDefinition {
                name: parsed_name,
                body,
                redirects,
            },
        ] = syntax.statements()
        else {
            self.complete = false;
            self.analysis_refused = true;
            return;
        };
        if parsed_name != name {
            self.complete = false;
            self.analysis_refused = true;
            return;
        }
        let bodies = &self.function_bodies;
        self.state
            .functions
            .retain(|binding| bodies[binding.body].name != name);
        self.define_function(name, body, redirects);
        if let Some(binding) = self
            .state
            .functions
            .iter_mut()
            .find(|binding| self.function_bodies[binding.body].name == name)
        {
            binding.exported = BindingAttribute::Yes;
            binding.readonly = BindingAttribute::No;
        }
    }

    pub(super) fn lower_bash_env_startup(&mut self, child: &ChildShell) -> Lowered {
        if !child.runs_bash_env {
            return Lowered::default();
        }
        let (value, origins) = if let Some(binding) = self
            .state
            .variables
            .iter()
            .find(|binding| binding.name == "BASH_ENV")
        {
            (&binding.value, binding.origins.clone())
        } else if let Some((_, value)) = self
            .ambient_variables
            .iter()
            .find(|(name, _)| name == "BASH_ENV")
        {
            (value, Vec::new())
        } else {
            return Lowered::default();
        };
        let VariableValue::Static(value) = value else {
            if !matches!(value, VariableValue::Unset) {
                self.complete = false;
                self.analysis_refused = true;
            }
            return Lowered::default();
        };
        let variables = self.visible_variables();
        let ResolvedWord::Static { value: path, .. } =
            resolve_word(value, &[], &variables, ExpansionContext::Assignment, |_| {
                None
            })
        else {
            self.complete = false;
            self.analysis_refused = true;
            return Lowered::default();
        };
        if path.is_empty() {
            return Lowered::default();
        }
        let path = if path.starts_with('~') {
            let Some(path) = resolve_from_cwd(
                known_cwd(&self.state),
                current_pwd(&self.state),
                &path,
                &self.home,
                self.platform,
                true,
            ) else {
                self.complete = false;
                self.analysis_refused = true;
                return Lowered::default();
            };
            path
        } else if AbsolutePath::new(self.platform, &path).is_ok() {
            path
        } else {
            // Bash searches PATH for a bare BASH_ENV value. Treating it as a
            // cwd-relative file could bind reviewed content to the wrong code.
            self.complete = false;
            self.analysis_refused = true;
            return Lowered::default();
        };
        let previous = self.suppress_bash_startup;
        self.suppress_bash_startup = true;
        let mut lowered = self.lower_command(
            "bash",
            &[],
            &[],
            &[Word::from_literal(&path)],
            &[],
            CommandContext {
                injected_origins: &InjectedOrigins {
                    name: Vec::new(),
                    arguments: vec![origins],
                },
                exact_target: None,
                builtin_target: false,
            },
        );
        self.suppress_bash_startup = previous;
        let state = self.state.clone();
        let ambient_variables = self.ambient_variables.clone();
        for stage in &lowered.stages {
            self.visible_execution_states.push(VisibleExecutionState {
                stage: *stage,
                state: state.clone(),
                ambient_variables: ambient_variables.clone(),
            });
        }
        if let Some(sink) = lowered.stages.last().copied() {
            lowered.extend(self.lower_visible_execution_now(sink));
        }
        lowered
    }

    pub(super) fn lower_isolated_bash_env_startup(
        &mut self,
        program: &ProgramDraft,
        arguments: &[Word],
        assignments: &[(String, Word)],
        updates: &[AssignmentUpdate],
        child: &ChildShell,
        argument_origins: &[Vec<usize>],
    ) -> Lowered {
        if self.suppress_bash_startup || !child.executes_payload {
            return Lowered::default();
        }
        let parent_state = self.state.clone();
        let parent_ambient_variables = self.ambient_variables.clone();
        let parent_lookup_mode = self.next_lookup_mode;
        self.prepare_isolated_environment(program, arguments, assignments, updates);
        let program_name = match program {
            ProgramDraft::Static(program) => program.as_str(),
            ProgramDraft::Env { .. } | ProgramDraft::Unresolved => "",
        };
        self.prepare_child_functions(program_name, arguments, Some(child), false);
        self.prepare_child_positionals(child, argument_origins);
        self.next_lookup_mode = None;
        let lowered = self.lower_bash_env_startup(child);
        self.pending_visible_child_state = Some(VisibleExecutionState {
            stage: usize::MAX,
            state: self.state.clone(),
            ambient_variables: self.ambient_variables.clone(),
        });
        self.next_lookup_mode = parent_lookup_mode;
        self.state = parent_state;
        self.ambient_variables = parent_ambient_variables;
        lowered
    }

    pub(super) fn payload_with_environment_assignments(
        &self,
        program: &ProgramDraft,
        arguments: &[Word],
        assignments: &[(String, Word)],
        payload: String,
    ) -> String {
        let program = match program {
            ProgramDraft::Static(program) => program.as_str(),
            ProgramDraft::Env { .. } | ProgramDraft::Unresolved => return payload,
        };
        let prefixes = assignments
            .iter()
            .filter(|(name, value)| {
                matches!(name.as_str(), "TAR_OPTIONS" | "TAPE")
                    && value.substitutions().is_empty()
                    && !wrapper_clears_environment(program, arguments, name)
            })
            .map(|(name, value)| format!("{name}={}", value.raw()))
            .collect::<Vec<_>>();
        if prefixes.is_empty() {
            payload
        } else {
            format!("{} {payload}", prefixes.join(" "))
        }
    }
}
