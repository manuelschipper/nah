//! Applies current-shell variable effects from Bash builtins.

use nah_parse::Word;

use super::assignments::{
    declaration_binding_names, declaration_enables_nameref, declaration_has_unmodeled_expansion,
    declaration_nameref_targets_tar_options, read_variable_assignment, valid_variable_name,
};
use super::{AssignmentUpdate, Lowered, Lowerer, VisibleStdin};
use crate::bash_content::{
    mapfile_has_callback, mapfile_variable_assignment, printf_variable_assignment,
};
use crate::bash_descriptors::DescriptorReadEffects;
use crate::bash_model::{ProgramDraft, VariableValue};

pub(super) struct BuiltinEffects {
    pub(super) exact_variable_write: Option<(String, String, Vec<usize>)>,
    pub(super) current_shell_eval: bool,
    pub(super) current_shell_source: bool,
}

impl Lowerer {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn lower_builtin_effects(
        &mut self,
        program: &ProgramDraft,
        arguments: &[Word],
        local_arguments: &[Word],
        assignments: &[(String, Word)],
        assignment_updates: &[AssignmentUpdate],
        descriptor_read: Option<&DescriptorReadEffects>,
        builtin_target: bool,
        handled_tar_options_state: bool,
        lowered_payload: Option<&(Lowered, bool)>,
    ) -> BuiltinEffects {
        let exact_variable_write = if builtin_target {
            match program {
                ProgramDraft::Static(program) if program == "printf" => {
                    printf_variable_assignment(local_arguments)
                        .filter(|(name, _)| valid_variable_name(name))
                        .map(|(name, value)| (name, value, Vec::new()))
                }
                ProgramDraft::Static(program) if program == "read" => {
                    let descriptor_input = descriptor_read
                        .and_then(|read| read.exact_content.as_ref())
                        .map(|content| VisibleStdin {
                            value: content.clone(),
                            origins: descriptor_read
                                .map(|read| read.origins.clone())
                                .unwrap_or_default(),
                        });
                    read_variable_assignment(
                        local_arguments,
                        descriptor_input.as_ref().or(self.visible_stdin.as_ref()),
                    )
                }
                ProgramDraft::Static(program)
                    if matches!(program.as_str(), "mapfile" | "readarray") =>
                {
                    descriptor_read
                        .and_then(|read| read.exact_content.as_deref())
                        .and_then(|content| mapfile_variable_assignment(local_arguments, content))
                        .filter(|(name, _)| valid_variable_name(name))
                        .map(|(name, value)| {
                            (
                                name,
                                value,
                                descriptor_read
                                    .map(|read| read.origins.clone())
                                    .unwrap_or_default(),
                            )
                        })
                }
                ProgramDraft::Static(_) | ProgramDraft::Env { .. } | ProgramDraft::Unresolved => {
                    None
                }
            }
        } else {
            None
        };
        let current_shell_eval =
            builtin_target && matches!(program, ProgramDraft::Static(program) if program == "eval");
        if builtin_target
            && matches!(program, ProgramDraft::Static(program)
                if matches!(program.as_str(), "mapfile" | "readarray"))
            && mapfile_has_callback(local_arguments)
        {
            self.analysis_refused = true;
        }
        let current_shell_source = builtin_target
            && matches!(program, ProgramDraft::Static(program) if matches!(program.as_str(), "." | "source"));
        let mut mutated_locals = if builtin_target {
            if current_shell_source || current_shell_eval && lowered_payload.is_some() {
                Vec::new()
            } else if let ProgramDraft::Static(program) = program {
                self.mutated_local_variables(program, local_arguments, arguments)
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };
        if handled_tar_options_state {
            mutated_locals.retain(|name| name != "TAR_OPTIONS");
        }
        if let Some((name, _, _)) = &exact_variable_write {
            mutated_locals.retain(|candidate| candidate != name);
        }
        if !mutated_locals.is_empty() {
            self.complete = false;
            let origins = descriptor_read
                .map(|read| read.origins.clone())
                .unwrap_or_default();
            for name in mutated_locals {
                self.mark_local_variable_unknown_with_origins(&name, origins.clone());
            }
        }
        if builtin_target
            && let ProgramDraft::Static(program_name) = program
            && matches!(
                program_name.as_str(),
                "declare" | "export" | "local" | "readonly" | "typeset"
            )
        {
            let preserve_tar_options_nameref =
                declaration_enables_nameref(program_name, local_arguments)
                    && declaration_nameref_targets_tar_options(local_arguments, assignments);
            self.apply_assignment_updates(
                assignments,
                assignment_updates.to_vec(),
                preserve_tar_options_nameref,
            );
            self.update_variable_attributes(program_name, local_arguments, assignments);
        }
        if builtin_target && let ProgramDraft::Static(program) = program {
            let nameref = declaration_enables_nameref(program, local_arguments);
            let unmodeled =
                declaration_has_unmodeled_expansion(program, local_arguments, assignments)
                    && !(nameref
                        && declaration_nameref_targets_tar_options(local_arguments, assignments));
            if unmodeled {
                self.complete = false;
                if nameref {
                    for binding in &mut self.state.variables {
                        binding.value = VariableValue::Unknown;
                    }
                }
                for name in declaration_binding_names(local_arguments, assignments) {
                    self.set_local_variable(&name, VariableValue::Unknown);
                }
            }
        }
        BuiltinEffects {
            exact_variable_write,
            current_shell_eval,
            current_shell_source,
        }
    }
}
