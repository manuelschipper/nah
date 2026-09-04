//! Classifies one resolved shell command as typed invocation evidence.

use nah_parse::Word;
use nah_proto::action::SemanticCode;

use crate::bash_execution::execution_spec;
use crate::bash_filesystem::chmod_weakens_permissions;
use crate::bash_model::{InvocationDraft, ProgramDraft};
use crate::shell_word::static_word;

#[allow(clippy::too_many_arguments)]
pub(crate) fn invocation(
    program: &ProgramDraft,
    lexical_program: Option<&str>,
    arguments: &[Word],
    words: Vec<String>,
    argv: Option<Vec<String>>,
    local_utility: bool,
    semantic_operation: Option<SemanticCode>,
    evals_substitution: bool,
    direct_execution: bool,
    pattern_program: bool,
) -> InvocationDraft {
    if matches!(program, ProgramDraft::Unresolved) {
        return InvocationDraft::CodeExecution {
            program: "shell".to_owned(),
            interpreter: None,
            source: SemanticCode::UNRESOLVED_COMMAND,
            code: None,
            input: None,
            words,
            argv: None,
        };
    }
    let ProgramDraft::Static(program) = program else {
        return InvocationDraft::Opaque {
            program: program.clone(),
            words,
            argv: None,
        };
    };
    let lexical_program = lexical_program.unwrap_or(program);
    if semantic_operation.as_ref().is_some_and(|operation| {
        operation == &SemanticCode::CRITICAL_MUTATION || operation == &SemanticCode::HOST_POWER
    }) {
        return InvocationDraft::Known {
            program: if pattern_program
                && semantic_operation.as_ref() == Some(&SemanticCode::CRITICAL_MUTATION)
            {
                "shell".to_owned()
            } else {
                lexical_program.to_owned()
            },
            operation: semantic_operation.expect("matched priority semantic operation"),
            words,
            argv,
        };
    }
    if pattern_program {
        return InvocationDraft::CodeExecution {
            program: "shell".to_owned(),
            interpreter: None,
            source: SemanticCode::SHELL_PATTERN,
            code: None,
            input: None,
            words,
            argv: None,
        };
    }
    if direct_execution {
        return InvocationDraft::CodeExecution {
            program: lexical_program.to_owned(),
            interpreter: None,
            source: SemanticCode::DIRECT_FILE,
            code: None,
            input: None,
            words,
            argv,
        };
    }
    if local_utility {
        return InvocationDraft::Known {
            program: lexical_program.to_owned(),
            operation: SemanticCode::LOCAL_UTILITY,
            words,
            argv,
        };
    }
    if let Some(operation) = semantic_operation {
        return InvocationDraft::Known {
            program: lexical_program.to_owned(),
            operation,
            words,
            argv,
        };
    }
    if let Some(execution) = execution_spec(program, arguments) {
        return InvocationDraft::CodeExecution {
            program: lexical_program.to_owned(),
            interpreter: (!matches!(program.as_str(), "." | "source")).then(|| program.clone()),
            source: execution.source,
            code: execution.code,
            input: None,
            words,
            argv,
        };
    }
    let (interpreter, source) = match program.as_str() {
        "eval" => (
            None,
            if evals_substitution {
                SemanticCode::EVALUATED_SUBSTITUTION
            } else {
                SemanticCode::EVALUATED_SHELL
            },
        ),
        "rm" | "rmdir" | "unlink" | "find" => {
            return InvocationDraft::Known {
                program: lexical_program.to_owned(),
                operation: SemanticCode::REMOVE,
                words,
                argv,
            };
        }
        "chmod" | "chown" | "chgrp" | "setfacl" => {
            return InvocationDraft::Known {
                program: lexical_program.to_owned(),
                operation: if program == "chmod" && chmod_weakens_permissions(arguments) {
                    SemanticCode::PERMISSION_WEAKEN
                } else {
                    SemanticCode::PERMISSION_CHANGE
                },
                words,
                argv,
            };
        }
        "dd" | "cp" | "shred" | "truncate" | "blkdiscard" | "pvremove" | "wipefs"
        | "cryptsetup" | "sgdisk" | "sfdisk" | "parted" | "mdadm" | "nvme" | "hdparm"
        | "diskutil" | "badblocks" => {
            return InvocationDraft::Known {
                program: lexical_program.to_owned(),
                operation: SemanticCode::STORAGE_WRITE,
                words,
                argv,
            };
        }
        command if command.starts_with("mkfs") || command.starts_with("newfs") => {
            return InvocationDraft::Known {
                program: lexical_program.to_owned(),
                operation: SemanticCode::STORAGE_WRITE,
                words,
                argv,
            };
        }
        _ => {
            return InvocationDraft::Opaque {
                program: ProgramDraft::Static(lexical_program.to_owned()),
                words,
                argv,
            };
        }
    };
    let code = (source == SemanticCode::EVALUATED_SHELL)
        .then(|| static_arguments(arguments).map(|arguments| arguments.join(" ")))
        .flatten();
    InvocationDraft::CodeExecution {
        program: lexical_program.to_owned(),
        interpreter,
        source,
        code,
        input: None,
        words,
        argv,
    }
}

pub(crate) fn static_argv(program: &str, arguments: &[Word]) -> Option<Vec<String>> {
    let mut argv = vec![program.to_owned()];
    argv.extend(static_arguments(arguments)?);
    Some(argv)
}

fn static_arguments(arguments: &[Word]) -> Option<Vec<String>> {
    arguments
        .iter()
        .map(|argument| {
            (!crate::shell_word::has_unmodeled_expansion(argument.raw()))
                .then(|| static_word(argument.raw(), argument.substitutions().is_empty()))
                .flatten()
        })
        .collect()
}
