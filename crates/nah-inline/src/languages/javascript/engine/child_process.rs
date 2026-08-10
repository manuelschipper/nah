//! Node child-process call shapes and exact nested executions.

use super::*;

pub(super) fn child_callable(member: Member) -> &'static str {
    match member {
        Member::Exec => "child_process.exec",
        Member::ExecSync => "child_process.execSync",
        Member::Spawn => "child_process.spawn",
        Member::SpawnSync => "child_process.spawnSync",
        Member::ExecFile => "child_process.execFile",
        Member::ExecFileSync => "child_process.execFileSync",
        _ => unreachable!(),
    }
}

pub(super) enum ChildExecution {
    None,
    Command {
        argv: Vec<String>,
        cwd: NestedExecutionCwd,
    },
    Bash {
        code: String,
        cwd: NestedExecutionCwd,
    },
    OpaqueShell {
        program: String,
        code: String,
        cwd: NestedExecutionCwd,
    },
}

pub(super) enum ChildCallSummary {
    Call {
        kind: LanguageCallKind,
        execution: ChildExecution,
        callback: Option<usize>,
        partial: bool,
    },
    Partial,
    Invalid,
}

#[derive(Default)]
struct ChildShape {
    args: Option<usize>,
    options: Option<usize>,
    callback: Option<usize>,
}

enum ChildShapeError {
    Partial,
    Invalid,
}

#[derive(Clone, Copy)]
enum ChildValueStatus {
    Exact,
    Partial,
    Invalid,
}

#[derive(Clone, Copy)]
enum ChildShell {
    Argv,
    Bash,
    Posix,
    Opaque,
}

pub(super) fn summarize_child_call(
    member: Member,
    arguments: &Arguments,
    platform: Platform,
    current_cwd: &NestedExecutionCwd,
) -> ChildCallSummary {
    if !arguments.complete {
        return ChildCallSummary::Partial;
    }
    let values = &arguments.values;
    let shape = match child_shape(member, values) {
        Ok(shape) => shape,
        Err(ChildShapeError::Partial) => return ChildCallSummary::Partial,
        Err(ChildShapeError::Invalid) => return ChildCallSummary::Invalid,
    };
    let mut partial = false;
    for status in std::iter::once(
        values
            .first()
            .map_or(ChildValueStatus::Invalid, child_command_status),
    )
    .chain(shape.args.map(|index| child_args_status(&values[index])))
    .chain(
        shape
            .options
            .map(|index| child_options_status(&values[index])),
    )
    .chain(
        shape
            .callback
            .map(|index| child_callback_status(&values[index])),
    ) {
        match status {
            ChildValueStatus::Exact => {}
            ChildValueStatus::Partial => partial = true,
            ChildValueStatus::Invalid => return ChildCallSummary::Invalid,
        }
    }
    let options = shape.options.map(|index| &values[index]);
    let (shell, context_exact, shell_partial, cwd) =
        match child_shell(member, options, platform, current_cwd) {
            Ok(summary) => summary,
            Err(ChildShapeError::Partial) => return ChildCallSummary::Partial,
            Err(ChildShapeError::Invalid) => return ChildCallSummary::Invalid,
        };
    partial |= shell_partial || !context_exact || shape.callback.is_some();
    let argv = child_argv(
        values.first().unwrap(),
        shape.args.map(|index| &values[index]),
    );
    if argv.is_none() {
        partial = true;
    }
    let execution = if context_exact {
        match (shell, argv) {
            (ChildShell::Argv, Some(argv)) => ChildExecution::Command { argv, cwd },
            (ChildShell::Bash, Some(argv)) => ChildExecution::Bash {
                code: argv.join(" "),
                cwd,
            },
            (ChildShell::Posix, Some(argv)) => ChildExecution::OpaqueShell {
                program: "sh".to_owned(),
                code: argv.join(" "),
                cwd,
            },
            (ChildShell::Opaque, Some(argv)) => child_opaque_shell_program(options, platform)
                .map_or(ChildExecution::None, |program| {
                    ChildExecution::OpaqueShell {
                        program,
                        code: argv.join(" "),
                        cwd,
                    }
                }),
            _ => ChildExecution::None,
        }
    } else {
        ChildExecution::None
    };
    let kind = match shell {
        ChildShell::Argv => LanguageCallKind::LocalUtility,
        ChildShell::Bash | ChildShell::Posix | ChildShell::Opaque => {
            LanguageCallKind::EvaluatedShell
        }
    };
    ChildCallSummary::Call {
        kind,
        execution,
        callback: shape.callback,
        partial,
    }
}

fn child_shape(member: Member, values: &[Value]) -> Result<ChildShape, ChildShapeError> {
    if values.is_empty() {
        return Err(ChildShapeError::Invalid);
    }
    match member {
        Member::Exec => match values.len() {
            1 => Ok(ChildShape::default()),
            2 => match &values[1] {
                Value::Object(_) | Value::Null | Value::Undefined => Ok(ChildShape {
                    options: Some(1),
                    ..ChildShape::default()
                }),
                value if child_callback_shape(value) => Ok(ChildShape {
                    callback: Some(1),
                    ..ChildShape::default()
                }),
                value if unknown_value(value) => Ok(ChildShape {
                    options: Some(1),
                    ..ChildShape::default()
                }),
                _ => Err(ChildShapeError::Invalid),
            },
            3 => Ok(ChildShape {
                options: Some(1),
                callback: Some(2),
                ..ChildShape::default()
            }),
            _ => Err(ChildShapeError::Invalid),
        },
        Member::ExecSync => match values.len() {
            1 => Ok(ChildShape::default()),
            2 => Ok(ChildShape {
                options: Some(1),
                ..ChildShape::default()
            }),
            _ => Err(ChildShapeError::Invalid),
        },
        Member::Spawn | Member::SpawnSync => match values.len() {
            1 => Ok(ChildShape::default()),
            2 => child_args_or_options(&values[1]),
            3 => Ok(ChildShape {
                args: Some(1),
                options: Some(2),
                ..ChildShape::default()
            }),
            _ => Err(ChildShapeError::Invalid),
        },
        Member::ExecFile => match values.len() {
            1 => Ok(ChildShape::default()),
            2 => child_args_options_or_callback(&values[1]),
            3 => {
                if child_args_shape(&values[1]) {
                    if child_callback_shape(&values[2]) {
                        Ok(ChildShape {
                            args: Some(1),
                            callback: Some(2),
                            ..ChildShape::default()
                        })
                    } else {
                        Ok(ChildShape {
                            args: Some(1),
                            options: Some(2),
                            ..ChildShape::default()
                        })
                    }
                } else if child_options_shape(&values[1]) {
                    Ok(ChildShape {
                        options: Some(1),
                        callback: Some(2),
                        ..ChildShape::default()
                    })
                } else {
                    Err(if unknown_value(&values[1]) {
                        ChildShapeError::Partial
                    } else {
                        ChildShapeError::Invalid
                    })
                }
            }
            4 => Ok(ChildShape {
                args: Some(1),
                options: Some(2),
                callback: Some(3),
            }),
            _ => Err(ChildShapeError::Invalid),
        },
        Member::ExecFileSync => match values.len() {
            1 => Ok(ChildShape::default()),
            2 => child_args_or_options(&values[1]),
            3 => Ok(ChildShape {
                args: Some(1),
                options: Some(2),
                ..ChildShape::default()
            }),
            _ => Err(ChildShapeError::Invalid),
        },
        _ => unreachable!(),
    }
}

fn child_args_or_options(value: &Value) -> Result<ChildShape, ChildShapeError> {
    if child_args_shape(value) {
        Ok(ChildShape {
            args: Some(1),
            ..ChildShape::default()
        })
    } else if child_options_shape(value) {
        Ok(ChildShape {
            options: Some(1),
            ..ChildShape::default()
        })
    } else {
        Err(if unknown_value(value) {
            ChildShapeError::Partial
        } else {
            ChildShapeError::Invalid
        })
    }
}

fn child_args_options_or_callback(value: &Value) -> Result<ChildShape, ChildShapeError> {
    if child_args_shape(value) {
        Ok(ChildShape {
            args: Some(1),
            ..ChildShape::default()
        })
    } else if child_options_shape(value) {
        Ok(ChildShape {
            options: Some(1),
            ..ChildShape::default()
        })
    } else if child_callback_shape(value) {
        Ok(ChildShape {
            callback: Some(1),
            ..ChildShape::default()
        })
    } else {
        Err(if unknown_value(value) {
            ChildShapeError::Partial
        } else {
            ChildShapeError::Invalid
        })
    }
}

fn child_args_shape(value: &Value) -> bool {
    matches!(value, Value::Array(_) | Value::Null | Value::Undefined)
}

fn child_options_shape(value: &Value) -> bool {
    matches!(value, Value::Object(_) | Value::Null | Value::Undefined)
}

pub(super) fn child_callback_shape(value: &Value) -> bool {
    matches!(
        value,
        Value::Function(_) | Value::Known(_) | Value::Require | Value::Eval | Value::ObjectBuiltin
    )
}

fn child_command_status(value: &Value) -> ChildValueStatus {
    match value {
        Value::String(value) if !value.contains('\0') => ChildValueStatus::Exact,
        value if unknown_value(value) => ChildValueStatus::Partial,
        _ => ChildValueStatus::Invalid,
    }
}

fn child_args_status(value: &Value) -> ChildValueStatus {
    match value {
        Value::Array(values) => {
            let mut status = ChildValueStatus::Exact;
            for value in values {
                match child_command_status(value) {
                    ChildValueStatus::Exact => {}
                    ChildValueStatus::Partial => status = ChildValueStatus::Partial,
                    ChildValueStatus::Invalid => return ChildValueStatus::Invalid,
                }
            }
            status
        }
        Value::Null | Value::Undefined => ChildValueStatus::Exact,
        value if unknown_value(value) => ChildValueStatus::Partial,
        _ => ChildValueStatus::Invalid,
    }
}

fn child_options_status(value: &Value) -> ChildValueStatus {
    match value {
        Value::Object(properties) if properties.values().any(accessor_value) => {
            ChildValueStatus::Partial
        }
        Value::Object(_) | Value::Null | Value::Undefined => ChildValueStatus::Exact,
        value if unknown_value(value) => ChildValueStatus::Partial,
        _ => ChildValueStatus::Invalid,
    }
}

fn child_callback_status(value: &Value) -> ChildValueStatus {
    if child_callback_shape(value) {
        ChildValueStatus::Exact
    } else if unknown_value(value) {
        ChildValueStatus::Partial
    } else {
        ChildValueStatus::Invalid
    }
}

fn child_shell(
    member: Member,
    options: Option<&Value>,
    platform: Platform,
    current_cwd: &NestedExecutionCwd,
) -> Result<(ChildShell, bool, bool, NestedExecutionCwd), ChildShapeError> {
    let always_shell = matches!(member, Member::Exec | Member::ExecSync);
    let default = if always_shell && platform != Platform::Windows {
        ChildShell::Posix
    } else if always_shell {
        ChildShell::Opaque
    } else {
        ChildShell::Argv
    };
    let default_partial = matches!(default, ChildShell::Opaque);
    let Some(options) = options else {
        return Ok((default, true, default_partial, current_cwd.clone()));
    };
    let properties = match options {
        Value::Null | Value::Undefined => {
            return Ok((default, true, default_partial, current_cwd.clone()));
        }
        Value::Object(properties) => properties,
        value if unknown_value(value) => {
            return if always_shell {
                Ok((ChildShell::Opaque, false, true, NestedExecutionCwd::Unknown))
            } else {
                Err(ChildShapeError::Partial)
            };
        }
        _ => return Err(ChildShapeError::Invalid),
    };
    if properties.values().any(accessor_value) {
        return Err(ChildShapeError::Partial);
    }
    let context_exact = properties
        .get("env")
        .is_none_or(|value| matches!(value, Value::Null | Value::Undefined));
    let cwd = match properties.get("cwd") {
        None | Some(Value::Null | Value::Undefined) => current_cwd.clone(),
        Some(Value::String(path)) if !path.is_empty() && !path.contains('\0') => {
            current_cwd.changed(path, platform)
        }
        Some(value) if unknown_value(value) => return Err(ChildShapeError::Partial),
        Some(_) => return Err(ChildShapeError::Invalid),
    };
    let Some(shell) = properties.get("shell") else {
        return Ok((default, context_exact, default_partial, cwd));
    };
    if always_shell {
        let shell = match value_string(shell) {
            Some("/bin/bash" | "bash") if platform != Platform::Windows => ChildShell::Bash,
            Some("/bin/sh" | "sh") if platform != Platform::Windows => ChildShell::Posix,
            _ => ChildShell::Opaque,
        };
        return Ok((
            shell,
            context_exact,
            matches!(shell, ChildShell::Opaque),
            cwd,
        ));
    }
    let shell = match shell {
        Value::Bool(false) | Value::Null | Value::Undefined => ChildShell::Argv,
        Value::String(value) if value.is_empty() => ChildShell::Argv,
        Value::String(value) if platform != Platform::Windows && value == "/bin/bash" => {
            ChildShell::Bash
        }
        Value::Bool(true) if platform != Platform::Windows => ChildShell::Posix,
        Value::String(value)
            if platform != Platform::Windows && matches!(value.as_str(), "/bin/sh" | "sh") =>
        {
            ChildShell::Posix
        }
        Value::Bool(true) | Value::String(_) => ChildShell::Opaque,
        value if unknown_value(value) => return Err(ChildShapeError::Partial),
        _ => return Err(ChildShapeError::Invalid),
    };
    Ok((
        shell,
        context_exact,
        matches!(shell, ChildShell::Opaque),
        cwd,
    ))
}

fn child_opaque_shell_program(options: Option<&Value>, platform: Platform) -> Option<String> {
    if let Some(Value::Object(properties)) = options
        && let Some(Value::String(shell)) = properties.get("shell")
    {
        return (!shell.is_empty()).then(|| shell.clone());
    }
    (platform != Platform::Windows).then(|| "sh".to_owned())
}

fn child_argv(command: &Value, args: Option<&Value>) -> Option<Vec<String>> {
    let mut argv = vec![value_string(command)?.to_owned()];
    match args {
        None | Some(Value::Null | Value::Undefined) => {}
        Some(Value::Array(values)) => {
            for value in values {
                argv.push(value_string(value)?.to_owned());
            }
        }
        Some(_) => return None,
    }
    Some(argv)
}
