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
    options: Option<ChildOptions>,
    callback: Option<usize>,
    partial: bool,
}

enum ChildShapeError {
    Invalid,
}

#[derive(Clone, Copy)]
enum ChildOptions {
    ExecSpread(usize),
    Strict(usize),
    Nullable(usize),
}

impl ChildOptions {
    fn index(self) -> usize {
        match self {
            Self::ExecSpread(index) | Self::Strict(index) | Self::Nullable(index) => index,
        }
    }
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
    let formal_count = child_formal_count(member);
    let mut widened = Vec::new();
    let (values, spread_partial) = if arguments.complete {
        (
            &arguments.values[..arguments.values.len().min(formal_count)],
            false,
        )
    } else if let Some(uncertain_from) = arguments.uncertain_from {
        widened.extend(
            arguments
                .values
                .iter()
                .take(uncertain_from.min(formal_count))
                .cloned(),
        );
        widened.resize(formal_count, Value::Unknown);
        (widened.as_slice(), true)
    } else {
        return ChildCallSummary::Partial;
    };
    let shape = match child_shape(member, values) {
        Ok(shape) => shape,
        Err(ChildShapeError::Invalid) => return ChildCallSummary::Invalid,
    };
    let mut partial = spread_partial || shape.partial;
    for status in std::iter::once(values.first().map_or(ChildValueStatus::Invalid, |value| {
        child_command_status(member, value)
    }))
    .chain(shape.args.map(|index| child_args_status(&values[index])))
    .chain(
        shape
            .options
            .map(|options| child_options_status(options, &values[options.index()])),
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
    let options = shape
        .options
        .map(|options| (options, &values[options.index()]));
    let (shell, context_exact, shell_partial, cwd) =
        match child_shell(member, options, platform, current_cwd) {
            Ok(summary) => summary,
            Err(ChildShapeError::Invalid) => return ChildCallSummary::Invalid,
        };
    let callback = matches!(member, Member::Exec | Member::ExecFile)
        .then_some(shape.callback)
        .flatten()
        .filter(|index| !matches!(values[*index], Value::Null | Value::Undefined));
    partial |= shell_partial || !context_exact || callback.is_some();
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
        callback,
        partial,
    }
}

fn child_formal_count(member: Member) -> usize {
    match member {
        Member::Exec | Member::Spawn | Member::SpawnSync | Member::ExecFileSync => 3,
        Member::ExecSync => 2,
        Member::ExecFile => 4,
        _ => unreachable!(),
    }
}

fn child_shape(member: Member, values: &[Value]) -> Result<ChildShape, ChildShapeError> {
    if values.is_empty() {
        return Err(ChildShapeError::Invalid);
    }
    match member {
        Member::Exec => child_exec_shape(values),
        Member::ExecSync => Ok(ChildShape {
            options: values.get(1).map(|_| ChildOptions::ExecSpread(1)),
            ..ChildShape::default()
        }),
        Member::Spawn | Member::SpawnSync => child_spawn_shape(values),
        Member::ExecFile => child_exec_file_shape(values, true),
        Member::ExecFileSync => child_exec_file_shape(values, false),
        _ => unreachable!(),
    }
}

fn child_exec_shape(values: &[Value]) -> Result<ChildShape, ChildShapeError> {
    let Some(options) = values.get(1) else {
        return Ok(ChildShape::default());
    };
    if child_callback_shape(options) {
        return Ok(ChildShape {
            callback: Some(1),
            ..ChildShape::default()
        });
    }
    if unknown_value(options) {
        return Ok(ChildShape {
            options: Some(ChildOptions::ExecSpread(1)),
            partial: true,
            ..ChildShape::default()
        });
    }
    Ok(ChildShape {
        options: Some(ChildOptions::ExecSpread(1)),
        callback: values.get(2).map(|_| 2),
        ..ChildShape::default()
    })
}

fn child_spawn_shape(values: &[Value]) -> Result<ChildShape, ChildShapeError> {
    let Some(args) = values.get(1) else {
        return Ok(ChildShape::default());
    };
    match args {
        Value::Array(_) => Ok(ChildShape {
            args: Some(1),
            options: values.get(2).map(|_| ChildOptions::Strict(2)),
            ..ChildShape::default()
        }),
        Value::Null | Value::Undefined => Ok(ChildShape {
            options: values.get(2).map(|_| ChildOptions::Strict(2)),
            ..ChildShape::default()
        }),
        Value::Object(_) => Ok(ChildShape {
            options: Some(ChildOptions::Strict(1)),
            ..ChildShape::default()
        }),
        value if unknown_value(value) => Ok(ChildShape {
            options: Some(ChildOptions::Strict(1)),
            partial: true,
            ..ChildShape::default()
        }),
        _ => Err(ChildShapeError::Invalid),
    }
}

fn child_exec_file_shape(
    values: &[Value],
    asynchronous: bool,
) -> Result<ChildShape, ChildShapeError> {
    let Some(args) = values.get(1) else {
        return Ok(ChildShape::default());
    };
    match args {
        Value::Array(_) | Value::Null | Value::Undefined => {
            child_exec_file_array_shape(values, asynchronous)
        }
        Value::Object(_) => Ok(ChildShape {
            options: Some(ChildOptions::Nullable(1)),
            callback: values.get(2).map(|_| 2),
            ..ChildShape::default()
        }),
        value if child_callback_shape(value) => Ok(ChildShape {
            callback: Some(1),
            ..ChildShape::default()
        }),
        value if unknown_value(value) => Ok(ChildShape {
            options: Some(ChildOptions::Nullable(1)),
            partial: true,
            ..ChildShape::default()
        }),
        _ => Err(ChildShapeError::Invalid),
    }
}

fn child_exec_file_array_shape(
    values: &[Value],
    asynchronous: bool,
) -> Result<ChildShape, ChildShapeError> {
    let args = matches!(values.get(1), Some(Value::Array(_))).then_some(1);
    let Some(options) = values.get(2) else {
        return Ok(ChildShape {
            args,
            ..ChildShape::default()
        });
    };
    if asynchronous && child_callback_shape(options) {
        return Ok(ChildShape {
            args,
            callback: Some(2),
            ..ChildShape::default()
        });
    }
    if unknown_value(options) {
        return Ok(ChildShape {
            args,
            options: Some(ChildOptions::Nullable(2)),
            partial: true,
            ..ChildShape::default()
        });
    }
    Ok(ChildShape {
        args,
        options: Some(ChildOptions::Nullable(2)),
        callback: asynchronous.then(|| values.get(3).map(|_| 3)).flatten(),
        ..ChildShape::default()
    })
}

pub(super) fn child_callback_shape(value: &Value) -> bool {
    matches!(
        value,
        Value::Function(_)
            | Value::Known(_)
            | Value::Require
            | Value::Eval
            | Value::FunctionConstructor
            | Value::DynamicFunction(_)
            | Value::ObjectBuiltin
    )
}

fn child_command_status(member: Member, value: &Value) -> ChildValueStatus {
    match value {
        Value::String(value)
            if !value.contains('\0')
                && (!value.is_empty() || matches!(member, Member::Exec | Member::ExecSync)) =>
        {
            ChildValueStatus::Exact
        }
        value if unknown_value(value) => ChildValueStatus::Partial,
        _ => ChildValueStatus::Invalid,
    }
}

fn child_args_status(value: &Value) -> ChildValueStatus {
    match value {
        Value::Array(values) => {
            let mut status = ChildValueStatus::Exact;
            for value in values {
                match child_arg_status(value) {
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

fn child_arg_status(value: &Value) -> ChildValueStatus {
    match value {
        Value::String(value) if value.contains('\0') => ChildValueStatus::Invalid,
        Value::Undefined | Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {
            ChildValueStatus::Exact
        }
        value if unknown_value(value) => ChildValueStatus::Partial,
        _ => ChildValueStatus::Partial,
    }
}

fn child_options_status(options: ChildOptions, value: &Value) -> ChildValueStatus {
    match (options, value) {
        (_, Value::Object(properties)) if properties.values().any(accessor_value) => {
            ChildValueStatus::Partial
        }
        (ChildOptions::ExecSpread(_), _) if !unknown_value(value) => ChildValueStatus::Exact,
        (ChildOptions::Strict(_), Value::Object(_) | Value::Undefined)
        | (ChildOptions::Nullable(_), Value::Object(_) | Value::Null | Value::Undefined) => {
            ChildValueStatus::Exact
        }
        (_, value) if unknown_value(value) => ChildValueStatus::Partial,
        _ => ChildValueStatus::Invalid,
    }
}

fn child_callback_status(value: &Value) -> ChildValueStatus {
    if child_callback_shape(value) || matches!(value, Value::Null | Value::Undefined) {
        ChildValueStatus::Exact
    } else if unknown_value(value) {
        ChildValueStatus::Partial
    } else {
        ChildValueStatus::Invalid
    }
}

fn child_shell(
    member: Member,
    options: Option<(ChildOptions, &Value)>,
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
    let Some((options_kind, options)) = options else {
        return Ok((default, true, default_partial, current_cwd.clone()));
    };
    let properties = match options {
        Value::Null | Value::Undefined => {
            return Ok((default, true, default_partial, current_cwd.clone()));
        }
        Value::Object(properties) => properties,
        value if unknown_value(value) => {
            return Ok((ChildShell::Opaque, false, true, NestedExecutionCwd::Unknown));
        }
        _ if matches!(options_kind, ChildOptions::ExecSpread(_)) => {
            return Ok((default, true, default_partial, current_cwd.clone()));
        }
        _ => return Err(ChildShapeError::Invalid),
    };
    let accessor_partial = properties.values().any(accessor_value);
    let context_exact = properties
        .get("env")
        .is_none_or(|value| matches!(value, Value::Null | Value::Undefined));
    let cwd = match properties.get("cwd") {
        None | Some(Value::Null | Value::Undefined) => current_cwd.clone(),
        Some(Value::String(path)) if !path.is_empty() && !path.contains('\0') => {
            current_cwd.changed(path, platform)
        }
        Some(value) if unknown_value(value) || accessor_value(value) => NestedExecutionCwd::Unknown,
        Some(_) => return Err(ChildShapeError::Invalid),
    };
    let Some(shell) = properties.get("shell") else {
        return Ok((
            default,
            context_exact,
            default_partial || accessor_partial,
            cwd,
        ));
    };
    if unknown_value(shell) || accessor_value(shell) {
        return Ok((ChildShell::Opaque, false, true, cwd));
    }
    if always_shell {
        let shell = match shell {
            Value::String(shell)
                if platform != Platform::Windows
                    && matches!(shell.as_str(), "/bin/bash" | "bash") =>
            {
                ChildShell::Bash
            }
            Value::String(shell)
                if platform != Platform::Windows && matches!(shell.as_str(), "/bin/sh" | "sh") =>
            {
                ChildShell::Posix
            }
            Value::String(_) => ChildShell::Opaque,
            _ => default,
        };
        return Ok((
            shell,
            context_exact,
            matches!(shell, ChildShell::Opaque) || accessor_partial,
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
        _ => return Err(ChildShapeError::Invalid),
    };
    Ok((
        shell,
        context_exact,
        matches!(shell, ChildShell::Opaque) || accessor_partial,
        cwd,
    ))
}

fn child_opaque_shell_program(
    options: Option<(ChildOptions, &Value)>,
    platform: Platform,
) -> Option<String> {
    if let Some((_, Value::Object(properties))) = options
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
                argv.push(string_coercion(value)?);
            }
        }
        Some(_) => return None,
    }
    Some(argv)
}
