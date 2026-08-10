//! Python os.exec and subprocess call-shape and execution semantics.

use super::*;

pub(super) fn os_exec_callable(kind: StringKind) -> &'static str {
    match kind {
        StringKind::Execl => "os.execl",
        StringKind::Execlp => "os.execlp",
        StringKind::Execle => "os.execle",
        StringKind::Execv => "os.execv",
        StringKind::Execvp => "os.execvp",
        StringKind::Execvpe => "os.execvpe",
    }
}

pub(super) fn subprocess_callable(kind: SubprocessKind) -> &'static str {
    match kind {
        SubprocessKind::Run => "subprocess.run",
        SubprocessKind::Call => "subprocess.call",
        SubprocessKind::Popen => "subprocess.popen",
        SubprocessKind::CheckCall => "subprocess.check_call",
        SubprocessKind::CheckOutput => "subprocess.check_output",
    }
}

pub(super) fn os_exec_call_shape(kind: StringKind, arguments: &Arguments) -> CallShape {
    if !arguments.complete {
        return CallShape::Incomplete;
    }
    let valid = arguments.keywords.is_empty()
        && match kind {
            StringKind::Execl | StringKind::Execlp => arguments.positional.len() >= 2,
            StringKind::Execle => arguments.positional.len() >= 3,
            StringKind::Execv | StringKind::Execvp => arguments.positional.len() == 2,
            StringKind::Execvpe => arguments.positional.len() == 3,
        };
    if valid {
        CallShape::Valid
    } else {
        CallShape::Invalid
    }
}

pub(super) fn exec_vector_admission(value: &Value, state: &State) -> ValueAdmission {
    match value {
        Value::Cell(cell) => match state.cells.get(*cell) {
            Some(Cell::Sequence {
                values,
                indexable: true,
            }) if values.is_empty() || empty_path_value(&values[0]) == Some(true) => {
                ValueAdmission::Invalid
            }
            Some(Cell::Sequence {
                values,
                indexable: true,
            }) => path_values_admission(values),
            Some(Cell::Sequence {
                indexable: false, ..
            }) => ValueAdmission::Invalid,
            Some(Cell::Unknown) | None => ValueAdmission::Possible,
        },
        Value::Unknown | Value::Produced(_) => ValueAdmission::Possible,
        _ => ValueAdmission::Invalid,
    }
}

pub(super) fn exec_environment_admission(value: &Value, state: &State) -> ValueAdmission {
    match value {
        Value::EmptyDictionary => ValueAdmission::Exact,
        Value::Module(Module::Environment)
            if !state.invalid_modules.contains(&Module::Environment) =>
        {
            ValueAdmission::Exact
        }
        Value::Unknown | Value::Produced(_) => ValueAdmission::Possible,
        _ => ValueAdmission::Invalid,
    }
}

pub(super) fn exec_varargs_admission(values: &[Value]) -> ValueAdmission {
    if values.is_empty() || empty_path_value(&values[0]) == Some(true) {
        ValueAdmission::Invalid
    } else {
        path_values_admission(values)
    }
}

pub(super) fn os_exec_admission(
    kind: StringKind,
    arguments: &Arguments,
    state: &State,
) -> ValueAdmission {
    let path = nonempty_path_admission(arguments.positional.first());
    let arguments = match kind {
        StringKind::Execl | StringKind::Execlp => {
            exec_varargs_admission(&arguments.positional[1..])
        }
        StringKind::Execle => combine_admission(
            exec_varargs_admission(&arguments.positional[1..arguments.positional.len() - 1]),
            exec_environment_admission(
                arguments
                    .positional
                    .last()
                    .expect("execle shape requires an environment"),
                state,
            ),
        ),
        StringKind::Execv | StringKind::Execvp => {
            exec_vector_admission(&arguments.positional[1], state)
        }
        StringKind::Execvpe => combine_admission(
            exec_vector_admission(&arguments.positional[1], state),
            exec_environment_admission(&arguments.positional[2], state),
        ),
    };
    combine_admission(path, arguments)
}

pub(super) fn subprocess_command_admission(
    value: &Value,
    state: &State,
    shell: Option<bool>,
) -> ValueAdmission {
    match value {
        Value::Cell(cell) => match state.cells.get(*cell) {
            Some(Cell::Sequence { values, .. }) if values.is_empty() => match shell {
                Some(false) => ValueAdmission::Invalid,
                Some(true) => ValueAdmission::Exact,
                None => ValueAdmission::Possible,
            },
            Some(Cell::Sequence { values, .. }) if empty_path_value(&values[0]) == Some(true) => {
                match shell {
                    Some(false) => ValueAdmission::Invalid,
                    Some(true) => ValueAdmission::Exact,
                    None => ValueAdmission::Possible,
                }
            }
            Some(Cell::Sequence { values, .. }) => path_values_admission(values),
            Some(Cell::Unknown) | None => ValueAdmission::Possible,
        },
        value if empty_path_value(value) == Some(true) => match shell {
            Some(false) => ValueAdmission::Invalid,
            Some(true) => ValueAdmission::Exact,
            None => ValueAdmission::Possible,
        },
        value => path_admission(Some(value)),
    }
}

pub(super) fn subprocess_options(
    kind: SubprocessKind,
    arguments: &Arguments,
    state: &State,
    platform: Platform,
) -> Option<(bool, bool, NestedExecutionCwd)> {
    if !arguments.complete || arguments.positional.len() > 1 {
        return None;
    }
    if kind == SubprocessKind::CheckOutput
        && arguments.keywords.iter().any(|(name, _)| name == "stdout")
    {
        return None;
    }
    let mut shell = false;
    let mut cwd = state.cwd.clone();
    let mut capture_output = false;
    let mut input = false;
    let mut stdin = None;
    let mut stdout_option = None;
    let mut stderr = None;
    let mut text = None;
    let mut universal_newlines = None;
    let mut seen = BTreeSet::new();
    for (name, value) in &arguments.keywords {
        if name == "args" {
            continue;
        }
        if !seen.insert(name) {
            return None;
        }
        match name.as_str() {
            "bufsize" => {}
            "shell" => shell = exact_bool(value)?,
            "cwd" => match value {
                Value::None => {}
                value => {
                    let path = value_string(value)?;
                    if path.is_empty() || path.contains('\0') {
                        return None;
                    }
                    cwd = cwd.changed(path, platform);
                }
            },
            "capture_output" if kind == SubprocessKind::Run => {
                capture_output = exact_bool(value)?;
            }
            "check" if kind == SubprocessKind::Run => {}
            "timeout" if kind != SubprocessKind::Popen => {}
            "input" if matches!(kind, SubprocessKind::Run | SubprocessKind::CheckOutput) => {
                input = !matches!(value, Value::None);
            }
            "text" => text = Some(exact_bool(value)?),
            "universal_newlines" => universal_newlines = Some(exact_bool(value)?),
            "encoding" | "errors" if matches!(value, Value::None | Value::String(_)) => {}
            "stdin" => stdin = Some(subprocess_stdio(value, false)?),
            "stdout" => {
                let fd = subprocess_stdio(value, false)?;
                stdout_option = Some(fd);
            }
            "stderr" => stderr = Some(subprocess_stdio(value, true)?),
            _ => return None,
        }
    }
    if capture_output && (stdout_option.flatten().is_some() || stderr.flatten().is_some())
        || input && stdin.flatten().is_some()
        || matches!((text, universal_newlines), (Some(left), Some(right)) if left != right)
    {
        return None;
    }
    let stdout_inherited = if capture_output {
        false
    } else {
        match stdout_option {
            Some(Some(fd)) => fd == 1,
            Some(None) => true,
            None => kind != SubprocessKind::CheckOutput,
        }
    };
    Some((shell, stdout_inherited, cwd))
}

pub(super) fn subprocess_stdio(value: &Value, allow_stdout_redirect: bool) -> Option<Option<i64>> {
    match value {
        Value::None => Some(None),
        Value::Bool(value) => Some(Some(i64::from(*value))),
        Value::Int(fd)
            if *fd >= 0 || *fd == -1 || *fd == -3 || allow_stdout_redirect && *fd == -2 =>
        {
            Some(Some(*fd))
        }
        _ => None,
    }
}

pub(super) fn subprocess_bufsize_admission(value: Option<&Value>) -> ValueAdmission {
    match value {
        None | Some(Value::None | Value::Int(_) | Value::Bool(_)) => ValueAdmission::Exact,
        Some(Value::Unknown | Value::Produced(_)) => ValueAdmission::Possible,
        Some(_) => ValueAdmission::Invalid,
    }
}

pub(super) fn invalid_subprocess_options(kind: SubprocessKind, arguments: &Arguments) -> bool {
    arguments.keywords.iter().any(|(name, value)| {
        matches!(
            (kind, name.as_str()),
            (SubprocessKind::CheckOutput, "stdout")
                | (SubprocessKind::Popen, "timeout")
                | (
                    SubprocessKind::Call | SubprocessKind::Popen | SubprocessKind::CheckCall,
                    "input"
                )
                | (
                    SubprocessKind::Call
                        | SubprocessKind::Popen
                        | SubprocessKind::CheckCall
                        | SubprocessKind::CheckOutput,
                    "capture_output" | "check"
                )
        ) || name == "cwd"
            && value_string(value).is_some_and(|path| path.is_empty() || path.contains('\0'))
            || matches!(name.as_str(), "stdin" | "stdout") && matches!(value, Value::Int(-2))
    })
}

pub(super) fn subprocess_shell(arguments: &Arguments) -> Option<bool> {
    if !arguments.complete
        || arguments
            .keywords
            .iter()
            .filter(|(name, _)| name == "shell")
            .count()
            > 1
    {
        return None;
    }
    arguments
        .keywords
        .iter()
        .find(|(name, _)| name == "shell")
        .map_or(Some(false), |(_, value)| exact_bool(value))
}

pub(super) fn valid_subprocess_shape(arguments: &Arguments) -> bool {
    const KEYWORDS: &[&str] = &[
        "args",
        "bufsize",
        "executable",
        "stdin",
        "stdout",
        "stderr",
        "preexec_fn",
        "close_fds",
        "shell",
        "cwd",
        "env",
        "universal_newlines",
        "startupinfo",
        "creationflags",
        "restore_signals",
        "start_new_session",
        "pass_fds",
        "user",
        "group",
        "extra_groups",
        "encoding",
        "errors",
        "text",
        "umask",
        "pipesize",
        "process_group",
        "input",
        "capture_output",
        "timeout",
        "check",
    ];
    valid_call_shape(arguments, 1, KEYWORDS)
}

pub(super) fn exact_bool(value: &Value) -> Option<bool> {
    match value {
        Value::Bool(value) => Some(*value),
        Value::Int(0) | Value::None => Some(false),
        Value::Int(1) => Some(true),
        _ => None,
    }
}

pub(super) fn exact_index(value: &Value) -> Option<i64> {
    match value {
        Value::Int(value) => Some(*value),
        Value::Bool(value) => Some(i64::from(*value)),
        _ => None,
    }
}

pub(super) fn argv_value(value: &Value, state: &State, budget: &mut Budget) -> Option<Vec<String>> {
    bounded_argv_values(sequence_values(value, state)?, budget)
}

pub(super) fn bounded_argv_values(values: &[Value], budget: &mut Budget) -> Option<Vec<String>> {
    bounded_strings(
        values.iter().map(|value| match value {
            Value::String(value) | Value::Path(value) => Some(value.as_str()),
            _ => None,
        }),
        budget,
    )
}

pub(super) fn bounded_strings<'a>(
    values: impl IntoIterator<Item = Option<&'a str>>,
    budget: &mut Budget,
) -> Option<Vec<String>> {
    let mut output = Vec::new();
    let mut bytes = 0usize;
    for value in values {
        let value = value?;
        if output.len() >= MAX_COLLECTION_ITEMS {
            budget.refuse_work();
            return None;
        }
        let next_bytes = bytes.checked_add(value.len());
        if !budget.admit_value_bytes(next_bytes) {
            return None;
        }
        bytes = next_bytes.expect("the byte total was admitted");
        output.push(value.to_owned());
    }
    Some(output)
}
