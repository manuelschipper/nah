//! Python call shapes and argument-value admission.

use super::*;

pub(super) fn one_argument<'a>(arguments: &'a Arguments, keyword: &str) -> Option<&'a Value> {
    if !arguments.complete || arguments.positional.len() + arguments.keywords.len() != 1 {
        return None;
    }
    arguments.positional.first().or_else(|| {
        arguments
            .keywords
            .first()
            .filter(|(name, _)| name == keyword)
            .map(|(_, value)| value)
    })
}

pub(super) fn argument<'a>(
    arguments: &'a Arguments,
    position: usize,
    keyword: &str,
) -> Option<&'a Value> {
    if !arguments.complete
        || arguments
            .keywords
            .iter()
            .filter(|(name, _)| name == keyword)
            .count()
            > 1
    {
        return None;
    }
    arguments.positional.get(position).or_else(|| {
        arguments
            .keywords
            .iter()
            .find(|(name, _)| name == keyword)
            .map(|(_, value)| value)
    })
}

pub(super) fn dynamic_arguments(function: KnownFunction, arguments: &Arguments) -> Option<bool> {
    if !arguments.complete
        || arguments.positional.is_empty()
        || arguments.positional.len() > 3
        || !arguments.positional[1..]
            .iter()
            .all(|value| *value == Value::EmptyDictionary)
        || !(arguments.keywords.is_empty()
            || function == KnownFunction::Exec
                && arguments.keywords.as_slice() == [("closure".to_owned(), Value::None)])
    {
        return None;
    }
    Some(arguments.positional.len() > 1)
}

pub(super) fn code_mode(value: &str) -> Option<CodeMode> {
    match value {
        "eval" => Some(CodeMode::Eval),
        "exec" => Some(CodeMode::Exec),
        "single" => Some(CodeMode::Single),
        _ => None,
    }
}

pub(super) fn required_argument<'a>(
    arguments: &'a Arguments,
    position: usize,
    keyword: &str,
) -> Option<&'a Value> {
    if !arguments.complete {
        return None;
    }
    let positional = arguments.positional.get(position);
    let mut keywords = arguments
        .keywords
        .iter()
        .filter(|(name, _)| name == keyword);
    let keyword = keywords.next().map(|(_, value)| value);
    if keywords.next().is_some() || positional.is_some() == keyword.is_some() {
        None
    } else {
        positional.or(keyword)
    }
}

pub(super) fn call_shape(
    arguments: &Arguments,
    required: usize,
    positional: &[&str],
    positional_only: usize,
    keyword_only: &[&str],
) -> CallShape {
    if arguments.positional.len() > positional.len() {
        return CallShape::Invalid;
    }
    let mut seen = BTreeSet::new();
    for (name, _) in &arguments.keywords {
        if !seen.insert(name.as_str()) {
            return CallShape::Invalid;
        }
        if let Some(index) = positional.iter().position(|parameter| parameter == name) {
            if index < positional_only || index < arguments.positional.len() {
                return CallShape::Invalid;
            }
        } else if !keyword_only.contains(&name.as_str()) {
            return CallShape::Invalid;
        }
    }
    if !arguments.complete {
        return CallShape::Incomplete;
    }
    for (index, name) in positional.iter().take(required).enumerate() {
        if index >= arguments.positional.len()
            && (index < positional_only
                || !arguments
                    .keywords
                    .iter()
                    .any(|(keyword, _)| keyword == name))
        {
            return CallShape::Invalid;
        }
    }
    CallShape::Valid
}

pub(super) fn os_dir_fd_call_shape(
    arguments: &Arguments,
    program: &str,
    required: usize,
    positional: &[&str],
    keyword_only: &[&str],
) -> CallShape {
    if before_python3_minor(program, 3) {
        call_shape(arguments, required, positional, positional.len(), &[])
    } else {
        call_shape(arguments, required, positional, 0, keyword_only)
    }
}

pub(super) fn dir_fd_changes_base(arguments: &Arguments, keyword: &str) -> bool {
    arguments
        .keywords
        .iter()
        .find(|(name, _)| name == keyword)
        .is_some_and(|(_, value)| *value != Value::None)
}

pub(super) fn is_python2(program: &str) -> bool {
    matches!(program, "python2" | "pypy2")
        || program.starts_with("python2.")
        || program.starts_with("pypy2.")
}

pub(super) fn before_python3_minor(program: &str, minor: u16) -> bool {
    is_python2(program) || python3_minor(program).is_some_and(|version| version < minor)
}

pub(super) fn python3_minor(program: &str) -> Option<u16> {
    program
        .strip_prefix("python3.")
        .or_else(|| program.strip_prefix("pypy3."))
        .and_then(|version| version.strip_suffix('t').unwrap_or(version).parse().ok())
}

pub(super) fn valid_call_shape(
    arguments: &Arguments,
    max_positional: usize,
    keywords: &[&str],
) -> bool {
    matches!(
        call_shape(
            arguments,
            0,
            &keywords[..max_positional],
            0,
            &keywords[max_positional..],
        ),
        CallShape::Valid
    )
}

pub(super) fn possible_path_argument(
    arguments: &Arguments,
    position: usize,
    keyword: &str,
) -> bool {
    argument(arguments, position, keyword).is_some_and(possible_scalar_value)
}

pub(super) fn possible_scalar_argument(
    arguments: &Arguments,
    position: usize,
    keyword: &str,
) -> bool {
    argument(arguments, position, keyword).is_some_and(possible_scalar_value)
}

pub(super) fn possible_scalar_value(value: &Value) -> bool {
    matches!(
        value,
        Value::Unknown
            | Value::String(_)
            | Value::ImplicitString(_)
            | Value::Bytes(_)
            | Value::Path(_)
            | Value::Decoded(_)
            | Value::Produced(_)
    )
}

pub(super) fn text_admission(value: Option<&Value>) -> ValueAdmission {
    match value {
        Some(Value::String(_) | Value::ImplicitString(_)) => ValueAdmission::Exact,
        Some(Value::Unknown | Value::Produced(_) | Value::Decoded(_)) => ValueAdmission::Possible,
        Some(_) | None => ValueAdmission::Invalid,
    }
}

pub(super) fn path_admission(value: Option<&Value>) -> ValueAdmission {
    match value {
        Some(Value::String(_) | Value::ImplicitString(_) | Value::Bytes(_) | Value::Path(_)) => {
            ValueAdmission::Exact
        }
        Some(Value::Unknown | Value::Produced(_) | Value::Decoded(_)) => ValueAdmission::Possible,
        Some(_) | None => ValueAdmission::Invalid,
    }
}

pub(super) fn nonempty_path_admission(value: Option<&Value>) -> ValueAdmission {
    match value.and_then(empty_path_value) {
        Some(true) => ValueAdmission::Invalid,
        Some(false) | None => path_admission(value),
    }
}

pub(super) fn bytes_admission(value: Option<&Value>) -> ValueAdmission {
    match value {
        Some(Value::Bytes(_)) => ValueAdmission::Exact,
        Some(Value::Unknown | Value::Produced(_) | Value::Decoded(_)) => ValueAdmission::Possible,
        Some(_) | None => ValueAdmission::Invalid,
    }
}

pub(super) fn open_target_admission(value: Option<&Value>) -> ValueAdmission {
    match value {
        Some(
            Value::String(_)
            | Value::ImplicitString(_)
            | Value::Bytes(_)
            | Value::Path(_)
            | Value::Bool(_),
        ) => ValueAdmission::Exact,
        Some(Value::Int(value)) if *value >= 0 => ValueAdmission::Exact,
        Some(Value::Unknown | Value::Produced(_) | Value::Decoded(_)) => ValueAdmission::Possible,
        Some(_) | None => ValueAdmission::Invalid,
    }
}

pub(super) fn open_mode_admission(value: Option<&Value>, raw: bool) -> ValueAdmission {
    match value {
        None => ValueAdmission::Exact,
        Some(Value::String(value) | Value::ImplicitString(value)) => {
            if valid_open_mode(value, raw) {
                ValueAdmission::Exact
            } else {
                ValueAdmission::Invalid
            }
        }
        Some(Value::Decoded(value)) => open_mode_admission(Some(value), raw),
        Some(Value::Unknown | Value::Produced(_)) => ValueAdmission::Possible,
        Some(_) => ValueAdmission::Invalid,
    }
}

pub(super) fn popen_mode_admission(value: Option<&Value>) -> ValueAdmission {
    match value {
        None => ValueAdmission::Exact,
        Some(Value::String(value) | Value::ImplicitString(value))
            if value == "r" || value == "w" =>
        {
            ValueAdmission::Exact
        }
        Some(Value::Decoded(value)) => popen_mode_admission(Some(value)),
        Some(Value::Unknown | Value::Produced(_)) => ValueAdmission::Possible,
        Some(_) => ValueAdmission::Invalid,
    }
}

pub(super) fn popen_buffering_admission(value: Option<&Value>) -> ValueAdmission {
    match value {
        None | Some(Value::Bool(true)) => ValueAdmission::Exact,
        Some(Value::Int(value)) if *value != 0 => ValueAdmission::Exact,
        Some(Value::Unknown | Value::Produced(_)) => ValueAdmission::Possible,
        Some(_) => ValueAdmission::Invalid,
    }
}

pub(super) fn compile_source_admission(value: &Value) -> ValueAdmission {
    match value {
        Value::String(_) | Value::ImplicitString(_) => ValueAdmission::Exact,
        Value::Bytes(_) | Value::Unknown | Value::Produced(_) | Value::Decoded(_) => {
            ValueAdmission::Possible
        }
        _ => ValueAdmission::Invalid,
    }
}

pub(super) fn import_level_admission(value: Option<&Value>) -> ValueAdmission {
    match value {
        None | Some(Value::Bool(_)) => ValueAdmission::Exact,
        Some(Value::Int(value)) if *value >= 0 => ValueAdmission::Exact,
        Some(Value::Unknown | Value::Produced(_)) => ValueAdmission::Possible,
        Some(_) => ValueAdmission::Invalid,
    }
}

pub(super) fn combine_admission(left: ValueAdmission, right: ValueAdmission) -> ValueAdmission {
    match (left, right) {
        (ValueAdmission::Invalid, _) | (_, ValueAdmission::Invalid) => ValueAdmission::Invalid,
        (ValueAdmission::Possible, _) | (_, ValueAdmission::Possible) => ValueAdmission::Possible,
        (ValueAdmission::Exact, ValueAdmission::Exact) => ValueAdmission::Exact,
    }
}

pub(super) fn path_values_admission(values: &[Value]) -> ValueAdmission {
    values
        .iter()
        .fold(ValueAdmission::Exact, |admission, value| {
            combine_admission(admission, path_admission(Some(value)))
        })
}

pub(super) fn empty_path_value(value: &Value) -> Option<bool> {
    match value {
        Value::String(value) | Value::ImplicitString(value) | Value::Path(value) => {
            Some(value.is_empty())
        }
        Value::Bytes(value) => Some(value.is_empty()),
        _ => None,
    }
}
