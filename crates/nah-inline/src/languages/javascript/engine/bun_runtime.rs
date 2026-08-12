//! Bun process and filesystem API semantics.

use super::*;

pub(super) fn bun_member(property: &str) -> Option<BunMember> {
    match property {
        "spawn" => Some(BunMember::Spawn),
        "spawnSync" => Some(BunMember::SpawnSync),
        "file" => Some(BunMember::File),
        "write" => Some(BunMember::Write),
        _ => None,
    }
}

pub(super) fn bun_file_member(property: &str) -> Option<BunFileMember> {
    match property {
        "text" => Some(BunFileMember::Text),
        "json" => Some(BunFileMember::Json),
        "arrayBuffer" => Some(BunFileMember::ArrayBuffer),
        "bytes" => Some(BunFileMember::Bytes),
        "delete" => Some(BunFileMember::Delete),
        _ => None,
    }
}

pub(super) fn bun_callable(member: BunMember) -> &'static str {
    match member {
        BunMember::Spawn => "Bun.spawn",
        BunMember::SpawnSync => "Bun.spawnSync",
        BunMember::File => "Bun.file",
        BunMember::Write => "Bun.write",
    }
}

pub(super) fn bun_file_callable(member: BunFileMember) -> &'static str {
    match member {
        BunFileMember::Text => "Bun.file.text",
        BunFileMember::Json => "Bun.file.json",
        BunFileMember::ArrayBuffer => "Bun.file.arrayBuffer",
        BunFileMember::Bytes => "Bun.file.bytes",
        BunFileMember::Delete => "Bun.file.delete",
    }
}

pub(super) fn bun_spawn_argv(
    arguments: &Arguments,
    prototype_integrity_known: bool,
    current_cwd: &NestedExecutionCwd,
    platform: Platform,
) -> RuntimeCallSummary<BunSpawnSummary> {
    if !arguments.complete {
        return RuntimeCallSummary::Partial;
    }
    let Some(first) = arguments.values.first() else {
        return RuntimeCallSummary::Invalid;
    };
    let (command, options) = match first {
        Value::Array(command) => (command, arguments.values.get(1)),
        Value::Object(properties) => {
            let Some(command) = properties.get("cmd") else {
                return if prototype_integrity_known {
                    RuntimeCallSummary::Invalid
                } else {
                    RuntimeCallSummary::Partial
                };
            };
            match bun_spawn_options_certainty(properties) {
                ExecutionCertainty::Known => {}
                ExecutionCertainty::Unknown => return RuntimeCallSummary::Partial,
                ExecutionCertainty::Invalid => return RuntimeCallSummary::Invalid,
            }
            let string_command;
            let command = match command {
                Value::Array(command) => command,
                Value::String(command) => {
                    string_command = command
                        .chars()
                        .map(|value| Value::String(value.to_string()))
                        .collect::<Vec<_>>();
                    &string_command
                }
                command if unknown_value(command) || matches!(command, Value::Accessor) => {
                    return RuntimeCallSummary::Partial;
                }
                _ => return RuntimeCallSummary::Invalid,
            };
            let stdout_inherited = match properties
                .get("stdout")
                .map_or(BunStdout::Exact(false), bun_stdout)
            {
                BunStdout::Exact(inherited) => inherited,
                BunStdout::Partial => return bun_spawn_command_partial(command),
                BunStdout::Invalid => return RuntimeCallSummary::Invalid,
            };
            let context_exact = properties.keys().all(|key| {
                matches!(key.as_str(), "cmd" | "cwd") || !bun_spawn_context_property(key)
            });
            let cwd = bun_spawn_cwd(properties, current_cwd, platform);
            let context_exact = context_exact && cwd != NestedExecutionCwd::Unknown;
            if !prototype_integrity_known {
                return bun_spawn_command_partial(command);
            }
            return bun_spawn_command(command, cwd, context_exact, stdout_inherited);
        }
        value if unknown_value(value) => return RuntimeCallSummary::Partial,
        _ => return RuntimeCallSummary::Invalid,
    };
    let (cwd, context_exact, stdout_inherited) = match options {
        None | Some(Value::Undefined) => (current_cwd.clone(), true, false),
        Some(Value::Object(properties)) => {
            match bun_spawn_options_certainty(properties) {
                ExecutionCertainty::Known => {}
                ExecutionCertainty::Unknown => return bun_spawn_command_partial(command),
                ExecutionCertainty::Invalid => return RuntimeCallSummary::Invalid,
            }
            let stdout_inherited = match properties
                .get("stdout")
                .map_or(BunStdout::Exact(false), bun_stdout)
            {
                BunStdout::Exact(inherited) => inherited,
                BunStdout::Partial => return bun_spawn_command_partial(command),
                BunStdout::Invalid => return RuntimeCallSummary::Invalid,
            };
            let context_exact = properties
                .keys()
                .all(|key| key == "cwd" || !bun_spawn_context_property(key));
            let cwd = bun_spawn_cwd(properties, current_cwd, platform);
            let context_exact = context_exact && cwd != NestedExecutionCwd::Unknown;
            if !prototype_integrity_known {
                return bun_spawn_command_partial(command);
            }
            (cwd, context_exact, stdout_inherited)
        }
        Some(
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) | Value::Array(_),
        ) if prototype_integrity_known || matches!(options, Some(Value::Null)) => {
            (current_cwd.clone(), true, false)
        }
        Some(Value::Bool(_) | Value::Number(_) | Value::String(_) | Value::Array(_)) => {
            return bun_spawn_command_partial(command);
        }
        Some(_) => return bun_spawn_command_partial(command),
    };
    bun_spawn_command(command, cwd, context_exact, stdout_inherited)
}

pub(super) fn bun_spawn_command_partial(command: &[Value]) -> RuntimeCallSummary<BunSpawnSummary> {
    match bun_spawn_command(command, NestedExecutionCwd::Unknown, false, false) {
        RuntimeCallSummary::Effect(summary) => RuntimeCallSummary::EffectPartial(summary),
        RuntimeCallSummary::EffectPartial(summary) => RuntimeCallSummary::EffectPartial(summary),
        RuntimeCallSummary::Partial => RuntimeCallSummary::Partial,
        RuntimeCallSummary::Invalid => RuntimeCallSummary::Invalid,
    }
}

pub(super) fn bun_spawn_command(
    command: &[Value],
    cwd: NestedExecutionCwd,
    context_exact: bool,
    stdout_inherited: bool,
) -> RuntimeCallSummary<BunSpawnSummary> {
    if command.is_empty() {
        return RuntimeCallSummary::Invalid;
    }
    let mut argv = Vec::with_capacity(command.len());
    let mut exact = true;
    for value in command {
        if let Some(value) = string_coercion(value) {
            argv.push(value);
        } else {
            exact = false;
        }
    }
    let summary = BunSpawnSummary {
        argv: exact.then_some(argv),
        cwd,
        context_exact,
        stdout_inherited,
    };
    if exact {
        RuntimeCallSummary::Effect(summary)
    } else {
        RuntimeCallSummary::EffectPartial(summary)
    }
}

pub(super) fn bun_spawn_cwd(
    properties: &BTreeMap<String, Value>,
    current_cwd: &NestedExecutionCwd,
    platform: Platform,
) -> NestedExecutionCwd {
    match properties.get("cwd") {
        None | Some(Value::Undefined | Value::Null) => current_cwd.clone(),
        Some(Value::String(path)) if !path.is_empty() && !path.contains('\0') => {
            current_cwd.changed(path, platform)
        }
        Some(_) => NestedExecutionCwd::Unknown,
    }
}

pub(super) fn bun_spawn_context_property(property: &str) -> bool {
    matches!(
        property,
        "cwd"
            | "env"
            | "stdin"
            | "stderr"
            | "stdio"
            | "onExit"
            | "ipc"
            | "serialization"
            | "windowsHide"
            | "windowsVerbatimArguments"
            | "argv0"
            | "signal"
            | "timeout"
            | "killSignal"
            | "detached"
            | "lazy"
            | "terminal"
    )
}

pub(super) fn bun_spawn_options_certainty(
    properties: &BTreeMap<String, Value>,
) -> ExecutionCertainty {
    for (property, value) in properties {
        if accessor_value(value) && bun_spawn_context_property(property) {
            return ExecutionCertainty::Unknown;
        }
        let certainty = match property.as_str() {
            "env" => match value {
                Value::Undefined | Value::Null | Value::Object(_) | Value::Array(_) => {
                    ExecutionCertainty::Known
                }
                value if unknown_value(value) => ExecutionCertainty::Unknown,
                _ => ExecutionCertainty::Invalid,
            },
            "stdin" | "stderr" => match value {
                Value::Bool(_) => ExecutionCertainty::Invalid,
                value if unknown_value(value) => ExecutionCertainty::Unknown,
                _ => ExecutionCertainty::Known,
            },
            "timeout" => match value {
                Value::Undefined | Value::Null => ExecutionCertainty::Known,
                Value::Number(value) if *value >= 0 => ExecutionCertainty::Known,
                value if unknown_value(value) => ExecutionCertainty::Unknown,
                _ => ExecutionCertainty::Invalid,
            },
            "cwd" if matches!(value, Value::Bool(_)) => ExecutionCertainty::Unknown,
            _ => ExecutionCertainty::Known,
        };
        if certainty != ExecutionCertainty::Known {
            return certainty;
        }
    }
    ExecutionCertainty::Known
}

pub(super) enum BunStdout {
    Exact(bool),
    Partial,
    Invalid,
}

pub(super) fn bun_stdout(value: &Value) -> BunStdout {
    match value {
        Value::Undefined | Value::Null | Value::BunFile(_) => BunStdout::Exact(false),
        Value::String(value) if value == "inherit" => BunStdout::Exact(true),
        Value::String(value) if matches!(value.as_str(), "pipe" | "ignore") => {
            BunStdout::Exact(false)
        }
        Value::Number(1) => BunStdout::Exact(true),
        Value::Number(2) => BunStdout::Exact(false),
        Value::Number(fd) if (3..=i64::from(i32::MAX)).contains(fd) => BunStdout::Partial,
        value if unknown_value(value) || *value == Value::Accessor => BunStdout::Partial,
        _ => BunStdout::Invalid,
    }
}

pub(super) fn bun_file(
    arguments: &Arguments,
    prototype_integrity_known: bool,
) -> RuntimeCallSummary<Option<String>> {
    if !arguments.complete {
        return RuntimeCallSummary::Partial;
    }
    let Some(path) = arguments.values.first() else {
        return RuntimeCallSummary::Invalid;
    };
    let mut partial = false;
    match arguments.values.get(1) {
        None | Some(Value::Undefined | Value::Null) => {}
        Some(Value::Object(properties)) => match properties.get("type") {
            None if !prototype_integrity_known => partial = true,
            None
            | Some(
                Value::Undefined
                | Value::Null
                | Value::Bool(_)
                | Value::Number(_)
                | Value::String(_)
                | Value::Array(_)
                | Value::Object(_),
            ) => {}
            Some(value) if unknown_value(value) || matches!(value, Value::Accessor) => {
                partial = true;
            }
            Some(_) => {}
        },
        Some(value) if unknown_value(value) => partial = true,
        Some(Value::Bool(_) | Value::Number(_) | Value::String(_) | Value::Array(_))
            if !prototype_integrity_known =>
        {
            partial = true;
        }
        Some(_) if !prototype_integrity_known => partial = true,
        Some(_) => {}
    }
    let path = match path {
        Value::String(path) => Some(path.clone()),
        Value::Number(fd) if (0..=i32::MAX.into()).contains(fd) => None,
        value if unknown_value(value) => None,
        _ => return RuntimeCallSummary::Invalid,
    };
    if partial {
        RuntimeCallSummary::EffectPartial(path)
    } else {
        RuntimeCallSummary::Effect(path)
    }
}

pub(super) fn summarize_bun_write(
    arguments: &Arguments,
    prototype_integrity_known: bool,
) -> FsCallSummary {
    if !arguments.complete {
        return FsCallSummary::Partial;
    }
    let [destination, source, ..] = arguments.values.as_slice() else {
        return FsCallSummary::Invalid;
    };
    let destination = match destination {
        Value::String(path) => Some(path.clone()),
        Value::BunFile(path) => path.clone(),
        Value::Number(fd) if (0..=i64::from(i32::MAX)).contains(fd) => None,
        value if unknown_value(value) => None,
        _ => return FsCallSummary::Invalid,
    };
    let source_partial = match source {
        Value::String(_) | Value::Number(_) | Value::Bool(_) | Value::BunFile(_) => false,
        Value::Object(_) | Value::Array(_) => true,
        value if unknown_value(value) => true,
        value if known_object_like(value) => true,
        _ => return FsCallSummary::Invalid,
    };
    let mut filesystems = vec![LanguageFilesystem::new(
        destination,
        FilesystemOperation::Write,
        false,
    )];
    if let Value::BunFile(source) = source {
        filesystems.push(LanguageFilesystem::new(
            source.clone(),
            FilesystemOperation::Read,
            false,
        ));
    }
    let options = arguments.values.get(2).map_or(ShapeValue::Exact, |value| {
        bun_write_options(value, prototype_integrity_known)
    });
    if options == ShapeValue::Invalid {
        return FsCallSummary::Invalid;
    }
    if source_partial || options == ShapeValue::Partial {
        FsCallSummary::EffectPartial(filesystems)
    } else {
        FsCallSummary::Effect(filesystems)
    }
}

pub(super) fn bun_write_options(value: &Value, prototype_integrity_known: bool) -> ShapeValue {
    let properties = match value {
        Value::Undefined | Value::Null => return ShapeValue::Exact,
        Value::Array(_) if prototype_integrity_known => return ShapeValue::Exact,
        Value::Array(_) => return ShapeValue::Partial,
        Value::Object(properties) => properties,
        value if unknown_value(value) => return ShapeValue::Partial,
        value if known_object_like(value) => return ShapeValue::Partial,
        _ => return ShapeValue::Invalid,
    };
    match properties.get("mode") {
        None | Some(Value::Undefined | Value::Null) => {}
        Some(Value::Number(mode)) if (0..=0o777).contains(mode) => {}
        Some(value) if unknown_value(value) || matches!(value, Value::Accessor) => {
            return ShapeValue::Partial;
        }
        Some(_) => return ShapeValue::Invalid,
    }
    match properties.get("createPath") {
        None | Some(Value::Undefined | Value::Null | Value::Bool(_)) => {}
        Some(value) if unknown_value(value) || matches!(value, Value::Accessor) => {
            return ShapeValue::Partial;
        }
        Some(_) => return ShapeValue::Invalid,
    }
    if !prototype_integrity_known
        && (!properties.contains_key("mode") || !properties.contains_key("createPath"))
    {
        ShapeValue::Partial
    } else {
        ShapeValue::Exact
    }
}
