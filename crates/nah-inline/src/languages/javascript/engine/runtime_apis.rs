//! Deno, Bun, OpenClaw, and JavaScript runtime API semantics.

use super::*;

pub(super) fn deno_member(property: &str) -> Option<DenoMember> {
    match property {
        "chdir" => Some(DenoMember::Chdir),
        "remove" => Some(DenoMember::Remove),
        "removeSync" => Some(DenoMember::RemoveSync),
        "mkdir" => Some(DenoMember::Mkdir),
        "mkdirSync" => Some(DenoMember::MkdirSync),
        "readFile" => Some(DenoMember::ReadFile),
        "readFileSync" => Some(DenoMember::ReadFileSync),
        "readTextFile" => Some(DenoMember::ReadTextFile),
        "readTextFileSync" => Some(DenoMember::ReadTextFileSync),
        "writeFile" => Some(DenoMember::WriteFile),
        "writeFileSync" => Some(DenoMember::WriteFileSync),
        "writeTextFile" => Some(DenoMember::WriteTextFile),
        "writeTextFileSync" => Some(DenoMember::WriteTextFileSync),
        _ => None,
    }
}

pub(super) fn deno_command_member(property: &str) -> Option<DenoCommandMember> {
    match property {
        "spawn" => Some(DenoCommandMember::Spawn),
        "output" => Some(DenoCommandMember::Output),
        "outputSync" => Some(DenoCommandMember::OutputSync),
        _ => None,
    }
}

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

pub(super) fn openclaw_member(property: &str) -> Option<OpenClawMember> {
    match property {
        "call" => Some(OpenClawMember::Call),
        "callValue" => Some(OpenClawMember::CallValue),
        _ => None,
    }
}

pub(super) fn deno_callable(member: DenoMember) -> &'static str {
    match member {
        DenoMember::Chdir => "Deno.chdir",
        DenoMember::Remove => "Deno.remove",
        DenoMember::RemoveSync => "Deno.removeSync",
        DenoMember::Mkdir => "Deno.mkdir",
        DenoMember::MkdirSync => "Deno.mkdirSync",
        DenoMember::ReadFile => "Deno.readFile",
        DenoMember::ReadFileSync => "Deno.readFileSync",
        DenoMember::ReadTextFile => "Deno.readTextFile",
        DenoMember::ReadTextFileSync => "Deno.readTextFileSync",
        DenoMember::WriteFile => "Deno.writeFile",
        DenoMember::WriteFileSync => "Deno.writeFileSync",
        DenoMember::WriteTextFile => "Deno.writeTextFile",
        DenoMember::WriteTextFileSync => "Deno.writeTextFileSync",
    }
}

pub(super) fn deno_member_synchronous(member: DenoMember) -> bool {
    matches!(
        member,
        DenoMember::Chdir
            | DenoMember::RemoveSync
            | DenoMember::MkdirSync
            | DenoMember::ReadFileSync
            | DenoMember::ReadTextFileSync
            | DenoMember::WriteFileSync
            | DenoMember::WriteTextFileSync
    )
}

pub(super) fn deno_member_constructible(member: DenoMember) -> bool {
    member != DenoMember::Chdir
        && (deno_member_synchronous(member) || member == DenoMember::WriteTextFile)
}

pub(super) fn deno_command_callable(member: DenoCommandMember) -> &'static str {
    match member {
        DenoCommandMember::Spawn => "Deno.Command.spawn",
        DenoCommandMember::Output => "Deno.Command.output",
        DenoCommandMember::OutputSync => "Deno.Command.outputSync",
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

pub(super) fn attach_deno_command_source(
    summary: RuntimeCallSummary<DenoCommandValue>,
    arguments: &Arguments,
) -> RuntimeCallSummary<DenoCommandValue> {
    let source = DenoCommandSource {
        program: arguments
            .values
            .first()
            .cloned()
            .unwrap_or(Value::Undefined),
        options: arguments.values.get(1).cloned(),
    };
    match summary {
        RuntimeCallSummary::Effect(mut command) => {
            command.source = Some(Box::new(source));
            RuntimeCallSummary::Effect(command)
        }
        RuntimeCallSummary::EffectPartial(mut command) => {
            command.source = Some(Box::new(source));
            RuntimeCallSummary::EffectPartial(command)
        }
        RuntimeCallSummary::Partial => RuntimeCallSummary::Partial,
        RuntimeCallSummary::Invalid => RuntimeCallSummary::Invalid,
    }
}

pub(super) fn refresh_deno_command(
    command: DenoCommandValue,
    prototype_integrity_known: bool,
    platform: Platform,
) -> RuntimeCallSummary<DenoCommandValue> {
    let Some(source) = command.source.as_deref() else {
        return RuntimeCallSummary::Effect(command);
    };
    let mut values = vec![source.program.clone()];
    values.extend(source.options.clone());
    let arguments = Arguments {
        values,
        complete: true,
        assembly_branches: Vec::new(),
    };
    attach_deno_command_source(
        deno_command(&arguments, prototype_integrity_known, platform),
        &arguments,
    )
}

pub(super) fn partialize_deno_command(
    summary: RuntimeCallSummary<DenoCommandValue>,
) -> RuntimeCallSummary<DenoCommandValue> {
    match summary {
        RuntimeCallSummary::Effect(mut command)
        | RuntimeCallSummary::EffectPartial(mut command) => {
            command.argv = None;
            command.cwd = NestedExecutionCwd::Unknown;
            command.context_exact = false;
            command.spawn_stdout_inherited = false;
            command.output_stdout_inherited = false;
            RuntimeCallSummary::EffectPartial(command)
        }
        RuntimeCallSummary::Partial => RuntimeCallSummary::Partial,
        RuntimeCallSummary::Invalid => RuntimeCallSummary::Invalid,
    }
}

pub(super) fn deno_command(
    arguments: &Arguments,
    prototype_integrity_known: bool,
    platform: Platform,
) -> RuntimeCallSummary<DenoCommandValue> {
    if !arguments.complete {
        return RuntimeCallSummary::Partial;
    }
    let (mut argv, base) = match arguments.values.first() {
        Some(Value::String(program)) => (Some(vec![program.clone()]), ExecutionCertainty::Known),
        Some(value) if unknown_value(value) => (None, ExecutionCertainty::Unknown),
        Some(_) | None => (None, ExecutionCertainty::Invalid),
    };
    let Some(options) = arguments.values.get(1) else {
        return RuntimeCallSummary::Effect(DenoCommandValue {
            argv,
            cwd: NestedExecutionCwd::Inherited,
            spawn: base,
            output: base,
            context_exact: true,
            spawn_stdout_inherited: true,
            output_stdout_inherited: false,
            spawn_throws_after_effect: false,
            output_throws_after_effect: false,
            source: None,
        });
    };
    if matches!(options, Value::Undefined) {
        return RuntimeCallSummary::Effect(DenoCommandValue {
            argv,
            cwd: NestedExecutionCwd::Inherited,
            spawn: base,
            output: base,
            context_exact: true,
            spawn_stdout_inherited: true,
            output_stdout_inherited: false,
            spawn_throws_after_effect: false,
            output_throws_after_effect: false,
            source: None,
        });
    }
    if matches!(options, Value::Null) {
        return RuntimeCallSummary::Effect(DenoCommandValue {
            argv,
            cwd: NestedExecutionCwd::Inherited,
            spawn: base,
            output: ExecutionCertainty::Invalid,
            context_exact: true,
            spawn_stdout_inherited: true,
            output_stdout_inherited: false,
            spawn_throws_after_effect: false,
            output_throws_after_effect: false,
            source: None,
        });
    }
    if matches!(
        options,
        Value::Bool(_) | Value::Number(_) | Value::String(_) | Value::Array(_)
    ) {
        let command = DenoCommandValue {
            argv,
            cwd: NestedExecutionCwd::Inherited,
            spawn: base,
            output: base,
            context_exact: true,
            spawn_stdout_inherited: true,
            output_stdout_inherited: false,
            spawn_throws_after_effect: false,
            output_throws_after_effect: false,
            source: None,
        };
        return if prototype_integrity_known {
            RuntimeCallSummary::Effect(command)
        } else {
            partialize_deno_command(RuntimeCallSummary::Effect(command))
        };
    }
    if known_object_like(options) {
        return RuntimeCallSummary::EffectPartial(DenoCommandValue {
            argv: None,
            cwd: NestedExecutionCwd::Unknown,
            spawn: base,
            output: base,
            context_exact: false,
            spawn_stdout_inherited: false,
            output_stdout_inherited: false,
            spawn_throws_after_effect: false,
            output_throws_after_effect: false,
            source: None,
        });
    }
    let Value::Object(properties) = options else {
        return RuntimeCallSummary::Effect(DenoCommandValue {
            argv,
            cwd: NestedExecutionCwd::Unknown,
            spawn: merge_execution(base, ExecutionCertainty::Unknown),
            output: merge_execution(base, ExecutionCertainty::Unknown),
            context_exact: false,
            spawn_stdout_inherited: false,
            output_stdout_inherited: false,
            spawn_throws_after_effect: false,
            output_throws_after_effect: false,
            source: None,
        });
    };
    let mut args_certainty = ExecutionCertainty::Known;
    if let Some(args) = properties.get("args") {
        match args {
            Value::Undefined => {}
            Value::Array(values) => {
                if let Some(exact_argv) = &mut argv {
                    for value in values {
                        let Some(value) = string_coercion(value) else {
                            args_certainty = ExecutionCertainty::Unknown;
                            break;
                        };
                        exact_argv.push(value);
                    }
                }
                if args_certainty != ExecutionCertainty::Known {
                    argv = None;
                }
            }
            Value::String(value) if value.is_ascii() => {
                if let Some(exact_argv) = &mut argv {
                    exact_argv.extend(value.bytes().map(|byte| char::from(byte).to_string()));
                }
            }
            Value::Bool(_) | Value::Number(_) => {}
            Value::Object(values) if !values.contains_key("length") => {}
            Value::Null => {
                argv = None;
                args_certainty = ExecutionCertainty::Invalid;
            }
            _ => {
                argv = None;
                args_certainty = ExecutionCertainty::Unknown;
            }
        }
    }
    let cwd = match properties.get("cwd") {
        None | Some(Value::Undefined | Value::Null) => NestedExecutionCwd::Inherited,
        Some(Value::String(path)) if !path.is_empty() && !path.contains('\0') => {
            NestedExecutionCwd::Path(path.clone())
        }
        Some(_) => NestedExecutionCwd::Unknown,
    };
    let context_exact = cwd != NestedExecutionCwd::Unknown
        && properties.keys().all(|key| {
            matches!(key.as_str(), "args" | "cwd") || !deno_command_context_property(key, platform)
        });
    let mut spawn = merge_execution(base, args_certainty);
    let mut output = spawn;
    let mut spawn_stdout_inherited = true;
    let mut output_stdout_inherited = false;
    let mut spawn_throws_after_effect = false;
    let mut output_throws_after_effect = false;
    for (key, value) in properties {
        if matches!(key.as_str(), "stdin" | "stdout" | "stderr") {
            spawn = merge_execution(spawn, deno_spawn_stdio_certainty(value));
            output = merge_execution(output, deno_output_stdio_certainty(value));
        }
        if key == "stdout" {
            spawn_stdout_inherited = matches!(value, Value::Undefined | Value::Null)
                || matches!(value, Value::String(stdout) if stdout == "inherit")
                || matches!(value, Value::Number(1));
            output_stdout_inherited = matches!(value, Value::String(stdout) if stdout == "inherit")
                || matches!(value, Value::Number(1));
        }
        if let Some(certainty) = deno_context_certainty(key, value, platform) {
            spawn = merge_execution(spawn, certainty);
            output = merge_execution(output, certainty);
        }
        if key == "signal" {
            match value {
                Value::Undefined => {}
                Value::Null => output_throws_after_effect = true,
                value if unknown_value(value) || matches!(value, Value::Accessor) => {}
                _ => {
                    spawn_throws_after_effect = true;
                    output_throws_after_effect = true;
                }
            }
        }
    }
    for (key, value) in properties {
        if !accessor_value(value) {
            continue;
        }
        spawn = merge_execution(spawn, ExecutionCertainty::Unknown);
        if key != "args" && deno_command_option_property(key, platform) {
            output = merge_execution(output, ExecutionCertainty::Unknown);
        }
    }
    if matches!(properties.get("stdin"), Some(Value::String(stdin)) if stdin == "piped") {
        output = ExecutionCertainty::Invalid;
    }
    let command = DenoCommandValue {
        argv,
        cwd,
        spawn,
        output,
        context_exact,
        spawn_stdout_inherited,
        output_stdout_inherited,
        spawn_throws_after_effect,
        output_throws_after_effect,
        source: None,
    };
    if !prototype_integrity_known
        && deno_command_option_names()
            .iter()
            .filter(|property| deno_command_option_property(property, platform))
            .any(|property| !properties.contains_key(*property))
    {
        partialize_deno_command(RuntimeCallSummary::Effect(command))
    } else {
        RuntimeCallSummary::Effect(command)
    }
}

pub(super) fn known_object_like(value: &Value) -> bool {
    matches!(
        value,
        Value::Module(_)
            | Value::Known(_)
            | Value::Function(_)
            | Value::Require
            | Value::Eval
            | Value::FunctionConstructor
            | Value::DynamicFunction(_)
            | Value::ObjectBuiltin
            | Value::Process
            | Value::Environment
            | Value::Deno
            | Value::DenoCommandConstructor
            | Value::DenoCommand(_)
            | Value::Bun
            | Value::BunFile(_)
            | Value::OpenClawTools
            | Value::Promise
            | Value::RejectedPromise
    )
}

pub(super) fn merge_execution(
    left: ExecutionCertainty,
    right: ExecutionCertainty,
) -> ExecutionCertainty {
    match (left, right) {
        (ExecutionCertainty::Invalid, _) | (_, ExecutionCertainty::Invalid) => {
            ExecutionCertainty::Invalid
        }
        (ExecutionCertainty::Unknown, _) | (_, ExecutionCertainty::Unknown) => {
            ExecutionCertainty::Unknown
        }
        (ExecutionCertainty::Known, ExecutionCertainty::Known) => ExecutionCertainty::Known,
    }
}

pub(super) fn deno_command_context_property(property: &str, platform: Platform) -> bool {
    matches!(property, "cwd" | "clearEnv" | "env")
        || (property == "windowsRawArguments" && platform == Platform::Windows)
}

pub(super) fn deno_command_option_property(property: &str, platform: Platform) -> bool {
    deno_command_option_names().contains(&property)
        && !matches!(
            (property, platform),
            ("windowsRawArguments", Platform::Linux | Platform::Macos)
                | ("uid" | "gid", Platform::Windows)
        )
}

pub(super) fn deno_command_option_names() -> &'static [&'static str] {
    &[
        "args",
        "cwd",
        "clearEnv",
        "env",
        "uid",
        "gid",
        "signal",
        "stdin",
        "stdout",
        "stderr",
        "windowsRawArguments",
    ]
}

pub(super) fn deno_spawn_stdio_certainty(value: &Value) -> ExecutionCertainty {
    match value {
        Value::Undefined | Value::Null => ExecutionCertainty::Known,
        Value::String(value) if matches!(value.as_str(), "inherit" | "piped" | "null") => {
            ExecutionCertainty::Known
        }
        Value::Number(fd) if (0..=2).contains(fd) => ExecutionCertainty::Known,
        Value::Number(fd) if (3..=i64::from(i32::MAX)).contains(fd) => ExecutionCertainty::Unknown,
        value if unknown_value(value) || *value == Value::Accessor => ExecutionCertainty::Unknown,
        _ => ExecutionCertainty::Invalid,
    }
}

pub(super) fn deno_output_stdio_certainty(value: &Value) -> ExecutionCertainty {
    match value {
        Value::Undefined => ExecutionCertainty::Known,
        Value::String(value) if matches!(value.as_str(), "inherit" | "piped" | "null") => {
            ExecutionCertainty::Known
        }
        Value::Number(fd) if (0..=2).contains(fd) => ExecutionCertainty::Known,
        Value::Number(fd) if (3..=i64::from(i32::MAX)).contains(fd) => ExecutionCertainty::Unknown,
        value if unknown_value(value) || *value == Value::Accessor => ExecutionCertainty::Unknown,
        _ => ExecutionCertainty::Invalid,
    }
}

pub(super) fn deno_context_certainty(
    property: &str,
    value: &Value,
    platform: Platform,
) -> Option<ExecutionCertainty> {
    let certainty = match property {
        "clearEnv" => match value {
            Value::Undefined | Value::Bool(_) => ExecutionCertainty::Known,
            value if unknown_value(value) || *value == Value::Accessor => {
                ExecutionCertainty::Unknown
            }
            _ => ExecutionCertainty::Invalid,
        },
        "windowsRawArguments" if platform == Platform::Windows => match value {
            Value::Undefined | Value::Bool(_) => ExecutionCertainty::Known,
            value if unknown_value(value) || *value == Value::Accessor => {
                ExecutionCertainty::Unknown
            }
            _ => ExecutionCertainty::Invalid,
        },
        "windowsRawArguments" => return None,
        "uid" | "gid" if platform != Platform::Windows => match value {
            Value::Undefined | Value::Null => ExecutionCertainty::Known,
            Value::Number(value) if valid_u32(*value) => ExecutionCertainty::Known,
            value if unknown_value(value) || *value == Value::Accessor => {
                ExecutionCertainty::Unknown
            }
            _ => ExecutionCertainty::Invalid,
        },
        "uid" | "gid" => return None,
        "env" => deno_env_certainty(value),
        "cwd" => match value {
            Value::Undefined | Value::Null | Value::String(_) => ExecutionCertainty::Known,
            value if unknown_value(value) || *value == Value::Accessor => {
                ExecutionCertainty::Unknown
            }
            _ => ExecutionCertainty::Invalid,
        },
        _ => return None,
    };
    Some(certainty)
}

pub(super) fn deno_env_certainty(value: &Value) -> ExecutionCertainty {
    let values = match value {
        Value::Undefined | Value::Bool(_) | Value::Number(_) | Value::String(_) => {
            return ExecutionCertainty::Known;
        }
        Value::Null => return ExecutionCertainty::Invalid,
        Value::Object(properties) => properties.values().collect::<Vec<_>>(),
        Value::Array(values) => values.iter().collect(),
        value if unknown_value(value) || *value == Value::Accessor => {
            return ExecutionCertainty::Unknown;
        }
        _ => return ExecutionCertainty::Unknown,
    };
    if values.iter().all(|value| matches!(value, Value::String(_))) {
        ExecutionCertainty::Known
    } else if values
        .iter()
        .any(|value| unknown_value(value) || matches!(value, Value::Accessor))
    {
        ExecutionCertainty::Unknown
    } else {
        ExecutionCertainty::Invalid
    }
}

pub(super) fn summarize_deno_call(
    member: DenoMember,
    arguments: &Arguments,
    prototype_integrity_known: bool,
) -> FsCallSummary {
    if !arguments.complete {
        return FsCallSummary::Partial;
    }
    let values = &arguments.values;
    let Some(target) = values.first() else {
        return FsCallSummary::Invalid;
    };
    if !possible_path_argument(target) {
        return FsCallSummary::Invalid;
    }
    let path = || values.first().and_then(value_string).map(str::to_owned);
    // Deno's JavaScript wrappers ignore extra arguments. Only values read by
    // the wrapper can prevent the filesystem operation.
    match member {
        DenoMember::Chdir => FsCallSummary::Invalid,
        DenoMember::Remove | DenoMember::RemoveSync => {
            let recursive = match values.get(1).map_or(OptionValue::Exact(false), |value| {
                deno_remove_options(value, prototype_integrity_known)
            }) {
                OptionValue::Exact(recursive) => recursive,
                OptionValue::Partial => {
                    return FsCallSummary::EffectPartial(vec![LanguageFilesystem::new(
                        path(),
                        FilesystemOperation::Delete,
                        true,
                    )]);
                }
                OptionValue::Invalid => return FsCallSummary::Invalid,
            };
            FsCallSummary::Effect(vec![LanguageFilesystem::new(
                path(),
                FilesystemOperation::Delete,
                recursive,
            )])
        }
        DenoMember::Mkdir | DenoMember::MkdirSync => {
            let recursive = match values.get(1).map_or(OptionValue::Exact(false), |value| {
                deno_mkdir_options(value, prototype_integrity_known)
            }) {
                OptionValue::Exact(recursive) => recursive,
                OptionValue::Partial => {
                    return FsCallSummary::EffectPartial(vec![LanguageFilesystem::new(
                        path(),
                        FilesystemOperation::Write,
                        true,
                    )]);
                }
                OptionValue::Invalid => return FsCallSummary::Invalid,
            };
            FsCallSummary::Effect(vec![LanguageFilesystem::new(
                path(),
                FilesystemOperation::Write,
                recursive,
            )])
        }
        DenoMember::ReadFile | DenoMember::ReadTextFile => {
            let filesystems = vec![LanguageFilesystem::new(
                path(),
                FilesystemOperation::Read,
                false,
            )];
            match values.get(1).map_or(ShapeValue::Exact, |value| {
                deno_read_options(value, prototype_integrity_known)
            }) {
                ShapeValue::Exact => FsCallSummary::Effect(filesystems),
                ShapeValue::Partial => FsCallSummary::EffectPartial(filesystems),
                ShapeValue::Invalid => FsCallSummary::Invalid,
            }
        }
        DenoMember::ReadFileSync | DenoMember::ReadTextFileSync => {
            FsCallSummary::Effect(vec![LanguageFilesystem::new(
                path(),
                FilesystemOperation::Read,
                false,
            )])
        }
        DenoMember::WriteFile | DenoMember::WriteFileSync => {
            let Some(data) = values.get(1) else {
                return FsCallSummary::Invalid;
            };
            if matches!(data, Value::String(_)) {
                return FsCallSummary::Invalid;
            }
            if !unknown_value(data) {
                return FsCallSummary::Invalid;
            }
            let filesystems = vec![LanguageFilesystem::new(
                path(),
                FilesystemOperation::Write,
                false,
            )];
            let synchronous = member == DenoMember::WriteFileSync;
            match values.get(2).map_or(ShapeValue::Exact, |value| {
                deno_write_options(value, synchronous, prototype_integrity_known)
            }) {
                ShapeValue::Exact => FsCallSummary::EffectPartial(filesystems),
                ShapeValue::Partial => FsCallSummary::EffectPartial(filesystems),
                ShapeValue::Invalid => FsCallSummary::Invalid,
            }
        }
        DenoMember::WriteTextFile | DenoMember::WriteTextFileSync => {
            let data = values.get(1).unwrap_or(&Value::Undefined);
            let partial = string_coercion(data).is_none();
            let filesystems = vec![LanguageFilesystem::new(
                path(),
                FilesystemOperation::Write,
                false,
            )];
            let synchronous = member == DenoMember::WriteTextFileSync;
            match values.get(2).map_or(ShapeValue::Exact, |value| {
                deno_write_options(value, synchronous, prototype_integrity_known)
            }) {
                ShapeValue::Exact if !partial => FsCallSummary::Effect(filesystems),
                ShapeValue::Exact | ShapeValue::Partial => {
                    FsCallSummary::EffectPartial(filesystems)
                }
                ShapeValue::Invalid => FsCallSummary::Invalid,
            }
        }
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

pub(super) fn deno_remove_options(value: &Value, prototype_integrity_known: bool) -> OptionValue {
    match value {
        Value::Undefined => OptionValue::Exact(false),
        Value::Null => OptionValue::Invalid,
        Value::Object(properties) => match properties.get("recursive") {
            None if prototype_integrity_known => OptionValue::Exact(false),
            None => OptionValue::Partial,
            Some(value) if unknown_value(value) || matches!(value, Value::Accessor) => {
                OptionValue::Partial
            }
            // Deno.remove applies JavaScript truthiness before the native op.
            Some(value) => truthy(value)
                .map(OptionValue::Exact)
                .unwrap_or(OptionValue::Partial),
        },
        value if unknown_value(value) => OptionValue::Partial,
        _ if prototype_integrity_known => OptionValue::Exact(false),
        _ => OptionValue::Partial,
    }
}

pub(super) fn deno_mkdir_options(value: &Value, prototype_integrity_known: bool) -> OptionValue {
    let properties = match value {
        Value::Undefined | Value::Null => return OptionValue::Exact(false),
        Value::Object(properties) => properties,
        value if unknown_value(value) => return OptionValue::Partial,
        _ if prototype_integrity_known => return OptionValue::Exact(false),
        _ => return OptionValue::Partial,
    };
    match properties.get("mode") {
        None | Some(Value::Undefined | Value::Null) => {}
        Some(Value::Number(mode)) if valid_u32(*mode) => {}
        Some(value) if unknown_value(value) || matches!(value, Value::Accessor) => {
            return OptionValue::Partial;
        }
        Some(_) => return OptionValue::Invalid,
    }
    let recursive = match properties.get("recursive") {
        None | Some(Value::Undefined | Value::Null) => OptionValue::Exact(false),
        Some(Value::Bool(recursive)) => OptionValue::Exact(*recursive),
        Some(value) if unknown_value(value) || matches!(value, Value::Accessor) => {
            OptionValue::Partial
        }
        Some(_) => OptionValue::Invalid,
    };
    if !prototype_integrity_known
        && (!properties.contains_key("mode") || !properties.contains_key("recursive"))
    {
        OptionValue::Partial
    } else {
        recursive
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum ShapeValue {
    Exact,
    Partial,
    Invalid,
}

pub(super) fn deno_read_options(value: &Value, prototype_integrity_known: bool) -> ShapeValue {
    match value {
        Value::Object(properties) => match properties.get("signal") {
            None if !prototype_integrity_known => ShapeValue::Partial,
            None | Some(Value::Undefined | Value::Null) => ShapeValue::Exact,
            Some(value) if unknown_value(value) || matches!(value, Value::Accessor) => {
                ShapeValue::Partial
            }
            Some(signal) => match truthy(signal) {
                Some(false) => ShapeValue::Exact,
                Some(true) => ShapeValue::Invalid,
                None => ShapeValue::Partial,
            },
        },
        Value::Undefined | Value::Null => ShapeValue::Exact,
        Value::Bool(_) | Value::Number(_) | Value::String(_) if prototype_integrity_known => {
            ShapeValue::Exact
        }
        Value::Bool(_) | Value::Number(_) | Value::String(_) => ShapeValue::Partial,
        value if unknown_value(value) => ShapeValue::Partial,
        _ => ShapeValue::Partial,
    }
}

pub(super) fn deno_write_options(
    value: &Value,
    synchronous: bool,
    prototype_integrity_known: bool,
) -> ShapeValue {
    let properties = match value {
        Value::Undefined => {
            return ShapeValue::Exact;
        }
        Value::Bool(_) | Value::Number(_) | Value::String(_) if prototype_integrity_known => {
            return ShapeValue::Exact;
        }
        Value::Bool(_) | Value::Number(_) | Value::String(_) => return ShapeValue::Partial,
        Value::Null => return ShapeValue::Invalid,
        Value::Object(properties) => properties,
        value if unknown_value(value) => return ShapeValue::Partial,
        _ => return ShapeValue::Partial,
    };
    match properties.get("signal") {
        None | Some(Value::Undefined | Value::Null) => {}
        Some(value) if unknown_value(value) || matches!(value, Value::Accessor) => {
            return ShapeValue::Partial;
        }
        Some(_) if synchronous => return ShapeValue::Invalid,
        Some(signal) => match truthy(signal) {
            Some(false) => {}
            Some(true) => return ShapeValue::Invalid,
            None => return ShapeValue::Partial,
        },
    }
    match properties.get("mode") {
        None | Some(Value::Undefined | Value::Null) => {}
        Some(Value::Number(mode)) if valid_u32(*mode) => {}
        Some(value) if unknown_value(value) || matches!(value, Value::Accessor) => {
            return ShapeValue::Partial;
        }
        Some(_) => return ShapeValue::Invalid,
    }
    for property in ["append", "create", "createNew"] {
        match properties.get(property) {
            None | Some(Value::Undefined | Value::Null | Value::Bool(_)) => {}
            Some(value) if unknown_value(value) || matches!(value, Value::Accessor) => {
                return ShapeValue::Partial;
            }
            Some(_) => return ShapeValue::Invalid,
        }
    }
    if !prototype_integrity_known
        && ["signal", "mode", "append", "create", "createNew"]
            .iter()
            .any(|property| !properties.contains_key(*property))
    {
        ShapeValue::Partial
    } else {
        ShapeValue::Exact
    }
}

pub(super) fn valid_u32(value: i64) -> bool {
    (0..=i64::from(u32::MAX)).contains(&value)
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

pub(super) fn summarize_openclaw_call(arguments: &Arguments) -> RuntimeCallSummary<()> {
    if !arguments.complete {
        return RuntimeCallSummary::Partial;
    }
    let valid_target = match arguments.values.first() {
        Some(Value::String(target)) => !target.trim().is_empty(),
        Some(value) if unknown_value(value) => true,
        _ => false,
    };
    if !valid_target {
        return RuntimeCallSummary::Invalid;
    }
    RuntimeCallSummary::Partial
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
