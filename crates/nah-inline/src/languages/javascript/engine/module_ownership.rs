//! JavaScript module ownership, loaded-value invalidation, and property lookup.

use super::*;

pub(super) fn module_from_source(source: &str) -> Option<Module> {
    match source {
        "fs" | "node:fs" => Some(Module::Fs),
        "fs/promises" | "node:fs/promises" => Some(Module::FsPromises),
        "child_process" | "node:child_process" => Some(Module::ChildProcess),
        _ => None,
    }
}

pub(super) fn module_member(module: Module, property: &str) -> Option<Member> {
    match (module, property) {
        (Module::Fs | Module::FsPromises, "appendFile") => Some(Member::AppendFile),
        (Module::Fs, "appendFileSync") => Some(Member::AppendFileSync),
        (Module::Fs | Module::FsPromises, "chmod") => Some(Member::Chmod),
        (Module::Fs, "chmodSync") => Some(Member::ChmodSync),
        (Module::Fs | Module::FsPromises, "chown") => Some(Member::Chown),
        (Module::Fs, "chownSync") => Some(Member::ChownSync),
        (Module::Fs | Module::FsPromises, "copyFile") => Some(Member::CopyFile),
        (Module::Fs, "copyFileSync") => Some(Member::CopyFileSync),
        (Module::Fs, "createWriteStream") => Some(Member::CreateWriteStream),
        (Module::Fs | Module::FsPromises, "link") => Some(Member::Link),
        (Module::Fs, "linkSync") => Some(Member::LinkSync),
        (Module::Fs | Module::FsPromises, "mkdir") => Some(Member::Mkdir),
        (Module::Fs, "mkdirSync") => Some(Member::MkdirSync),
        (Module::Fs | Module::FsPromises, "open") => Some(Member::Open),
        (Module::Fs, "openSync") => Some(Member::OpenSync),
        (Module::Fs | Module::FsPromises, "rename") => Some(Member::Rename),
        (Module::Fs, "renameSync") => Some(Member::RenameSync),
        (Module::Fs | Module::FsPromises, "rmdir") => Some(Member::Rmdir),
        (Module::Fs, "rmdirSync") => Some(Member::RmdirSync),
        (Module::Fs | Module::FsPromises, "rm") => Some(Member::Rm),
        (Module::Fs, "rmSync") => Some(Member::RmSync),
        (Module::Fs | Module::FsPromises, "symlink") => Some(Member::Symlink),
        (Module::Fs, "symlinkSync") => Some(Member::SymlinkSync),
        (Module::Fs | Module::FsPromises, "truncate") => Some(Member::Truncate),
        (Module::Fs, "truncateSync") => Some(Member::TruncateSync),
        (Module::Fs | Module::FsPromises, "unlink") => Some(Member::Unlink),
        (Module::Fs, "unlinkSync") => Some(Member::UnlinkSync),
        (Module::Fs | Module::FsPromises, "writeFile") => Some(Member::WriteFile),
        (Module::Fs, "writeFileSync") => Some(Member::WriteFileSync),
        (Module::ChildProcess, "exec") => Some(Member::Exec),
        (Module::ChildProcess, "execSync") => Some(Member::ExecSync),
        (Module::ChildProcess, "spawn") => Some(Member::Spawn),
        (Module::ChildProcess, "spawnSync") => Some(Member::SpawnSync),
        (Module::ChildProcess, "execFile") => Some(Member::ExecFile),
        (Module::ChildProcess, "execFileSync") => Some(Member::ExecFileSync),
        _ => None,
    }
}

pub(super) fn augmented_coercion_proven(
    left: &Value,
    right: Option<&Value>,
    state: &State,
) -> bool {
    let primitive = |value: &Value| {
        matches!(
            value,
            Value::Undefined | Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_)
        )
    };
    let ordinary_object = |value: &Value| {
        matches!(value, Value::Object(properties)
            if state.prototype_integrity_known
                && !properties.contains_key("valueOf")
                && !properties.contains_key("toString"))
    };
    let right_proven = right.is_none_or(|right| primitive(right) || ordinary_object(right));
    (primitive(left) && right_proven)
        || (matches!(left, Value::NodeModuleMember(_))
            && state.prototype_integrity_known
            && right_proven)
}

pub(super) fn unknown_value(value: &Value) -> bool {
    matches!(
        value,
        Value::Unknown
            | Value::Accessor
            | Value::AccessorGetter(_)
            | Value::DynamicEvalResult
            | Value::UnknownModuleMember(_)
            | Value::UnknownReceiver(_)
    )
}

pub(super) fn runtime_global_value(value: &Value) -> bool {
    matches!(
        value,
        Value::Require
            | Value::Eval
            | Value::FunctionConstructor
            | Value::ObjectBuiltin
            | Value::Process
            | Value::Environment
            | Value::Deno
            | Value::DenoCommandConstructor
            | Value::Bun
            | Value::OpenClawTools
            | Value::Known(KnownFunction::BunShell)
    )
}

pub(super) fn contains_local_function(value: &Value) -> bool {
    match value {
        Value::Function(_) | Value::AccessorGetter(_) => true,
        Value::Array(values) => values.iter().any(contains_local_function),
        Value::Object(properties) => properties.values().any(contains_local_function),
        _ => false,
    }
}

pub(super) fn invalidate_loaded_module_value(value: &mut Value, module: Module) {
    match value {
        Value::LoadedModule(loaded) if *loaded == module => *value = Value::Unknown,
        Value::Array(values) => {
            for value in values {
                invalidate_loaded_module_value(value, module);
            }
        }
        Value::Object(properties) => {
            for value in properties.values_mut() {
                invalidate_loaded_module_value(value, module);
            }
        }
        Value::UnknownReceiver(value) => invalidate_loaded_module_value(value, module),
        _ => {}
    }
}

pub(super) fn exact_non_iterable(value: &Value) -> bool {
    matches!(
        value,
        Value::Undefined
            | Value::Null
            | Value::Bool(_)
            | Value::Number(_)
            | Value::Object(_)
            | Value::Module(_)
            | Value::Known(_)
            | Value::Function(_)
            | Value::Require
            | Value::Eval
            | Value::FunctionConstructor
            | Value::DynamicFunction(_)
            | Value::ObjectBuiltin
            | Value::Process
            | Value::Environment
            | Value::CommonJsModule
            | Value::LoadedModule(_)
            | Value::NodeModule
            | Value::NodeModulePrototype
            | Value::NodeModuleMember(_)
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

pub(super) fn exact_non_callable(value: &Value) -> bool {
    matches!(
        value,
        Value::Undefined
            | Value::Null
            | Value::Bool(_)
            | Value::Number(_)
            | Value::String(_)
            | Value::NonCallablePrimitive
            | Value::Array(_)
            | Value::Object(_)
            | Value::Module(_)
            | Value::Process
            | Value::Environment
            | Value::CommonJsModule
            | Value::LoadedModule(_)
            | Value::NodeModulePrototype
            | Value::Deno
            | Value::DenoCommand(_)
            | Value::Bun
            | Value::BunFile(_)
            | Value::OpenClawTools
    )
}

pub(super) fn property_value(value: &Value, property: &str, state: &State) -> Value {
    match value {
        Value::Object(properties) => properties
            .get(property)
            .cloned()
            .unwrap_or(Value::Undefined),
        Value::Module(module) => module_property_value(*module, property, state),
        Value::LoadedModule(module) => {
            if !state.loaded_modules_intact.contains(module) {
                Value::Unknown
            } else {
                module_member(*module, property).map_or(
                    Value::UnknownModuleMember(*module),
                    |member| match module {
                        Module::Fs | Module::FsPromises => {
                            Value::Known(KnownFunction::Fs(*module, member))
                        }
                        Module::ChildProcess => Value::Known(KnownFunction::Child(member)),
                    },
                )
            }
        }
        Value::NodeModule => node_module_property_value(property, state).unwrap_or(Value::Unknown),
        Value::NodeModulePrototype if property == "require" => {
            resolved_node_property(NodeProperty::PrototypeRequire, state)
        }
        Value::NodeModulePrototype if property == "constructor" => Value::NodeModule,
        Value::CommonJsModule => commonjs_module_property(property)
            .map(|property| resolved_node_property(property, state))
            .unwrap_or(Value::Unknown),
        Value::Deno if property == "Command" => Value::DenoCommandConstructor,
        Value::Deno => deno_member(property)
            .map(|member| Value::Known(KnownFunction::Deno(member)))
            .unwrap_or(Value::Unknown),
        Value::DenoCommand(command) => deno_command_member(property)
            .map(|member| Value::Known(KnownFunction::DenoCommand(member, command.clone())))
            .unwrap_or(Value::Unknown),
        Value::Bun => bun_member(property)
            .map(|member| Value::Known(KnownFunction::Bun(member)))
            .unwrap_or(Value::Unknown),
        Value::BunFile(path) => bun_file_member(property)
            .map(|member| Value::Known(KnownFunction::BunFile(member, path.clone())))
            .unwrap_or(Value::Unknown),
        Value::OpenClawTools => openclaw_member(property)
            .map(|member| Value::Known(KnownFunction::OpenClaw(member)))
            .unwrap_or(Value::Unknown),
        _ => Value::Unknown,
    }
}

pub(super) fn module_property_value(module: Module, property: &str, state: &State) -> Value {
    if module == Module::Fs && property == "promises" {
        return Value::Module(Module::FsPromises);
    }
    module_member(module, property).map_or(Value::Unknown, |member| {
        if state.owned_members.contains(&(module, member)) {
            match module {
                Module::Fs | Module::FsPromises => Value::Known(KnownFunction::Fs(module, member)),
                Module::ChildProcess => Value::Known(KnownFunction::Child(member)),
            }
        } else {
            Value::Unknown
        }
    })
}

pub(super) fn possible_path_argument(value: &Value) -> bool {
    matches!(value, Value::String(_)) || unknown_value(value)
}

pub(super) fn possible_file_argument(value: &Value) -> bool {
    possible_path_argument(value) || matches!(value, Value::Number(_))
}

pub(super) fn value_string(value: &Value) -> Option<&str> {
    match value {
        Value::String(value) => Some(value),
        _ => None,
    }
}
