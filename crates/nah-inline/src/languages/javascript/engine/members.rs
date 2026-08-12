//! Resolves JavaScript member reads against owned modules and abstract values.

use super::*;

impl Interpreter<'_> {
    pub(super) fn member(&mut self, node: &HirNode, state: &mut State, call_depth: usize) -> Value {
        let member = match self.member_reference(node, state, call_depth) {
            Ok(member) => member,
            Err(value) => return value,
        };
        self.read_member(&member, state)
    }

    pub(super) fn read_member(&mut self, member: &MemberReference, state: &State) -> Value {
        let Some(property) = member.property.as_deref() else {
            return Value::Unknown;
        };
        let object = member.object.clone();
        match object {
            Value::Invalid | Value::SynchronousThrow | Value::Divergent => object,
            Value::NonCallablePrimitive => {
                Value::UnknownReceiver(Box::new(Value::NonCallablePrimitive))
            }
            Value::Undefined | Value::Null => Value::SynchronousThrow,
            Value::DynamicEvalResult => Value::DynamicEvalResult,
            Value::Module(Module::Fs) if property == "promises" => {
                Value::Module(Module::FsPromises)
            }
            Value::NodeModule => {
                node_module_property_value(property, state).unwrap_or(Value::Unknown)
            }
            Value::NodeModuleMember(member) => {
                Value::UnknownReceiver(Box::new(Value::NodeModuleMember(member)))
            }
            Value::NodeModulePrototype if property == "require" => {
                resolved_node_property(NodeProperty::PrototypeRequire, state)
            }
            Value::NodeModulePrototype if property == "constructor" => Value::NodeModule,
            Value::NodeModulePrototype => {
                Value::UnknownReceiver(Box::new(Value::NodeModulePrototype))
            }
            Value::CommonJsModule if matches!(property, "constructor" | "require") => {
                commonjs_module_property(property)
                    .map(|property| resolved_node_property(property, state))
                    .unwrap_or(Value::Unknown)
            }
            Value::CommonJsModule => Value::UnknownReceiver(Box::new(Value::CommonJsModule)),
            Value::Module(module) => module_member(module, property).map_or(
                Value::UnknownModuleMember(module),
                |member| {
                    if state.owned_members.contains(&(module, member)) {
                        match module {
                            Module::Fs | Module::FsPromises => {
                                Value::Known(KnownFunction::Fs(module, member))
                            }
                            Module::ChildProcess => Value::Known(KnownFunction::Child(member)),
                        }
                    } else {
                        Value::Unknown
                    }
                },
            ),
            Value::LoadedModule(module) => {
                if !state.loaded_modules_intact.contains(&module) {
                    Value::Unknown
                } else {
                    module_member(module, property).map_or(
                        Value::UnknownModuleMember(module),
                        |member| match module {
                            Module::Fs | Module::FsPromises => {
                                Value::Known(KnownFunction::Fs(module, member))
                            }
                            Module::ChildProcess => Value::Known(KnownFunction::Child(member)),
                        },
                    )
                }
            }
            Value::Object(properties) => {
                let value = properties.get(property).cloned();
                match value {
                    Some(value) if accessor_value(&value) => {
                        self.complete = false;
                        Value::UnknownReceiver(Box::new(Value::Object(properties)))
                    }
                    Some(Value::Known(function)) if direct_receiver_required(&function) => {
                        Value::UnknownReceiver(Box::new(Value::Object(properties)))
                    }
                    Some(value) if value != Value::Unknown => value,
                    _ => Value::UnknownReceiver(Box::new(Value::Object(properties))),
                }
            }
            Value::Array(values) => property
                .parse::<usize>()
                .ok()
                .filter(|index| index.to_string() == property)
                .and_then(|index| values.get(index))
                .cloned()
                .unwrap_or_else(|| Value::UnknownReceiver(Box::new(Value::Array(values)))),
            Value::ObjectBuiltin if property == "defineProperty" => {
                Value::Known(KnownFunction::DefineProperty)
            }
            Value::ObjectBuiltin if property == "setPrototypeOf" => {
                Value::Known(KnownFunction::SetPrototypeOf)
            }
            Value::Process if property == "env" => Value::Environment,
            Value::Process if property == "chdir" => Value::Known(KnownFunction::ProcessChdir),
            Value::Environment if property == "HOME" => Value::String(self.home.to_owned()),
            Value::Deno if property == "Command" => Value::DenoCommandConstructor,
            Value::Deno => deno_member(property)
                .map_or(Value::UnknownReceiver(Box::new(Value::Deno)), |member| {
                    Value::Known(KnownFunction::Deno(member))
                }),
            Value::DenoCommand(command) => deno_command_member(property).map_or(
                Value::UnknownReceiver(Box::new(Value::DenoCommand(command.clone()))),
                |member| Value::Known(KnownFunction::DenoCommand(member, command)),
            ),
            Value::Bun => bun_member(property)
                .map_or(Value::UnknownReceiver(Box::new(Value::Bun)), |member| {
                    Value::Known(KnownFunction::Bun(member))
                }),
            Value::BunFile(path) => bun_file_member(property).map_or(
                Value::UnknownReceiver(Box::new(Value::BunFile(path.clone()))),
                |member| Value::Known(KnownFunction::BunFile(member, path)),
            ),
            Value::OpenClawTools => openclaw_member(property).map_or(
                Value::UnknownReceiver(Box::new(Value::OpenClawTools)),
                |member| Value::Known(KnownFunction::OpenClaw(member)),
            ),
            _ => Value::Unknown,
        }
    }
}
