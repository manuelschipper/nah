//! JavaScript bindings, scopes, containers, and runtime ownership invalidation.

use super::*;

impl State {
    pub(super) fn new(ownership: RuntimeOwnership) -> Self {
        let mut bindings = [
            ("eval", Value::Eval),
            ("Function", Value::FunctionConstructor),
            ("Object", Value::ObjectBuiltin),
        ]
        .into_iter()
        .map(|(name, value)| (name.to_owned(), value))
        .collect::<BTreeMap<_, _>>();
        let mut owned_members = BTreeSet::new();
        let mut loaded_modules_intact = BTreeSet::new();
        match ownership {
            RuntimeOwnership::DenoEval => {
                bindings.insert("Deno".into(), Value::Deno);
            }
            RuntimeOwnership::Bun => {
                bindings.insert("Bun".into(), Value::Bun);
                bindings.insert("$".into(), Value::Known(KnownFunction::BunShell));
                bindings.insert("require".into(), Value::Require);
                bindings.insert("module".into(), commonjs_module_value());
                bindings.insert("process".into(), Value::Process);
            }
            RuntimeOwnership::OpenClaw => {
                bindings.insert("tools".into(), Value::OpenClawTools);
            }
            RuntimeOwnership::Node => {
                bindings.insert("require".into(), Value::Require);
                bindings.insert("module".into(), commonjs_module_value());
                bindings.insert("process".into(), Value::Process);
            }
            RuntimeOwnership::DenoCheckedEval | RuntimeOwnership::Unowned => {}
        }
        if matches!(ownership, RuntimeOwnership::Node | RuntimeOwnership::Bun) {
            loaded_modules_intact.extend([Module::Fs, Module::FsPromises, Module::ChildProcess]);
            owned_members.extend([
                (Module::Fs, Member::AppendFile),
                (Module::Fs, Member::AppendFileSync),
                (Module::Fs, Member::Chmod),
                (Module::Fs, Member::ChmodSync),
                (Module::Fs, Member::Chown),
                (Module::Fs, Member::ChownSync),
                (Module::Fs, Member::CopyFile),
                (Module::Fs, Member::CopyFileSync),
                (Module::Fs, Member::CreateWriteStream),
                (Module::Fs, Member::Link),
                (Module::Fs, Member::LinkSync),
                (Module::Fs, Member::Mkdir),
                (Module::Fs, Member::MkdirSync),
                (Module::Fs, Member::Open),
                (Module::Fs, Member::OpenSync),
                (Module::Fs, Member::Rename),
                (Module::Fs, Member::RenameSync),
                (Module::Fs, Member::Rmdir),
                (Module::Fs, Member::RmdirSync),
                (Module::Fs, Member::Rm),
                (Module::Fs, Member::RmSync),
                (Module::Fs, Member::Symlink),
                (Module::Fs, Member::SymlinkSync),
                (Module::Fs, Member::Truncate),
                (Module::Fs, Member::TruncateSync),
                (Module::Fs, Member::Unlink),
                (Module::Fs, Member::UnlinkSync),
                (Module::Fs, Member::WriteFile),
                (Module::Fs, Member::WriteFileSync),
                (Module::FsPromises, Member::AppendFile),
                (Module::FsPromises, Member::Chmod),
                (Module::FsPromises, Member::Chown),
                (Module::FsPromises, Member::CopyFile),
                (Module::FsPromises, Member::Link),
                (Module::FsPromises, Member::Mkdir),
                (Module::FsPromises, Member::Open),
                (Module::FsPromises, Member::Rename),
                (Module::FsPromises, Member::Rmdir),
                (Module::FsPromises, Member::Rm),
                (Module::FsPromises, Member::Symlink),
                (Module::FsPromises, Member::Truncate),
                (Module::FsPromises, Member::Unlink),
                (Module::FsPromises, Member::WriteFile),
                (Module::ChildProcess, Member::Exec),
                (Module::ChildProcess, Member::ExecSync),
                (Module::ChildProcess, Member::Spawn),
                (Module::ChildProcess, Member::SpawnSync),
                (Module::ChildProcess, Member::ExecFile),
                (Module::ChildProcess, Member::ExecFileSync),
            ]);
        }
        Self {
            scopes: vec![Scope {
                id: 0,
                bindings,
                function: true,
            }],
            scope_chain: vec![0],
            next_scope_id: 1,
            owned_members,
            loaded_modules_intact,
            node_properties: default_node_properties(),
            cwd: NestedExecutionCwd::Inherited,
            prototype_integrity_known: true,
            runtime_globals_intact: true,
        }
    }
    pub(super) fn get(&self, name: &str) -> Value {
        self.scope_chain
            .iter()
            .rev()
            .filter_map(|id| self.scopes.iter().find(|scope| scope.id == *id))
            .find_map(|scope| scope.bindings.get(name))
            .cloned()
            .unwrap_or(Value::Unknown)
    }

    pub(super) fn declare(&mut self, name: &str, value: Value) {
        let Some(id) = self.scope_chain.last().copied() else {
            return;
        };
        if let Some(scope) = self.scopes.iter_mut().find(|scope| scope.id == id) {
            scope.bindings.insert(name.to_owned(), value);
        }
    }

    pub(super) fn predeclare_var(&mut self, name: &str) {
        let target = self.scope_chain.iter().rev().find_map(|id| {
            self.scopes
                .iter()
                .find(|scope| scope.id == *id && scope.function)
                .map(|scope| scope.id)
        });
        if let Some(scope) =
            target.and_then(|id| self.scopes.iter_mut().find(|scope| scope.id == id))
        {
            let binding = scope
                .bindings
                .entry(name.to_owned())
                .or_insert(Value::Unknown);
            if matches!(
                binding,
                Value::Require
                    | Value::Eval
                    | Value::FunctionConstructor
                    | Value::ObjectBuiltin
                    | Value::Process
                    | Value::Deno
                    | Value::DenoCommandConstructor
                    | Value::Bun
                    | Value::OpenClawTools
                    | Value::Known(KnownFunction::BunShell)
            ) {
                *binding = Value::Unknown;
            }
        }
    }

    pub(super) fn assign(&mut self, name: &str, value: Value) {
        let target = self.scope_chain.iter().rev().find_map(|id| {
            self.scopes
                .iter()
                .find(|scope| scope.id == *id && scope.bindings.contains_key(name))
                .map(|scope| scope.id)
        });
        if let Some(scope) =
            target.and_then(|id| self.scopes.iter_mut().find(|scope| scope.id == id))
        {
            if Some(scope.id) == self.scope_chain.first().copied()
                && scope.bindings.get(name).is_some_and(runtime_global_value)
            {
                self.runtime_globals_intact = false;
            }
            scope.bindings.insert(name.to_owned(), value);
        } else if let Some(id) = self.scope_chain.first().copied()
            && let Some(scope) = self.scopes.iter_mut().find(|scope| scope.id == id)
        {
            scope.bindings.insert(name.to_owned(), value);
        }
    }

    pub(super) fn push_scope(&mut self, function: bool) {
        let id = self.next_scope_id;
        self.next_scope_id += 1;
        self.scopes.push(Scope {
            id,
            bindings: BTreeMap::new(),
            function,
        });
        self.scope_chain.push(id);
    }

    pub(super) fn pop_scope(&mut self) {
        if let Some(id) = self.scope_chain.pop()
            && let Some(index) = self.scopes.iter().position(|scope| scope.id == id)
        {
            self.scopes.remove(index);
        }
    }

    pub(super) fn invalidate_module(&mut self, module: Module) {
        self.owned_members.retain(|(owned, _)| {
            *owned != module
                && !matches!(
                    (module, *owned),
                    (Module::Fs, Module::FsPromises) | (Module::FsPromises, Module::Fs)
                )
        });
        self.invalidate_loaded_module_cache(module);
    }

    pub(super) fn invalidate_loaded_module_cache(&mut self, module: Module) {
        self.loaded_modules_intact.retain(|loaded| {
            *loaded != module
                && !matches!(
                    (module, *loaded),
                    (Module::Fs, Module::FsPromises) | (Module::FsPromises, Module::Fs)
                )
        });
        for scope in &mut self.scopes {
            for value in scope.bindings.values_mut() {
                invalidate_loaded_module_value(value, module);
            }
        }
    }

    pub(super) fn invalidate_node_module_loader(&mut self) {
        self.owned_members.clear();
    }

    pub(super) fn invalidate_node_module_properties(&mut self) {
        self.invalidate_node_module_loader();
        self.loaded_modules_intact.clear();
        for property in self.node_properties.values_mut() {
            property.value = Value::Unknown;
            property.own = None;
            property.kind = NodePropertyKind::Unknown;
            property.enumerable = None;
            property.assignment = NodeMutation::Unknown;
            property.deletion = NodeMutation::Unknown;
        }
    }

    pub(super) fn invalidate_node_module_escape(&mut self, value: &Value) {
        match value {
            Value::CommonJsModule | Value::NodeModule | Value::NodeModulePrototype => {
                self.invalidate_node_module_properties();
            }
            Value::NodeModuleMember(member) if node_module_loader_hook(*member) => {
                self.invalidate_node_module_loader();
            }
            Value::NodeModuleMember(_) => {}
            Value::Array(values) => {
                for value in values {
                    self.invalidate_node_module_escape(value);
                }
            }
            Value::Object(properties) => {
                for value in properties.values() {
                    self.invalidate_node_module_escape(value);
                }
            }
            Value::UnknownReceiver(value) => self.invalidate_node_module_escape(value),
            _ => {}
        }
    }

    pub(super) fn widen(&mut self) {
        for scope in &mut self.scopes {
            for value in scope.bindings.values_mut() {
                *value = Value::Unknown;
            }
        }
        self.owned_members.clear();
        self.loaded_modules_intact.clear();
        for property in self.node_properties.values_mut() {
            property.value = Value::Unknown;
            property.own = None;
            property.kind = NodePropertyKind::Unknown;
            property.enumerable = None;
            property.assignment = NodeMutation::Unknown;
            property.deletion = NodeMutation::Unknown;
        }
        self.cwd = NestedExecutionCwd::Unknown;
        self.prototype_integrity_known = false;
        self.runtime_globals_intact = false;
    }

    pub(super) fn invalidate_value(&mut self, value: &Value) {
        if runtime_global_value(value) {
            self.runtime_globals_intact = false;
        }
        match value {
            Value::Module(module) | Value::UnknownModuleMember(module) => {
                self.invalidate_module(*module);
            }
            Value::LoadedModule(module) => self.invalidate_loaded_module(*module),
            Value::CommonJsModule | Value::NodeModule | Value::NodeModulePrototype => {
                self.invalidate_node_module_properties();
            }
            Value::NodeModuleMember(member) => {
                if node_module_loader_hook(*member) {
                    self.invalidate_node_module_loader();
                }
            }
            Value::Array(values) => {
                for value in values {
                    self.invalidate_value(value);
                }
            }
            Value::Object(properties) => {
                for value in properties.values() {
                    self.invalidate_value(value);
                }
            }
            Value::UnknownReceiver(value) => self.invalidate_value(value),
            _ => {}
        }
        self.forget_container(value);
    }

    pub(super) fn forget_container(&mut self, value: &Value) {
        if !matches!(value, Value::Array(_) | Value::Object(_)) {
            return;
        }
        for scope in &mut self.scopes {
            for binding in scope.bindings.values_mut() {
                if binding == value {
                    *binding = Value::Unknown;
                }
            }
        }
        if matches!(
            value,
            Value::Process
                | Value::Environment
                | Value::Deno
                | Value::DenoCommandConstructor
                | Value::DenoCommand(_)
                | Value::Bun
                | Value::BunFile(_)
                | Value::OpenClawTools
        ) {
            for scope in &mut self.scopes {
                for binding in scope.bindings.values_mut() {
                    if binding == value
                        || matches!(
                            (value, &*binding),
                            (
                                Value::Process | Value::Environment,
                                Value::Process | Value::Environment
                            )
                        )
                    {
                        *binding = Value::Unknown;
                    }
                }
            }
        }
    }

    pub(super) fn replace_mutated_container(&mut self, original: &Value, replacement: &Value) {
        for scope in &mut self.scopes {
            for binding in scope.bindings.values_mut() {
                replace_mutated_container_value(binding, original, replacement, true);
            }
        }
    }

    pub(super) fn invalidate_loaded_module(&mut self, module: Module) {
        self.invalidate_module(module);
    }

    pub(super) fn dynamic_global(&self, ownership: RuntimeOwnership) -> Self {
        let mut state = Self::new(ownership);
        state.owned_members = self.owned_members.clone();
        state.loaded_modules_intact = self.loaded_modules_intact.clone();
        state.node_properties = self.node_properties.clone();
        state.cwd.clone_from(&self.cwd);
        state.prototype_integrity_known = self.prototype_integrity_known;
        state.runtime_globals_intact = self.runtime_globals_intact;
        if !state.runtime_globals_intact {
            state.owned_members.clear();
            for scope in &mut state.scopes {
                for value in scope.bindings.values_mut() {
                    if runtime_global_value(value) {
                        *value = Value::Unknown;
                    }
                }
            }
        }
        state
    }
}

fn replace_mutated_container_value(
    value: &mut Value,
    original: &Value,
    replacement: &Value,
    direct_binding: bool,
) {
    if value == original {
        if direct_binding {
            *value = Value::Unknown;
        } else {
            value.clone_from(replacement);
        }
        return;
    }
    match value {
        Value::Array(values) => {
            for value in values {
                replace_mutated_container_value(value, original, replacement, false);
            }
        }
        Value::Object(properties) => {
            for value in properties.values_mut() {
                replace_mutated_container_value(value, original, replacement, false);
            }
        }
        Value::DenoCommand(command) => {
            if let Some(source) = command.source.as_mut() {
                replace_mutated_container_value(&mut source.program, original, replacement, false);
                if let Some(options) = &mut source.options {
                    replace_mutated_container_value(options, original, replacement, false);
                }
            }
        }
        Value::UnknownReceiver(value) => {
            replace_mutated_container_value(value, original, replacement, false);
        }
        _ => {}
    }
}
