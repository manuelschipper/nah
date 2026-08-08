use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use nah_proto::action::{FilesystemOperation, InvocationInput};
use nah_proto::ctx::Platform;
use serde_json::{Map, Value as JsonValue};

use crate::{
    InlineInput, InlineRefusal, InlineReport, LanguageAnalysis, LanguageCall, LanguageCallKind,
    LanguageDraft, LanguageFilesystem, NestedExecutionCwd,
};

use super::parser::{CoverageKind, HirField, HirKind, HirNode};
use super::{Profile, RuntimeOwnership, SourceContext, SyntaxProfile};

const MAX_WORK: usize = 262_144;
const MAX_STATEMENTS: usize = 4_096;
const MAX_FUNCTIONS: usize = 128;
const MAX_CALL_DEPTH: usize = 16;
const MAX_COLLECTION_ITEMS: usize = 256;
const MAX_VALUE_BYTES: usize = crate::SOURCE_LIMIT;
const MAX_DYNAMIC_SOURCE_BYTES: usize = crate::SOURCE_LIMIT;
const MAX_NATIVE_ARGUMENTS: usize = 16;
const MAX_NATIVE_COLLECTION_ITEMS: usize = 64;
const MAX_NATIVE_EVIDENCE_BYTES: usize = crate::SOURCE_LIMIT;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Module {
    Fs,
    FsPromises,
    ChildProcess,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Member {
    AppendFile,
    AppendFileSync,
    Chmod,
    ChmodSync,
    Chown,
    ChownSync,
    CopyFile,
    CopyFileSync,
    CreateWriteStream,
    Link,
    LinkSync,
    Mkdir,
    MkdirSync,
    Open,
    OpenSync,
    Rename,
    RenameSync,
    Rmdir,
    RmdirSync,
    Rm,
    RmSync,
    Symlink,
    SymlinkSync,
    Truncate,
    TruncateSync,
    Unlink,
    UnlinkSync,
    WriteFile,
    WriteFileSync,
    Exec,
    ExecSync,
    Spawn,
    SpawnSync,
    ExecFile,
    ExecFileSync,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DenoMember {
    Chdir,
    Remove,
    RemoveSync,
    Mkdir,
    MkdirSync,
    ReadFile,
    ReadFileSync,
    ReadTextFile,
    ReadTextFileSync,
    WriteFile,
    WriteFileSync,
    WriteTextFile,
    WriteTextFileSync,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DenoCommandMember {
    Spawn,
    Output,
    OutputSync,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BunMember {
    Spawn,
    SpawnSync,
    File,
    Write,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BunFileMember {
    Text,
    Json,
    ArrayBuffer,
    Bytes,
    Delete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OpenClawMember {
    Call,
    CallValue,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum NodeModuleMember {
    Load,
    CreateRequire,
    Require,
    IsBuiltin,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum NodeProperty {
    ModuleLoad,
    ModuleCreateRequire,
    ModuleIsBuiltin,
    ModuleAlias,
    ModulePrototype,
    ModuleConstructor,
    PrototypeRequire,
    CommonJsRequire,
    CommonJsConstructor,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NodeMutation {
    Applies,
    Ignored,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NodePropertyKind {
    Absent,
    Data,
    Accessor,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct NodePropertyState {
    value: Value,
    own: Option<bool>,
    kind: NodePropertyKind,
    enumerable: Option<bool>,
    assignment: NodeMutation,
    deletion: NodeMutation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DenoCommandValue {
    argv: Option<Vec<String>>,
    cwd: NestedExecutionCwd,
    spawn: ExecutionCertainty,
    output: ExecutionCertainty,
    context_exact: bool,
    spawn_stdout_inherited: bool,
    output_stdout_inherited: bool,
    spawn_throws_after_effect: bool,
    output_throws_after_effect: bool,
    source: Option<Box<DenoCommandSource>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DenoCommandSource {
    program: Value,
    options: Option<Value>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExecutionCertainty {
    Known,
    Unknown,
    Invalid,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum KnownFunction {
    DefineProperty,
    SetPrototypeOf,
    Fs(Module, Member),
    Child(Member),
    Deno(DenoMember),
    DenoCommand(DenoCommandMember, DenoCommandValue),
    Bun(BunMember),
    BunFile(BunFileMember, Option<String>),
    BunShell,
    OpenClaw(OpenClawMember),
    ProcessChdir,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LocalFunction {
    parameters: Option<Vec<String>>,
    body: HirNode,
    expression_body: bool,
    asynchronous: bool,
    strict: bool,
    captured_scopes: Vec<usize>,
    source_identity: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Value {
    Unknown,
    Invalid,
    NonCallablePrimitive,
    SynchronousThrow,
    Divergent,
    Promise,
    RejectedPromise,
    Undefined,
    Null,
    Bool(bool),
    Number(i64),
    String(String),
    Array(Vec<Value>),
    Object(BTreeMap<String, Value>),
    Module(Module),
    Known(KnownFunction),
    Function(Arc<LocalFunction>),
    Accessor,
    AccessorGetter(Arc<LocalFunction>),
    Require,
    Eval,
    DynamicEvalResult,
    FunctionConstructor,
    DynamicFunction(Option<String>),
    ObjectBuiltin,
    Process,
    Environment,
    CommonJsModule,
    InheritedNodeProperty(NodeProperty),
    NodeModule,
    LoadedModule(Module),
    NodeModulePrototype,
    NodeModuleMember(NodeModuleMember),
    Deno,
    DenoCommandConstructor,
    DenoCommand(DenoCommandValue),
    Bun,
    BunFile(Option<String>),
    OpenClawTools,
    UnknownModuleMember(Module),
    UnknownReceiver(Box<Value>),
}

#[derive(Clone)]
struct MemberReference {
    object: Value,
    property: Option<String>,
    prototype_mutation: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Scope {
    id: usize,
    bindings: BTreeMap<String, Value>,
    function: bool,
}

#[derive(Clone, Debug)]
struct State {
    scopes: Vec<Scope>,
    scope_chain: Vec<usize>,
    next_scope_id: usize,
    owned_members: BTreeSet<(Module, Member)>,
    loaded_modules_intact: BTreeSet<Module>,
    node_properties: BTreeMap<NodeProperty, NodePropertyState>,
    cwd: NestedExecutionCwd,
    prototype_integrity_known: bool,
    runtime_globals_intact: bool,
}

impl PartialEq for State {
    fn eq(&self, other: &Self) -> bool {
        self.scopes == other.scopes
            && self.scope_chain == other.scope_chain
            && self.owned_members == other.owned_members
            && self.loaded_modules_intact == other.loaded_modules_intact
            && self.node_properties == other.node_properties
            && self.cwd == other.cwd
            && self.prototype_integrity_known == other.prototype_integrity_known
            && self.runtime_globals_intact == other.runtime_globals_intact
    }
}

impl Eq for State {}

impl State {
    fn new(ownership: RuntimeOwnership) -> Self {
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
    fn get(&self, name: &str) -> Value {
        self.scope_chain
            .iter()
            .rev()
            .filter_map(|id| self.scopes.iter().find(|scope| scope.id == *id))
            .find_map(|scope| scope.bindings.get(name))
            .cloned()
            .unwrap_or(Value::Unknown)
    }

    fn declare(&mut self, name: &str, value: Value) {
        let Some(id) = self.scope_chain.last().copied() else {
            return;
        };
        if let Some(scope) = self.scopes.iter_mut().find(|scope| scope.id == id) {
            scope.bindings.insert(name.to_owned(), value);
        }
    }

    fn predeclare_var(&mut self, name: &str) {
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

    fn assign(&mut self, name: &str, value: Value) {
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

    fn push_scope(&mut self, function: bool) {
        let id = self.next_scope_id;
        self.next_scope_id += 1;
        self.scopes.push(Scope {
            id,
            bindings: BTreeMap::new(),
            function,
        });
        self.scope_chain.push(id);
    }

    fn pop_scope(&mut self) {
        if let Some(id) = self.scope_chain.pop()
            && let Some(index) = self.scopes.iter().position(|scope| scope.id == id)
        {
            self.scopes.remove(index);
        }
    }

    fn invalidate_module(&mut self, module: Module) {
        self.owned_members.retain(|(owned, _)| {
            *owned != module
                && !matches!(
                    (module, *owned),
                    (Module::Fs, Module::FsPromises) | (Module::FsPromises, Module::Fs)
                )
        });
        self.invalidate_loaded_module_cache(module);
    }

    fn invalidate_loaded_module_cache(&mut self, module: Module) {
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

    fn invalidate_node_module_loader(&mut self) {
        self.owned_members.clear();
    }

    fn invalidate_node_module_properties(&mut self) {
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

    fn invalidate_node_module_escape(&mut self, value: &Value) {
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

    fn widen(&mut self) {
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

    fn invalidate_value(&mut self, value: &Value) {
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

    fn forget_container(&mut self, value: &Value) {
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

    fn replace_mutated_container(&mut self, original: &Value, replacement: &Value) {
        for scope in &mut self.scopes {
            for binding in scope.bindings.values_mut() {
                replace_mutated_container_value(binding, original, replacement, true);
            }
        }
    }

    fn invalidate_loaded_module(&mut self, module: Module) {
        self.invalidate_module(module);
    }

    fn dynamic_global(&self, ownership: RuntimeOwnership) -> Self {
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

#[derive(Default)]
struct Budget {
    work: usize,
    statements: usize,
    functions: usize,
    dynamic_source_bytes: usize,
    refusal: Option<InlineRefusal>,
}

impl Budget {
    fn spend(&mut self) -> bool {
        self.work += 1;
        if self.work <= MAX_WORK {
            true
        } else {
            self.refuse();
            false
        }
    }

    fn enter_statement(&mut self) -> bool {
        self.statements += 1;
        if self.statements <= MAX_STATEMENTS {
            true
        } else {
            self.refuse();
            false
        }
    }

    fn add_function(&mut self) -> bool {
        self.functions += 1;
        if self.functions <= MAX_FUNCTIONS {
            true
        } else {
            self.refuse();
            false
        }
    }

    fn admit_bytes(&mut self, bytes: Option<usize>) -> bool {
        if bytes.is_some_and(|bytes| bytes <= MAX_VALUE_BYTES) {
            true
        } else {
            self.refuse();
            false
        }
    }

    fn enter_dynamic_source(&mut self, bytes: usize) -> bool {
        if let Some(total) = self
            .dynamic_source_bytes
            .checked_add(bytes)
            .filter(|total| *total <= MAX_DYNAMIC_SOURCE_BYTES)
        {
            self.dynamic_source_bytes = total;
            true
        } else {
            self.refuse();
            false
        }
    }

    fn refuse(&mut self) {
        self.refusal.get_or_insert(InlineRefusal::WorkLimit);
    }

    fn absorb(&mut self, other: Self) {
        self.work = self.work.saturating_add(other.work);
        self.statements = self.statements.saturating_add(other.statements);
        self.functions = self.functions.saturating_add(other.functions);
        self.dynamic_source_bytes = self
            .dynamic_source_bytes
            .saturating_add(other.dynamic_source_bytes);
        if self.work > MAX_WORK
            || self.statements > MAX_STATEMENTS
            || self.functions > MAX_FUNCTIONS
            || self.dynamic_source_bytes > MAX_DYNAMIC_SOURCE_BYTES
        {
            self.refuse();
        }
        if let Some(refusal) = other.refusal {
            self.refusal.get_or_insert(refusal);
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Control {
    Next,
    Break,
    Continue,
    Return,
    Throw,
    Diverge,
}

#[derive(Clone, Copy)]
enum BindingMode {
    Assign,
    Lexical,
    Var,
}

#[derive(Default)]
struct Arguments {
    values: Vec<Value>,
    complete: bool,
    assembly_branches: Vec<AssemblyBranch>,
}

enum RuntimeCallSummary<T> {
    Effect(T),
    EffectPartial(T),
    Partial,
    Invalid,
}

struct BunSpawnSummary {
    argv: Option<Vec<String>>,
    cwd: NestedExecutionCwd,
    context_exact: bool,
    stdout_inherited: bool,
}

struct Interpreter<'a> {
    source: &'a str,
    home: &'a str,
    platform: Platform,
    depth: usize,
    profile: Profile,
    strict: bool,
    report: InlineReport,
    draft: LanguageDraft,
    complete: bool,
    budget: Budget,
    return_value: Value,
    conditional_depth: usize,
    catchable_depth: usize,
    execution_dominators: Vec<usize>,
    awaited_call: Option<usize>,
    async_frames: Vec<AsyncFrame>,
}

struct AssemblyBranch {
    state: State,
    conditional_depth: usize,
    execution_dominators: Vec<usize>,
}

struct AsyncFrame {
    deferred: bool,
    prefix: Option<State>,
}

pub(super) fn analyze(profile: Profile, input: &InlineInput<'_>, depth: usize) -> LanguageAnalysis {
    if profile.syntax == SyntaxProfile::Ambiguous {
        return LanguageAnalysis::new(InlineReport::default(), LanguageDraft::partial());
    }
    let parsed = match (profile.syntax, profile.context) {
        (SyntaxProfile::JavaScript, SourceContext::Module) => super::parser::javascript(input.code),
        (SyntaxProfile::JavaScript, SourceContext::FunctionBody) => {
            super::parser::javascript_function_body(input.code)
        }
        (SyntaxProfile::TypeScript, SourceContext::Module) => super::parser::typescript(input.code),
        (SyntaxProfile::TypeScript, SourceContext::FunctionBody) => {
            super::parser::typescript_function_body(input.code)
        }
        (SyntaxProfile::Tsx, _) => super::parser::tsx(input.code),
        (SyntaxProfile::Ambiguous, _) => unreachable!(),
    };
    let module = match parsed {
        Ok(module) if module.executable() => module,
        Ok(_) => return LanguageAnalysis::new(InlineReport::default(), LanguageDraft::partial()),
        Err(refusal) => return LanguageAnalysis::refused(refusal),
    };
    debug_assert!(module.coverage().iter().all(|covered| {
        matches!(
            covered.kind(),
            CoverageKind::Unsupported | CoverageKind::Error
        ) && covered.span().end() <= input.code.len()
    }));
    let strict = strict_directive(module.root(), input.code) || source_is_module(module.root());
    let mut interpreter = Interpreter {
        source: input.code,
        home: input.home,
        platform: input.platform,
        depth,
        profile,
        strict,
        report: InlineReport::default(),
        draft: LanguageDraft::default(),
        complete: true,
        budget: Budget::default(),
        return_value: Value::Undefined,
        conditional_depth: 0,
        catchable_depth: 0,
        execution_dominators: Vec::new(),
        awaited_call: None,
        async_frames: Vec::new(),
    };
    if profile.ownership == RuntimeOwnership::DenoCheckedEval {
        interpreter.complete = false;
        interpreter.draft.set_partial();
    }
    let mut state = State::new(profile.ownership);
    interpreter.hoist_vars(module.root(), &mut state);
    interpreter.exec_sequence(module.root(), &mut state, false, 0);
    if let Some(refusal) = interpreter.budget.refusal {
        interpreter.report.refuse(refusal);
        interpreter.draft.set_partial();
    }
    if !interpreter.complete {
        interpreter.draft.set_partial();
    }
    LanguageAnalysis::new(interpreter.report, interpreter.draft)
}

impl<'a> Interpreter<'a> {
    fn start_assembly_branch(&mut self, state: &State, branches: &mut Vec<AssemblyBranch>) {
        self.complete = false;
        self.draft.set_partial();
        branches.push(AssemblyBranch {
            state: state.clone(),
            conditional_depth: self.conditional_depth,
            execution_dominators: self.execution_dominators.clone(),
        });
        self.conditional_depth = self.conditional_depth.saturating_add(1);
    }

    fn finish_assembly_branches(
        &mut self,
        state: &mut State,
        branches: &mut Vec<AssemblyBranch>,
        value: Value,
    ) -> Value {
        self.close_assembly_branches(state, branches);
        value
    }

    fn close_assembly_branches(&mut self, state: &mut State, branches: &mut Vec<AssemblyBranch>) {
        while let Some(branch) = branches.pop() {
            self.conditional_depth = branch.conditional_depth;
            self.execution_dominators = branch.execution_dominators;
            *state = join_states(branch.state, state.clone());
        }
    }

    fn exec_sequence(
        &mut self,
        node: &HirNode,
        state: &mut State,
        scoped: bool,
        call_depth: usize,
    ) -> Control {
        if scoped {
            state.push_scope(false);
        }
        if !self.predeclare(node, state) {
            if scoped {
                state.pop_scope();
            }
            return Control::Next;
        }
        let mut control = Control::Next;
        for child in named_children(node) {
            control = self.exec_statement(child, state, call_depth);
            if control != Control::Next || self.budget.refusal.is_some() {
                break;
            }
        }
        if scoped {
            state.pop_scope();
        }
        control
    }

    fn predeclare(&mut self, node: &HirNode, state: &mut State) -> bool {
        for child in named_children(node) {
            match child.kind() {
                HirKind::FunctionDeclaration => {
                    let Some(name) = child.child(HirField::Name) else {
                        continue;
                    };
                    let Some(function) = self.function_value(child, state) else {
                        return false;
                    };
                    state.declare(self.text(name), function);
                }
                HirKind::LexicalDeclaration => {
                    for declarator in named_children(child)
                        .filter(|child| child.kind() == HirKind::VariableDeclarator)
                    {
                        if let Some(pattern) = declarator.child(HirField::Name) {
                            self.predeclare_pattern(pattern, state, false);
                        }
                    }
                }
                HirKind::ImportStatement => self.bind_import(child, state),
                HirKind::ExportStatement => {
                    if !self.type_only_export(child) && !self.predeclare(child, state) {
                        return false;
                    }
                }
                HirKind::ClassDeclaration => {
                    if let Some(name) = child.child(HirField::Name) {
                        state.declare(self.text(name), Value::Unknown);
                    }
                }
                _ => {}
            }
        }
        self.budget.refusal.is_none()
    }

    fn hoist_vars(&self, node: &HirNode, state: &mut State) {
        for child in named_children(node) {
            match child.kind() {
                HirKind::VariableDeclaration => {
                    for declarator in named_children(child)
                        .filter(|child| child.kind() == HirKind::VariableDeclarator)
                    {
                        if let Some(pattern) = declarator.child(HirField::Name) {
                            self.predeclare_pattern(pattern, state, true);
                        }
                    }
                }
                HirKind::FunctionDeclaration
                | HirKind::FunctionExpression
                | HirKind::ArrowFunction
                | HirKind::ClassDeclaration
                | HirKind::TypeOnly => {}
                HirKind::ExportStatement if !self.type_only_export(child) => {
                    self.hoist_vars(child, state)
                }
                _ => self.hoist_vars(child, state),
            }
        }
    }

    fn predeclare_pattern(&self, node: &HirNode, state: &mut State, function: bool) {
        match node.kind() {
            HirKind::Identifier | HirKind::ShorthandPropertyIdentifier => {
                if function {
                    state.predeclare_var(self.text(node));
                } else {
                    state.declare(self.text(node), Value::Unknown);
                }
            }
            HirKind::Pair | HirKind::AssignmentPattern => {
                if let Some(value) = node
                    .child(HirField::Value)
                    .or_else(|| node.child(HirField::Left))
                {
                    self.predeclare_pattern(value, state, function);
                }
            }
            HirKind::ObjectPattern | HirKind::ArrayPattern | HirKind::RestPattern => {
                for child in named_children(node) {
                    self.predeclare_pattern(child, state, function);
                }
            }
            _ => {}
        }
    }

    fn exec_statement(&mut self, node: &HirNode, state: &mut State, call_depth: usize) -> Control {
        if !self.budget.enter_statement() || !self.budget.spend() {
            return Control::Next;
        }
        match node.kind() {
            HirKind::Program => self.exec_sequence(node, state, false, call_depth),
            HirKind::StatementBlock => self.exec_sequence(node, state, true, call_depth),
            HirKind::ExpressionStatement => {
                if let Some(expression) = named_children(node).next() {
                    let value = self.eval(expression, state, call_depth);
                    if let Some(control) = abrupt_control(&value) {
                        return control;
                    }
                }
                Control::Next
            }
            HirKind::LexicalDeclaration | HirKind::VariableDeclaration => {
                self.declaration(node, state, call_depth)
            }
            HirKind::FunctionDeclaration | HirKind::ImportStatement | HirKind::TypeOnly => {
                Control::Next
            }
            HirKind::ExportStatement => {
                if !self.type_only_export(node) {
                    for child in named_children(node) {
                        if !matches!(child.kind(), HirKind::TypeOnly) {
                            let control = self.exec_statement(child, state, call_depth);
                            if control != Control::Next {
                                return control;
                            }
                        }
                    }
                }
                Control::Next
            }
            HirKind::IfStatement => self.if_statement(node, state, call_depth),
            HirKind::WhileStatement => self.while_statement(node, state, call_depth),
            HirKind::BreakStatement => Control::Break,
            HirKind::ContinueStatement => Control::Continue,
            HirKind::ReturnStatement => {
                self.return_value = named_children(node)
                    .next()
                    .map_or(Value::Undefined, |value| {
                        self.eval(value, state, call_depth)
                    });
                abrupt_control(&self.return_value).unwrap_or(Control::Return)
            }
            HirKind::ThrowStatement => {
                if let Some(value) = named_children(node).next() {
                    let value = self.eval(value, state, call_depth);
                    if value == Value::Divergent {
                        return Control::Diverge;
                    }
                }
                Control::Throw
            }
            HirKind::TryStatement => self.try_statement(node, state, call_depth),
            HirKind::Comment | HirKind::Token | HirKind::EmptyStatement => Control::Next,
            HirKind::ClassDeclaration | HirKind::Unsupported | HirKind::Error => {
                self.complete = false;
                state.widen();
                Control::Next
            }
            _ => {
                let value = self.eval(node, state, call_depth);
                abrupt_control(&value).unwrap_or(Control::Next)
            }
        }
    }

    fn declaration(&mut self, node: &HirNode, state: &mut State, call_depth: usize) -> Control {
        for declarator in
            named_children(node).filter(|child| child.kind() == HirKind::VariableDeclarator)
        {
            let value = declarator
                .child(HirField::Value)
                .map_or(Value::Undefined, |value| {
                    self.eval(value, state, call_depth)
                });
            if let Some(control) = abrupt_control(&value) {
                return control;
            }
            if let Some(pattern) = declarator.child(HirField::Name) {
                let mode = if node.kind() == HirKind::VariableDeclaration {
                    BindingMode::Var
                } else {
                    BindingMode::Lexical
                };
                if let Some(value) = self.assign_pattern(pattern, value, state, mode, call_depth) {
                    return abrupt_control(&value).unwrap_or(Control::Throw);
                }
            }
        }
        Control::Next
    }

    fn if_statement(&mut self, node: &HirNode, state: &mut State, call_depth: usize) -> Control {
        let condition = node
            .child(HirField::Condition)
            .map_or(Value::Unknown, |condition| {
                self.eval(condition, state, call_depth)
            });
        if let Some(control) = abrupt_control(&condition) {
            return control;
        }
        let consequence = node.child(HirField::Consequence);
        let alternative = node
            .child(HirField::Alternative)
            .and_then(|clause| named_children(clause).next());
        match truthy(&condition) {
            Some(true) => consequence.map_or(Control::Next, |branch| {
                self.exec_branch(branch, state, call_depth)
            }),
            Some(false) => alternative.map_or(Control::Next, |branch| {
                self.exec_branch(branch, state, call_depth)
            }),
            None => {
                self.complete = false;
                let mut yes = state.clone();
                let mut no = state.clone();
                let saved_return = self.return_value.clone();
                let saved_dominators = self.execution_dominators.clone();
                self.conditional_depth += 1;
                self.return_value = saved_return.clone();
                let yes_control = consequence.map_or(Control::Next, |branch| {
                    self.exec_branch(branch, &mut yes, call_depth)
                });
                let yes_return = self.return_value.clone();
                self.execution_dominators = saved_dominators.clone();
                self.return_value = saved_return.clone();
                let no_control = alternative.map_or(Control::Next, |branch| {
                    self.exec_branch(branch, &mut no, call_depth)
                });
                let no_return = self.return_value.clone();
                self.conditional_depth -= 1;
                self.execution_dominators = saved_dominators;
                self.return_value =
                    if yes_control == Control::Return && no_control == Control::Return {
                        join_values(yes_return, no_return)
                    } else if yes_control == Control::Return || no_control == Control::Return {
                        Value::Unknown
                    } else {
                        saved_return
                    };
                *state = join_states(yes, no);
                if yes_control == no_control {
                    yes_control
                } else {
                    Control::Next
                }
            }
        }
    }

    fn while_statement(&mut self, node: &HirNode, state: &mut State, call_depth: usize) -> Control {
        let Some(body) = node.child(HirField::Body) else {
            return Control::Next;
        };
        for _ in 0..64 {
            let condition = node
                .child(HirField::Condition)
                .map_or(Value::Unknown, |condition| {
                    self.eval(condition, state, call_depth)
                });
            if let Some(control) = abrupt_control(&condition) {
                return control;
            }
            match truthy(&condition) {
                Some(false) => return Control::Next,
                Some(true) => {
                    let before = state.clone();
                    match self.exec_branch(body, state, call_depth) {
                        Control::Break => return Control::Next,
                        Control::Return => return Control::Return,
                        Control::Throw => return Control::Throw,
                        Control::Diverge => return Control::Diverge,
                        Control::Next | Control::Continue => {
                            if *state == before {
                                return Control::Diverge;
                            }
                        }
                    }
                }
                None => {
                    self.complete = false;
                    let before = state.clone();
                    let mut iterated = state.clone();
                    let saved_dominators = self.execution_dominators.clone();
                    self.conditional_depth += 1;
                    self.exec_branch(body, &mut iterated, call_depth);
                    self.conditional_depth -= 1;
                    self.execution_dominators = saved_dominators;
                    *state = join_states(before, iterated);
                    return Control::Next;
                }
            }
        }
        self.budget.refuse();
        Control::Next
    }

    fn try_statement(&mut self, node: &HirNode, state: &mut State, call_depth: usize) -> Control {
        let catches = node.child(HirField::Handler).is_some();
        if catches {
            self.catchable_depth += 1;
        }
        let mut control = node.child(HirField::Body).map_or(Control::Next, |body| {
            self.exec_sequence(body, state, true, call_depth)
        });
        if catches {
            self.catchable_depth -= 1;
        }
        if control == Control::Diverge {
            return control;
        }
        if control == Control::Throw
            && let Some(handler) = node.child(HirField::Handler)
        {
            state.push_scope(false);
            let parameter_control = handler.child(HirField::Parameter).and_then(|parameter| {
                self.predeclare_pattern(parameter, state, false);
                self.assign_pattern(
                    parameter,
                    Value::Unknown,
                    state,
                    BindingMode::Lexical,
                    call_depth,
                )
                .and_then(|value| abrupt_control(&value))
            });
            if let Some(parameter_control) = parameter_control {
                control = parameter_control;
            } else {
                control = handler.child(HirField::Body).map_or(Control::Next, |body| {
                    self.exec_sequence(body, state, false, call_depth)
                });
            }
            state.pop_scope();
        }
        if control == Control::Diverge {
            return control;
        }
        if let Some(finalizer) = node.child(HirField::Finalizer)
            && let Some(body) = finalizer.child(HirField::Body)
        {
            let final_control = self.exec_sequence(body, state, true, call_depth);
            if final_control != Control::Next {
                control = final_control;
            }
        }
        control
    }

    fn exec_branch(&mut self, node: &HirNode, state: &mut State, call_depth: usize) -> Control {
        if node.kind() == HirKind::StatementBlock {
            self.exec_sequence(node, state, true, call_depth)
        } else {
            self.exec_statement(node, state, call_depth)
        }
    }

    fn eval(&mut self, node: &HirNode, state: &mut State, call_depth: usize) -> Value {
        if !self.budget.spend() {
            return Value::Unknown;
        }
        match node.kind() {
            HirKind::Identifier => state.get(self.text(node)),
            HirKind::String => {
                let source = self.text(node).to_owned();
                self.decode_string(&source)
                    .map_or(Value::Unknown, Value::String)
            }
            HirKind::TemplateString => self.template(node, state, call_depth),
            HirKind::Number => parse_number(self.text(node)).map_or(Value::Unknown, Value::Number),
            HirKind::True => Value::Bool(true),
            HirKind::False => Value::Bool(false),
            HirKind::Null => Value::Null,
            HirKind::Undefined => Value::Undefined,
            HirKind::Array => self.array(node, state, call_depth),
            HirKind::Object => self.object(node, state, call_depth),
            HirKind::FunctionExpression | HirKind::ArrowFunction => {
                self.function_value(node, state).unwrap_or(Value::Unknown)
            }
            HirKind::ParenthesizedExpression | HirKind::TransparentExpression => {
                named_children(node)
                    .next()
                    .map_or(Value::Unknown, |child| self.eval(child, state, call_depth))
            }
            HirKind::AwaitExpression => {
                let value = if let Some(child) = named_children(node).next() {
                    let awaited_call = direct_call_identity(child);
                    let previous = std::mem::replace(&mut self.awaited_call, awaited_call);
                    let value = self.eval(child, state, call_depth);
                    self.awaited_call = previous;
                    value
                } else {
                    Value::Unknown
                };
                if let Some(frame) = self.async_frames.last_mut()
                    && frame.deferred
                    && frame.prefix.is_none()
                {
                    let mut prefix = state.clone();
                    if self.conditional_depth > 0 {
                        prefix.cwd = NestedExecutionCwd::Unknown;
                        self.complete = false;
                    }
                    frame.prefix = Some(prefix);
                }
                match value {
                    Value::RejectedPromise => Value::SynchronousThrow,
                    Value::Promise => Value::Unknown,
                    value => value,
                }
            }
            HirKind::SequenceExpression => {
                let mut value = Value::Undefined;
                for child in named_children(node) {
                    value = self.eval(child, state, call_depth);
                    if abrupt_value(&value) {
                        return value;
                    }
                }
                value
            }
            HirKind::BinaryExpression => self.binary(node, state, call_depth),
            HirKind::UnaryExpression => self.unary(node, state, call_depth),
            HirKind::TernaryExpression => self.ternary(node, state, call_depth),
            HirKind::AssignmentExpression => self.assignment(node, state, call_depth),
            HirKind::AugmentedAssignmentExpression | HirKind::UpdateExpression => {
                self.augmented_assignment(node, state, call_depth)
            }
            HirKind::MemberExpression | HirKind::SubscriptExpression => {
                self.member(node, state, call_depth)
            }
            HirKind::CallExpression => self.call(node, state, call_depth),
            HirKind::NewExpression => self.construct(node, state, call_depth),
            HirKind::ComputedPropertyName | HirKind::TemplateSubstitution => named_children(node)
                .next()
                .map_or(Value::Unknown, |child| self.eval(child, state, call_depth)),
            HirKind::ExpressionStatement => named_children(node)
                .next()
                .map_or(Value::Undefined, |child| {
                    self.eval(child, state, call_depth)
                }),
            HirKind::Unsupported | HirKind::Error => {
                self.complete = false;
                Value::Unknown
            }
            _ => Value::Unknown,
        }
    }

    fn binary(&mut self, node: &HirNode, state: &mut State, call_depth: usize) -> Value {
        let Some(left_node) = node.child(HirField::Left) else {
            return Value::Unknown;
        };
        let Some(right_node) = node.child(HirField::Right) else {
            return Value::Unknown;
        };
        let operator = node
            .child(HirField::Operator)
            .map_or_else(String::new, |operator| self.text(operator).to_owned());
        let left = self.eval(left_node, state, call_depth);
        if abrupt_value(&left) {
            return left;
        }
        match operator.as_str() {
            "&&" => match truthy(&left) {
                Some(false) => left,
                Some(true) => self.eval(right_node, state, call_depth),
                None => {
                    self.complete = false;
                    let before = state.clone();
                    let saved_dominators = self.execution_dominators.clone();
                    self.conditional_depth += 1;
                    let right = self.eval(right_node, state, call_depth);
                    self.conditional_depth -= 1;
                    self.execution_dominators = saved_dominators;
                    *state = join_states(before, state.clone());
                    join_values(left, right)
                }
            },
            "||" => match truthy(&left) {
                Some(true) => left,
                Some(false) => self.eval(right_node, state, call_depth),
                None => {
                    self.complete = false;
                    let before = state.clone();
                    let saved_dominators = self.execution_dominators.clone();
                    self.conditional_depth += 1;
                    let right = self.eval(right_node, state, call_depth);
                    self.conditional_depth -= 1;
                    self.execution_dominators = saved_dominators;
                    *state = join_states(before, state.clone());
                    join_values(left, right)
                }
            },
            "??" => match left {
                Value::Null | Value::Undefined => self.eval(right_node, state, call_depth),
                Value::Unknown => {
                    self.complete = false;
                    let before = state.clone();
                    let saved_dominators = self.execution_dominators.clone();
                    self.conditional_depth += 1;
                    let right = self.eval(right_node, state, call_depth);
                    self.conditional_depth -= 1;
                    self.execution_dominators = saved_dominators;
                    *state = join_states(before, state.clone());
                    join_values(Value::Unknown, right)
                }
                value => value,
            },
            _ => {
                let right = self.eval(right_node, state, call_depth);
                if abrupt_value(&right) {
                    return right;
                }
                match operator.as_str() {
                    "+" => self.add_values(left, right),
                    "===" => strict_equal(&left, &right).map_or(Value::Unknown, Value::Bool),
                    "!==" => strict_equal(&left, &right)
                        .map(|equal| Value::Bool(!equal))
                        .unwrap_or(Value::Unknown),
                    "==" => loose_equal(&left, &right).map_or(Value::Unknown, Value::Bool),
                    "!=" => loose_equal(&left, &right)
                        .map(|equal| Value::Bool(!equal))
                        .unwrap_or(Value::Unknown),
                    _ => Value::Unknown,
                }
            }
        }
    }

    fn unary(&mut self, node: &HirNode, state: &mut State, call_depth: usize) -> Value {
        let operator = node
            .child(HirField::Operator)
            .map_or_else(String::new, |operator| self.text(operator).to_owned());
        let argument = node
            .child(HirField::Argument)
            .or_else(|| named_children(node).next())
            .map_or(Value::Unknown, |value| self.eval(value, state, call_depth));
        if abrupt_value(&argument) {
            return argument;
        }
        match operator.as_str() {
            "!" => truthy(&argument).map_or(Value::Unknown, |value| Value::Bool(!value)),
            "void" => Value::Undefined,
            "+" => match argument {
                Value::Number(value) => Value::Number(value),
                _ => Value::Unknown,
            },
            "-" => match argument {
                Value::Number(value) => value.checked_neg().map_or(Value::Unknown, Value::Number),
                _ => Value::Unknown,
            },
            "delete" => {
                if let Some(argument) = node.child(HirField::Argument) {
                    if let Some(target) = member_assignment_target(argument) {
                        let member = match self.member_reference(target, state, call_depth) {
                            Ok(member) => member,
                            Err(value) => return value,
                        };
                        return match self.delete_member(member, state) {
                            NodeMutation::Applies => Value::Bool(true),
                            NodeMutation::Ignored if self.strict => Value::SynchronousThrow,
                            NodeMutation::Ignored => Value::Bool(false),
                            NodeMutation::Unknown => {
                                self.complete = false;
                                self.draft.set_partial();
                                Value::Unknown
                            }
                        };
                    } else if let Some(value) =
                        self.assign_target(argument, Value::Unknown, state, call_depth)
                    {
                        return value;
                    }
                }
                Value::Bool(true)
            }
            _ => Value::Unknown,
        }
    }

    fn ternary(&mut self, node: &HirNode, state: &mut State, call_depth: usize) -> Value {
        let condition = node
            .child(HirField::Condition)
            .map_or(Value::Unknown, |value| self.eval(value, state, call_depth));
        if abrupt_value(&condition) {
            return condition;
        }
        let consequence = node.child(HirField::Consequence);
        let alternative = node.child(HirField::Alternative);
        match truthy(&condition) {
            Some(true) => {
                consequence.map_or(Value::Unknown, |value| self.eval(value, state, call_depth))
            }
            Some(false) => {
                alternative.map_or(Value::Unknown, |value| self.eval(value, state, call_depth))
            }
            None => {
                self.complete = false;
                let mut yes = state.clone();
                let mut no = state.clone();
                let saved_dominators = self.execution_dominators.clone();
                self.conditional_depth += 1;
                let yes_value = consequence.map_or(Value::Unknown, |value| {
                    self.eval(value, &mut yes, call_depth)
                });
                self.execution_dominators = saved_dominators.clone();
                let no_value = alternative.map_or(Value::Unknown, |value| {
                    self.eval(value, &mut no, call_depth)
                });
                self.conditional_depth -= 1;
                self.execution_dominators = saved_dominators;
                *state = join_states(yes, no);
                join_values(yes_value, no_value)
            }
        }
    }

    fn assignment(&mut self, node: &HirNode, state: &mut State, call_depth: usize) -> Value {
        let left = node.child(HirField::Left);
        let member = match left.and_then(member_assignment_target) {
            Some(target) => match self.member_reference(target, state, call_depth) {
                Ok(member) => Some(member),
                Err(value) => return value,
            },
            None => None,
        };
        let value = node
            .child(HirField::Right)
            .map_or(Value::Unknown, |right| self.eval(right, state, call_depth));
        if abrupt_value(&value) {
            return value;
        }
        if let Some(value) = self.store_assignment(member, left, value.clone(), state, call_depth) {
            return value;
        }
        value
    }

    fn store_assignment(
        &mut self,
        member: Option<MemberReference>,
        left: Option<&HirNode>,
        value: Value,
        state: &mut State,
        call_depth: usize,
    ) -> Option<Value> {
        if let Some(member) = member {
            match self.assign_member(member, value.clone(), state) {
                NodeMutation::Ignored if self.strict => return Some(Value::SynchronousThrow),
                NodeMutation::Ignored => {}
                NodeMutation::Applies => state.invalidate_node_module_escape(&value),
                NodeMutation::Unknown => {
                    state.invalidate_node_module_escape(&value);
                    self.complete = false;
                    self.draft.set_partial();
                }
            }
        } else if let Some(left) = left
            && let Some(value) = self.assign_target(left, value, state, call_depth)
        {
            return Some(value);
        }
        None
    }

    fn augmented_assignment(
        &mut self,
        node: &HirNode,
        state: &mut State,
        call_depth: usize,
    ) -> Value {
        let left = node
            .child(HirField::Left)
            .or_else(|| named_children(node).next());
        let member = match left.and_then(member_assignment_target) {
            Some(target) => match self.member_reference(target, state, call_depth) {
                Ok(member) => Some(member),
                Err(value) => return value,
            },
            None => None,
        };
        let left_value = if let Some(member) = &member {
            self.read_member(member, state)
        } else {
            left.map_or(Value::Unknown, |left| self.eval(left, state, call_depth))
        };
        if abrupt_value(&left_value) {
            return left_value;
        }
        let operator = node
            .child(HirField::Operator)
            .map_or("", |operator| self.text(operator));
        if matches!(operator, "&&=" | "||=" | "??=") {
            let assign = match operator {
                "&&=" => truthy(&left_value),
                "||=" => truthy(&left_value).map(|truthy| !truthy),
                "??=" => nullish(&left_value),
                _ => unreachable!(),
            };
            if assign == Some(false) {
                return left_value;
            }
            let Some(right) = node.child(HirField::Right) else {
                return Value::Unknown;
            };
            if assign == Some(true) {
                let value = self.eval(right, state, call_depth);
                if abrupt_value(&value) {
                    return value;
                }
                if let Some(value) =
                    self.store_assignment(member, left, value.clone(), state, call_depth)
                {
                    return value;
                }
                return value;
            }
            self.complete = false;
            self.draft.set_partial();
            let no = state.clone();
            let mut yes = state.clone();
            let saved_dominators = self.execution_dominators.clone();
            self.conditional_depth += 1;
            let value = self.eval(right, &mut yes, call_depth);
            if !abrupt_value(&value)
                && self
                    .store_assignment(member, left, value.clone(), &mut yes, call_depth)
                    .is_none()
            {
                *state = join_states(no, yes);
                self.conditional_depth -= 1;
                self.execution_dominators = saved_dominators;
                return join_values(left_value, value);
            }
            *state = no;
            self.conditional_depth -= 1;
            self.execution_dominators = saved_dominators;
            return left_value;
        }
        let right = node
            .child(HirField::Right)
            .map(|right| self.eval(right, state, call_depth));
        if let Some(value) = &right
            && abrupt_value(value)
        {
            return value.clone();
        }
        let replacement = Value::NonCallablePrimitive;
        if !augmented_coercion_proven(&left_value, right.as_ref(), state) {
            self.complete = false;
            self.draft.set_partial();
            if self.catchable_depth > 0 && member.as_ref().is_some_and(node_loader_reference) {
                return replacement;
            }
        }
        if let Some(value) =
            self.store_assignment(member, left, replacement.clone(), state, call_depth)
        {
            value
        } else {
            replacement
        }
    }

    fn assign_target(
        &mut self,
        node: &HirNode,
        value: Value,
        state: &mut State,
        call_depth: usize,
    ) -> Option<Value> {
        match node.kind() {
            HirKind::Identifier => state.assign(self.text(node), value),
            HirKind::ObjectPattern | HirKind::ArrayPattern => {
                return self.assign_pattern(node, value, state, BindingMode::Assign, call_depth);
            }
            HirKind::ParenthesizedExpression => {
                if let Some(target) = named_children(node).next() {
                    return self.assign_target(target, value, state, call_depth);
                }
            }
            HirKind::MemberExpression | HirKind::SubscriptExpression => {
                let member = match self.member_reference(node, state, call_depth) {
                    Ok(member) => member,
                    Err(value) => return Some(value),
                };
                return self.store_assignment(Some(member), None, value, state, call_depth);
            }
            _ => {}
        }
        None
    }

    fn member_reference(
        &mut self,
        node: &HirNode,
        state: &mut State,
        call_depth: usize,
    ) -> Result<MemberReference, Value> {
        let object = node
            .child(HirField::Object)
            .map_or(Value::Unknown, |object| {
                self.eval(object, state, call_depth)
            });
        if abrupt_value(&object) {
            return Err(object);
        }
        let property = if let Some(property) = node.child(HirField::Property) {
            Some(self.text(property).to_owned())
        } else {
            let value = node
                .child(HirField::Index)
                .map_or(Value::Unknown, |index| self.eval(index, state, call_depth));
            if abrupt_value(&value) {
                return Err(value);
            }
            string_coercion(&value)
        };
        Ok(MemberReference {
            object,
            property,
            prototype_mutation: prototype_mutation_target(self.text(node)),
        })
    }

    fn assign_node_property(
        &mut self,
        property: NodeProperty,
        replacement: Value,
        state: &mut State,
    ) -> NodeMutation {
        let current = state
            .node_properties
            .get(&property)
            .cloned()
            .unwrap_or_else(unknown_node_property);
        match current.assignment {
            NodeMutation::Ignored => NodeMutation::Ignored,
            NodeMutation::Applies => {
                let creates_own = current.own == Some(false);
                let property_state = state
                    .node_properties
                    .entry(property)
                    .or_insert_with(unknown_node_property);
                property_state.value = replacement;
                if creates_own {
                    property_state.own = Some(true);
                    property_state.kind = NodePropertyKind::Data;
                    property_state.enumerable = Some(true);
                    property_state.deletion = NodeMutation::Applies;
                }
                if node_property_loader_hook(property) {
                    state.invalidate_node_module_loader();
                }
                NodeMutation::Applies
            }
            NodeMutation::Unknown => {
                let property_state = state
                    .node_properties
                    .entry(property)
                    .or_insert_with(unknown_node_property);
                property_state.value = join_values(current.value, replacement);
                property_state.own = None;
                property_state.kind = NodePropertyKind::Unknown;
                property_state.enumerable = None;
                property_state.assignment = NodeMutation::Unknown;
                property_state.deletion = NodeMutation::Unknown;
                if node_property_loader_hook(property) {
                    state.invalidate_node_module_loader();
                }
                self.complete = false;
                self.draft.set_partial();
                NodeMutation::Unknown
            }
        }
    }

    fn define_node_property(
        &mut self,
        property: NodeProperty,
        arguments: &Arguments,
        state: &mut State,
    ) {
        let current = state
            .node_properties
            .get(&property)
            .cloned()
            .unwrap_or_else(unknown_node_property);
        let (defined, changes_value, uncertain) =
            defined_node_property(current, arguments.values.get(2));
        state.node_properties.insert(property, defined);
        if changes_value && node_property_loader_hook(property) {
            state.invalidate_node_module_loader();
        }
        if uncertain {
            self.complete = false;
            self.draft.set_partial();
        }
    }

    fn delete_node_property(&mut self, property: NodeProperty, state: &mut State) -> NodeMutation {
        let current = state
            .node_properties
            .get(&property)
            .cloned()
            .unwrap_or_else(unknown_node_property);
        if current.own == Some(false) {
            return NodeMutation::Applies;
        }
        match current.deletion {
            NodeMutation::Ignored => NodeMutation::Ignored,
            NodeMutation::Applies => {
                state
                    .node_properties
                    .insert(property, absent_node_property(property));
                if node_property_loader_hook(property) {
                    state.invalidate_node_module_loader();
                }
                NodeMutation::Applies
            }
            NodeMutation::Unknown => {
                let absent = absent_node_property(property);
                state.node_properties.insert(
                    property,
                    NodePropertyState {
                        value: join_values(current.value, absent.value),
                        own: None,
                        kind: NodePropertyKind::Unknown,
                        enumerable: None,
                        assignment: NodeMutation::Unknown,
                        deletion: NodeMutation::Unknown,
                    },
                );
                if node_property_loader_hook(property) {
                    state.invalidate_node_module_loader();
                }
                self.complete = false;
                self.draft.set_partial();
                NodeMutation::Unknown
            }
        }
    }

    fn assign_member(
        &mut self,
        member: MemberReference,
        replacement: Value,
        state: &mut State,
    ) -> NodeMutation {
        if member.prototype_mutation {
            state.prototype_integrity_known = false;
            self.complete = false;
            self.draft.set_partial();
        }
        if matches!(
            (&member.object, member.property.as_deref()),
            (Value::Object(properties), Some(property))
                if properties.get(property).is_some_and(accessor_value)
        ) {
            self.complete = false;
        }
        match (&member.object, member.property.as_deref()) {
            (Value::NodeModule, Some(property)) => {
                if let Some(property) = node_module_property(property) {
                    self.assign_node_property(property, replacement.clone(), state)
                } else {
                    NodeMutation::Applies
                }
            }
            (Value::NodeModule, None) => {
                state.invalidate_node_module_properties();
                NodeMutation::Unknown
            }
            (Value::NodeModulePrototype, Some("require")) => self.assign_node_property(
                NodeProperty::PrototypeRequire,
                replacement.clone(),
                state,
            ),
            (Value::NodeModulePrototype, Some("constructor")) => NodeMutation::Ignored,
            (Value::NodeModulePrototype, None) => {
                state.invalidate_node_module_properties();
                NodeMutation::Unknown
            }
            (Value::NodeModulePrototype, Some(_)) => NodeMutation::Applies,
            (Value::CommonJsModule, Some(property @ ("constructor" | "require"))) => {
                let property =
                    commonjs_module_property(property).expect("reviewed CommonJS property");
                self.assign_node_property(property, replacement.clone(), state)
            }
            (Value::CommonJsModule, None) => {
                state.invalidate_node_module_properties();
                NodeMutation::Unknown
            }
            (Value::CommonJsModule, Some(_)) => NodeMutation::Applies,
            (Value::Object(properties), Some(property))
                if properties
                    .get(property)
                    .is_none_or(|value| !accessor_value(value)) =>
            {
                let mut properties = properties.clone();
                properties.insert(property.to_owned(), replacement);
                state.replace_mutated_container(&member.object, &Value::Object(properties));
                NodeMutation::Applies
            }
            (Value::Array(values), Some(property)) => {
                let Some(index) = property
                    .parse::<usize>()
                    .ok()
                    .filter(|index| *index < MAX_COLLECTION_ITEMS && *index <= values.len())
                else {
                    state.forget_container(&member.object);
                    return NodeMutation::Unknown;
                };
                let mut values = values.clone();
                if index == values.len() {
                    values.push(replacement);
                } else {
                    values[index] = replacement;
                }
                state.replace_mutated_container(&member.object, &Value::Array(values));
                NodeMutation::Applies
            }
            (Value::LoadedModule(module), Some(_)) => {
                state.invalidate_loaded_module(*module);
                NodeMutation::Applies
            }
            (Value::Module(module), Some(property)) => {
                if *module == Module::Fs && property == "promises" {
                    state.invalidate_module(Module::FsPromises);
                } else if let Some(known) = module_member(*module, property) {
                    state.owned_members.remove(&(*module, known));
                    state.invalidate_loaded_module_cache(*module);
                } else {
                    state.invalidate_module(*module);
                }
                NodeMutation::Applies
            }
            _ => {
                state.invalidate_value(&member.object);
                NodeMutation::Unknown
            }
        }
    }

    fn delete_member(&mut self, member: MemberReference, state: &mut State) -> NodeMutation {
        match (&member.object, member.property.as_deref()) {
            (Value::Object(properties), Some(property)) => {
                let mut properties = properties.clone();
                properties.remove(property);
                state.replace_mutated_container(&member.object, &Value::Object(properties));
                NodeMutation::Applies
            }
            (Value::Array(values), Some(property)) => {
                let Some(index) = property
                    .parse::<usize>()
                    .ok()
                    .filter(|index| *index < values.len())
                else {
                    state.forget_container(&member.object);
                    return NodeMutation::Unknown;
                };
                let mut values = values.clone();
                values[index] = Value::Undefined;
                state.replace_mutated_container(&member.object, &Value::Array(values));
                NodeMutation::Applies
            }
            (Value::NodeModule, Some(property)) => {
                if let Some(property) = node_module_property(property) {
                    self.delete_node_property(property, state)
                } else {
                    NodeMutation::Unknown
                }
            }
            (Value::CommonJsModule, Some(property @ ("require" | "constructor"))) => {
                let property =
                    commonjs_module_property(property).expect("reviewed CommonJS property");
                self.delete_node_property(property, state)
            }
            (Value::NodeModulePrototype, Some("require")) => {
                self.delete_node_property(NodeProperty::PrototypeRequire, state)
            }
            (Value::NodeModulePrototype, Some("constructor")) => NodeMutation::Ignored,
            _ => {
                self.assign_member(member, Value::Unknown, state);
                NodeMutation::Unknown
            }
        }
    }

    fn assign_pattern(
        &mut self,
        node: &HirNode,
        value: Value,
        state: &mut State,
        mode: BindingMode,
        call_depth: usize,
    ) -> Option<Value> {
        match node.kind() {
            HirKind::Identifier | HirKind::ShorthandPropertyIdentifier => match mode {
                BindingMode::Assign | BindingMode::Var => {
                    state.assign(self.text(node), value);
                }
                BindingMode::Lexical => state.declare(self.text(node), value),
            },
            HirKind::ObjectPattern => {
                if abrupt_value(&value) {
                    return Some(value);
                }
                if matches!(value, Value::Undefined | Value::Null) {
                    return Some(Value::SynchronousThrow);
                }
                for child in named_children(node) {
                    match child.kind() {
                        HirKind::ShorthandPropertyIdentifier => {
                            let property = self.text(child).to_owned();
                            let selected = self.read_property(&value, &property, state);
                            if let Some(value) =
                                self.assign_pattern(child, selected, state, mode, call_depth)
                            {
                                return Some(value);
                            }
                        }
                        HirKind::Pair => {
                            let property = match child.child(HirField::Key) {
                                Some(key) => {
                                    match self.object_property_name(key, state, call_depth) {
                                        Ok(property) => property,
                                        Err(value) => return Some(value),
                                    }
                                }
                                None => None,
                            };
                            let selected = property.as_deref().map_or(Value::Unknown, |property| {
                                self.read_property(&value, property, state)
                            });
                            if let Some(target) = child.child(HirField::Value)
                                && let Some(value) =
                                    self.assign_pattern(target, selected, state, mode, call_depth)
                            {
                                return Some(value);
                            }
                        }
                        HirKind::AssignmentPattern => {
                            let property = child
                                .child(HirField::Left)
                                .map(|target| self.text(target).to_owned());
                            let selected = property.as_deref().map_or(Value::Unknown, |property| {
                                self.read_property(&value, property, state)
                            });
                            if let Some(value) =
                                self.assign_pattern(child, selected, state, mode, call_depth)
                            {
                                return Some(value);
                            }
                        }
                        _ => {
                            self.predeclare_pattern(child, state, matches!(mode, BindingMode::Var))
                        }
                    }
                }
            }
            HirKind::ArrayPattern => {
                let values = match &value {
                    Value::Array(values) => Some(values.clone()),
                    Value::String(value) => Some(
                        value
                            .chars()
                            .map(|value| Value::String(value.to_string()))
                            .collect(),
                    ),
                    value if exact_non_iterable(value) => {
                        return Some(Value::SynchronousThrow);
                    }
                    Value::SynchronousThrow | Value::Divergent => return Some(value),
                    _ => None,
                };
                for (index, child) in named_children(node).enumerate() {
                    let selected = values.as_ref().map_or(Value::Unknown, |values| {
                        values.get(index).cloned().unwrap_or(Value::Undefined)
                    });
                    if let Some(value) =
                        self.assign_pattern(child, selected, state, mode, call_depth)
                    {
                        return Some(value);
                    }
                }
            }
            HirKind::AssignmentPattern => {
                if let Some(target) = node.child(HirField::Left) {
                    let value = if value == Value::Undefined {
                        node.child(HirField::Right)
                            .map_or(Value::Unknown, |right| self.eval(right, state, call_depth))
                    } else {
                        value
                    };
                    if abrupt_value(&value) {
                        return Some(value);
                    }
                    if let Some(value) = self.assign_pattern(target, value, state, mode, call_depth)
                    {
                        return Some(value);
                    }
                }
            }
            HirKind::RestPattern => {
                if let Some(target) = named_children(node).next()
                    && let Some(value) =
                        self.assign_pattern(target, Value::Unknown, state, mode, call_depth)
                {
                    return Some(value);
                }
            }
            HirKind::MemberExpression | HirKind::SubscriptExpression
                if matches!(mode, BindingMode::Assign) =>
            {
                return self.assign_target(node, value, state, call_depth);
            }
            _ => {}
        }
        None
    }

    fn member(&mut self, node: &HirNode, state: &mut State, call_depth: usize) -> Value {
        let member = match self.member_reference(node, state, call_depth) {
            Ok(member) => member,
            Err(value) => return value,
        };
        self.read_member(&member, state)
    }

    fn read_member(&mut self, member: &MemberReference, state: &State) -> Value {
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

    fn call(&mut self, node: &HirNode, state: &mut State, call_depth: usize) -> Value {
        let awaited = self.awaited_call == Some(node as *const HirNode as usize);
        let function = node.child(HirField::Function);
        let direct_receiver = function.is_some_and(direct_receiver_expression);
        let tagged_template = node
            .child(HirField::Arguments)
            .is_some_and(|arguments| arguments.kind() == HirKind::TemplateString);
        let callable = function.map_or(Value::Unknown, |function| {
            self.eval(function, state, call_depth)
        });
        if abrupt_value(&callable) {
            return callable;
        }
        let mut arguments = node.child(HirField::Arguments).map_or_else(
            || Arguments {
                values: Vec::new(),
                complete: false,
                assembly_branches: Vec::new(),
            },
            |arguments| self.arguments(arguments, state, call_depth),
        );
        let mut branches = std::mem::take(&mut arguments.assembly_branches);
        let value = (|| {
            if let Some(value) = arguments.values.iter().find(|value| abrupt_value(value)) {
                return value.clone();
            }
            let selective_define_property =
                matches!(&callable, Value::Known(KnownFunction::DefineProperty));
            if !selective_define_property {
                for value in &arguments.values {
                    state.invalidate_node_module_escape(value);
                }
            }
            match callable {
                Value::Invalid => Value::SynchronousThrow,
                Value::SynchronousThrow | Value::Divergent => callable,
                Value::Promise | Value::RejectedPromise => Value::SynchronousThrow,
                callable if exact_non_callable(&callable) => Value::SynchronousThrow,
                Value::Require => self.require(arguments),
                Value::NodeModuleMember(NodeModuleMember::IsBuiltin) => Value::Unknown,
                Value::NodeModuleMember(
                    member @ (NodeModuleMember::Load | NodeModuleMember::Require),
                ) => {
                    debug_assert!(node_module_loader_hook(member));
                    let loaded = self.require(arguments);
                    state.invalidate_node_module_loader();
                    self.complete = false;
                    match loaded {
                        Value::Module(module) => Value::LoadedModule(module),
                        value => value,
                    }
                }
                Value::NodeModuleMember(member) => {
                    debug_assert!(node_module_loader_hook(member));
                    state.invalidate_node_module_loader();
                    self.complete = false;
                    Value::Unknown
                }
                Value::Eval => self.eval_source(arguments, state),
                Value::DenoCommandConstructor => Value::SynchronousThrow,
                Value::DynamicEvalResult => {
                    self.complete = false;
                    self.draft.set_partial();
                    state.widen();
                    Value::Unknown
                }
                Value::FunctionConstructor => self.dynamic_function(arguments, state),
                Value::DynamicFunction(body) => {
                    self.call_dynamic_function(body.as_deref(), arguments, state)
                }
                Value::Known(function)
                    if direct_receiver_required(&function) && !direct_receiver =>
                {
                    Value::SynchronousThrow
                }
                Value::Known(function) => {
                    self.call_known(function, arguments, state, call_depth, tagged_template)
                }
                Value::Function(function) => {
                    self.call_local(&function, arguments, state, call_depth, awaited)
                }
                Value::UnknownModuleMember(module) => {
                    state.invalidate_module(module);
                    state.cwd = NestedExecutionCwd::Unknown;
                    self.complete = false;
                    Value::Unknown
                }
                Value::UnknownReceiver(receiver) => {
                    state.invalidate_value(&receiver);
                    state.cwd = NestedExecutionCwd::Unknown;
                    self.complete = false;
                    Value::Unknown
                }
                _ => {
                    for value in &arguments.values {
                        state.invalidate_value(value);
                    }
                    state.cwd = NestedExecutionCwd::Unknown;
                    self.complete = false;
                    Value::Unknown
                }
            }
        })();
        self.close_assembly_branches(state, &mut branches);
        value
    }

    fn construct(&mut self, node: &HirNode, state: &mut State, call_depth: usize) -> Value {
        let constructor_node = node.child(HirField::Constructor);
        let constructor = constructor_node.map_or(Value::Unknown, |constructor| {
            self.eval(constructor, state, call_depth)
        });
        if abrupt_value(&constructor) {
            return constructor;
        }
        let mut arguments = node.child(HirField::Arguments).map_or_else(
            || Arguments {
                values: Vec::new(),
                complete: false,
                assembly_branches: Vec::new(),
            },
            |arguments| self.arguments(arguments, state, call_depth),
        );
        let mut branches = std::mem::take(&mut arguments.assembly_branches);
        let value = (|| {
            if let Some(value) = arguments.values.iter().find(|value| abrupt_value(value)) {
                return value.clone();
            }
            if constructor == Value::DenoCommandConstructor {
                let summary =
                    deno_command(&arguments, state.prototype_integrity_known, self.platform);
                let summary = attach_deno_command_source(summary, &arguments);
                return match summary {
                    RuntimeCallSummary::Effect(argv) => Value::DenoCommand(argv),
                    RuntimeCallSummary::EffectPartial(argv) => {
                        self.complete = false;
                        self.draft.set_partial();
                        Value::DenoCommand(argv)
                    }
                    RuntimeCallSummary::Partial => {
                        self.complete = false;
                        self.draft.set_partial();
                        Value::Unknown
                    }
                    RuntimeCallSummary::Invalid => Value::Invalid,
                };
            }
            if constructor == Value::Invalid {
                return Value::Invalid;
            }
            if constructor == Value::DynamicEvalResult {
                self.complete = false;
                self.draft.set_partial();
                state.widen();
                return Value::Unknown;
            }
            if constructor == Value::FunctionConstructor {
                return self.dynamic_function(arguments, state);
            }
            if let Value::DynamicFunction(body) = constructor {
                let value = self.call_dynamic_function(body.as_deref(), arguments, state);
                return if abrupt_value(&value) {
                    value
                } else {
                    Value::Object(BTreeMap::new())
                };
            }
            if let Value::Known(function) = constructor {
                return match function {
                    KnownFunction::Deno(member) if deno_member_constructible(member) => {
                        let value = self.call_known(
                            KnownFunction::Deno(member),
                            arguments,
                            state,
                            call_depth,
                            false,
                        );
                        if abrupt_value(&value) || member == DenoMember::WriteTextFile {
                            value
                        } else {
                            Value::Object(BTreeMap::new())
                        }
                    }
                    KnownFunction::BunShell => {
                        self.complete = false;
                        self.draft.set_partial();
                        state.widen();
                        Value::Unknown
                    }
                    KnownFunction::Deno(_)
                    | KnownFunction::DenoCommand(_, _)
                    | KnownFunction::Bun(_)
                    | KnownFunction::BunFile(_, _)
                    | KnownFunction::OpenClaw(_)
                    | KnownFunction::ProcessChdir => Value::SynchronousThrow,
                    function => {
                        for value in &arguments.values {
                            state.invalidate_value(value);
                        }
                        state.cwd = NestedExecutionCwd::Unknown;
                        self.complete = false;
                        let _ = function;
                        Value::Unknown
                    }
                };
            }
            if matches!(constructor, Value::Promise | Value::RejectedPromise) {
                return Value::SynchronousThrow;
            }
            for value in &arguments.values {
                state.invalidate_value(value);
            }
            state.cwd = NestedExecutionCwd::Unknown;
            self.complete = false;
            Value::Unknown
        })();
        self.close_assembly_branches(state, &mut branches);
        value
    }

    fn dynamic_function(&mut self, arguments: Arguments, state: &mut State) -> Value {
        if !arguments.complete {
            self.complete = false;
            self.draft.set_partial();
            state.widen();
            return Value::DynamicFunction(None);
        }
        let Some(values) = arguments
            .values
            .iter()
            .map(string_coercion)
            .collect::<Option<Vec<_>>>()
        else {
            self.complete = false;
            self.draft.set_partial();
            state.widen();
            return Value::DynamicFunction(None);
        };
        let (parameters, body) = values
            .split_last()
            .map_or((&[][..], ""), |(body, parameters)| {
                (parameters, body.as_str())
            });
        let Some(parameter_bytes) = parameters.iter().try_fold(0usize, |bytes, parameter| {
            bytes.checked_add(parameter.len())?.checked_add(1)
        }) else {
            self.budget.refuse();
            self.complete = false;
            self.draft.set_partial();
            state.widen();
            return Value::DynamicFunction(None);
        };
        let Some(source_bytes) = parameter_bytes.checked_add(body.len()) else {
            self.budget.refuse();
            self.complete = false;
            self.draft.set_partial();
            state.widen();
            return Value::DynamicFunction(None);
        };
        if !self.budget.enter_dynamic_source(source_bytes) {
            self.complete = false;
            self.draft.set_partial();
            state.widen();
            return Value::DynamicFunction(None);
        }
        match super::parser::javascript_dynamic_function(parameters, body) {
            Ok(true) => {
                let body = parameters.is_empty().then(|| body.to_owned());
                Value::DynamicFunction(body)
            }
            Ok(false)
            | Err(InlineRefusal::StructureIncomplete | InlineRefusal::StructureMismatch) => {
                Value::SynchronousThrow
            }
            Err(refusal) => {
                self.report.refuse(refusal);
                self.complete = false;
                self.draft.set_partial();
                state.widen();
                Value::DynamicFunction(None)
            }
        }
    }

    fn call_dynamic_function(
        &mut self,
        body: Option<&str>,
        arguments: Arguments,
        state: &mut State,
    ) -> Value {
        let Some(body) = body else {
            self.complete = false;
            self.draft.set_partial();
            state.widen();
            return Value::Unknown;
        };
        if !arguments.complete || !self.budget.enter_dynamic_source(body.len()) {
            self.complete = false;
            self.draft.set_partial();
            state.widen();
            return Value::Unknown;
        }
        if self.depth + 1 >= 16 {
            self.report.refuse(InlineRefusal::RecursionLimit);
            self.complete = false;
            self.draft.set_partial();
            state.widen();
            return Value::Unknown;
        }
        let module = match super::parser::javascript_function_body(body) {
            Ok(module) if module.executable() => module,
            Ok(_) | Err(InlineRefusal::StructureIncomplete | InlineRefusal::StructureMismatch) => {
                return Value::SynchronousThrow;
            }
            Err(refusal) => {
                self.report.refuse(refusal);
                self.complete = false;
                self.draft.set_partial();
                state.widen();
                return Value::Unknown;
            }
        };
        let mut nested = Interpreter {
            source: body,
            home: self.home,
            platform: self.platform,
            depth: self.depth + 1,
            profile: Profile {
                syntax: SyntaxProfile::JavaScript,
                ..self.profile
            },
            strict: strict_directive(module.root(), body),
            report: InlineReport::default(),
            draft: LanguageDraft::default(),
            complete: true,
            budget: Budget::default(),
            return_value: Value::Undefined,
            conditional_depth: self.conditional_depth,
            catchable_depth: self.catchable_depth,
            execution_dominators: Vec::new(),
            awaited_call: None,
            async_frames: Vec::new(),
        };
        let mut nested_state = state.dynamic_global(self.profile.ownership);
        nested_state.push_scope(true);
        nested.hoist_vars(module.root(), &mut nested_state);
        let control = nested.exec_sequence(module.root(), &mut nested_state, false, 0);
        nested_state.pop_scope();
        let failed = nested.budget.refusal.is_some();
        if let Some(refusal) = nested.budget.refusal {
            nested.report.refuse(refusal);
            nested.draft.set_partial();
        }
        if !nested.complete {
            nested.draft.set_partial();
        }
        let return_value = nested.return_value.clone();
        self.report.extend(nested.report);
        self.merge_nested_draft(&nested.draft, &nested.execution_dominators);
        self.complete &= nested.complete;
        self.budget.absorb(nested.budget);
        if source_mutates(module.root()) || failed || !nested.complete {
            self.complete = false;
            self.draft.set_partial();
            state.widen();
        }
        let value = match control {
            Control::Next => Value::Undefined,
            Control::Return => return_value,
            Control::Throw => Value::SynchronousThrow,
            Control::Diverge => Value::Divergent,
            Control::Break | Control::Continue => Value::SynchronousThrow,
        };
        if contains_local_function(&value) {
            self.complete = false;
            self.draft.set_partial();
            state.widen();
            Value::Unknown
        } else {
            value
        }
    }

    fn arguments(&mut self, node: &HirNode, state: &mut State, call_depth: usize) -> Arguments {
        let mut arguments = Arguments {
            values: Vec::new(),
            complete: !delimited_has_hole(node, self.source),
            assembly_branches: Vec::new(),
        };
        let mut branches = Vec::new();
        for child in named_children(node) {
            if child.kind() == HirKind::SpreadElement {
                let value = named_children(child)
                    .next()
                    .map_or(Value::Unknown, |value| self.eval(value, state, call_depth));
                if abrupt_value(&value) {
                    arguments.values.push(value);
                    break;
                }
                if exact_non_iterable(&value) {
                    arguments.values.push(Value::SynchronousThrow);
                    break;
                }
                match value {
                    Value::Array(values)
                        if arguments.values.len() + values.len() <= MAX_COLLECTION_ITEMS =>
                    {
                        arguments.values.extend(values);
                    }
                    Value::String(value)
                        if arguments.values.len() + value.chars().count()
                            <= MAX_COLLECTION_ITEMS =>
                    {
                        arguments
                            .values
                            .extend(value.chars().map(|value| Value::String(value.to_string())));
                    }
                    Value::Array(_) | Value::String(_) => arguments.complete = false,
                    _ => {
                        arguments.complete = false;
                        self.start_assembly_branch(state, &mut branches);
                    }
                }
            } else {
                let value = self.eval(child, state, call_depth);
                let abrupt = abrupt_value(&value);
                arguments.values.push(value);
                if abrupt {
                    break;
                }
            }
            if arguments.values.len() > MAX_COLLECTION_ITEMS {
                arguments.complete = false;
                arguments.values.truncate(MAX_COLLECTION_ITEMS);
                self.budget.refuse();
                break;
            }
        }
        if !arguments.complete {
            self.complete = false;
        }
        arguments.assembly_branches = branches;
        arguments
    }

    fn require(&mut self, arguments: Arguments) -> Value {
        if !arguments.complete || arguments.values.len() != 1 {
            self.complete = false;
            return Value::Unknown;
        }
        let value =
            arguments
                .values
                .first()
                .and_then(value_string)
                .map_or(Value::Unknown, |source| match source {
                    "module" | "node:module" => Value::NodeModule,
                    source => module_from_source(source).map_or(Value::Unknown, Value::Module),
                });
        if value == Value::Unknown {
            self.complete = false;
        }
        value
    }

    fn eval_source(&mut self, arguments: Arguments, state: &mut State) -> Value {
        if !arguments.complete {
            self.complete = false;
            self.draft.set_partial();
            state.widen();
            return Value::Unknown;
        }
        let Some(value) = arguments.values.first() else {
            return Value::Undefined;
        };
        let source = match value {
            Value::String(source) => source,
            Value::Unknown | Value::UnknownModuleMember(_) | Value::UnknownReceiver(_) => {
                self.complete = false;
                self.draft.set_partial();
                state.widen();
                return Value::Unknown;
            }
            value => return value.clone(),
        };
        if !self.budget.enter_dynamic_source(source.len()) {
            self.complete = false;
            self.draft.set_partial();
            state.widen();
            return Value::Unknown;
        }
        if self.depth + 1 >= 16 {
            self.report.refuse(InlineRefusal::RecursionLimit);
            self.complete = false;
            state.widen();
            return Value::Unknown;
        }
        let module = match super::parser::javascript(source) {
            Ok(module) if module.executable() && named_children(module.root()).next().is_none() => {
                return Value::Undefined;
            }
            Ok(module) if module.executable() => module,
            Ok(_) => return Value::SynchronousThrow,
            Err(InlineRefusal::StructureIncomplete | InlineRefusal::StructureMismatch) => {
                return Value::SynchronousThrow;
            }
            Err(refusal) => {
                self.report.refuse(refusal);
                self.complete = false;
                state.widen();
                return Value::Unknown;
            }
        };
        let mutates = source_mutates(module.root());
        let mut nested = Interpreter {
            source,
            home: self.home,
            platform: self.platform,
            depth: self.depth + 1,
            profile: Profile {
                syntax: SyntaxProfile::JavaScript,
                ..self.profile
            },
            strict: self.strict
                || strict_directive(module.root(), source)
                || source_is_module(module.root()),
            report: InlineReport::default(),
            draft: LanguageDraft::default(),
            complete: true,
            budget: Budget::default(),
            return_value: Value::Undefined,
            conditional_depth: self.conditional_depth,
            catchable_depth: self.catchable_depth,
            execution_dominators: Vec::new(),
            awaited_call: None,
            async_frames: Vec::new(),
        };
        let mut nested_state = state.clone();
        nested.hoist_vars(module.root(), &mut nested_state);
        let nested_control = nested.exec_sequence(module.root(), &mut nested_state, false, 0);
        let failed = nested.budget.refusal.is_some();
        if let Some(refusal) = nested.budget.refusal {
            nested.report.refuse(refusal);
            nested.draft.set_partial();
        }
        if !nested.complete {
            nested.draft.set_partial();
        }
        self.report.extend(nested.report);
        self.merge_nested_draft(&nested.draft, &nested.execution_dominators);
        self.complete &= nested.complete;
        self.budget.absorb(nested.budget);
        if mutates || failed {
            state.widen();
        } else {
            *state = nested_state;
        }
        match nested_control {
            Control::Next => Value::DynamicEvalResult,
            Control::Throw | Control::Return | Control::Break | Control::Continue => {
                Value::SynchronousThrow
            }
            Control::Diverge => Value::Divergent,
        }
    }

    fn merge_nested_draft(&mut self, nested: &LanguageDraft, nested_dominators: &[usize]) {
        if !nested.complete() {
            self.draft.set_partial();
        }
        let external_dominators = self.execution_dominators.clone();
        let mut ordinals = Vec::with_capacity(nested.calls().len());
        for call in nested.calls() {
            let mut dominators = external_dominators.clone();
            dominators.extend(
                call.execution_dominators()
                    .iter()
                    .filter_map(|ordinal| ordinals.get(*ordinal).copied().flatten()),
            );
            dominators.sort_unstable();
            dominators.dedup();
            let call = LanguageCall::new(
                call.kind(),
                call.input().clone(),
                call.filesystems().to_vec(),
                call.endpoint().map(str::to_owned),
                call.conditional_depth(),
                dominators,
            );
            ordinals.push(self.draft.push_call(call));
        }
        for flow in nested.flows() {
            if let (Some(Some(from)), Some(Some(to))) =
                (ordinals.get(flow.from()), ordinals.get(flow.to()))
            {
                self.draft.push_flow(*from, *to);
            }
        }
        self.execution_dominators.extend(
            nested_dominators
                .iter()
                .filter_map(|ordinal| ordinals.get(*ordinal).copied().flatten()),
        );
        self.execution_dominators.sort_unstable();
        self.execution_dominators.dedup();
    }

    fn materialize_property_descriptor(
        &mut self,
        descriptor: Value,
        state: &mut State,
        call_depth: usize,
    ) -> Result<Value, Value> {
        let Value::Object(mut properties) = descriptor else {
            return Ok(descriptor);
        };
        for property in [
            "enumerable",
            "configurable",
            "value",
            "writable",
            "get",
            "set",
        ] {
            let value = match properties.get(property).cloned() {
                Some(Value::AccessorGetter(getter)) => self.call_local(
                    &getter,
                    Arguments {
                        values: Vec::new(),
                        complete: true,
                        assembly_branches: Vec::new(),
                    },
                    state,
                    call_depth,
                    false,
                ),
                Some(Value::Accessor) => Value::Undefined,
                _ => continue,
            };
            if abrupt_value(&value) {
                return Err(value);
            }
            properties.insert(property.to_owned(), value);
        }
        Ok(Value::Object(properties))
    }

    fn call_known(
        &mut self,
        function: KnownFunction,
        mut arguments: Arguments,
        state: &mut State,
        call_depth: usize,
        _tagged_template: bool,
    ) -> Value {
        match function {
            KnownFunction::DefineProperty => {
                let target = arguments.values.first().cloned().unwrap_or(Value::Unknown);
                if invalid_define_property_target(&target) {
                    return Value::SynchronousThrow;
                }
                if arguments.complete
                    && let Some(descriptor) = arguments.values.get(2).cloned()
                {
                    match self.materialize_property_descriptor(descriptor, state, call_depth) {
                        Ok(descriptor) => arguments.values[2] = descriptor,
                        Err(value) => return value,
                    }
                }
                if arguments.complete
                    && (arguments.values.len() < 3
                        || arguments
                            .values
                            .get(2)
                            .is_some_and(invalid_property_descriptor))
                {
                    return Value::SynchronousThrow;
                }
                if arguments.complete
                    && let Some(property) = node_define_property_target(&arguments)
                    && state.node_properties.get(&property).is_some_and(|current| {
                        arguments.values.get(2).is_some_and(|descriptor| {
                            invalid_node_property_redefinition(current, descriptor)
                        })
                    })
                {
                    return Value::SynchronousThrow;
                }
                if arguments.complete && invalid_node_prototype_constructor_definition(&arguments) {
                    return Value::SynchronousThrow;
                }
                self.complete = false;
                if arguments.values.first().is_none_or(unknown_value) {
                    state.prototype_integrity_known = false;
                }
                let reviewed_node_definition = arguments.complete
                    && arguments.values.len() >= 3
                    && node_define_property_target(&arguments).is_some();
                if !reviewed_node_definition {
                    for value in arguments.values.iter().skip(1) {
                        state.invalidate_node_module_escape(value);
                    }
                }
                if let Some(Value::NodeModule) = arguments.values.first() {
                    if arguments.complete && arguments.values.len() >= 3 {
                        if let Some(property) = arguments.values.get(1).and_then(value_string)
                            && let Some(property) = node_module_property(property)
                        {
                            self.define_node_property(property, &arguments, state);
                        } else if arguments.values.get(1).and_then(value_string).is_none() {
                            state.invalidate_node_module_properties();
                        }
                    } else {
                        state.invalidate_node_module_properties();
                    }
                } else if let Some(Value::NodeModulePrototype) = arguments.values.first() {
                    if arguments.complete && arguments.values.len() >= 3 {
                        if arguments.values.get(1).and_then(value_string) == Some("require") {
                            self.define_node_property(
                                NodeProperty::PrototypeRequire,
                                &arguments,
                                state,
                            );
                        } else if arguments.values.get(1).and_then(value_string).is_none() {
                            state.invalidate_node_module_properties();
                        }
                    } else {
                        state.invalidate_node_module_properties();
                    }
                } else if let Some(Value::CommonJsModule) = arguments.values.first() {
                    if arguments.complete && arguments.values.len() >= 3 {
                        if let Some(property) = arguments.values.get(1).and_then(value_string)
                            && let Some(property) = commonjs_module_property(property)
                        {
                            self.define_node_property(property, &arguments, state);
                        } else if arguments.values.get(1).and_then(value_string).is_none() {
                            state.invalidate_node_module_properties();
                        }
                    } else {
                        state.invalidate_node_module_properties();
                    }
                } else if let Some(Value::Object(_) | Value::Array(_)) = arguments.values.first() {
                    if arguments.complete
                        && arguments.values.len() >= 3
                        && arguments.values.get(1).and_then(value_string).is_some()
                    {
                        state.forget_container(&arguments.values[0]);
                    } else {
                        state.invalidate_value(&arguments.values[0]);
                    }
                } else if let Some(Value::Module(module)) = arguments.values.first() {
                    if arguments.complete
                        && arguments.values.len() >= 3
                        && let Some(property) = arguments.values.get(1).and_then(value_string)
                        && let Some(member) = module_member(*module, property)
                    {
                        state.owned_members.remove(&(*module, member));
                    } else {
                        state.invalidate_module(*module);
                    }
                } else if let Some(value) = arguments.values.first() {
                    state.invalidate_value(value);
                }
                target
            }
            KnownFunction::SetPrototypeOf => {
                self.complete = false;
                self.draft.set_partial();
                state.prototype_integrity_known = false;
                arguments.values.first().cloned().unwrap_or(Value::Unknown)
            }
            KnownFunction::Fs(module, member) => {
                match summarize_fs_call(module, member, &arguments) {
                    FsCallSummary::Effect(filesystems) => {
                        let ordinal = self.emit_call(
                            LanguageCallKind::DirectFile,
                            fs_callable(module, member),
                            &arguments,
                            state,
                            filesystems,
                        );
                        if fs_callback_unmodeled(module, member) {
                            self.complete = false;
                            self.draft.set_partial();
                            if let Some(Value::Function(callback)) = arguments.values.last() {
                                self.analyze_callback(callback, state, call_depth, ordinal);
                            }
                        }
                    }
                    FsCallSummary::EffectPartial(filesystems) => {
                        self.emit_call(
                            LanguageCallKind::DirectFile,
                            fs_callable(module, member),
                            &arguments,
                            state,
                            filesystems,
                        );
                        self.complete = false;
                        self.draft.set_partial();
                    }
                    FsCallSummary::Partial => {
                        self.complete = false;
                        self.draft.set_partial();
                    }
                    FsCallSummary::Invalid => {}
                }
                fs_return_value(module, member)
            }
            KnownFunction::ProcessChdir => {
                if !arguments.complete || arguments.values.len() != 1 {
                    return Value::SynchronousThrow;
                }
                match &arguments.values[0] {
                    Value::String(path) if !path.is_empty() && !path.contains('\0') => {
                        self.emit_call(
                            LanguageCallKind::LocalUtility,
                            "process.chdir",
                            &arguments,
                            state,
                            Vec::new(),
                        );
                        state.cwd = state.cwd.changed(path, self.platform);
                        Value::Undefined
                    }
                    value if unknown_value(value) => {
                        self.complete = false;
                        self.draft.set_partial();
                        state.cwd = NestedExecutionCwd::Unknown;
                        Value::Unknown
                    }
                    _ => Value::SynchronousThrow,
                }
            }
            KnownFunction::Child(member) => {
                match summarize_child_call(member, &arguments, self.platform, &state.cwd) {
                    ChildCallSummary::Call {
                        kind,
                        execution,
                        callback,
                        partial,
                    } => {
                        let ordinal = self.emit_call(
                            kind,
                            child_callable(member),
                            &arguments,
                            state,
                            Vec::new(),
                        );
                        match execution {
                            ChildExecution::Command { argv, cwd } => {
                                super::super::common::add_exact_argv_at(
                                    &mut self.report,
                                    argv,
                                    cwd,
                                    false,
                                );
                            }
                            ChildExecution::Bash { code, cwd } => {
                                super::super::common::add_exact_shell_program_at(
                                    &mut self.report,
                                    "bash",
                                    &code,
                                    cwd,
                                    false,
                                );
                            }
                            ChildExecution::OpaqueShell { program, code, cwd } => {
                                super::super::common::add_exact_shell_program_at(
                                    &mut self.report,
                                    &program,
                                    &code,
                                    cwd,
                                    false,
                                );
                            }
                            ChildExecution::None => {}
                        }
                        if let Some(index) = callback
                            && let Some(Value::Function(callback)) = arguments.values.get(index)
                        {
                            self.analyze_callback(callback, state, call_depth, ordinal);
                        }
                        if partial {
                            self.complete = false;
                            self.draft.set_partial();
                        }
                        Value::Object(BTreeMap::new())
                    }
                    ChildCallSummary::Partial => {
                        self.complete = false;
                        self.draft.set_partial();
                        Value::Unknown
                    }
                    ChildCallSummary::Invalid => Value::Unknown,
                }
            }
            KnownFunction::Deno(DenoMember::Chdir) => {
                if !arguments.complete || arguments.values.len() != 1 {
                    return Value::SynchronousThrow;
                }
                match &arguments.values[0] {
                    Value::String(path) if !path.is_empty() && !path.contains('\0') => {
                        self.emit_call(
                            LanguageCallKind::LocalUtility,
                            "Deno.chdir",
                            &arguments,
                            state,
                            Vec::new(),
                        );
                        state.cwd = state.cwd.changed(path, self.platform);
                        Value::Undefined
                    }
                    value if unknown_value(value) => {
                        self.complete = false;
                        self.draft.set_partial();
                        state.cwd = NestedExecutionCwd::Unknown;
                        Value::Unknown
                    }
                    _ => Value::SynchronousThrow,
                }
            }
            KnownFunction::Deno(member) => {
                let summary =
                    summarize_deno_call(member, &arguments, state.prototype_integrity_known);
                match summary {
                    FsCallSummary::Effect(filesystems) => {
                        self.emit_call(
                            LanguageCallKind::DirectFile,
                            deno_callable(member),
                            &arguments,
                            state,
                            filesystems,
                        );
                    }
                    FsCallSummary::EffectPartial(filesystems) => {
                        self.emit_call(
                            LanguageCallKind::DirectFile,
                            deno_callable(member),
                            &arguments,
                            state,
                            filesystems,
                        );
                        self.complete = false;
                        self.draft.set_partial();
                    }
                    FsCallSummary::Partial => {
                        self.complete = false;
                        self.draft.set_partial();
                    }
                    FsCallSummary::Invalid if deno_member_synchronous(member) => {
                        return Value::SynchronousThrow;
                    }
                    FsCallSummary::Invalid => return Value::RejectedPromise,
                }
                if deno_member_synchronous(member) {
                    Value::Unknown
                } else {
                    Value::Promise
                }
            }
            KnownFunction::DenoCommand(member, command) => {
                if !arguments.complete {
                    self.complete = false;
                    self.draft.set_partial();
                    return Value::Unknown;
                }
                let command = match refresh_deno_command(
                    command,
                    state.prototype_integrity_known,
                    self.platform,
                ) {
                    RuntimeCallSummary::Effect(command) => command,
                    RuntimeCallSummary::EffectPartial(command) => {
                        self.complete = false;
                        self.draft.set_partial();
                        command
                    }
                    RuntimeCallSummary::Partial => {
                        self.complete = false;
                        self.draft.set_partial();
                        return Value::Unknown;
                    }
                    RuntimeCallSummary::Invalid => return Value::SynchronousThrow,
                };
                let cwd = match &command.cwd {
                    NestedExecutionCwd::Inherited => state.cwd.clone(),
                    NestedExecutionCwd::Path(path) => state.cwd.changed(path, self.platform),
                    NestedExecutionCwd::Unknown => NestedExecutionCwd::Unknown,
                };
                let context_exact = command.context_exact && cwd != NestedExecutionCwd::Unknown;
                let evidence = Arguments {
                    values: vec![command.argv.as_ref().map_or(Value::Unknown, |argv| {
                        Value::Array(argv.iter().cloned().map(Value::String).collect())
                    })],
                    complete: true,
                    assembly_branches: Vec::new(),
                };
                let certainty = if member == DenoCommandMember::Spawn {
                    command.spawn
                } else {
                    command.output
                };
                if certainty == ExecutionCertainty::Known {
                    self.emit_call(
                        LanguageCallKind::LocalUtility,
                        deno_command_callable(member),
                        &evidence,
                        state,
                        Vec::new(),
                    );
                    if context_exact && let Some(argv) = command.argv.clone() {
                        let stdout_inherited = if member == DenoCommandMember::Spawn {
                            command.spawn_stdout_inherited
                        } else {
                            command.output_stdout_inherited
                        };
                        if stdout_inherited {
                            super::super::common::add_exact_argv_at(
                                &mut self.report,
                                argv,
                                cwd.clone(),
                                true,
                            );
                        } else {
                            super::super::common::add_exact_argv_at(
                                &mut self.report,
                                argv,
                                cwd.clone(),
                                false,
                            );
                        }
                    }
                } else if certainty == ExecutionCertainty::Unknown {
                    self.emit_call(
                        LanguageCallKind::LocalUtility,
                        deno_command_callable(member),
                        &evidence,
                        state,
                        Vec::new(),
                    );
                    self.complete = false;
                    self.draft.set_partial();
                } else {
                    return Value::SynchronousThrow;
                }
                if certainty == ExecutionCertainty::Known
                    && (!context_exact || command.argv.is_none())
                {
                    self.complete = false;
                    self.draft.set_partial();
                }
                let throws_after_effect = match member {
                    DenoCommandMember::Spawn => command.spawn_throws_after_effect,
                    DenoCommandMember::Output => command.output_throws_after_effect,
                    DenoCommandMember::OutputSync => false,
                };
                if throws_after_effect {
                    return Value::SynchronousThrow;
                }
                if member == DenoCommandMember::Output {
                    Value::Promise
                } else {
                    Value::Object(BTreeMap::new())
                }
            }
            KnownFunction::Bun(member) => match member {
                BunMember::File => match bun_file(&arguments, state.prototype_integrity_known) {
                    RuntimeCallSummary::Effect(path) => Value::BunFile(path),
                    RuntimeCallSummary::EffectPartial(path) => {
                        self.complete = false;
                        self.draft.set_partial();
                        Value::BunFile(path)
                    }
                    RuntimeCallSummary::Partial => {
                        self.complete = false;
                        self.draft.set_partial();
                        Value::Unknown
                    }
                    RuntimeCallSummary::Invalid => Value::SynchronousThrow,
                },
                BunMember::Spawn | BunMember::SpawnSync => {
                    match bun_spawn_argv(
                        &arguments,
                        state.prototype_integrity_known,
                        &state.cwd,
                        self.platform,
                    ) {
                        RuntimeCallSummary::Effect(summary) => {
                            self.emit_call(
                                LanguageCallKind::LocalUtility,
                                bun_callable(member),
                                &arguments,
                                state,
                                Vec::new(),
                            );
                            if summary.context_exact
                                && let Some(argv) = summary.argv
                            {
                                super::super::common::add_exact_argv_at(
                                    &mut self.report,
                                    argv,
                                    summary.cwd,
                                    summary.stdout_inherited,
                                );
                            } else {
                                self.complete = false;
                                self.draft.set_partial();
                            }
                            Value::Object(BTreeMap::new())
                        }
                        RuntimeCallSummary::EffectPartial(_summary) => {
                            self.emit_call(
                                LanguageCallKind::LocalUtility,
                                bun_callable(member),
                                &arguments,
                                state,
                                Vec::new(),
                            );
                            self.complete = false;
                            self.draft.set_partial();
                            Value::Object(BTreeMap::new())
                        }
                        RuntimeCallSummary::Partial => {
                            self.emit_call(
                                LanguageCallKind::LocalUtility,
                                bun_callable(member),
                                &arguments,
                                state,
                                Vec::new(),
                            );
                            self.complete = false;
                            self.draft.set_partial();
                            Value::Object(BTreeMap::new())
                        }
                        RuntimeCallSummary::Invalid => Value::SynchronousThrow,
                    }
                }
                BunMember::Write => {
                    match summarize_bun_write(&arguments, state.prototype_integrity_known) {
                        FsCallSummary::Effect(filesystems) => {
                            self.emit_call(
                                LanguageCallKind::DirectFile,
                                bun_callable(member),
                                &arguments,
                                state,
                                filesystems,
                            );
                            Value::Promise
                        }
                        FsCallSummary::EffectPartial(filesystems) => {
                            self.emit_call(
                                LanguageCallKind::DirectFile,
                                bun_callable(member),
                                &arguments,
                                state,
                                filesystems,
                            );
                            self.complete = false;
                            self.draft.set_partial();
                            Value::Promise
                        }
                        FsCallSummary::Partial => {
                            self.complete = false;
                            self.draft.set_partial();
                            Value::Promise
                        }
                        FsCallSummary::Invalid => Value::SynchronousThrow,
                    }
                }
            },
            KnownFunction::BunFile(member, path) => {
                if !arguments.complete {
                    self.complete = false;
                    self.draft.set_partial();
                    return Value::Unknown;
                }
                let operation = if member == BunFileMember::Delete {
                    FilesystemOperation::Delete
                } else {
                    FilesystemOperation::Read
                };
                self.emit_call(
                    LanguageCallKind::DirectFile,
                    bun_file_callable(member),
                    &arguments,
                    state,
                    vec![LanguageFilesystem::new(path, operation, false)],
                );
                Value::Promise
            }
            KnownFunction::BunShell => {
                self.complete = false;
                self.draft.set_partial();
                Value::Promise
            }
            KnownFunction::OpenClaw(member) => match summarize_openclaw_call(&arguments) {
                RuntimeCallSummary::Partial => {
                    let _ = member;
                    self.complete = false;
                    self.draft.set_partial();
                    Value::Promise
                }
                RuntimeCallSummary::Effect(()) | RuntimeCallSummary::EffectPartial(()) => {
                    Value::Promise
                }
                RuntimeCallSummary::Invalid => Value::RejectedPromise,
            },
        }
    }

    fn analyze_callback(
        &mut self,
        callback: &LocalFunction,
        state: &State,
        call_depth: usize,
        dominator: Option<usize>,
    ) {
        let Some(parameters) = &callback.parameters else {
            return;
        };
        let arguments = Arguments {
            values: vec![Value::Unknown; parameters.len()],
            complete: true,
            assembly_branches: Vec::new(),
        };
        let mut callback_state = state.clone();
        let prior_conditional_depth = self.conditional_depth;
        let prior_dominators = self.execution_dominators.clone();
        let prior_return_value = self.return_value.clone();
        self.conditional_depth = self.conditional_depth.saturating_add(1);
        if let Some(dominator) = dominator {
            self.execution_dominators.push(dominator);
        }
        self.call_local(callback, arguments, &mut callback_state, call_depth, false);
        self.conditional_depth = prior_conditional_depth;
        self.execution_dominators = prior_dominators;
        self.return_value = prior_return_value;
    }

    fn emit_call(
        &mut self,
        kind: LanguageCallKind,
        callable: &str,
        arguments: &Arguments,
        state: &State,
        filesystems: Vec<LanguageFilesystem>,
    ) -> Option<usize> {
        let mut unresolved_filesystem = false;
        let filesystems = filesystems
            .into_iter()
            .map(|mut filesystem| {
                if let Some(requested) = filesystem.requested().map(str::to_owned)
                    && !is_absolute(&requested, self.platform)
                {
                    if let Some(requested) = state.cwd.resolve(&requested, self.platform) {
                        filesystem = filesystem.with_requested(requested);
                    } else {
                        filesystem = filesystem.without_requested();
                        unresolved_filesystem = true;
                    }
                }
                filesystem
            })
            .collect::<Vec<_>>();
        let input = language_call_input(self.profile.syntax, callable, arguments);
        if !input.complete()
            || unresolved_filesystem
            || filesystems
                .iter()
                .any(|filesystem| filesystem.requested().is_none())
        {
            self.draft.set_partial();
        }
        let call = LanguageCall::new(
            kind,
            input,
            filesystems,
            None,
            self.conditional_depth,
            self.execution_dominators.clone(),
        );
        let ordinal = self.draft.push_call(call)?;
        if self.conditional_depth > 0 {
            self.execution_dominators.push(ordinal);
        }
        Some(ordinal)
    }

    fn call_local(
        &mut self,
        function: &LocalFunction,
        arguments: Arguments,
        state: &mut State,
        call_depth: usize,
        awaited: bool,
    ) -> Value {
        if call_depth >= MAX_CALL_DEPTH || !arguments.complete {
            self.complete = false;
            return Value::Unknown;
        }
        if function
            .captured_scopes
            .iter()
            .any(|id| !state.scopes.iter().any(|scope| scope.id == *id))
        {
            self.complete = false;
            return Value::Unknown;
        }
        if function.source_identity != self.source.as_ptr() as usize {
            self.complete = false;
            self.draft.set_partial();
            state.widen();
            return Value::Unknown;
        }
        let Some(parameters) = &function.parameters else {
            self.complete = false;
            return Value::Unknown;
        };
        if parameters.len() != arguments.values.len() {
            self.complete = false;
            return Value::Unknown;
        }
        let caller_chain =
            std::mem::replace(&mut state.scope_chain, function.captured_scopes.clone());
        let caller_strict = std::mem::replace(&mut self.strict, function.strict);
        state.push_scope(true);
        for (name, value) in parameters.iter().zip(arguments.values) {
            state.declare(name, value);
        }
        self.hoist_vars(&function.body, state);
        self.return_value = Value::Undefined;
        self.async_frames.push(AsyncFrame {
            deferred: function.asynchronous && !awaited,
            prefix: None,
        });
        let value = if function.expression_body {
            self.eval(&function.body, state, call_depth + 1)
        } else {
            let control = self.exec_sequence(&function.body, state, false, call_depth + 1);
            match control {
                Control::Return => self.return_value.clone(),
                Control::Throw => Value::SynchronousThrow,
                Control::Diverge => Value::Divergent,
                Control::Next | Control::Break | Control::Continue => Value::Undefined,
            }
        };
        let async_frame = self
            .async_frames
            .pop()
            .expect("local function execution has an async frame");
        if let Some(mut prefix) = async_frame.prefix {
            prefix
                .scopes
                .retain(|scope| caller_chain.contains(&scope.id));
            prefix.scope_chain.clone_from(&caller_chain);
            *state = prefix;
        } else {
            state.pop_scope();
            state.scope_chain.clone_from(&caller_chain);
        }
        self.strict = caller_strict;
        if function.asynchronous {
            match value {
                Value::Divergent => Value::Divergent,
                Value::SynchronousThrow | Value::RejectedPromise => Value::RejectedPromise,
                _ => Value::Promise,
            }
        } else {
            value
        }
    }

    fn function_value(&mut self, node: &HirNode, state: &State) -> Option<Value> {
        if !self.budget.add_function() {
            return None;
        }
        let parameters = self.parameters(node);
        let body = node.child(HirField::Body)?.clone();
        Some(Value::Function(Arc::new(LocalFunction {
            parameters,
            expression_body: body.kind() != HirKind::StatementBlock,
            asynchronous: asynchronous_function(node, self.source),
            strict: self.strict || strict_directive(&body, self.source),
            captured_scopes: state.scope_chain.clone(),
            source_identity: self.source.as_ptr() as usize,
            body,
        })))
    }

    fn parameters(&self, node: &HirNode) -> Option<Vec<String>> {
        if let Some(parameter) = node.child(HirField::Parameter) {
            return self.parameter_name(parameter).map(|name| vec![name]);
        }
        let Some(parameters) = node.child(HirField::Parameters) else {
            return Some(Vec::new());
        };
        let mut names = Vec::new();
        for parameter in named_children(parameters) {
            names.push(self.parameter_name(parameter)?);
        }
        Some(names)
    }

    fn parameter_name(&self, node: &HirNode) -> Option<String> {
        let identifier = match node.kind() {
            HirKind::Identifier => node,
            HirKind::RequiredParameter if node.child(HirField::Value).is_none() => node
                .child(HirField::Name)
                .or_else(|| node.child(HirField::Parameter))
                .or_else(|| {
                    named_children(node).find(|child| child.kind() == HirKind::Identifier)
                })?,
            _ => return None,
        };
        (identifier.kind() == HirKind::Identifier).then(|| self.text(identifier).to_owned())
    }

    fn template(&mut self, node: &HirNode, state: &mut State, call_depth: usize) -> Value {
        let mut value = String::new();
        let mut exact = true;
        let mut branches = Vec::new();
        for child in node.children() {
            let part = match child.kind() {
                HirKind::StringFragment => Some(self.text(child).to_owned()),
                HirKind::EscapeSequence => decode_escape(self.text(child)),
                HirKind::TemplateSubstitution => {
                    let value = named_children(child)
                        .next()
                        .map_or(Value::Unknown, |expression| {
                            self.eval(expression, state, call_depth)
                        });
                    if abrupt_value(&value) {
                        return self.finish_assembly_branches(state, &mut branches, value);
                    }
                    match string_coercion(&value) {
                        Some(value) => Some(value),
                        None => {
                            exact = false;
                            self.start_assembly_branch(state, &mut branches);
                            continue;
                        }
                    }
                }
                HirKind::Token | HirKind::Comment => continue,
                _ => None,
            };
            let Some(part) = part else {
                self.complete = false;
                self.draft.set_partial();
                exact = false;
                continue;
            };
            if !exact {
                continue;
            }
            let Some(bytes) = value.len().checked_add(part.len()) else {
                self.budget.refuse();
                return self.finish_assembly_branches(state, &mut branches, Value::Unknown);
            };
            if !self.budget.admit_bytes(Some(bytes)) {
                return self.finish_assembly_branches(state, &mut branches, Value::Unknown);
            }
            value.push_str(&part);
        }
        let value = if exact {
            Value::String(value)
        } else {
            Value::Unknown
        };
        self.finish_assembly_branches(state, &mut branches, value)
    }

    fn array(&mut self, node: &HirNode, state: &mut State, call_depth: usize) -> Value {
        let mut values = Vec::new();
        let mut exact = true;
        let mut branches = Vec::new();
        let mut cursor = node.span().start().saturating_add(1);
        let mut has_element = false;
        for child in named_children(node) {
            let holes = delimited_holes(self.source, cursor, child.span().start(), has_element);
            match holes {
                Some(holes) => values.extend((0..holes).map(|_| Value::Undefined)),
                None => {
                    self.complete = false;
                    self.draft.set_partial();
                    exact = false;
                }
            }
            if child.kind() == HirKind::SpreadElement {
                let spread = named_children(child)
                    .next()
                    .map_or(Value::Unknown, |value| self.eval(value, state, call_depth));
                if abrupt_value(&spread) {
                    return self.finish_assembly_branches(state, &mut branches, spread);
                }
                if exact_non_iterable(&spread) {
                    return self.finish_assembly_branches(
                        state,
                        &mut branches,
                        Value::SynchronousThrow,
                    );
                }
                match spread {
                    Value::Array(spread) => values.extend(spread),
                    Value::String(spread) => {
                        values.extend(spread.chars().map(|value| Value::String(value.to_string())));
                    }
                    _ => {
                        exact = false;
                        self.start_assembly_branch(state, &mut branches);
                    }
                }
            } else {
                let value = self.eval(child, state, call_depth);
                if abrupt_value(&value) {
                    return self.finish_assembly_branches(state, &mut branches, value);
                }
                values.push(value);
            }
            has_element = true;
            cursor = child.span().end();
            if values.len() > MAX_COLLECTION_ITEMS
                || !self.budget.admit_bytes(values_bytes(&values))
            {
                return self.finish_assembly_branches(state, &mut branches, Value::Unknown);
            }
        }
        let trailing_end = node.span().end().saturating_sub(1);
        match delimited_holes(self.source, cursor, trailing_end, has_element) {
            Some(holes) => values.extend((0..holes).map(|_| Value::Undefined)),
            None => {
                self.complete = false;
                self.draft.set_partial();
                exact = false;
            }
        }
        let value = if values.len() > MAX_COLLECTION_ITEMS
            || !self.budget.admit_bytes(values_bytes(&values))
        {
            Value::Unknown
        } else if exact {
            Value::Array(values)
        } else {
            Value::Unknown
        };
        self.finish_assembly_branches(state, &mut branches, value)
    }

    fn object(&mut self, node: &HirNode, state: &mut State, call_depth: usize) -> Value {
        let mut properties = BTreeMap::new();
        let mut prototype_unknown = false;
        let mut exact = true;
        let mut branches = Vec::new();
        for child in named_children(node) {
            let (name, value) = match child.kind() {
                HirKind::Pair => {
                    let key = child.child(HirField::Key);
                    let name = key.map_or(Ok(None), |key| {
                        self.object_property_name(key, state, call_depth)
                    });
                    let name = match name {
                        Err(value) => {
                            return self.finish_assembly_branches(state, &mut branches, value);
                        }
                        Ok(Some(name)) => name,
                        Ok(None) => {
                            exact = false;
                            self.start_assembly_branch(state, &mut branches);
                            if let Some(value) = child.child(HirField::Value) {
                                let value = self.eval(value, state, call_depth);
                                if abrupt_value(&value) {
                                    return self.finish_assembly_branches(
                                        state,
                                        &mut branches,
                                        value,
                                    );
                                }
                            }
                            continue;
                        }
                    };
                    let value = child
                        .child(HirField::Value)
                        .map_or(Value::Unknown, |value| self.eval(value, state, call_depth));
                    if abrupt_value(&value) {
                        return self.finish_assembly_branches(state, &mut branches, value);
                    }
                    if name == "__proto__"
                        && key.is_some_and(|key| key.kind() != HirKind::ComputedPropertyName)
                    {
                        prototype_unknown = true;
                        continue;
                    }
                    (name, value)
                }
                HirKind::ShorthandPropertyIdentifier => {
                    let name = self.text(child).to_owned();
                    let value = state.get(&name);
                    (name, value)
                }
                HirKind::MethodDefinition => {
                    let name = child.child(HirField::Name).map_or(Ok(None), |name| {
                        self.object_property_name(name, state, call_depth)
                    });
                    let name = match name {
                        Err(value) => {
                            return self.finish_assembly_branches(state, &mut branches, value);
                        }
                        Ok(Some(name)) => name,
                        Ok(None) => {
                            exact = false;
                            self.start_assembly_branch(state, &mut branches);
                            continue;
                        }
                    };
                    let value = match self.method_accessor_kind(child) {
                        Some("get") => match self.function_value(child, state) {
                            Some(Value::Function(function)) => Value::AccessorGetter(function),
                            _ => Value::Unknown,
                        },
                        Some("set") => Value::Accessor,
                        _ => self.function_value(child, state).unwrap_or(Value::Unknown),
                    };
                    (name, value)
                }
                HirKind::SpreadElement => {
                    let spread = named_children(child)
                        .next()
                        .map_or(Value::Unknown, |value| self.eval(value, state, call_depth));
                    if abrupt_value(&spread) {
                        return self.finish_assembly_branches(state, &mut branches, spread);
                    }
                    match spread {
                        Value::Object(spread) => {
                            for (name, mut value) in spread {
                                if accessor_value(&value) {
                                    self.complete = false;
                                    value = Value::Unknown;
                                }
                                properties.insert(name, value);
                            }
                        }
                        Value::Array(spread) => {
                            for (index, value) in spread.into_iter().enumerate() {
                                properties.insert(index.to_string(), value);
                            }
                        }
                        Value::String(spread) => {
                            for (index, value) in spread.chars().enumerate() {
                                properties
                                    .insert(index.to_string(), Value::String(value.to_string()));
                            }
                        }
                        Value::Undefined | Value::Null | Value::Bool(_) | Value::Number(_) => {}
                        _ => {
                            exact = false;
                            self.start_assembly_branch(state, &mut branches);
                        }
                    }
                    if properties.len() > MAX_COLLECTION_ITEMS
                        || !self.budget.admit_bytes(properties_bytes(&properties))
                    {
                        return self.finish_assembly_branches(state, &mut branches, Value::Unknown);
                    }
                    continue;
                }
                _ => {
                    return self.finish_assembly_branches(state, &mut branches, Value::Unknown);
                }
            };
            if value == Value::Accessor
                && matches!(properties.get(&name), Some(Value::AccessorGetter(_)))
            {
                continue;
            }
            properties.insert(name, value);
            if properties.len() > MAX_COLLECTION_ITEMS
                || !self.budget.admit_bytes(properties_bytes(&properties))
            {
                return self.finish_assembly_branches(state, &mut branches, Value::Unknown);
            }
        }
        let value = if prototype_unknown || !exact {
            Value::Unknown
        } else {
            Value::Object(properties)
        };
        self.finish_assembly_branches(state, &mut branches, value)
    }

    fn object_property_name(
        &mut self,
        node: &HirNode,
        state: &mut State,
        call_depth: usize,
    ) -> Result<Option<String>, Value> {
        if node.kind() != HirKind::ComputedPropertyName {
            return Ok(self.property_name(node, state, call_depth));
        }
        let value = named_children(node)
            .next()
            .map_or(Value::Unknown, |value| self.eval(value, state, call_depth));
        if abrupt_value(&value) {
            Err(value)
        } else {
            Ok(string_coercion(&value))
        }
    }

    fn property_name(
        &mut self,
        node: &HirNode,
        state: &mut State,
        call_depth: usize,
    ) -> Option<String> {
        match node.kind() {
            HirKind::PropertyIdentifier
            | HirKind::Identifier
            | HirKind::ShorthandPropertyIdentifier
            | HirKind::Number => Some(self.text(node).to_owned()),
            HirKind::String => {
                let source = self.text(node).to_owned();
                self.decode_string(&source)
            }
            HirKind::ComputedPropertyName => named_children(node)
                .next()
                .map(|value| self.eval(value, state, call_depth))
                .and_then(|value| string_coercion(&value)),
            _ => None,
        }
    }

    fn decode_string(&mut self, source: &str) -> Option<String> {
        let value = decode_js_string(source)?;
        self.budget.admit_bytes(Some(value.len())).then_some(value)
    }

    fn add_values(&mut self, left: Value, right: Value) -> Value {
        match (left, right) {
            (Value::String(mut left), right) => {
                let Some(right) = string_coercion(&right) else {
                    return Value::Unknown;
                };
                let bytes = left.len().checked_add(right.len());
                if !self.budget.admit_bytes(bytes) {
                    return Value::Unknown;
                }
                left.push_str(&right);
                Value::String(left)
            }
            (left, Value::String(right)) => {
                let Some(mut left) = string_coercion(&left) else {
                    return Value::Unknown;
                };
                let bytes = left.len().checked_add(right.len());
                if !self.budget.admit_bytes(bytes) {
                    return Value::Unknown;
                }
                left.push_str(&right);
                Value::String(left)
            }
            (Value::Number(left), Value::Number(right)) => left
                .checked_add(right)
                .map_or(Value::Unknown, Value::Number),
            _ => Value::Unknown,
        }
    }

    fn bind_import(&mut self, node: &HirNode, state: &mut State) {
        if self.text(node).trim_start().starts_with("import type ") {
            return;
        }
        let source = node
            .child(HirField::Source)
            .map(|source| self.text(source).to_owned());
        let module = source
            .as_deref()
            .and_then(|source| self.decode_string(source))
            .as_deref()
            .and_then(|source| {
                if matches!(source, "module" | "node:module") {
                    Some(Value::NodeModule)
                } else {
                    module_from_source(source).map(Value::Module)
                }
            })
            .filter(|_| {
                matches!(
                    self.profile.ownership,
                    RuntimeOwnership::Node | RuntimeOwnership::Bun
                )
            });
        if module.is_none() {
            self.complete = false;
        }
        let Some(clause) = named_children(node).find(|child| child.kind() == HirKind::ImportClause)
        else {
            return;
        };
        for child in named_children(clause) {
            match child.kind() {
                HirKind::Identifier => {
                    state.declare(self.text(child), module.clone().unwrap_or(Value::Unknown));
                }
                HirKind::NamespaceImport => {
                    if let Some(name) = named_children(child).next() {
                        state.declare(self.text(name), module.clone().unwrap_or(Value::Unknown));
                    }
                }
                HirKind::NamedImports => {
                    for specifier in named_children(child)
                        .filter(|child| child.kind() == HirKind::ImportSpecifier)
                    {
                        if self.text(specifier).trim_start().starts_with("type ") {
                            continue;
                        }
                        let Some(name_node) = specifier.child(HirField::Name) else {
                            continue;
                        };
                        let imported = self.text(name_node);
                        let local = specifier
                            .child(HirField::Alias)
                            .map_or(imported, |alias| self.text(alias));
                        let value = module.as_ref().map_or(Value::Unknown, |module| {
                            property_value(module, imported, state)
                        });
                        state.declare(local, value);
                    }
                }
                _ => {}
            }
        }
    }

    fn type_only_export(&self, node: &HirNode) -> bool {
        self.text(node).trim_start().starts_with("export type ")
            || named_children(node).all(|child| child.kind() == HirKind::TypeOnly)
    }

    fn read_property(&mut self, value: &Value, property: &str, state: &State) -> Value {
        let selected = property_value(value, property, state);
        if accessor_value(&selected)
            || matches!(&selected, Value::Known(function) if direct_receiver_required(function))
        {
            self.complete = false;
            Value::Unknown
        } else {
            selected
        }
    }

    fn method_accessor_kind(&self, node: &HirNode) -> Option<&'static str> {
        if let Some(kind) = node.child(HirField::Kind) {
            return match self.text(kind) {
                "get" => Some("get"),
                "set" => Some("set"),
                _ => None,
            };
        }
        let source = self.text(node).trim_start();
        if source.starts_with("get ") {
            Some("get")
        } else if source.starts_with("set ") {
            Some("set")
        } else {
            None
        }
    }

    fn text(&self, node: &HirNode) -> &str {
        self.source
            .get(node.span().start()..node.span().end())
            .unwrap_or_default()
    }
}

fn named_children(node: &HirNode) -> impl Iterator<Item = &HirNode> {
    node.children()
        .iter()
        .filter(|child| !matches!(child.kind(), HirKind::Token | HirKind::Comment))
}

fn strict_directive(node: &HirNode, source: &str) -> bool {
    for statement in named_children(node) {
        if statement.kind() != HirKind::ExpressionStatement {
            return false;
        }
        let mut expressions = named_children(statement);
        let Some(expression) = expressions.next() else {
            return false;
        };
        if expression.kind() != HirKind::String || expressions.next().is_some() {
            return false;
        }
        let literal = source
            .get(expression.span().start()..expression.span().end())
            .unwrap_or_default();
        if matches!(literal, "'use strict'" | "\"use strict\"") {
            return true;
        }
    }
    false
}

fn source_is_module(node: &HirNode) -> bool {
    named_children(node).any(|child| {
        matches!(
            child.kind(),
            HirKind::ImportStatement | HirKind::ExportStatement
        )
    })
}

fn asynchronous_function(node: &HirNode, source: &str) -> bool {
    node.children().iter().any(|child| {
        child.kind() == HirKind::Token
            && source
                .get(child.span().start()..child.span().end())
                .is_some_and(|token| token == "async")
    })
}

fn member_assignment_target(node: &HirNode) -> Option<&HirNode> {
    match node.kind() {
        HirKind::MemberExpression | HirKind::SubscriptExpression => Some(node),
        HirKind::ParenthesizedExpression | HirKind::TransparentExpression => named_children(node)
            .next()
            .and_then(member_assignment_target),
        _ => None,
    }
}

fn prototype_mutation_target(source: &str) -> bool {
    let compact = source
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    let builtin_prototype = [
        "Object", "Number", "Boolean", "String", "Function", "Array", "Promise",
    ]
    .iter()
    .any(|root| {
        [
            format!("{root}.prototype"),
            format!("{root}['prototype']"),
            format!("{root}[\"prototype\"]"),
        ]
        .iter()
        .any(|prefix| {
            compact.strip_prefix(prefix).is_some_and(|suffix| {
                suffix.is_empty() || suffix.starts_with('.') || suffix.starts_with('[')
            })
        })
    });
    if builtin_prototype {
        return true;
    }
    let Some(segments) = simple_member_segments(&compact) else {
        return false;
    };
    segments.iter().any(|segment| segment == "__proto__")
}

fn simple_member_segments(source: &str) -> Option<Vec<String>> {
    let bytes = source.as_bytes();
    let mut cursor = 0;
    let mut segments = Vec::new();
    while cursor < bytes.len() {
        if !segments.is_empty() {
            match bytes[cursor] {
                b'.' => cursor += 1,
                b'[' => {
                    cursor += 1;
                    let quote = *bytes.get(cursor)?;
                    if !matches!(quote, b'\'' | b'"') {
                        return None;
                    }
                    cursor += 1;
                    let start = cursor;
                    while bytes.get(cursor).is_some_and(|byte| *byte != quote) {
                        if bytes[cursor] == b'\\' {
                            return None;
                        }
                        cursor += 1;
                    }
                    let segment = source.get(start..cursor)?.to_owned();
                    cursor += 1;
                    if bytes.get(cursor) != Some(&b']') {
                        return None;
                    }
                    cursor += 1;
                    segments.push(segment);
                    continue;
                }
                _ => return None,
            }
        }
        let start = cursor;
        while bytes
            .get(cursor)
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$'))
        {
            cursor += 1;
        }
        if cursor == start {
            return None;
        }
        segments.push(source.get(start..cursor)?.to_owned());
    }
    Some(segments)
}

fn direct_receiver_expression(node: &HirNode) -> bool {
    match node.kind() {
        HirKind::MemberExpression | HirKind::SubscriptExpression => true,
        HirKind::ParenthesizedExpression | HirKind::TransparentExpression => named_children(node)
            .next()
            .is_some_and(direct_receiver_expression),
        _ => false,
    }
}

fn direct_call_identity(node: &HirNode) -> Option<usize> {
    match node.kind() {
        HirKind::CallExpression => Some(node as *const HirNode as usize),
        HirKind::ParenthesizedExpression | HirKind::TransparentExpression => {
            named_children(node).next().and_then(direct_call_identity)
        }
        _ => None,
    }
}

fn direct_receiver_required(function: &KnownFunction) -> bool {
    matches!(
        function,
        KnownFunction::DenoCommand(_, _) | KnownFunction::BunFile(_, _)
    )
}

fn source_mutates(node: &HirNode) -> bool {
    if matches!(
        node.kind(),
        HirKind::AssignmentExpression
            | HirKind::AugmentedAssignmentExpression
            | HirKind::UpdateExpression
            | HirKind::LexicalDeclaration
            | HirKind::VariableDeclaration
            | HirKind::FunctionDeclaration
            | HirKind::ClassDeclaration
            | HirKind::ImportStatement
            | HirKind::Unsupported
            | HirKind::Error
    ) {
        return true;
    }
    named_children(node).any(source_mutates)
}

fn module_from_source(source: &str) -> Option<Module> {
    match source {
        "fs" | "node:fs" => Some(Module::Fs),
        "fs/promises" | "node:fs/promises" => Some(Module::FsPromises),
        "child_process" | "node:child_process" => Some(Module::ChildProcess),
        _ => None,
    }
}

fn module_member(module: Module, property: &str) -> Option<Member> {
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

fn commonjs_module_value() -> Value {
    Value::CommonJsModule
}

fn default_node_properties() -> BTreeMap<NodeProperty, NodePropertyState> {
    BTreeMap::from([
        (
            NodeProperty::ModuleLoad,
            mutable_node_property(Value::NodeModuleMember(NodeModuleMember::Load), true, true),
        ),
        (
            NodeProperty::ModuleCreateRequire,
            mutable_node_property(
                Value::NodeModuleMember(NodeModuleMember::CreateRequire),
                true,
                true,
            ),
        ),
        (
            NodeProperty::ModuleIsBuiltin,
            mutable_node_property(
                Value::NodeModuleMember(NodeModuleMember::IsBuiltin),
                true,
                true,
            ),
        ),
        (
            NodeProperty::ModuleAlias,
            mutable_node_property(Value::NodeModule, true, true),
        ),
        (
            NodeProperty::ModulePrototype,
            mutable_node_property(Value::NodeModulePrototype, false, false),
        ),
        (
            NodeProperty::ModuleConstructor,
            inherited_node_property(
                Value::InheritedNodeProperty(NodeProperty::ModuleConstructor),
                NodeMutation::Applies,
                NodePropertyKind::Data,
                false,
            ),
        ),
        (
            NodeProperty::PrototypeRequire,
            mutable_node_property(
                Value::NodeModuleMember(NodeModuleMember::Require),
                true,
                true,
            ),
        ),
        (
            NodeProperty::CommonJsRequire,
            inherited_node_property(
                Value::InheritedNodeProperty(NodeProperty::CommonJsRequire),
                NodeMutation::Applies,
                NodePropertyKind::Data,
                true,
            ),
        ),
        (
            NodeProperty::CommonJsConstructor,
            inherited_node_property(
                Value::InheritedNodeProperty(NodeProperty::CommonJsConstructor),
                NodeMutation::Ignored,
                NodePropertyKind::Accessor,
                false,
            ),
        ),
    ])
}

fn mutable_node_property(value: Value, configurable: bool, enumerable: bool) -> NodePropertyState {
    NodePropertyState {
        value,
        own: Some(true),
        kind: NodePropertyKind::Data,
        enumerable: Some(enumerable),
        assignment: NodeMutation::Applies,
        deletion: if configurable {
            NodeMutation::Applies
        } else {
            NodeMutation::Ignored
        },
    }
}

fn inherited_node_property(
    value: Value,
    assignment: NodeMutation,
    kind: NodePropertyKind,
    enumerable: bool,
) -> NodePropertyState {
    NodePropertyState {
        value,
        own: Some(false),
        kind,
        enumerable: Some(enumerable),
        assignment,
        deletion: NodeMutation::Ignored,
    }
}

fn absent_node_property(property: NodeProperty) -> NodePropertyState {
    match property {
        NodeProperty::ModuleConstructor
        | NodeProperty::CommonJsRequire
        | NodeProperty::CommonJsConstructor => default_node_properties()
            .remove(&property)
            .expect("reviewed Node property"),
        _ => NodePropertyState {
            value: Value::Undefined,
            own: Some(false),
            kind: NodePropertyKind::Absent,
            enumerable: None,
            assignment: NodeMutation::Applies,
            deletion: NodeMutation::Ignored,
        },
    }
}

fn unknown_node_property() -> NodePropertyState {
    NodePropertyState {
        value: Value::Unknown,
        own: None,
        kind: NodePropertyKind::Unknown,
        enumerable: None,
        assignment: NodeMutation::Unknown,
        deletion: NodeMutation::Unknown,
    }
}

fn defined_node_property(
    current: NodePropertyState,
    descriptor: Option<&Value>,
) -> (NodePropertyState, bool, bool) {
    let Some(Value::Object(properties)) = descriptor else {
        let replacement = descriptor
            .and_then(property_descriptor_replacement)
            .unwrap_or(Value::Unknown);
        return (
            NodePropertyState {
                value: join_values(current.value, replacement),
                own: None,
                kind: NodePropertyKind::Unknown,
                enumerable: None,
                assignment: NodeMutation::Unknown,
                deletion: NodeMutation::Unknown,
            },
            true,
            true,
        );
    };
    if current.own.is_none()
        || current.assignment == NodeMutation::Unknown
        || current.deletion == NodeMutation::Unknown
    {
        let replacement =
            property_descriptor_replacement(descriptor.expect("reviewed property descriptor"))
                .unwrap_or(Value::Unknown);
        return (
            NodePropertyState {
                value: join_values(current.value, replacement),
                own: None,
                kind: NodePropertyKind::Unknown,
                enumerable: None,
                assignment: NodeMutation::Unknown,
                deletion: NodeMutation::Unknown,
            },
            true,
            true,
        );
    }
    let creates_own = current.own == Some(false);
    let replacement =
        property_descriptor_replacement(descriptor.expect("reviewed property descriptor"));
    let accessor = properties.contains_key("get") || properties.contains_key("set");
    let data = properties.contains_key("value") || properties.contains_key("writable");
    let kind = if accessor {
        NodePropertyKind::Accessor
    } else if data || creates_own {
        NodePropertyKind::Data
    } else {
        current.kind
    };
    let changes_value = creates_own
        || kind != current.kind
        || replacement.as_ref().is_some_and(|replacement| {
            unknown_value(replacement)
                || unknown_value(&current.value)
                || replacement != &current.value
        });
    let value = replacement.unwrap_or_else(|| {
        if creates_own {
            Value::Undefined
        } else {
            current.value.clone()
        }
    });
    let assignment = match kind {
        NodePropertyKind::Accessor if accessor => {
            properties
                .get("set")
                .map_or(NodeMutation::Ignored, |setter| {
                    if *setter == Value::Undefined || exact_undefined_getter(setter) {
                        NodeMutation::Ignored
                    } else {
                        NodeMutation::Unknown
                    }
                })
        }
        NodePropertyKind::Accessor => current.assignment,
        NodePropertyKind::Data if data => properties.get("writable").map_or_else(
            || {
                if creates_own {
                    NodeMutation::Ignored
                } else {
                    current.assignment
                }
            },
            node_mutation,
        ),
        NodePropertyKind::Data if creates_own => NodeMutation::Ignored,
        NodePropertyKind::Data => current.assignment,
        NodePropertyKind::Absent | NodePropertyKind::Unknown => NodeMutation::Unknown,
    };
    let deletion = properties.get("configurable").map_or_else(
        || {
            if creates_own {
                NodeMutation::Ignored
            } else {
                current.deletion
            }
        },
        node_mutation,
    );
    let enumerable = properties.get("enumerable").map_or_else(
        || {
            if creates_own {
                Some(false)
            } else {
                current.enumerable
            }
        },
        truthy,
    );
    let uncertain = assignment == NodeMutation::Unknown || deletion == NodeMutation::Unknown;
    let defined = NodePropertyState {
        value,
        own: Some(true),
        kind,
        enumerable,
        assignment,
        deletion,
    };
    if node_property_redefinition_may_reject(&current, properties) {
        (
            join_node_property_state(current, defined),
            changes_value,
            true,
        )
    } else {
        (defined, changes_value, uncertain)
    }
}

fn node_mutation(value: &Value) -> NodeMutation {
    match truthy(value) {
        Some(true) => NodeMutation::Applies,
        Some(false) => NodeMutation::Ignored,
        None => NodeMutation::Unknown,
    }
}

fn node_define_property_target(arguments: &Arguments) -> Option<NodeProperty> {
    let property = arguments.values.get(1).and_then(value_string)?;
    match arguments.values.first()? {
        Value::NodeModule => node_module_property(property),
        Value::NodeModulePrototype if property == "require" => Some(NodeProperty::PrototypeRequire),
        Value::CommonJsModule => commonjs_module_property(property),
        _ => None,
    }
}

fn invalid_node_prototype_constructor_definition(arguments: &Arguments) -> bool {
    if !matches!(arguments.values.first(), Some(Value::NodeModulePrototype))
        || arguments.values.get(1).and_then(value_string) != Some("constructor")
    {
        return false;
    }
    let Some(Value::Object(properties)) = arguments.values.get(2) else {
        return false;
    };
    properties.contains_key("value")
        || properties.contains_key("writable")
        || properties.get("configurable").and_then(truthy) == Some(true)
        || properties.get("enumerable").and_then(truthy) == Some(true)
        || properties
            .get("get")
            .is_some_and(|value| !unknown_value(value))
        || properties
            .get("set")
            .is_some_and(|value| *value != Value::Undefined)
}

fn invalid_node_property_redefinition(current: &NodePropertyState, descriptor: &Value) -> bool {
    let Value::Object(properties) = descriptor else {
        return false;
    };
    if current.own != Some(true) || current.deletion != NodeMutation::Ignored {
        return false;
    }
    if properties.get("configurable").and_then(truthy) == Some(true) {
        return true;
    }
    if let Some(enumerable) = properties.get("enumerable").and_then(truthy)
        && current
            .enumerable
            .is_some_and(|current| current != enumerable)
    {
        return true;
    }
    if let Some(kind) = descriptor_property_kind(properties)
        && matches!(
            current.kind,
            NodePropertyKind::Data | NodePropertyKind::Accessor
        )
        && kind != current.kind
    {
        return true;
    }
    if current.kind != NodePropertyKind::Data || current.assignment != NodeMutation::Ignored {
        return false;
    }
    if properties.get("writable").and_then(truthy) == Some(true) {
        return true;
    }
    properties.get("value").is_some_and(|value| {
        value != &current.value && strict_equal(&current.value, value) == Some(false)
    })
}

fn node_property_redefinition_may_reject(
    current: &NodePropertyState,
    properties: &BTreeMap<String, Value>,
) -> bool {
    if current.own != Some(true) || current.deletion != NodeMutation::Ignored {
        return false;
    }
    if properties.get("enumerable").is_some_and(|value| {
        truthy(value).is_none_or(|enumerable| current.enumerable != Some(enumerable))
    }) || properties
        .get("configurable")
        .is_some_and(|value| truthy(value) != Some(false))
    {
        return true;
    }
    if let Some(kind) = descriptor_property_kind(properties) {
        if current.kind == NodePropertyKind::Unknown {
            return true;
        }
        if kind != current.kind {
            return true;
        }
    }
    if current.kind == NodePropertyKind::Accessor {
        return properties.contains_key("get") || properties.contains_key("set");
    }
    current.kind == NodePropertyKind::Data
        && current.assignment == NodeMutation::Ignored
        && (properties
            .get("writable")
            .is_some_and(|value| truthy(value) != Some(false))
            || properties.get("value").is_some_and(|value| {
                value != &current.value && strict_equal(&current.value, value) != Some(true)
            }))
}

fn descriptor_property_kind(properties: &BTreeMap<String, Value>) -> Option<NodePropertyKind> {
    if properties.contains_key("get") || properties.contains_key("set") {
        Some(NodePropertyKind::Accessor)
    } else if properties.contains_key("value") || properties.contains_key("writable") {
        Some(NodePropertyKind::Data)
    } else {
        None
    }
}

fn node_module_property(property: &str) -> Option<NodeProperty> {
    match property {
        "_load" => Some(NodeProperty::ModuleLoad),
        "createRequire" => Some(NodeProperty::ModuleCreateRequire),
        "isBuiltin" => Some(NodeProperty::ModuleIsBuiltin),
        "Module" => Some(NodeProperty::ModuleAlias),
        "prototype" => Some(NodeProperty::ModulePrototype),
        "constructor" => Some(NodeProperty::ModuleConstructor),
        _ => None,
    }
}

fn node_module_property_value(property: &str, state: &State) -> Option<Value> {
    node_module_property(property).map(|property| resolved_node_property(property, state))
}

fn commonjs_module_property(property: &str) -> Option<NodeProperty> {
    match property {
        "require" => Some(NodeProperty::CommonJsRequire),
        "constructor" => Some(NodeProperty::CommonJsConstructor),
        _ => None,
    }
}

fn resolved_node_property(property: NodeProperty, state: &State) -> Value {
    match state
        .node_properties
        .get(&property)
        .map(|property| &property.value)
    {
        Some(Value::InheritedNodeProperty(NodeProperty::CommonJsRequire)) => {
            resolved_node_property(NodeProperty::PrototypeRequire, state)
        }
        Some(Value::InheritedNodeProperty(NodeProperty::ModuleConstructor)) => {
            Value::FunctionConstructor
        }
        Some(Value::InheritedNodeProperty(NodeProperty::CommonJsConstructor)) => Value::NodeModule,
        Some(value) => value.clone(),
        None => Value::Unknown,
    }
}

fn property_descriptor_replacement(descriptor: &Value) -> Option<Value> {
    match descriptor {
        Value::Object(properties) => {
            if let Some(value) = properties.get("value") {
                Some(if accessor_value(value) {
                    Value::Unknown
                } else {
                    value.clone()
                })
            } else if let Some(getter) = properties.get("get") {
                Some(if accessor_value(getter) {
                    Value::Unknown
                } else if *getter == Value::Undefined || exact_undefined_getter(getter) {
                    Value::Undefined
                } else {
                    Value::Unknown
                })
            } else if properties.contains_key("set") {
                Some(Value::Undefined)
            } else {
                None
            }
        }
        value if unknown_value(value) => Some(Value::Unknown),
        _ => None,
    }
}

fn exact_undefined_getter(value: &Value) -> bool {
    matches!(
        value,
        Value::Function(function)
            if function.expression_body && function.body.kind() == HirKind::Undefined
    )
}

fn invalid_define_property_target(value: &Value) -> bool {
    matches!(
        value,
        Value::Undefined
            | Value::Null
            | Value::Bool(_)
            | Value::Number(_)
            | Value::String(_)
            | Value::NonCallablePrimitive
    )
}

fn accessor_value(value: &Value) -> bool {
    matches!(value, Value::Accessor | Value::AccessorGetter(_))
}

fn invalid_property_descriptor(value: &Value) -> bool {
    match value {
        Value::Undefined | Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {
            true
        }
        Value::Object(properties) => {
            let accessor = properties.contains_key("get") || properties.contains_key("set");
            let data = properties.contains_key("value") || properties.contains_key("writable");
            accessor && data
                || ["get", "set"].into_iter().any(|property| {
                    properties.get(property).is_some_and(|value| {
                        *value != Value::Undefined && exact_non_callable(value)
                    })
                })
        }
        _ => false,
    }
}

fn node_module_loader_hook(member: NodeModuleMember) -> bool {
    !matches!(member, NodeModuleMember::IsBuiltin)
}

fn node_property_loader_hook(property: NodeProperty) -> bool {
    matches!(
        property,
        NodeProperty::ModuleLoad
            | NodeProperty::ModuleCreateRequire
            | NodeProperty::PrototypeRequire
            | NodeProperty::CommonJsRequire
    )
}

fn node_loader_reference(member: &MemberReference) -> bool {
    match (&member.object, member.property.as_deref()) {
        (Value::NodeModule, Some(property)) => {
            node_module_property(property).is_some_and(node_property_loader_hook)
        }
        (Value::NodeModulePrototype, Some("require"))
        | (Value::CommonJsModule, Some("require")) => true,
        _ => false,
    }
}

fn augmented_coercion_proven(left: &Value, right: Option<&Value>, state: &State) -> bool {
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

fn deno_member(property: &str) -> Option<DenoMember> {
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

fn deno_command_member(property: &str) -> Option<DenoCommandMember> {
    match property {
        "spawn" => Some(DenoCommandMember::Spawn),
        "output" => Some(DenoCommandMember::Output),
        "outputSync" => Some(DenoCommandMember::OutputSync),
        _ => None,
    }
}

fn bun_member(property: &str) -> Option<BunMember> {
    match property {
        "spawn" => Some(BunMember::Spawn),
        "spawnSync" => Some(BunMember::SpawnSync),
        "file" => Some(BunMember::File),
        "write" => Some(BunMember::Write),
        _ => None,
    }
}

fn bun_file_member(property: &str) -> Option<BunFileMember> {
    match property {
        "text" => Some(BunFileMember::Text),
        "json" => Some(BunFileMember::Json),
        "arrayBuffer" => Some(BunFileMember::ArrayBuffer),
        "bytes" => Some(BunFileMember::Bytes),
        "delete" => Some(BunFileMember::Delete),
        _ => None,
    }
}

fn openclaw_member(property: &str) -> Option<OpenClawMember> {
    match property {
        "call" => Some(OpenClawMember::Call),
        "callValue" => Some(OpenClawMember::CallValue),
        _ => None,
    }
}

fn deno_callable(member: DenoMember) -> &'static str {
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

fn deno_member_synchronous(member: DenoMember) -> bool {
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

fn deno_member_constructible(member: DenoMember) -> bool {
    member != DenoMember::Chdir
        && (deno_member_synchronous(member) || member == DenoMember::WriteTextFile)
}

fn deno_command_callable(member: DenoCommandMember) -> &'static str {
    match member {
        DenoCommandMember::Spawn => "Deno.Command.spawn",
        DenoCommandMember::Output => "Deno.Command.output",
        DenoCommandMember::OutputSync => "Deno.Command.outputSync",
    }
}

fn bun_callable(member: BunMember) -> &'static str {
    match member {
        BunMember::Spawn => "Bun.spawn",
        BunMember::SpawnSync => "Bun.spawnSync",
        BunMember::File => "Bun.file",
        BunMember::Write => "Bun.write",
    }
}

fn bun_file_callable(member: BunFileMember) -> &'static str {
    match member {
        BunFileMember::Text => "Bun.file.text",
        BunFileMember::Json => "Bun.file.json",
        BunFileMember::ArrayBuffer => "Bun.file.arrayBuffer",
        BunFileMember::Bytes => "Bun.file.bytes",
        BunFileMember::Delete => "Bun.file.delete",
    }
}

fn fs_callable(module: Module, member: Member) -> &'static str {
    if module == Module::FsPromises {
        return match member {
            Member::AppendFile => "fs.promises.appendFile",
            Member::Chmod => "fs.promises.chmod",
            Member::Chown => "fs.promises.chown",
            Member::CopyFile => "fs.promises.copyFile",
            Member::Link => "fs.promises.link",
            Member::Mkdir => "fs.promises.mkdir",
            Member::Open => "fs.promises.open",
            Member::Rename => "fs.promises.rename",
            Member::Rmdir => "fs.promises.rmdir",
            Member::Rm => "fs.promises.rm",
            Member::Symlink => "fs.promises.symlink",
            Member::Truncate => "fs.promises.truncate",
            Member::Unlink => "fs.promises.unlink",
            Member::WriteFile => "fs.promises.writeFile",
            _ => unreachable!(),
        };
    }
    match member {
        Member::AppendFile => "fs.appendFile",
        Member::AppendFileSync => "fs.appendFileSync",
        Member::Chmod => "fs.chmod",
        Member::ChmodSync => "fs.chmodSync",
        Member::Chown => "fs.chown",
        Member::ChownSync => "fs.chownSync",
        Member::CopyFile => "fs.copyFile",
        Member::CopyFileSync => "fs.copyFileSync",
        Member::CreateWriteStream => "fs.createWriteStream",
        Member::Link => "fs.link",
        Member::LinkSync => "fs.linkSync",
        Member::Mkdir => "fs.mkdir",
        Member::MkdirSync => "fs.mkdirSync",
        Member::Open => "fs.open",
        Member::OpenSync => "fs.openSync",
        Member::Rename => "fs.rename",
        Member::RenameSync => "fs.renameSync",
        Member::Rmdir => "fs.rmdir",
        Member::RmdirSync => "fs.rmdirSync",
        Member::Rm => "fs.rm",
        Member::RmSync => "fs.rmSync",
        Member::Symlink => "fs.symlink",
        Member::SymlinkSync => "fs.symlinkSync",
        Member::Truncate => "fs.truncate",
        Member::TruncateSync => "fs.truncateSync",
        Member::Unlink => "fs.unlink",
        Member::UnlinkSync => "fs.unlinkSync",
        Member::WriteFile => "fs.writeFile",
        Member::WriteFileSync => "fs.writeFileSync",
        _ => unreachable!(),
    }
}

fn fs_return_value(module: Module, member: Member) -> Value {
    if module == Module::FsPromises {
        return Value::Unknown;
    }
    match member {
        Member::CreateWriteStream => Value::Object(BTreeMap::new()),
        Member::MkdirSync | Member::OpenSync => Value::Unknown,
        _ => Value::Undefined,
    }
}

fn fs_callback_unmodeled(module: Module, member: Member) -> bool {
    module == Module::Fs
        && matches!(
            member,
            Member::AppendFile
                | Member::Chmod
                | Member::Chown
                | Member::CopyFile
                | Member::Link
                | Member::Mkdir
                | Member::Open
                | Member::Rename
                | Member::Rmdir
                | Member::Rm
                | Member::Symlink
                | Member::Truncate
                | Member::Unlink
                | Member::WriteFile
        )
}

fn child_callable(member: Member) -> &'static str {
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

enum ChildExecution {
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

enum ChildCallSummary {
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

fn summarize_child_call(
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

fn child_callback_shape(value: &Value) -> bool {
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

fn unknown_value(value: &Value) -> bool {
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

fn runtime_global_value(value: &Value) -> bool {
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

fn contains_local_function(value: &Value) -> bool {
    match value {
        Value::Function(_) | Value::AccessorGetter(_) => true,
        Value::Array(values) => values.iter().any(contains_local_function),
        Value::Object(properties) => properties.values().any(contains_local_function),
        _ => false,
    }
}

fn invalidate_loaded_module_value(value: &mut Value, module: Module) {
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

fn exact_non_iterable(value: &Value) -> bool {
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

fn exact_non_callable(value: &Value) -> bool {
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

enum FsCallSummary {
    Effect(Vec<LanguageFilesystem>),
    EffectPartial(Vec<LanguageFilesystem>),
    Partial,
    Invalid,
}

fn attach_deno_command_source(
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

fn refresh_deno_command(
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

fn partialize_deno_command(
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

fn deno_command(
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

fn known_object_like(value: &Value) -> bool {
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

fn merge_execution(left: ExecutionCertainty, right: ExecutionCertainty) -> ExecutionCertainty {
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

fn deno_command_context_property(property: &str, platform: Platform) -> bool {
    matches!(property, "cwd" | "clearEnv" | "env")
        || (property == "windowsRawArguments" && platform == Platform::Windows)
}

fn deno_command_option_property(property: &str, platform: Platform) -> bool {
    deno_command_option_names().contains(&property)
        && !matches!(
            (property, platform),
            ("windowsRawArguments", Platform::Linux | Platform::Macos)
                | ("uid" | "gid", Platform::Windows)
        )
}

fn deno_command_option_names() -> &'static [&'static str] {
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

fn deno_spawn_stdio_certainty(value: &Value) -> ExecutionCertainty {
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

fn deno_output_stdio_certainty(value: &Value) -> ExecutionCertainty {
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

fn deno_context_certainty(
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

fn deno_env_certainty(value: &Value) -> ExecutionCertainty {
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

fn summarize_deno_call(
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

fn bun_spawn_argv(
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

fn bun_spawn_command_partial(command: &[Value]) -> RuntimeCallSummary<BunSpawnSummary> {
    match bun_spawn_command(command, NestedExecutionCwd::Unknown, false, false) {
        RuntimeCallSummary::Effect(summary) => RuntimeCallSummary::EffectPartial(summary),
        RuntimeCallSummary::EffectPartial(summary) => RuntimeCallSummary::EffectPartial(summary),
        RuntimeCallSummary::Partial => RuntimeCallSummary::Partial,
        RuntimeCallSummary::Invalid => RuntimeCallSummary::Invalid,
    }
}

fn bun_spawn_command(
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

fn bun_spawn_cwd(
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

fn bun_spawn_context_property(property: &str) -> bool {
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

fn bun_spawn_options_certainty(properties: &BTreeMap<String, Value>) -> ExecutionCertainty {
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

enum BunStdout {
    Exact(bool),
    Partial,
    Invalid,
}

fn bun_stdout(value: &Value) -> BunStdout {
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

fn deno_remove_options(value: &Value, prototype_integrity_known: bool) -> OptionValue {
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

fn deno_mkdir_options(value: &Value, prototype_integrity_known: bool) -> OptionValue {
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
enum ShapeValue {
    Exact,
    Partial,
    Invalid,
}

fn deno_read_options(value: &Value, prototype_integrity_known: bool) -> ShapeValue {
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

fn deno_write_options(
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

fn valid_u32(value: i64) -> bool {
    (0..=i64::from(u32::MAX)).contains(&value)
}

fn bun_file(
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

fn summarize_openclaw_call(arguments: &Arguments) -> RuntimeCallSummary<()> {
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

fn summarize_bun_write(arguments: &Arguments, prototype_integrity_known: bool) -> FsCallSummary {
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

fn bun_write_options(value: &Value, prototype_integrity_known: bool) -> ShapeValue {
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

fn summarize_fs_call(module: Module, member: Member, arguments: &Arguments) -> FsCallSummary {
    if !arguments.complete {
        return FsCallSummary::Partial;
    }
    if module == Module::FsPromises {
        return summarize_fs_promise_call(member, arguments);
    }
    let values = &arguments.values;
    let path = |index, operation, recursive| {
        LanguageFilesystem::new(
            values.get(index).and_then(value_string).map(str::to_owned),
            operation,
            recursive,
        )
    };
    let possible_path = |index| values.get(index).is_some_and(possible_path_argument);
    match member {
        Member::Rm | Member::Rmdir => {
            let recursive = match values.as_slice() {
                [target, callback]
                    if possible_path_argument(target) && possible_callback(callback) =>
                {
                    false
                }
                [target, options, callback]
                    if possible_path_argument(target) && possible_callback(callback) =>
                {
                    match recursive_option(options) {
                        OptionValue::Exact(recursive) => recursive,
                        OptionValue::Partial => return FsCallSummary::Partial,
                        OptionValue::Invalid => return FsCallSummary::Invalid,
                    }
                }
                _ => return FsCallSummary::Invalid,
            };
            FsCallSummary::Effect(vec![path(0, FilesystemOperation::Delete, recursive)])
        }
        Member::RmSync | Member::RmdirSync => {
            if !possible_path(0) || !(1..=2).contains(&values.len()) {
                return FsCallSummary::Invalid;
            }
            let recursive = match values
                .get(1)
                .map_or(OptionValue::Exact(false), recursive_option)
            {
                OptionValue::Exact(recursive) => recursive,
                OptionValue::Partial => return FsCallSummary::Partial,
                OptionValue::Invalid => return FsCallSummary::Invalid,
            };
            FsCallSummary::Effect(vec![path(0, FilesystemOperation::Delete, recursive)])
        }
        Member::Unlink => {
            if values.len() != 2 || !possible_path(0) || !possible_callback(&values[1]) {
                return FsCallSummary::Invalid;
            }
            FsCallSummary::Effect(vec![path(0, FilesystemOperation::Delete, false)])
        }
        Member::UnlinkSync => {
            if values.len() != 1 || !possible_path(0) {
                return FsCallSummary::Invalid;
            }
            FsCallSummary::Effect(vec![path(0, FilesystemOperation::Delete, false)])
        }
        Member::WriteFile | Member::AppendFile => {
            if values.get(2).is_some_and(option_has_accessor) {
                return FsCallSummary::Partial;
            }
            let valid = match values.as_slice() {
                [target, data, callback] => {
                    possible_file_argument(target)
                        && possible_data(data)
                        && possible_callback(callback)
                }
                [target, data, options, callback] => {
                    possible_file_argument(target)
                        && possible_data(data)
                        && possible_write_options(options)
                        && possible_callback(callback)
                }
                _ => false,
            };
            if !valid {
                return FsCallSummary::Invalid;
            }
            FsCallSummary::Effect(vec![path(0, FilesystemOperation::Write, false)])
        }
        Member::WriteFileSync | Member::AppendFileSync => {
            if values.get(2).is_some_and(option_has_accessor) {
                return FsCallSummary::Partial;
            }
            if !(2..=3).contains(&values.len())
                || !values.first().is_some_and(possible_file_argument)
                || !possible_data(&values[1])
                || values
                    .get(2)
                    .is_some_and(|value| !possible_write_options(value))
            {
                return FsCallSummary::Invalid;
            }
            FsCallSummary::Effect(vec![path(0, FilesystemOperation::Write, false)])
        }
        Member::CreateWriteStream => {
            if !possible_path(0) || !(1..=2).contains(&values.len()) {
                return FsCallSummary::Invalid;
            }
            let Some(options) = values.get(1) else {
                return FsCallSummary::Effect(vec![path(0, FilesystemOperation::Write, false)]);
            };
            match options {
                Value::String(_) => {}
                Value::Object(properties) => {
                    if properties.values().any(accessor_value) {
                        return FsCallSummary::Partial;
                    }
                    if properties
                        .get("fs")
                        .is_some_and(|value| !matches!(value, Value::Null | Value::Undefined))
                    {
                        return FsCallSummary::Partial;
                    }
                    if let Some(fd) = properties.get("fd")
                        && !matches!(fd, Value::Null | Value::Undefined)
                    {
                        return match fd {
                            Value::Number(_) => {
                                FsCallSummary::Effect(vec![LanguageFilesystem::new(
                                    None,
                                    FilesystemOperation::Write,
                                    false,
                                )])
                            }
                            value if unknown_value(value) => {
                                FsCallSummary::EffectPartial(vec![LanguageFilesystem::new(
                                    None,
                                    FilesystemOperation::Write,
                                    false,
                                )])
                            }
                            _ => FsCallSummary::Invalid,
                        };
                    }
                }
                value if unknown_value(value) => return FsCallSummary::Partial,
                _ => return FsCallSummary::Invalid,
            }
            FsCallSummary::Effect(vec![path(0, FilesystemOperation::Write, false)])
        }
        Member::CopyFile => {
            let valid = match values.as_slice() {
                [source, target, callback] => {
                    possible_path_argument(source)
                        && possible_path_argument(target)
                        && possible_callback(callback)
                }
                [source, target, mode, callback] => {
                    possible_path_argument(source)
                        && possible_path_argument(target)
                        && possible_number(mode)
                        && possible_callback(callback)
                }
                _ => false,
            };
            if !valid {
                return FsCallSummary::Invalid;
            }
            FsCallSummary::Effect(vec![
                path(0, FilesystemOperation::Read, false),
                path(1, FilesystemOperation::Write, false),
            ])
        }
        Member::CopyFileSync => {
            if !(2..=3).contains(&values.len())
                || !possible_path(0)
                || !possible_path(1)
                || values.get(2).is_some_and(|value| !possible_number(value))
            {
                return FsCallSummary::Invalid;
            }
            FsCallSummary::Effect(vec![
                path(0, FilesystemOperation::Read, false),
                path(1, FilesystemOperation::Write, false),
            ])
        }
        Member::Rename | Member::Link => {
            if values.len() != 3
                || !possible_path(0)
                || !possible_path(1)
                || !possible_callback(&values[2])
            {
                return FsCallSummary::Invalid;
            }
            move_or_link_filesystems(member, values, &path)
        }
        Member::RenameSync | Member::LinkSync => {
            if values.len() != 2 || !possible_path(0) || !possible_path(1) {
                return FsCallSummary::Invalid;
            }
            move_or_link_filesystems(member, values, &path)
        }
        Member::Symlink => {
            let valid = match values.as_slice() {
                [source, target, callback] => {
                    possible_path_argument(source)
                        && possible_path_argument(target)
                        && possible_callback(callback)
                }
                [source, target, kind, callback] => {
                    possible_path_argument(source)
                        && possible_path_argument(target)
                        && possible_symlink_kind(kind)
                        && possible_callback(callback)
                }
                _ => false,
            };
            if !valid {
                return FsCallSummary::Invalid;
            }
            FsCallSummary::Effect(vec![
                path(1, FilesystemOperation::Write, false)
                    .metadata()
                    .without_final_symlink_follow(),
            ])
        }
        Member::SymlinkSync => {
            if !(2..=3).contains(&values.len())
                || !possible_path(0)
                || !possible_path(1)
                || values
                    .get(2)
                    .is_some_and(|value| !possible_symlink_kind(value))
            {
                return FsCallSummary::Invalid;
            }
            FsCallSummary::Effect(vec![
                path(1, FilesystemOperation::Write, false)
                    .metadata()
                    .without_final_symlink_follow(),
            ])
        }
        Member::Truncate => {
            let valid = match values.as_slice() {
                [target, callback] => possible_file_argument(target) && possible_callback(callback),
                [target, length, callback] => {
                    possible_file_argument(target)
                        && possible_number(length)
                        && possible_callback(callback)
                }
                _ => false,
            };
            if !valid {
                return FsCallSummary::Invalid;
            }
            FsCallSummary::Effect(vec![path(0, FilesystemOperation::Write, false)])
        }
        Member::TruncateSync => {
            if !(1..=2).contains(&values.len())
                || !values.first().is_some_and(possible_file_argument)
                || values.get(1).is_some_and(|value| !possible_number(value))
            {
                return FsCallSummary::Invalid;
            }
            FsCallSummary::Effect(vec![path(0, FilesystemOperation::Write, false)])
        }
        Member::Chmod | Member::Chown => {
            let expected = if member == Member::Chmod { 3 } else { 4 };
            if values.len() != expected
                || !possible_path(0)
                || (member == Member::Chmod && !possible_mode(&values[1]))
                || (member == Member::Chown
                    && values[1..expected - 1]
                        .iter()
                        .any(|value| !possible_number(value)))
                || !possible_callback(&values[expected - 1])
            {
                return FsCallSummary::Invalid;
            }
            FsCallSummary::Effect(vec![path(0, FilesystemOperation::Write, false).metadata()])
        }
        Member::ChmodSync | Member::ChownSync => {
            let expected = if member == Member::ChmodSync { 2 } else { 3 };
            if values.len() != expected
                || !possible_path(0)
                || (member == Member::ChmodSync && !possible_mode(&values[1]))
                || (member == Member::ChownSync
                    && values[1..].iter().any(|value| !possible_number(value)))
            {
                return FsCallSummary::Invalid;
            }
            FsCallSummary::Effect(vec![path(0, FilesystemOperation::Write, false).metadata()])
        }
        Member::Mkdir => {
            let recursive = match values.as_slice() {
                [target, callback]
                    if possible_path_argument(target) && possible_callback(callback) =>
                {
                    false
                }
                [target, options, callback]
                    if possible_path_argument(target) && possible_callback(callback) =>
                {
                    match mkdir_recursive_option(options) {
                        OptionValue::Exact(recursive) => recursive,
                        OptionValue::Partial => return FsCallSummary::Partial,
                        OptionValue::Invalid => return FsCallSummary::Invalid,
                    }
                }
                _ => return FsCallSummary::Invalid,
            };
            FsCallSummary::Effect(vec![path(0, FilesystemOperation::Write, recursive)])
        }
        Member::MkdirSync => {
            if !possible_path(0) || !(1..=2).contains(&values.len()) {
                return FsCallSummary::Invalid;
            }
            let recursive = match values
                .get(1)
                .map_or(OptionValue::Exact(false), mkdir_recursive_option)
            {
                OptionValue::Exact(recursive) => recursive,
                OptionValue::Partial => return FsCallSummary::Partial,
                OptionValue::Invalid => return FsCallSummary::Invalid,
            };
            FsCallSummary::Effect(vec![path(0, FilesystemOperation::Write, recursive)])
        }
        Member::Open => {
            let flags = match values.as_slice() {
                [target, callback]
                    if possible_path_argument(target) && possible_callback(callback) =>
                {
                    "r"
                }
                [target, flags, callback]
                    if possible_path_argument(target) && possible_callback(callback) =>
                {
                    let Some(flags) = value_string(flags) else {
                        return FsCallSummary::Partial;
                    };
                    flags
                }
                [target, flags, mode, callback]
                    if possible_path_argument(target)
                        && possible_mode(mode)
                        && possible_callback(callback) =>
                {
                    let Some(flags) = value_string(flags) else {
                        return FsCallSummary::Partial;
                    };
                    flags
                }
                _ => return FsCallSummary::Invalid,
            };
            open_filesystems(flags, &path)
        }
        Member::OpenSync => {
            if !(2..=3).contains(&values.len())
                || !possible_path(0)
                || values.get(2).is_some_and(|value| !possible_mode(value))
            {
                return FsCallSummary::Invalid;
            }
            let Some(flags) = values.get(1).and_then(value_string) else {
                return FsCallSummary::Partial;
            };
            open_filesystems(flags, &path)
        }
        Member::Exec
        | Member::ExecSync
        | Member::Spawn
        | Member::SpawnSync
        | Member::ExecFile
        | Member::ExecFileSync => FsCallSummary::Invalid,
    }
}

fn summarize_fs_promise_call(member: Member, arguments: &Arguments) -> FsCallSummary {
    let values = &arguments.values;
    let path = |index, operation, recursive| {
        LanguageFilesystem::new(
            values.get(index).and_then(value_string).map(str::to_owned),
            operation,
            recursive,
        )
    };
    let possible_path = |index| values.get(index).is_some_and(possible_path_argument);
    match member {
        Member::Rm | Member::Rmdir => {
            if !possible_path(0) || !(1..=2).contains(&values.len()) {
                return FsCallSummary::Invalid;
            }
            let recursive = match values
                .get(1)
                .map_or(OptionValue::Exact(false), recursive_option)
            {
                OptionValue::Exact(recursive) => recursive,
                OptionValue::Partial => return FsCallSummary::Partial,
                OptionValue::Invalid => return FsCallSummary::Invalid,
            };
            FsCallSummary::Effect(vec![path(0, FilesystemOperation::Delete, recursive)])
        }
        Member::Unlink => {
            if values.len() != 1 || !possible_path(0) {
                return FsCallSummary::Invalid;
            }
            FsCallSummary::Effect(vec![path(0, FilesystemOperation::Delete, false)])
        }
        Member::WriteFile | Member::AppendFile => {
            if values.get(2).is_some_and(option_has_accessor) {
                return FsCallSummary::Partial;
            }
            if !(2..=3).contains(&values.len())
                || !values.first().is_some_and(possible_file_argument)
                || !possible_data(&values[1])
                || values
                    .get(2)
                    .is_some_and(|value| !possible_write_options(value))
            {
                return FsCallSummary::Invalid;
            }
            FsCallSummary::Effect(vec![path(0, FilesystemOperation::Write, false)])
        }
        Member::CopyFile => {
            if !(2..=3).contains(&values.len())
                || !possible_path(0)
                || !possible_path(1)
                || values.get(2).is_some_and(|value| !possible_number(value))
            {
                return FsCallSummary::Invalid;
            }
            FsCallSummary::Effect(vec![
                path(0, FilesystemOperation::Read, false),
                path(1, FilesystemOperation::Write, false),
            ])
        }
        Member::Rename | Member::Link => {
            if values.len() != 2 || !possible_path(0) || !possible_path(1) {
                return FsCallSummary::Invalid;
            }
            move_or_link_filesystems(member, values, &path)
        }
        Member::Symlink => {
            if !(2..=3).contains(&values.len())
                || !possible_path(0)
                || !possible_path(1)
                || values
                    .get(2)
                    .is_some_and(|value| !possible_symlink_kind(value))
            {
                return FsCallSummary::Invalid;
            }
            FsCallSummary::Effect(vec![
                path(1, FilesystemOperation::Write, false)
                    .metadata()
                    .without_final_symlink_follow(),
            ])
        }
        Member::Truncate => {
            if !(1..=2).contains(&values.len())
                || !values.first().is_some_and(possible_file_argument)
                || values.get(1).is_some_and(|value| !possible_number(value))
            {
                return FsCallSummary::Invalid;
            }
            FsCallSummary::Effect(vec![path(0, FilesystemOperation::Write, false)])
        }
        Member::Chmod | Member::Chown => {
            let expected = if member == Member::Chmod { 2 } else { 3 };
            if values.len() != expected
                || !possible_path(0)
                || (member == Member::Chmod && !possible_mode(&values[1]))
                || (member == Member::Chown
                    && values[1..].iter().any(|value| !possible_number(value)))
            {
                return FsCallSummary::Invalid;
            }
            FsCallSummary::Effect(vec![path(0, FilesystemOperation::Write, false).metadata()])
        }
        Member::Mkdir => {
            if !possible_path(0) || !(1..=2).contains(&values.len()) {
                return FsCallSummary::Invalid;
            }
            let recursive = match values
                .get(1)
                .map_or(OptionValue::Exact(false), mkdir_recursive_option)
            {
                OptionValue::Exact(recursive) => recursive,
                OptionValue::Partial => return FsCallSummary::Partial,
                OptionValue::Invalid => return FsCallSummary::Invalid,
            };
            FsCallSummary::Effect(vec![path(0, FilesystemOperation::Write, recursive)])
        }
        Member::Open => {
            if !possible_path(0)
                || !(1..=3).contains(&values.len())
                || values.get(2).is_some_and(|value| !possible_mode(value))
            {
                return FsCallSummary::Invalid;
            }
            let flags = match values.get(1) {
                None => "r",
                Some(flags) => {
                    let Some(flags) = value_string(flags) else {
                        return FsCallSummary::Partial;
                    };
                    flags
                }
            };
            open_filesystems(flags, &path)
        }
        Member::AppendFileSync
        | Member::ChmodSync
        | Member::ChownSync
        | Member::CopyFileSync
        | Member::CreateWriteStream
        | Member::LinkSync
        | Member::MkdirSync
        | Member::OpenSync
        | Member::RenameSync
        | Member::RmdirSync
        | Member::RmSync
        | Member::SymlinkSync
        | Member::TruncateSync
        | Member::UnlinkSync
        | Member::WriteFileSync
        | Member::Exec
        | Member::ExecSync
        | Member::Spawn
        | Member::SpawnSync
        | Member::ExecFile
        | Member::ExecFileSync => FsCallSummary::Invalid,
    }
}

fn move_or_link_filesystems(
    member: Member,
    values: &[Value],
    path: &impl Fn(usize, FilesystemOperation, bool) -> LanguageFilesystem,
) -> FsCallSummary {
    let identity = values.first().and_then(value_string).map(str::to_owned);
    if matches!(member, Member::Link | Member::LinkSync) {
        FsCallSummary::Effect(vec![
            path(0, FilesystemOperation::Write, false).metadata(),
            path(1, FilesystemOperation::Write, false).observed_identity(identity, true, true),
        ])
    } else {
        FsCallSummary::Effect(vec![
            path(0, FilesystemOperation::Delete, false),
            path(1, FilesystemOperation::Write, false)
                .identity(identity, false)
                .protects_descendants()
                .without_final_symlink_follow(),
        ])
    }
}

fn open_filesystems(
    flags: &str,
    path: &impl Fn(usize, FilesystemOperation, bool) -> LanguageFilesystem,
) -> FsCallSummary {
    let operations: &[FilesystemOperation] = match flags {
        "r" | "rs" => &[FilesystemOperation::Read],
        "r+" | "rs+" => &[FilesystemOperation::Read, FilesystemOperation::Write],
        "w" | "wx" | "w+" | "wx+" | "a" | "ax" | "a+" | "ax+" | "as" | "as+" => {
            &[FilesystemOperation::Write]
        }
        _ => return FsCallSummary::Invalid,
    };
    FsCallSummary::Effect(
        operations
            .iter()
            .map(|operation| path(0, *operation, false))
            .collect(),
    )
}

enum OptionValue {
    Exact(bool),
    Partial,
    Invalid,
}

fn recursive_option(value: &Value) -> OptionValue {
    match value {
        Value::Object(properties) => {
            if properties.values().any(accessor_value) {
                return OptionValue::Partial;
            }
            match properties.get("recursive") {
                Some(Value::Bool(recursive)) => OptionValue::Exact(*recursive),
                Some(value) if unknown_value(value) => OptionValue::Partial,
                Some(_) => OptionValue::Invalid,
                None => OptionValue::Exact(false),
            }
        }
        value if unknown_value(value) => OptionValue::Partial,
        _ => OptionValue::Invalid,
    }
}

fn mkdir_recursive_option(value: &Value) -> OptionValue {
    if matches!(value, Value::Number(_) | Value::String(_)) {
        OptionValue::Exact(false)
    } else {
        recursive_option(value)
    }
}

fn possible_callback(value: &Value) -> bool {
    child_callback_shape(value) || unknown_value(value)
}

fn possible_data(value: &Value) -> bool {
    matches!(value, Value::String(_)) || unknown_value(value)
}

fn possible_write_options(value: &Value) -> bool {
    matches!(value, Value::String(_) | Value::Object(_)) || unknown_value(value)
}

fn possible_number(value: &Value) -> bool {
    matches!(value, Value::Number(_)) || unknown_value(value)
}

fn possible_mode(value: &Value) -> bool {
    matches!(value, Value::Number(_) | Value::String(_)) || unknown_value(value)
}

fn option_has_accessor(value: &Value) -> bool {
    matches!(value, Value::Object(properties) if properties.values().any(accessor_value))
}

fn possible_symlink_kind(value: &Value) -> bool {
    matches!(value, Value::String(_) | Value::Undefined | Value::Null) || unknown_value(value)
}

fn property_value(value: &Value, property: &str, state: &State) -> Value {
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

fn module_property_value(module: Module, property: &str, state: &State) -> Value {
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

fn possible_path_argument(value: &Value) -> bool {
    matches!(value, Value::String(_)) || unknown_value(value)
}

fn possible_file_argument(value: &Value) -> bool {
    possible_path_argument(value) || matches!(value, Value::Number(_))
}

fn value_string(value: &Value) -> Option<&str> {
    match value {
        Value::String(value) => Some(value),
        _ => None,
    }
}

fn language_call_input(
    syntax: SyntaxProfile,
    callable: &str,
    arguments: &Arguments,
) -> InvocationInput {
    let mut complete = arguments.complete;
    let represented = arguments.values.len();
    let mut positional = Vec::with_capacity(represented.min(MAX_NATIVE_ARGUMENTS));
    for value in arguments.values.iter().take(MAX_NATIVE_ARGUMENTS) {
        let (value, exact) = native_value(value, 0);
        complete &= exact;
        positional.push(value);
    }
    if represented > MAX_NATIVE_ARGUMENTS {
        complete = false;
        if let Some(value) = positional.last_mut() {
            *value = native_unknown();
        }
    }
    let mut payload = language_call_payload(syntax, callable, positional);
    if serde_json::to_vec(&payload).map_or(true, |bytes| bytes.len() > MAX_NATIVE_EVIDENCE_BYTES) {
        complete = false;
        payload = language_call_payload(syntax, callable, vec![native_unknown()]);
    }
    InvocationInput::native(payload, complete)
}

fn language_call_payload(
    syntax: SyntaxProfile,
    callable: &str,
    positional: Vec<JsonValue>,
) -> JsonValue {
    let language = match syntax {
        SyntaxProfile::JavaScript => "javascript",
        SyntaxProfile::TypeScript => "typescript",
        SyntaxProfile::Tsx => "tsx",
        SyntaxProfile::Ambiguous => unreachable!(),
    };
    let mut payload = Map::new();
    // JavaScript v2 adds object and undefined values without changing frozen v1.
    payload.insert("v".into(), JsonValue::from(2));
    payload.insert("language".into(), JsonValue::String(language.into()));
    payload.insert("callable".into(), JsonValue::String(callable.into()));
    payload.insert("positional".into(), JsonValue::Array(positional));
    payload.insert("keywords".into(), JsonValue::Array(Vec::new()));
    JsonValue::Object(payload)
}

fn native_value(value: &Value, depth: usize) -> (JsonValue, bool) {
    if depth >= 16 {
        return (native_unknown(), false);
    }
    match value {
        Value::Undefined => (native_tag("undefined", None), true),
        Value::Null => (native_tag("null", None), true),
        Value::Bool(value) => (native_tag("bool", Some(JsonValue::Bool(*value))), true),
        Value::Number(value) => (native_tag("int", Some(JsonValue::from(*value))), true),
        Value::String(value) => bounded_native_string(value),
        Value::Array(values) if values.len() <= MAX_NATIVE_COLLECTION_ITEMS => {
            let mut exact = true;
            let items = values
                .iter()
                .map(|value| {
                    let (value, item_exact) = native_value(value, depth + 1);
                    exact &= item_exact;
                    value
                })
                .collect();
            (native_sequence(items), exact)
        }
        Value::Object(properties) if properties.len() <= MAX_NATIVE_COLLECTION_ITEMS => {
            let mut exact = true;
            let properties = properties
                .iter()
                .map(|(name, value)| {
                    let (value, property_exact) = native_value(value, depth + 1);
                    exact &= property_exact;
                    let mut property = Map::new();
                    property.insert("name".into(), JsonValue::String(name.clone()));
                    property.insert("value".into(), value);
                    JsonValue::Object(property)
                })
                .collect();
            (native_object(properties), exact)
        }
        Value::Invalid
        | Value::NonCallablePrimitive
        | Value::SynchronousThrow
        | Value::Divergent
        | Value::Promise
        | Value::RejectedPromise
        | Value::Unknown
        | Value::Array(_)
        | Value::Object(_)
        | Value::Module(_)
        | Value::Known(_)
        | Value::Function(_)
        | Value::Accessor
        | Value::AccessorGetter(_)
        | Value::Require
        | Value::Eval
        | Value::DynamicEvalResult
        | Value::FunctionConstructor
        | Value::DynamicFunction(_)
        | Value::ObjectBuiltin
        | Value::Process
        | Value::Environment
        | Value::CommonJsModule
        | Value::InheritedNodeProperty(_)
        | Value::NodeModule
        | Value::LoadedModule(_)
        | Value::NodeModulePrototype
        | Value::NodeModuleMember(_)
        | Value::Deno
        | Value::DenoCommandConstructor
        | Value::DenoCommand(_)
        | Value::Bun
        | Value::BunFile(_)
        | Value::OpenClawTools
        | Value::UnknownModuleMember(_)
        | Value::UnknownReceiver(_) => (native_unknown(), false),
    }
}

fn bounded_native_string(value: &str) -> (JsonValue, bool) {
    if value.len() > MAX_NATIVE_EVIDENCE_BYTES {
        (native_unknown(), false)
    } else {
        (
            native_tag("string", Some(JsonValue::String(value.to_owned()))),
            true,
        )
    }
}

fn native_unknown() -> JsonValue {
    native_tag("unknown", None)
}

fn native_sequence(items: Vec<JsonValue>) -> JsonValue {
    let mut tagged = Map::new();
    tagged.insert("kind".into(), JsonValue::String("sequence".into()));
    tagged.insert("items".into(), JsonValue::Array(items));
    JsonValue::Object(tagged)
}

fn native_object(properties: Vec<JsonValue>) -> JsonValue {
    let mut tagged = Map::new();
    tagged.insert("kind".into(), JsonValue::String("object".into()));
    tagged.insert("properties".into(), JsonValue::Array(properties));
    JsonValue::Object(tagged)
}

fn native_tag(kind: &str, value: Option<JsonValue>) -> JsonValue {
    let mut tagged = Map::new();
    tagged.insert("kind".into(), JsonValue::String(kind.into()));
    if let Some(value) = value {
        tagged.insert("value".into(), value);
    }
    JsonValue::Object(tagged)
}

fn string_coercion(value: &Value) -> Option<String> {
    match value {
        Value::Undefined => Some("undefined".to_owned()),
        Value::Null => Some("null".to_owned()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Number(value) => Some(value.to_string()),
        Value::String(value) => Some(value.clone()),
        _ => None,
    }
}

fn abrupt_value(value: &Value) -> bool {
    matches!(value, Value::SynchronousThrow | Value::Divergent)
}

fn abrupt_control(value: &Value) -> Option<Control> {
    match value {
        Value::SynchronousThrow => Some(Control::Throw),
        Value::Divergent => Some(Control::Diverge),
        _ => None,
    }
}

fn truthy(value: &Value) -> Option<bool> {
    match value {
        Value::Invalid
        | Value::NonCallablePrimitive
        | Value::Accessor
        | Value::AccessorGetter(_)
        | Value::SynchronousThrow
        | Value::Divergent
        | Value::Unknown
        | Value::DynamicEvalResult
        | Value::UnknownModuleMember(_)
        | Value::UnknownReceiver(_) => None,
        Value::Undefined | Value::Null => Some(false),
        Value::Bool(value) => Some(*value),
        Value::Number(value) => Some(*value != 0),
        Value::String(value) => Some(!value.is_empty()),
        Value::Promise
        | Value::RejectedPromise
        | Value::Array(_)
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
        | Value::InheritedNodeProperty(_)
        | Value::NodeModule
        | Value::LoadedModule(_)
        | Value::NodeModulePrototype
        | Value::NodeModuleMember(_)
        | Value::Deno
        | Value::DenoCommandConstructor
        | Value::DenoCommand(_)
        | Value::Bun
        | Value::BunFile(_)
        | Value::OpenClawTools => Some(true),
    }
}

fn nullish(value: &Value) -> Option<bool> {
    match value {
        Value::Undefined | Value::Null => Some(true),
        value if unknown_value(value) || abrupt_value(value) => None,
        _ => Some(false),
    }
}

fn strict_equal(left: &Value, right: &Value) -> Option<bool> {
    match (left, right) {
        (Value::Undefined, Value::Undefined) | (Value::Null, Value::Null) => Some(true),
        (Value::Bool(left), Value::Bool(right)) => Some(left == right),
        (Value::Number(left), Value::Number(right)) => Some(left == right),
        (Value::String(left), Value::String(right)) => Some(left == right),
        (left, right) if uncertain_identity(left) || uncertain_identity(right) => None,
        (left, right) if primitive_value(left) || primitive_value(right) => Some(false),
        _ => None,
    }
}

fn primitive_value(value: &Value) -> bool {
    matches!(
        value,
        Value::Undefined | Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_)
    )
}

fn uncertain_identity(value: &Value) -> bool {
    matches!(
        value,
        Value::Unknown
            | Value::DynamicEvalResult
            | Value::Invalid
            | Value::SynchronousThrow
            | Value::Divergent
            | Value::UnknownModuleMember(_)
            | Value::UnknownReceiver(_)
    )
}

fn loose_equal(left: &Value, right: &Value) -> Option<bool> {
    match (left, right) {
        (Value::Undefined, Value::Null) | (Value::Null, Value::Undefined) => Some(true),
        (Value::Undefined, Value::Undefined)
        | (Value::Null, Value::Null)
        | (Value::Bool(_), Value::Bool(_))
        | (Value::Number(_), Value::Number(_))
        | (Value::String(_), Value::String(_)) => strict_equal(left, right),
        (left, right) if unknown_value(left) || unknown_value(right) => None,
        _ => None,
    }
}

fn join_values(left: Value, right: Value) -> Value {
    if left == right { left } else { Value::Unknown }
}

fn join_node_property_state(
    left: NodePropertyState,
    right: NodePropertyState,
) -> NodePropertyState {
    NodePropertyState {
        value: join_values(left.value, right.value),
        own: if left.own == right.own {
            left.own
        } else {
            None
        },
        kind: if left.kind == right.kind {
            left.kind
        } else {
            NodePropertyKind::Unknown
        },
        enumerable: if left.enumerable == right.enumerable {
            left.enumerable
        } else {
            None
        },
        assignment: if left.assignment == right.assignment {
            left.assignment
        } else {
            NodeMutation::Unknown
        },
        deletion: if left.deletion == right.deletion {
            left.deletion
        } else {
            NodeMutation::Unknown
        },
    }
}

fn join_states(mut left: State, right: State) -> State {
    if left.scopes.len() != right.scopes.len() || left.scope_chain != right.scope_chain {
        return State {
            scopes: left
                .scopes
                .into_iter()
                .map(|scope| Scope {
                    id: scope.id,
                    function: scope.function,
                    bindings: scope
                        .bindings
                        .into_keys()
                        .map(|name| (name, Value::Unknown))
                        .collect(),
                })
                .collect(),
            scope_chain: left.scope_chain,
            next_scope_id: left.next_scope_id.max(right.next_scope_id),
            owned_members: left
                .owned_members
                .intersection(&right.owned_members)
                .copied()
                .collect(),
            loaded_modules_intact: left
                .loaded_modules_intact
                .intersection(&right.loaded_modules_intact)
                .copied()
                .collect(),
            node_properties: left
                .node_properties
                .into_iter()
                .map(|(property, value)| {
                    let right = right
                        .node_properties
                        .get(&property)
                        .cloned()
                        .unwrap_or_else(unknown_node_property);
                    (property, join_node_property_state(value, right))
                })
                .collect(),
            cwd: if left.cwd == right.cwd {
                left.cwd
            } else {
                NestedExecutionCwd::Unknown
            },
            prototype_integrity_known: left.prototype_integrity_known
                && right.prototype_integrity_known,
            runtime_globals_intact: left.runtime_globals_intact && right.runtime_globals_intact,
        };
    }
    for (left_scope, right_scope) in left.scopes.iter_mut().zip(right.scopes) {
        let names = left_scope
            .bindings
            .keys()
            .chain(right_scope.bindings.keys())
            .cloned()
            .collect::<BTreeSet<_>>();
        left_scope.bindings = names
            .into_iter()
            .map(|name| {
                let left = left_scope
                    .bindings
                    .get(&name)
                    .cloned()
                    .unwrap_or(Value::Unknown);
                let right = right_scope
                    .bindings
                    .get(&name)
                    .cloned()
                    .unwrap_or(Value::Unknown);
                (name, join_values(left, right))
            })
            .collect();
    }
    left.owned_members = left
        .owned_members
        .intersection(&right.owned_members)
        .copied()
        .collect();
    left.loaded_modules_intact = left
        .loaded_modules_intact
        .intersection(&right.loaded_modules_intact)
        .copied()
        .collect();
    for (property, value) in &mut left.node_properties {
        let right = right
            .node_properties
            .get(property)
            .cloned()
            .unwrap_or_else(unknown_node_property);
        *value = join_node_property_state(value.clone(), right);
    }
    if left.cwd != right.cwd {
        left.cwd = NestedExecutionCwd::Unknown;
    }
    left.prototype_integrity_known &= right.prototype_integrity_known;
    left.runtime_globals_intact &= right.runtime_globals_intact;
    left.next_scope_id = left.next_scope_id.max(right.next_scope_id);
    left
}

fn values_bytes(values: &[Value]) -> Option<usize> {
    values.iter().try_fold(0usize, |bytes, value| {
        bytes.checked_add(value_bytes(value)?)
    })
}

fn properties_bytes(properties: &BTreeMap<String, Value>) -> Option<usize> {
    properties.iter().try_fold(0usize, |bytes, (name, value)| {
        bytes
            .checked_add(name.len())?
            .checked_add(value_bytes(value)?)
    })
}

fn value_bytes(value: &Value) -> Option<usize> {
    match value {
        Value::String(value) => Some(value.len()),
        Value::Array(values) => values_bytes(values),
        Value::Object(properties) => properties_bytes(properties),
        _ => Some(0),
    }
}

fn parse_number(source: &str) -> Option<i64> {
    let source = source.replace('_', "");
    if let Some(hex) = source
        .strip_prefix("0x")
        .or_else(|| source.strip_prefix("0X"))
    {
        i64::from_str_radix(hex, 16).ok()
    } else if let Some(binary) = source
        .strip_prefix("0b")
        .or_else(|| source.strip_prefix("0B"))
    {
        i64::from_str_radix(binary, 2).ok()
    } else if let Some(octal) = source
        .strip_prefix("0o")
        .or_else(|| source.strip_prefix("0O"))
    {
        i64::from_str_radix(octal, 8).ok()
    } else {
        source.parse().ok()
    }
}

fn decode_js_string(source: &str) -> Option<String> {
    let quote = source.as_bytes().first().copied()?;
    if !matches!(quote, b'\'' | b'"') || source.as_bytes().last().copied() != Some(quote) {
        return None;
    }
    decode_escaped(&source[1..source.len() - 1])
}

fn decode_escape(source: &str) -> Option<String> {
    source.strip_prefix('\\').and_then(|source| {
        let wrapped = format!("\\{source}");
        decode_escaped(&wrapped)
    })
}

fn decode_escaped(source: &str) -> Option<String> {
    let mut value = String::new();
    let mut chars = source.chars();
    while let Some(character) = chars.next() {
        if character != '\\' {
            value.push(character);
            continue;
        }
        let escaped = chars.next()?;
        match escaped {
            '\n' => {}
            '\r' => {
                if chars.clone().next() == Some('\n') {
                    chars.next();
                }
            }
            'b' => value.push('\u{0008}'),
            'f' => value.push('\u{000c}'),
            'n' => value.push('\n'),
            'r' => value.push('\r'),
            't' => value.push('\t'),
            'v' => value.push('\u{000b}'),
            '0' if !chars
                .clone()
                .next()
                .is_some_and(|next| next.is_ascii_digit()) =>
            {
                value.push('\0');
            }
            'x' => {
                let code = take_hex(&mut chars, 2)?;
                value.push(char::from_u32(code)?);
            }
            'u' if chars.clone().next() == Some('{') => {
                chars.next();
                let mut hex = String::new();
                for next in chars.by_ref() {
                    if next == '}' {
                        break;
                    }
                    if !next.is_ascii_hexdigit() || hex.len() >= 6 {
                        return None;
                    }
                    hex.push(next);
                }
                if hex.is_empty() {
                    return None;
                }
                value.push(char::from_u32(u32::from_str_radix(&hex, 16).ok()?)?);
            }
            'u' => {
                let code = take_hex(&mut chars, 4)?;
                value.push(char::from_u32(code)?);
            }
            '\\' | '\'' | '"' | '`' | '$' => value.push(escaped),
            character if !character.is_ascii_digit() => value.push(character),
            _ => return None,
        }
    }
    Some(value)
}

fn take_hex(chars: &mut impl Iterator<Item = char>, count: usize) -> Option<u32> {
    let mut value = 0u32;
    for _ in 0..count {
        value = value.checked_mul(16)?;
        value = value.checked_add(chars.next()?.to_digit(16)?)?;
    }
    Some(value)
}

fn delimited_has_hole(node: &HirNode, source: &str) -> bool {
    let Some(source) = source.get(node.span().start()..node.span().end()) else {
        return true;
    };
    let mut depth = 0usize;
    let mut previous_comma = true;
    let mut quote = None;
    let mut escaped = false;
    for character in source.chars() {
        if let Some(active_quote) = quote {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == active_quote {
                quote = None;
            }
            continue;
        }
        match character {
            '\'' | '"' | '`' => {
                if depth == 1 {
                    previous_comma = false;
                }
                quote = Some(character);
            }
            '[' | '(' | '{' => {
                if depth == 1 {
                    previous_comma = false;
                }
                depth += 1;
            }
            ']' | ')' | '}' => {
                depth = depth.saturating_sub(1);
                if depth == 1 {
                    previous_comma = false;
                }
            }
            ',' if depth == 1 => {
                if previous_comma {
                    return true;
                }
                previous_comma = true;
            }
            character if depth == 1 && !character.is_whitespace() => previous_comma = false,
            _ => {}
        }
    }
    false
}

fn delimited_holes(source: &str, start: usize, end: usize, follows_element: bool) -> Option<usize> {
    let mut characters = source.get(start..end)?.chars().peekable();
    let mut commas = 0usize;
    while let Some(character) = characters.next() {
        match character {
            ',' => commas += 1,
            character if character.is_whitespace() => {}
            '/' => match characters.next()? {
                '/' => {
                    for character in characters.by_ref() {
                        if matches!(character, '\n' | '\r') {
                            break;
                        }
                    }
                }
                '*' => {
                    let mut previous = '\0';
                    let mut closed = false;
                    for character in characters.by_ref() {
                        if previous == '*' && character == '/' {
                            closed = true;
                            break;
                        }
                        previous = character;
                    }
                    if !closed {
                        return None;
                    }
                }
                _ => return None,
            },
            _ => return None,
        }
    }
    Some(commas.saturating_sub(usize::from(follows_element)))
}

fn is_absolute(path: &str, platform: Platform) -> bool {
    path.starts_with('/')
        || platform == Platform::Windows
            && (path.starts_with("\\\\")
                || path.as_bytes().get(1) == Some(&b':')
                    && path
                        .as_bytes()
                        .get(2)
                        .is_some_and(|byte| matches!(byte, b'/' | b'\\')))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn analysis_for(program: &str, code: &str) -> LanguageAnalysis {
        let profile = super::super::profile(program).unwrap();
        analyze(
            profile,
            &InlineInput {
                program,
                code,
                home: "/home/dev",
                platform: Platform::Linux,
            },
            0,
        )
    }

    fn analysis(code: &str) -> LanguageAnalysis {
        analysis_for("node", code)
    }

    fn report(code: &str) -> InlineReport {
        analysis(code).into_report()
    }

    fn requested_for(program: &str, code: &str, target: &str) -> bool {
        analysis_for(program, code)
            .draft()
            .calls()
            .iter()
            .any(|call| {
                call.filesystems()
                    .iter()
                    .any(|filesystem| filesystem.requested() == Some(target))
            })
    }

    fn root_for(program: &str, code: &str) -> bool {
        requested_for(program, code, "/")
    }

    fn root(code: &str) -> bool {
        root_for("node", code)
    }

    fn assert_inert(code: &str) {
        let analysis = analysis(code);
        assert_eq!(analysis.report(), &InlineReport::default(), "{code}");
        assert!(analysis.draft().calls().is_empty(), "{code}");
    }

    #[test]
    fn require_imports_and_exact_values_reach_owned_sinks() {
        assert!(root(
            "const fs=require('fs'); const target=`${'/'}`; fs.rmSync(target, {recursive:true})"
        ));
        assert!(root(
            "import * as files from 'node:fs'; files.rmSync('/', {recursive:true})"
        ));
        assert!(root(
            "import {rmSync as remove} from 'fs'; remove('/', {recursive:true})"
        ));
        assert!(root(
            "const files=require('fs'); eval(\"files.rmSync('/', {recursive:true})\")"
        ));
        assert_eq!(
            report("const {spawn}=require('child_process'); spawn('nah', ['nap'])")
                .nested_executions(),
            [crate::NestedExecution::Command {
                argv: vec!["nah".into(), "nap".into()],
                cwd: crate::NestedExecutionCwd::Inherited,
                stdout_inherited: false,
            }]
        );
    }

    #[test]
    fn dormant_code_getters_builders_and_dynamic_construction_are_inert() {
        let dangerous = "require('child_process').execSync('rm -rf /')";
        for code in [
            format!("function dormant(){{{dangerous}}}"),
            format!("setTimeout(()=>{dangerous}, 0)"),
            format!("const value={{get danger(){{{dangerous}}}}}"),
            format!("builder({dangerous:?})"),
            format!("new Function({dangerous:?})"),
        ] {
            assert_inert(&code);
        }
        assert_eq!(
            report(&format!("new Function({dangerous:?})()"))
                .nested_executions()
                .len(),
            1
        );
    }

    #[test]
    fn lexical_shadowing_and_branch_local_ownership_do_not_escape() {
        for code in [
            "{ const require=safe; require('fs').rmSync('/', {recursive:true}) }",
            "if (true) { const fs=require('fs'); } fs.rmSync('/', {recursive:true})",
            "function safe(require) { require('fs').rmSync('/', {recursive:true}) } safe(other)",
            "try { throw 1 } catch (require) { require('fs').rmSync('/', {recursive:true}) }",
            "const fs=require('fs'); function make(){const fs=safe; return ()=>fs.rmSync('/', {recursive:true})} make()()",
        ] {
            assert_inert(code);
        }
    }

    #[test]
    fn monkey_patches_and_unknown_module_consumers_remove_ownership() {
        for code in [
            "const fs=require('fs'); fs.rmSync=safe; fs.rmSync('/', {recursive:true})",
            "require('fs').rmSync=safe; require('fs').rmSync('/', {recursive:true})",
            "const cp=require('child_process'); Object.defineProperty(cp, 'exec', {value:safe}); cp.exec('rm -rf /')",
            "const fs=require('fs'); plugin(fs); fs.rmSync('/', {recursive:true})",
            "const fs=require('fs'); if (flag) { fs.rmSync=safe } fs.rmSync('/', {recursive:true})",
            "const fs=require('fs'); switch (flag) { default: break } fs.rmSync('/', {recursive:true})",
            "const options={recursive:true}; options.recursive=false; require('fs').rmSync('/', options)",
            "const options={recursive:true}; const alias=options; alias.recursive=false; require('fs').rmSync('/', options)",
            "const options={recursive:true}; Object.defineProperty(options, 'recursive', {value:false}); require('fs').rmSync('/', options)",
            "const options={constructor:require('module'),recursive:true}; options.recursive=false; require('fs').rmSync('/', options)",
            "process.env.HOME='/tmp/safe'; require('fs').rmSync(process.env.HOME, {recursive:true})",
            "const env=process.env; env.HOME='/tmp/safe'; require('fs').rmSync(process.env.HOME, {recursive:true})",
            "eval('require=safe'); require('fs').rmSync('/', {recursive:true})",
            "eval(\"require('fs').rmSync=safe\"); require('fs').rmSync('/', {recursive:true})",
        ] {
            assert!(!root(code), "{code}");
        }
        assert!(
            report("const args=['-rf','/']; args.push('safe'); require('child_process').spawn('rm', args)")
                .nested_executions()
                .is_empty()
        );
    }

    #[test]
    fn direct_node_module_loader_changes_remove_module_ownership() {
        for code in [
            "require('module')._load=safe; require('fs').rmSync('/', {recursive:true})",
            "const Module=require('module'); Module._load=safe; require('fs').rmSync('/', {recursive:true})",
            "const Module=require('node:module'); delete Module.createRequire; require('fs').rmSync('/', {recursive:true})",
            "const Module=require('module'); plugin(Module._load); require('fs').rmSync('/', {recursive:true})",
            "const Module=require('module'); sink.loader=Module._load; require('fs').rmSync('/', {recursive:true})",
            "const Module=require('node:module'); Module.createRequire('/tmp/plugin.js'); require('fs').rmSync('/', {recursive:true})",
            "const Module=require('node:module'); Module.isBuiltin=undefined; Module.isBuiltin('fs'); require('fs').rmSync('/', {recursive:true})",
            "const Module=require('node:module').Module; Module._load=safe; require('fs').rmSync('/', {recursive:true})",
            "const Module=module.constructor; Module._load=safe; require('fs').rmSync('/', {recursive:true})",
            "require('module').prototype.constructor._load=safe; require('fs').rmSync('/', {recursive:true})",
            "module.require=safe; require('fs').rmSync('/', {recursive:true})",
            "Object.defineProperty(module, 'require', {value:safe}); require('fs').rmSync('/', {recursive:true})",
            "require('module').prototype.require=safe; require('fs').rmSync('/', {recursive:true})",
            "Object.defineProperty(require('module').prototype, 'require', {value:safe}); require('fs').rmSync('/', {recursive:true})",
            "const box=[require('module')]; box[0]._load=safe; require('fs').rmSync('/', {recursive:true})",
            "const Module=require('module'); sink.loader=[Module._load]; require('fs').rmSync('/', {recursive:true})",
        ] {
            assert!(!root(code), "{code}");
        }
        assert!(
            report("const Module=require('module'); Module._load('fs'); require('child_process').spawn('rm', ['-rf', '/'])")
                .nested_executions()
                .is_empty()
        );
    }

    #[test]
    fn rebound_node_properties_do_not_reuse_stale_provenance() {
        for code in [
            "const {rmSync}=require('fs'); const M=require('module'); M._load=undefined; M._load('fs'); rmSync('/',{recursive:true})",
            "const {rmSync}=require('fs'); const M=require('module'); M.isBuiltin=undefined; M.isBuiltin('fs'); rmSync('/',{recursive:true})",
            "const {rmSync}=require('fs'); module.require=undefined; module.require('fs'); rmSync('/',{recursive:true})",
            "const {rmSync}=require('fs'); const M=require('module'); M.Module=undefined; M.Module.isBuiltin('fs'); rmSync('/',{recursive:true})",
            "const {rmSync}=require('fs'); Object.defineProperty(module,'constructor',{value:undefined}); module.constructor.isBuiltin('fs'); rmSync('/',{recursive:true})",
            "const {rmSync}=require('fs'); const M=require('module'); Object.defineProperty(M,'_load',null); rmSync('/',{recursive:true})",
            "const {rmSync}=require('fs'); const M=require('module'); Object.defineProperty(M,'_load'); rmSync('/',{recursive:true})",
            "const {rmSync}=require('fs'); const M=require('module'); Object.defineProperty(M,'_load',{set(value){}}); M._load('fs'); rmSync('/',{recursive:true})",
            "const {rmSync}=require('fs'); const M=require('module'); Object.defineProperty(M,'_load',{get:undefined}); M._load('fs'); rmSync('/',{recursive:true})",
            "const {rmSync}=require('fs'); const M=require('module'); delete M._load; M._load('fs'); rmSync('/',{recursive:true})",
            "const {rmSync}=require('fs'); const M=require('module'); delete M.isBuiltin; M.isBuiltin('fs'); rmSync('/',{recursive:true})",
            "const {rmSync}=require('fs'); const M=require('module'); delete M.Module; M.Module.isBuiltin('fs'); rmSync('/',{recursive:true})",
            "const {rmSync}=require('fs'); const M=require('module'); M._load+=1; M._load('fs'); rmSync('/',{recursive:true})",
            "const {rmSync}=require('fs'); const M=require('module'); Object.defineProperty(M,'_load',{get:()=>undefined}); M._load('fs'); rmSync('/',{recursive:true})",
            "const {rmSync}=require('fs'); const M=require('module'); M.prototype.require=undefined; module.require('fs'); rmSync('/',{recursive:true})",
            "const {rmSync}=require('fs'); const M=require('module'); Object.defineProperty(M.prototype,'require',{value:undefined}); module.require('fs'); rmSync('/',{recursive:true})",
            "const {rmSync}=require('fs'); const M=require('module'); delete M.prototype.require; module.require('fs'); rmSync('/',{recursive:true})",
            "const M=require('module'); M._load('fs').rmSync=()=>{}; M._load('fs').rmSync('/',{recursive:true})",
            "const M=require('module'),fs=M._load('fs'); require('fs').rmSync=()=>{}; fs.rmSync('/',{recursive:true})",
            "const M=require('module'); M._load-={}; M._load('fs').rmSync('/',{recursive:true})",
            "const M=require('module'); M._load+=process.env.TAG; M._load('fs').rmSync('/',{recursive:true})",
        ] {
            assert!(analysis(code).draft().calls().is_empty(), "{code}");
        }
    }

    #[test]
    fn node_property_barriers_preserve_reachable_tail_effects() {
        for code in [
            "const {rmSync}=require('fs'); module.constructor=undefined; module.constructor._load('fs'); rmSync('/',{recursive:true})",
            "const {rmSync}=require('fs'); const M=require('module'); Object.defineProperty(M,'_load',{configurable:false}); delete M._load; M._load('fs'); rmSync('/',{recursive:true})",
            "const {rmSync}=require('fs'); const M=require('module'); Object.defineProperty(M,'_load',{writable:false}); M._load=undefined; M._load('fs'); rmSync('/',{recursive:true})",
            "const {rmSync}=require('fs'); const F=require('module').constructor; F.isBuiltin=()=>true; F.isBuiltin('fs'); rmSync('/',{recursive:true})",
            "const {rmSync}=require('fs'); const M=require('module'); M.constructor=undefined; delete M.constructor; M.constructor(''); rmSync('/',{recursive:true})",
            "const {rmSync}=require('fs'); const M=require('module'); M._load+=1; M._load.toString(); rmSync('/',{recursive:true})",
            "const {rmSync}=require('fs'); const M=require('module'); try { M._load+=null.x } catch {} M._load('fs'); rmSync('/',{recursive:true})",
            "const {rmSync}=require('fs'); const M=require('module'); Object.defineProperty(M,'_load',{configurable:false})._load('fs'); rmSync('/',{recursive:true})",
            "const {rmSync}=require('fs'),M=require('module'); plugin(M); M._load=undefined; M._load('fs'); rmSync('/',{recursive:true})",
            "const M=require('module'); module.constructor=M._load; require('fs').rmSync('/',{recursive:true})",
        ] {
            assert!(root(code), "{code}");
        }
    }

    #[test]
    fn node_descriptor_flags_keep_exact_loader_ownership() {
        for code in [
            "const M=require('module'); Object.defineProperty(M,'_load',{writable:false}); M._load=safe; require('fs').rmSync('/',{recursive:true})",
            "const M=require('module'); Object.defineProperty(M,'_load',{configurable:false}); delete M._load; require('fs').rmSync('/',{recursive:true})",
            "const M=require('module'); Object.defineProperty(M,'_load',{configurable:false}); Object.defineProperty(M,'_load',{enumerable:true}); require('fs').rmSync('/',{recursive:true})",
            "const M=require('module'); Object.defineProperty(M,'_load',{configurable:false}); Object.defineProperty(M,'_load',{value:M._load}); require('fs').rmSync('/',{recursive:true})",
        ] {
            assert!(root(code), "{code}");
        }
        for code in [
            "const M=require('module'); Object.defineProperty(M,'_load',{configurable:false}); M._load=safe; require('fs').rmSync('/',{recursive:true})",
            "const M=require('module'); Object.defineProperty(M,'_load',{writable:false}); delete M._load; require('fs').rmSync('/',{recursive:true})",
            "const M=require('module'); Object.defineProperty(M,'_load',{configurable:false}); Object.defineProperty(M,'_load',{enumerable:false}); require('fs').rmSync('/',{recursive:true})",
            "const M=require('module'); Object.defineProperty(M,'_load',{configurable:false}); Object.defineProperty(M,'_load',{get(){return M._load}}); require('fs').rmSync('/',{recursive:true})",
        ] {
            assert!(!root(code), "{code}");
        }
    }

    #[test]
    fn invalid_property_descriptors_stop_before_tail() {
        for code in [
            "const {rmSync}=require('fs'); const M=require('module'); Object.defineProperty(M,'_load',{value:safe,get(){}}); rmSync('/',{recursive:true})",
            "const {rmSync}=require('fs'); const M=require('module'); Object.defineProperty(M,'_load',{get:1}); rmSync('/',{recursive:true})",
            "const {rmSync}=require('fs'); const M=require('module'); Object.defineProperty(M,'_load',{set:'x'}); rmSync('/',{recursive:true})",
            "const {rmSync}=require('fs'); const M=require('module'); Object.defineProperty(M.prototype,'constructor',{value:undefined}); rmSync('/',{recursive:true})",
            "const {rmSync}=require('fs'),M=require('module'); Object.defineProperty(M,'_load',{get(){return ()=>{}},set(value){},configurable:false}); Object.defineProperty(M,'_load',{value:undefined}); rmSync('/',{recursive:true})",
        ] {
            assert!(!root(code), "{code}");
        }
    }

    #[test]
    fn javascript_runtime_order_preserves_reachable_loader_effects() {
        for code in [
            "const M=require('module'); M._load ||= null.x; M._load('fs').rmSync('/',{recursive:true})",
            "const M=require('module'); M._load ??= null.x; M._load('fs').rmSync('/',{recursive:true})",
            "const M=require('module'); try{M._load-={valueOf(){throw 1}}}catch{} M._load('fs').rmSync('/',{recursive:true})",
            "const {rmSync}=require('fs'); Object.defineProperty({},'x',{get get(){return ()=>1}}); rmSync('/',{recursive:true})",
            "const M=require('module');const d={get value(){return M._load}};Object.defineProperty(M,'_load',d);M._load('fs').rmSync('/',{recursive:true})",
            "Object.defineProperty({},'x',{get value(){require('fs').rmSync('/',{recursive:true});return 1}})",
        ] {
            assert!(root(code), "{code}");
        }
    }

    #[test]
    fn strict_writes_deletes_and_invalid_targets_stop_unreachable_tails() {
        for code in [
            "Object.defineProperty(null,'x',{}); require('fs').rmSync('/',{recursive:true})",
            "Object.defineProperty(1,'x',{}); require('fs').rmSync('/',{recursive:true})",
            "'use strict'; const M=require('module');Object.defineProperty(M,'_load',{writable:false});M._load=undefined;require('fs').rmSync('/',{recursive:true})",
            "'use strict';module.constructor=undefined;require('fs').rmSync('/',{recursive:true})",
            "function f(){'use strict';module.constructor=undefined}f();require('fs').rmSync('/',{recursive:true})",
            "export {};const M=require('module');Object.defineProperty(M,'_load',{writable:false});M._load=undefined;require('fs').rmSync('/',{recursive:true})",
            "const {rmSync}=require('fs'),M=require('module');if(delete M.prototype)rmSync('/',{recursive:true})",
            "const {rmSync}=require('fs'),M=require('module');Object.defineProperty(M,'_load',{configurable:false});if(delete M._load)rmSync('/',{recursive:true})",
            "'use strict';const {rmSync}=require('fs'),M=require('module');delete M.prototype;rmSync('/',{recursive:true})",
            "'use strict';const {rmSync}=require('fs'),M=require('module');Object.defineProperty(M,'_load',{writable:false});[M._load]=[undefined];rmSync('/',{recursive:true})",
        ] {
            assert!(!root(code), "{code}");
        }
        for code in [
            "'\\x75se strict';module.constructor=undefined;require('fs').rmSync('/',{recursive:true})",
            "const M=require('module');Object.defineProperty(M,'_load',{writable:false});M._load=undefined;require('fs').rmSync('/',{recursive:true})",
            "const {rmSync}=require('fs'),M=require('module');delete M.prototype;rmSync('/',{recursive:true})",
        ] {
            assert!(root(code), "{code}");
        }
    }

    #[test]
    fn aliased_node_module_loader_changes_remove_module_ownership() {
        for code in [
            "const Module=require('module'); const alias=Module; alias._load=safe; require('fs').rmSync('/', {recursive:true})",
            "const {_load:load}=require('node:module'); load('fs'); require('fs').rmSync('/', {recursive:true})",
            "const {Module}=require('node:module'); Module._load=safe; require('fs').rmSync('/', {recursive:true})",
            "import {createRequire as makeRequire} from 'node:module'; makeRequire('/tmp/plugin.js'); require('fs').rmSync('/', {recursive:true})",
            "import {Module} from 'node:module'; Module._load=safe; require('fs').rmSync('/', {recursive:true})",
        ] {
            assert!(!root(code), "{code}");
        }
        assert!(!root_for(
            "bun-js",
            "const Module=require('node:module'); const alias=Module; alias._load=safe; require('fs').rmSync('/', {recursive:true})",
        ));
        assert!(!root_for(
            "tsx",
            "import {Module} from 'node:module'; Module._load=safe; require('fs').rmSync('/', {recursive:true})",
        ));
    }

    #[test]
    fn unrelated_node_module_reads_preserve_module_ownership() {
        for code in [
            "const Module=require('module'); const names=Module.builtinModules; require('fs').rmSync('project-relative', {recursive:true})",
            "const Module=require('node:module'); Module.isBuiltin('fs'); require('fs').rmSync('project-relative', {recursive:true})",
            "const Module=require('module'); const alias=Module; alias.builtinModules; require('fs').rmSync('project-relative', {recursive:true})",
            "const box={loader:require('module'),x:0}; box.x=1; require('fs').rmSync('project-relative', {recursive:true})",
            "const box=[require('module'),0]; box[1]=1; require('fs').rmSync('project-relative', {recursive:true})",
            "const box={loader:require('module'),x:0}; Object.defineProperty(box,'x',{value:1}); require('fs').rmSync('project-relative', {recursive:true})",
            "const box=[require('module'),0]; Object.defineProperty(box,'1',{value:1}); require('fs').rmSync('project-relative', {recursive:true})",
            "const M=require('module'); const box={}; box.check=M.isBuiltin; require('fs').rmSync('project-relative', {recursive:true})",
            "const M=require('module'); M.isBuiltin=()=>false; require('fs').rmSync('project-relative', {recursive:true})",
            "const M=require('module'); M.Module=undefined; require('fs').rmSync('project-relative', {recursive:true})",
            "const M=require('module'); M.constructor=undefined; require('fs').rmSync('project-relative', {recursive:true})",
            "const M=require('module'); M.prototype=undefined; require('fs').rmSync('project-relative', {recursive:true})",
            "module.constructor=undefined; require('fs').rmSync('project-relative', {recursive:true})",
            "const M=require('module'); delete M.Module; require('fs').rmSync('project-relative', {recursive:true})",
        ] {
            assert!(requested_for("node", code, "project-relative"), "{code}");
        }

        assert!(!root(
            "const arr=[null, require('fs')]; arr['01'].rmSync('/', {recursive:true})"
        ));
        for code in [
            "const M=require('module'); plugin(M.isBuiltin); require('fs').rmSync('/', {recursive:true})",
            "const M=require('module'); plugin([M.isBuiltin]); require('fs').rmSync('/', {recursive:true})",
        ] {
            assert!(root(code), "{code}");
        }
    }

    #[test]
    fn only_real_node_prototype_hooks_remove_loader_ownership() {
        for code in [
            "require('module').constructor._load=safe; require('fs').rmSync('/', {recursive:true})",
            "require('module').prototype._load=safe; require('fs').rmSync('/', {recursive:true})",
            "require('module').prototype.createRequire=safe; require('fs').rmSync('/', {recursive:true})",
            "const Module=require('module'); Object.defineProperty(Module, 'unrelated', {value:1}); require('fs').rmSync('/', {recursive:true})",
            "const Module=require('module'); Module.require=safe; require('fs').rmSync('/', {recursive:true})",
            "const Module=require('module'); Object.defineProperty(Module, 'require', {value:safe}); require('fs').rmSync('/', {recursive:true})",
            "module.exports=safe; require('fs').rmSync('/', {recursive:true})",
            "Object.defineProperty(module, 'exports', {value:safe}); require('fs').rmSync('/', {recursive:true})",
            "const Module=require('module'); Object.defineProperty(Module.prototype, '_load', {value:safe}); require('fs').rmSync('/', {recursive:true})",
            "const {rmSync}=require('fs'); const Module=require('module'); Object.defineProperty(Module, '_load', {}); Module._load('fs'); rmSync('/', {recursive:true})",
            "const {rmSync}=require('fs'); delete module.require; module.require('fs'); rmSync('/', {recursive:true})",
        ] {
            assert!(root(code), "{code}");
        }
        assert!(!root(
            "require('module').prototype.isBuiltin('fs'); require('fs').rmSync('/', {recursive:true})"
        ));
        assert!(root(
            "require('module').constructor.isBuiltin('fs'); require('fs').rmSync('/', {recursive:true})"
        ));
    }

    #[test]
    fn var_hoisting_short_circuits_and_divergence_preserve_reachability() {
        for code in [
            "if (false) { var require=safe } require('fs').rmSync('/', {recursive:true})",
            "var fs=require('fs'); if (true) { var fs=safe } fs.rmSync('/', {recursive:true})",
            "true || require('fs').rmSync('/', {recursive:true})",
            "while (true) {} require('fs').rmSync('/', {recursive:true})",
        ] {
            assert_inert(code);
        }
        assert!(root("false || require('fs').rmSync('/', {recursive:true})"));
    }

    #[test]
    fn uncertain_function_returns_do_not_choose_one_branch() {
        assert_eq!(
            report(
                "function target(){if(flag){return '/tmp/safe'}else{return '/'}} require('fs').rmSync(target(), {recursive:true})"
            ),
            InlineReport::default()
        );
        assert!(root(
            "function target(){if(flag){return '/'}else{return '/'}} require('fs').rmSync(target(), {recursive:true})"
        ));
    }

    #[test]
    fn unsupported_and_malformed_regions_do_not_execute_nested_text() {
        let dangerous = "require('child_process').execSync('rm -rf /')";
        for code in [
            format!("switch (value) {{ case 1: {dangerous} }}"),
            format!("class Hidden {{ static run() {{ {dangerous} }} }}"),
            format!("const broken = ; {dangerous}"),
        ] {
            assert_inert(&code);
        }
    }
}
