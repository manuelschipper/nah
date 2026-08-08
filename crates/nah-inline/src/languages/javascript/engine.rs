use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use nah_proto::action::{FilesystemOperation, InvocationInput};
use nah_proto::ctx::Platform;
use serde_json::{Map, Value as JsonValue};

use crate::{
    InlineInput, InlineRefusal, InlineReport, LanguageAnalysis, LanguageCall, LanguageCallKind,
    LanguageDraft, LanguageFilesystem,
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

#[derive(Clone, Debug, Eq, PartialEq)]
struct DenoCommandValue {
    argv: Option<Vec<String>>,
    spawn: ExecutionCertainty,
    output: ExecutionCertainty,
    context_exact: bool,
    spawn_stdout_inherited: bool,
    output_stdout_inherited: bool,
    spawn_throws_after_effect: bool,
    output_throws_after_effect: bool,
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
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LocalFunction {
    parameters: Option<Vec<String>>,
    body: HirNode,
    expression_body: bool,
    asynchronous: bool,
    captured_scopes: Vec<usize>,
    source_identity: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Value {
    Unknown,
    Invalid,
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
    Require,
    Eval,
    DynamicEvalResult,
    FunctionConstructor,
    DynamicFunction(Option<String>),
    ObjectBuiltin,
    Process,
    Environment,
    Deno,
    DenoCommandConstructor,
    DenoCommand(DenoCommandValue),
    Bun,
    BunFile(Option<String>),
    OpenClawTools,
    UnknownModuleMember(Module),
    UnknownReceiver(Box<Value>),
}

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
    relative_cwd_known: bool,
    prototype_integrity_known: bool,
    runtime_globals_intact: bool,
}

impl PartialEq for State {
    fn eq(&self, other: &Self) -> bool {
        self.scopes == other.scopes
            && self.scope_chain == other.scope_chain
            && self.owned_members == other.owned_members
            && self.relative_cwd_known == other.relative_cwd_known
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
        match ownership {
            RuntimeOwnership::DenoEval => {
                bindings.insert("Deno".into(), Value::Deno);
            }
            RuntimeOwnership::Bun => {
                bindings.insert("Bun".into(), Value::Bun);
                bindings.insert("$".into(), Value::Known(KnownFunction::BunShell));
                bindings.insert("require".into(), Value::Require);
                bindings.insert("process".into(), Value::Process);
            }
            RuntimeOwnership::OpenClaw => {
                bindings.insert("tools".into(), Value::OpenClawTools);
            }
            RuntimeOwnership::Node => {
                bindings.insert("require".into(), Value::Require);
                bindings.insert("process".into(), Value::Process);
            }
            RuntimeOwnership::DenoCheckedEval | RuntimeOwnership::Unowned => {}
        }
        if matches!(ownership, RuntimeOwnership::Node | RuntimeOwnership::Bun) {
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
            relative_cwd_known: true,
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
    }

    fn widen(&mut self) {
        for scope in &mut self.scopes {
            for value in scope.bindings.values_mut() {
                *value = Value::Unknown;
            }
        }
        self.owned_members.clear();
        self.relative_cwd_known = false;
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
        if matches!(value, Value::Array(_) | Value::Object(_)) {
            for scope in &mut self.scopes {
                for binding in scope.bindings.values_mut() {
                    if binding == value {
                        *binding = Value::Unknown;
                    }
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

    fn dynamic_global(&self, ownership: RuntimeOwnership) -> Self {
        let mut state = Self::new(ownership);
        state.owned_members = self.owned_members.clone();
        state.relative_cwd_known = self.relative_cwd_known;
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
    context_exact: bool,
    stdout_inherited: bool,
}

struct Interpreter<'a> {
    source: &'a str,
    home: &'a str,
    platform: Platform,
    depth: usize,
    profile: Profile,
    report: InlineReport,
    draft: LanguageDraft,
    complete: bool,
    budget: Budget,
    return_value: Value,
    conditional_depth: usize,
    execution_dominators: Vec<usize>,
}

struct AssemblyBranch {
    state: State,
    conditional_depth: usize,
    execution_dominators: Vec<usize>,
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
    let mut interpreter = Interpreter {
        source: input.code,
        home: input.home,
        platform: input.platform,
        depth,
        profile,
        report: InlineReport::default(),
        draft: LanguageDraft::default(),
        complete: true,
        budget: Budget::default(),
        return_value: Value::Undefined,
        conditional_depth: 0,
        execution_dominators: Vec::new(),
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
        let mut control = node.child(HirField::Body).map_or(Control::Next, |body| {
            self.exec_sequence(body, state, true, call_depth)
        });
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
                let value = named_children(node)
                    .next()
                    .map_or(Value::Unknown, |child| self.eval(child, state, call_depth));
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
                if let Some(left) = node
                    .child(HirField::Left)
                    .or_else(|| named_children(node).next())
                    && let Some(value) = self.assign_target(left, Value::Unknown, state, call_depth)
                {
                    return value;
                }
                if let Some(right) = node.child(HirField::Right) {
                    let value = self.eval(right, state, call_depth);
                    if abrupt_value(&value) {
                        return value;
                    }
                }
                Value::Unknown
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
                if let Some(argument) = node.child(HirField::Argument)
                    && let Some(value) =
                        self.assign_target(argument, Value::Unknown, state, call_depth)
                {
                    return value;
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
        if let Some(member) = member {
            self.assign_member(member, state);
        } else if let Some(left) = left
            && let Some(value) = self.assign_target(left, value.clone(), state, call_depth)
        {
            return value;
        }
        value
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
                self.assign_member(member, state);
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

    fn assign_member(&mut self, member: MemberReference, state: &mut State) {
        if member.prototype_mutation {
            state.prototype_integrity_known = false;
            self.complete = false;
            self.draft.set_partial();
        }
        if matches!(
            (&member.object, member.property.as_deref()),
            (Value::Object(properties), Some(property))
                if properties.get(property) == Some(&Value::Accessor)
        ) {
            self.complete = false;
        }
        match (&member.object, member.property.as_deref()) {
            (Value::Module(module), Some(property)) => {
                if *module == Module::Fs && property == "promises" {
                    state.invalidate_module(Module::FsPromises);
                } else if let Some(known) = module_member(*module, property) {
                    state.owned_members.remove(&(*module, known));
                } else {
                    state.invalidate_module(*module);
                }
            }
            _ => state.invalidate_value(&member.object),
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
            _ => {}
        }
        None
    }

    fn member(&mut self, node: &HirNode, state: &mut State, call_depth: usize) -> Value {
        let object = node
            .child(HirField::Object)
            .map_or(Value::Unknown, |object| {
                self.eval(object, state, call_depth)
            });
        if abrupt_value(&object) {
            return object;
        }
        let property = if let Some(property) = node.child(HirField::Property) {
            self.text(property).to_owned()
        } else {
            let value = node
                .child(HirField::Index)
                .map_or(Value::Unknown, |index| self.eval(index, state, call_depth));
            if abrupt_value(&value) {
                return value;
            }
            let Some(property) = value_string(&value) else {
                return Value::Unknown;
            };
            property.to_owned()
        };
        match object {
            Value::Invalid | Value::SynchronousThrow | Value::Divergent => object,
            Value::DynamicEvalResult => Value::DynamicEvalResult,
            Value::Module(Module::Fs) if property == "promises" => {
                Value::Module(Module::FsPromises)
            }
            Value::Module(module) => module_member(module, &property).map_or(
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
            Value::Object(properties) => {
                let value = properties.get(&property).cloned();
                match value {
                    Some(Value::Accessor) => {
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
            Value::Array(values) => Value::UnknownReceiver(Box::new(Value::Array(values))),
            Value::ObjectBuiltin if property == "defineProperty" => {
                Value::Known(KnownFunction::DefineProperty)
            }
            Value::ObjectBuiltin if property == "setPrototypeOf" => {
                Value::Known(KnownFunction::SetPrototypeOf)
            }
            Value::Process if property == "env" => Value::Environment,
            Value::Environment if property == "HOME" => Value::String(self.home.to_owned()),
            Value::Deno if property == "Command" => Value::DenoCommandConstructor,
            Value::Deno => deno_member(&property)
                .map_or(Value::UnknownReceiver(Box::new(Value::Deno)), |member| {
                    Value::Known(KnownFunction::Deno(member))
                }),
            Value::DenoCommand(command) => deno_command_member(&property).map_or(
                Value::UnknownReceiver(Box::new(Value::DenoCommand(command.clone()))),
                |member| Value::Known(KnownFunction::DenoCommand(member, command)),
            ),
            Value::Bun => bun_member(&property)
                .map_or(Value::UnknownReceiver(Box::new(Value::Bun)), |member| {
                    Value::Known(KnownFunction::Bun(member))
                }),
            Value::BunFile(path) => bun_file_member(&property).map_or(
                Value::UnknownReceiver(Box::new(Value::BunFile(path.clone()))),
                |member| Value::Known(KnownFunction::BunFile(member, path)),
            ),
            Value::OpenClawTools => openclaw_member(&property).map_or(
                Value::UnknownReceiver(Box::new(Value::OpenClawTools)),
                |member| Value::Known(KnownFunction::OpenClaw(member)),
            ),
            _ => Value::Unknown,
        }
    }

    fn call(&mut self, node: &HirNode, state: &mut State, call_depth: usize) -> Value {
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
            match callable {
                Value::Invalid | Value::SynchronousThrow | Value::Divergent => callable,
                Value::Promise | Value::RejectedPromise => Value::SynchronousThrow,
                Value::Require => self.require(arguments),
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
                    self.call_local(&function, arguments, state, call_depth)
                }
                Value::UnknownModuleMember(module) => {
                    state.invalidate_module(module);
                    state.relative_cwd_known = false;
                    self.complete = false;
                    Value::Unknown
                }
                Value::UnknownReceiver(receiver) => {
                    state.invalidate_value(&receiver);
                    state.relative_cwd_known = false;
                    self.complete = false;
                    Value::Unknown
                }
                _ => {
                    for value in &arguments.values {
                        state.invalidate_value(value);
                    }
                    state.relative_cwd_known = false;
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
                    | KnownFunction::OpenClaw(_) => Value::SynchronousThrow,
                    function => {
                        for value in &arguments.values {
                            state.invalidate_value(value);
                        }
                        state.relative_cwd_known = false;
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
            state.relative_cwd_known = false;
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
            report: InlineReport::default(),
            draft: LanguageDraft::default(),
            complete: true,
            budget: Budget::default(),
            return_value: Value::Undefined,
            conditional_depth: self.conditional_depth,
            execution_dominators: Vec::new(),
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
        let value = arguments
            .values
            .first()
            .and_then(value_string)
            .and_then(module_from_source)
            .map_or(Value::Unknown, Value::Module);
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
            report: InlineReport::default(),
            draft: LanguageDraft::default(),
            complete: true,
            budget: Budget::default(),
            return_value: Value::Undefined,
            conditional_depth: self.conditional_depth,
            execution_dominators: Vec::new(),
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

    fn call_known(
        &mut self,
        function: KnownFunction,
        arguments: Arguments,
        state: &mut State,
        call_depth: usize,
        _tagged_template: bool,
    ) -> Value {
        match function {
            KnownFunction::DefineProperty => {
                self.complete = false;
                if arguments.values.first().is_none_or(unknown_value) {
                    state.prototype_integrity_known = false;
                }
                if let Some(Value::Module(module)) = arguments.values.first() {
                    if arguments.complete
                        && arguments.values.len() == 3
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
                Value::Unknown
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
            KnownFunction::Child(member) => {
                match summarize_child_call(member, &arguments, self.platform) {
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
                            ChildExecution::Command(argv) => {
                                super::super::common::add_exact_argv(&mut self.report, argv);
                            }
                            ChildExecution::Bash(code) => {
                                super::super::common::add_exact_bash(&mut self.report, &code);
                            }
                            ChildExecution::OpaqueShell { program, code } => {
                                super::super::common::add_exact_shell_program(
                                    &mut self.report,
                                    &program,
                                    &code,
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
                    if command.context_exact
                        && let Some(argv) = command.argv.clone()
                    {
                        let stdout_inherited = if member == DenoCommandMember::Spawn {
                            command.spawn_stdout_inherited
                        } else {
                            command.output_stdout_inherited
                        };
                        if stdout_inherited {
                            super::super::common::add_exact_inherited_argv(&mut self.report, argv);
                        } else {
                            super::super::common::add_exact_argv(&mut self.report, argv);
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
                    && (!command.context_exact || command.argv.is_none())
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
                    match bun_spawn_argv(&arguments, state.prototype_integrity_known) {
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
                                if summary.stdout_inherited {
                                    super::super::common::add_exact_inherited_argv(
                                        &mut self.report,
                                        argv,
                                    );
                                } else {
                                    super::super::common::add_exact_argv(&mut self.report, argv);
                                }
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
        self.call_local(callback, arguments, &mut callback_state, call_depth);
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
                if !state.relative_cwd_known
                    && filesystem
                        .requested()
                        .is_some_and(|path| !is_absolute(path, self.platform))
                {
                    filesystem = filesystem.without_requested();
                    unresolved_filesystem = true;
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
        state.push_scope(true);
        for (name, value) in parameters.iter().zip(arguments.values) {
            state.declare(name, value);
        }
        self.hoist_vars(&function.body, state);
        self.return_value = Value::Undefined;
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
        state.pop_scope();
        state.scope_chain = caller_chain;
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
            asynchronous: asynchronous_function_source(self.text(node)),
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
                    let value = if self.method_is_accessor(child) {
                        Value::Accessor
                    } else {
                        Value::Unknown
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
                                if value == Value::Accessor {
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
            .and_then(module_from_source)
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
                    state.declare(
                        self.text(child),
                        module.map_or(Value::Unknown, Value::Module),
                    );
                }
                HirKind::NamespaceImport => {
                    if let Some(name) = named_children(child).next() {
                        state.declare(
                            self.text(name),
                            module.map_or(Value::Unknown, Value::Module),
                        );
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
                        let value = module.map_or(Value::Unknown, |module| {
                            module_property_value(module, imported, state)
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
        if selected == Value::Accessor
            || matches!(&selected, Value::Known(function) if direct_receiver_required(function))
        {
            self.complete = false;
            Value::Unknown
        } else {
            selected
        }
    }

    fn method_is_accessor(&self, node: &HirNode) -> bool {
        node.child(HirField::Kind)
            .is_some_and(|kind| matches!(self.text(kind), "get" | "set"))
            || self.text(node).trim_start().starts_with("get ")
            || self.text(node).trim_start().starts_with("set ")
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

fn asynchronous_function_source(source: &str) -> bool {
    let Some(rest) = source.trim_start().strip_prefix("async") else {
        return false;
    };
    match rest.chars().next() {
        Some('(' | '<') => true,
        Some(character) if character.is_whitespace() => !rest.trim_start().starts_with("=>"),
        _ => false,
    }
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

fn deno_member(property: &str) -> Option<DenoMember> {
    match property {
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
        DenoMember::RemoveSync
            | DenoMember::MkdirSync
            | DenoMember::ReadFileSync
            | DenoMember::ReadTextFileSync
            | DenoMember::WriteFileSync
            | DenoMember::WriteTextFileSync
    )
}

fn deno_member_constructible(member: DenoMember) -> bool {
    deno_member_synchronous(member) || member == DenoMember::WriteTextFile
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
    Command(Vec<String>),
    Bash(String),
    OpaqueShell { program: String, code: String },
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
    Opaque,
}

fn summarize_child_call(
    member: Member,
    arguments: &Arguments,
    platform: Platform,
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
    let (shell, context_exact, shell_partial) = match child_shell(member, options, platform) {
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
            (ChildShell::Argv, Some(argv)) => ChildExecution::Command(argv),
            (ChildShell::Bash, Some(argv)) => ChildExecution::Bash(argv.join(" ")),
            (ChildShell::Opaque, Some(argv)) => child_opaque_shell_program(options, platform)
                .map_or(ChildExecution::None, |program| {
                    ChildExecution::OpaqueShell {
                        program,
                        code: argv.join(" "),
                    }
                }),
            _ => ChildExecution::None,
        }
    } else {
        ChildExecution::None
    };
    let kind = match shell {
        ChildShell::Argv => LanguageCallKind::LocalUtility,
        ChildShell::Bash | ChildShell::Opaque => LanguageCallKind::EvaluatedShell,
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
        Value::Object(properties) if properties.values().any(|value| *value == Value::Accessor) => {
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
) -> Result<(ChildShell, bool, bool), ChildShapeError> {
    let always_shell = matches!(member, Member::Exec | Member::ExecSync);
    let default = if always_shell {
        ChildShell::Opaque
    } else {
        ChildShell::Argv
    };
    let Some(options) = options else {
        return Ok((default, true, always_shell));
    };
    let properties = match options {
        Value::Null | Value::Undefined => return Ok((default, true, always_shell)),
        Value::Object(properties) => properties,
        value if unknown_value(value) => {
            return if always_shell {
                Ok((ChildShell::Opaque, false, true))
            } else {
                Err(ChildShapeError::Partial)
            };
        }
        _ => return Err(ChildShapeError::Invalid),
    };
    if properties.values().any(|value| *value == Value::Accessor) {
        return Err(ChildShapeError::Partial);
    }
    let context_exact = ["cwd", "env"].iter().all(|property| {
        properties
            .get(*property)
            .is_none_or(|value| matches!(value, Value::Null | Value::Undefined))
    });
    let Some(shell) = properties.get("shell") else {
        return Ok((default, context_exact, always_shell));
    };
    if always_shell {
        let shell = if platform != Platform::Windows && value_string(shell) == Some("/bin/bash") {
            ChildShell::Bash
        } else {
            ChildShell::Opaque
        };
        return Ok((shell, context_exact, matches!(shell, ChildShell::Opaque)));
    }
    let shell = match shell {
        Value::Bool(false) | Value::Null | Value::Undefined => ChildShell::Argv,
        Value::String(value) if value.is_empty() => ChildShell::Argv,
        Value::String(value) if platform != Platform::Windows && value == "/bin/bash" => {
            ChildShell::Bash
        }
        Value::Bool(true) | Value::String(_) => ChildShell::Opaque,
        value if unknown_value(value) => return Err(ChildShapeError::Partial),
        _ => return Err(ChildShapeError::Invalid),
    };
    Ok((shell, context_exact, matches!(shell, ChildShell::Opaque)))
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
        Value::Function(_) => true,
        Value::Array(values) => values.iter().any(contains_local_function),
        Value::Object(properties) => properties.values().any(contains_local_function),
        _ => false,
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

enum FsCallSummary {
    Effect(Vec<LanguageFilesystem>),
    EffectPartial(Vec<LanguageFilesystem>),
    Partial,
    Invalid,
}

fn partialize_deno_command(
    summary: RuntimeCallSummary<DenoCommandValue>,
) -> RuntimeCallSummary<DenoCommandValue> {
    match summary {
        RuntimeCallSummary::Effect(mut command)
        | RuntimeCallSummary::EffectPartial(mut command) => {
            command.argv = None;
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
            spawn: base,
            output: base,
            context_exact: true,
            spawn_stdout_inherited: true,
            output_stdout_inherited: false,
            spawn_throws_after_effect: false,
            output_throws_after_effect: false,
        });
    };
    if matches!(options, Value::Undefined) {
        return RuntimeCallSummary::Effect(DenoCommandValue {
            argv,
            spawn: base,
            output: base,
            context_exact: true,
            spawn_stdout_inherited: true,
            output_stdout_inherited: false,
            spawn_throws_after_effect: false,
            output_throws_after_effect: false,
        });
    }
    if matches!(options, Value::Null) {
        return RuntimeCallSummary::Effect(DenoCommandValue {
            argv,
            spawn: base,
            output: ExecutionCertainty::Invalid,
            context_exact: true,
            spawn_stdout_inherited: true,
            output_stdout_inherited: false,
            spawn_throws_after_effect: false,
            output_throws_after_effect: false,
        });
    }
    if matches!(
        options,
        Value::Bool(_) | Value::Number(_) | Value::String(_) | Value::Array(_)
    ) {
        let command = DenoCommandValue {
            argv,
            spawn: base,
            output: base,
            context_exact: true,
            spawn_stdout_inherited: true,
            output_stdout_inherited: false,
            spawn_throws_after_effect: false,
            output_throws_after_effect: false,
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
            spawn: base,
            output: base,
            context_exact: false,
            spawn_stdout_inherited: false,
            output_stdout_inherited: false,
            spawn_throws_after_effect: false,
            output_throws_after_effect: false,
        });
    }
    let Value::Object(properties) = options else {
        return RuntimeCallSummary::Effect(DenoCommandValue {
            argv,
            spawn: merge_execution(base, ExecutionCertainty::Unknown),
            output: merge_execution(base, ExecutionCertainty::Unknown),
            context_exact: false,
            spawn_stdout_inherited: false,
            output_stdout_inherited: false,
            spawn_throws_after_effect: false,
            output_throws_after_effect: false,
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
    let context_exact = properties
        .keys()
        .all(|key| key == "args" || !deno_command_context_property(key, platform));
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
        if !matches!(value, Value::Accessor) {
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
        spawn,
        output,
        context_exact,
        spawn_stdout_inherited,
        output_stdout_inherited,
        spawn_throws_after_effect,
        output_throws_after_effect,
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
            let context_exact = properties
                .keys()
                .all(|key| key == "cmd" || !bun_spawn_context_property(key));
            if !prototype_integrity_known {
                return bun_spawn_command_partial(command);
            }
            return bun_spawn_command(command, context_exact, stdout_inherited);
        }
        value if unknown_value(value) => return RuntimeCallSummary::Partial,
        _ => return RuntimeCallSummary::Invalid,
    };
    let (context_exact, stdout_inherited) = match options {
        None | Some(Value::Undefined) => (true, false),
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
                .all(|key| !bun_spawn_context_property(key));
            if !prototype_integrity_known {
                return bun_spawn_command_partial(command);
            }
            (context_exact, stdout_inherited)
        }
        Some(
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) | Value::Array(_),
        ) if prototype_integrity_known || matches!(options, Some(Value::Null)) => (true, false),
        Some(Value::Bool(_) | Value::Number(_) | Value::String(_) | Value::Array(_)) => {
            return bun_spawn_command_partial(command);
        }
        Some(_) => return bun_spawn_command_partial(command),
    };
    bun_spawn_command(command, context_exact, stdout_inherited)
}

fn bun_spawn_command_partial(command: &[Value]) -> RuntimeCallSummary<BunSpawnSummary> {
    match bun_spawn_command(command, false, false) {
        RuntimeCallSummary::Effect(summary) => RuntimeCallSummary::EffectPartial(summary),
        RuntimeCallSummary::EffectPartial(summary) => RuntimeCallSummary::EffectPartial(summary),
        RuntimeCallSummary::Partial => RuntimeCallSummary::Partial,
        RuntimeCallSummary::Invalid => RuntimeCallSummary::Invalid,
    }
}

fn bun_spawn_command(
    command: &[Value],
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
        context_exact,
        stdout_inherited,
    };
    if exact {
        RuntimeCallSummary::Effect(summary)
    } else {
        RuntimeCallSummary::EffectPartial(summary)
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
        if matches!(value, Value::Accessor) && bun_spawn_context_property(property) {
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
                    if properties.values().any(|value| *value == Value::Accessor) {
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
            if properties.values().any(|value| *value == Value::Accessor) {
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
    matches!(value, Value::Object(properties) if properties.values().any(|value| *value == Value::Accessor))
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
    payload.insert("v".into(), JsonValue::from(1));
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
        | Value::Require
        | Value::Eval
        | Value::DynamicEvalResult
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
        | Value::Accessor
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
        | Value::OpenClawTools => Some(true),
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
            relative_cwd_known: left.relative_cwd_known && right.relative_cwd_known,
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
    left.relative_cwd_known &= right.relative_cwd_known;
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

    fn analysis(code: &str) -> LanguageAnalysis {
        let profile = super::super::profile("node").unwrap();
        analyze(
            profile,
            &InlineInput {
                program: "node",
                code,
                home: "/home/dev",
                platform: Platform::Linux,
            },
            0,
        )
    }

    fn report(code: &str) -> InlineReport {
        analysis(code).into_report()
    }

    fn root(code: &str) -> bool {
        analysis(code).draft().calls().iter().any(|call| {
            call.filesystems()
                .iter()
                .any(|filesystem| filesystem.requested() == Some("/"))
        })
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
