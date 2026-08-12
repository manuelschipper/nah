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

mod assignments;
mod bun_runtime;
mod calls;
mod child_process;
mod deno_runtime;
mod dynamic_source;
mod evidence;
mod expressions;
mod filesystem;
mod hir_execution;
mod imports;
mod known_calls;
mod literals;
mod members;
mod module_ownership;
mod node_runtime;
mod openclaw_runtime;
mod runtime_apis;
mod runtime_calls;
mod state;
mod string_literals;
mod syntax;
mod value_semantics;

use bun_runtime::*;
use child_process::{
    ChildCallSummary, ChildExecution, child_callable, child_callback_shape, summarize_child_call,
};
use deno_runtime::*;
use evidence::*;
use filesystem::*;
use module_ownership::*;
use node_runtime::*;
use openclaw_runtime::*;
use runtime_apis::*;
use string_literals::*;
use syntax::*;
use value_semantics::*;

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

pub(super) fn interpret(
    profile: Profile,
    input: &InlineInput<'_>,
    depth: usize,
) -> LanguageAnalysis {
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
    fn text(&self, node: &HirNode) -> &str {
        self.source
            .get(node.span().start()..node.span().end())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests;
