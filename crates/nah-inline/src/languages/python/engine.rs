use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use nah_proto::action::{FilesystemOperation, InvocationInput};
use nah_proto::ctx::Platform;
use serde_json::{Map, Value as JsonValue};

use crate::{
    EnvironmentValue, Finding, FindingKind, InlineInput, InlineRefusal, InlineReport,
    LanguageAnalysis, LanguageCall, LanguageCallKind, LanguageDraft, LanguageFilesystem,
    NestedExecution, NestedExecutionCwd, ProtectionInput,
};

use super::{
    InitialState,
    parser::{HirField, HirKind, HirNode},
};

mod bindings;
mod call_shapes;
mod data_flow;
mod evidence;
mod expressions;
mod filesystem;
mod hir_execution;
mod imports;
mod known_calls;
mod network;
mod operators;
mod process;
mod runtime_calls;
mod string_paths;
mod value_semantics;

use bindings::*;
use call_shapes::*;
use data_flow::*;
use evidence::*;
use filesystem::*;
use imports::*;
use network::*;
use process::*;
use string_paths::*;
use value_semantics::*;

const MAX_WORK: usize = 262_144;
const MAX_STATEMENTS: usize = 4_096;
const MAX_CALL_DEPTH: usize = 16;
const MAX_LOOP_ITERATIONS: usize = 64;
const MAX_COLLECTION_ITEMS: usize = 256;
const MAX_CELLS: usize = 1_024;
const MAX_VALUE_BYTES: usize = crate::SOURCE_LIMIT;
const MAX_DYNAMIC_SOURCE_BYTES: usize = crate::SOURCE_LIMIT;
const MAX_NATIVE_ARGUMENTS: usize = 16;
const MAX_NATIVE_COLLECTION_ITEMS: usize = 64;
const MAX_NATIVE_EVIDENCE_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum KnownFunction {
    Base64Decode,
    Compile,
    Eval,
    Exec,
    Getattr,
    GetIpython,
    Import,
    IpythonCell,
    IpythonGetoutput,
    IpythonSystem,
    IpythonSyntaxCell,
    IpythonSyntaxGetoutput,
    IpythonSyntaxSystem,
    IoFile,
    Open,
    OsAbspath,
    OsChmod,
    OsChdir,
    OsChown,
    OsExec(StringKind),
    OsExpanduser,
    OsGetenv,
    OsLchown,
    OsLink,
    OsMkdir,
    OsMakedirs,
    OsOpen,
    OsPopen,
    OsRealpath,
    OsRemove,
    OsUnlink,
    OsRemovedirs,
    OsRename,
    OsReplace,
    OsRmdir,
    OsSymlink,
    OsSystem,
    OsTruncate,
    Path,
    PathHome,
    PathJoin,
    Request(RequestKind),
    Setattr,
    ShutilCopy(CopyKind),
    ShutilMove,
    ShutilRmtree,
    ShutilWhich,
    Subprocess(SubprocessKind),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IpythonShell {
    Bash,
    Sh,
    Unknown,
}

const OWNED_BUILTINS: &[(&str, KnownFunction)] = &[
    ("eval", KnownFunction::Eval),
    ("exec", KnownFunction::Exec),
    ("compile", KnownFunction::Compile),
    ("open", KnownFunction::Open),
    ("getattr", KnownFunction::Getattr),
    ("setattr", KnownFunction::Setattr),
    ("__import__", KnownFunction::Import),
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RequestKind {
    RequestsGet,
    RequestsPost,
    RequestsPut,
    RequestsPatch,
    RequestsDelete,
    HttpxGet,
    HttpxPost,
    HttpxPut,
    HttpxPatch,
    HttpxDelete,
    UrlOpen,
    UrlRetrieve,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StringKind {
    Execl,
    Execlp,
    Execle,
    Execv,
    Execvp,
    Execvpe,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SubprocessKind {
    Run,
    Call,
    Popen,
    CheckCall,
    CheckOutput,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CopyKind {
    Copy,
    Copy2,
    Copyfile,
    Copytree,
    Copymode,
    Copystat,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CodeMode {
    Eval,
    Exec,
    Single,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Cell {
    Sequence { values: Vec<Value>, indexable: bool },
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Value {
    Unknown,
    None,
    Bool(bool),
    Int(i64),
    String(String),
    ImplicitString(String),
    Bytes(Vec<u8>),
    EmptyDictionary,
    ImportRegistry,
    ImportRegistryMutator(ImportRegistryMutation),
    ImportRegistryRead(ImportRegistryRead),
    Cell(usize),
    Module(Module),
    Known(KnownFunction),
    LocalFunction(usize),
    Path(String),
    PathMethod { path: String, method: String },
    CellMethod { cell: usize, method: String },
    StringMethod { value: String, method: String },
    BytesMethod { value: Vec<u8>, method: String },
    Decoded(Box<Value>),
    DecodedMethod { value: Box<Value>, method: String },
    ModuleMethod(Module),
    Compiled { source: String, mode: CodeMode },
    Produced(Vec<usize>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Parameter {
    name: String,
    default: Option<Value>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LocalFunction {
    name: String,
    parameters: Option<Vec<Parameter>>,
    body: HirNode,
    source: Arc<str>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct State {
    bindings: BTreeMap<String, Value>,
    cells: Vec<Cell>,
    functions: Vec<LocalFunction>,
    invalid_modules: BTreeSet<Module>,
    cwd: NestedExecutionCwd,
    ipython_shell: IpythonShell,
}

impl Default for State {
    fn default() -> Self {
        let bindings = OWNED_BUILTINS
            .iter()
            .copied()
            .map(|(name, function)| (name, Value::Known(function)))
            .map(|(name, value)| (name.to_owned(), value))
            .collect();
        Self {
            bindings,
            cells: Vec::new(),
            functions: Vec::new(),
            invalid_modules: BTreeSet::new(),
            cwd: NestedExecutionCwd::Inherited,
            ipython_shell: IpythonShell::Unknown,
        }
    }
}

#[derive(Default)]
struct Budget {
    work: usize,
    statements: usize,
    dynamic_source_bytes: usize,
    refusal: Option<InlineRefusal>,
}

impl Budget {
    fn spend(&mut self) -> bool {
        self.work += 1;
        if self.work <= MAX_WORK {
            true
        } else {
            self.refusal = Some(InlineRefusal::WorkLimit);
            false
        }
    }

    fn enter_statement(&mut self) -> bool {
        self.statements += 1;
        if self.statements <= MAX_STATEMENTS {
            true
        } else {
            self.refusal = Some(InlineRefusal::WorkLimit);
            false
        }
    }

    fn admit_value_bytes(&mut self, bytes: Option<usize>) -> bool {
        if bytes.is_some_and(|bytes| bytes <= MAX_VALUE_BYTES) {
            true
        } else {
            self.refuse_work();
            false
        }
    }

    fn enter_dynamic_source(&mut self, bytes: usize) -> bool {
        if let Some(bytes) = self
            .dynamic_source_bytes
            .checked_add(bytes)
            .filter(|bytes| *bytes <= MAX_DYNAMIC_SOURCE_BYTES)
        {
            self.dynamic_source_bytes = bytes;
            true
        } else {
            self.refuse_work();
            false
        }
    }

    fn refuse_work(&mut self) {
        self.refusal.get_or_insert(InlineRefusal::WorkLimit);
    }
}

#[derive(Clone, Debug)]
struct Arguments {
    positional: Vec<Value>,
    keywords: Vec<(String, Value)>,
    complete: bool,
}

enum ArgumentBindings {
    Bound(Vec<(String, Value)>),
    Invalid,
    Incomplete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CallShape {
    Valid,
    Invalid,
    Incomplete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ValueAdmission {
    Exact,
    Possible,
    Invalid,
}

impl Default for Arguments {
    fn default() -> Self {
        Self {
            positional: Vec::new(),
            keywords: Vec::new(),
            complete: true,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Control {
    Next,
    Return(Value),
    Raise,
    Break,
    Continue,
    Diverge,
}

struct Interpreter<'a> {
    program: &'a str,
    source: Arc<str>,
    root_source: Arc<str>,
    input: InlineInput<'a>,
    report: InlineReport,
    budget: Budget,
    complete: bool,
    draft: LanguageDraft,
    conditional_depth: usize,
    execution_dominators: Vec<usize>,
    call_stack: Vec<String>,
    pending_control: Option<Control>,
    initial_state: InitialState,
    ipython_syntax: bool,
    ipython_capture: bool,
}

pub(super) fn interpret(
    program: &str,
    input: &InlineInput<'_>,
    protection: Option<&ProtectionInput<'_>>,
    depth: usize,
    initial_state: InitialState,
    ipython_syntax: bool,
    ipython_capture: bool,
) -> LanguageAnalysis {
    let module = match super::parser::lower(input.code, program) {
        Ok(module) if !module.opaque() => module,
        Ok(_) => {
            return LanguageAnalysis::new(InlineReport::default(), LanguageDraft::partial());
        }
        Err(refusal) => return LanguageAnalysis::refused(refusal),
    };
    let source = Arc::from(input.code);
    let mut interpreter = Interpreter {
        program,
        source: Arc::clone(&source),
        root_source: source,
        input: *input,
        report: InlineReport::default(),
        budget: Budget::default(),
        complete: true,
        draft: LanguageDraft::default(),
        conditional_depth: 0,
        execution_dominators: Vec::new(),
        call_stack: Vec::with_capacity(depth),
        pending_control: None,
        initial_state,
        ipython_syntax,
        ipython_capture,
    };
    let mut state = match initial_state {
        InitialState::Fresh => State::default(),
        InitialState::Persistent => State {
            invalid_modules: [Module::Ipython, Module::Environment].into_iter().collect(),
            cwd: NestedExecutionCwd::Unknown,
            ..State::default()
        },
    };
    state.ipython_shell = observed_ipython_shell(protection);
    if matches!(initial_state, InitialState::Fresh) && crate::is_ipython_interpreter(program) {
        state.bindings.insert(
            "get_ipython".to_owned(),
            Value::Known(KnownFunction::GetIpython),
        );
    }
    interpreter.exec_block(module.root(), &mut state, depth);
    if let Some(refusal) = interpreter.budget.refusal {
        interpreter.report.refuse(refusal);
        interpreter.draft.set_partial();
    }
    if !interpreter.complete {
        interpreter.draft.set_partial();
    }
    let report =
        super::super::common::with_protection(interpreter.report, program, input, protection);
    LanguageAnalysis::new(report, interpreter.draft)
}

fn observed_ipython_shell(protection: Option<&ProtectionInput<'_>>) -> IpythonShell {
    let Some(protection) = protection else {
        return IpythonShell::Unknown;
    };
    match protection
        .ambient_variables
        .iter()
        .rev()
        .find(|(name, _)| name == "SHELL")
        .map(|(_, value)| value)
    {
        Some(EnvironmentValue::Static(shell)) => match shell.rsplit('/').next() {
            Some("bash") => IpythonShell::Bash,
            Some("sh" | "dash") => IpythonShell::Sh,
            _ => IpythonShell::Unknown,
        },
        Some(EnvironmentValue::Unset) => IpythonShell::Sh,
        Some(EnvironmentValue::Unknown) | None => IpythonShell::Unknown,
    }
}

impl Interpreter<'_> {
    fn add_destructive_target(&mut self, target: &str) {
        let normalized = normalize_path(target, self.input.platform);
        let root = if self.input.platform == Platform::Windows {
            normalized.len() == 2 && normalized.ends_with(':')
        } else {
            normalized == "/"
        };
        if root {
            self.report
                .push(Finding::exact(FindingKind::RootDestruction));
        }
        if normalized == normalize_path(self.input.home, self.input.platform) {
            self.report
                .push(Finding::exact(FindingKind::HomeDestruction));
        }
    }

    fn text(&self, node: &HirNode) -> &str {
        // HIR spans were validated against this exact source before interpretation.
        unsafe_text(&self.source, node)
    }
}

fn named_children(node: &HirNode) -> impl Iterator<Item = &HirNode> {
    node.children()
        .iter()
        .filter(|child| !matches!(child.kind(), HirKind::Token | HirKind::Comment))
}

fn unsafe_text<'a>(source: &'a str, node: &HirNode) -> &'a str {
    source
        .get(node.span().start()..node.span().end())
        .unwrap_or_default()
}

fn os_open_flag(name: &str, platform: Platform) -> Option<i64> {
    let value = match (platform, name) {
        (_, "O_RDONLY") => 0,
        (_, "O_WRONLY") => 1,
        (_, "O_RDWR") => 2,
        (Platform::Linux, "O_APPEND") => 1_024,
        (Platform::Linux, "O_CREAT") => 64,
        (Platform::Linux, "O_EXCL") => 128,
        (Platform::Linux, "O_TRUNC") => 512,
        (Platform::Macos, "O_APPEND") => 8,
        (Platform::Macos, "O_CREAT") => 512,
        (Platform::Macos, "O_EXCL") => 2_048,
        (Platform::Macos, "O_TRUNC") => 1_024,
        (Platform::Windows, "O_APPEND") => 8,
        (Platform::Windows, "O_CREAT") => 256,
        (Platform::Windows, "O_EXCL") => 1_024,
        (Platform::Windows, "O_TRUNC") => 512,
        (Platform::Windows, "O_BINARY") => 32_768,
        (Platform::Windows, "O_TEXT") => 16_384,
        _ => return None,
    };
    Some(value)
}

fn os_open_mutation_flags(platform: Platform) -> i64 {
    ["O_CREAT", "O_TRUNC"]
        .into_iter()
        .filter_map(|name| os_open_flag(name, platform))
        .fold(0, |flags, flag| flags | flag)
}

#[cfg(test)]
mod tests;
