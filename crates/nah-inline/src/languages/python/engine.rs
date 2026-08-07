use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use nah_proto::action::{FilesystemOperation, InvocationInput};
use nah_proto::ctx::Platform;
use serde_json::{Map, Value as JsonValue};

use crate::{
    Finding, FindingKind, InlineInput, InlineRefusal, InlineReport, LanguageAnalysis, LanguageCall,
    LanguageCallKind, LanguageDraft, LanguageFilesystem, NestedExecution, ProtectionInput,
};

use super::parser::{HirField, HirKind, HirNode};

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

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Module {
    Base64,
    Builtins,
    Io,
    Os,
    Environment,
    OsPath,
    Pathlib,
    Requests,
    Httpx,
    Shutil,
    Subprocess,
    Urllib,
    UrllibRequest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum KnownFunction {
    Base64Decode,
    Compile,
    Eval,
    Exec,
    Getattr,
    Import,
    IoFile,
    Open,
    OsAbspath,
    OsChmod,
    OsChown,
    OsExec(StringKind),
    OsExpanduser,
    OsGetenv,
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
    ShutilCopy(CopyKind),
    ShutilMove,
    ShutilRmtree,
    ShutilWhich,
    Subprocess(SubprocessKind),
}

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
    Sequence(Vec<Value>),
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
    relative_cwd_known: bool,
}

impl Default for State {
    fn default() -> Self {
        let bindings = [
            ("eval", Value::Known(KnownFunction::Eval)),
            ("exec", Value::Known(KnownFunction::Exec)),
            ("compile", Value::Known(KnownFunction::Compile)),
            ("open", Value::Known(KnownFunction::Open)),
            ("getattr", Value::Known(KnownFunction::Getattr)),
            ("__import__", Value::Known(KnownFunction::Import)),
        ]
        .into_iter()
        .map(|(name, value)| (name.to_owned(), value))
        .collect();
        Self {
            bindings,
            cells: Vec::new(),
            functions: Vec::new(),
            invalid_modules: BTreeSet::new(),
            relative_cwd_known: true,
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
    input: InlineInput<'a>,
    report: InlineReport,
    budget: Budget,
    complete: bool,
    draft: LanguageDraft,
    conditional_depth: usize,
    execution_dominators: Vec<usize>,
    call_stack: Vec<String>,
    pending_control: Option<Control>,
}

pub(super) fn analyze(
    program: &str,
    input: &InlineInput<'_>,
    protection: Option<&ProtectionInput<'_>>,
    depth: usize,
) -> LanguageAnalysis {
    let module = match super::parser::lower(input.code, program) {
        Ok(module) if !module.opaque() => module,
        Ok(_) => {
            return LanguageAnalysis::new(InlineReport::default(), LanguageDraft::partial());
        }
        Err(refusal) => return LanguageAnalysis::refused(refusal),
    };
    let mut interpreter = Interpreter {
        program,
        source: Arc::from(input.code),
        input: *input,
        report: InlineReport::default(),
        budget: Budget::default(),
        complete: true,
        draft: LanguageDraft::default(),
        conditional_depth: 0,
        execution_dominators: Vec::new(),
        call_stack: Vec::with_capacity(depth),
        pending_control: None,
    };
    let mut state = State::default();
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

impl Interpreter<'_> {
    fn exec_block(&mut self, node: &HirNode, state: &mut State, depth: usize) -> Control {
        if let Some(control) = &self.pending_control {
            return control.clone();
        }
        for child in node.children() {
            if matches!(child.kind(), HirKind::Token | HirKind::Comment) {
                continue;
            }
            if !self.budget.enter_statement() || !self.budget.spend() {
                break;
            }
            let control = self.exec_statement(child, state, depth);
            if control != Control::Next {
                return control;
            }
        }
        Control::Next
    }

    fn exec_statement(&mut self, node: &HirNode, state: &mut State, depth: usize) -> Control {
        let control = match node.kind() {
            HirKind::Module | HirKind::Block => self.exec_block(node, state, depth),
            HirKind::Import => {
                self.import(node, state);
                Control::Next
            }
            HirKind::ImportFrom => {
                self.import_from(node, state);
                Control::Next
            }
            HirKind::ExpressionStatement => {
                if let Some(expression) = named_children(node).next() {
                    if expression.kind() == HirKind::Assignment {
                        self.assignment(expression, state, depth);
                    } else if expression.kind() == HirKind::AugmentedAssignment {
                        self.augmented_assignment(expression, state, depth);
                    } else {
                        self.eval(expression, state, depth);
                    }
                }
                Control::Next
            }
            HirKind::Assignment => {
                self.assignment(node, state, depth);
                Control::Next
            }
            HirKind::AugmentedAssignment => {
                self.augmented_assignment(node, state, depth);
                Control::Next
            }
            HirKind::If => self.if_statement(node, state, depth),
            HirKind::For => self.for_statement(node, state, depth),
            HirKind::While => self.while_statement(node, state, depth),
            HirKind::Function => {
                self.define_function(node, state, depth, false);
                Control::Next
            }
            HirKind::DecoratedDefinition => {
                for decorator in node
                    .children()
                    .iter()
                    .filter(|child| child.kind() == HirKind::Decorator)
                {
                    for expression in named_children(decorator) {
                        self.eval(expression, state, depth);
                    }
                }
                if let Some(definition) = node.child(HirField::Definition) {
                    if definition.kind() == HirKind::Function {
                        self.define_function(definition, state, depth, true);
                    } else {
                        self.exec_class(definition, state, depth);
                    }
                }
                Control::Next
            }
            HirKind::Class => {
                self.exec_class(node, state, depth);
                Control::Next
            }
            HirKind::Return => {
                let value = named_children(node)
                    .next()
                    .map_or(Value::None, |value| self.eval(value, state, depth));
                Control::Return(value)
            }
            HirKind::Raise => {
                for expression in named_children(node) {
                    self.eval(expression, state, depth);
                }
                Control::Raise
            }
            HirKind::Break => Control::Break,
            HirKind::Continue => Control::Continue,
            HirKind::With => self.with_statement(node, state, depth),
            HirKind::Delete => {
                for target in named_children(node) {
                    self.delete(target, state);
                }
                Control::Next
            }
            HirKind::Try => self.try_statement(node, state, depth),
            HirKind::Exec => {
                if let Some(source) = named_children(node).next() {
                    let value = self.eval(source, state, depth);
                    self.dynamic_execution(value, CodeMode::Exec, state, depth);
                }
                Control::Next
            }
            HirKind::Print => {
                for expression in named_children(node) {
                    self.eval(expression, state, depth);
                }
                Control::Next
            }
            HirKind::Pass | HirKind::Comment | HirKind::Token => Control::Next,
            HirKind::Unsupported | HirKind::Error => {
                self.complete = false;
                self.widen_unsupported_bindings(node, state);
                Control::Next
            }
            _ => {
                self.eval(node, state, depth);
                Control::Next
            }
        };
        self.pending_control.take().unwrap_or(control)
    }

    fn eval(&mut self, node: &HirNode, state: &mut State, depth: usize) -> Value {
        if self.pending_control.is_some() {
            return Value::Unknown;
        }
        if !self.budget.spend() {
            return Value::Unknown;
        }
        match node.kind() {
            HirKind::Identifier => state
                .bindings
                .get(self.text(node))
                .cloned()
                .unwrap_or(Value::Unknown),
            HirKind::String => self.string(node, state, depth),
            HirKind::ConcatenatedString => self.concatenated_string(node, state, depth),
            HirKind::Integer => parse_integer(self.text(node)).map_or(Value::Unknown, Value::Int),
            HirKind::Float => Value::Unknown,
            HirKind::True => Value::Bool(true),
            HirKind::False => Value::Bool(false),
            HirKind::None => Value::None,
            HirKind::List | HirKind::Tuple | HirKind::Set => self.collection(node, state, depth),
            HirKind::Dictionary => {
                let mut empty = true;
                for child in named_children(node) {
                    empty = false;
                    if child.kind() == HirKind::Pair {
                        if let Some(key) = child.child(HirField::Key) {
                            self.eval(key, state, depth);
                        }
                        if let Some(value) = child.child(HirField::Value) {
                            self.eval(value, state, depth);
                        }
                    } else {
                        self.eval(child, state, depth);
                    }
                }
                if empty {
                    Value::EmptyDictionary
                } else {
                    Value::Unknown
                }
            }
            HirKind::ParenthesizedExpression => named_children(node)
                .next()
                .map_or(Value::None, |child| self.eval(child, state, depth)),
            HirKind::Attribute => self.attribute(node, state, depth),
            HirKind::Call => self.call(node, state, depth),
            HirKind::BinaryOperator => self.binary(node, state, depth),
            HirKind::BooleanOperator => self.boolean(node, state, depth),
            HirKind::ComparisonOperator => self.comparison(node, state, depth),
            HirKind::NotOperator => {
                let value = node
                    .child(HirField::Argument)
                    .or_else(|| named_children(node).next())
                    .map_or(Value::Unknown, |value| self.eval(value, state, depth));
                truthy(&value, state).map_or(Value::Unknown, |value| Value::Bool(!value))
            }
            HirKind::UnaryOperator => self.unary(node, state, depth),
            HirKind::ConditionalExpression => self.conditional_expression(node, state, depth),
            HirKind::Subscript => self.subscript(node, state, depth),
            HirKind::Lambda => Value::Unknown,
            HirKind::Generator => Value::Unknown,
            HirKind::Assignment => {
                self.assignment(node, state, depth);
                node.child(HirField::Left)
                    .and_then(|left| state.bindings.get(self.text(left)))
                    .cloned()
                    .unwrap_or(Value::Unknown)
            }
            HirKind::Unsupported | HirKind::Error => {
                self.complete = false;
                self.widen_unsupported_bindings(node, state);
                Value::Unknown
            }
            _ => {
                self.eval_children(node, state, depth);
                Value::Unknown
            }
        }
    }

    fn eval_children(&mut self, node: &HirNode, state: &mut State, depth: usize) {
        for child in named_children(node) {
            if !matches!(
                child.kind(),
                HirKind::Function | HirKind::Class | HirKind::Lambda
            ) {
                self.eval(child, state, depth);
            }
        }
    }

    fn assignment(&mut self, node: &HirNode, state: &mut State, depth: usize) {
        let Some(left) = node.child(HirField::Left) else {
            self.complete = false;
            return;
        };
        let value = node
            .child(HirField::Right)
            .map_or(Value::Unknown, |right| self.eval(right, state, depth));
        if self.pending_control.is_some() {
            return;
        }
        self.assign(left, value, state);
    }

    fn augmented_assignment(&mut self, node: &HirNode, state: &mut State, depth: usize) {
        let Some(left) = node.child(HirField::Left) else {
            return;
        };
        let current = self.eval(left, state, depth);
        let right = node
            .child(HirField::Right)
            .map_or(Value::Unknown, |right| self.eval(right, state, depth));
        if self.pending_control.is_some() {
            return;
        }
        let operator = node
            .child(HirField::Operator)
            .map(|operator| self.text(operator))
            .unwrap_or_default()
            .to_owned();
        let value = binary_value(current, right, &operator, &mut self.budget);
        self.assign(left, value, state);
    }

    fn assign(&mut self, target: &HirNode, value: Value, state: &mut State) {
        match target.kind() {
            HirKind::Identifier => {
                state.bindings.insert(self.text(target).to_owned(), value);
            }
            HirKind::Tuple | HirKind::List => {
                let values = sequence_values(&value, state).map(Vec::from);
                for (index, child) in named_children(target).enumerate() {
                    let value = values
                        .as_ref()
                        .and_then(|values| values.get(index))
                        .cloned()
                        .unwrap_or(Value::Unknown);
                    self.assign(child, value, state);
                }
            }
            HirKind::Attribute => target
                .child(HirField::Object)
                .into_iter()
                .for_each(|object| self.invalidate_mutation_target(object, state)),
            HirKind::Subscript => named_children(target)
                .next()
                .into_iter()
                .for_each(|object| self.invalidate_mutation_target(object, state)),
            _ => self.complete = false,
        }
    }

    fn invalidate_mutation_target(&mut self, target: &HirNode, state: &mut State) {
        if let Some(module) = owned_module_target(target, state, &self.source) {
            invalidate_module(module, state);
            self.complete = false;
            return;
        }
        let mut root = target;
        while root.kind() != HirKind::Identifier {
            let Some(child) = named_children(root).next() else {
                self.complete = false;
                return;
            };
            root = child;
        }
        let name = self.text(root).to_owned();
        match state.bindings.get(&name).cloned() {
            Some(Value::Cell(cell)) => {
                if let Some(value) = state.cells.get_mut(cell) {
                    *value = Cell::Unknown;
                }
            }
            Some(Value::Module(module)) => {
                invalidate_module(module, state);
            }
            _ => {
                state.bindings.insert(name, Value::Unknown);
            }
        }
        self.complete = false;
    }

    fn delete(&mut self, target: &HirNode, state: &mut State) {
        match target.kind() {
            HirKind::Identifier => {
                state
                    .bindings
                    .insert(self.text(target).to_owned(), Value::Unknown);
            }
            HirKind::Tuple | HirKind::List | HirKind::ParenthesizedExpression => {
                for target in named_children(target) {
                    self.delete(target, state);
                }
            }
            HirKind::Attribute => target
                .child(HirField::Object)
                .into_iter()
                .for_each(|object| self.invalidate_mutation_target(object, state)),
            HirKind::Subscript => named_children(target)
                .next()
                .into_iter()
                .for_each(|object| self.invalidate_mutation_target(object, state)),
            _ => self.complete = false,
        }
    }

    fn widen_unsupported_bindings(&mut self, node: &HirNode, state: &mut State) {
        for name in assigned_names(node, &self.source) {
            state.bindings.insert(name, Value::Unknown);
        }
        for name in capture_names(node, &self.source) {
            state.bindings.insert(name, Value::Unknown);
        }
    }

    fn import(&mut self, node: &HirNode, state: &mut State) {
        for imported in named_children(node) {
            let (name, alias) = import_name(imported, &self.source);
            let value = if alias.is_some() {
                module_value(&name)
            } else {
                name.split('.').next().and_then(module_value)
            }
            .unwrap_or(Value::Unknown);
            let value = retain_owned_module(value, state);
            let binding =
                alias.unwrap_or_else(|| name.split('.').next().unwrap_or(name.as_str()).to_owned());
            state.bindings.insert(binding, value);
        }
    }

    fn import_from(&mut self, node: &HirNode, state: &mut State) {
        let module = node
            .child(HirField::ModuleName)
            .map(|module| self.text(module).trim_matches('.'))
            .unwrap_or_default();
        for imported in node.children().iter().filter(|child| {
            matches!(child.kind(), HirKind::AliasedImport | HirKind::DottedName)
                && child.field() != Some(HirField::ModuleName)
        }) {
            let (name, alias) = import_name(imported, &self.source);
            let binding = alias.unwrap_or_else(|| name.clone());
            let value = if module_value(module).is_some_and(|value| {
                matches!(value, Value::Module(module) if state.invalid_modules.contains(&module))
            }) {
                Value::Unknown
            } else {
                imported_value(module, &name).unwrap_or(Value::Unknown)
            };
            state.bindings.insert(binding, value);
        }
    }

    fn define_function(
        &mut self,
        node: &HirNode,
        state: &mut State,
        depth: usize,
        decorated: bool,
    ) {
        let Some(name_node) = node.child(HirField::Name) else {
            return;
        };
        let name = self.text(name_node).to_owned();
        let parameters = node
            .child(HirField::Parameters)
            .and_then(|parameters| self.parameters(parameters, state, depth));
        if let Some(annotation) = node.child(HirField::ReturnType) {
            self.eval(annotation, state, depth);
        }
        if self.pending_control.is_some() {
            return;
        }
        let Some(body) = node.child(HirField::Body) else {
            state.bindings.insert(name, Value::Unknown);
            return;
        };
        if decorated
            || self.text(node).trim_start().starts_with("async ")
            || contains_kind(body, HirKind::Unsupported, self.source.as_ref(), "yield")
        {
            state.bindings.insert(name, Value::Unknown);
            return;
        }
        let function = state.functions.len();
        state.functions.push(LocalFunction {
            name: name.clone(),
            parameters,
            body: body.clone(),
            source: Arc::clone(&self.source),
        });
        state.bindings.insert(name, Value::LocalFunction(function));
    }

    fn parameters(
        &mut self,
        node: &HirNode,
        state: &mut State,
        depth: usize,
    ) -> Option<Vec<Parameter>> {
        let mut parameters = Vec::new();
        let mut complete = true;
        for child in named_children(node) {
            match child.kind() {
                HirKind::Identifier => parameters.push(Parameter {
                    name: self.text(child).to_owned(),
                    default: None,
                }),
                HirKind::DefaultParameter | HirKind::TypedDefaultParameter => {
                    if let Some(annotation) = child.child(HirField::Type) {
                        self.eval(annotation, state, depth);
                    }
                    let default = child
                        .child(HirField::Value)
                        .map(|value| self.eval(value, state, depth));
                    if let Some(name) = child
                        .child(HirField::Name)
                        .filter(|name| name.kind() == HirKind::Identifier)
                    {
                        parameters.push(Parameter {
                            name: self.text(name).to_owned(),
                            default,
                        });
                    } else {
                        complete = false;
                    }
                }
                HirKind::TypedParameter => {
                    if let Some(name) = child.child(HirField::Name).or_else(|| {
                        named_children(child).find(|node| node.kind() == HirKind::Identifier)
                    }) {
                        parameters.push(Parameter {
                            name: self.text(name).to_owned(),
                            default: None,
                        });
                    } else {
                        complete = false;
                    }
                    if let Some(annotation) = child.child(HirField::Type) {
                        self.eval(annotation, state, depth);
                    }
                }
                _ => complete = false,
            }
        }
        let mut names = BTreeSet::new();
        if parameters
            .iter()
            .any(|parameter| !names.insert(parameter.name.as_str()))
        {
            complete = false;
        }
        if complete {
            Some(parameters)
        } else {
            self.complete = false;
            None
        }
    }

    fn exec_class(&mut self, node: &HirNode, state: &mut State, depth: usize) {
        for child in node.children() {
            if matches!(child.field(), Some(HirField::Name | HirField::Body)) {
                continue;
            }
            if child.kind() != HirKind::Token {
                self.eval(child, state, depth);
            }
        }
        if let Some(body) = node.child(HirField::Body) {
            let mut class_state = state.clone();
            if self.exec_block(body, &mut class_state, depth) != Control::Next {
                self.complete = false;
            }
            propagate_invalid_modules(&class_state.invalid_modules, state);
            state.relative_cwd_known &= class_state.relative_cwd_known;
            state.cells = class_state.cells;
        }
        if let Some(name) = node.child(HirField::Name) {
            state
                .bindings
                .insert(self.text(name).to_owned(), Value::Unknown);
        }
    }

    fn if_statement(&mut self, node: &HirNode, state: &mut State, depth: usize) -> Control {
        let condition = node
            .child(HirField::Condition)
            .map_or(Value::Unknown, |condition| {
                self.eval(condition, state, depth)
            });
        let consequence = node.child(HirField::Consequence);
        let alternatives = node
            .children()
            .iter()
            .filter(|child| child.field() == Some(HirField::Alternative))
            .collect::<Vec<_>>();
        match truthy(&condition, state) {
            Some(true) => {
                consequence.map_or(Control::Next, |body| self.exec_block(body, state, depth))
            }
            Some(false) => self.exec_alternatives(&alternatives, state, depth),
            None => {
                self.complete = false;
                let mut yes = state.clone();
                let mut no = state.clone();
                let dominators = self.execution_dominators.clone();
                self.conditional_depth += 1;
                let yes_control = consequence
                    .map_or(Control::Next, |body| self.exec_block(body, &mut yes, depth));
                self.execution_dominators.clone_from(&dominators);
                let no_control = self.exec_alternatives(&alternatives, &mut no, depth);
                self.conditional_depth -= 1;
                self.execution_dominators = dominators;
                let (joined, control) = merge_branch_states(yes, yes_control, no, no_control);
                *state = joined;
                control
            }
        }
    }

    fn exec_alternatives(
        &mut self,
        alternatives: &[&HirNode],
        state: &mut State,
        depth: usize,
    ) -> Control {
        let Some((alternative, rest)) = alternatives.split_first() else {
            return Control::Next;
        };
        match alternative.kind() {
            HirKind::Else => alternative
                .child(HirField::Body)
                .map_or(Control::Next, |body| self.exec_block(body, state, depth)),
            HirKind::Elif => {
                let condition = alternative
                    .child(HirField::Condition)
                    .map_or(Value::Unknown, |condition| {
                        self.eval(condition, state, depth)
                    });
                match truthy(&condition, state) {
                    Some(true) => alternative
                        .child(HirField::Consequence)
                        .map_or(Control::Next, |body| self.exec_block(body, state, depth)),
                    Some(false) => self.exec_alternatives(rest, state, depth),
                    None => {
                        self.complete = false;
                        let mut yes = state.clone();
                        let mut no = state.clone();
                        let dominators = self.execution_dominators.clone();
                        self.conditional_depth += 1;
                        let yes_control = alternative
                            .child(HirField::Consequence)
                            .map_or(Control::Next, |body| self.exec_block(body, &mut yes, depth));
                        self.execution_dominators.clone_from(&dominators);
                        let no_control = self.exec_alternatives(rest, &mut no, depth);
                        self.conditional_depth -= 1;
                        self.execution_dominators = dominators;
                        let (joined, control) =
                            merge_branch_states(yes, yes_control, no, no_control);
                        *state = joined;
                        control
                    }
                }
            }
            _ => Control::Next,
        }
    }

    fn for_statement(&mut self, node: &HirNode, state: &mut State, depth: usize) -> Control {
        let Some(target) = node.child(HirField::Left) else {
            return Control::Next;
        };
        let iterable = node
            .child(HirField::Right)
            .map_or(Value::Unknown, |right| self.eval(right, state, depth));
        let Some(body) = node.child(HirField::Body) else {
            return Control::Next;
        };
        let values = sequence_values(&iterable, state).map(Vec::from);
        let Some(values) = values else {
            self.complete = false;
            let before = state.clone();
            self.assign(target, Value::Unknown, state);
            let dominators = self.execution_dominators.clone();
            self.conditional_depth += 1;
            let control = self.exec_block(body, state, depth);
            self.execution_dominators.clone_from(&dominators);
            let joined_control = match &control {
                Control::Next | Control::Continue => {
                    *state = join_states(before, state.clone());
                    self.exec_loop_else(node, state, depth)
                }
                Control::Break => {
                    let mut zero_iterations = before;
                    let _ = self.exec_loop_else(node, &mut zero_iterations, depth);
                    *state = join_states(zero_iterations, state.clone());
                    Control::Next
                }
                _ => {
                    let mut zero_iterations = before;
                    let zero_control = self.exec_loop_else(node, &mut zero_iterations, depth);
                    *state = zero_iterations;
                    if control == zero_control {
                        control
                    } else {
                        Control::Next
                    }
                }
            };
            self.conditional_depth -= 1;
            self.execution_dominators = dominators;
            return joined_control;
        };
        if values.len() > MAX_LOOP_ITERATIONS {
            self.complete = false;
            self.budget.refusal = Some(InlineRefusal::WorkLimit);
        }
        let complete = values.len() <= MAX_LOOP_ITERATIONS;
        let mut broke = false;
        for value in values.into_iter().take(MAX_LOOP_ITERATIONS) {
            self.assign(target, value, state);
            match self.exec_block(body, state, depth) {
                Control::Next | Control::Continue => {}
                Control::Break => {
                    broke = true;
                    break;
                }
                control => return control,
            }
        }
        if complete && !broke {
            self.exec_loop_else(node, state, depth)
        } else {
            Control::Next
        }
    }

    fn while_statement(&mut self, node: &HirNode, state: &mut State, depth: usize) -> Control {
        let Some(condition) = node.child(HirField::Condition) else {
            self.complete = false;
            return Control::Next;
        };
        let Some(body) = node.child(HirField::Body) else {
            self.complete = false;
            return Control::Next;
        };
        for _ in 0..MAX_LOOP_ITERATIONS {
            let value = self.eval(condition, state, depth);
            match truthy(&value, state) {
                Some(false) => return self.exec_loop_else(node, state, depth),
                Some(true) => {
                    let before = state.clone();
                    match self.exec_block(body, state, depth) {
                        Control::Next | Control::Continue => {
                            if *state == before {
                                return Control::Diverge;
                            }
                        }
                        Control::Break => return Control::Next,
                        control => return control,
                    }
                }
                None => {
                    self.complete = false;
                    let dominators = self.execution_dominators.clone();
                    self.conditional_depth += 1;
                    let mut exits = state.clone();
                    let exit_control = self.exec_loop_else(node, &mut exits, depth);
                    self.execution_dominators.clone_from(&dominators);
                    let mut iterates = state.clone();
                    let body_control = self.exec_block(body, &mut iterates, depth);
                    self.conditional_depth -= 1;
                    self.execution_dominators = dominators;
                    *state = if matches!(
                        body_control,
                        Control::Return(_) | Control::Raise | Control::Diverge
                    ) {
                        exits
                    } else {
                        join_states(exits, iterates)
                    };
                    return if exit_control == body_control {
                        exit_control
                    } else {
                        Control::Next
                    };
                }
            }
        }
        self.complete = false;
        self.budget.refusal = Some(InlineRefusal::WorkLimit);
        Control::Next
    }

    fn exec_loop_else(&mut self, node: &HirNode, state: &mut State, depth: usize) -> Control {
        node.child(HirField::Alternative)
            .and_then(|alternative| alternative.child(HirField::Body))
            .map_or(Control::Next, |body| self.exec_block(body, state, depth))
    }

    fn with_statement(&mut self, node: &HirNode, state: &mut State, depth: usize) -> Control {
        for item in node
            .children()
            .iter()
            .find(|child| child.kind() == HirKind::WithClause)
            .into_iter()
            .flat_map(named_children)
        {
            let Some(value) = item.child(HirField::Value) else {
                self.complete = false;
                continue;
            };
            if value.kind() == HirKind::AsPattern {
                if let Some(context) =
                    named_children(value).find(|child| child.field() != Some(HirField::Alias))
                {
                    self.eval(context, state, depth);
                }
                if self.pending_control.is_some() {
                    break;
                }
                if let Some(alias) = value.child(HirField::Alias) {
                    self.assign_unknown(alias, state);
                } else {
                    self.complete = false;
                }
            } else {
                self.eval(value, state, depth);
            }
        }
        if let Some(control) = self.pending_control.take() {
            return control;
        }
        node.child(HirField::Body)
            .map_or(Control::Next, |body| self.exec_block(body, state, depth))
    }

    fn assign_unknown(&mut self, target: &HirNode, state: &mut State) {
        if target.kind() == HirKind::Identifier {
            state
                .bindings
                .insert(self.text(target).to_owned(), Value::Unknown);
            return;
        }
        let mut found = false;
        for child in named_children(target) {
            found = true;
            self.assign_unknown(child, state);
        }
        if !found {
            self.complete = false;
        }
    }

    fn try_statement(&mut self, node: &HirNode, state: &mut State, depth: usize) -> Control {
        let mut control = node
            .child(HirField::Body)
            .map_or(Control::Next, |body| self.exec_block(body, state, depth));
        if control == Control::Raise {
            let mut bare_handler = None;
            for clause in node
                .children()
                .iter()
                .filter(|child| child.kind() == HirKind::Except)
            {
                let mut children = named_children(clause);
                let first = children.next();
                if first.is_some_and(|child| child.kind() == HirKind::Block)
                    && children.next().is_none()
                {
                    bare_handler = first;
                } else {
                    self.complete = false;
                }
            }
            if let Some(body) = bare_handler {
                control = self.exec_block(body, state, depth);
            }
        } else if control == Control::Next
            && let Some(alternative) = node
                .children()
                .iter()
                .find(|child| child.kind() == HirKind::Else)
            && let Some(body) = alternative.child(HirField::Body).or_else(|| {
                named_children(alternative).find(|child| child.kind() == HirKind::Block)
            })
        {
            control = self.exec_block(body, state, depth);
        }
        if let Some(finally) = node
            .children()
            .iter()
            .find(|child| child.kind() == HirKind::Finally)
            && let Some(body) = finally
                .child(HirField::Body)
                .or_else(|| named_children(finally).find(|child| child.kind() == HirKind::Block))
        {
            let final_control = self.exec_block(body, state, depth);
            if final_control != Control::Next {
                control = final_control;
            }
        }
        control
    }

    fn collection(&mut self, node: &HirNode, state: &mut State, depth: usize) -> Value {
        let mut values = Vec::new();
        let mut bytes = 0usize;
        for child in named_children(node) {
            if values.len() >= MAX_COLLECTION_ITEMS {
                self.complete = false;
                self.budget.refuse_work();
                return Value::Unknown;
            }
            if child.kind() == HirKind::ListSplat {
                let spread = named_children(child)
                    .next()
                    .map_or(Value::Unknown, |value| self.eval(value, state, depth));
                if let Some(items) = sequence_values(&spread, state) {
                    if items.len() > MAX_COLLECTION_ITEMS - values.len() {
                        self.complete = false;
                        self.budget.refuse_work();
                        return Value::Unknown;
                    }
                    let item_bytes = values_bytes(items);
                    let Some(total_bytes) = item_bytes.and_then(|item_bytes| {
                        bytes
                            .checked_add(item_bytes)
                            .filter(|bytes| *bytes <= MAX_VALUE_BYTES)
                    }) else {
                        self.budget.refuse_work();
                        return Value::Unknown;
                    };
                    values.extend_from_slice(items);
                    bytes = total_bytes;
                } else {
                    self.complete = false;
                    return Value::Unknown;
                }
            } else {
                let value = self.eval(child, state, depth);
                let Some(total_bytes) = value_bytes(&value).and_then(|value_bytes| {
                    bytes
                        .checked_add(value_bytes)
                        .filter(|bytes| *bytes <= MAX_VALUE_BYTES)
                }) else {
                    self.budget.refuse_work();
                    return Value::Unknown;
                };
                values.push(value);
                bytes = total_bytes;
            }
        }
        if state.cells.len() >= MAX_CELLS {
            self.budget.refusal = Some(InlineRefusal::WorkLimit);
            return Value::Unknown;
        }
        let cell = state.cells.len();
        state.cells.push(Cell::Sequence(values));
        Value::Cell(cell)
    }

    fn string(&mut self, node: &HirNode, state: &mut State, depth: usize) -> Value {
        let start = node
            .children()
            .iter()
            .find(|child| child.kind() == HirKind::StringStart)
            .map(|child| self.text(child))
            .unwrap_or_default();
        let prefix_end = start.find(['\'', '"']).unwrap_or(start.len());
        let prefix = start[..prefix_end].to_ascii_lowercase();
        let raw = prefix.contains('r');
        let bytes = prefix.contains('b');
        let formatted = prefix.contains('f');
        let mut value = String::new();
        for child in node.children() {
            match child.kind() {
                HirKind::StringContent => {
                    let Some(content) = decode_string_fragment(self.text(child), raw) else {
                        return Value::Unknown;
                    };
                    if !bounded_push_str(&mut value, &content, &mut self.budget) {
                        return Value::Unknown;
                    }
                }
                HirKind::Interpolation if formatted => {
                    let Some(expression) = child.child(HirField::Expression) else {
                        return Value::Unknown;
                    };
                    let interpolated = self.eval(expression, state, depth);
                    if child.child(HirField::TypeConversion).is_some()
                        || child.child(HirField::FormatSpecifier).is_some()
                    {
                        self.complete = false;
                        return Value::Unknown;
                    }
                    let Some(interpolated) = display_value(&interpolated) else {
                        return Value::Unknown;
                    };
                    if !bounded_push_str(&mut value, &interpolated, &mut self.budget) {
                        return Value::Unknown;
                    }
                }
                _ => {}
            }
        }
        if bytes {
            Value::Bytes(value.into_bytes())
        } else {
            Value::String(value)
        }
    }

    fn concatenated_string(&mut self, node: &HirNode, state: &mut State, depth: usize) -> Value {
        let mut result = None;
        for child in named_children(node) {
            let next = self.eval(child, state, depth);
            result = Some(match result {
                None => next,
                Some(value) => binary_value(value, next, "+", &mut self.budget),
            });
        }
        match result.unwrap_or(Value::String(String::new())) {
            Value::String(value) => Value::ImplicitString(value),
            value => value,
        }
    }

    fn attribute(&mut self, node: &HirNode, state: &mut State, depth: usize) -> Value {
        let Some(object) = node.child(HirField::Object) else {
            return Value::Unknown;
        };
        let Some(attribute) = node.child(HirField::Attribute) else {
            return Value::Unknown;
        };
        let object = self.eval(object, state, depth);
        let attribute = self.text(attribute);
        let value = match object {
            Value::Module(module) => {
                if module == Module::Os
                    && let Some(value) = os_open_flag(attribute, self.input.platform)
                {
                    Value::Int(value)
                } else {
                    module_attribute(module, attribute).unwrap_or(Value::ModuleMethod(module))
                }
            }
            Value::Path(path) => Value::PathMethod {
                path,
                method: attribute.to_owned(),
            },
            Value::Cell(cell) => Value::CellMethod {
                cell,
                method: attribute.to_owned(),
            },
            Value::String(value) => Value::StringMethod {
                value,
                method: attribute.to_owned(),
            },
            Value::Bytes(value) => Value::BytesMethod {
                value,
                method: attribute.to_owned(),
            },
            Value::Decoded(value) => Value::DecodedMethod {
                value,
                method: attribute.to_owned(),
            },
            Value::Known(KnownFunction::Path) if attribute == "home" => {
                Value::Known(KnownFunction::PathHome)
            }
            Value::Produced(origins) => Value::Produced(origins),
            _ => Value::Unknown,
        };
        if self.budget.admit_value_bytes(value_bytes(&value)) {
            value
        } else {
            Value::Unknown
        }
    }

    fn call(&mut self, node: &HirNode, state: &mut State, depth: usize) -> Value {
        let callable = node
            .child(HirField::Function)
            .map_or(Value::Unknown, |function| self.eval(function, state, depth));
        if self.pending_control.is_some() {
            return Value::Unknown;
        }
        let arguments = node
            .child(HirField::Arguments)
            .map_or_else(Arguments::default, |arguments| {
                self.arguments(arguments, state, depth)
            });
        if self.pending_control.is_some() {
            return Value::Unknown;
        }
        match callable {
            Value::Known(function) => self.call_known(function, arguments, state, depth),
            Value::LocalFunction(function) => self.call_local(function, arguments, state, depth),
            Value::PathMethod { path, method } => {
                self.call_path_method(path, &method, arguments, state)
            }
            Value::CellMethod { cell, method } => {
                self.call_cell_method(cell, &method, arguments, state)
            }
            Value::StringMethod { value, method } => {
                self.call_string_method(value, &method, arguments)
            }
            Value::BytesMethod { value, method } => {
                self.call_bytes_method(value, &method, arguments)
            }
            Value::DecodedMethod { value, method } => {
                if method == "decode"
                    && arguments.positional.is_empty()
                    && arguments.keywords.is_empty()
                {
                    Value::Decoded(value)
                } else {
                    Value::Unknown
                }
            }
            Value::ModuleMethod(module) => {
                if module == Module::Environment {
                    invalidate_module(module, state);
                }
                state.relative_cwd_known = false;
                Value::Unknown
            }
            Value::Produced(origins) => {
                state.relative_cwd_known = false;
                Value::Produced(origins)
            }
            _ => {
                invalidate_argument_cells(&arguments, state);
                state.relative_cwd_known = false;
                Value::Unknown
            }
        }
    }

    fn arguments(&mut self, node: &HirNode, state: &mut State, depth: usize) -> Arguments {
        let mut arguments = Arguments::default();
        for child in named_children(node) {
            match child.kind() {
                HirKind::KeywordArgument => {
                    let Some(name) = child.child(HirField::Name) else {
                        arguments.complete = false;
                        continue;
                    };
                    let value = child
                        .child(HirField::Value)
                        .map_or(Value::Unknown, |value| self.eval(value, state, depth));
                    let name = self.text(name).to_owned();
                    if arguments
                        .keywords
                        .iter()
                        .any(|(existing, _)| existing == &name)
                    {
                        arguments.complete = false;
                    }
                    arguments.keywords.push((name, value));
                }
                HirKind::ListSplat => {
                    let value = named_children(child)
                        .next()
                        .map_or(Value::Unknown, |value| self.eval(value, state, depth));
                    if let Some(values) = sequence_values(&value, state) {
                        arguments.positional.extend_from_slice(values);
                    } else {
                        arguments.complete = false;
                    }
                }
                HirKind::DictionarySplat => {
                    self.eval_children(child, state, depth);
                    arguments.complete = false;
                }
                _ => arguments.positional.push(self.eval(child, state, depth)),
            }
        }
        arguments
    }

    fn call_known(
        &mut self,
        function: KnownFunction,
        arguments: Arguments,
        state: &mut State,
        depth: usize,
    ) -> Value {
        match function {
            KnownFunction::ShutilRmtree => {
                if !valid_call_shape(
                    &arguments,
                    3,
                    &["path", "ignore_errors", "onerror", "onexc", "dir_fd"],
                ) || required_argument(&arguments, 0, "path").is_none()
                    || !possible_path_argument(&arguments, 0, "path")
                {
                    return Value::Unknown;
                }
                self.emit_filesystem_call(
                    "shutil.rmtree",
                    &arguments,
                    state,
                    vec![filesystem_argument(
                        &arguments,
                        0,
                        "path",
                        FilesystemOperation::Delete,
                        true,
                    )],
                );
                if let Some(path) = one_argument(&arguments, "path").and_then(value_string) {
                    self.add_destructive_target(path);
                }
                Value::None
            }
            KnownFunction::OsSystem | KnownFunction::OsPopen => {
                let valid = if function == KnownFunction::OsSystem {
                    valid_call_shape(&arguments, 1, &["command"])
                        && required_argument(&arguments, 0, "command").is_some()
                        && possible_scalar_argument(&arguments, 0, "command")
                } else {
                    valid_call_shape(&arguments, 3, &["cmd", "mode", "buffering"])
                        && required_argument(&arguments, 0, "cmd").is_some()
                        && possible_scalar_argument(&arguments, 0, "cmd")
                };
                if !valid {
                    return Value::Unknown;
                }
                let name = if function == KnownFunction::OsSystem {
                    "command"
                } else {
                    "cmd"
                };
                if let Some(value) = one_argument(&arguments, name) {
                    if decoded(value) {
                        self.report
                            .push(Finding::exact(FindingKind::DecodedExecution));
                    }
                    if let Some(code) = value_string(value)
                        && self.input.platform != Platform::Windows
                    {
                        self.push_shell(code, function == KnownFunction::OsSystem);
                    }
                }
                self.emit_call(
                    LanguageCallKind::EvaluatedShell,
                    if function == KnownFunction::OsSystem {
                        "os.system"
                    } else {
                        "os.popen"
                    },
                    &arguments,
                    state,
                    Vec::new(),
                    None,
                )
                .map_or(Value::Unknown, |origin| Value::Produced(vec![origin]))
            }
            KnownFunction::OsExec(kind) => {
                if !valid_os_exec_shape(kind, &arguments)
                    || !possible_os_exec(kind, &arguments, state)
                {
                    return Value::Unknown;
                }
                let callable = os_exec_callable(kind);
                self.emit_call(
                    LanguageCallKind::LocalUtility,
                    callable,
                    &arguments,
                    state,
                    Vec::new(),
                    None,
                );
                self.os_exec(kind, &arguments, state);
                self.pending_control = Some(Control::Raise);
                Value::None
            }
            KnownFunction::Subprocess(kind) => {
                if required_argument(&arguments, 0, "args").is_none()
                    || arguments.positional.len() > 1
                    || !valid_subprocess_shape(&arguments)
                {
                    return Value::Unknown;
                }
                let origin = if let Some(shell) = subprocess_shell(&arguments) {
                    let command = required_argument(&arguments, 0, "args")
                        .expect("required subprocess argument was checked");
                    if !possible_subprocess_command(command, state) {
                        return Value::Unknown;
                    }
                    self.emit_call(
                        if shell {
                            LanguageCallKind::EvaluatedShell
                        } else {
                            LanguageCallKind::LocalUtility
                        },
                        subprocess_callable(kind),
                        &arguments,
                        state,
                        Vec::new(),
                        None,
                    )
                } else {
                    self.draft.set_partial();
                    None
                };
                self.subprocess(kind, &arguments, state);
                origin.map_or(Value::Unknown, |origin| Value::Produced(vec![origin]))
            }
            KnownFunction::Eval | KnownFunction::Exec => {
                if let Some(isolated) = dynamic_arguments(function, &arguments)
                    && let Some(value) = arguments.positional.first()
                {
                    let exact_source = matches!(value, Value::String(_) | Value::Compiled { .. });
                    let mode = if function == KnownFunction::Eval {
                        CodeMode::Eval
                    } else {
                        CodeMode::Exec
                    };
                    if isolated {
                        let mut isolated_state = State::default();
                        self.dynamic_execution(value.clone(), mode, &mut isolated_state, depth);
                        propagate_invalid_modules(&isolated_state.invalid_modules, state);
                        state.relative_cwd_known &= isolated_state.relative_cwd_known;
                    } else {
                        self.dynamic_execution(value.clone(), mode, state, depth);
                    }
                    if !exact_source {
                        state.relative_cwd_known = false;
                    }
                }
                Value::Unknown
            }
            KnownFunction::Compile => {
                if arguments.complete
                    && arguments.positional.len() == 3
                    && arguments.keywords.is_empty()
                    && arguments.positional.get(1).and_then(value_string).is_some()
                    && let (Some(source), Some(mode)) = (
                        arguments.positional.first().and_then(value_string),
                        arguments.positional.get(2).and_then(value_string),
                    )
                    && let Some(mode) = code_mode(mode)
                    && let Some(source) = bounded_owned(source, &mut self.budget)
                {
                    return Value::Compiled { source, mode };
                }
                Value::Unknown
            }
            KnownFunction::Base64Decode => {
                let value = arguments
                    .positional
                    .first()
                    .cloned()
                    .unwrap_or(Value::Unknown);
                Value::Decoded(Box::new(match value {
                    Value::String(value) => {
                        decode_base64(&value).map_or(Value::Unknown, Value::Bytes)
                    }
                    Value::Bytes(value) => std::str::from_utf8(&value)
                        .ok()
                        .and_then(decode_base64)
                        .map_or(Value::Unknown, Value::Bytes),
                    _ => Value::Unknown,
                }))
            }
            KnownFunction::Path => {
                if !arguments.complete
                    || !arguments.keywords.is_empty()
                    || arguments.positional.len() != 1
                {
                    return Value::Unknown;
                }
                arguments
                    .positional
                    .first()
                    .and_then(value_string)
                    .and_then(|path| bounded_owned(path, &mut self.budget))
                    .map_or(Value::Unknown, Value::Path)
            }
            KnownFunction::PathHome => {
                if arguments.positional.is_empty()
                    && arguments.keywords.is_empty()
                    && !state.invalid_modules.contains(&Module::Environment)
                {
                    bounded_owned(self.input.home, &mut self.budget)
                        .map_or(Value::Unknown, Value::Path)
                } else {
                    Value::Unknown
                }
            }
            KnownFunction::PathJoin => {
                let mut joined = String::new();
                for part in &arguments.positional {
                    let Some(part) = value_string(part) else {
                        return Value::Unknown;
                    };
                    let Some(value) = join_path(joined, part, &mut self.budget) else {
                        return Value::Unknown;
                    };
                    joined = value;
                }
                Value::String(joined)
            }
            KnownFunction::OsExpanduser => {
                if state.invalid_modules.contains(&Module::Environment) {
                    Value::Unknown
                } else {
                    arguments
                        .positional
                        .first()
                        .and_then(value_string)
                        .and_then(|path| expand_home(path, self.input.home, &mut self.budget))
                        .map_or(Value::Unknown, Value::String)
                }
            }
            KnownFunction::OsAbspath => arguments
                .positional
                .first()
                .and_then(value_string)
                .filter(|path| is_absolute(path, self.input.platform))
                .and_then(|path| bounded_owned(path, &mut self.budget))
                .map_or(Value::Unknown, Value::String),
            KnownFunction::OsRealpath => Value::Unknown,
            KnownFunction::OsGetenv => {
                if state.invalid_modules.contains(&Module::Environment) {
                    Value::Unknown
                } else {
                    arguments
                        .positional
                        .first()
                        .and_then(value_string)
                        .filter(|name| *name == "HOME")
                        .and_then(|_| bounded_owned(self.input.home, &mut self.budget))
                        .map_or(Value::Unknown, Value::String)
                }
            }
            KnownFunction::Getattr => {
                if arguments.positional.len() >= 2
                    && let Some(attribute) = arguments.positional.get(1).and_then(value_string)
                    && let Some(value) = arguments.positional.first()
                {
                    return match value {
                        Value::Module(module) => {
                            module_attribute(*module, attribute).unwrap_or(Value::Unknown)
                        }
                        _ => Value::Unknown,
                    };
                }
                Value::Unknown
            }
            KnownFunction::Import => arguments
                .positional
                .first()
                .and_then(value_string)
                .and_then(module_value)
                .map(|value| retain_owned_module(value, state))
                .unwrap_or(Value::Unknown),
            KnownFunction::ShutilWhich => Value::Unknown,
            KnownFunction::Request(kind) => {
                if required_argument(&arguments, 0, request_url_keyword(kind)).is_none()
                    || !possible_scalar_argument(&arguments, 0, request_url_keyword(kind))
                {
                    return Value::Unknown;
                }
                let callable = request_callable(kind);
                let endpoint = argument(&arguments, 0, request_url_keyword(kind))
                    .and_then(value_string)
                    .map(str::to_owned);
                let mut filesystems = Vec::new();
                if kind == RequestKind::UrlRetrieve {
                    filesystems.push(filesystem_argument(
                        &arguments,
                        1,
                        "filename",
                        FilesystemOperation::Write,
                        false,
                    ));
                }
                self.emit_call(
                    LanguageCallKind::NetworkTransfer,
                    callable,
                    &arguments,
                    state,
                    filesystems,
                    endpoint,
                )
                .map_or(Value::Unknown, |origin| Value::Produced(vec![origin]))
            }
            KnownFunction::Open | KnownFunction::IoFile => {
                let (max_positional, keywords) = if function == KnownFunction::Open {
                    (
                        8,
                        &[
                            "file",
                            "mode",
                            "buffering",
                            "encoding",
                            "errors",
                            "newline",
                            "closefd",
                            "opener",
                        ][..],
                    )
                } else {
                    (4, &["file", "mode", "closefd", "opener"][..])
                };
                if !valid_call_shape(&arguments, max_positional, keywords) {
                    return Value::Unknown;
                }
                if required_argument(&arguments, 0, "file").is_none() {
                    return Value::Unknown;
                }
                if !argument(&arguments, 0, "file").is_some_and(possible_open_target) {
                    return Value::Unknown;
                }
                let callable = if function == KnownFunction::Open {
                    "builtins.open"
                } else {
                    "io.fileio"
                };
                let Some(operations) = open_operations(&arguments) else {
                    self.draft.set_partial();
                    return Value::Unknown;
                };
                if operations.is_empty() {
                    return Value::Unknown;
                }
                let filesystems = operations
                    .into_iter()
                    .map(|operation| filesystem_argument(&arguments, 0, "file", operation, false))
                    .collect();
                self.emit_filesystem_call(callable, &arguments, state, filesystems)
                    .map_or(Value::Unknown, |origin| Value::Produced(vec![origin]))
            }
            KnownFunction::OsRemove
            | KnownFunction::OsUnlink
            | KnownFunction::OsRemovedirs
            | KnownFunction::OsRmdir => {
                let (callable, recursive) = match function {
                    KnownFunction::OsRemove => ("os.remove", false),
                    KnownFunction::OsUnlink => ("os.unlink", false),
                    KnownFunction::OsRemovedirs => ("os.removedirs", true),
                    KnownFunction::OsRmdir => ("os.rmdir", false),
                    _ => unreachable!(),
                };
                if !valid_call_shape(&arguments, 1, &["path", "dir_fd"])
                    || required_argument(&arguments, 0, "path").is_none()
                    || !possible_path_argument(&arguments, 0, "path")
                {
                    return Value::Unknown;
                }
                self.emit_filesystem_call(
                    callable,
                    &arguments,
                    state,
                    vec![filesystem_argument(
                        &arguments,
                        0,
                        "path",
                        FilesystemOperation::Delete,
                        recursive,
                    )],
                );
                Value::None
            }
            KnownFunction::OsMkdir | KnownFunction::OsMakedirs | KnownFunction::OsTruncate => {
                let (callable, keyword, recursive, required, max_positional, keywords) =
                    match function {
                        KnownFunction::OsMkdir => (
                            "os.mkdir",
                            "path",
                            false,
                            1,
                            2,
                            &["path", "mode", "dir_fd"] as &[_],
                        ),
                        KnownFunction::OsMakedirs => (
                            "os.makedirs",
                            "name",
                            true,
                            1,
                            3,
                            &["name", "mode", "exist_ok"] as &[_],
                        ),
                        KnownFunction::OsTruncate => (
                            "os.truncate",
                            "path",
                            false,
                            2,
                            2,
                            &["path", "length"] as &[_],
                        ),
                        _ => unreachable!(),
                    };
                if !valid_call_shape(&arguments, max_positional, keywords)
                    || (0..required).any(|position| {
                        let name = keywords[position];
                        required_argument(&arguments, position, name).is_none()
                    })
                    || !possible_path_argument(&arguments, 0, keyword)
                {
                    return Value::Unknown;
                }
                self.emit_filesystem_call(
                    callable,
                    &arguments,
                    state,
                    vec![
                        filesystem_argument(
                            &arguments,
                            0,
                            keyword,
                            FilesystemOperation::Write,
                            recursive,
                        )
                        .metadata_if(function != KnownFunction::OsTruncate),
                    ],
                );
                Value::None
            }
            KnownFunction::ShutilCopy(kind) => {
                if !valid_call_shape(
                    &arguments,
                    2,
                    &[
                        "src",
                        "dst",
                        "follow_symlinks",
                        "copy_function",
                        "dirs_exist_ok",
                    ],
                ) || required_argument(&arguments, 0, "src").is_none()
                    || required_argument(&arguments, 1, "dst").is_none()
                    || !possible_path_argument(&arguments, 0, "src")
                    || !possible_path_argument(&arguments, 1, "dst")
                {
                    return Value::Unknown;
                }
                let recursive = kind == CopyKind::Copytree;
                let metadata = matches!(kind, CopyKind::Copymode | CopyKind::Copystat);
                self.emit_filesystem_call(
                    shutil_copy_callable(kind),
                    &arguments,
                    state,
                    vec![
                        filesystem_argument(
                            &arguments,
                            0,
                            "src",
                            FilesystemOperation::Read,
                            recursive,
                        )
                        .metadata_if(metadata),
                        filesystem_argument(
                            &arguments,
                            1,
                            "dst",
                            FilesystemOperation::Write,
                            recursive,
                        )
                        .metadata_if(metadata),
                    ],
                );
                Value::Unknown
            }
            KnownFunction::OsChmod | KnownFunction::OsChown => {
                let (callable, required, max_positional, keywords) =
                    if function == KnownFunction::OsChmod {
                        (
                            "os.chmod",
                            2,
                            2,
                            &["path", "mode", "dir_fd", "follow_symlinks"] as &[_],
                        )
                    } else {
                        (
                            "os.chown",
                            3,
                            3,
                            &["path", "uid", "gid", "dir_fd", "follow_symlinks"] as &[_],
                        )
                    };
                if !valid_call_shape(&arguments, max_positional, keywords)
                    || (0..required).any(|position| {
                        required_argument(&arguments, position, keywords[position]).is_none()
                    })
                    || !possible_path_argument(&arguments, 0, "path")
                {
                    return Value::Unknown;
                }
                self.emit_filesystem_call(
                    callable,
                    &arguments,
                    state,
                    vec![
                        filesystem_argument(
                            &arguments,
                            0,
                            "path",
                            FilesystemOperation::Write,
                            false,
                        )
                        .metadata()
                        .protects_descendants(),
                    ],
                );
                Value::None
            }
            KnownFunction::OsRename | KnownFunction::OsReplace | KnownFunction::ShutilMove => {
                let (callable, max_positional, keywords) = match function {
                    KnownFunction::OsRename => (
                        "os.rename",
                        2,
                        &["src", "dst", "src_dir_fd", "dst_dir_fd"] as &[_],
                    ),
                    KnownFunction::OsReplace => (
                        "os.replace",
                        2,
                        &["src", "dst", "src_dir_fd", "dst_dir_fd"] as &[_],
                    ),
                    KnownFunction::ShutilMove => {
                        ("shutil.move", 3, &["src", "dst", "copy_function"] as &[_])
                    }
                    _ => unreachable!(),
                };
                if !valid_call_shape(&arguments, max_positional, keywords)
                    || required_argument(&arguments, 0, "src").is_none()
                    || required_argument(&arguments, 1, "dst").is_none()
                    || !possible_path_argument(&arguments, 0, "src")
                    || !possible_path_argument(&arguments, 1, "dst")
                {
                    return Value::Unknown;
                }
                let identity = argument(&arguments, 0, "src")
                    .and_then(value_string)
                    .map(str::to_owned);
                self.emit_filesystem_call(
                    callable,
                    &arguments,
                    state,
                    vec![
                        filesystem_argument(
                            &arguments,
                            0,
                            "src",
                            FilesystemOperation::Delete,
                            false,
                        ),
                        filesystem_argument(
                            &arguments,
                            1,
                            "dst",
                            FilesystemOperation::Write,
                            false,
                        )
                        .identity(identity, false)
                        .protects_descendants(),
                    ],
                );
                Value::None
            }
            KnownFunction::OsLink => {
                if !valid_call_shape(
                    &arguments,
                    2,
                    &["src", "dst", "src_dir_fd", "dst_dir_fd", "follow_symlinks"],
                ) || required_argument(&arguments, 0, "src").is_none()
                    || required_argument(&arguments, 1, "dst").is_none()
                    || !possible_path_argument(&arguments, 0, "src")
                    || !possible_path_argument(&arguments, 1, "dst")
                {
                    return Value::Unknown;
                }
                let identity = argument(&arguments, 0, "src")
                    .and_then(value_string)
                    .map(str::to_owned);
                self.emit_filesystem_call(
                    "os.link",
                    &arguments,
                    state,
                    vec![
                        filesystem_argument(
                            &arguments,
                            1,
                            "dst",
                            FilesystemOperation::Write,
                            false,
                        )
                        .identity(identity, true),
                    ],
                );
                Value::None
            }
            KnownFunction::OsSymlink => {
                if !valid_call_shape(
                    &arguments,
                    3,
                    &["src", "dst", "target_is_directory", "dir_fd"],
                ) || required_argument(&arguments, 0, "src").is_none()
                    || required_argument(&arguments, 1, "dst").is_none()
                    || !possible_path_argument(&arguments, 1, "dst")
                {
                    return Value::Unknown;
                }
                self.emit_filesystem_call(
                    "os.symlink",
                    &arguments,
                    state,
                    vec![
                        filesystem_argument(
                            &arguments,
                            1,
                            "dst",
                            FilesystemOperation::Write,
                            false,
                        )
                        .metadata(),
                    ],
                );
                Value::None
            }
            KnownFunction::OsOpen => {
                if !valid_call_shape(&arguments, 3, &["path", "flags", "mode", "dir_fd"])
                    || required_argument(&arguments, 0, "path").is_none()
                    || required_argument(&arguments, 1, "flags").is_none()
                    || !possible_path_argument(&arguments, 0, "path")
                {
                    return Value::Unknown;
                }
                let Some(Value::Int(flags)) = argument(&arguments, 1, "flags") else {
                    self.draft.set_partial();
                    return Value::Unknown;
                };
                let access = flags & 3;
                if access == 3 {
                    return Value::Unknown;
                }
                let mut filesystems = Vec::new();
                if matches!(access, 0 | 2) {
                    filesystems.push(filesystem_argument(
                        &arguments,
                        0,
                        "path",
                        FilesystemOperation::Read,
                        false,
                    ));
                }
                if matches!(access, 1 | 2)
                    || flags & os_open_mutation_flags(self.input.platform) != 0
                {
                    filesystems.push(filesystem_argument(
                        &arguments,
                        0,
                        "path",
                        FilesystemOperation::Write,
                        false,
                    ));
                }
                if filesystems.is_empty() {
                    return Value::Unknown;
                }
                self.emit_filesystem_call("os.open", &arguments, state, filesystems)
                    .map_or(Value::Unknown, |origin| Value::Produced(vec![origin]))
            }
        }
    }

    fn emit_filesystem_call(
        &mut self,
        callable: &str,
        arguments: &Arguments,
        state: &State,
        filesystems: Vec<LanguageFilesystem>,
    ) -> Option<usize> {
        self.emit_call(
            LanguageCallKind::DirectFile,
            callable,
            arguments,
            state,
            filesystems,
            None,
        )
    }

    fn emit_call(
        &mut self,
        kind: LanguageCallKind,
        callable: &str,
        arguments: &Arguments,
        state: &State,
        filesystems: Vec<LanguageFilesystem>,
        endpoint: Option<String>,
    ) -> Option<usize> {
        let mut unresolved_filesystem = false;
        let filesystems = filesystems
            .into_iter()
            .map(|mut filesystem| {
                if !state.relative_cwd_known
                    && filesystem
                        .requested()
                        .is_some_and(|path| !is_absolute(path, self.input.platform))
                {
                    filesystem = filesystem.without_requested();
                    unresolved_filesystem = true;
                }
                if !state.relative_cwd_known
                    && filesystem
                        .identity_path()
                        .is_some_and(|path| !is_absolute(path, self.input.platform))
                {
                    filesystem = filesystem.without_identity();
                    unresolved_filesystem = true;
                }
                filesystem
            })
            .collect::<Vec<_>>();
        let input = language_call_input(callable, arguments, state);
        if !input.complete()
            || unresolved_filesystem
            || filesystems
                .iter()
                .any(|filesystem| filesystem.requested().is_none())
            || kind == LanguageCallKind::NetworkTransfer && endpoint.is_none()
        {
            self.draft.set_partial();
        }
        let origins = argument_origins(arguments, state);
        let call = LanguageCall::new(
            kind,
            input,
            filesystems,
            endpoint,
            self.conditional_depth,
            self.execution_dominators.clone(),
        );
        let ordinal = self.draft.push_call(call)?;
        if self.conditional_depth > 0 {
            self.execution_dominators.push(ordinal);
        }
        for origin in origins {
            self.draft.push_flow(origin, ordinal);
        }
        Some(ordinal)
    }

    fn call_local(
        &mut self,
        function: usize,
        arguments: Arguments,
        state: &mut State,
        depth: usize,
    ) -> Value {
        if depth >= MAX_CALL_DEPTH {
            self.budget.refusal = Some(InlineRefusal::RecursionLimit);
            return Value::Unknown;
        }
        let Some(function) = state.functions.get(function).cloned() else {
            return Value::Unknown;
        };
        if self.call_stack.contains(&function.name) {
            self.complete = false;
            return Value::Unknown;
        }
        let Some(parameters) = function.parameters.as_deref() else {
            self.complete = false;
            return Value::Unknown;
        };
        let Some(bindings) = bind_arguments(parameters, &arguments) else {
            self.complete = false;
            return Value::Unknown;
        };
        let mut local = state.clone();
        let globals = global_names(&function.body, &function.source);
        for name in assigned_names(&function.body, &function.source) {
            if !globals.contains(&name) {
                local.bindings.insert(name, Value::Unknown);
            }
        }
        for (name, value) in bindings {
            local.bindings.insert(name, value);
        }
        self.call_stack.push(function.name);
        let outer_source = std::mem::replace(&mut self.source, function.source);
        let control = self.exec_block(&function.body, &mut local, depth + 1);
        let result = match &control {
            Control::Return(value) => value.clone(),
            _ => Value::None,
        };
        self.source = outer_source;
        self.call_stack.pop();
        for (cell, local_cell) in state.cells.iter_mut().zip(local.cells) {
            *cell = local_cell;
        }
        propagate_invalid_modules(&local.invalid_modules, state);
        state.relative_cwd_known &= local.relative_cwd_known;
        for name in globals {
            state.bindings.insert(name, Value::Unknown);
        }
        if matches!(control, Control::Raise | Control::Diverge) {
            self.pending_control = Some(control);
        }
        result
    }

    fn call_path_method(
        &mut self,
        path: String,
        method: &str,
        arguments: Arguments,
        state: &mut State,
    ) -> Value {
        match method {
            "with_name" => {
                arguments
                    .positional
                    .first()
                    .and_then(value_string)
                    .map_or(Value::Unknown, |name| {
                        let parent = path
                            .rsplit_once(['/', '\\'])
                            .map_or("", |(parent, _)| parent);
                        join_path(parent.to_owned(), name, &mut self.budget)
                            .map_or(Value::Unknown, Value::Path)
                    })
            }
            "joinpath" => {
                let mut joined = path;
                for value in &arguments.positional {
                    let Some(value) = value_string(value) else {
                        return Value::Unknown;
                    };
                    let Some(value) = join_path(joined, value, &mut self.budget) else {
                        return Value::Unknown;
                    };
                    joined = value;
                }
                Value::Path(joined)
            }
            "expanduser" if !state.invalid_modules.contains(&Module::Environment) => {
                expand_home(&path, self.input.home, &mut self.budget)
                    .map_or(Value::Unknown, Value::Path)
            }
            "expanduser" => Value::Unknown,
            "resolve" | "absolute" => Value::Unknown,
            "read_text" | "read_bytes" => {
                let valid = if method == "read_text" {
                    valid_call_shape(&arguments, 3, &["encoding", "errors", "newline"])
                } else {
                    valid_call_shape(&arguments, 0, &[])
                };
                if !valid {
                    return Value::Unknown;
                }
                self.emit_filesystem_call(
                    &format!("pathlib.path.{method}"),
                    &arguments,
                    state,
                    vec![LanguageFilesystem::new(
                        Some(path),
                        FilesystemOperation::Read,
                        false,
                    )],
                )
                .map_or(Value::Unknown, |origin| Value::Produced(vec![origin]))
            }
            "write_text" | "write_bytes" | "touch" | "mkdir" | "chmod" | "lchmod" => {
                let valid = match method {
                    "write_text" => {
                        valid_call_shape(&arguments, 4, &["data", "encoding", "errors", "newline"])
                            && required_argument(&arguments, 0, "data").is_some()
                    }
                    "write_bytes" => {
                        valid_call_shape(&arguments, 1, &["data"])
                            && required_argument(&arguments, 0, "data").is_some()
                    }
                    "touch" => valid_call_shape(&arguments, 2, &["mode", "exist_ok"]),
                    "mkdir" => valid_call_shape(&arguments, 3, &["mode", "parents", "exist_ok"]),
                    "chmod" => {
                        valid_call_shape(&arguments, 1, &["mode", "follow_symlinks"])
                            && required_argument(&arguments, 0, "mode").is_some()
                    }
                    "lchmod" => {
                        valid_call_shape(&arguments, 1, &["mode"])
                            && required_argument(&arguments, 0, "mode").is_some()
                    }
                    _ => unreachable!(),
                };
                if !valid {
                    return Value::Unknown;
                }
                self.emit_filesystem_call(
                    &format!("pathlib.path.{method}"),
                    &arguments,
                    state,
                    vec![
                        LanguageFilesystem::new(
                            Some(path),
                            FilesystemOperation::Write,
                            method == "mkdir"
                                && argument(&arguments, 1, "parents")
                                    .and_then(exact_bool)
                                    .unwrap_or(false),
                        )
                        .metadata_if(matches!(method, "touch" | "mkdir" | "chmod" | "lchmod"))
                        .protects_descendants_if(matches!(method, "chmod" | "lchmod")),
                    ],
                );
                Value::None
            }
            "unlink" | "rmdir" => {
                let valid = if method == "unlink" {
                    valid_call_shape(&arguments, 1, &["missing_ok"])
                } else {
                    valid_call_shape(&arguments, 0, &[])
                };
                if !valid {
                    return Value::Unknown;
                }
                self.emit_filesystem_call(
                    &format!("pathlib.path.{method}"),
                    &arguments,
                    state,
                    vec![LanguageFilesystem::new(
                        Some(path),
                        FilesystemOperation::Delete,
                        false,
                    )],
                );
                Value::None
            }
            "rename" | "replace" => {
                if !valid_call_shape(&arguments, 1, &["target"])
                    || required_argument(&arguments, 0, "target").is_none()
                    || !possible_path_argument(&arguments, 0, "target")
                {
                    return Value::Unknown;
                }
                let target = argument(&arguments, 0, "target")
                    .and_then(value_string)
                    .map(str::to_owned);
                self.emit_filesystem_call(
                    &format!("pathlib.path.{method}"),
                    &arguments,
                    state,
                    vec![
                        LanguageFilesystem::new(
                            Some(path.clone()),
                            FilesystemOperation::Delete,
                            false,
                        ),
                        LanguageFilesystem::new(target.clone(), FilesystemOperation::Write, false)
                            .identity(Some(path), false)
                            .protects_descendants(),
                    ],
                );
                target.map_or(Value::Unknown, Value::Path)
            }
            "hardlink_to" | "link_to" => {
                if !valid_call_shape(&arguments, 1, &["target"])
                    || required_argument(&arguments, 0, "target").is_none()
                    || !possible_path_argument(&arguments, 0, "target")
                {
                    return Value::Unknown;
                }
                let target = argument(&arguments, 0, "target")
                    .and_then(value_string)
                    .map(str::to_owned);
                let (destination, identity) = if method == "hardlink_to" {
                    (Some(path), target)
                } else {
                    (target, Some(path))
                };
                self.emit_filesystem_call(
                    &format!("pathlib.path.{method}"),
                    &arguments,
                    state,
                    vec![
                        LanguageFilesystem::new(destination, FilesystemOperation::Write, false)
                            .identity(identity, true),
                    ],
                );
                Value::None
            }
            "symlink_to" => {
                if !valid_call_shape(&arguments, 2, &["target", "target_is_directory"])
                    || required_argument(&arguments, 0, "target").is_none()
                {
                    return Value::Unknown;
                }
                self.emit_filesystem_call(
                    "pathlib.path.symlink_to",
                    &arguments,
                    state,
                    vec![
                        LanguageFilesystem::new(Some(path), FilesystemOperation::Write, false)
                            .metadata(),
                    ],
                );
                Value::None
            }
            _ => Value::Unknown,
        }
    }

    fn call_cell_method(
        &mut self,
        cell: usize,
        method: &str,
        arguments: Arguments,
        state: &mut State,
    ) -> Value {
        if method == "append"
            && arguments.complete
            && arguments.keywords.is_empty()
            && arguments.positional.len() == 1
            && let Some(value) = state.cells.get_mut(cell)
        {
            match value {
                Cell::Sequence(values) => {
                    let bytes = values_bytes(values).and_then(|bytes| {
                        value_bytes(&arguments.positional[0])
                            .and_then(|added| bytes.checked_add(added))
                    });
                    if values.len() < MAX_COLLECTION_ITEMS && self.budget.admit_value_bytes(bytes) {
                        values.push(arguments.positional[0].clone());
                    } else {
                        *value = Cell::Unknown;
                        self.budget.refuse_work();
                    }
                }
                Cell::Unknown => {}
            }
            return Value::None;
        }
        if method == "extend"
            && arguments.complete
            && arguments.keywords.is_empty()
            && arguments.positional.len() == 1
        {
            let extension = sequence_values(&arguments.positional[0], state).map(Vec::from);
            if let Some(value) = state.cells.get_mut(cell) {
                match extension {
                    Some(extension) => match value {
                        Cell::Sequence(values) => {
                            let items = values.len().checked_add(extension.len());
                            let bytes = values_bytes(values).and_then(|bytes| {
                                values_bytes(&extension).and_then(|added| bytes.checked_add(added))
                            });
                            if items.is_some_and(|items| items <= MAX_COLLECTION_ITEMS)
                                && self.budget.admit_value_bytes(bytes)
                            {
                                values.extend(extension);
                            } else {
                                *value = Cell::Unknown;
                                self.budget.refuse_work();
                            }
                        }
                        Cell::Unknown => {}
                    },
                    None => {
                        if matches!(value, Cell::Sequence(_)) {
                            *value = Cell::Unknown;
                        }
                    }
                }
                return Value::None;
            }
        }
        if let Some(value) = state.cells.get_mut(cell) {
            *value = Cell::Unknown;
        }
        self.complete = false;
        Value::Unknown
    }

    fn call_string_method(&mut self, value: String, method: &str, arguments: Arguments) -> Value {
        match method {
            "encode" if arguments.positional.is_empty() => Value::Bytes(value.into_bytes()),
            "format" => {
                let mut formatted = value;
                for argument in arguments.positional {
                    let Some(display) = display_value(&argument) else {
                        return Value::Unknown;
                    };
                    if !formatted.contains("{}") {
                        continue;
                    }
                    if !self.budget.admit_value_bytes(
                        formatted
                            .len()
                            .checked_sub(2)
                            .and_then(|bytes| bytes.checked_add(display.len())),
                    ) {
                        return Value::Unknown;
                    }
                    formatted = formatted.replacen("{}", &display, 1);
                }
                Value::String(formatted)
            }
            _ => Value::Unknown,
        }
    }

    fn call_bytes_method(&mut self, value: Vec<u8>, method: &str, arguments: Arguments) -> Value {
        if method == "decode" && arguments.positional.len() <= 1 {
            String::from_utf8(value).map_or(Value::Unknown, Value::String)
        } else {
            Value::Unknown
        }
    }

    fn subprocess(&mut self, kind: SubprocessKind, arguments: &Arguments, state: &State) {
        let Some(command) = argument(arguments, 0, "args") else {
            return;
        };
        let Some((shell, stdout_inherited)) = subprocess_options(kind, arguments) else {
            return;
        };
        if shell && decoded(command) {
            self.report
                .push(Finding::exact(FindingKind::DecodedExecution));
        }
        if shell {
            let code = value_string(command).or_else(|| {
                sequence_values(command, state)
                    .and_then(|values| values.first())
                    .and_then(value_string)
            });
            if let Some(code) = code
                && self.input.platform != Platform::Windows
            {
                self.push_shell(code, stdout_inherited);
            }
        } else if let Some(argv) = argv_value(command, state, &mut self.budget) {
            self.push_command(argv, stdout_inherited);
        }
    }

    fn os_exec(&mut self, kind: StringKind, arguments: &Arguments, state: &State) {
        let argv = match kind {
            StringKind::Execl | StringKind::Execlp
                if arguments.keywords.is_empty()
                    && arguments.positional.len() >= 2
                    && arguments
                        .positional
                        .iter()
                        .all(|value| value_string(value).is_some()) =>
            {
                let values = std::iter::once(value_string(&arguments.positional[0]))
                    .chain(arguments.positional[2..].iter().map(value_string));
                let Some(argv) = bounded_strings(values, &mut self.budget) else {
                    return;
                };
                argv
            }
            StringKind::Execv | StringKind::Execvp
                if arguments.keywords.is_empty() && arguments.positional.len() == 2 =>
            {
                let Some(program) = value_string(&arguments.positional[0]) else {
                    return;
                };
                let Some(argv) = argv_value(&arguments.positional[1], state, &mut self.budget)
                else {
                    return;
                };
                if argv.is_empty() {
                    return;
                }
                std::iter::once(program.to_owned())
                    .chain(argv.into_iter().skip(1))
                    .collect()
            }
            _ => return,
        };
        self.push_command(argv, true);
    }

    fn push_shell(&mut self, code: &str, stdout_inherited: bool) {
        if !self.budget.admit_value_bytes(Some(code.len())) {
            return;
        }
        self.report.push_nested_execution(NestedExecution::Shell {
            program: "sh".into(),
            code: code.to_owned(),
            stdout_inherited,
        });
    }

    fn push_command(&mut self, argv: Vec<String>, stdout_inherited: bool) {
        let bytes = argv
            .iter()
            .try_fold(0usize, |bytes, value| bytes.checked_add(value.len()));
        if argv.len() > MAX_COLLECTION_ITEMS || !self.budget.admit_value_bytes(bytes) {
            self.budget.refuse_work();
            return;
        }
        self.report.push_nested_execution(NestedExecution::Command {
            argv,
            stdout_inherited,
        });
    }

    fn dynamic_execution(
        &mut self,
        value: Value,
        string_mode: CodeMode,
        state: &mut State,
        depth: usize,
    ) {
        let (source, mode) = match value {
            Value::String(source) => (source, string_mode),
            Value::Compiled { source, mode } => (source, mode),
            _ => return,
        };
        if source.len() > crate::SOURCE_LIMIT {
            self.report.refuse(InlineRefusal::SourceLimit);
            return;
        }
        if !self.budget.enter_dynamic_source(source.len()) {
            return;
        }
        if depth >= MAX_CALL_DEPTH {
            self.budget.refusal = Some(InlineRefusal::RecursionLimit);
            return;
        }
        let module = match super::parser::lower(&source, self.program) {
            Ok(module) if !module.opaque() => module,
            Ok(_) => {
                self.complete = false;
                return;
            }
            Err(refusal) => {
                self.report.refuse(refusal);
                return;
            }
        };
        let mut statements = named_children(module.root());
        let first = statements.next();
        if matches!(mode, CodeMode::Eval | CodeMode::Single) && statements.next().is_some() {
            self.complete = false;
            return;
        }
        if mode == CodeMode::Single && first.is_none() {
            self.complete = false;
            return;
        }
        let expression = if mode == CodeMode::Eval {
            let Some(statement) = first.filter(|node| node.kind() == HirKind::ExpressionStatement)
            else {
                self.complete = false;
                return;
            };
            let mut expressions = named_children(statement);
            let expression = expressions.next();
            if expression.is_none() || expressions.next().is_some() {
                self.complete = false;
                return;
            }
            expression
        } else {
            None
        };
        let outer = std::mem::replace(&mut self.source, Arc::from(source));
        if let Some(expression) = expression {
            self.eval(expression, state, depth + 1);
        } else if mode != CodeMode::Single || first.is_some() {
            let _ = self.exec_block(module.root(), state, depth + 1);
        }
        self.source = outer;
    }

    fn binary(&mut self, node: &HirNode, state: &mut State, depth: usize) -> Value {
        let left = node
            .child(HirField::Left)
            .map_or(Value::Unknown, |left| self.eval(left, state, depth));
        let right = node
            .child(HirField::Right)
            .map_or(Value::Unknown, |right| self.eval(right, state, depth));
        let operator = node
            .child(HirField::Operator)
            .map(|operator| self.text(operator))
            .unwrap_or_default()
            .to_owned();
        binary_value(left, right, &operator, &mut self.budget)
    }

    fn boolean(&mut self, node: &HirNode, state: &mut State, depth: usize) -> Value {
        let Some(left_node) = node.child(HirField::Left) else {
            return Value::Unknown;
        };
        let left = self.eval(left_node, state, depth);
        let operator = node
            .child(HirField::Operator)
            .map(|operator| self.text(operator))
            .unwrap_or_default();
        match (operator, truthy(&left, state)) {
            ("and", Some(false)) | ("or", Some(true)) => left,
            ("and", Some(true)) | ("or", Some(false)) => node
                .child(HirField::Right)
                .map_or(Value::Unknown, |right| self.eval(right, state, depth)),
            ("and" | "or", None) => {
                self.complete = false;
                let dominators = self.execution_dominators.clone();
                for ordinal in producer_ordinals(&left) {
                    if !self.execution_dominators.contains(&ordinal) {
                        self.execution_dominators.push(ordinal);
                    }
                }
                self.conditional_depth += 1;
                let right = node
                    .child(HirField::Right)
                    .map_or(Value::Unknown, |right| self.eval(right, state, depth));
                self.conditional_depth -= 1;
                self.execution_dominators = dominators;
                join_values(left, right)
            }
            _ => {
                self.complete = false;
                Value::Unknown
            }
        }
    }

    fn comparison(&mut self, node: &HirNode, state: &mut State, depth: usize) -> Value {
        let mut left = None;
        let mut operator = None;
        let mut compared = false;
        let mut unknown = false;
        for child in node.children() {
            if child.field() == Some(HirField::Operators) {
                operator = Some(self.text(child).to_owned());
                continue;
            }
            if matches!(child.kind(), HirKind::Token | HirKind::Comment) {
                continue;
            }
            let conditional = unknown && left.is_some();
            let dominators = self.execution_dominators.clone();
            if conditional {
                self.complete = false;
                self.conditional_depth += 1;
            }
            let right = self.eval(child, state, depth);
            if conditional {
                self.conditional_depth -= 1;
                self.execution_dominators = dominators;
            }
            let Some(previous) = left.replace(right.clone()) else {
                continue;
            };
            let Some(operator) = operator.take() else {
                self.complete = false;
                return Value::Unknown;
            };
            compared = true;
            match compare_values(&previous, &right, &operator) {
                Some(false) => return Value::Bool(false),
                Some(true) => {}
                None => unknown = true,
            }
        }
        if !compared || operator.is_some() {
            self.complete = false;
            Value::Unknown
        } else if unknown {
            Value::Unknown
        } else {
            Value::Bool(true)
        }
    }

    fn unary(&mut self, node: &HirNode, state: &mut State, depth: usize) -> Value {
        let value = named_children(node)
            .find(|child| child.field() != Some(HirField::Operator))
            .map_or(Value::Unknown, |value| self.eval(value, state, depth));
        let operator = node
            .child(HirField::Operator)
            .map(|operator| self.text(operator))
            .unwrap_or_default();
        match (operator, value) {
            ("-", Value::Int(value)) => value.checked_neg().map_or(Value::Unknown, Value::Int),
            ("+", Value::Int(value)) => Value::Int(value),
            _ => Value::Unknown,
        }
    }

    fn conditional_expression(&mut self, node: &HirNode, state: &mut State, depth: usize) -> Value {
        let children = named_children(node).collect::<Vec<_>>();
        if children.len() != 3 {
            self.eval_children(node, state, depth);
            return Value::Unknown;
        }
        let condition = self.eval(children[1], state, depth);
        match truthy(&condition, state) {
            Some(true) => self.eval(children[0], state, depth),
            Some(false) => self.eval(children[2], state, depth),
            None => {
                self.complete = false;
                let dominators = self.execution_dominators.clone();
                self.conditional_depth += 1;
                let yes = self.eval(children[0], state, depth);
                self.execution_dominators.clone_from(&dominators);
                let no = self.eval(children[2], state, depth);
                self.conditional_depth -= 1;
                self.execution_dominators = dominators;
                join_values(yes, no)
            }
        }
    }

    fn subscript(&mut self, node: &HirNode, state: &mut State, depth: usize) -> Value {
        let children = named_children(node).collect::<Vec<_>>();
        if children.len() < 2 {
            return Value::Unknown;
        }
        let object = self.eval(children[0], state, depth);
        let index = self.eval(children[1], state, depth);
        if object == Value::Module(Module::Environment)
            && !state.invalid_modules.contains(&Module::Environment)
            && value_string(&index).is_some_and(|value| value == "HOME")
        {
            Value::String(self.input.home.to_owned())
        } else {
            Value::Unknown
        }
    }

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

fn module_value(name: &str) -> Option<Value> {
    let module = match name {
        "base64" => Module::Base64,
        "builtins" | "__builtin__" => Module::Builtins,
        "io" => Module::Io,
        "os" => Module::Os,
        "os.path" => Module::OsPath,
        "pathlib" => Module::Pathlib,
        "requests" => Module::Requests,
        "httpx" => Module::Httpx,
        "shutil" => Module::Shutil,
        "subprocess" => Module::Subprocess,
        "urllib" => Module::Urllib,
        "urllib.request" => Module::UrllibRequest,
        _ => return None,
    };
    Some(Value::Module(module))
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
    ["O_APPEND", "O_CREAT", "O_TRUNC"]
        .into_iter()
        .filter_map(|name| os_open_flag(name, platform))
        .fold(0, |flags, flag| flags | flag)
}

fn imported_value(module: &str, name: &str) -> Option<Value> {
    let module = module_value(module)?;
    let Value::Module(module) = module else {
        return None;
    };
    module_attribute(module, name)
}

fn module_attribute(module: Module, attribute: &str) -> Option<Value> {
    let function = match (module, attribute) {
        (Module::Base64, "b64decode" | "urlsafe_b64decode") => KnownFunction::Base64Decode,
        (Module::Builtins, "eval") => KnownFunction::Eval,
        (Module::Builtins, "exec") => KnownFunction::Exec,
        (Module::Builtins, "compile") => KnownFunction::Compile,
        (Module::Builtins, "open") => KnownFunction::Open,
        (Module::Builtins, "getattr") => KnownFunction::Getattr,
        (Module::Io, "FileIO") => KnownFunction::IoFile,
        (Module::Urllib, "request") => return Some(Value::Module(Module::UrllibRequest)),
        (Module::Os, "path") => return Some(Value::Module(Module::OsPath)),
        (Module::Os, "environ") => return Some(Value::Module(Module::Environment)),
        (Module::Os, "system") => KnownFunction::OsSystem,
        (Module::Os, "popen") => KnownFunction::OsPopen,
        (Module::Os, "execl") => KnownFunction::OsExec(StringKind::Execl),
        (Module::Os, "execlp") => KnownFunction::OsExec(StringKind::Execlp),
        (Module::Os, "execle") => KnownFunction::OsExec(StringKind::Execle),
        (Module::Os, "execv") => KnownFunction::OsExec(StringKind::Execv),
        (Module::Os, "execvp") => KnownFunction::OsExec(StringKind::Execvp),
        (Module::Os, "execvpe") => KnownFunction::OsExec(StringKind::Execvpe),
        (Module::Os, "remove") => KnownFunction::OsRemove,
        (Module::Os, "unlink") => KnownFunction::OsUnlink,
        (Module::Os, "rename") => KnownFunction::OsRename,
        (Module::Os, "replace") => KnownFunction::OsReplace,
        (Module::Os, "link") => KnownFunction::OsLink,
        (Module::Os, "symlink") => KnownFunction::OsSymlink,
        (Module::Os, "chmod") => KnownFunction::OsChmod,
        (Module::Os, "chown" | "lchown") => KnownFunction::OsChown,
        (Module::Os, "mkdir") => KnownFunction::OsMkdir,
        (Module::Os, "makedirs") => KnownFunction::OsMakedirs,
        (Module::Os, "rmdir") => KnownFunction::OsRmdir,
        (Module::Os, "removedirs") => KnownFunction::OsRemovedirs,
        (Module::Os, "truncate") => KnownFunction::OsTruncate,
        (Module::Os, "open") => KnownFunction::OsOpen,
        (Module::Os, "getenv") => KnownFunction::OsGetenv,
        (Module::OsPath, "expanduser") => KnownFunction::OsExpanduser,
        (Module::OsPath, "abspath") => KnownFunction::OsAbspath,
        (Module::OsPath, "realpath") => KnownFunction::OsRealpath,
        (Module::OsPath, "join") => KnownFunction::PathJoin,
        (Module::Pathlib, "Path") => KnownFunction::Path,
        (Module::Shutil, "rmtree") => KnownFunction::ShutilRmtree,
        (Module::Shutil, "move") => KnownFunction::ShutilMove,
        (Module::Shutil, "copy") => KnownFunction::ShutilCopy(CopyKind::Copy),
        (Module::Shutil, "copy2") => KnownFunction::ShutilCopy(CopyKind::Copy2),
        (Module::Shutil, "copyfile") => KnownFunction::ShutilCopy(CopyKind::Copyfile),
        (Module::Shutil, "copytree") => KnownFunction::ShutilCopy(CopyKind::Copytree),
        (Module::Shutil, "copymode") => KnownFunction::ShutilCopy(CopyKind::Copymode),
        (Module::Shutil, "copystat") => KnownFunction::ShutilCopy(CopyKind::Copystat),
        (Module::Shutil, "which") => KnownFunction::ShutilWhich,
        (Module::Subprocess, "run") => KnownFunction::Subprocess(SubprocessKind::Run),
        (Module::Subprocess, "call") => KnownFunction::Subprocess(SubprocessKind::Call),
        (Module::Subprocess, "Popen") => KnownFunction::Subprocess(SubprocessKind::Popen),
        (Module::Subprocess, "check_call") => KnownFunction::Subprocess(SubprocessKind::CheckCall),
        (Module::Subprocess, "check_output") => {
            KnownFunction::Subprocess(SubprocessKind::CheckOutput)
        }
        (Module::Requests, "get") => KnownFunction::Request(RequestKind::RequestsGet),
        (Module::Requests, "post") => KnownFunction::Request(RequestKind::RequestsPost),
        (Module::Requests, "put") => KnownFunction::Request(RequestKind::RequestsPut),
        (Module::Requests, "patch") => KnownFunction::Request(RequestKind::RequestsPatch),
        (Module::Requests, "delete") => KnownFunction::Request(RequestKind::RequestsDelete),
        (Module::Httpx, "get") => KnownFunction::Request(RequestKind::HttpxGet),
        (Module::Httpx, "post") => KnownFunction::Request(RequestKind::HttpxPost),
        (Module::Httpx, "put") => KnownFunction::Request(RequestKind::HttpxPut),
        (Module::Httpx, "patch") => KnownFunction::Request(RequestKind::HttpxPatch),
        (Module::Httpx, "delete") => KnownFunction::Request(RequestKind::HttpxDelete),
        (Module::UrllibRequest, "urlopen") => KnownFunction::Request(RequestKind::UrlOpen),
        (Module::UrllibRequest, "urlretrieve") => KnownFunction::Request(RequestKind::UrlRetrieve),
        _ => return None,
    };
    Some(Value::Known(function))
}

fn filesystem_argument(
    arguments: &Arguments,
    position: usize,
    keyword: &str,
    operation: FilesystemOperation,
    recursive: bool,
) -> LanguageFilesystem {
    LanguageFilesystem::new(
        argument(arguments, position, keyword)
            .and_then(value_string)
            .map(str::to_owned),
        operation,
        recursive,
    )
}

fn os_exec_callable(kind: StringKind) -> &'static str {
    match kind {
        StringKind::Execl => "os.execl",
        StringKind::Execlp => "os.execlp",
        StringKind::Execle => "os.execle",
        StringKind::Execv => "os.execv",
        StringKind::Execvp => "os.execvp",
        StringKind::Execvpe => "os.execvpe",
    }
}

fn subprocess_callable(kind: SubprocessKind) -> &'static str {
    match kind {
        SubprocessKind::Run => "subprocess.run",
        SubprocessKind::Call => "subprocess.call",
        SubprocessKind::Popen => "subprocess.popen",
        SubprocessKind::CheckCall => "subprocess.check_call",
        SubprocessKind::CheckOutput => "subprocess.check_output",
    }
}

fn request_callable(kind: RequestKind) -> &'static str {
    match kind {
        RequestKind::RequestsGet => "requests.get",
        RequestKind::RequestsPost => "requests.post",
        RequestKind::RequestsPut => "requests.put",
        RequestKind::RequestsPatch => "requests.patch",
        RequestKind::RequestsDelete => "requests.delete",
        RequestKind::HttpxGet => "httpx.get",
        RequestKind::HttpxPost => "httpx.post",
        RequestKind::HttpxPut => "httpx.put",
        RequestKind::HttpxPatch => "httpx.patch",
        RequestKind::HttpxDelete => "httpx.delete",
        RequestKind::UrlOpen => "urllib.request.urlopen",
        RequestKind::UrlRetrieve => "urllib.request.urlretrieve",
    }
}

fn request_url_keyword(kind: RequestKind) -> &'static str {
    match kind {
        RequestKind::RequestsGet
        | RequestKind::RequestsPost
        | RequestKind::RequestsPut
        | RequestKind::RequestsPatch
        | RequestKind::RequestsDelete
        | RequestKind::HttpxGet
        | RequestKind::HttpxPost
        | RequestKind::HttpxPut
        | RequestKind::HttpxPatch
        | RequestKind::HttpxDelete => "url",
        RequestKind::UrlOpen | RequestKind::UrlRetrieve => "url",
    }
}

fn shutil_copy_callable(kind: CopyKind) -> &'static str {
    match kind {
        CopyKind::Copy => "shutil.copy",
        CopyKind::Copy2 => "shutil.copy2",
        CopyKind::Copyfile => "shutil.copyfile",
        CopyKind::Copytree => "shutil.copytree",
        CopyKind::Copymode => "shutil.copymode",
        CopyKind::Copystat => "shutil.copystat",
    }
}

fn open_operations(arguments: &Arguments) -> Option<Vec<FilesystemOperation>> {
    if !arguments.complete {
        return None;
    }
    let mode = arguments.positional.get(1).or_else(|| {
        arguments
            .keywords
            .iter()
            .find(|(name, _)| name == "mode")
            .map(|(_, value)| value)
    });
    let mode = match mode {
        Some(mode) => value_string(mode)?,
        None => "r",
    };
    let access = mode
        .bytes()
        .filter(|byte| matches!(byte, b'r' | b'w' | b'a' | b'x'))
        .collect::<Vec<_>>();
    let valid = access.len() == 1
        && mode
            .bytes()
            .all(|byte| matches!(byte, b'r' | b'w' | b'a' | b'x' | b'b' | b't' | b'+'))
        && mode.matches('+').count() <= 1
        && mode.matches('b').count() <= 1
        && mode.matches('t').count() <= 1
        && !(mode.contains('b') && mode.contains('t'));
    if !valid {
        return Some(Vec::new());
    }
    let mut operations = Vec::new();
    if access[0] == b'r' || mode.contains('+') {
        operations.push(FilesystemOperation::Read);
    }
    if access[0] != b'r' || mode.contains('+') {
        operations.push(FilesystemOperation::Write);
    }
    Some(operations)
}

fn language_call_input(callable: &str, arguments: &Arguments, state: &State) -> InvocationInput {
    let mut complete = arguments.complete;
    let mut positional = Vec::new();
    let mut keywords = Vec::new();
    let represented = arguments.positional.len() + arguments.keywords.len();
    let limit = represented.min(MAX_NATIVE_ARGUMENTS);
    let positional_limit = arguments.positional.len().min(limit);
    for value in arguments.positional.iter().take(positional_limit) {
        let (value, exact) = native_value(value, state, &mut BTreeSet::new());
        complete &= exact;
        positional.push(value);
    }
    for (name, value) in arguments
        .keywords
        .iter()
        .take(limit.saturating_sub(positional_limit))
    {
        let (value, exact) = native_value(value, state, &mut BTreeSet::new());
        complete &= exact;
        let mut keyword = Map::new();
        keyword.insert("name".into(), JsonValue::String(name.clone()));
        keyword.insert("value".into(), value);
        keywords.push(JsonValue::Object(keyword));
    }
    if represented > MAX_NATIVE_ARGUMENTS {
        complete = false;
        if let Some(value) = keywords.last_mut() {
            if let Some(value) = value.get_mut("value") {
                *value = native_unknown();
            }
        } else if let Some(value) = positional.last_mut() {
            *value = native_unknown();
        }
    }
    let mut payload = language_call_payload(callable, positional, keywords);
    if serde_json::to_vec(&payload).map_or(true, |bytes| bytes.len() > MAX_NATIVE_EVIDENCE_BYTES) {
        complete = false;
        payload = language_call_payload(callable, vec![native_unknown()], Vec::new());
    }
    InvocationInput::native(payload, complete)
}

fn language_call_payload(
    callable: &str,
    positional: Vec<JsonValue>,
    keywords: Vec<JsonValue>,
) -> JsonValue {
    let mut payload = Map::new();
    payload.insert("v".into(), JsonValue::from(1));
    payload.insert("language".into(), JsonValue::String("python".into()));
    payload.insert("callable".into(), JsonValue::String(callable.into()));
    payload.insert("positional".into(), JsonValue::Array(positional));
    payload.insert("keywords".into(), JsonValue::Array(keywords));
    JsonValue::Object(payload)
}

fn native_value(value: &Value, state: &State, visiting: &mut BTreeSet<usize>) -> (JsonValue, bool) {
    match value {
        Value::None => (native_tag("null", None), true),
        Value::Bool(value) => (native_tag("bool", Some(JsonValue::Bool(*value))), true),
        Value::Int(value) => (native_tag("int", Some(JsonValue::from(*value))), true),
        Value::String(value) | Value::ImplicitString(value) => {
            bounded_native_string("string", value)
        }
        Value::Bytes(value) => {
            if value.len() > MAX_NATIVE_EVIDENCE_BYTES {
                return (native_unknown(), false);
            }
            (
                native_tag("bytes", Some(JsonValue::String(lower_hex(value)))),
                true,
            )
        }
        Value::Path(value) => bounded_native_string("path", value),
        Value::Cell(cell) => {
            let Some(Cell::Sequence(values)) = state.cells.get(*cell) else {
                return (native_unknown(), false);
            };
            if values.len() > MAX_NATIVE_COLLECTION_ITEMS || !visiting.insert(*cell) {
                return (native_unknown(), false);
            }
            let mut exact = true;
            let items = values
                .iter()
                .map(|value| {
                    let (value, item_exact) = native_value(value, state, visiting);
                    exact &= item_exact;
                    value
                })
                .collect();
            visiting.remove(cell);
            (native_sequence(items), exact)
        }
        Value::Decoded(value) => native_value(value, state, visiting),
        Value::Unknown
        | Value::EmptyDictionary
        | Value::Module(_)
        | Value::Known(_)
        | Value::LocalFunction(_)
        | Value::PathMethod { .. }
        | Value::CellMethod { .. }
        | Value::StringMethod { .. }
        | Value::BytesMethod { .. }
        | Value::DecodedMethod { .. }
        | Value::ModuleMethod(_)
        | Value::Compiled { .. }
        | Value::Produced(_) => (native_unknown(), false),
    }
}

fn bounded_native_string(kind: &str, value: &str) -> (JsonValue, bool) {
    if value.len() > MAX_NATIVE_EVIDENCE_BYTES {
        (native_unknown(), false)
    } else {
        (
            native_tag(kind, Some(JsonValue::String(value.to_owned()))),
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

fn native_tag(kind: &str, value: Option<JsonValue>) -> JsonValue {
    let mut tagged = Map::new();
    tagged.insert("kind".into(), JsonValue::String(kind.into()));
    if let Some(value) = value {
        tagged.insert("value".into(), value);
    }
    JsonValue::Object(tagged)
}

fn lower_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(DIGITS[usize::from(byte >> 4)] as char);
        encoded.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    encoded
}

fn argument_origins(arguments: &Arguments, state: &State) -> BTreeSet<usize> {
    let mut origins = BTreeSet::new();
    for value in arguments
        .positional
        .iter()
        .chain(arguments.keywords.iter().map(|(_, value)| value))
    {
        value_origins(value, state, &mut BTreeSet::new(), &mut origins);
    }
    origins
}

fn value_origins(
    value: &Value,
    state: &State,
    visiting: &mut BTreeSet<usize>,
    origins: &mut BTreeSet<usize>,
) {
    match value {
        Value::Produced(values) => origins.extend(values),
        Value::Decoded(value) => value_origins(value, state, visiting, origins),
        Value::Cell(cell) if visiting.insert(*cell) => {
            if let Some(Cell::Sequence(values)) = state.cells.get(*cell) {
                for value in values {
                    value_origins(value, state, visiting, origins);
                }
            }
            visiting.remove(cell);
        }
        _ => {}
    }
}

fn import_name(node: &HirNode, source: &str) -> (String, Option<String>) {
    if node.kind() == HirKind::AliasedImport {
        let name = node
            .child(HirField::Name)
            .map(|name| unsafe_text(source, name).to_owned())
            .unwrap_or_default();
        let alias = node
            .child(HirField::Alias)
            .map(|alias| unsafe_text(source, alias).to_owned());
        (name, alias)
    } else {
        (unsafe_text(source, node).to_owned(), None)
    }
}

fn sequence_values<'a>(value: &'a Value, state: &'a State) -> Option<&'a [Value]> {
    let Value::Cell(cell) = value else {
        return None;
    };
    match state.cells.get(*cell) {
        Some(Cell::Sequence(values)) => Some(values),
        Some(Cell::Unknown) | None => None,
    }
}

fn value_bytes(value: &Value) -> Option<usize> {
    match value {
        Value::String(value) | Value::ImplicitString(value) | Value::Path(value) => {
            Some(value.len())
        }
        Value::Compiled { source, .. } => Some(source.len()),
        Value::Bytes(value) => Some(value.len()),
        Value::PathMethod { path, method } => path.len().checked_add(method.len()),
        Value::CellMethod { method, .. } => Some(method.len()),
        Value::StringMethod { value, method } => value.len().checked_add(method.len()),
        Value::BytesMethod { value, method } => value.len().checked_add(method.len()),
        Value::Decoded(value) => value_bytes(value),
        Value::DecodedMethod { value, method } => {
            value_bytes(value).and_then(|bytes| bytes.checked_add(method.len()))
        }
        Value::Unknown
        | Value::None
        | Value::Bool(_)
        | Value::Int(_)
        | Value::EmptyDictionary
        | Value::Cell(_)
        | Value::Module(_)
        | Value::ModuleMethod(_)
        | Value::Known(_)
        | Value::LocalFunction(_)
        | Value::Produced(_) => Some(0),
    }
}

fn values_bytes(values: &[Value]) -> Option<usize> {
    values.iter().try_fold(0usize, |bytes, value| {
        value_bytes(value).and_then(|value| bytes.checked_add(value))
    })
}

fn bind_arguments(parameters: &[Parameter], arguments: &Arguments) -> Option<Vec<(String, Value)>> {
    if !arguments.complete || arguments.positional.len() > parameters.len() {
        return None;
    }
    let mut values = vec![None; parameters.len()];
    for (index, value) in arguments.positional.iter().enumerate() {
        values[index] = Some(value.clone());
    }
    let positions = parameters
        .iter()
        .enumerate()
        .map(|(index, parameter)| (parameter.name.as_str(), index))
        .collect::<BTreeMap<_, _>>();
    let mut keywords = BTreeSet::new();
    for (name, value) in &arguments.keywords {
        if !keywords.insert(name.as_str()) {
            return None;
        }
        let index = *positions.get(name.as_str())?;
        if values[index].is_some() {
            return None;
        }
        values[index] = Some(value.clone());
    }
    parameters
        .iter()
        .zip(values)
        .map(|(parameter, value)| {
            value
                .or_else(|| parameter.default.clone())
                .map(|value| (parameter.name.clone(), value))
        })
        .collect()
}

fn invalidate_argument_cells(arguments: &Arguments, state: &mut State) {
    for cell in arguments
        .positional
        .iter()
        .chain(arguments.keywords.iter().map(|(_, value)| value))
        .filter_map(|value| match value {
            Value::Cell(cell) => Some(*cell),
            _ => None,
        })
        .collect::<BTreeSet<_>>()
    {
        if let Some(value) = state.cells.get_mut(cell) {
            *value = Cell::Unknown;
        }
    }
    let modules = arguments
        .positional
        .iter()
        .chain(arguments.keywords.iter().map(|(_, value)| value))
        .filter_map(|value| match value {
            Value::Module(module) => Some(*module),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    for module in modules {
        invalidate_module(module, state);
    }
}

fn retain_owned_module(value: Value, state: &State) -> Value {
    match value {
        Value::Module(module) if state.invalid_modules.contains(&module) => Value::Unknown,
        value => value,
    }
}

fn invalidate_module(module: Module, state: &mut State) {
    state.invalid_modules.insert(module);
    for value in state.bindings.values_mut() {
        if *value == Value::Module(module) {
            *value = Value::Unknown;
        }
    }
    for cell in &mut state.cells {
        if let Cell::Sequence(values) = cell {
            for value in values {
                if *value == Value::Module(module) {
                    *value = Value::Unknown;
                }
            }
        }
    }
}

fn owned_module_target(node: &HirNode, state: &State, source: &str) -> Option<Module> {
    match node.kind() {
        HirKind::Identifier => match state.bindings.get(unsafe_text(source, node)) {
            Some(Value::Module(module)) => Some(*module),
            _ => None,
        },
        HirKind::Attribute => {
            let object = owned_module_target(node.child(HirField::Object)?, state, source)?;
            let attribute = unsafe_text(source, node.child(HirField::Attribute)?);
            match module_attribute(object, attribute) {
                Some(Value::Module(module)) => Some(module),
                _ => Some(object),
            }
        }
        _ => None,
    }
}

fn propagate_invalid_modules(modules: &BTreeSet<Module>, state: &mut State) {
    let modules = modules
        .difference(&state.invalid_modules)
        .copied()
        .collect::<Vec<_>>();
    for module in modules {
        invalidate_module(module, state);
    }
}

fn join_states(mut left: State, right: State) -> State {
    left.invalid_modules.extend(&right.invalid_modules);
    left.relative_cwd_known &= right.relative_cwd_known;
    let names = left
        .bindings
        .keys()
        .chain(right.bindings.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    for name in names {
        let value = match (left.bindings.get(&name), right.bindings.get(&name)) {
            (Some(left_value), Some(right_value))
                if values_match(left_value, right_value, &left.functions, &right.functions) =>
            {
                left_value.clone()
            }
            (Some(left_value), Some(right_value)) => {
                join_distinct_values(left_value.clone(), right_value.clone())
            }
            _ => Value::Unknown,
        };
        left.bindings.insert(name, value);
    }
    let cells = left.cells.len().max(right.cells.len());
    left.cells.resize(cells, Cell::Unknown);
    for (index, cell) in left.cells.iter_mut().enumerate() {
        if !right.cells.get(index).is_some_and(|right_cell| {
            cells_match(cell, right_cell, &left.functions, &right.functions)
        }) {
            *cell = Cell::Unknown;
        }
    }
    left
}

fn merge_branch_states(
    yes: State,
    yes_control: Control,
    no: State,
    no_control: Control,
) -> (State, Control) {
    if yes_control == Control::Next {
        return if no_control == Control::Next {
            (join_states(yes, no), Control::Next)
        } else {
            (yes, Control::Next)
        };
    }
    if no_control == Control::Next {
        return (no, Control::Next);
    }
    if yes_control == no_control {
        return (join_states(yes, no), yes_control);
    }
    match (yes_control, no_control) {
        (Control::Return(yes_value), Control::Return(no_value)) => (
            join_states(yes, no),
            Control::Return(join_values(yes_value, no_value)),
        ),
        (Control::Return(value), _) => (yes, Control::Return(value)),
        (_, Control::Return(value)) => (no, Control::Return(value)),
        (Control::Raise, _) => (yes, Control::Raise),
        (_, Control::Raise) => (no, Control::Raise),
        (Control::Break, _) => (join_states(yes, no), Control::Break),
        (_, Control::Break) => (join_states(yes, no), Control::Break),
        (Control::Continue, _) => (join_states(yes, no), Control::Continue),
        (_, Control::Continue) => (join_states(yes, no), Control::Continue),
        (Control::Diverge, Control::Diverge) => (join_states(yes, no), Control::Diverge),
        (Control::Next, _) | (_, Control::Next) => unreachable!(),
    }
}

fn values_match(
    left: &Value,
    right: &Value,
    left_functions: &[LocalFunction],
    right_functions: &[LocalFunction],
) -> bool {
    match (left, right) {
        (Value::LocalFunction(left_index), Value::LocalFunction(right_index)) => {
            left_index == right_index
                && left_functions
                    .get(*left_index)
                    .is_some_and(|function| right_functions.get(*right_index) == Some(function))
        }
        _ => left == right,
    }
}

fn cells_match(
    left: &Cell,
    right: &Cell,
    left_functions: &[LocalFunction],
    right_functions: &[LocalFunction],
) -> bool {
    match (left, right) {
        (Cell::Unknown, Cell::Unknown) => true,
        (Cell::Sequence(left), Cell::Sequence(right)) => {
            left.len() == right.len()
                && left
                    .iter()
                    .zip(right)
                    .all(|(left, right)| values_match(left, right, left_functions, right_functions))
        }
        _ => false,
    }
}

fn assigned_names(node: &HirNode, source: &str) -> BTreeSet<String> {
    fn visit(node: &HirNode, source: &str, names: &mut BTreeSet<String>, root: bool) {
        if !root {
            match node.kind() {
                HirKind::Function | HirKind::Class => {
                    if let Some(name) = node.child(HirField::Name) {
                        names.insert(unsafe_text(source, name).to_owned());
                    }
                    return;
                }
                HirKind::DecoratedDefinition => {
                    if let Some(name) = node
                        .child(HirField::Definition)
                        .and_then(|definition| definition.child(HirField::Name))
                    {
                        names.insert(unsafe_text(source, name).to_owned());
                    }
                    return;
                }
                HirKind::Lambda => return,
                _ => {}
            }
        }
        match node.kind() {
            HirKind::Assignment | HirKind::AugmentedAssignment | HirKind::For => {
                if let Some(left) = node.child(HirField::Left) {
                    collect_targets(left, source, names);
                }
            }
            HirKind::Import => {
                for imported in named_children(node) {
                    let (name, alias) = import_name(imported, source);
                    names.insert(alias.unwrap_or_else(|| {
                        name.split('.').next().unwrap_or(name.as_str()).to_owned()
                    }));
                }
                return;
            }
            HirKind::ImportFrom => {
                for imported in node.children().iter().filter(|child| {
                    matches!(child.kind(), HirKind::AliasedImport | HirKind::DottedName)
                        && child.field() != Some(HirField::ModuleName)
                }) {
                    let (name, alias) = import_name(imported, source);
                    names.insert(alias.unwrap_or(name));
                }
                return;
            }
            _ => {}
        }
        for child in node.children() {
            visit(child, source, names, false);
        }
    }
    fn collect_targets(node: &HirNode, source: &str, names: &mut BTreeSet<String>) {
        if node.kind() == HirKind::Identifier {
            names.insert(unsafe_text(source, node).to_owned());
        } else if matches!(
            node.kind(),
            HirKind::Tuple | HirKind::List | HirKind::ParenthesizedExpression
        ) || node.kind() == HirKind::Unsupported
            && unsafe_text(source, node).trim_start().starts_with('*')
        {
            for child in node.children() {
                collect_targets(child, source, names);
            }
        }
    }
    let mut names = BTreeSet::new();
    visit(node, source, &mut names, true);
    names
}

fn capture_names(node: &HirNode, source: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        if node.kind() == HirKind::CasePattern {
            let mut pattern = vec![node];
            while let Some(node) = pattern.pop() {
                if node.kind() == HirKind::Identifier {
                    let name = unsafe_text(source, node);
                    if name != "_" {
                        names.insert(name.to_owned());
                    }
                } else {
                    pattern.extend(node.children());
                }
            }
            continue;
        }
        stack.extend(node.children());
    }
    names
}

fn global_names(node: &HirNode, source: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        if node.kind() == HirKind::Unsupported {
            let text = unsafe_text(source, node).trim();
            if let Some(declared) = text.strip_prefix("global ") {
                names.extend(
                    declared
                        .split(',')
                        .map(str::trim)
                        .filter(|name| !name.is_empty())
                        .map(str::to_owned),
                );
            }
        }
        if matches!(
            node.kind(),
            HirKind::Function | HirKind::Class | HirKind::Lambda
        ) {
            continue;
        }
        stack.extend(node.children());
    }
    names
}

fn contains_kind(node: &HirNode, kind: HirKind, source: &str, prefix: &str) -> bool {
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        if node.kind() == kind && unsafe_text(source, node).trim_start().starts_with(prefix) {
            return true;
        }
        if matches!(
            node.kind(),
            HirKind::Function | HirKind::Class | HirKind::Lambda
        ) {
            continue;
        }
        stack.extend(node.children());
    }
    false
}

fn parse_integer(value: &str) -> Option<i64> {
    let value = value.replace('_', "");
    if let Some(value) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        i64::from_str_radix(value, 16).ok()
    } else if let Some(value) = value
        .strip_prefix("0o")
        .or_else(|| value.strip_prefix("0O"))
    {
        i64::from_str_radix(value, 8).ok()
    } else if let Some(value) = value
        .strip_prefix("0b")
        .or_else(|| value.strip_prefix("0B"))
    {
        i64::from_str_radix(value, 2).ok()
    } else {
        value.parse().ok()
    }
}

fn binary_value(left: Value, right: Value, operator: &str, budget: &mut Budget) -> Value {
    let origins = producer_ordinals(&left)
        .chain(producer_ordinals(&right))
        .collect::<BTreeSet<_>>();
    if !origins.is_empty() {
        return Value::Produced(origins.into_iter().collect());
    }
    match (left, right, operator) {
        (Value::String(mut left), Value::String(right), "+") => {
            if bounded_push_str(&mut left, &right, budget) {
                Value::String(left)
            } else {
                Value::Unknown
            }
        }
        (Value::Bytes(mut left), Value::Bytes(right), "+") => {
            if budget.admit_value_bytes(left.len().checked_add(right.len())) {
                left.extend(right);
                Value::Bytes(left)
            } else {
                Value::Unknown
            }
        }
        (Value::Int(left), Value::Int(right), "+") => {
            left.checked_add(right).map_or(Value::Unknown, Value::Int)
        }
        (Value::Int(left), Value::Int(right), "-") => {
            left.checked_sub(right).map_or(Value::Unknown, Value::Int)
        }
        (Value::Int(left), Value::Int(right), "*") => {
            left.checked_mul(right).map_or(Value::Unknown, Value::Int)
        }
        (Value::Int(left), Value::Int(right), "|") => Value::Int(left | right),
        (Value::Path(left), Value::String(right), "/") => {
            join_path(left, &right, budget).map_or(Value::Unknown, Value::Path)
        }
        _ => Value::Unknown,
    }
}

fn compare_values(left: &Value, right: &Value, operator: &str) -> Option<bool> {
    let equal = match (left, right) {
        (Value::None, Value::None) => Some(true),
        (Value::None, Value::Bool(_) | Value::Int(_) | Value::String(_) | Value::Bytes(_))
        | (Value::Bool(_) | Value::Int(_) | Value::String(_) | Value::Bytes(_), Value::None) => {
            Some(false)
        }
        (Value::Bool(left), Value::Bool(right)) => Some(left == right),
        (Value::Int(left), Value::Int(right)) => Some(left == right),
        (Value::Bool(left), Value::Int(right)) | (Value::Int(right), Value::Bool(left)) => {
            Some(i64::from(*left) == *right)
        }
        (Value::String(left), Value::String(right))
        | (Value::ImplicitString(left), Value::ImplicitString(right))
        | (Value::String(left), Value::ImplicitString(right))
        | (Value::ImplicitString(left), Value::String(right))
        | (Value::Path(left), Value::Path(right)) => Some(left == right),
        (Value::Bytes(left), Value::Bytes(right)) => Some(left == right),
        _ => None,
    };
    match operator {
        "==" => equal,
        "!=" => equal.map(|value| !value),
        "is" => match (left, right) {
            (Value::None, Value::None) => Some(true),
            (Value::None, _) | (_, Value::None) => Some(false),
            _ => None,
        },
        "is not" => match (left, right) {
            (Value::None, Value::None) => Some(false),
            (Value::None, _) | (_, Value::None) => Some(true),
            _ => None,
        },
        "<" => match (left, right) {
            (Value::Int(left), Value::Int(right)) => Some(left < right),
            (Value::String(left), Value::String(right)) => Some(left < right),
            _ => None,
        },
        "<=" => match (left, right) {
            (Value::Int(left), Value::Int(right)) => Some(left <= right),
            (Value::String(left), Value::String(right)) => Some(left <= right),
            _ => None,
        },
        ">" => match (left, right) {
            (Value::Int(left), Value::Int(right)) => Some(left > right),
            (Value::String(left), Value::String(right)) => Some(left > right),
            _ => None,
        },
        ">=" => match (left, right) {
            (Value::Int(left), Value::Int(right)) => Some(left >= right),
            (Value::String(left), Value::String(right)) => Some(left >= right),
            _ => None,
        },
        _ => None,
    }
}

fn join_values(left: Value, right: Value) -> Value {
    if left == right {
        return left;
    }
    join_distinct_values(left, right)
}

fn join_distinct_values(left: Value, right: Value) -> Value {
    let origins = producer_ordinals(&left)
        .chain(producer_ordinals(&right))
        .collect::<BTreeSet<_>>();
    if origins.is_empty() {
        Value::Unknown
    } else {
        Value::Produced(origins.into_iter().collect())
    }
}

fn producer_ordinals(value: &Value) -> impl Iterator<Item = usize> + '_ {
    match value {
        Value::Produced(origins) => origins.as_slice(),
        Value::Decoded(value) => match value.as_ref() {
            Value::Produced(origins) => origins.as_slice(),
            _ => &[],
        },
        _ => &[],
    }
    .iter()
    .copied()
}

fn truthy(value: &Value, state: &State) -> Option<bool> {
    match value {
        Value::None => Some(false),
        Value::Bool(value) => Some(*value),
        Value::Int(value) => Some(*value != 0),
        Value::String(value) | Value::ImplicitString(value) => Some(!value.is_empty()),
        Value::Bytes(value) => Some(!value.is_empty()),
        Value::EmptyDictionary => Some(false),
        Value::Cell(cell) => match state.cells.get(*cell) {
            Some(Cell::Sequence(values)) => Some(!values.is_empty()),
            Some(Cell::Unknown) | None => None,
        },
        Value::Module(_) | Value::Known(_) | Value::LocalFunction(_) | Value::Path(_) => Some(true),
        _ => None,
    }
}

fn display_value(value: &Value) -> Option<String> {
    match value {
        Value::None => Some("None".into()),
        Value::Bool(true) => Some("True".into()),
        Value::Bool(false) => Some("False".into()),
        Value::Int(value) => Some(value.to_string()),
        Value::String(value) | Value::ImplicitString(value) | Value::Path(value) => {
            Some(value.clone())
        }
        _ => None,
    }
}

fn value_string(value: &Value) -> Option<&str> {
    match value {
        Value::String(value) | Value::ImplicitString(value) | Value::Path(value) => Some(value),
        Value::Decoded(value) => value_string(value),
        _ => None,
    }
}

fn decoded(value: &Value) -> bool {
    matches!(value, Value::Decoded(_))
}

fn one_argument<'a>(arguments: &'a Arguments, keyword: &str) -> Option<&'a Value> {
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

fn argument<'a>(arguments: &'a Arguments, position: usize, keyword: &str) -> Option<&'a Value> {
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

fn dynamic_arguments(function: KnownFunction, arguments: &Arguments) -> Option<bool> {
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

fn code_mode(value: &str) -> Option<CodeMode> {
    match value {
        "eval" => Some(CodeMode::Eval),
        "exec" => Some(CodeMode::Exec),
        "single" => Some(CodeMode::Single),
        _ => None,
    }
}

fn required_argument<'a>(
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

fn valid_call_shape(arguments: &Arguments, max_positional: usize, keywords: &[&str]) -> bool {
    arguments.complete
        && arguments.positional.len() <= max_positional
        && arguments
            .keywords
            .iter()
            .all(|(name, _)| keywords.contains(&name.as_str()))
        && keywords
            .iter()
            .take(arguments.positional.len())
            .all(|parameter| !arguments.keywords.iter().any(|(name, _)| name == parameter))
}

fn valid_os_exec_shape(kind: StringKind, arguments: &Arguments) -> bool {
    if !arguments.complete || !arguments.keywords.is_empty() {
        return false;
    }
    match kind {
        StringKind::Execl | StringKind::Execlp => arguments.positional.len() >= 2,
        StringKind::Execle => arguments.positional.len() >= 3,
        StringKind::Execv | StringKind::Execvp => arguments.positional.len() == 2,
        StringKind::Execvpe => arguments.positional.len() == 3,
    }
}

fn possible_path_argument(arguments: &Arguments, position: usize, keyword: &str) -> bool {
    argument(arguments, position, keyword).is_some_and(possible_scalar_value)
}

fn possible_scalar_argument(arguments: &Arguments, position: usize, keyword: &str) -> bool {
    argument(arguments, position, keyword).is_some_and(possible_scalar_value)
}

fn possible_scalar_value(value: &Value) -> bool {
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

fn possible_open_target(value: &Value) -> bool {
    possible_scalar_value(value) || matches!(value, Value::Int(_))
}

fn possible_subprocess_command(value: &Value, state: &State) -> bool {
    if possible_scalar_value(value) {
        return true;
    }
    match value {
        Value::Cell(cell) => match state.cells.get(*cell) {
            Some(Cell::Sequence(values)) => values.iter().all(possible_scalar_value),
            Some(Cell::Unknown) | None => true,
        },
        _ => false,
    }
}

fn possible_os_exec(kind: StringKind, arguments: &Arguments, state: &State) -> bool {
    match kind {
        StringKind::Execl | StringKind::Execlp => {
            arguments.positional.iter().all(possible_scalar_value)
        }
        StringKind::Execle => arguments.positional[..arguments.positional.len() - 1]
            .iter()
            .all(possible_scalar_value),
        StringKind::Execv | StringKind::Execvp | StringKind::Execvpe => {
            possible_scalar_value(&arguments.positional[0])
                && possible_subprocess_command(&arguments.positional[1], state)
        }
    }
}
fn subprocess_options(kind: SubprocessKind, arguments: &Arguments) -> Option<(bool, bool)> {
    if !arguments.complete || arguments.positional.len() > 1 {
        return None;
    }
    let mut shell = false;
    let mut stdout = kind != SubprocessKind::CheckOutput;
    let mut seen = BTreeSet::new();
    for (name, value) in &arguments.keywords {
        if name == "args" {
            continue;
        }
        if !seen.insert(name) {
            return None;
        }
        match name.as_str() {
            "shell" => shell = exact_bool(value)?,
            "capture_output" if kind == SubprocessKind::Run => {
                if exact_bool(value)? {
                    stdout = false;
                }
            }
            "check" if kind == SubprocessKind::Run => {
                exact_bool(value)?;
            }
            "cwd" if kind == SubprocessKind::Popen => {
                value_string(value)?;
            }
            _ => return None,
        }
    }
    Some((shell, stdout))
}

fn subprocess_shell(arguments: &Arguments) -> Option<bool> {
    if !arguments.complete
        || arguments
            .keywords
            .iter()
            .filter(|(name, _)| name == "shell")
            .count()
            > 1
    {
        return None;
    }
    arguments
        .keywords
        .iter()
        .find(|(name, _)| name == "shell")
        .map_or(Some(false), |(_, value)| exact_bool(value))
}

fn valid_subprocess_shape(arguments: &Arguments) -> bool {
    const KEYWORDS: &[&str] = &[
        "args",
        "bufsize",
        "executable",
        "stdin",
        "stdout",
        "stderr",
        "preexec_fn",
        "close_fds",
        "shell",
        "cwd",
        "env",
        "universal_newlines",
        "startupinfo",
        "creationflags",
        "restore_signals",
        "start_new_session",
        "pass_fds",
        "user",
        "group",
        "extra_groups",
        "encoding",
        "errors",
        "text",
        "umask",
        "pipesize",
        "process_group",
        "input",
        "capture_output",
        "timeout",
        "check",
    ];
    valid_call_shape(arguments, 1, KEYWORDS)
}

fn exact_bool(value: &Value) -> Option<bool> {
    match value {
        Value::Bool(value) => Some(*value),
        Value::Int(0) | Value::None => Some(false),
        Value::Int(1) => Some(true),
        _ => None,
    }
}

fn argv_value(value: &Value, state: &State, budget: &mut Budget) -> Option<Vec<String>> {
    bounded_argv_values(sequence_values(value, state)?, budget)
}

fn bounded_argv_values(values: &[Value], budget: &mut Budget) -> Option<Vec<String>> {
    bounded_strings(
        values.iter().map(|value| match value {
            Value::String(value) | Value::Path(value) => Some(value.as_str()),
            _ => None,
        }),
        budget,
    )
}

fn bounded_strings<'a>(
    values: impl IntoIterator<Item = Option<&'a str>>,
    budget: &mut Budget,
) -> Option<Vec<String>> {
    let mut output = Vec::new();
    let mut bytes = 0usize;
    for value in values {
        let value = value?;
        if output.len() >= MAX_COLLECTION_ITEMS {
            budget.refuse_work();
            return None;
        }
        let next_bytes = bytes.checked_add(value.len());
        if !budget.admit_value_bytes(next_bytes) {
            return None;
        }
        bytes = next_bytes.expect("the byte total was admitted");
        output.push(value.to_owned());
    }
    Some(output)
}

fn decode_string_fragment(value: &str, raw: bool) -> Option<String> {
    if raw {
        return Some(value.to_owned());
    }
    let bytes = value.as_bytes();
    let mut output = String::new();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] != b'\\' {
            let character = value[index..].chars().next()?;
            output.push(character);
            index += character.len_utf8();
            continue;
        }
        index += 1;
        let escape = *bytes.get(index)?;
        index += 1;
        match escape {
            b'\\' => output.push('\\'),
            b'\'' => output.push('\''),
            b'"' => output.push('"'),
            b'n' => output.push('\n'),
            b'r' => output.push('\r'),
            b't' => output.push('\t'),
            b'a' => output.push('\x07'),
            b'b' => output.push('\x08'),
            b'f' => output.push('\x0c'),
            b'v' => output.push('\x0b'),
            b'\n' => {}
            b'x' => {
                let value = parse_hex(bytes.get(index..index + 2)?)?;
                output.push(char::from(value as u8));
                index += 2;
            }
            b'u' => {
                let value = parse_hex(bytes.get(index..index + 4)?)?;
                output.push(char::from_u32(value)?);
                index += 4;
            }
            b'U' => {
                let value = parse_hex(bytes.get(index..index + 8)?)?;
                output.push(char::from_u32(value)?);
                index += 8;
            }
            b'0'..=b'7' => {
                let mut value = u32::from(escape - b'0');
                let mut digits = 1;
                while digits < 3
                    && bytes
                        .get(index)
                        .is_some_and(|byte| matches!(byte, b'0'..=b'7'))
                {
                    value = value * 8 + u32::from(bytes[index] - b'0');
                    index += 1;
                    digits += 1;
                }
                output.push(char::from_u32(value)?);
            }
            other => {
                output.push('\\');
                output.push(char::from(other));
            }
        }
    }
    Some(output)
}

fn parse_hex(bytes: &[u8]) -> Option<u32> {
    bytes.iter().try_fold(0u32, |value, byte| {
        let digit = match byte {
            b'0'..=b'9' => u32::from(byte - b'0'),
            b'a'..=b'f' => u32::from(byte - b'a') + 10,
            b'A'..=b'F' => u32::from(byte - b'A') + 10,
            _ => return None,
        };
        Some(value * 16 + digit)
    })
}

fn decode_base64(value: &str) -> Option<Vec<u8>> {
    let mut output = Vec::new();
    let mut buffer = 0u32;
    let mut bits = 0usize;
    for byte in value.bytes().filter(|byte| !byte.is_ascii_whitespace()) {
        if byte == b'=' {
            break;
        }
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return None,
        };
        buffer = (buffer << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    Some(output)
}

fn bounded_owned(value: &str, budget: &mut Budget) -> Option<String> {
    budget
        .admit_value_bytes(Some(value.len()))
        .then(|| value.to_owned())
}

fn bounded_push_str(output: &mut String, value: &str, budget: &mut Budget) -> bool {
    if !budget.admit_value_bytes(output.len().checked_add(value.len())) {
        return false;
    }
    output.push_str(value);
    true
}

fn join_path(mut base: String, relative: &str, budget: &mut Budget) -> Option<String> {
    if base.is_empty() {
        return bounded_owned(relative, budget);
    }
    let separator = usize::from(!base.ends_with(['/', '\\']));
    let relative = relative.trim_start_matches(['/', '\\']);
    if !budget.admit_value_bytes(
        base.len()
            .checked_add(separator)
            .and_then(|bytes| bytes.checked_add(relative.len())),
    ) {
        return None;
    }
    if !base.ends_with(['/', '\\']) {
        base.push('/');
    }
    base.push_str(relative);
    Some(base)
}

fn expand_home(path: &str, home: &str, budget: &mut Budget) -> Option<String> {
    if path == "~" {
        bounded_owned(home, budget)
    } else if let Some(relative) = path.strip_prefix("~/").or_else(|| path.strip_prefix("~\\")) {
        join_path(home.to_owned(), relative, budget)
    } else {
        bounded_owned(path, budget)
    }
}

fn is_absolute(path: &str, platform: Platform) -> bool {
    if platform == Platform::Windows {
        path.starts_with(['/', '\\'])
            || path.as_bytes().get(1) == Some(&b':')
                && path
                    .as_bytes()
                    .get(2)
                    .is_some_and(|byte| matches!(byte, b'/' | b'\\'))
    } else {
        path.starts_with('/')
    }
}

fn normalize_path(path: &str, platform: Platform) -> String {
    let absolute = path.starts_with(['/', '\\']);
    let mut components = Vec::new();
    for component in path.split(['/', '\\']) {
        match component {
            "" | "." => {}
            ".." => {
                components.pop();
            }
            component => components.push(if platform == Platform::Windows {
                component.to_ascii_lowercase()
            } else {
                component.to_owned()
            }),
        }
    }
    let normalized = components.join("/");
    if absolute && platform != Platform::Windows {
        format!("/{normalized}")
    } else {
        normalized
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(code: &str) -> InlineReport {
        analyze(
            "python3",
            &InlineInput {
                program: "python3",
                code,
                home: "/home/dev",
                platform: Platform::Linux,
            },
            None,
            0,
        )
        .into_report()
    }

    fn assert_work_limit(report: &InlineReport) {
        assert!(report.findings().is_empty(), "{report:?}");
        assert!(report.nested_executions().is_empty(), "{report:?}");
        assert_eq!(report.refusals(), [InlineRefusal::WorkLimit]);
    }

    #[test]
    fn constants_branches_loops_and_alias_cells_feed_known_sinks() {
        for code in [
            "import shutil\nbase='/'\nif True:\n    shutil.rmtree(base)",
            "import shutil\nfor target in ['/tmp', '/']:\n    shutil.rmtree(target)",
            "import subprocess\nargv=['rm']\nalias=argv\nalias.extend(['-rf','/'])\nsubprocess.run(argv)",
        ] {
            let report = report(code);
            assert!(
                report.contains_exact(FindingKind::RootDestruction)
                    || !report.nested_executions().is_empty(),
                "{code}: {report:?}"
            );
        }
    }

    #[test]
    fn f_strings_paths_and_local_functions_are_bounded_values() {
        let report =
            report("import os\ndef run(name):\n    os.system(f'printf {name}')\nrun('child')");
        assert!(matches!(
            report.nested_executions(),
            [NestedExecution::Shell { code, .. }] if code == "printf child"
        ));
    }

    #[test]
    fn local_functions_execute_only_after_exact_argument_binding() {
        for code in [
            "import shutil\ndef danger(required):\n    shutil.rmtree('/')\ndanger()",
            "import shutil\ndef danger(value):\n    shutil.rmtree('/')\ndanger(1, 2)",
            "import shutil\ndef danger(value):\n    shutil.rmtree('/')\ndanger(other=1)",
            "import shutil\ndef danger(value):\n    shutil.rmtree('/')\ndanger(1, value=2)",
            "import shutil\ndef danger(*values):\n    shutil.rmtree('/')\ndanger()",
        ] {
            assert_eq!(report(code), InlineReport::default(), "{code}");
        }

        for code in [
            "import shutil\ndef danger(path='/'): shutil.rmtree(path)\ndanger()",
            "import shutil\ndef danger(path): shutil.rmtree(path)\ndanger(path='/')",
            "import shutil\ndef danger(path: str): shutil.rmtree(path)\ndanger('/')",
            "import shutil\ndef invoke(callback, target): callback(target)\nalias=invoke\nalias(shutil.rmtree, '/')",
        ] {
            assert!(
                report(code).contains_exact(FindingKind::RootDestruction),
                "{code}"
            );
        }
    }

    #[test]
    fn function_locals_are_predeclared_without_masking_global_or_attribute_access() {
        for code in [
            "import shutil\ndef run():\n    shutil.rmtree('/')\n    shutil += other\nrun()",
            "import shutil\ndef run():\n    shutil.rmtree('/')\n    import shutil\nrun()",
            "import shutil\ndef run():\n    shutil.rmtree('/')\n    *shutil, = values\nrun()",
            "import shutil as tool\ndef run():\n    tool.rmtree('/')\n    import package as tool\nrun()",
            "from shutil import rmtree\ndef run():\n    rmtree('/')\n    from shutil import rmtree\nrun()",
            "import shutil\ndef run():\n    shutil.rmtree('/')\n    for shutil in []:\n        pass\nrun()",
            "import shutil\ndef run():\n    shutil.rmtree('/')\n    def shutil():\n        pass\nrun()",
            "import shutil\ndef run():\n    shutil.rmtree('/')\n    class shutil:\n        pass\nrun()",
        ] {
            assert_eq!(report(code), InlineReport::default(), "{code}");
        }

        for code in [
            "import shutil\ndef run():\n    shutil.rmtree('/')\n    shutil.member = None\nrun()",
            "import shutil\ndef run():\n    global shutil\n    shutil.rmtree('/')\n    shutil = None\nrun()",
        ] {
            assert!(
                report(code).contains_exact(FindingKind::RootDestruction),
                "{code}"
            );
        }
    }

    #[test]
    fn branch_local_function_indices_do_not_alias_different_bodies() {
        assert_eq!(
            report(
                "import shutil\nif condition:\n    def action(): shutil.rmtree('/')\nelse:\n    def action(): pass\naction()"
            ),
            InlineReport::default()
        );
        assert_eq!(
            report(
                "import shutil\nif condition:\n    def action(): shutil.rmtree('/')\n    callbacks=[action]\nelse:\n    def action(): pass\n    callbacks=[action]\ncallback,=callbacks\ncallback()"
            ),
            InlineReport::default()
        );
        assert!(
            report(
                "import shutil\ndef action(): shutil.rmtree('/')\nif condition:\n    alias=action\nelse:\n    alias=action\nalias()"
            )
            .contains_exact(FindingKind::RootDestruction)
        );
    }

    #[test]
    fn local_calls_propagate_mutations_to_shared_cells() {
        for code in [
            "import subprocess\nargv=['rm']\nalias=argv\ndef finish(parts): parts.extend(['-rf','/'])\nfinish(alias)\nsubprocess.run(argv)",
            "import subprocess\nargv=['rm']\nalias=argv\ndef finish(parts): parts.extend(['-rf','/'])\nfinish(parts=alias)\nsubprocess.run(argv)",
            "import subprocess\nargv=['rm']\nalias=argv\ndef finish(): alias.extend(['-rf','/'])\nfinish()\nsubprocess.run(argv)",
        ] {
            assert!(matches!(
                report(code).nested_executions(),
                [NestedExecution::Command { argv, .. }] if argv == &["rm", "-rf", "/"]
            ));
        }

        assert!(matches!(
            report(
                "import subprocess\nargv=['rm']\ndef finish(parts): parts.extend(['-rf','/'])\nfinish()\nsubprocess.run(argv)"
            )
            .nested_executions(),
            [NestedExecution::Command { argv, .. }] if argv == &["rm"]
        ));

        let mut code = "items=['x']\ndef grow(values):\n".to_owned();
        for _ in 0..9 {
            code.push_str("    values.extend(values)\n");
        }
        code.push_str("grow(items)");
        assert_work_limit(&report(&code));
    }

    #[test]
    fn unknown_calls_and_rebound_owners_do_not_invent_effects() {
        for code in [
            "shutil.rmtree('/')",
            "import shutil\nshutil=safe\nshutil.rmtree('/')",
            "command=plugin.make(user)\nimport os\nos.system(command)",
        ] {
            assert_eq!(report(code), InlineReport::default(), "{code}");
        }
    }

    #[test]
    fn comparisons_follow_operand_order_and_known_false_conditions() {
        assert_eq!(
            report("import shutil\nif 1 != 1:\n    shutil.rmtree('/')"),
            InlineReport::default()
        );
        assert!(
            report("import shutil\nif shutil.rmtree('/') == None:\n    pass")
                .contains_exact(FindingKind::RootDestruction)
        );
    }

    #[test]
    fn path_and_exec_summaries_preserve_runtime_identity() {
        assert_eq!(
            report("import os, shutil\nshutil.rmtree(os.path.abspath('~'))"),
            InlineReport::default()
        );
        assert!(
            report("import os, shutil\nshutil.rmtree(os.path.expanduser('~'))")
                .contains_exact(FindingKind::HomeDestruction)
        );
        assert_eq!(
            report("import os.path, shutil\nshutil.rmtree(os.abspath('~'))"),
            InlineReport::default()
        );
        assert!(matches!(
            report("import os\nos.execl('/bin/echo', 'rm', '-rf', '/')")
                .nested_executions(),
            [NestedExecution::Command { argv, .. }] if argv == &["/bin/echo", "-rf", "/"]
        ));
    }

    #[test]
    fn loop_else_and_iteration_limits_do_not_drop_control_flow() {
        assert!(
            report("import shutil\nfor value in []:\n    pass\nelse:\n    shutil.rmtree('/')")
                .contains_exact(FindingKind::RootDestruction)
        );
        assert_eq!(
            report("import shutil\nfor value in [1]:\n    break\nelse:\n    shutil.rmtree('/')"),
            InlineReport::default()
        );
        assert!(
            report("import shutil\nwhile False:\n    pass\nelse:\n    shutil.rmtree('/')")
                .contains_exact(FindingKind::RootDestruction)
        );
        assert_eq!(
            report("import shutil\nwhile True:\n    break\nelse:\n    shutil.rmtree('/')"),
            InlineReport::default()
        );
        assert!(
            report("import shutil\nwhile condition:\n    break\nelse:\n    shutil.rmtree('/')")
                .contains_exact(FindingKind::RootDestruction)
        );
        assert_eq!(
            report("import shutil\nwhile True:\n    pass\nshutil.rmtree('/')"),
            InlineReport::default()
        );

        let values = (0..64)
            .map(|value| value.to_string())
            .chain(std::iter::once("'/'".to_owned()))
            .collect::<Vec<_>>()
            .join(",");
        let report = report(&format!(
            "import shutil\nfor target in [{values}]:\n    shutil.rmtree(target)"
        ));
        assert!(!report.contains_exact(FindingKind::RootDestruction));
        assert_eq!(report.refusals(), [InlineRefusal::WorkLimit]);
    }

    #[test]
    fn unsupported_boundaries_do_not_execute_nested_calls() {
        for code in [
            "import shutil\n[shutil.rmtree('/') for _ in []]",
            "import shutil\nmatch 0:\n    case 1: shutil.rmtree('/')",
        ] {
            assert_eq!(report(code), InlineReport::default(), "{code}");
        }
    }

    #[test]
    fn dynamic_code_preserves_parse_mode_and_source_identity() {
        assert_eq!(
            report("eval(\"import shutil; shutil.rmtree('/')\")"),
            InlineReport::default()
        );
        for code in [
            "import shutil\neval(\"shutil.rmtree('/')\")",
            "exec(\"import shutil; shutil.rmtree('/')\")",
            "eval(compile(\"import shutil; shutil.rmtree('/')\", '<x>', 'exec'))",
            "source=\"import shutil\\ndef run():\\n    shutil.rmtree('/')\"\nexec(source)\nrun()",
        ] {
            assert!(
                report(code).contains_exact(FindingKind::RootDestruction),
                "{code}"
            );
        }
        assert_eq!(
            report("compile(\"import shutil; shutil.rmtree('/')\", '<x>', 'exec')"),
            InlineReport::default()
        );
        assert_eq!(
            report("eval(\"shutil.rmtree('/')\", 3)"),
            InlineReport::default()
        );
        assert_eq!(
            report("exec(\"import shutil\", {}, {})\nshutil.rmtree('/')"),
            InlineReport::default()
        );
    }

    #[test]
    fn reachability_and_mutation_do_not_reuse_stale_exact_values() {
        for code in [
            "import shutil\nif []:\n    shutil.rmtree('/')",
            "import subprocess\nargv=['rm','-rf','/']\nargv[0]='echo'\nsubprocess.run(argv)",
            "import subprocess\nargv=['rm','-rf','/']\nargv.clear()\nsubprocess.run(argv)",
            "import os\napi=os\nos.system=safe\napi.system('rm -rf /')",
            "import shutil\ntarget='/'\nshutil.rmtree(f'{target!r}')",
            "import shutil\ntry:\n    pass\nexcept:\n    shutil.rmtree('/')",
            "import shutil\ntry:\n    raise RuntimeError()\nelse:\n    shutil.rmtree('/')",
            "import shutil\ndef safe():\n    try:\n        return\n    finally:\n        pass\n    shutil.rmtree('/')\nsafe()",
        ] {
            assert_eq!(report(code), InlineReport::default(), "{code}");
        }
        for code in [
            "import shutil\nclass Config:\n    shutil.rmtree('/')",
            "import shutil\ntry:\n    pass\nfinally:\n    shutil.rmtree('/')",
            "import shutil\ntry:\n    raise RuntimeError()\nexcept:\n    shutil.rmtree('/')",
        ] {
            assert!(
                report(code).contains_exact(FindingKind::RootDestruction),
                "{code}"
            );
        }
    }

    #[test]
    fn exponential_string_bytes_and_dynamic_source_are_bounded() {
        for initial in ["value='x'\n", "value=b'x'\n"] {
            let mut code = initial.to_owned();
            for _ in 0..21 {
                code.push_str("value=value+value\n");
            }
            assert_work_limit(&report(&code));
        }

        let mut code = "source='#x\\n'\n".to_owned();
        for _ in 0..19 {
            code.push_str("source=source+source\n");
        }
        code.push_str("exec(source)");
        assert_work_limit(&report(&code));
    }

    #[test]
    fn collection_mutation_and_splats_respect_the_item_cap() {
        let mut appends = "items=[]\n".to_owned();
        for _ in 0..=MAX_COLLECTION_ITEMS {
            appends.push_str("items.append('x')\n");
        }
        assert_work_limit(&report(&appends));

        let mut extension = "items=['x']\n".to_owned();
        for _ in 0..9 {
            extension.push_str("items.extend(items)\n");
        }
        assert_work_limit(&report(&extension));

        let first = std::iter::repeat_n("'x'", 200)
            .collect::<Vec<_>>()
            .join(",");
        let second = std::iter::repeat_n("'x'", 100)
            .collect::<Vec<_>>()
            .join(",");
        let splat = format!("first=[{first}]\nsecond=[{second}]\ncombined=[*first,*second]");
        assert_work_limit(&report(&splat));
    }

    #[test]
    fn dynamic_source_and_nested_value_bytes_are_checked_before_use() {
        let input = InlineInput {
            program: "python3",
            code: "",
            home: "/home/dev",
            platform: Platform::Linux,
        };
        let mut interpreter = Interpreter {
            program: "python3",
            source: Arc::from(""),
            input,
            report: InlineReport::default(),
            budget: Budget::default(),
            complete: true,
            draft: LanguageDraft::default(),
            conditional_depth: 0,
            execution_dominators: Vec::new(),
            call_stack: Vec::new(),
            pending_control: None,
        };
        interpreter.dynamic_execution(
            Value::String("#".repeat(crate::SOURCE_LIMIT + 1)),
            CodeMode::Exec,
            &mut State::default(),
            0,
        );
        assert_eq!(interpreter.report.refusals(), [InlineRefusal::SourceLimit]);

        let large = "x".repeat(MAX_VALUE_BYTES / 2 + 1);
        let mut budget = Budget::default();
        assert!(join_path(large.clone(), &large, &mut budget).is_none());
        assert_eq!(budget.refusal, Some(InlineRefusal::WorkLimit));

        let values = [Value::String(large.clone()), Value::String(large)];
        let mut budget = Budget::default();
        assert!(bounded_strings(values.iter().map(value_string), &mut budget).is_none());
        assert_eq!(budget.refusal, Some(InlineRefusal::WorkLimit));
    }
}
