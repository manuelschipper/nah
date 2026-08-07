use std::{collections::BTreeMap, collections::BTreeSet, sync::Arc};

use nah_proto::ctx::Platform;

use crate::{Finding, FindingKind, InlineInput, InlineRefusal, InlineReport, ProtectionInput};

use super::parser::{CoverageKind, HirField, HirKind, HirNode};

const MAX_WORK: usize = 262_144;
const MAX_STATEMENTS: usize = 4_096;
const MAX_FUNCTIONS: usize = 128;
const MAX_CALL_DEPTH: usize = 16;
const MAX_COLLECTION_ITEMS: usize = 256;
const MAX_VALUE_BYTES: usize = crate::SOURCE_LIMIT;
const MAX_DYNAMIC_SOURCE_BYTES: usize = crate::SOURCE_LIMIT;

const SYSTEM_TREES: &[&str] = &[
    "/",
    "/bin",
    "/boot",
    "/dev",
    "/etc",
    "/lib",
    "/lib32",
    "/lib64",
    "/proc",
    "/root",
    "/run",
    "/sbin",
    "/sys",
    "/usr",
    "/var",
    "/Library",
    "/System",
    "/private/etc",
    "/private/var",
];

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Module {
    Fs,
    ChildProcess,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Member {
    Rm,
    RmSync,
    Exec,
    ExecSync,
    Spawn,
    SpawnSync,
    ExecFile,
    ExecFileSync,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum KnownFunction {
    DefineProperty,
    Fs(Member),
    Child(Member),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LocalFunction {
    parameters: Option<Vec<String>>,
    body: HirNode,
    expression_body: bool,
    required_scope_depth: usize,
    source_identity: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Value {
    Unknown,
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
    Require,
    Eval,
    ObjectBuiltin,
    Process,
    Environment,
    UnknownModuleMember(Module),
    UnknownReceiver(Box<Value>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Scope {
    bindings: BTreeMap<String, Value>,
    function: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct State {
    scopes: Vec<Scope>,
    owned_members: BTreeSet<(Module, Member)>,
}

impl Default for State {
    fn default() -> Self {
        let bindings = [
            ("require", Value::Require),
            ("eval", Value::Eval),
            ("Object", Value::ObjectBuiltin),
            ("process", Value::Process),
        ]
        .into_iter()
        .map(|(name, value)| (name.to_owned(), value))
        .collect();
        let owned_members = [
            (Module::Fs, Member::Rm),
            (Module::Fs, Member::RmSync),
            (Module::ChildProcess, Member::Exec),
            (Module::ChildProcess, Member::ExecSync),
            (Module::ChildProcess, Member::Spawn),
            (Module::ChildProcess, Member::SpawnSync),
            (Module::ChildProcess, Member::ExecFile),
            (Module::ChildProcess, Member::ExecFileSync),
        ]
        .into_iter()
        .collect();
        Self {
            scopes: vec![Scope {
                bindings,
                function: true,
            }],
            owned_members,
        }
    }
}

impl State {
    fn get(&self, name: &str) -> Value {
        self.scopes
            .iter()
            .rev()
            .find_map(|scope| scope.bindings.get(name))
            .cloned()
            .unwrap_or(Value::Unknown)
    }

    fn declare(&mut self, name: &str, value: Value) {
        if let Some(scope) = self.scopes.last_mut() {
            scope.bindings.insert(name.to_owned(), value);
        }
    }

    fn predeclare_var(&mut self, name: &str) {
        if let Some(scope) = self.scopes.iter_mut().rev().find(|scope| scope.function) {
            let binding = scope
                .bindings
                .entry(name.to_owned())
                .or_insert(Value::Unknown);
            if matches!(
                binding,
                Value::Require | Value::Eval | Value::ObjectBuiltin | Value::Process
            ) {
                *binding = Value::Unknown;
            }
        }
    }

    fn assign(&mut self, name: &str, value: Value) {
        if let Some(scope) = self
            .scopes
            .iter_mut()
            .rev()
            .find(|scope| scope.bindings.contains_key(name))
        {
            scope.bindings.insert(name.to_owned(), value);
        } else if let Some(scope) = self.scopes.first_mut() {
            scope.bindings.insert(name.to_owned(), value);
        }
    }

    fn push_scope(&mut self, function: bool) {
        self.scopes.push(Scope {
            bindings: BTreeMap::new(),
            function,
        });
    }

    fn pop_scope(&mut self) {
        self.scopes.pop();
    }

    fn invalidate_module(&mut self, module: Module) {
        self.owned_members.retain(|(owned, _)| *owned != module);
    }

    fn widen(&mut self) {
        for scope in &mut self.scopes {
            for value in scope.bindings.values_mut() {
                *value = Value::Unknown;
            }
        }
        self.owned_members.clear();
    }

    fn invalidate_value(&mut self, value: &Value) {
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
        if matches!(value, Value::Process | Value::Environment) {
            for scope in &mut self.scopes {
                for binding in scope.bindings.values_mut() {
                    if matches!(binding, Value::Process | Value::Environment) {
                        *binding = Value::Unknown;
                    }
                }
            }
        }
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
}

struct Interpreter<'a> {
    program: &'a str,
    source: &'a str,
    home: &'a str,
    platform: Platform,
    depth: usize,
    report: InlineReport,
    budget: Budget,
    return_value: Value,
}

pub(super) fn analyze(
    program: &str,
    input: &InlineInput<'_>,
    protection: Option<&ProtectionInput<'_>>,
    depth: usize,
) -> InlineReport {
    let module = match super::parser::javascript(input.code) {
        Ok(module) if module.executable() => module,
        Ok(_) => return InlineReport::default(),
        Err(refusal) => return InlineReport::refused(refusal),
    };
    debug_assert!(module.coverage().iter().all(|covered| {
        matches!(
            covered.kind(),
            CoverageKind::Unsupported | CoverageKind::Error
        ) && covered.span().end() <= input.code.len()
    }));
    let mut interpreter = Interpreter {
        program,
        source: input.code,
        home: input.home,
        platform: input.platform,
        depth,
        report: InlineReport::default(),
        budget: Budget::default(),
        return_value: Value::Undefined,
    };
    let mut state = State::default();
    interpreter.hoist_vars(module.root(), &mut state);
    interpreter.exec_sequence(module.root(), &mut state, false, 0);
    if let Some(refusal) = interpreter.budget.refusal {
        interpreter.report.refuse(refusal);
    }
    super::super::common::with_protection(interpreter.report, program, input, protection)
}

impl<'a> Interpreter<'a> {
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
                | HirKind::ClassDeclaration => {}
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
                    self.eval(expression, state, call_depth);
                }
                Control::Next
            }
            HirKind::LexicalDeclaration | HirKind::VariableDeclaration => {
                self.declaration(node, state, call_depth);
                Control::Next
            }
            HirKind::FunctionDeclaration | HirKind::ImportStatement => Control::Next,
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
                Control::Return
            }
            HirKind::ThrowStatement => {
                if let Some(value) = named_children(node).next() {
                    self.eval(value, state, call_depth);
                }
                Control::Throw
            }
            HirKind::TryStatement => self.try_statement(node, state, call_depth),
            HirKind::Comment | HirKind::Token | HirKind::EmptyStatement => Control::Next,
            HirKind::ClassDeclaration | HirKind::Unsupported | HirKind::Error => {
                state.widen();
                Control::Next
            }
            _ => {
                self.eval(node, state, call_depth);
                Control::Next
            }
        }
    }

    fn declaration(&mut self, node: &HirNode, state: &mut State, call_depth: usize) {
        for declarator in
            named_children(node).filter(|child| child.kind() == HirKind::VariableDeclarator)
        {
            let value = declarator
                .child(HirField::Value)
                .map_or(Value::Undefined, |value| {
                    self.eval(value, state, call_depth)
                });
            if let Some(pattern) = declarator.child(HirField::Name) {
                let mode = if node.kind() == HirKind::VariableDeclaration {
                    BindingMode::Var
                } else {
                    BindingMode::Lexical
                };
                self.assign_pattern(pattern, value, state, mode, call_depth);
            }
        }
    }

    fn if_statement(&mut self, node: &HirNode, state: &mut State, call_depth: usize) -> Control {
        let condition = node
            .child(HirField::Condition)
            .map_or(Value::Unknown, |condition| {
                self.eval(condition, state, call_depth)
            });
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
                let mut yes = state.clone();
                let mut no = state.clone();
                let saved_return = self.return_value.clone();
                self.return_value = saved_return.clone();
                let yes_control = consequence.map_or(Control::Next, |branch| {
                    self.exec_branch(branch, &mut yes, call_depth)
                });
                let yes_return = self.return_value.clone();
                self.return_value = saved_return.clone();
                let no_control = alternative.map_or(Control::Next, |branch| {
                    self.exec_branch(branch, &mut no, call_depth)
                });
                let no_return = self.return_value.clone();
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
                    let before = state.clone();
                    let mut iterated = state.clone();
                    self.exec_branch(body, &mut iterated, call_depth);
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
        if control == Control::Throw
            && let Some(handler) = node.child(HirField::Handler)
        {
            state.push_scope(false);
            if let Some(parameter) = handler.child(HirField::Parameter) {
                self.predeclare_pattern(parameter, state, false);
                self.assign_pattern(
                    parameter,
                    Value::Unknown,
                    state,
                    BindingMode::Lexical,
                    call_depth,
                );
            }
            control = handler.child(HirField::Body).map_or(Control::Next, |body| {
                self.exec_sequence(body, state, false, call_depth)
            });
            state.pop_scope();
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
            HirKind::ParenthesizedExpression => named_children(node)
                .next()
                .map_or(Value::Unknown, |child| self.eval(child, state, call_depth)),
            HirKind::SequenceExpression => {
                let mut value = Value::Undefined;
                for child in named_children(node) {
                    value = self.eval(child, state, call_depth);
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
                {
                    self.assign_target(left, Value::Unknown, state, call_depth);
                }
                if let Some(right) = node.child(HirField::Right) {
                    self.eval(right, state, call_depth);
                }
                Value::Unknown
            }
            HirKind::MemberExpression | HirKind::SubscriptExpression => {
                self.member(node, state, call_depth)
            }
            HirKind::CallExpression => self.call(node, state, call_depth),
            HirKind::ComputedPropertyName | HirKind::TemplateSubstitution => named_children(node)
                .next()
                .map_or(Value::Unknown, |child| self.eval(child, state, call_depth)),
            HirKind::ExpressionStatement => named_children(node)
                .next()
                .map_or(Value::Undefined, |child| {
                    self.eval(child, state, call_depth)
                }),
            HirKind::Unsupported | HirKind::Error => Value::Unknown,
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
        match operator.as_str() {
            "&&" => match truthy(&left) {
                Some(false) => left,
                Some(true) => self.eval(right_node, state, call_depth),
                None => {
                    let before = state.clone();
                    let right = self.eval(right_node, state, call_depth);
                    *state = join_states(before, state.clone());
                    join_values(left, right)
                }
            },
            "||" => match truthy(&left) {
                Some(true) => left,
                Some(false) => self.eval(right_node, state, call_depth),
                None => {
                    let before = state.clone();
                    let right = self.eval(right_node, state, call_depth);
                    *state = join_states(before, state.clone());
                    join_values(left, right)
                }
            },
            "??" => match left {
                Value::Null | Value::Undefined => self.eval(right_node, state, call_depth),
                Value::Unknown => {
                    let before = state.clone();
                    let right = self.eval(right_node, state, call_depth);
                    *state = join_states(before, state.clone());
                    join_values(Value::Unknown, right)
                }
                value => value,
            },
            _ => {
                let right = self.eval(right_node, state, call_depth);
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
                    self.assign_target(argument, Value::Unknown, state, call_depth);
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
                let mut yes = state.clone();
                let mut no = state.clone();
                let yes_value = consequence.map_or(Value::Unknown, |value| {
                    self.eval(value, &mut yes, call_depth)
                });
                let no_value = alternative.map_or(Value::Unknown, |value| {
                    self.eval(value, &mut no, call_depth)
                });
                *state = join_states(yes, no);
                join_values(yes_value, no_value)
            }
        }
    }

    fn assignment(&mut self, node: &HirNode, state: &mut State, call_depth: usize) -> Value {
        let value = node
            .child(HirField::Right)
            .map_or(Value::Unknown, |right| self.eval(right, state, call_depth));
        if let Some(left) = node.child(HirField::Left) {
            self.assign_target(left, value.clone(), state, call_depth);
        }
        value
    }

    fn assign_target(
        &mut self,
        node: &HirNode,
        value: Value,
        state: &mut State,
        call_depth: usize,
    ) {
        match node.kind() {
            HirKind::Identifier => state.assign(self.text(node), value),
            HirKind::ObjectPattern | HirKind::ArrayPattern => {
                self.assign_pattern(node, value, state, BindingMode::Assign, call_depth);
            }
            HirKind::ParenthesizedExpression => {
                if let Some(target) = named_children(node).next() {
                    self.assign_target(target, value, state, call_depth);
                }
            }
            HirKind::MemberExpression | HirKind::SubscriptExpression => {
                let object = node
                    .child(HirField::Object)
                    .map_or(Value::Unknown, |object| {
                        self.eval(object, state, call_depth)
                    });
                let property = self.member_name(node, state, call_depth);
                match (&object, property.as_deref()) {
                    (Value::Module(module), Some(property)) => {
                        if let Some(member) = module_member(*module, property) {
                            state.owned_members.remove(&(*module, member));
                        } else {
                            state.invalidate_module(*module);
                        }
                    }
                    _ => state.invalidate_value(&object),
                }
            }
            _ => {}
        }
    }

    fn assign_pattern(
        &mut self,
        node: &HirNode,
        value: Value,
        state: &mut State,
        mode: BindingMode,
        call_depth: usize,
    ) {
        match node.kind() {
            HirKind::Identifier | HirKind::ShorthandPropertyIdentifier => match mode {
                BindingMode::Assign | BindingMode::Var => {
                    state.assign(self.text(node), value);
                }
                BindingMode::Lexical => state.declare(self.text(node), value),
            },
            HirKind::ObjectPattern => {
                for child in named_children(node) {
                    match child.kind() {
                        HirKind::ShorthandPropertyIdentifier => {
                            let property = self.text(child);
                            let selected = property_value(&value, property, state);
                            self.assign_pattern(child, selected, state, mode, call_depth);
                        }
                        HirKind::Pair => {
                            let property = child
                                .child(HirField::Key)
                                .and_then(|key| self.property_name(key, state, call_depth));
                            let selected = property.as_deref().map_or(Value::Unknown, |property| {
                                property_value(&value, property, state)
                            });
                            if let Some(target) = child.child(HirField::Value) {
                                self.assign_pattern(target, selected, state, mode, call_depth);
                            }
                        }
                        _ => {
                            self.predeclare_pattern(child, state, matches!(mode, BindingMode::Var))
                        }
                    }
                }
            }
            HirKind::ArrayPattern => {
                let values = match value {
                    Value::Array(values) => values,
                    _ => Vec::new(),
                };
                for (index, child) in named_children(node).enumerate() {
                    let selected = values.get(index).cloned().unwrap_or(Value::Unknown);
                    self.assign_pattern(child, selected, state, mode, call_depth);
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
                    self.assign_pattern(target, value, state, mode, call_depth);
                }
            }
            HirKind::RestPattern => {
                if let Some(target) = named_children(node).next() {
                    self.assign_pattern(target, Value::Unknown, state, mode, call_depth);
                }
            }
            _ => {}
        }
    }

    fn member(&mut self, node: &HirNode, state: &mut State, call_depth: usize) -> Value {
        let object = node
            .child(HirField::Object)
            .map_or(Value::Unknown, |object| {
                self.eval(object, state, call_depth)
            });
        let Some(property) = self.member_name(node, state, call_depth) else {
            return Value::Unknown;
        };
        match object {
            Value::Module(module) => module_member(module, &property).map_or(
                Value::UnknownModuleMember(module),
                |member| {
                    if state.owned_members.contains(&(module, member)) {
                        match module {
                            Module::Fs => Value::Known(KnownFunction::Fs(member)),
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
                    Some(value) if value != Value::Unknown => value,
                    _ => Value::UnknownReceiver(Box::new(Value::Object(properties))),
                }
            }
            Value::Array(values) => Value::UnknownReceiver(Box::new(Value::Array(values))),
            Value::ObjectBuiltin if property == "defineProperty" => {
                Value::Known(KnownFunction::DefineProperty)
            }
            Value::Process if property == "env" => Value::Environment,
            Value::Environment if property == "HOME" => Value::String(self.home.to_owned()),
            _ => Value::Unknown,
        }
    }

    fn member_name(
        &mut self,
        node: &HirNode,
        state: &mut State,
        call_depth: usize,
    ) -> Option<String> {
        if let Some(property) = node.child(HirField::Property) {
            return Some(self.text(property).to_owned());
        }
        node.child(HirField::Index)
            .map(|index| self.eval(index, state, call_depth))
            .and_then(|value| value_string(&value).map(str::to_owned))
    }

    fn call(&mut self, node: &HirNode, state: &mut State, call_depth: usize) -> Value {
        let callable = node
            .child(HirField::Function)
            .map_or(Value::Unknown, |function| {
                self.eval(function, state, call_depth)
            });
        let arguments = node.child(HirField::Arguments).map_or_else(
            || Arguments {
                values: Vec::new(),
                complete: false,
            },
            |arguments| self.arguments(arguments, state, call_depth),
        );
        match callable {
            Value::Require => self.require(arguments),
            Value::Eval => self.eval_source(arguments, state),
            Value::Known(function) => self.call_known(function, arguments, state),
            Value::Function(function) => self.call_local(&function, arguments, state, call_depth),
            Value::UnknownModuleMember(module) => {
                state.invalidate_module(module);
                Value::Unknown
            }
            Value::UnknownReceiver(receiver) => {
                state.invalidate_value(&receiver);
                Value::Unknown
            }
            _ => {
                for value in &arguments.values {
                    state.invalidate_value(value);
                }
                Value::Unknown
            }
        }
    }

    fn arguments(&mut self, node: &HirNode, state: &mut State, call_depth: usize) -> Arguments {
        let mut arguments = Arguments {
            values: Vec::new(),
            complete: !delimited_has_hole(node, self.source),
        };
        for child in named_children(node) {
            if child.kind() == HirKind::SpreadElement {
                let value = named_children(child)
                    .next()
                    .map_or(Value::Unknown, |value| self.eval(value, state, call_depth));
                if let Value::Array(values) = value
                    && arguments.values.len() + values.len() <= MAX_COLLECTION_ITEMS
                {
                    arguments.values.extend(values);
                } else {
                    arguments.complete = false;
                }
            } else {
                arguments.values.push(self.eval(child, state, call_depth));
            }
            if arguments.values.len() > MAX_COLLECTION_ITEMS {
                arguments.complete = false;
                arguments.values.truncate(MAX_COLLECTION_ITEMS);
                self.budget.refuse();
                break;
            }
        }
        arguments
    }

    fn require(&mut self, arguments: Arguments) -> Value {
        if !arguments.complete || arguments.values.len() != 1 {
            return Value::Unknown;
        }
        arguments
            .values
            .first()
            .and_then(value_string)
            .and_then(module_from_source)
            .map_or(Value::Unknown, Value::Module)
    }

    fn eval_source(&mut self, arguments: Arguments, state: &mut State) -> Value {
        if !arguments.complete || arguments.values.len() != 1 {
            return Value::Unknown;
        }
        let Some(source) = arguments.values.first().and_then(value_string) else {
            return Value::Unknown;
        };
        if !self.budget.enter_dynamic_source(source.len()) {
            return Value::Unknown;
        }
        if self.depth + 1 >= 16 {
            self.report.refuse(InlineRefusal::RecursionLimit);
            state.widen();
            return Value::Unknown;
        }
        let module = match super::parser::javascript(source) {
            Ok(module) if module.executable() => module,
            Ok(_) => {
                state.widen();
                return Value::Unknown;
            }
            Err(refusal) => {
                self.report.refuse(refusal);
                state.widen();
                return Value::Unknown;
            }
        };
        let mutates = source_mutates(module.root());
        let mut nested = Interpreter {
            program: self.program,
            source,
            home: self.home,
            platform: self.platform,
            depth: self.depth + 1,
            report: InlineReport::default(),
            budget: Budget::default(),
            return_value: Value::Undefined,
        };
        let mut nested_state = state.clone();
        nested.hoist_vars(module.root(), &mut nested_state);
        nested.exec_sequence(module.root(), &mut nested_state, false, 0);
        let failed = nested.budget.refusal.is_some();
        if let Some(refusal) = nested.budget.refusal {
            nested.report.refuse(refusal);
        }
        self.report.extend(nested.report);
        self.budget.absorb(nested.budget);
        if mutates || failed {
            state.widen();
        } else {
            *state = nested_state;
        }
        Value::Unknown
    }

    fn call_known(
        &mut self,
        function: KnownFunction,
        arguments: Arguments,
        state: &mut State,
    ) -> Value {
        match function {
            KnownFunction::DefineProperty => {
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
            KnownFunction::Fs(member) => {
                let supported = match member {
                    Member::RmSync => {
                        arguments.complete
                            && arguments.values.len() == 2
                            && arguments.values.get(1).is_some_and(recursive_options)
                    }
                    Member::Rm => {
                        arguments.complete
                            && arguments.values.len() == 3
                            && arguments.values.get(1).is_some_and(recursive_options)
                            && arguments.values.get(2).is_some_and(empty_callback)
                    }
                    _ => false,
                };
                if supported && let Some(target) = arguments.values.first().and_then(value_string) {
                    self.add_destructive_target(target);
                }
                Value::Undefined
            }
            KnownFunction::Child(member) => {
                match member {
                    Member::Exec | Member::ExecSync => {
                        if arguments.complete
                            && arguments.values.len() == 1
                            && let Some(code) = arguments.values.first().and_then(value_string)
                        {
                            super::super::common::add_exact_shell(
                                &mut self.report,
                                code,
                                self.platform,
                            );
                        }
                    }
                    Member::Spawn | Member::SpawnSync | Member::ExecFile | Member::ExecFileSync => {
                        if let Some(argv) = child_argv(&arguments) {
                            super::super::common::add_exact_argv(&mut self.report, argv);
                        }
                    }
                    Member::Rm | Member::RmSync => {}
                }
                Value::Unknown
            }
        }
    }

    fn call_local(
        &mut self,
        function: &LocalFunction,
        arguments: Arguments,
        state: &mut State,
        call_depth: usize,
    ) -> Value {
        if call_depth >= MAX_CALL_DEPTH || !arguments.complete {
            return Value::Unknown;
        }
        if state.scopes.len() < function.required_scope_depth {
            return Value::Unknown;
        }
        if function.source_identity != self.source.as_ptr() as usize {
            return Value::Unknown;
        }
        let Some(parameters) = &function.parameters else {
            return Value::Unknown;
        };
        if parameters.len() != arguments.values.len() {
            return Value::Unknown;
        }
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
            if control == Control::Return {
                self.return_value.clone()
            } else {
                Value::Undefined
            }
        };
        state.pop_scope();
        value
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
            required_scope_depth: state.scopes.len(),
            source_identity: self.source.as_ptr() as usize,
            body,
        })))
    }

    fn parameters(&self, node: &HirNode) -> Option<Vec<String>> {
        if let Some(parameter) = node.child(HirField::Parameter) {
            return (parameter.kind() == HirKind::Identifier)
                .then(|| vec![self.text(parameter).to_owned()]);
        }
        let Some(parameters) = node.child(HirField::Parameters) else {
            return Some(Vec::new());
        };
        let mut names = Vec::new();
        for parameter in named_children(parameters) {
            if parameter.kind() != HirKind::Identifier {
                return None;
            }
            names.push(self.text(parameter).to_owned());
        }
        Some(names)
    }

    fn template(&mut self, node: &HirNode, state: &mut State, call_depth: usize) -> Value {
        let mut value = String::new();
        for child in node.children() {
            let part = match child.kind() {
                HirKind::StringFragment => Some(self.text(child).to_owned()),
                HirKind::EscapeSequence => decode_escape(self.text(child)),
                HirKind::TemplateSubstitution => named_children(child)
                    .next()
                    .map(|expression| self.eval(expression, state, call_depth))
                    .and_then(|value| string_coercion(&value)),
                HirKind::Token | HirKind::Comment => continue,
                _ => None,
            };
            let Some(part) = part else {
                return Value::Unknown;
            };
            let Some(bytes) = value.len().checked_add(part.len()) else {
                self.budget.refuse();
                return Value::Unknown;
            };
            if !self.budget.admit_bytes(Some(bytes)) {
                return Value::Unknown;
            }
            value.push_str(&part);
        }
        Value::String(value)
    }

    fn array(&mut self, node: &HirNode, state: &mut State, call_depth: usize) -> Value {
        if delimited_has_hole(node, self.source) {
            return Value::Unknown;
        }
        let mut values = Vec::new();
        for child in named_children(node) {
            if child.kind() == HirKind::SpreadElement {
                let spread = named_children(child)
                    .next()
                    .map_or(Value::Unknown, |value| self.eval(value, state, call_depth));
                let Value::Array(spread) = spread else {
                    return Value::Unknown;
                };
                values.extend(spread);
            } else {
                values.push(self.eval(child, state, call_depth));
            }
            if values.len() > MAX_COLLECTION_ITEMS
                || !self.budget.admit_bytes(values_bytes(&values))
            {
                return Value::Unknown;
            }
        }
        Value::Array(values)
    }

    fn object(&mut self, node: &HirNode, state: &mut State, call_depth: usize) -> Value {
        let mut properties = BTreeMap::new();
        for child in named_children(node) {
            let (name, value) = match child.kind() {
                HirKind::Pair => {
                    let Some(name) = child
                        .child(HirField::Key)
                        .and_then(|key| self.property_name(key, state, call_depth))
                    else {
                        if let Some(value) = child.child(HirField::Value) {
                            self.eval(value, state, call_depth);
                        }
                        return Value::Unknown;
                    };
                    let value = child
                        .child(HirField::Value)
                        .map_or(Value::Unknown, |value| self.eval(value, state, call_depth));
                    (name, value)
                }
                HirKind::ShorthandPropertyIdentifier => {
                    let name = self.text(child).to_owned();
                    let value = state.get(&name);
                    (name, value)
                }
                HirKind::MethodDefinition => {
                    let Some(name) = child
                        .child(HirField::Name)
                        .and_then(|name| self.property_name(name, state, call_depth))
                    else {
                        return Value::Unknown;
                    };
                    (name, Value::Unknown)
                }
                HirKind::SpreadElement => {
                    let spread = named_children(child)
                        .next()
                        .map_or(Value::Unknown, |value| self.eval(value, state, call_depth));
                    let Value::Object(spread) = spread else {
                        return Value::Unknown;
                    };
                    for (name, value) in spread {
                        properties.insert(name, value);
                    }
                    continue;
                }
                _ => return Value::Unknown,
            };
            if properties.insert(name, value).is_some()
                || properties.len() > MAX_COLLECTION_ITEMS
                || !self.budget.admit_bytes(properties_bytes(&properties))
            {
                return Value::Unknown;
            }
        }
        Value::Object(properties)
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

    fn add_destructive_target(&mut self, target: &str) {
        let normalized = normalize_path(target, self.platform);
        let home = normalize_path(self.home, self.platform);
        if normalized == home {
            self.report
                .push(Finding::exact(FindingKind::HomeDestruction));
        }
        if SYSTEM_TREES
            .iter()
            .any(|tree| normalize_path(tree, self.platform) == normalized)
        {
            self.report
                .push(Finding::exact(FindingKind::RootDestruction));
        }
    }

    fn bind_import(&mut self, node: &HirNode, state: &mut State) {
        let source = node
            .child(HirField::Source)
            .map(|source| self.text(source).to_owned());
        let module = source
            .as_deref()
            .and_then(|source| self.decode_string(source))
            .as_deref()
            .and_then(module_from_source);
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
                        let Some(name_node) = specifier.child(HirField::Name) else {
                            continue;
                        };
                        let imported = self.text(name_node);
                        let local = specifier
                            .child(HirField::Alias)
                            .map_or(imported, |alias| self.text(alias));
                        let value = module
                            .and_then(|module| module_member(module, imported).map(|m| (module, m)))
                            .and_then(|(module, member)| {
                                state.owned_members.contains(&(module, member)).then_some(
                                    match module {
                                        Module::Fs => Value::Known(KnownFunction::Fs(member)),
                                        Module::ChildProcess => {
                                            Value::Known(KnownFunction::Child(member))
                                        }
                                    },
                                )
                            })
                            .unwrap_or(Value::Unknown);
                        state.declare(local, value);
                    }
                }
                _ => {}
            }
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
        "child_process" | "node:child_process" => Some(Module::ChildProcess),
        _ => None,
    }
}

fn module_member(module: Module, property: &str) -> Option<Member> {
    match (module, property) {
        (Module::Fs, "rm") => Some(Member::Rm),
        (Module::Fs, "rmSync") => Some(Member::RmSync),
        (Module::ChildProcess, "exec") => Some(Member::Exec),
        (Module::ChildProcess, "execSync") => Some(Member::ExecSync),
        (Module::ChildProcess, "spawn") => Some(Member::Spawn),
        (Module::ChildProcess, "spawnSync") => Some(Member::SpawnSync),
        (Module::ChildProcess, "execFile") => Some(Member::ExecFile),
        (Module::ChildProcess, "execFileSync") => Some(Member::ExecFileSync),
        _ => None,
    }
}

fn property_value(value: &Value, property: &str, state: &State) -> Value {
    match value {
        Value::Object(properties) => properties.get(property).cloned().unwrap_or(Value::Unknown),
        Value::Module(module) => {
            module_member(*module, property).map_or(Value::Unknown, |member| {
                if state.owned_members.contains(&(*module, member)) {
                    match module {
                        Module::Fs => Value::Known(KnownFunction::Fs(member)),
                        Module::ChildProcess => Value::Known(KnownFunction::Child(member)),
                    }
                } else {
                    Value::Unknown
                }
            })
        }
        _ => Value::Unknown,
    }
}

fn recursive_options(value: &Value) -> bool {
    let Value::Object(properties) = value else {
        return false;
    };
    properties.get("recursive") == Some(&Value::Bool(true))
        && properties.iter().all(|(name, value)| match name.as_str() {
            "recursive" | "force" => matches!(value, Value::Bool(_)),
            _ => false,
        })
}

fn empty_callback(value: &Value) -> bool {
    let Value::Function(function) = value else {
        return false;
    };
    function.parameters.as_deref() == Some(&[])
        && !function.expression_body
        && named_children(&function.body).next().is_none()
}

fn child_argv(arguments: &Arguments) -> Option<Vec<String>> {
    if !arguments.complete || !(1..=2).contains(&arguments.values.len()) {
        return None;
    }
    let program = arguments.values.first().and_then(value_string)?.to_owned();
    let mut argv = vec![program];
    if let Some(Value::Array(values)) = arguments.values.get(1) {
        for value in values {
            argv.push(value_string(value)?.to_owned());
        }
    } else if arguments.values.len() == 2 {
        return None;
    }
    Some(argv)
}

fn value_string(value: &Value) -> Option<&str> {
    match value {
        Value::String(value) => Some(value),
        _ => None,
    }
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

fn truthy(value: &Value) -> Option<bool> {
    match value {
        Value::Unknown | Value::UnknownModuleMember(_) | Value::UnknownReceiver(_) => None,
        Value::Undefined | Value::Null => Some(false),
        Value::Bool(value) => Some(*value),
        Value::Number(value) => Some(*value != 0),
        Value::String(value) => Some(!value.is_empty()),
        Value::Array(_)
        | Value::Object(_)
        | Value::Module(_)
        | Value::Known(_)
        | Value::Function(_)
        | Value::Require
        | Value::Eval
        | Value::ObjectBuiltin
        | Value::Process
        | Value::Environment => Some(true),
    }
}

fn strict_equal(left: &Value, right: &Value) -> Option<bool> {
    match (left, right) {
        (Value::Undefined, Value::Undefined) | (Value::Null, Value::Null) => Some(true),
        (Value::Bool(left), Value::Bool(right)) => Some(left == right),
        (Value::Number(left), Value::Number(right)) => Some(left == right),
        (Value::String(left), Value::String(right)) => Some(left == right),
        (Value::Unknown, _) | (_, Value::Unknown) => None,
        _ => Some(false),
    }
}

fn loose_equal(left: &Value, right: &Value) -> Option<bool> {
    match (left, right) {
        (Value::Undefined, Value::Null) | (Value::Null, Value::Undefined) => Some(true),
        (Value::Undefined, Value::Undefined)
        | (Value::Null, Value::Null)
        | (Value::Bool(_), Value::Bool(_))
        | (Value::Number(_), Value::Number(_))
        | (Value::String(_), Value::String(_)) => strict_equal(left, right),
        (Value::Unknown, _) | (_, Value::Unknown) => None,
        _ => None,
    }
}

fn join_values(left: Value, right: Value) -> Value {
    if left == right { left } else { Value::Unknown }
}

fn join_states(mut left: State, right: State) -> State {
    if left.scopes.len() != right.scopes.len() {
        return State {
            scopes: left
                .scopes
                .into_iter()
                .map(|scope| Scope {
                    function: scope.function,
                    bindings: scope
                        .bindings
                        .into_keys()
                        .map(|name| (name, Value::Unknown))
                        .collect(),
                })
                .collect(),
            owned_members: left
                .owned_members
                .intersection(&right.owned_members)
                .copied()
                .collect(),
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

fn normalize_path(path: &str, platform: Platform) -> String {
    let mut path = path.trim().replace('\\', "/");
    if platform == Platform::Windows {
        path.make_ascii_lowercase();
    }
    let (prefix, rest) = if let Some(rest) = path.strip_prefix('/') {
        ("/".to_owned(), rest)
    } else if platform == Platform::Windows
        && path.as_bytes().get(1) == Some(&b':')
        && path.as_bytes().get(2) == Some(&b'/')
    {
        (path[..3].to_owned(), &path[3..])
    } else {
        return path.trim_end_matches('/').to_owned();
    };
    let mut components = Vec::new();
    for component in rest.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                components.pop();
            }
            _ => components.push(component),
        }
    }
    if components.is_empty() {
        prefix
    } else {
        format!("{prefix}{}", components.join("/"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(code: &str) -> InlineReport {
        analyze(
            "node",
            &InlineInput {
                program: "node",
                code,
                home: "/home/dev",
                platform: Platform::Linux,
            },
            None,
            0,
        )
    }

    fn root(code: &str) -> bool {
        report(code).contains_exact(FindingKind::RootDestruction)
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
    fn dormant_code_getters_builders_and_dynamic_constructors_are_inert() {
        let dangerous = "require('child_process').execSync('rm -rf /')";
        for code in [
            format!("function dormant(){{{dangerous}}}"),
            format!("setTimeout(()=>{dangerous}, 0)"),
            format!("const value={{get danger(){{{dangerous}}}}}"),
            format!("builder({dangerous:?})"),
            format!("new Function({dangerous:?})()"),
        ] {
            assert_eq!(report(&code), InlineReport::default(), "{code}");
        }
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
            assert_eq!(report(code), InlineReport::default(), "{code}");
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
            assert_eq!(report(code), InlineReport::default(), "{code}");
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
            assert_eq!(report(code), InlineReport::default(), "{code}");
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
            assert_eq!(report(&code), InlineReport::default(), "{code}");
        }
    }
}
