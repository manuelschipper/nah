//! Collects local function definitions by name, preserving the parser's
//! arena lifetime so the effect visitor can later walk a reachable function's
//! body. Collection is a manual recursion (not the `Visit` trait) because the
//! trait hands out short-lived borrows, and reachability needs `'a` references
//! it can revisit after the top-level pass.

use std::collections::{HashMap, HashSet};
use std::ops::{Deref, DerefMut};

use oxc_ast::ast::{
    BindingPattern, Class, ClassElement, Declaration, ExportDefaultDeclarationKind, Expression,
    ForStatementInit, FormalParameters, Function, FunctionBody, MethodDefinitionKind, Program,
    PropertyKind, Statement, VariableDeclarationKind, VariableDeclarator,
};
use oxc_span::{GetSpan, Span};

use super::unparen;

/// A locally defined function: its simple positional parameter names (in order;
/// a destructuring parameter contributes an empty name that never binds, so it
/// stays symbolic) and its body. Rest parameter names bind remaining call
/// arguments.
pub(super) struct FnInfo<'a> {
    binding_scope: Span,
    /// Assignment expression that installed this function, when it was not
    /// introduced by a declaration or declarator.
    assignment_span: Option<u32>,
    /// End of a function-valued variable's initializer. Function declarations
    /// are hoisted and therefore have no initialization boundary.
    initialized_at: Option<u32>,
    pub params: Vec<String>,
    pub param_bindings: HashSet<String>,
    pub parameters: &'a FormalParameters<'a>,
    /// The name visible only inside a named function expression.
    pub self_binding: Option<String>,
    pub is_async: bool,
    pub is_generator: bool,
    pub expression_body: bool,
    pub body: &'a FunctionBody<'a>,
    /// A local receiver decision, or `None` when the named function uses its
    /// module's process evidence.
    pub process_scope: Option<bool>,
}

struct ReceiverBinding {
    binding_scope: Span,
    initializer_span: Span,
    initialized_at: u32,
    kind: JsReceiverKind,
}

enum JsReceiverKind {
    Class,
    Instance(String),
    Object,
    Unknown,
}

/// name -> definitions of locally defined functions from declarations,
/// declarators, and assignment expressions.
pub(super) struct FnTable<'a> {
    functions: HashMap<String, Vec<FnInfo<'a>>>,
    declared_callables: Vec<String>,
    receiver_bindings: HashMap<String, Vec<ReceiverBinding>>,
    reassigned_receivers: HashSet<u32>,
    reassigned_members: HashSet<(u32, String)>,
    reassigned_member_owners: HashSet<u32>,
    pub plus_coercion_callbacks: PlusCoercionTable<'a>,
    pub class_plus_coercion_callbacks: ClassPlusCoercionTable<'a>,
    pub class_constructor_returns: ClassConstructorReturnTable<'a>,
}

pub(super) type PlusCoercionTable<'a> = HashMap<u32, Vec<&'a Expression<'a>>>;
pub(super) type ClassPlusCoercionTable<'a> = HashMap<u32, Vec<&'a Function<'a>>>;
pub(super) type ClassConstructorReturnTable<'a> = HashMap<u32, Vec<&'a Expression<'a>>>;

impl<'a> FnTable<'a> {
    fn new() -> Self {
        Self {
            functions: HashMap::new(),
            declared_callables: Vec::new(),
            receiver_bindings: HashMap::new(),
            reassigned_receivers: HashSet::new(),
            reassigned_members: HashSet::new(),
            reassigned_member_owners: HashSet::new(),
            plus_coercion_callbacks: PlusCoercionTable::new(),
            class_plus_coercion_callbacks: ClassPlusCoercionTable::new(),
            class_constructor_returns: ClassConstructorReturnTable::new(),
        }
    }

    pub(super) fn declared_callables(&self) -> &[String] {
        &self.declared_callables
    }

    fn declare(&mut self, name: String) {
        if !self.declared_callables.contains(&name) {
            self.declared_callables.push(name);
        }
    }

    fn bind_receiver(
        &mut self,
        owner: &str,
        value: &Expression<'_>,
        binding_scope: Span,
        initialized_at: u32,
    ) {
        let kind = match unparen(value) {
            Expression::ClassExpression(_) => JsReceiverKind::Class,
            Expression::NewExpression(new) => match unparen(&new.callee) {
                Expression::Identifier(class) => {
                    JsReceiverKind::Instance(class.name.as_str().to_string())
                }
                _ => JsReceiverKind::Unknown,
            },
            Expression::ObjectExpression(_) => JsReceiverKind::Object,
            _ => JsReceiverKind::Unknown,
        };
        self.receiver_bindings
            .entry(owner.to_string())
            .or_default()
            .push(ReceiverBinding {
                binding_scope,
                initializer_span: value.span(),
                initialized_at,
                kind,
            });
    }

    fn bind_class(&mut self, owner: &str, binding_scope: Span, initializer_span: Span) {
        self.receiver_bindings
            .entry(owner.to_string())
            .or_default()
            .push(ReceiverBinding {
                binding_scope,
                initializer_span,
                initialized_at: initializer_span.end,
                kind: JsReceiverKind::Class,
            });
    }

    fn reassign_receiver(
        &mut self,
        owner: &str,
        value: &Expression<'_>,
        binding_scope: Span,
        assignment_span: Span,
    ) {
        if let Some(initialized_at) = self
            .receiver_binding(owner, assignment_span)
            .map(|binding| binding.initialized_at)
        {
            self.reassigned_receivers.insert(initialized_at);
        }
        self.bind_receiver(owner, value, binding_scope, assignment_span.end);
        self.reassigned_receivers.insert(assignment_span.end);
    }

    fn receiver_binding(&self, owner: &str, use_span: Span) -> Option<&ReceiverBinding> {
        self.receiver_bindings
            .get(owner)?
            .iter()
            .filter(|binding| {
                binding.binding_scope.start <= use_span.start
                    && use_span.end <= binding.binding_scope.end
                    && (binding.initialized_at <= use_span.start
                        || binding.initializer_span.start <= use_span.start
                            && use_span.end <= binding.initializer_span.end)
            })
            .min_by_key(|binding| {
                (
                    binding.binding_scope.end - binding.binding_scope.start,
                    u32::MAX - binding.initialized_at,
                )
            })
    }

    fn member_was_reassigned(&self, receiver: &ReceiverBinding, method: &str) -> bool {
        self.reassigned_receivers.contains(&receiver.initialized_at)
            || self
                .reassigned_member_owners
                .contains(&receiver.initialized_at)
            || self
                .reassigned_members
                .contains(&(receiver.initialized_at, method.to_string()))
    }

    pub(super) fn object_member<'t>(
        &'t self,
        owner: &str,
        method: &str,
        use_span: Span,
    ) -> Option<(&'t FnInfo<'a>, Span)> {
        let binding = self.receiver_binding(owner, use_span)?;
        if self.member_was_reassigned(binding, method)
            || !matches!(binding.kind, JsReceiverKind::Object)
        {
            return None;
        }
        resolve_member(self, &format!("{owner}.{method}"), binding.initialized_at)
            .map(|function| (function, binding.binding_scope))
    }

    pub(super) fn instance_member<'t>(
        &'t self,
        owner: &str,
        method: &str,
        use_span: Span,
    ) -> Option<(&'t FnInfo<'a>, Span, &'t str, Span)> {
        let receiver = self.receiver_binding(owner, use_span)?;
        if self.member_was_reassigned(receiver, method) {
            return None;
        }
        let JsReceiverKind::Instance(class) = &receiver.kind else {
            return None;
        };
        let (function, class_scope) = self.class_member(class, method, use_span)?;
        Some((function, receiver.binding_scope, class, class_scope))
    }

    pub(super) fn class_member<'t>(
        &'t self,
        class: &str,
        method: &str,
        use_span: Span,
    ) -> Option<(&'t FnInfo<'a>, Span)> {
        let binding = self.receiver_binding(class, use_span)?;
        if !matches!(binding.kind, JsReceiverKind::Class) {
            return None;
        }
        resolve_member(self, &format!("{class}.{method}"), binding.initialized_at)
            .map(|function| (function, binding.binding_scope))
    }
}

impl<'a> Deref for FnTable<'a> {
    type Target = HashMap<String, Vec<FnInfo<'a>>>;

    fn deref(&self) -> &Self::Target {
        &self.functions
    }
}

impl DerefMut for FnTable<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.functions
    }
}

/// Positional parameter names; a destructured parameter contributes an empty
/// name so later parameters keep their positions.
pub(super) fn param_names(params: &FormalParameters) -> Vec<String> {
    params
        .items
        .iter()
        .map(|item| match &item.pattern {
            BindingPattern::BindingIdentifier(id) => id.name.as_str().to_string(),
            _ => String::new(),
        })
        .collect()
}

pub(super) fn param_binding_names(params: &FormalParameters) -> HashSet<String> {
    let mut names = HashSet::new();
    for param in &params.items {
        super::collect_binding_names(&param.pattern, &mut names);
    }
    if let Some(rest) = &params.rest {
        super::collect_binding_names(&rest.rest.argument, &mut names);
    }
    names
}

pub(super) fn collect<'a>(program: &'a Program<'a>) -> FnTable<'a> {
    let mut table = FnTable::new();
    stmts(&program.body, &mut table, 0, program.span, program.span);
    table
}

pub(super) fn resolve<'t, 'a>(
    table: &'t FnTable<'a>,
    name: &str,
    use_span: Span,
) -> Option<&'t FnInfo<'a>> {
    table
        .get(name)?
        .iter()
        .rev()
        .filter(|function| {
            function.assignment_span.is_none()
                && function.binding_scope.start <= use_span.start
                && use_span.end <= function.binding_scope.end
                && function.initialized_at.is_none_or(|initialized_at| {
                    initialized_at <= use_span.start
                        || function.body.span.start <= use_span.start
                            && use_span.end <= function.body.span.end
                })
        })
        .min_by_key(|function| function.binding_scope.end - function.binding_scope.start)
}

pub(super) fn resolve_assignment<'t, 'a>(
    table: &'t FnTable<'a>,
    name: &str,
    assignment_span: u32,
) -> Option<&'t FnInfo<'a>> {
    table
        .get(name)?
        .iter()
        .find(|function| function.assignment_span == Some(assignment_span))
}

pub(super) fn resolve_declarator<'t, 'a>(
    table: &'t FnTable<'a>,
    name: &str,
    initialized_at: u32,
) -> Option<&'t FnInfo<'a>> {
    table.get(name)?.iter().find(|function| {
        function.assignment_span.is_none() && function.initialized_at == Some(initialized_at)
    })
}

/// Bound recursion so an adversarial deeply-nested source cannot make
/// collection unbounded; anything deeper is simply not indexed (its calls
/// become unresolved boundaries, which is safe).
const MAX_COLLECT_DEPTH: u32 = 64;

fn stmts<'a>(
    list: &'a [Statement<'a>],
    table: &mut FnTable<'a>,
    depth: u32,
    lexical_scope: Span,
    function_scope: Span,
) {
    if depth > MAX_COLLECT_DEPTH {
        return;
    }
    for stmt in list {
        stmt_one(stmt, table, depth, lexical_scope, function_scope);
    }
}

fn stmt_one<'a>(
    stmt: &'a Statement<'a>,
    table: &mut FnTable<'a>,
    depth: u32,
    lexical_scope: Span,
    function_scope: Span,
) {
    if depth > MAX_COLLECT_DEPTH {
        return;
    }
    if let Some(decl) = stmt.as_declaration() {
        declaration(decl, table, depth, lexical_scope, function_scope);
        return;
    }
    match stmt {
        // `export function f() {}` — the declaration sits inside the export.
        Statement::ExportNamedDeclaration(e) => {
            if let Some(decl) = &e.declaration {
                declaration(decl, table, depth, lexical_scope, function_scope);
            }
        }
        Statement::ExportDefaultDeclaration(export) => match &export.declaration {
            ExportDefaultDeclarationKind::FunctionDeclaration(function) => {
                let name = function
                    .id
                    .as_ref()
                    .map(|id| id.name.as_str().to_string())
                    .unwrap_or_else(|| "default".to_string());
                record_function(name, function, table, lexical_scope, None, None, depth);
            }
            ExportDefaultDeclarationKind::FunctionExpression(function) => {
                record_function(
                    "default".to_string(),
                    function,
                    table,
                    lexical_scope,
                    None,
                    None,
                    depth,
                );
            }
            ExportDefaultDeclarationKind::ArrowFunctionExpression(function) => {
                record_arrow(
                    "default".to_string(),
                    function,
                    table,
                    lexical_scope,
                    None,
                    None,
                    depth,
                );
            }
            ExportDefaultDeclarationKind::ClassDeclaration(class) => {
                let owner = class
                    .id
                    .as_ref()
                    .map(|id| id.name.as_str())
                    .unwrap_or("default");
                table.bind_class(owner, lexical_scope, class.span);
                record_class_callables(class, owner, table, lexical_scope, None, class.span.end);
            }
            _ => {}
        },
        Statement::BlockStatement(b) => stmts(&b.body, table, depth + 1, b.span, function_scope),
        Statement::IfStatement(s) => {
            stmt_one(
                &s.consequent,
                table,
                depth + 1,
                lexical_scope,
                function_scope,
            );
            if let Some(alt) = &s.alternate {
                stmt_one(alt, table, depth + 1, lexical_scope, function_scope);
            }
        }
        Statement::ForStatement(s) => {
            if let Some(ForStatementInit::VariableDeclaration(v)) = &s.init {
                let binding_scope = if v.kind == VariableDeclarationKind::Var {
                    function_scope
                } else {
                    s.span
                };
                for d in &v.declarations {
                    declarator(d, table, depth, binding_scope);
                }
            }
            stmt_one(&s.body, table, depth + 1, s.span, function_scope);
        }
        Statement::ForInStatement(s) => stmt_one(&s.body, table, depth + 1, s.span, function_scope),
        Statement::ForOfStatement(s) => stmt_one(&s.body, table, depth + 1, s.span, function_scope),
        Statement::WhileStatement(s) => stmt_one(&s.body, table, depth + 1, s.span, function_scope),
        Statement::DoWhileStatement(s) => {
            stmt_one(&s.body, table, depth + 1, s.span, function_scope)
        }
        Statement::LabeledStatement(s) => {
            stmt_one(&s.body, table, depth + 1, lexical_scope, function_scope)
        }
        Statement::TryStatement(s) => {
            stmts(
                &s.block.body,
                table,
                depth + 1,
                s.block.span,
                function_scope,
            );
            if let Some(h) = &s.handler {
                stmts(&h.body.body, table, depth + 1, h.body.span, function_scope);
            }
            if let Some(f) = &s.finalizer {
                stmts(&f.body, table, depth + 1, f.span, function_scope);
            }
        }
        Statement::SwitchStatement(s) => {
            for case in &s.cases {
                stmts(&case.consequent, table, depth + 1, s.span, function_scope);
            }
        }
        Statement::ExpressionStatement(s) => {
            collect_assignment(&s.expression, table, depth, lexical_scope)
        }
        _ => {}
    }
}

fn declaration<'a>(
    decl: &'a Declaration<'a>,
    table: &mut FnTable<'a>,
    depth: u32,
    lexical_scope: Span,
    function_scope: Span,
) {
    match decl {
        Declaration::FunctionDeclaration(func) => {
            if let (Some(id), Some(body)) = (&func.id, &func.body) {
                table.declare(id.name.as_str().to_string());
                table
                    .entry(id.name.as_str().to_string())
                    .or_default()
                    .push(FnInfo {
                        binding_scope: lexical_scope,
                        assignment_span: None,
                        initialized_at: None,
                        params: param_names(&func.params),
                        param_bindings: param_binding_names(&func.params),
                        parameters: &func.params,
                        self_binding: None,
                        is_async: func.r#async,
                        is_generator: func.generator,
                        expression_body: false,
                        body,
                        process_scope: super::function_process_scope(body, &func.params),
                    });
                // Index nested named functions too, so a call between siblings
                // inside an executed function resolves.
                stmts(&body.statements, table, depth + 1, body.span, body.span);
            }
        }
        Declaration::VariableDeclaration(v) => {
            let binding_scope = if v.kind == VariableDeclarationKind::Var {
                function_scope
            } else {
                lexical_scope
            };
            for d in &v.declarations {
                declarator(d, table, depth, binding_scope);
            }
        }
        Declaration::ClassDeclaration(class) => {
            if let Some(id) = &class.id {
                table.bind_class(id.name.as_str(), lexical_scope, class.span);
                record_class_callables(
                    class,
                    id.name.as_str(),
                    table,
                    lexical_scope,
                    None,
                    class.span.end,
                );
            }
            record_class_plus_coercion_callbacks(class, table, depth);
        }
        _ => {}
    }
}

fn declarator<'a>(
    d: &'a VariableDeclarator<'a>,
    table: &mut FnTable<'a>,
    depth: u32,
    binding_scope: Span,
) {
    let BindingPattern::BindingIdentifier(id) = &d.id else {
        return;
    };
    let Some(init) = &d.init else {
        return;
    };
    table.bind_receiver(id.name.as_str(), init, binding_scope, d.span.end);
    record_plus_coercion_callbacks(init, &mut table.plus_coercion_callbacks);
    if let Expression::ClassExpression(class) = unparen(init) {
        record_class_callables(
            class,
            id.name.as_str(),
            table,
            binding_scope,
            None,
            d.span.end,
        );
        record_class_plus_coercion_callbacks(class, table, depth);
    }
    record_object_callables(
        init,
        id.name.as_str(),
        table,
        binding_scope,
        None,
        d.span.end,
    );
    match init {
        Expression::FunctionExpression(f) => {
            if let Some(body) = &f.body {
                table.declare(id.name.as_str().to_string());
                table
                    .entry(id.name.as_str().to_string())
                    .or_default()
                    .push(FnInfo {
                        binding_scope,
                        assignment_span: None,
                        initialized_at: Some(d.span.end),
                        params: param_names(&f.params),
                        param_bindings: param_binding_names(&f.params),
                        parameters: &f.params,
                        self_binding: f.id.as_ref().map(|id| id.name.as_str().to_string()),
                        is_async: f.r#async,
                        is_generator: f.generator,
                        expression_body: false,
                        body,
                        process_scope: super::function_process_scope(body, &f.params),
                    });
                stmts(&body.statements, table, depth + 1, body.span, body.span);
            }
        }
        Expression::ArrowFunctionExpression(a) => {
            table.declare(id.name.as_str().to_string());
            table
                .entry(id.name.as_str().to_string())
                .or_default()
                .push(FnInfo {
                    binding_scope,
                    assignment_span: None,
                    initialized_at: Some(d.span.end),
                    params: param_names(&a.params),
                    param_bindings: param_binding_names(&a.params),
                    parameters: &a.params,
                    self_binding: None,
                    is_async: a.r#async,
                    is_generator: false,
                    expression_body: a.expression,
                    body: &a.body,
                    process_scope: super::function_process_scope(&a.body, &a.params),
                });
            stmts(
                &a.body.statements,
                table,
                depth + 1,
                a.body.span,
                a.body.span,
            );
        }
        _ => {}
    }
}

fn collect_assignment<'a>(
    expression: &'a Expression<'a>,
    table: &mut FnTable<'a>,
    depth: u32,
    binding_scope: Span,
) {
    let Expression::AssignmentExpression(assignment) = unparen(expression) else {
        return;
    };
    if !assignment.operator.is_assign() {
        return;
    }
    if super::plus_coercion::plus_coercion_assignment_object(&assignment.left).is_some() {
        table
            .plus_coercion_callbacks
            .insert(assignment.span.start, vec![&assignment.right]);
    }
    match &assignment.left {
        oxc_ast::ast::AssignmentTarget::StaticMemberExpression(member) => {
            if let Expression::Identifier(owner) = unparen(&member.object)
                && let Some(initialized_at) = table
                    .receiver_binding(owner.name.as_str(), assignment.span)
                    .map(|binding| binding.initialized_at)
            {
                table
                    .reassigned_members
                    .insert((initialized_at, member.property.name.as_str().to_string()));
            }
        }
        oxc_ast::ast::AssignmentTarget::ComputedMemberExpression(member) => {
            if let Expression::Identifier(owner) = unparen(&member.object)
                && let Some(initialized_at) = table
                    .receiver_binding(owner.name.as_str(), assignment.span)
                    .map(|binding| binding.initialized_at)
            {
                if let Some(method) = super::literal_property_name(&member.expression) {
                    table
                        .reassigned_members
                        .insert((initialized_at, method.to_string()));
                } else {
                    table.reassigned_member_owners.insert(initialized_at);
                }
            }
        }
        _ => {}
    }
    let oxc_ast::ast::AssignmentTarget::AssignmentTargetIdentifier(id) = &assignment.left else {
        return;
    };
    table.reassign_receiver(
        id.name.as_str(),
        &assignment.right,
        binding_scope,
        assignment.span,
    );
    record_plus_coercion_callbacks(&assignment.right, &mut table.plus_coercion_callbacks);
    if let Expression::ClassExpression(class) = unparen(&assignment.right) {
        record_class_callables(
            class,
            id.name.as_str(),
            table,
            binding_scope,
            Some(assignment.span.start),
            assignment.span.end,
        );
        record_class_plus_coercion_callbacks(class, table, depth);
    }
    record_object_callables(
        &assignment.right,
        id.name.as_str(),
        table,
        binding_scope,
        Some(assignment.span.start),
        assignment.span.end,
    );
    match unparen(&assignment.right) {
        Expression::FunctionExpression(function) => {
            if let Some(body) = &function.body {
                table.declare(id.name.as_str().to_string());
                table
                    .entry(id.name.as_str().to_string())
                    .or_default()
                    .push(FnInfo {
                        binding_scope,
                        assignment_span: Some(assignment.span.start),
                        initialized_at: Some(assignment.span.end),
                        params: param_names(&function.params),
                        param_bindings: param_binding_names(&function.params),
                        parameters: &function.params,
                        self_binding: function.id.as_ref().map(|id| id.name.as_str().to_string()),
                        is_async: function.r#async,
                        is_generator: function.generator,
                        expression_body: false,
                        body,
                        process_scope: super::function_process_scope(body, &function.params),
                    });
                stmts(&body.statements, table, depth + 1, body.span, body.span);
            }
        }
        Expression::ArrowFunctionExpression(function) => {
            table.declare(id.name.as_str().to_string());
            table
                .entry(id.name.as_str().to_string())
                .or_default()
                .push(FnInfo {
                    binding_scope,
                    assignment_span: Some(assignment.span.start),
                    initialized_at: Some(assignment.span.end),
                    params: param_names(&function.params),
                    param_bindings: param_binding_names(&function.params),
                    parameters: &function.params,
                    self_binding: None,
                    is_async: function.r#async,
                    is_generator: false,
                    expression_body: function.expression,
                    body: &function.body,
                    process_scope: super::function_process_scope(&function.body, &function.params),
                });
            stmts(
                &function.body.statements,
                table,
                depth + 1,
                function.body.span,
                function.body.span,
            );
        }
        _ => {}
    }
}

fn record_class_callables<'a>(
    class: &'a Class<'a>,
    owner: &str,
    table: &mut FnTable<'a>,
    binding_scope: Span,
    assignment_span: Option<u32>,
    initialized_at: u32,
) {
    for element in &class.body.body {
        let ClassElement::MethodDefinition(method) = element else {
            continue;
        };
        if let Some(name) = method.key.static_name()
            && let Some(body) = &method.value.body
        {
            let key = format!("{owner}.{name}");
            table.declare(key.clone());
            table.entry(key).or_default().push(FnInfo {
                binding_scope,
                assignment_span,
                initialized_at: Some(initialized_at),
                params: param_names(&method.value.params),
                param_bindings: param_binding_names(&method.value.params),
                parameters: &method.value.params,
                self_binding: None,
                is_async: method.value.r#async,
                is_generator: method.value.generator,
                expression_body: false,
                body,
                process_scope: super::function_process_scope(body, &method.value.params),
            });
            stmts(&body.statements, table, 1, body.span, body.span);
        }
    }
}

fn record_object_callables<'a>(
    expression: &'a Expression<'a>,
    owner: &str,
    table: &mut FnTable<'a>,
    binding_scope: Span,
    assignment_span: Option<u32>,
    initialized_at: u32,
) {
    let Expression::ObjectExpression(object) = unparen(expression) else {
        return;
    };
    for property in &object.properties {
        let Some(property) = property.as_property() else {
            continue;
        };
        let Some(name) = property.key.static_name() else {
            continue;
        };
        let key = format!("{owner}.{name}");
        match unparen(&property.value) {
            Expression::FunctionExpression(function) => record_function(
                key,
                function,
                table,
                binding_scope,
                assignment_span,
                Some(initialized_at),
                0,
            ),
            Expression::ArrowFunctionExpression(function) => record_arrow(
                key,
                function,
                table,
                binding_scope,
                assignment_span,
                Some(initialized_at),
                0,
            ),
            _ => {}
        }
    }
}

fn record_function<'a>(
    name: String,
    function: &'a Function<'a>,
    table: &mut FnTable<'a>,
    binding_scope: Span,
    assignment_span: Option<u32>,
    initialized_at: Option<u32>,
    depth: u32,
) {
    let Some(body) = &function.body else { return };
    table.declare(name.clone());
    table.entry(name).or_default().push(FnInfo {
        binding_scope,
        assignment_span,
        initialized_at,
        params: param_names(&function.params),
        param_bindings: param_binding_names(&function.params),
        parameters: &function.params,
        self_binding: function.id.as_ref().map(|id| id.name.as_str().to_string()),
        is_async: function.r#async,
        is_generator: function.generator,
        expression_body: false,
        body,
        process_scope: super::function_process_scope(body, &function.params),
    });
    stmts(&body.statements, table, depth + 1, body.span, body.span);
}

fn record_arrow<'a>(
    name: String,
    function: &'a oxc_ast::ast::ArrowFunctionExpression<'a>,
    table: &mut FnTable<'a>,
    binding_scope: Span,
    assignment_span: Option<u32>,
    initialized_at: Option<u32>,
    depth: u32,
) {
    table.declare(name.clone());
    table.entry(name).or_default().push(FnInfo {
        binding_scope,
        assignment_span,
        initialized_at,
        params: param_names(&function.params),
        param_bindings: param_binding_names(&function.params),
        parameters: &function.params,
        self_binding: None,
        is_async: function.r#async,
        is_generator: false,
        expression_body: function.expression,
        body: &function.body,
        process_scope: super::function_process_scope(&function.body, &function.params),
    });
    stmts(
        &function.body.statements,
        table,
        depth + 1,
        function.body.span,
        function.body.span,
    );
}

fn resolve_member<'t, 'a>(
    table: &'t FnTable<'a>,
    name: &str,
    initialized_at: u32,
) -> Option<&'t FnInfo<'a>> {
    table
        .get(name)?
        .iter()
        .find(|function| function.initialized_at == Some(initialized_at))
}

fn record_plus_coercion_callbacks<'a>(
    expression: &'a Expression<'a>,
    table: &mut PlusCoercionTable<'a>,
) {
    let Expression::ObjectExpression(object) = unparen(expression) else {
        return;
    };
    let callbacks = plus_coercion_callbacks(expression);
    if !callbacks.is_empty() {
        table.insert(object.span.start, callbacks);
    }
}

fn plus_coercion_callbacks<'a>(expression: &'a Expression<'a>) -> Vec<&'a Expression<'a>> {
    let Expression::ObjectExpression(object) = unparen(expression) else {
        return Vec::new();
    };
    let mut callbacks = Vec::new();
    for property in &object.properties {
        let Some(property) = property.as_property() else {
            continue;
        };
        if !super::plus_coercion::is_plus_coercion_property(&property.key) {
            continue;
        }
        callbacks.push(&property.value);
        if property.kind == PropertyKind::Get
            && let Expression::FunctionExpression(getter) = unparen(&property.value)
            && let Some(body) = &getter.body
        {
            let mut returned = Vec::new();
            let mut saw_bare = false;
            super::resolve::collect_returns(&body.statements, &mut returned, &mut saw_bare);
            callbacks.extend(returned);
        }
    }
    callbacks
}

fn record_class_plus_coercion_callbacks<'a>(
    class: &'a Class<'a>,
    table: &mut FnTable<'a>,
    depth: u32,
) {
    let callbacks = class
        .body
        .body
        .iter()
        .filter_map(|element| match element {
            ClassElement::MethodDefinition(method)
                if !method.r#static
                    && method.kind != MethodDefinitionKind::Set
                    && super::plus_coercion::is_plus_coercion_property(&method.key) =>
            {
                Some(method.value.as_ref())
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    for callback in &callbacks {
        if let Some(body) = &callback.body {
            stmts(&body.statements, table, depth + 1, body.span, body.span);
        }
    }
    if !callbacks.is_empty() {
        table
            .class_plus_coercion_callbacks
            .insert(class.span.start, callbacks);
    }

    let mut returned_callbacks = Vec::new();
    let mut constructor_returns = Vec::new();
    for element in &class.body.body {
        if let ClassElement::PropertyDefinition(property) = element
            && !property.r#static
            && super::plus_coercion::is_plus_coercion_property(&property.key)
            && let Some(value) = &property.value
        {
            returned_callbacks.push(value);
        }
        let ClassElement::MethodDefinition(method) = element else {
            continue;
        };
        if method.kind != MethodDefinitionKind::Constructor {
            continue;
        }
        let Some(body) = &method.value.body else {
            continue;
        };
        record_constructor_returns(
            &body.statements,
            depth + 1,
            &mut HashMap::new(),
            &mut returned_callbacks,
            &mut constructor_returns,
        );
    }
    if !returned_callbacks.is_empty() {
        table
            .plus_coercion_callbacks
            .insert(class.span.start, returned_callbacks);
    }
    if !constructor_returns.is_empty() {
        table
            .class_constructor_returns
            .insert(class.span.start, constructor_returns);
    }
}

fn record_constructor_returns<'a>(
    statements: &'a [Statement<'a>],
    depth: u32,
    local_callbacks: &mut HashMap<String, Vec<&'a Expression<'a>>>,
    returned_callbacks: &mut Vec<&'a Expression<'a>>,
    constructor_returns: &mut Vec<&'a Expression<'a>>,
) {
    if depth > MAX_COLLECT_DEPTH {
        return;
    }
    for statement in statements {
        if let Some(Declaration::VariableDeclaration(declaration)) = statement.as_declaration() {
            for declarator in &declaration.declarations {
                let BindingPattern::BindingIdentifier(identifier) = &declarator.id else {
                    continue;
                };
                let callbacks = declarator
                    .init
                    .as_ref()
                    .map(|init| constructor_return_callbacks(init, local_callbacks))
                    .unwrap_or_default();
                if callbacks.is_empty() {
                    local_callbacks.remove(identifier.name.as_str());
                } else {
                    local_callbacks.insert(identifier.name.as_str().to_string(), callbacks);
                }
            }
            continue;
        }
        match statement {
            Statement::ReturnStatement(returned) => {
                let Some(argument) = &returned.argument else {
                    continue;
                };
                let callbacks = constructor_return_callbacks(argument, local_callbacks);
                if callbacks.is_empty() {
                    constructor_returns.push(argument);
                } else {
                    returned_callbacks.extend(callbacks);
                }
            }
            Statement::BlockStatement(block) => record_constructor_returns(
                &block.body,
                depth + 1,
                &mut local_callbacks.clone(),
                returned_callbacks,
                constructor_returns,
            ),
            Statement::IfStatement(statement) => {
                record_constructor_return_statement(
                    &statement.consequent,
                    depth + 1,
                    local_callbacks,
                    returned_callbacks,
                    constructor_returns,
                );
                if let Some(alternate) = &statement.alternate {
                    record_constructor_return_statement(
                        alternate,
                        depth + 1,
                        local_callbacks,
                        returned_callbacks,
                        constructor_returns,
                    );
                }
            }
            Statement::ForStatement(statement) => record_constructor_return_statement(
                &statement.body,
                depth + 1,
                local_callbacks,
                returned_callbacks,
                constructor_returns,
            ),
            Statement::ForInStatement(statement) => record_constructor_return_statement(
                &statement.body,
                depth + 1,
                local_callbacks,
                returned_callbacks,
                constructor_returns,
            ),
            Statement::ForOfStatement(statement) => record_constructor_return_statement(
                &statement.body,
                depth + 1,
                local_callbacks,
                returned_callbacks,
                constructor_returns,
            ),
            Statement::WhileStatement(statement) => record_constructor_return_statement(
                &statement.body,
                depth + 1,
                local_callbacks,
                returned_callbacks,
                constructor_returns,
            ),
            Statement::DoWhileStatement(statement) => record_constructor_return_statement(
                &statement.body,
                depth + 1,
                local_callbacks,
                returned_callbacks,
                constructor_returns,
            ),
            Statement::LabeledStatement(statement) => record_constructor_return_statement(
                &statement.body,
                depth + 1,
                local_callbacks,
                returned_callbacks,
                constructor_returns,
            ),
            Statement::TryStatement(statement) => {
                record_constructor_returns(
                    &statement.block.body,
                    depth + 1,
                    &mut local_callbacks.clone(),
                    returned_callbacks,
                    constructor_returns,
                );
                if let Some(handler) = &statement.handler {
                    record_constructor_returns(
                        &handler.body.body,
                        depth + 1,
                        &mut local_callbacks.clone(),
                        returned_callbacks,
                        constructor_returns,
                    );
                }
                if let Some(finalizer) = &statement.finalizer {
                    record_constructor_returns(
                        &finalizer.body,
                        depth + 1,
                        &mut local_callbacks.clone(),
                        returned_callbacks,
                        constructor_returns,
                    );
                }
            }
            Statement::SwitchStatement(statement) => {
                for case in &statement.cases {
                    record_constructor_returns(
                        &case.consequent,
                        depth + 1,
                        &mut local_callbacks.clone(),
                        returned_callbacks,
                        constructor_returns,
                    );
                }
            }
            _ => {}
        }
    }
}

fn record_constructor_return_statement<'a>(
    statement: &'a Statement<'a>,
    depth: u32,
    local_callbacks: &HashMap<String, Vec<&'a Expression<'a>>>,
    returned_callbacks: &mut Vec<&'a Expression<'a>>,
    constructor_returns: &mut Vec<&'a Expression<'a>>,
) {
    record_constructor_returns(
        std::slice::from_ref(statement),
        depth,
        &mut local_callbacks.clone(),
        returned_callbacks,
        constructor_returns,
    );
}

fn constructor_return_callbacks<'a>(
    expression: &'a Expression<'a>,
    local_callbacks: &HashMap<String, Vec<&'a Expression<'a>>>,
) -> Vec<&'a Expression<'a>> {
    let callbacks = plus_coercion_callbacks(expression);
    if !callbacks.is_empty() {
        return callbacks;
    }
    let Expression::Identifier(identifier) = unparen(expression) else {
        return Vec::new();
    };
    local_callbacks
        .get(identifier.name.as_str())
        .cloned()
        .unwrap_or_default()
}
