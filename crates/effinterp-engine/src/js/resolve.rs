//! Callee/module resolution and argument-to-resource lowering for the JS
//! frontend. Kept separate from the visitor so the AST-shape matching lives
//! in one place.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};

use effinterp_proto::{PathPlatform, ResourceExpr, ResourceIdentity};
use im::HashMap as PersistentHashMap;
use oxc_allocator::Allocator;
use oxc_ast::ast::{
    AssignmentTarget, BindingPattern, CallExpression, Declaration, Expression, FunctionBody,
    NewExpression, Program, Statement, StaticMemberExpression, TemplateLiteral, UpdateExpression,
    VariableDeclarationKind, VariableDeclarator,
};
use oxc_ast_visit::{Visit, walk};
use oxc_parser::Parser;
use oxc_span::SourceType;

use super::{Bindings, ModuleCall};
use crate::ImportBinding;
use crate::value::{parse_url_endpoint, unresolved_resource};

const MAX_DYNAMIC_IMPORT_TARGETS: usize = 64;

#[derive(Debug, Clone)]
pub(super) struct DynamicImportCallback {
    pub parameter: String,
    pub aliases: Vec<String>,
    pub chained_calls: HashSet<u32>,
}

#[derive(Debug, Default)]
pub(super) struct DynamicImportFacts {
    pub scoped_imports: Vec<ImportBinding>,
    transparent_constructors: HashSet<u32>,
    quiet_calls: HashSet<u32>,
    literal_imports: HashSet<u32>,
    callbacks: HashMap<u32, DynamicImportCallback>,
}

impl DynamicImportFacts {
    pub(super) fn collect(program: &Program<'_>) -> Self {
        let mut bindings = DynamicBindingCollector::default();
        bindings.visit_program(program);
        if bindings.saturated {
            return Self::default();
        }

        let mut transparent_constructors = HashSet::new();
        let mut wrappers = HashSet::new();
        if !bindings.writes.contains_key("Function") {
            for (name, span_start) in &bindings.wrapper_candidates {
                transparent_constructors.insert(*span_start);
                if bindings.writes.get(name) == Some(&1) {
                    wrappers.insert(name.clone());
                }
            }
        }

        let mut facts = Self {
            transparent_constructors,
            ..Self::default()
        };
        let mut calls = DynamicCallCollector {
            bindings: &bindings,
            wrappers: &wrappers,
            facts: &mut facts,
            walk_depth: 0,
        };
        calls.visit_program(program);
        facts
    }

    pub(super) fn is_transparent_constructor(&self, new_expr: &NewExpression<'_>) -> bool {
        self.transparent_constructors.contains(&new_expr.span.start)
    }

    pub(super) fn is_quiet_call(&self, call: &CallExpression<'_>) -> bool {
        self.quiet_calls.contains(&call.span.start)
    }

    pub(super) fn is_literal_import(&self, span_start: u32) -> bool {
        self.literal_imports.contains(&span_start)
    }

    pub(super) fn callback(&self, call: &CallExpression<'_>) -> Option<&DynamicImportCallback> {
        self.callbacks.get(&call.span.start)
    }
}

#[derive(Default)]
struct DynamicBindingCollector {
    writes: HashMap<String, u32>,
    constant_values: HashMap<String, String>,
    wrapper_candidates: Vec<(String, u32)>,
    in_const: bool,
    walk_depth: u32,
    saturated: bool,
}

impl<'a> Visit<'a> for DynamicBindingCollector {
    fn visit_expression(&mut self, it: &Expression<'a>) {
        if self.walk_depth >= super::MAX_WALK_DEPTH {
            self.saturated = true;
            return;
        }
        self.walk_depth += 1;
        walk::walk_expression(self, it);
        self.walk_depth -= 1;
    }

    fn visit_statement(&mut self, it: &Statement<'a>) {
        if self.walk_depth >= super::MAX_WALK_DEPTH {
            self.saturated = true;
            return;
        }
        self.walk_depth += 1;
        walk::walk_statement(self, it);
        self.walk_depth -= 1;
    }

    fn visit_variable_declaration(&mut self, it: &oxc_ast::ast::VariableDeclaration<'a>) {
        let saved = self.in_const;
        self.in_const = it.kind == VariableDeclarationKind::Const;
        walk::walk_variable_declaration(self, it);
        self.in_const = saved;
    }

    fn visit_variable_declarator(&mut self, it: &VariableDeclarator<'a>) {
        if let (BindingPattern::BindingIdentifier(id), Some(init)) = (&it.id, &it.init) {
            let name = id.name.as_str().to_string();
            if self.in_const
                && let Some(value) = constant_string(init, self)
            {
                self.constant_values.insert(name.clone(), value);
            }
            if let Expression::NewExpression(new_expr) = unwrap_expr(init)
                && transparent_import_constructor(new_expr, self)
            {
                self.wrapper_candidates.push((name, new_expr.span.start));
            }
        }
        walk::walk_variable_declarator(self, it);
    }

    fn visit_binding_identifier(&mut self, it: &oxc_ast::ast::BindingIdentifier<'a>) {
        *self.writes.entry(it.name.as_str().to_string()).or_default() += 1;
    }

    fn visit_assignment_target(&mut self, it: &AssignmentTarget<'a>) {
        if let AssignmentTarget::AssignmentTargetIdentifier(id) = it {
            *self.writes.entry(id.name.as_str().to_string()).or_default() += 1;
        }
        walk::walk_assignment_target(self, it);
    }

    fn visit_update_expression(&mut self, it: &UpdateExpression<'a>) {
        if let oxc_ast::ast::SimpleAssignmentTarget::AssignmentTargetIdentifier(id) = &it.argument {
            *self.writes.entry(id.name.as_str().to_string()).or_default() += 1;
        }
        walk::walk_update_expression(self, it);
    }
}

struct DynamicCallCollector<'v> {
    bindings: &'v DynamicBindingCollector,
    wrappers: &'v HashSet<String>,
    facts: &'v mut DynamicImportFacts,
    walk_depth: u32,
}

impl<'a> Visit<'a> for DynamicCallCollector<'_> {
    fn visit_expression(&mut self, it: &Expression<'a>) {
        if self.walk_depth >= super::MAX_WALK_DEPTH {
            return;
        }
        self.walk_depth += 1;
        walk::walk_expression(self, it);
        self.walk_depth -= 1;
    }

    fn visit_statement(&mut self, it: &Statement<'a>) {
        if self.walk_depth >= super::MAX_WALK_DEPTH {
            return;
        }
        self.walk_depth += 1;
        walk::walk_statement(self, it);
        self.walk_depth -= 1;
    }

    fn visit_import_expression(&mut self, it: &oxc_ast::ast::ImportExpression<'a>) {
        if literal_targets(&it.source, self.bindings).is_some() {
            self.facts.literal_imports.insert(it.span.start);
        }
        walk::walk_import_expression(self, it);
    }

    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        if let Some((loader, callback_expr)) = then_callback(it)
            && let Some(targets) = loader_targets(loader, self.wrappers, self.bindings)
            && let Some((parameter, body)) = callback_parameter(callback_expr)
            && !callback_reassigns(body, parameter)
        {
            let mut aliases = Vec::with_capacity(targets.len());
            for (index, target) in targets.into_iter().enumerate() {
                let alias = format!("#dynamic-import:{}:{index}", loader_span(loader));
                self.facts.scoped_imports.push(ImportBinding {
                    local: alias.clone(),
                    module: canonical_module(&target),
                    imported: None,
                });
                aliases.push(alias);
            }
            self.facts.quiet_calls.insert(it.span.start);
            if let Expression::CallExpression(call) = unwrap_expr(loader) {
                self.facts.quiet_calls.insert(call.span.start);
            }
            if let Expression::ImportExpression(import) = unwrap_expr(loader) {
                self.facts.literal_imports.insert(import.span.start);
            }
            self.facts.callbacks.insert(
                it.span.start,
                DynamicImportCallback {
                    parameter: parameter.to_string(),
                    aliases,
                    chained_calls: chained_callback_calls(callback_expr, body, parameter),
                },
            );
        }
        walk::walk_call_expression(self, it);
    }
}

fn transparent_import_constructor(
    new_expr: &NewExpression<'_>,
    bindings: &DynamicBindingCollector,
) -> bool {
    if !is_function_constructor(new_expr) {
        return false;
    }
    let Some(parameter) = new_expr
        .arguments
        .first()
        .and_then(|argument| argument.as_expression())
        .and_then(|expr| constant_string(expr, bindings))
    else {
        return false;
    };
    let Some(body) = new_expr
        .arguments
        .get(1)
        .and_then(|argument| argument.as_expression())
        .and_then(|expr| constant_string(expr, bindings))
    else {
        return false;
    };
    if new_expr.arguments.len() != 2 {
        return false;
    }

    let source = format!("function __effinterp({parameter}) {{ {body} }}");
    if crate::lang::depth::js_nesting_exceeds(&source) {
        return false;
    }
    let allocator = Allocator::default();
    let parsed = Parser::new(&allocator, &source, SourceType::mjs()).parse();
    if !parsed.errors.is_empty() {
        return false;
    }
    let [Statement::FunctionDeclaration(function)] = parsed.program.body.as_slice() else {
        return false;
    };
    let Some(function_body) = &function.body else {
        return false;
    };
    if !function_body.directives.is_empty()
        || function_body.statements.len() != 1
        || function.params.items.len() != 1
        || function.params.rest.is_some()
    {
        return false;
    }
    let formal = &function.params.items[0];
    let BindingPattern::BindingIdentifier(param) = &formal.pattern else {
        return false;
    };
    if formal.initializer.is_some() {
        return false;
    }
    let Statement::ReturnStatement(returned) = &function_body.statements[0] else {
        return false;
    };
    let Some(Expression::ImportExpression(import)) = returned.argument.as_ref().map(unwrap_expr)
    else {
        return false;
    };
    matches!(unwrap_expr(&import.source), Expression::Identifier(source) if source.name == param.name)
        && import.options.is_none()
        && import.phase.is_none()
}

pub(super) fn is_function_constructor(new_expr: &NewExpression<'_>) -> bool {
    matches!(unwrap_expr(&new_expr.callee), Expression::Identifier(id) if id.name.as_str() == "Function")
}

fn constant_string(expr: &Expression<'_>, bindings: &DynamicBindingCollector) -> Option<String> {
    match unwrap_expr(expr) {
        Expression::StringLiteral(value) => Some(value.value.as_str().to_string()),
        Expression::TemplateLiteral(value) if value.expressions.is_empty() => {
            cooked_template_string(value)
        }
        Expression::Identifier(id) => {
            let name = id.name.as_str();
            (bindings.writes.get(name) == Some(&1))
                .then(|| bindings.constant_values.get(name).cloned())
                .flatten()
        }
        _ => None,
    }
}

pub(super) fn cooked_template_string(template: &TemplateLiteral<'_>) -> Option<String> {
    let mut text = String::new();
    for quasi in &template.quasis {
        text.push_str(quasi.value.cooked.as_ref()?.as_str());
    }
    Some(text)
}

fn literal_targets(
    expr: &Expression<'_>,
    bindings: &DynamicBindingCollector,
) -> Option<Vec<String>> {
    fn collect(
        expr: &Expression<'_>,
        bindings: &DynamicBindingCollector,
        out: &mut Vec<String>,
    ) -> Option<()> {
        if out.len() >= MAX_DYNAMIC_IMPORT_TARGETS {
            return None;
        }
        match unwrap_expr(expr) {
            Expression::ConditionalExpression(conditional) => {
                collect(&conditional.consequent, bindings, out)?;
                collect(&conditional.alternate, bindings, out)
            }
            other => {
                let value = constant_string(other, bindings)?;
                if !out.contains(&value) {
                    out.push(value);
                }
                Some(())
            }
        }
    }

    let mut targets = Vec::new();
    collect(expr, bindings, &mut targets)?;
    (!targets.is_empty()).then_some(targets)
}

fn then_callback<'a>(
    call: &'a CallExpression<'a>,
) -> Option<(&'a Expression<'a>, &'a Expression<'a>)> {
    let Expression::StaticMemberExpression(member) = unwrap_expr(&call.callee) else {
        return None;
    };
    if member.property.name.as_str() != "then" || call.arguments.len() != 1 {
        return None;
    }
    let callback = call.arguments[0].as_expression()?;
    Some((&member.object, callback))
}

fn loader_targets(
    loader: &Expression<'_>,
    wrappers: &HashSet<String>,
    bindings: &DynamicBindingCollector,
) -> Option<Vec<String>> {
    match unwrap_expr(loader) {
        Expression::ImportExpression(import)
            if import.options.is_none() && import.phase.is_none() =>
        {
            literal_targets(&import.source, bindings)
        }
        Expression::CallExpression(call) if call.arguments.len() == 1 => {
            let Expression::Identifier(callee) = unwrap_expr(&call.callee) else {
                return None;
            };
            if !wrappers.contains(callee.name.as_str()) {
                return None;
            }
            literal_targets(call.arguments[0].as_expression()?, bindings)
        }
        _ => None,
    }
}

fn loader_span(loader: &Expression<'_>) -> u32 {
    match unwrap_expr(loader) {
        Expression::ImportExpression(import) => import.span.start,
        Expression::CallExpression(call) => call.span.start,
        _ => 0,
    }
}

fn callback_parameter<'a>(expr: &'a Expression<'a>) -> Option<(&'a str, &'a FunctionBody<'a>)> {
    let (params, body) = match unwrap_expr(expr) {
        Expression::FunctionExpression(function) => (&function.params, function.body.as_deref()?),
        Expression::ArrowFunctionExpression(function) => (&function.params, function.body.as_ref()),
        _ => return None,
    };
    if params.items.len() != 1 || params.rest.is_some() {
        return None;
    }
    let parameter = &params.items[0];
    let BindingPattern::BindingIdentifier(identifier) = &parameter.pattern else {
        return None;
    };
    if parameter.initializer.is_some() {
        return None;
    }
    Some((identifier.name.as_str(), body))
}

fn callback_reassigns(body: &FunctionBody<'_>, parameter: &str) -> bool {
    struct Writes<'a> {
        parameter: &'a str,
        reassigned: bool,
    }
    impl<'a> Visit<'a> for Writes<'_> {
        fn visit_binding_identifier(&mut self, it: &oxc_ast::ast::BindingIdentifier<'a>) {
            self.reassigned |= it.name.as_str() == self.parameter;
        }

        fn visit_assignment_target(&mut self, it: &AssignmentTarget<'a>) {
            if let AssignmentTarget::AssignmentTargetIdentifier(id) = it {
                self.reassigned |= id.name.as_str() == self.parameter;
            }
            walk::walk_assignment_target(self, it);
        }

        fn visit_update_expression(&mut self, it: &UpdateExpression<'a>) {
            if let oxc_ast::ast::SimpleAssignmentTarget::AssignmentTargetIdentifier(id) =
                &it.argument
            {
                self.reassigned |= id.name.as_str() == self.parameter;
            }
            walk::walk_update_expression(self, it);
        }
    }

    let mut writes = Writes {
        parameter,
        reassigned: false,
    };
    writes.visit_function_body(body);
    writes.reassigned
}

fn chained_callback_calls(
    callback: &Expression<'_>,
    body: &FunctionBody<'_>,
    parameter: &str,
) -> HashSet<u32> {
    struct Returns<'a> {
        parameter: &'a str,
        calls: HashSet<u32>,
    }
    impl<'a> Visit<'a> for Returns<'_> {
        fn visit_return_statement(&mut self, it: &oxc_ast::ast::ReturnStatement<'a>) {
            if let Some(call) = it
                .argument
                .as_ref()
                .and_then(|argument| namespace_member_call(argument, self.parameter))
            {
                self.calls.insert(call.span.start);
            }
            walk::walk_return_statement(self, it);
        }
    }

    let mut returns = Returns {
        parameter,
        calls: HashSet::new(),
    };
    returns.visit_function_body(body);
    if matches!(unwrap_expr(callback), Expression::ArrowFunctionExpression(function) if function.expression)
        && let [Statement::ExpressionStatement(statement)] = body.statements.as_slice()
        && let Some(call) = namespace_member_call(&statement.expression, parameter)
    {
        returns.calls.insert(call.span.start);
    }
    returns.calls
}

fn namespace_member_call<'a>(
    expr: &'a Expression<'a>,
    parameter: &str,
) -> Option<&'a CallExpression<'a>> {
    let Expression::CallExpression(call) = unwrap_expr(expr) else {
        return None;
    };
    let Expression::StaticMemberExpression(member) = unwrap_expr(&call.callee) else {
        return None;
    };
    matches!(unwrap_expr(&member.object), Expression::Identifier(id) if id.name.as_str() == parameter)
        .then_some(call)
}

/// Bindings of the current function's parameters to caller argument
/// expressions, used to specialize a parameter identifier at its use site.
pub(super) type ParamEnv = PersistentHashMap<String, ResourceExpr>;

/// Canonicalize a module specifier: drop the `node:` prefix so `node:fs` and
/// `fs` resolve the same, and keep known subpaths like `fs/promises`.
/// `fs-extra` and `graceful-fs` are drop-in `fs` supersets, so their modeled
/// methods canonicalize to `fs`.
pub(super) fn canonical_module(spec: &str) -> String {
    let spec = spec.strip_prefix("node:").unwrap_or(spec);
    match spec {
        "fs-extra" | "graceful-fs" => "fs".to_string(),
        _ => spec.to_string(),
    }
}

/// Strip grouping and `await` so `await import('m')` and `(require('m'))`
/// resolve the same as the bare form.
fn unwrap_expr<'a, 'b>(expr: &'b Expression<'a>) -> &'b Expression<'a> {
    match expr {
        Expression::ParenthesizedExpression(p) => unwrap_expr(&p.expression),
        Expression::AwaitExpression(a) => unwrap_expr(&a.argument),
        Expression::TSAsExpression(e) => unwrap_expr(&e.expression),
        Expression::TSSatisfiesExpression(e) => unwrap_expr(&e.expression),
        Expression::TSTypeAssertion(e) => unwrap_expr(&e.expression),
        Expression::TSNonNullExpression(e) => unwrap_expr(&e.expression),
        Expression::TSInstantiationExpression(e) => unwrap_expr(&e.expression),
        other => other,
    }
}

/// If `expr` is `require('module')`, return the canonical module name.
pub(super) fn require_module(expr: &Expression) -> Option<String> {
    let Expression::CallExpression(call) = unwrap_expr(expr) else {
        return None;
    };
    let Expression::Identifier(id) = &call.callee else {
        return None;
    };
    if id.name.as_str() != "require" {
        return None;
    }
    match call.arguments.first().and_then(|a| a.as_expression()) {
        Some(Expression::StringLiteral(s)) => Some(canonical_module(s.value.as_str())),
        _ => None,
    }
}

/// Whether a callee is `getBuiltinModule` / `process.getBuiltinModule` —
/// Node's builtin-module loader, a binding like `require`, not an effect.
pub(super) fn is_get_builtin_module(callee: &Expression) -> bool {
    match unwrap_expr(callee) {
        Expression::Identifier(id) => id.name.as_str() == "getBuiltinModule",
        Expression::StaticMemberExpression(m) => m.property.name.as_str() == "getBuiltinModule",
        _ => false,
    }
}

/// If `expr` is `process.getBuiltinModule('node:module')` (or the same
/// call through `globalThis.process`), return the canonical module name.
pub(super) fn get_builtin_module(expr: &Expression) -> Option<String> {
    let Expression::CallExpression(call) = unwrap_expr(expr) else {
        return None;
    };
    if !is_get_builtin_module(&call.callee) {
        return None;
    }
    match call.arguments.first().and_then(|a| a.as_expression()) {
        Some(Expression::StringLiteral(s)) => Some(canonical_module(s.value.as_str())),
        _ => None,
    }
}

/// If `expr` is `import('module')` / `await import('module')`, return the
/// canonical specifier. A non-literal specifier stays unresolved.
pub(super) fn dynamic_import_module(expr: &Expression) -> Option<String> {
    let Expression::ImportExpression(imp) = unwrap_expr(expr) else {
        return None;
    };
    match &imp.source {
        Expression::StringLiteral(s) => Some(canonical_module(s.value.as_str())),
        _ => None,
    }
}

/// The module a binding initializer names: `require`, `getBuiltinModule`, or
/// `import()`, after stripping `await` / grouping.
pub(super) fn bound_module(expr: &Expression) -> Option<String> {
    require_module(expr)
        .or_else(|| get_builtin_module(expr))
        .or_else(|| dynamic_import_module(expr))
}

/// The module an expression denotes, following import aliases, `require`, and
/// the `fs.promises` submodule, also where a named import or destructured
/// binding takes `promises` from `fs`.
pub(super) fn module_of(expr: &Expression, bindings: &Bindings) -> Option<String> {
    match expr {
        Expression::Identifier(id) => {
            let name = id.name.as_str();
            bindings.namespaces.get(name).cloned().or_else(|| {
                bindings
                    .named
                    .get(name)
                    .filter(|(module, function)| module == "fs" && function == "promises")
                    .map(|_| "fs/promises".to_string())
            })
        }
        Expression::CallExpression(_) if !bindings.require_shadowed => require_module(expr),
        Expression::ParenthesizedExpression(p) => module_of(&p.expression, bindings),
        // `(await import('fs')).writeFileSync(...)`: only the awaited import
        // is the module namespace; a bare `import()` is its promise. Other
        // awaited receivers stay unresolved, since the caller's local-shadow
        // check does not look through `await`.
        Expression::AwaitExpression(a) => dynamic_import_module(&a.argument),
        Expression::StaticMemberExpression(m) => {
            let base = module_of(&m.object, bindings)?;
            match (base.as_str(), m.property.name.as_str()) {
                ("fs", "promises") => Some("fs/promises".to_string()),
                ("path", "posix") => Some("path/posix".to_string()),
                _ => None,
            }
        }
        _ => None,
    }
}

/// Resolve a call's callee to an effect API `(module, function)`.
pub(super) fn resolve_callee(callee: &Expression, bindings: &Bindings) -> Option<ModuleCall> {
    match callee {
        Expression::ComputedMemberExpression(_) => resolve_callee_reference(callee, bindings),
        // `fs.readFileSync(...)`, `require('fs').readFileSync(...)`,
        // `fs.promises.rm(...)`.
        Expression::StaticMemberExpression(m) => {
            let module = module_of(&m.object, bindings)?;
            Some(ModuleCall {
                module,
                function: m.property.name.as_str().to_string(),
            })
        }
        // A named import/destructured binding: `rm(...)` where
        // `import { rm } from 'fs/promises'`.
        Expression::Identifier(id) => {
            if let Some((module, function)) = bindings.named.get(id.name.as_str()) {
                Some(ModuleCall {
                    module: module.clone(),
                    function: function.clone(),
                })
            } else if id.name.as_str() == "fetch"
                && bindings
                    .namespaces
                    .get(id.name.as_str())
                    .is_some_and(|module| {
                        matches!(module.as_str(), "node-fetch" | "node-fetch-native")
                    })
            {
                Some(ModuleCall {
                    module: bindings.namespaces[id.name.as_str()].clone(),
                    function: "fetch".to_string(),
                })
            } else if id.name.as_str() == "fetch" && !bindings.declared.contains("fetch") {
                Some(ModuleCall {
                    module: "__global__".to_string(),
                    function: "fetch".to_string(),
                })
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Resolve the repository identity of a static imported member call. Unlike
/// effect-API resolution, this preserves the imported symbol path so the
/// repository composer can retract the matching frontend boundary.
pub(super) fn resolve_callee_reference(
    callee: &Expression,
    bindings: &Bindings,
) -> Option<ModuleCall> {
    fn member_path<'e, 'a>(
        expression: &'e Expression<'a>,
    ) -> Option<(&'e Expression<'a>, Vec<String>)> {
        match unwrap_expr(expression) {
            Expression::Identifier(_) | Expression::CallExpression(_) => {
                Some((expression, Vec::new()))
            }
            Expression::StaticMemberExpression(member) => {
                let (head, mut members) = member_path(&member.object)?;
                members.push(member.property.name.as_str().to_string());
                Some((head, members))
            }
            Expression::ComputedMemberExpression(member) => {
                let Expression::StringLiteral(property) = unwrap_expr(&member.expression) else {
                    return None;
                };
                let (head, mut members) = member_path(&member.object)?;
                members.push(property.value.as_str().to_string());
                Some((head, members))
            }
            _ => None,
        }
    }

    fn imported_symbol(name: &str, bindings: &Bindings) -> Option<(String, String)> {
        if let Some((module, imported)) = bindings.named.get(name) {
            return Some((module.clone(), imported.clone()));
        }
        bindings.namespaces.get(name).map(|module| {
            (
                module.clone(),
                if bindings.default_imports.contains(name) {
                    "default".to_string()
                } else {
                    String::new()
                },
            )
        })
    }

    let (head, members) = member_path(callee)?;
    if members.is_empty() {
        return resolve_callee(callee, bindings);
    }
    let (module, imported) = match unwrap_expr(head) {
        Expression::Identifier(identifier) => {
            let name = identifier.name.as_str();
            if bindings.member_was_reassigned(&format!("{name}.{}", members.join("."))) {
                return None;
            }
            imported_symbol(name, bindings).or_else(|| {
                let producer = bindings.member_producers.get(name)?;
                imported_symbol(producer, bindings)
            })?
        }
        Expression::CallExpression(_) if !bindings.require_shadowed => {
            (require_module(head)?, String::new())
        }
        _ => return None,
    };
    let function = if imported.is_empty() {
        members.join(".")
    } else {
        format!("{imported}.{}", members.join("."))
    };
    Some(ModuleCall { module, function })
}

/// Classify unrecoverable dynamic code execution.
pub(super) fn dynamic_exec(callee: &Expression) -> Option<&'static str> {
    match callee {
        Expression::Identifier(id) => match id.name.as_str() {
            "eval" => Some("eval"),
            "Function" => Some("Function"),
            "require" => None, // handled as a binding, not an effect
            _ => None,
        },
        _ => None,
    }
}

thread_local! {
    /// References to `const` locals bound to the runtime's `process` in the
    /// program being walked, by span start and name.
    static PROCESS_ALIASES: RefCell<HashSet<(u32, String)>> = RefCell::default();
}

/// Installs the `process` aliases of the program being walked until dropped,
/// then restores those of the enclosing program.
pub(super) struct ProcessAliases(HashSet<(u32, String)>);

impl ProcessAliases {
    pub(super) fn enter(aliases: HashSet<(u32, String)>) -> Self {
        Self(PROCESS_ALIASES.with(|slot| slot.replace(aliases)))
    }
}

impl Drop for ProcessAliases {
    fn drop(&mut self) {
        PROCESS_ALIASES.with(|slot| slot.replace(std::mem::take(&mut self.0)));
    }
}

thread_local! {
    static LITERAL_ENVIRONMENT: RefCell<Option<LiteralEnvironment>> = RefCell::default();
}

/// The literal module-scope environment writes of the program being walked
/// (target span start, name, value), and the function and class bodies,
/// whose code can run after any of them.
pub(super) struct LiteralEnvironment {
    pub(super) writes: Vec<(u32, String, String)>,
    pub(super) bodies: Vec<(u32, u32)>,
}

/// Installs the literal environment writes of the program being walked
/// until dropped, then restores those of the enclosing program.
pub(super) struct LiteralEnvironmentScope(Option<LiteralEnvironment>);

impl LiteralEnvironmentScope {
    pub(super) fn enter(environment: Option<LiteralEnvironment>) -> Self {
        Self(LITERAL_ENVIRONMENT.with(|slot| slot.replace(environment)))
    }
}

impl Drop for LiteralEnvironmentScope {
    fn drop(&mut self) {
        LITERAL_ENVIRONMENT.with(|slot| slot.replace(self.0.take()));
    }
}

/// What a read of `name` sees where it runs, when a literal write assigns it.
pub(super) enum LiteralEnvRead {
    /// Module-scope code before every write: the host's value.
    Host,
    /// Module-scope code after a write: the last value written before it.
    Value(String),
    /// A function or class body, which can run before or after any write.
    Unknown,
}

/// The value a read of `name` at `span` sees. None when no literal write in
/// the program being walked assigns `name`.
pub(super) fn literal_env_read(name: &str, span: u32) -> Option<LiteralEnvRead> {
    LITERAL_ENVIRONMENT.with(|slot| {
        let slot = slot.borrow();
        let environment = slot.as_ref()?;
        if !environment
            .writes
            .iter()
            .any(|(_, written, _)| written == name)
        {
            return None;
        }
        if environment
            .bodies
            .iter()
            .any(|(start, end)| (*start..*end).contains(&span))
        {
            return Some(LiteralEnvRead::Unknown);
        }
        // Module-scope statements run in source order.
        Some(
            environment
                .writes
                .iter()
                .filter(|(at, written, _)| written == name && *at < span)
                .max_by_key(|(at, _, _)| *at)
                .map_or(LiteralEnvRead::Host, |(_, _, value)| {
                    LiteralEnvRead::Value(value.clone())
                }),
        )
    })
}

/// An environment variable read at `span` as an untyped value: the host's
/// variable, or the literal a module-scope write assigned before it.
pub(super) fn environment_value(name: &str, span: u32) -> ResourceExpr {
    match literal_env_read(name, span) {
        None | Some(LiteralEnvRead::Host) => ResourceExpr::Environment {
            name: name.to_string(),
        },
        Some(LiteralEnvRead::Value(value)) => ResourceExpr::Literal { value },
        Some(LiteralEnvRead::Unknown) => unresolved_resource("value"),
    }
}

/// Whether `expr` names `process`, directly or through a `const` bound to the
/// runtime's own, so `p.env.HOME` is read and written as `process.env.HOME`.
pub(super) fn is_process_object(expr: &Expression) -> bool {
    let Expression::Identifier(id) = unwrap_expr(expr) else {
        return false;
    };
    id.name.as_str() == "process"
        || PROCESS_ALIASES.with(|aliases| {
            aliases
                .borrow()
                .contains(&(id.span.start, id.name.to_string()))
        })
}

/// Whether an expression is a bare `process.env` reference — the whole
/// environment handed to a callee (zx: `resolveDefaults(..., process.env)`).
pub(super) fn is_process_env(expr: &Expression) -> bool {
    let Expression::StaticMemberExpression(m) = unwrap_expr(expr) else {
        return false;
    };
    is_process_object(&m.object) && m.property.name.as_str() == "env"
}

/// If `member` is `process.env.NAME`, return NAME.
pub(super) fn process_env_name(member: &StaticMemberExpression) -> Option<String> {
    let Expression::StaticMemberExpression(inner) = unwrap_expr(&member.object) else {
        return None;
    };
    if is_process_object(&inner.object) && inner.property.name.as_str() == "env" {
        Some(member.property.name.as_str().to_string())
    } else {
        None
    }
}

/// Match argv slots after the interpreter and script; callers check receiver ownership.
pub(super) fn process_argv_index(
    member: &oxc_ast::ast::ComputedMemberExpression<'_>,
) -> Option<usize> {
    let Expression::StaticMemberExpression(argv) = unwrap_expr(&member.object) else {
        return None;
    };
    if argv.property.name.as_str() != "argv"
        || !matches!(unwrap_expr(&argv.object), Expression::Identifier(id) if id.name.as_str() == "process")
    {
        return None;
    }
    let Expression::NumericLiteral(index) = unwrap_expr(&member.expression) else {
        return None;
    };
    (index.value >= 2.0 && index.value.fract() == 0.0 && index.value < usize::MAX as f64)
        .then_some(index.value as usize)
}

/// Lower a filesystem-path argument expression to a resource. `path.join(...)`
/// becomes a join expression; templates keep symbolic parts; an identifier
/// bound to a caller argument (a function parameter) resolves to that
/// argument's expression, which is how argument substitution flows into a
/// callee's effects.
pub(super) fn fs_resource(
    expr: &Expression,
    runtime_cwd: Option<ResourceExpr>,
    source_cwd: Option<&str>,
    env: &ParamEnv,
    bindings: &Bindings,
) -> ResourceExpr {
    match unwrap_expr(expr) {
        Expression::ComputedMemberExpression(member) if bindings.process_runtime() => {
            process_argv_index(member)
                .and_then(|index| env.get(&format!("process.argv[{index}]")))
                .cloned()
                .or_else(|| {
                    is_process_env(&member.object)
                        .then(|| super::literal_property_name(&member.expression))
                        .flatten()
                        .and_then(|name| {
                            environment_path(
                                &name,
                                member.span.start,
                                runtime_cwd.clone(),
                                bindings,
                            )
                        })
                })
                .unwrap_or(unresolved_resource("filesystem"))
        }
        Expression::StaticMemberExpression(member) if bindings.process_runtime() => {
            process_env_name(member)
                .and_then(|name| environment_path(&name, member.span.start, runtime_cwd, bindings))
                .unwrap_or(unresolved_resource("filesystem"))
        }
        Expression::StringLiteral(s) => {
            crate::paths::resolve_fs_path_with_cwd(s.value.as_str(), runtime_cwd)
        }
        Expression::Identifier(id) => match env.get(id.name.as_str()) {
            Some(bound) => bound.clone(),
            None => unresolved_resource("filesystem"),
        },
        Expression::TemplateLiteral(t) if t.expressions.is_empty() => {
            let Some(text) = cooked_template_string(t) else {
                return unresolved_resource("filesystem");
            };
            crate::paths::resolve_fs_path_with_cwd(&text, runtime_cwd)
        }
        Expression::TemplateLiteral(t) => {
            // Interleave literal quasis and symbolic expressions in order.
            let mut parts = Vec::new();
            for (i, quasi) in t.quasis.iter().enumerate() {
                let raw = quasi.value.raw.as_str();
                if !raw.is_empty() {
                    parts.push(if i == 0 {
                        crate::paths::resolve_fs_path_with_cwd(raw, runtime_cwd.clone())
                    } else {
                        concrete_fs(raw)
                    });
                }
                if let Some(e) = t.expressions.get(i) {
                    parts.push(fs_resource(e, None, source_cwd, env, bindings));
                }
            }
            match parts.len() {
                0 => unresolved_resource("filesystem"),
                1 => parts.pop().unwrap(),
                _ => ResourceExpr::Join { parts },
            }
        }
        Expression::CallExpression(call)
            if bindings.process_runtime()
                && call.arguments.is_empty()
                && matches!(unwrap_expr(&call.callee), Expression::StaticMemberExpression(member)
                    if is_process_object(&member.object) && member.property.name.as_str() == "cwd") =>
        {
            runtime_cwd.unwrap_or_else(|| ResourceExpr::Parameter {
                name: "cwd".to_string(),
            })
        }
        Expression::CallExpression(call)
            if super::source_string::is_home_directory_call(call, bindings) =>
        {
            environment_path("HOME", call.span.start, runtime_cwd, bindings)
                .unwrap_or(unresolved_resource("filesystem"))
        }
        Expression::CallExpression(call) => {
            if let Some(callee) = resolve_callee(unwrap_expr(&call.callee), bindings)
                && matches!(callee.module.as_str(), "path" | "path/posix")
                && matches!(callee.function.as_str(), "join" | "resolve")
            {
                let mut parts: Vec<ResourceExpr> = call
                    .arguments
                    .iter()
                    .filter_map(|a| a.as_expression())
                    .map(|e| match unwrap_expr(e) {
                        Expression::StringLiteral(value) => concrete_fs(value.value.as_str()),
                        Expression::TemplateLiteral(value) if value.expressions.is_empty() => {
                            cooked_template_string(value).map_or_else(
                                || unresolved_resource("filesystem"),
                                |value| concrete_fs(&value),
                            )
                        }
                        _ => fs_resource(e, None, source_cwd, env, bindings),
                    })
                    .collect();
                if !parts.is_empty() {
                    let first_is_relative = matches!(
                        parts.first(),
                        Some(ResourceExpr::Concrete {
                            identity: ResourceIdentity::FsPath { path },
                        }) if !effinterp_proto::is_absolute_path(path, PathPlatform::Posix)
                    );
                    if first_is_relative {
                        parts.insert(
                            0,
                            runtime_cwd.unwrap_or_else(|| ResourceExpr::Parameter {
                                name: "cwd".to_string(),
                            }),
                        );
                    }
                    return effinterp_proto::normalize_resource(
                        ResourceExpr::Join { parts },
                        PathPlatform::Posix,
                    );
                }
            }
            unresolved_resource("filesystem")
        }
        // `new URL('../package.json', import.meta.url)` — the first argument
        // is the path when it is a relative/absolute file specifier, not a URL.
        Expression::NewExpression(new_expr) => {
            url_file_resource(new_expr, source_cwd, env, bindings)
                .unwrap_or(unresolved_resource("filesystem"))
        }
        _ => unresolved_resource("filesystem"),
    }
}

/// A path read at `span` from an environment variable (`process.env.HOME`,
/// or `os.homedir()`, which returns `$HOME` whenever it is set). The variable
/// stays symbolic for the effect site to resolve from the host context; a
/// literal module-scope write before the read is its value. A module that can
/// rewrite the environment otherwise leaves the path unresolved.
fn environment_path(
    name: &str,
    span: u32,
    cwd: Option<ResourceExpr>,
    bindings: &Bindings,
) -> Option<ResourceExpr> {
    if name.is_empty() {
        return None;
    }
    if bindings.environment_rewrites_are_literal() {
        return match literal_env_read(name, span) {
            None | Some(LiteralEnvRead::Host) => Some(ResourceExpr::Environment {
                name: name.to_string(),
            }),
            Some(LiteralEnvRead::Value(value)) => {
                Some(crate::paths::resolve_fs_path_with_cwd(&value, cwd))
            }
            Some(LiteralEnvRead::Unknown) => None,
        };
    }
    (!bindings.environment_is_rewritten()).then(|| ResourceExpr::Environment {
        name: name.to_string(),
    })
}

/// Whether a lowered expression carries usable information (is not a bare
/// unresolved family placeholder). A `Join` with an unresolved part still
/// counts: its concrete prefix is meaningful.
fn is_resolvable(expr: &ResourceExpr) -> bool {
    !matches!(expr, ResourceExpr::Unresolved { .. })
}

/// Record module-level `const/let/var NAME = <path>` constants whose value
/// lowers to a usable resource (a literal, a template, a `path.join`). Later
/// declarations win, and an earlier constant is visible to a later one. Used to
/// resolve a constant referenced inside a helper's return or effect
/// (e.g. `path.join(BASE, t)`).
pub(super) fn collect_consts(
    program: &Program,
    runtime_cwd: Option<ResourceExpr>,
    source_cwd: Option<&str>,
    bindings: &Bindings,
) -> ParamEnv {
    let mut env = ParamEnv::new();
    for stmt in &program.body {
        let Some(Declaration::VariableDeclaration(v)) = stmt.as_declaration() else {
            continue;
        };
        for d in &v.declarations {
            if let (BindingPattern::BindingIdentifier(id), Some(init)) = (&d.id, &d.init) {
                let resolved = fs_resource(init, runtime_cwd.clone(), source_cwd, &env, bindings);
                if is_resolvable(&resolved) {
                    env.insert(id.name.as_str().to_string(), resolved);
                }
            }
        }
    }
    env
}

/// Gather the argument expression of every `return` reachable in a body
/// (following control flow, not descending into nested functions/classes).
/// Sets `saw_bare` when a valueless `return` is seen, so a function that does
/// not always return a value is rejected by return-value inference.
pub(super) fn collect_returns<'a>(
    stmts: &'a [Statement<'a>],
    out: &mut Vec<&'a Expression<'a>>,
    saw_bare: &mut bool,
) {
    for stmt in stmts {
        collect_returns_stmt(stmt, out, saw_bare);
    }
}

fn collect_returns_stmt<'a>(
    stmt: &'a Statement<'a>,
    out: &mut Vec<&'a Expression<'a>>,
    saw_bare: &mut bool,
) {
    match stmt {
        Statement::ReturnStatement(r) => match &r.argument {
            Some(e) => out.push(e),
            None => *saw_bare = true,
        },
        Statement::BlockStatement(b) => collect_returns(&b.body, out, saw_bare),
        Statement::IfStatement(s) => {
            collect_returns_stmt(&s.consequent, out, saw_bare);
            if let Some(alt) = &s.alternate {
                collect_returns_stmt(alt, out, saw_bare);
            }
        }
        Statement::ForStatement(s) => collect_returns_stmt(&s.body, out, saw_bare),
        Statement::ForInStatement(s) => collect_returns_stmt(&s.body, out, saw_bare),
        Statement::ForOfStatement(s) => collect_returns_stmt(&s.body, out, saw_bare),
        Statement::WhileStatement(s) => collect_returns_stmt(&s.body, out, saw_bare),
        Statement::DoWhileStatement(s) => collect_returns_stmt(&s.body, out, saw_bare),
        Statement::LabeledStatement(s) => collect_returns_stmt(&s.body, out, saw_bare),
        Statement::TryStatement(s) => {
            collect_returns(&s.block.body, out, saw_bare);
            if let Some(h) = &s.handler {
                collect_returns(&h.body.body, out, saw_bare);
            }
            if let Some(f) = &s.finalizer {
                collect_returns(&f.body, out, saw_bare);
            }
        }
        Statement::SwitchStatement(s) => {
            for case in &s.cases {
                collect_returns(&case.consequent, out, saw_bare);
            }
        }
        // Nested functions and classes are separate scopes.
        _ => {}
    }
}

/// The resource a function returns, expressed under `env` (which binds the
/// function's parameters — to symbolic `Parameter` nodes when summarizing, or
/// to caller arguments when tracking a call). `Some` only when every `return`
/// lowers to the same usable resource; divergent, absent, valueless, or
/// unresolvable returns yield `None`.
pub(super) fn infer_returns(
    body: &[Statement],
    runtime_cwd: Option<ResourceExpr>,
    source_cwd: Option<&str>,
    env: &ParamEnv,
    bindings: &Bindings,
) -> Option<ResourceExpr> {
    let mut values = Vec::new();
    let mut saw_bare = false;
    collect_returns(body, &mut values, &mut saw_bare);
    if saw_bare || values.is_empty() {
        return None;
    }
    let mut resolved: Vec<ResourceExpr> = values
        .iter()
        .map(|e| fs_resource(e, runtime_cwd.clone(), source_cwd, env, bindings))
        .collect();
    let first = resolved.remove(0);
    if !is_resolvable(&first) || resolved.iter().any(|r| *r != first) {
        return None;
    }
    Some(first)
}

fn concrete_fs(text: &str) -> ResourceExpr {
    ResourceExpr::Concrete {
        identity: ResourceIdentity::FsPath {
            path: text.to_string(),
        },
    }
}

/// Lower a URL argument expression to a network endpoint identity.
pub(super) fn url_resource(expr: &Expression) -> ResourceExpr {
    let url = match unwrap_expr(expr) {
        Expression::StringLiteral(url) => url.value.as_str().to_string(),
        Expression::TemplateLiteral(template) if template.expressions.is_empty() => {
            let Some(url) = cooked_template_string(template) else {
                return unresolved_resource("network");
            };
            url
        }
        _ => {
            return unresolved_resource("network");
        }
    };
    parse_url_endpoint(&url)
        .map(|identity| ResourceExpr::Concrete { identity })
        .unwrap_or(unresolved_resource("network"))
}

/// `new URL('../package.json', import.meta.url)` (or any `new URL` whose first
/// argument is a file specifier, not a scheme URL): the string is the path.
fn url_file_resource(
    new_expr: &NewExpression,
    source_cwd: Option<&str>,
    env: &ParamEnv,
    bindings: &Bindings,
) -> Option<ResourceExpr> {
    let Expression::Identifier(id) = unwrap_expr(&new_expr.callee) else {
        return None;
    };
    if id.name.as_str() != "URL" {
        return None;
    }
    let first = new_expr.arguments.first()?.as_expression()?;
    match unwrap_expr(first) {
        Expression::StringLiteral(s) => {
            let text = s.value.as_str();
            if text.contains("://") {
                return None;
            }
            Some(crate::paths::resolve_fs_path(text, source_cwd))
        }
        other => {
            let source_cwd_resource = source_cwd.map(|path| ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath {
                    path: path.to_string(),
                },
            });
            let resolved = fs_resource(other, source_cwd_resource, source_cwd, env, bindings);
            is_resolvable(&resolved).then_some(resolved)
        }
    }
}

/// The process an exec-shaped call names: the first argument when it is a
/// string literal (`exec("git", ...)` / `execFile("npm", ...)`).
pub(super) fn process_resource(expr: &Expression) -> ResourceExpr {
    match unwrap_expr(expr) {
        Expression::StringLiteral(s) => {
            let name = s.value.as_str();
            if name.is_empty() {
                return unresolved_resource("process");
            }
            ResourceExpr::Concrete {
                identity: ResourceIdentity::Process {
                    executable: name.to_string(),
                    path: None,
                    argv: Vec::new(),
                    cwd: None,
                },
            }
        }
        _ => unresolved_resource("process"),
    }
}
