//! Per-file callable-surface extraction for cross-module analysis.
//!
//! Where [`super::JsFrontend`] produces a single file's execution plan
//! (inlining calls into local functions), this extractor produces a stored
//! [`Summary`] for each top-level function plus the module's import bindings,
//! so the repository index can link and compose calls across files.
//!
//! The two differ deliberately in how they treat a call to another function.
//! The execution walk inlines it; the extractor records it as a [`CallEdge`]
//! — a call to a local name, an imported binding, or an `obj.member` — leaving
//! resolution to the repository. Only calls that resolve to a *modeled* effect
//! API (fs, child_process, http, fetch, process.env) contribute effects to the
//! summary; every other call becomes a call edge for cross-file linking.

use std::collections::{BTreeMap, HashMap, HashSet};

use effinterp_proto::{
    AttrValue, Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CoverageLevel, Domain,
    Effect, ExecutionRealm, Modality, Operation, ResourceExpr, ResourceIdentity,
};
use oxc_ast::ast::{
    Argument, AssignmentExpression, AssignmentTarget, BindingPattern, CallExpression, Class,
    ClassElement, Declaration, ExportDefaultDeclarationKind, Expression, FormalParameters,
    FunctionBody, ImportDeclaration, ImportDeclarationSpecifier, ImportExpression,
    MethodDefinitionKind, NewExpression, ObjectExpression, Program, PropertyKey, PropertyKind,
    Statement, StaticMemberExpression, TSType, UnaryExpression, VariableDeclarator,
};
use oxc_ast_visit::{Visit, walk};
use oxc_span::GetSpan;

use super::bindings::CalleeBinding;
use super::collect::{param_binding_names, param_names};
use super::model::{
    FsTransferSource, ObjectLiteralBindings, ShellOption, call_option_shell, call_option_true,
    fs_dest_operation, fs_operation, fs_recursive_options, fs_transfer, is_inert_callee,
    is_inert_module_call, network_source_literal, object_literal, shell_command_source,
    subprocess_options_index,
};
use super::resolve::{self, ParamEnv};
use super::{Bindings, JS_DOMAINS, MAX_WALK_DEPTH, argument_expr, binding_declares, unparen};
use crate::control_flow::{
    ControlCaps, ControlExit, ControlFact, ControlFlow, ControlStack, SiteFacts,
};
use crate::module_summary::{
    CallEdge, CallResult, ClassEntry, FunctionEntry, ImportBinding, ModuleLoadEvidence,
    ModuleLoadKind, ModuleSummary,
};
use crate::resource_transfer::TransferBinding;
use crate::summary::Summary;
use crate::value::unresolved_resource;
use crate::{
    ObjectIdentity, ScopeKey, SemanticValue, SemanticValueKind, TypeRef, ValueArgument,
    ValueOrigin, merge_arguments, positional_arguments,
};

// ControlStack matches source allocations, so every capture uses this stable key.
static CAPTURE_SOURCE: &str = "js-summary";

fn summary_control(build: impl FnOnce(&mut crate::control_flow::Graph)) -> ControlStack {
    let mut control = ControlStack::default();
    let limits = crate::AnalysisLimits::default();
    control.enter(
        CAPTURE_SOURCE,
        true,
        Default::default(),
        0,
        0,
        None,
        ControlCaps {
            nodes: limits.max_causal_nodes,
            work: limits.max_causal_pairs,
        },
        build,
    );
    control
}

pub(super) fn summarize_ast(
    source: &str,
    program: &Program<'_>,
    file: &str,
    _scope: ScopeKey,
) -> ModuleSummary {
    // This module's spans are not the calling program's.
    let _literal_environment = resolve::LiteralEnvironmentScope::enter(None);
    let mut bindings = Bindings::default();
    let semantic = oxc_semantic::SemanticBuilder::new().build(program).semantic;
    if source.len() as u64 <= crate::AnalysisLimits::default().max_causal_pairs {
        bindings.readonly_writes = super::readonly_write_spans(&semantic);
    }
    bindings.reference_bindings = reference_bindings(&semantic);
    bindings.fixed_arrays = fixed_arrays(&semantic);
    bindings.global_process_spans = super::global_reference_spans(&semantic, "process");
    bindings.runtime_code_spans = ["eval", "Function"]
        .into_iter()
        .flat_map(|name| super::global_reference_spans(&semantic, name))
        .collect();
    bindings.throws_reject = super::throws_reject(program, source);
    bindings.source_digest =
        effinterp_proto::stable_hash(effinterp_proto::CONDITION_SOURCE_HASH_DOMAIN, &source);
    bindings.visit_program(program);
    bindings.guards = super::js_guard_regions(program, source, bindings.throws_reject, &bindings);
    bindings.dynamic_imports = resolve::DynamicImportFacts::collect(program);

    let mut imports = ImportCollector::default();
    imports.visit_program(program);
    let (commonjs_local, commonjs_forwards) = commonjs_exports(program);
    imports.local_exports.extend(commonjs_local);
    for forward in commonjs_forwards {
        imports.module_loads.push(ModuleLoadEvidence {
            local: forward.local.clone(),
            module: forward.module.clone(),
            kind: ModuleLoadKind::CommonJs,
        });
        imports.imports.push(forward.clone());
        imports.exports.push(forward);
    }

    // Module-level path constants, so a return like `path.join(BASE, t)`
    // resolves `BASE`. Summaries are file-relative, so there is no cwd.
    let consts = resolve::collect_consts(program, None, None, &bindings);

    let top_fns = top_level_functions(program);
    let mut known_bodies = KnownBodies::new();
    for function in &top_fns {
        known_bodies
            .entry(function.name.clone())
            .or_default()
            .push(KnownBody {
                body: function.body,
                formals: function.formal_params,
                process_scope: function.process_scope,
            });
    }
    let (returned_functions, returned_object_producers) =
        returned_object_functions(&top_fns, &bindings, &consts, &known_bodies, file);
    let returned_methods: HashSet<String> = returned_functions
        .iter()
        .map(|function| function.name.clone())
        .collect();
    let mut functions: Vec<FunctionEntry> = top_fns
        .iter()
        .map(|f| {
            summarize_function(
                f,
                &bindings,
                &consts,
                &known_bodies,
                &returned_methods,
                file,
            )
        })
        .collect();
    for function in &mut functions {
        if returned_object_producers.contains(&function.name) {
            function.returns_instances = vec![Some(function.name.clone())];
        }
    }
    functions.extend(returned_functions);
    functions.extend(module_object_functions(
        program,
        &imports.bound,
        &bindings,
        &consts,
        &known_bodies,
        file,
    ));
    let mut classes = collect_classes(
        program,
        &mut functions,
        &bindings,
        &consts,
        &known_bodies,
        file,
    );
    let producer_classes: Vec<_> = returned_object_producers
        .into_iter()
        .filter(|producer| !classes.iter().any(|class| class.name == *producer))
        .map(|name| ClassEntry {
            name,
            ..Default::default()
        })
        .collect();
    classes.extend(producer_classes);
    alias_default_export(program, &mut functions, &mut classes);
    let exported_definitions = local_exported_definitions(
        program,
        &imports.local_exports,
        &imports.exported_declarations,
        &functions,
        &classes,
    );

    let (module_calls, module_effects, module_transfers, module_control_flow, module_boundaries) =
        module_level(program, &imports.bound, &bindings, &known_bodies, file);

    // Confirm wrapped-const aliases: only a name bound exactly once, not
    // otherwise imported, and not a function of this module aliases the
    // wrapped external module. A rebound name stays unresolved.
    let mut import_bindings = imports.imports;
    import_bindings.retain(|binding| {
        binding.local.is_empty()
            || binding.local == "*"
            || imports.bound.get(&binding.local).copied().unwrap_or(1) == 1
    });
    imports.module_loads.retain(|load| {
        import_bindings
            .iter()
            .any(|binding| binding.local == load.local && binding.module == load.module)
    });
    let mut export_bindings = imports.exports;
    for (exported, local) in &imports.local_exports {
        if let Some(import) = import_bindings
            .iter()
            .find(|binding| binding.local == *local)
        {
            let mut export = import.clone();
            export.local = exported.clone();
            export_bindings.push(export);
        }
    }
    for (name, module, imported) in imports.aliases {
        if imports.bound.get(&name) == Some(&1)
            && !import_bindings.iter().any(|b| b.local == name)
            && !functions.iter().any(|f: &FunctionEntry| f.name == name)
        {
            let binding = ImportBinding {
                local: name,
                module,
                imported,
            };
            if imports.exported_declarations.contains(&binding.local) {
                export_bindings.push(binding.clone());
            }
            import_bindings.push(binding);
        }
    }

    ModuleSummary {
        linkage: crate::Linkage {
            explicit_exports: true,
            eager_async_calls: true,
            wildcard_excluded_names: vec!["default".to_string()],
            ..Default::default()
        },
        functions,
        module_calls,
        module_effects,
        module_transfers,
        module_control_flow,
        module_boundaries,
        imports: import_bindings,
        module_loads: imports.module_loads,
        scoped_imports: bindings.dynamic_imports.scoped_imports.clone(),
        exports: export_bindings,
        exported_definitions,
        classes,
        ..Default::default()
    }
}

fn local_exported_definitions(
    program: &Program,
    aliases: &[(String, String)],
    declarations: &HashSet<String>,
    functions: &[FunctionEntry],
    classes: &[ClassEntry],
) -> Vec<(String, String)> {
    let definitions = |exported: &str, local: &str| {
        functions
            .iter()
            .filter_map(|function| {
                if function.name == local {
                    Some((exported.to_string(), function.name.clone()))
                } else {
                    function
                        .name
                        .strip_prefix(&format!("{local}."))
                        .map(|suffix| (format!("{exported}.{suffix}"), function.name.clone()))
                }
            })
            .chain(
                classes
                    .iter()
                    .filter(|class| class.name == local)
                    .map(|class| (exported.to_string(), class.name.clone())),
            )
            .collect::<Vec<_>>()
    };
    let mut out: Vec<(String, String)> = aliases
        .iter()
        .flat_map(|(exported, local)| definitions(exported, local))
        .collect();
    out.extend(declarations.iter().flat_map(|name| definitions(name, name)));
    for statement in &program.body {
        match statement {
            Statement::ExportNamedDeclaration(export) => match &export.declaration {
                Some(Declaration::FunctionDeclaration(function)) => {
                    if let Some(id) = &function.id {
                        let name = id.name.as_str().to_string();
                        out.extend(definitions(&name, &name));
                    }
                }
                Some(Declaration::ClassDeclaration(class)) => {
                    if let Some(id) = &class.id {
                        let name = id.name.as_str().to_string();
                        out.extend(definitions(&name, &name));
                    }
                }
                _ => {}
            },
            // `export default wipe` names the function itself, so a call keeps
            // its arguments rather than passing through the alias entry.
            Statement::ExportDefaultDeclaration(export) => match &export.declaration {
                ExportDefaultDeclarationKind::Identifier(id) => {
                    out.extend(definitions("default", id.name.as_str()));
                }
                _ => out.extend(definitions("default", "default")),
            },
            _ => {}
        }
    }
    out.sort();
    out.dedup();
    out
}

fn commonjs_exports(program: &Program) -> (Vec<(String, String)>, Vec<ImportBinding>) {
    let mut out = BTreeMap::new();
    let mut forwards = Vec::new();
    let mut module_is_runtime = true;
    let mut exports_is_runtime = true;
    for statement in &program.body {
        if let Some(Declaration::FunctionDeclaration(function)) = statement.as_declaration()
            && let Some(id) = &function.id
        {
            exports_is_runtime &= id.name.as_str() != "exports";
            module_is_runtime &= id.name.as_str() != "module";
        }
    }
    for statement in &program.body {
        match statement.as_declaration() {
            Some(Declaration::VariableDeclaration(variable)) => {
                for declarator in &variable.declarations {
                    match &declarator.id {
                        BindingPattern::BindingIdentifier(id) => match id.name.as_str() {
                            "exports" => {
                                if let Some(init) = &declarator.init {
                                    exports_is_runtime = match unparen(init) {
                                        Expression::Identifier(id)
                                            if id.name.as_str() == "exports" =>
                                        {
                                            exports_is_runtime
                                        }
                                        Expression::StaticMemberExpression(member)
                                            if module_is_runtime && is_module_exports(member) =>
                                        {
                                            true
                                        }
                                        _ => false,
                                    };
                                }
                            }
                            "module" => {
                                if let Some(init) = &declarator.init {
                                    module_is_runtime = matches!(
                                        unparen(init),
                                        Expression::Identifier(id)
                                            if id.name.as_str() == "module"
                                    );
                                }
                            }
                            _ => {}
                        },
                        pattern => {
                            if binding_declares(pattern, "exports") {
                                exports_is_runtime = false;
                            }
                            if binding_declares(pattern, "module") {
                                module_is_runtime = false;
                            }
                        }
                    }
                }
                continue;
            }
            Some(Declaration::FunctionDeclaration(function)) => {
                if let Some(id) = &function.id {
                    exports_is_runtime &= id.name.as_str() != "exports";
                    module_is_runtime &= id.name.as_str() != "module";
                }
                continue;
            }
            Some(Declaration::ClassDeclaration(class)) => {
                if let Some(id) = &class.id {
                    exports_is_runtime &= id.name.as_str() != "exports";
                    module_is_runtime &= id.name.as_str() != "module";
                }
                continue;
            }
            _ => {}
        }
        let Statement::ExpressionStatement(statement) = statement else {
            continue;
        };
        let Expression::AssignmentExpression(assignment) = unparen(&statement.expression) else {
            continue;
        };
        if !assignment.operator.is_assign() {
            continue;
        }
        match &assignment.left {
            AssignmentTarget::AssignmentTargetIdentifier(id) => match id.name.as_str() {
                "exports" => {
                    exports_is_runtime = module_is_runtime
                        && matches!(
                            unparen(&assignment.right),
                            Expression::StaticMemberExpression(member) if is_module_exports(member)
                        );
                }
                "module" => module_is_runtime = false,
                _ => {}
            },
            AssignmentTarget::StaticMemberExpression(target) => {
                if module_is_runtime && is_module_exports(target) {
                    let keeps_exports = exports_is_runtime
                        && matches!(
                            unparen(&assignment.right),
                            Expression::Identifier(id) if id.name.as_str() == "exports"
                        );
                    out.clear();
                    forwards.clear();
                    // A function or a local name assigned whole is the
                    // module's callable value; `collect_commonjs_default_function`
                    // summarizes an inline one as `default`.
                    match unparen(&assignment.right) {
                        Expression::FunctionExpression(_)
                        | Expression::ArrowFunctionExpression(_) => {
                            out.insert("default".to_string(), "default".to_string());
                        }
                        Expression::Identifier(local) if local.name.as_str() != "exports" => {
                            out.insert("default".to_string(), local.name.as_str().to_string());
                        }
                        _ => {}
                    }
                    if let Some(module) = resolve::require_module(&assignment.right) {
                        forwards.push(ImportBinding {
                            local: "*".to_string(),
                            module,
                            imported: None,
                        });
                    }
                    if let Expression::ObjectExpression(object) = unparen(&assignment.right) {
                        for property in &object.properties {
                            match property {
                                oxc_ast::ast::ObjectPropertyKind::ObjectProperty(property) => {
                                    let Some(exported) = property.key.static_name() else {
                                        continue;
                                    };
                                    if let Expression::Identifier(local) = unparen(&property.value)
                                    {
                                        out.insert(
                                            exported.to_string(),
                                            local.name.as_str().to_string(),
                                        );
                                    } else if let Some((module, imported)) =
                                        commonjs_required_member(&property.value)
                                    {
                                        forwards.push(ImportBinding {
                                            local: exported.to_string(),
                                            module,
                                            imported: Some(imported),
                                        });
                                    }
                                }
                                oxc_ast::ast::ObjectPropertyKind::SpreadProperty(spread) => {
                                    if let Some(module) = resolve::require_module(&spread.argument)
                                    {
                                        forwards.push(ImportBinding {
                                            local: "*".to_string(),
                                            module,
                                            imported: None,
                                        });
                                    }
                                }
                            }
                        }
                    }
                    exports_is_runtime = keeps_exports;
                } else if let Some(exported) =
                    commonjs_export_member(target, module_is_runtime, exports_is_runtime)
                {
                    if let Expression::Identifier(local) = unparen(&assignment.right) {
                        out.insert(exported, local.name.as_str().to_string());
                    } else if let Some((module, imported)) =
                        commonjs_required_member(&assignment.right)
                    {
                        forwards.push(ImportBinding {
                            local: exported,
                            module,
                            imported: Some(imported),
                        });
                    }
                }
            }
            _ => {}
        }
    }
    // A replacement inside a branch may or may not run, so the module's
    // callable value is unknown until a later top-level assignment settles
    // it. One inside a function may run whenever it is called, so it is never
    // settled. An unknown value leaves a call of it unresolved.
    let mut unsettled = false;
    let mut deferred = false;
    for statement in &program.body {
        let mut assignments = ModuleExportsAssignments::default();
        assignments.visit_statement(statement);
        deferred |= assignments.truncated || assignments.in_function > 0;
        if is_module_exports_assignment(statement) {
            unsettled = false;
        } else if assignments.in_flow > 0 {
            unsettled = true;
        }
    }
    if unsettled || deferred {
        out.remove("default");
    }
    forwards.sort_by(|left, right| {
        (&left.local, &left.module, &left.imported).cmp(&(
            &right.local,
            &right.module,
            &right.imported,
        ))
    });
    forwards.dedup();
    (out.into_iter().collect(), forwards)
}

/// Bind each name a function is called or passed through, from the scope
/// it is read in, so parameters, block and loop variables, catch parameters
/// and hoisted declarations shadow outer namesakes exactly as JavaScript
/// resolves them.
fn reference_bindings(semantic: &oxc_semantic::Semantic<'_>) -> HashMap<u32, CalleeBinding> {
    let mut out = HashMap::new();
    for node in semantic.nodes().iter() {
        let oxc_ast::AstKind::IdentifierReference(id) = node.kind() else {
            continue;
        };
        if let Some(binding) = reference_binding(semantic, id, 0) {
            out.insert(id.span.start, binding);
        }
    }
    out
}

/// Array methods that call their callback with each element as its first
/// argument and never change the array.
const ELEMENT_CALLBACK_METHODS: &[&str] = &[
    "forEach",
    "map",
    "filter",
    "some",
    "every",
    "find",
    "findIndex",
    "flatMap",
];

/// Each iteration receiver whose array's elements are fixed where it is
/// declared: a never-rebound `name = [...]` binding whose every reference is
/// the receiver of an element-callback method call whose callback cannot
/// reach the array.
fn fixed_arrays(semantic: &oxc_semantic::Semantic<'_>) -> HashMap<u32, u32> {
    let scoping = semantic.scoping();
    let nodes = semantic.nodes();
    let mut out = HashMap::new();
    for symbol in scoping.symbol_ids() {
        let oxc_ast::AstKind::VariableDeclarator(declarator) =
            nodes.kind(scoping.symbol_declaration(symbol))
        else {
            continue;
        };
        let BindingPattern::BindingIdentifier(binding) = &declarator.id else {
            continue;
        };
        if !matches!(
            declarator.init.as_ref().map(unparen),
            Some(Expression::ArrayExpression(_))
        ) || !scoping.symbol_redeclarations(symbol).is_empty()
        {
            continue;
        }
        let mut receivers = Vec::new();
        let fixed = scoping
            .get_resolved_reference_ids(symbol)
            .iter()
            .all(|reference| {
                let reference = scoping.get_reference(*reference);
                let oxc_ast::AstKind::IdentifierReference(id) = nodes.kind(reference.node_id())
                else {
                    return false;
                };
                let member = nodes.parent_id(reference.node_id());
                let oxc_ast::AstKind::StaticMemberExpression(member_expr) = nodes.kind(member)
                else {
                    return false;
                };
                let oxc_ast::AstKind::CallExpression(call) = nodes.parent_kind(member) else {
                    return false;
                };
                receivers.push(id.span.start);
                !reference.is_write()
                    && matches!(&member_expr.object, Expression::Identifier(object) if object.span == id.span)
                    && ELEMENT_CALLBACK_METHODS.contains(&member_expr.property.name.as_str())
                    && call.callee.span() == member_expr.span
                    && call
                        .arguments
                        .first()
                        .and_then(|argument| argument.as_expression())
                        .is_some_and(|callback| callback_cannot_reach_array(semantic, callback))
            });
        if fixed {
            out.extend(
                receivers
                    .into_iter()
                    .map(|receiver| (receiver, binding.span.start)),
            );
        }
    }
    out
}

/// Whether an iteration callback provably never receives the array it
/// iterates, which the method passes as its third argument: an inline or
/// symbol-proven function with at most two formals, no rest parameter and no
/// `arguments`.
fn callback_cannot_reach_array(
    semantic: &oxc_semantic::Semantic<'_>,
    callback: &Expression<'_>,
) -> bool {
    let body_span = match unparen(callback) {
        Expression::FunctionExpression(function) => function.body.as_ref().map(|body| body.span),
        Expression::ArrowFunctionExpression(arrow) => Some(arrow.body.span),
        Expression::Identifier(id) => match reference_binding(semantic, id, 0) {
            Some(CalleeBinding::Function((start, end))) => Some(oxc_span::Span::new(start, end)),
            _ => None,
        },
        _ => None,
    };
    let Some(body_span) = body_span else {
        return false;
    };
    let nodes = semantic.nodes();
    let params = nodes.iter().find_map(|node| match node.kind() {
        oxc_ast::AstKind::Function(function)
            if function
                .body
                .as_ref()
                .is_some_and(|body| body.span == body_span) =>
        {
            Some(&function.params)
        }
        oxc_ast::AstKind::ArrowFunctionExpression(arrow) if arrow.body.span == body_span => {
            Some(&arrow.params)
        }
        _ => None,
    });
    params.is_some_and(|params| params.items.len() <= 2 && params.rest.is_none())
        && !nodes.iter().any(|node| {
            matches!(node.kind(), oxc_ast::AstKind::IdentifierReference(id)
                if id.name == "arguments"
                    && body_span.start <= id.span.start
                    && id.span.end <= body_span.end)
        })
}

/// Bound on `const a = b` alias hops followed to a function.
const MAX_ALIAS_HOPS: u32 = 8;

/// The function one reference binds to, following `const alias = name`
/// through each name's own symbol. None for an import, a `require` binding or
/// a global, which the module's imports resolve.
fn reference_binding(
    semantic: &oxc_semantic::Semantic<'_>,
    id: &oxc_ast::ast::IdentifierReference<'_>,
    hops: u32,
) -> Option<CalleeBinding> {
    let scoping = semantic.scoping();
    let symbol = scoping.get_reference(id.reference_id.get()?).symbol_id()?;
    if scoping.symbol_flags(symbol).is_import() {
        return None;
    }
    let rebound = !scoping.symbol_redeclarations(symbol).is_empty()
        || scoping
            .get_resolved_reference_ids(symbol)
            .iter()
            .any(|reference| scoping.get_reference(*reference).is_write());
    let body = match semantic.nodes().kind(scoping.symbol_declaration(symbol)) {
        oxc_ast::AstKind::Function(function) => function.body.as_ref().map(|body| body.span),
        oxc_ast::AstKind::VariableDeclarator(declarator) => {
            let alias = matches!(declarator.id, BindingPattern::BindingIdentifier(_));
            match declarator.init.as_ref().map(unparen) {
                Some(Expression::FunctionExpression(function)) if alias => {
                    function.body.as_ref().map(|body| body.span)
                }
                Some(Expression::ArrowFunctionExpression(arrow)) if alias => Some(arrow.body.span),
                Some(Expression::Identifier(target)) if alias && !rebound => {
                    return Some(if hops < MAX_ALIAS_HOPS {
                        reference_binding(semantic, target, hops + 1)
                            .unwrap_or(CalleeBinding::Opaque)
                    } else {
                        CalleeBinding::Opaque
                    });
                }
                // A `require` binding resolves through the module's imports.
                Some(init)
                    if resolve::require_module(init).is_some()
                        || commonjs_required_member(init).is_some() =>
                {
                    return None;
                }
                _ => None,
            }
        }
        _ => None,
    };
    Some(match body {
        Some(span) if !rebound => CalleeBinding::Function((span.start, span.end)),
        _ if rebound && may_hold_function(semantic, symbol) => CalleeBinding::Rebound,
        _ => CalleeBinding::Opaque,
    })
}

/// Whether a declaration or assignment of `symbol` gives it a function or
/// another name's value.
fn may_hold_function(
    semantic: &oxc_semantic::Semantic<'_>,
    symbol: oxc_semantic::SymbolId,
) -> bool {
    let scoping = semantic.scoping();
    let nodes = semantic.nodes();
    let function_like = |expr: &Expression<'_>| {
        matches!(
            unparen(expr),
            Expression::FunctionExpression(_)
                | Expression::ArrowFunctionExpression(_)
                | Expression::Identifier(_)
        )
    };
    let declared = std::iter::once(scoping.symbol_declaration(symbol)).chain(
        scoping
            .symbol_redeclarations(symbol)
            .iter()
            .map(|redeclaration| redeclaration.declaration),
    );
    let assigned = scoping
        .get_resolved_reference_ids(symbol)
        .iter()
        .map(|reference| scoping.get_reference(*reference))
        .filter(|reference| reference.is_write())
        .map(|reference| nodes.parent_id(reference.node_id()));
    declared.chain(assigned).any(|node| match nodes.kind(node) {
        oxc_ast::AstKind::Function(_) => true,
        oxc_ast::AstKind::VariableDeclarator(declarator) => {
            declarator.init.as_ref().is_some_and(function_like)
        }
        oxc_ast::AstKind::AssignmentExpression(assignment) => function_like(&assignment.right),
        _ => false,
    })
}

fn is_module_exports_assignment(statement: &Statement<'_>) -> bool {
    let Statement::ExpressionStatement(statement) = statement else {
        return false;
    };
    // Only a plain `=` replaces the value; `||=` and the like may keep it.
    matches!(
        unparen(&statement.expression),
        Expression::AssignmentExpression(assignment)
            if assignment.operator.is_assign()
                && matches!(&assignment.left, AssignmentTarget::StaticMemberExpression(target) if is_module_exports(target))
    )
}

/// Counts `module.exports = …` assignments, apart from those inside a
/// function body.
#[derive(Default)]
struct ModuleExportsAssignments {
    in_flow: usize,
    in_function: usize,
    function_depth: u32,
    walk_depth: u32,
    truncated: bool,
}

impl<'a> Visit<'a> for ModuleExportsAssignments {
    fn visit_expression(&mut self, it: &Expression<'a>) {
        if self.walk_depth >= MAX_WALK_DEPTH {
            self.truncated = true;
            return;
        }
        self.walk_depth += 1;
        walk::walk_expression(self, it);
        self.walk_depth -= 1;
    }

    fn visit_statement(&mut self, it: &Statement<'a>) {
        if self.walk_depth >= MAX_WALK_DEPTH {
            self.truncated = true;
            return;
        }
        self.walk_depth += 1;
        walk::walk_statement(self, it);
        self.walk_depth -= 1;
    }

    fn visit_function(&mut self, it: &oxc_ast::ast::Function<'a>, flags: oxc_semantic::ScopeFlags) {
        self.function_depth += 1;
        walk::walk_function(self, it, flags);
        self.function_depth -= 1;
    }

    fn visit_arrow_function_expression(&mut self, it: &oxc_ast::ast::ArrowFunctionExpression<'a>) {
        self.function_depth += 1;
        walk::walk_arrow_function_expression(self, it);
        self.function_depth -= 1;
    }

    fn visit_assignment_expression(&mut self, it: &AssignmentExpression<'a>) {
        if matches!(&it.left, AssignmentTarget::StaticMemberExpression(target) if is_module_exports(target))
        {
            if self.function_depth > 0 {
                self.in_function += 1;
            } else {
                self.in_flow += 1;
            }
        }
        walk::walk_assignment_expression(self, it);
    }
}

fn commonjs_required_member(expr: &Expression<'_>) -> Option<(String, String)> {
    let Expression::StaticMemberExpression(member) = unparen(expr) else {
        return None;
    };
    Some((
        resolve::require_module(&member.object)?,
        member.property.name.as_str().to_string(),
    ))
}

fn count_binding_pattern(
    pattern: &BindingPattern<'_>,
    bound: &mut std::collections::HashMap<String, u32>,
) {
    match pattern {
        BindingPattern::BindingIdentifier(id) => {
            *bound.entry(id.name.as_str().to_string()).or_default() += 1;
        }
        BindingPattern::ObjectPattern(object) => {
            for property in &object.properties {
                count_binding_pattern(&property.value, bound);
            }
            if let Some(rest) = &object.rest {
                count_binding_pattern(&rest.argument, bound);
            }
        }
        BindingPattern::ArrayPattern(array) => {
            for element in array.elements.iter().flatten() {
                count_binding_pattern(element, bound);
            }
            if let Some(rest) = &array.rest {
                count_binding_pattern(&rest.argument, bound);
            }
        }
        BindingPattern::AssignmentPattern(assignment) => {
            count_binding_pattern(&assignment.left, bound)
        }
    }
}

fn is_module_exports(member: &StaticMemberExpression) -> bool {
    matches!(unparen(&member.object), Expression::Identifier(module) if module.name.as_str() == "module")
        && member.property.name.as_str() == "exports"
}

fn commonjs_export_member(
    member: &StaticMemberExpression,
    module_is_runtime: bool,
    exports_is_runtime: bool,
) -> Option<String> {
    let exported = member.property.name.as_str().to_string();
    match unparen(&member.object) {
        Expression::Identifier(exports)
            if exports_is_runtime && exports.name.as_str() == "exports" =>
        {
            Some(exported)
        }
        Expression::StaticMemberExpression(module_exports)
            if module_is_runtime && is_module_exports(module_exports) =>
        {
            Some(exported)
        }
        _ => None,
    }
}

/// Calls and direct effects of the module's own top-level execution (outside
/// any function — a `process.env.X` read initializing a module const).
/// `visit_function_body` is a no-op, so a function's own body is not descended
/// into; only executed top-level code is captured.
fn module_level<'a>(
    program: &'a Program<'a>,
    bound: &HashMap<String, u32>,
    bindings: &Bindings,
    known_bodies: &KnownBodies<'a>,
    file: &str,
) -> (
    Vec<CallEdge>,
    Vec<effinterp_proto::Effect>,
    Vec<TransferBinding>,
    ControlFlow,
    Vec<Boundary>,
) {
    let _walk = crate::limits::summary_walk();
    let returned_methods = HashSet::new();
    let mut v = SummaryVisitor {
        control: summary_control(|graph| {
            super::control::build_program(graph, program, &bindings.readonly_writes)
        }),
        bindings,
        param_env: ParamEnv::new(),
        object_literal_vars: ObjectLiteralBindings::new(),
        source_literals: HashMap::new(),
        effects: Vec::new(),
        transfers: Vec::new(),
        boundaries: Vec::new(),
        calls: Vec::new(),
        instance_vars: HashMap::new(),
        instance_attrs: HashMap::new(),
        callable_attrs: HashMap::new(),
        returned_objects: HashMap::new(),
        pending_binds: None,
        stable_module_bindings: Some(bound),
        body_span: None,
        parameters: HashSet::new(),
        local_names: bindings.declared.clone(),
        known_bodies,
        returned_methods: &returned_methods,
        callback_sites: Default::default(),
        flushed_sites: 0,
        expanded_callbacks: HashSet::new(),
        array_elements: HashMap::new(),
        in_callback: false,
        callback_visits: 0,
        dynamic_namespaces: HashMap::new(),
        dynamic_chained_calls: HashSet::new(),
        nodes: 0,
        saturated: false,
        walk_depth: 0,
        process_runtime: bindings.process_runtime(),
        unsupported_process_receiver_reported: false,
        fact_file: file.to_string(),
        fact_function: String::new(),
        site_ordinal: 0,
        site_origins: HashMap::new(),
        _marker: std::marker::PhantomData,
    };
    for stmt in &program.body {
        if let Some(span) = super::control::module_load_span(stmt) {
            let module = match stmt {
                Statement::ImportDeclaration(import) => Some(import.source.value.as_str()),
                Statement::ExportAllDeclaration(export) => Some(export.source.value.as_str()),
                Statement::ExportNamedDeclaration(export) => {
                    export.source.as_ref().map(|source| source.value.as_str())
                }
                _ => None,
            }
            .expect("module load source");
            let mut facts = SiteFacts::known(Vec::new());
            if !super::model::is_node_builtin_module(module) {
                facts.exit = Some(ControlExit::Import {
                    module: module.to_string(),
                });
            }
            v.control
                .register(CAPTURE_SOURCE, true, super::control::span(span), facts);
        }
        v.visit_statement(stmt);
    }
    v.flush_callbacks();
    // Direct module analysis owns this file's model boundaries; from this
    // summary-only graph only budget refusals travel: the walk's own limits
    // and the control graph's.
    let boundary_start = v.boundaries.len();
    let flow = v.finish_control();
    let control_boundaries = v.boundaries.split_off(boundary_start);
    v.boundaries.retain(|boundary| boundary.limit.is_some());
    v.boundaries.extend(control_boundaries);
    (v.calls, v.effects, v.transfers, flow, v.boundaries)
}

/// A top-level function definition: its name, positional parameter names, and
/// body, in source order.
struct TopFn<'a> {
    name: String,
    is_async: bool,
    formal_params: &'a FormalParameters<'a>,
    params: Vec<String>,
    parameter_type_narrowing: Vec<Vec<String>>,
    body: &'a FunctionBody<'a>,
    process_scope: Option<bool>,
}

/// A callback passed by name: the function body its reference binds to, if
/// one is proven, and the arguments its call site proves for its formals.
#[derive(Clone)]
struct CallbackSite {
    callable: CallableRef,
    proven: Vec<Option<ResourceExpr>>,
}

/// A function named where a callable is expected: its summary name, the
/// body span its reference's symbol proves, and whether that symbol is a
/// reassigned local whose function is not known.
#[derive(Clone)]
struct CallableRef {
    name: String,
    span: Option<(u32, u32)>,
    rebound: bool,
}

/// Distinct argument bindings expanded per callback body before the rest
/// stay unresolved.
const MAX_CALLBACK_EXPANSIONS: usize = 4;

/// Every summarized function body by name: nested and block-local helpers
/// may share one, so a body is chosen by the span its reference binds to.
type KnownBodies<'a> = HashMap<String, Vec<KnownBody<'a>>>;

#[derive(Clone, Copy)]
struct KnownBody<'a> {
    body: &'a FunctionBody<'a>,
    formals: &'a FormalParameters<'a>,
    process_scope: Option<bool>,
}

fn parameter_type_narrowing(params: &FormalParameters) -> Vec<Vec<String>> {
    params
        .items
        .iter()
        .map(|item| {
            item.type_annotation
                .as_ref()
                .and_then(|annotation| finite_type_names(&annotation.type_annotation))
                .unwrap_or_default()
        })
        .collect()
}

fn finite_type_names(ty: &TSType<'_>) -> Option<Vec<String>> {
    fn push(ty: &TSType<'_>, names: &mut Vec<String>) -> Option<()> {
        match ty {
            TSType::TSTypeReference(reference) => {
                names.push(reference.type_name.to_string());
                Some(())
            }
            TSType::TSUnionType(union) if union.types.len() <= 4 => {
                for ty in &union.types {
                    push(ty, names)?;
                }
                Some(())
            }
            TSType::TSParenthesizedType(parenthesized) => {
                push(&parenthesized.type_annotation, names)
            }
            TSType::TSNullKeyword(_)
            | TSType::TSUndefinedKeyword(_)
            | TSType::TSNeverKeyword(_)
            | TSType::TSBooleanKeyword(_)
            | TSType::TSNumberKeyword(_)
            | TSType::TSStringKeyword(_) => Some(()),
            _ => None,
        }
    }
    let mut names = Vec::new();
    push(ty, &mut names)?;
    names.sort();
    names.dedup();
    (!names.is_empty()).then_some(names)
}

/// Bound on statement nesting while collecting function definitions, matching
/// the execution walk's collector.
const MAX_FN_COLLECT_DEPTH: u32 = 8;

/// Collect function declarations and `const/let/var` bindings to
/// function/arrow expressions — module scope first, then (bounded)
/// definitions nested inside function bodies (zx's `rmTemp` closure inside
/// `runScript`), so a call edge to a nested helper still resolves. Shallower
/// definitions sort first, and name lookups take the first match, so a
/// module-scope definition stays authoritative over a nested namesake.
fn top_level_functions<'a>(program: &'a Program<'a>) -> Vec<TopFn<'a>> {
    let mut out = Vec::new();
    collect_stmt_functions(&program.body, &mut out, 0);
    out.sort_by_key(|(depth, _)| *depth);
    out.into_iter().map(|(_, f)| f).collect()
}

struct ObjectMethodCollector<'v, 'a> {
    producer: String,
    bindings: &'v Bindings,
    consts: &'v ParamEnv,
    known_bodies: &'v KnownBodies<'a>,
    file: &'v str,
    functions: Vec<FunctionEntry>,
}

impl<'a> ObjectMethodCollector<'_, 'a> {
    fn collect_object(&mut self, object: &ObjectExpression<'a>, producer: &str) {
        for property in &object.properties {
            let oxc_ast::ast::ObjectPropertyKind::ObjectProperty(property) = property else {
                continue;
            };
            if property.computed || property.kind != PropertyKind::Init {
                continue;
            }
            let Some(name) = property.key.static_name() else {
                continue;
            };
            let qualified = format!("{producer}.{name}");
            match unparen(&property.value) {
                Expression::FunctionExpression(function) => {
                    if let Some(body) = &function.body {
                        self.functions.push(summarize_named_body(
                            qualified,
                            function.r#async,
                            param_names(&function.params),
                            &function.params,
                            parameter_type_narrowing(&function.params),
                            body,
                            super::function_process_scope(body, &function.params),
                            self.bindings,
                            self.consts,
                            self.known_bodies,
                            &HashSet::new(),
                            self.file,
                        ));
                    }
                }
                Expression::ArrowFunctionExpression(function) => {
                    self.functions.push(summarize_named_body(
                        qualified,
                        function.r#async,
                        param_names(&function.params),
                        &function.params,
                        parameter_type_narrowing(&function.params),
                        &function.body,
                        super::function_process_scope(&function.body, &function.params),
                        self.bindings,
                        self.consts,
                        self.known_bodies,
                        &HashSet::new(),
                        self.file,
                    ))
                }
                Expression::ObjectExpression(nested) => self.collect_object(nested, &qualified),
                _ => {}
            }
        }
    }
}

impl<'a> Visit<'a> for ObjectMethodCollector<'_, 'a> {
    fn visit_object_expression(&mut self, object: &ObjectExpression<'a>) {
        let producer = self.producer.clone();
        self.collect_object(object, &producer);
    }
}

fn returned_object_functions<'a>(
    functions: &[TopFn<'a>],
    bindings: &Bindings,
    consts: &ParamEnv,
    known_bodies: &KnownBodies<'a>,
    file: &str,
) -> (Vec<FunctionEntry>, HashSet<String>) {
    let mut out = Vec::new();
    let mut producers = HashSet::new();
    let mut seen = HashSet::new();
    for function in functions {
        let mut returns = Vec::new();
        let mut saw_bare = false;
        resolve::collect_returns(&function.body.statements, &mut returns, &mut saw_bare);
        let returns_object = !saw_bare
            && returns.len() == 1
            && returns
                .iter()
                .all(|returned| matches!(unparen(returned), Expression::ObjectExpression(_)));
        if returns_object {
            producers.insert(function.name.clone());
        }
        for returned in &returns {
            let mut collector = ObjectMethodCollector {
                producer: function.name.clone(),
                bindings,
                consts,
                known_bodies,
                file,
                functions: Vec::new(),
            };
            collector.visit_expression(returned);
            for entry in collector.functions {
                if seen.insert(entry.name.clone()) {
                    out.push(entry);
                }
            }
        }
    }
    (out, producers)
}

fn module_object_functions<'a>(
    program: &'a Program<'a>,
    bound: &HashMap<String, u32>,
    bindings: &Bindings,
    consts: &ParamEnv,
    known_bodies: &KnownBodies<'a>,
    file: &str,
) -> Vec<FunctionEntry> {
    let mut out = Vec::new();
    for statement in &program.body {
        let declaration = statement.as_declaration().or_else(|| match statement {
            Statement::ExportNamedDeclaration(export) => export.declaration.as_ref(),
            _ => None,
        });
        if let Some(Declaration::VariableDeclaration(variable)) = declaration {
            for declarator in &variable.declarations {
                let (
                    BindingPattern::BindingIdentifier(id),
                    Some(Expression::ObjectExpression(object)),
                ) = (&declarator.id, declarator.init.as_ref().map(unparen))
                else {
                    continue;
                };
                let producer = id.name.as_str();
                if bound.get(producer) != Some(&1) {
                    continue;
                }
                let mut collector = ObjectMethodCollector {
                    producer: producer.to_string(),
                    bindings,
                    consts,
                    known_bodies,
                    file,
                    functions: Vec::new(),
                };
                collector.collect_object(object, producer);
                out.extend(
                    collector
                        .functions
                        .into_iter()
                        .filter(|function| !bindings.member_was_reassigned(&function.name)),
                );
            }
        }
        if let Statement::ExportDefaultDeclaration(export) = statement
            && let ExportDefaultDeclarationKind::ObjectExpression(object) = &export.declaration
        {
            let mut collector = ObjectMethodCollector {
                producer: "default".to_string(),
                bindings,
                consts,
                known_bodies,
                file,
                functions: Vec::new(),
            };
            collector.collect_object(object, "default");
            out.extend(collector.functions);
        }
    }
    out
}

fn collect_stmt_functions<'a>(
    stmts: &'a [Statement<'a>],
    out: &mut Vec<(u32, TopFn<'a>)>,
    depth: u32,
) {
    if depth > MAX_FN_COLLECT_DEPTH {
        return;
    }
    // Where the whole-module callable and its nested definitions sit in
    // `out`: a later assignment replaces an earlier one and the helpers only
    // it defined, and stays at its own source position.
    let mut commonjs_default: Option<std::ops::Range<usize>> = None;
    for stmt in stmts {
        // A bare declaration or the declaration inside `export function foo` /
        // `export const bar = ...` — an exported function is still a top-level
        // callable the repository must resolve across files.
        let decl = stmt.as_declaration().or_else(|| match stmt {
            Statement::ExportNamedDeclaration(e) => e.declaration.as_ref(),
            _ => None,
        });
        if let Some(decl) = decl {
            collect_decl_functions(decl, out, depth);
        }
        if let Statement::ExportDefaultDeclaration(e) = stmt {
            collect_default_function(&e.declaration, out, depth);
        }
        // A block's own declarations: a call edge names its callee by body
        // span, so a block-local helper never stands in for a namesake.
        if let Statement::BlockStatement(block) = stmt {
            collect_stmt_functions(&block.body, out, depth + 1);
        }
        if depth == 0
            && let Some(functions) = collect_commonjs_default_function(stmt)
        {
            if let Some(previous) = commonjs_default.take() {
                out.drain(previous);
            }
            let start = out.len();
            out.extend(functions);
            commonjs_default = Some(start..out.len());
        }
    }
}

/// `module.exports = function () {}` / `module.exports = () => {}`: the
/// module's whole value is callable, which is what an ES default import of
/// it binds, so it is summarized as `default` too.
fn collect_commonjs_default_function<'a>(stmt: &'a Statement<'a>) -> Option<Vec<(u32, TopFn<'a>)>> {
    let Statement::ExpressionStatement(statement) = stmt else {
        return None;
    };
    let Expression::AssignmentExpression(assignment) = unparen(&statement.expression) else {
        return None;
    };
    if !assignment.operator.is_assign()
        || !matches!(&assignment.left, AssignmentTarget::StaticMemberExpression(target) if is_module_exports(target))
    {
        return None;
    }
    let (formal_params, body, is_async) = match unparen(&assignment.right) {
        Expression::FunctionExpression(function) => (
            &function.params,
            &**function.body.as_ref()?,
            function.r#async,
        ),
        Expression::ArrowFunctionExpression(arrow) => (&arrow.params, &*arrow.body, arrow.r#async),
        _ => return None,
    };
    let mut out = Vec::new();
    out.push((
        0,
        TopFn {
            name: "default".to_string(),
            params: param_names(formal_params),
            is_async,
            formal_params,
            parameter_type_narrowing: parameter_type_narrowing(formal_params),
            body,
            process_scope: super::function_process_scope(body, formal_params),
        },
    ));
    collect_stmt_functions(&body.statements, &mut out, 1);
    Some(out)
}

/// `export default function name()` / `export default () => {}` / an inline
/// function expression: the module's default export is callable as `default`.
fn collect_default_function<'a>(
    decl: &'a ExportDefaultDeclarationKind<'a>,
    out: &mut Vec<(u32, TopFn<'a>)>,
    depth: u32,
) {
    match decl {
        ExportDefaultDeclarationKind::FunctionDeclaration(func) => {
            let Some(body) = &func.body else {
                return;
            };
            let params = param_names(&func.params);
            let parameter_type_narrowing = parameter_type_narrowing(&func.params);
            if let Some(id) = &func.id {
                out.push((
                    depth,
                    TopFn {
                        name: id.name.as_str().to_string(),
                        params: params.clone(),
                        is_async: func.r#async,
                        formal_params: &func.params,
                        parameter_type_narrowing: parameter_type_narrowing.clone(),
                        body,
                        process_scope: super::function_process_scope(body, &func.params),
                    },
                ));
            }
            out.push((
                depth,
                TopFn {
                    name: "default".to_string(),
                    params,
                    formal_params: &func.params,
                    is_async: func.r#async,
                    parameter_type_narrowing,
                    body,
                    process_scope: super::function_process_scope(body, &func.params),
                },
            ));
            collect_stmt_functions(&body.statements, out, depth + 1);
        }
        ExportDefaultDeclarationKind::FunctionExpression(func) => {
            let Some(body) = &func.body else {
                return;
            };
            out.push((
                depth,
                TopFn {
                    name: "default".to_string(),
                    params: param_names(&func.params),
                    formal_params: &func.params,
                    is_async: func.r#async,
                    parameter_type_narrowing: parameter_type_narrowing(&func.params),
                    body,
                    process_scope: super::function_process_scope(body, &func.params),
                },
            ));
            collect_stmt_functions(&body.statements, out, depth + 1);
        }
        ExportDefaultDeclarationKind::ArrowFunctionExpression(a) => {
            out.push((
                depth,
                TopFn {
                    name: "default".to_string(),
                    params: param_names(&a.params),
                    is_async: a.r#async,
                    formal_params: &a.params,
                    parameter_type_narrowing: parameter_type_narrowing(&a.params),
                    body: &a.body,
                    process_scope: super::function_process_scope(&a.body, &a.params),
                },
            ));
            collect_stmt_functions(&a.body.statements, out, depth + 1);
        }
        _ => {}
    }
}

fn collect_decl_functions<'a>(
    decl: &'a Declaration<'a>,
    out: &mut Vec<(u32, TopFn<'a>)>,
    depth: u32,
) {
    match decl {
        Declaration::FunctionDeclaration(func) => {
            if let (Some(id), Some(body)) = (&func.id, &func.body) {
                out.push((
                    depth,
                    TopFn {
                        name: id.name.as_str().to_string(),
                        params: param_names(&func.params),
                        formal_params: &func.params,
                        is_async: func.r#async,
                        parameter_type_narrowing: parameter_type_narrowing(&func.params),
                        body,
                        process_scope: super::function_process_scope(body, &func.params),
                    },
                ));
                collect_stmt_functions(&body.statements, out, depth + 1);
            }
        }
        Declaration::VariableDeclaration(v) => {
            for d in &v.declarations {
                if let (BindingPattern::BindingIdentifier(id), Some(init)) = (&d.id, &d.init) {
                    let f = match init {
                        Expression::FunctionExpression(f) => f.body.as_ref().map(|b| {
                            (
                                param_names(&f.params),
                                f.r#async,
                                &*f.params,
                                parameter_type_narrowing(&f.params),
                                &**b,
                                super::function_process_scope(b, &f.params),
                            )
                        }),
                        Expression::ArrowFunctionExpression(a) => Some((
                            param_names(&a.params),
                            a.r#async,
                            &*a.params,
                            parameter_type_narrowing(&a.params),
                            &*a.body,
                            super::function_process_scope(&a.body, &a.params),
                        )),
                        _ => None,
                    };
                    if let Some((
                        params,
                        is_async,
                        formal_params,
                        parameter_type_narrowing,
                        body,
                        process_scope,
                    )) = f
                    {
                        out.push((
                            depth,
                            TopFn {
                                name: id.name.as_str().to_string(),
                                params,
                                formal_params,
                                is_async,
                                parameter_type_narrowing,
                                body,
                                process_scope,
                            },
                        ));
                        collect_stmt_functions(&body.statements, out, depth + 1);
                    }
                }
            }
        }
        _ => {}
    }
}

/// Class declarations (including `export class` / `export default class`) and
/// their methods, registered as `Class.method` so composition can dispatch a
/// typed receiver. A default-exported class is also filed under `default`.
fn collect_classes(
    program: &Program,
    functions: &mut Vec<FunctionEntry>,
    bindings: &Bindings,
    consts: &ParamEnv,
    known_bodies: &KnownBodies<'_>,
    file: &str,
) -> Vec<ClassEntry> {
    let mut classes = Vec::new();
    for stmt in &program.body {
        let class = class_from_stmt(stmt);
        let default = matches!(stmt, Statement::ExportDefaultDeclaration(_));
        if let Some(class) = class {
            push_class(
                class,
                default,
                &mut classes,
                functions,
                bindings,
                consts,
                known_bodies,
                file,
            );
        }
    }
    classes
}

fn class_from_stmt<'a>(stmt: &'a Statement<'a>) -> Option<&'a Class<'a>> {
    if let Some(Declaration::ClassDeclaration(c)) = stmt.as_declaration() {
        return Some(c);
    }
    match stmt {
        Statement::ExportNamedDeclaration(e) => match &e.declaration {
            Some(Declaration::ClassDeclaration(c)) => Some(c),
            _ => None,
        },
        Statement::ExportDefaultDeclaration(e) => match &e.declaration {
            ExportDefaultDeclarationKind::ClassDeclaration(c) => Some(c),
            _ => None,
        },
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
fn push_class(
    class: &Class,
    default: bool,
    classes: &mut Vec<ClassEntry>,
    functions: &mut Vec<FunctionEntry>,
    bindings: &Bindings,
    consts: &ParamEnv,
    known_bodies: &KnownBodies<'_>,
    file: &str,
) {
    let Some(id) = &class.id else {
        if default {
            collect_class_methods(
                "default",
                class,
                functions,
                bindings,
                consts,
                known_bodies,
                file,
            );
            classes.push(ClassEntry {
                name: "default".to_string(),
                ..Default::default()
            });
        }
        return;
    };
    let name = id.name.as_str().to_string();
    let bases = class
        .super_class
        .as_ref()
        .and_then(|s| match unparen(s) {
            Expression::Identifier(b) => Some(vec![b.name.as_str().to_string()]),
            _ => None,
        })
        .unwrap_or_default();
    collect_class_methods(
        &name,
        class,
        functions,
        bindings,
        consts,
        known_bodies,
        file,
    );
    classes.push(ClassEntry {
        name: name.clone(),
        bases: bases.clone(),
        ..Default::default()
    });
    if default {
        classes.push(ClassEntry {
            name: "default".to_string(),
            bases: vec![name],
            ..Default::default()
        });
    }
}

fn collect_class_methods(
    class_name: &str,
    class: &Class,
    functions: &mut Vec<FunctionEntry>,
    bindings: &Bindings,
    consts: &ParamEnv,
    known_bodies: &KnownBodies<'_>,
    file: &str,
) {
    for el in &class.body.body {
        let ClassElement::MethodDefinition(m) = el else {
            continue;
        };
        if !matches!(
            m.kind,
            MethodDefinitionKind::Method | MethodDefinitionKind::Constructor
        ) {
            continue;
        }
        let Some(method) = property_key_name(&m.key) else {
            continue;
        };
        let Some(body) = &m.value.body else {
            continue;
        };
        let name = if m.kind == MethodDefinitionKind::Constructor {
            class_name.to_string()
        } else {
            format!("{class_name}.{method}")
        };
        functions.push(summarize_function(
            &TopFn {
                name,
                params: param_names(&m.value.params),
                is_async: m.value.r#async,
                formal_params: &m.value.params,
                parameter_type_narrowing: parameter_type_narrowing(&m.value.params),
                body,
                process_scope: super::function_process_scope(body, &m.value.params),
            },
            bindings,
            consts,
            known_bodies,
            &HashSet::new(),
            file,
        ));
    }
}

fn property_key_name(key: &PropertyKey) -> Option<String> {
    key.static_name().map(|s| s.to_string())
}

/// `export default runTasks` / `export default Shell`: the default export is
/// an alias of a same-file function or class, so a default-import call or
/// `new` resolves without inventing a second body.
fn alias_default_export(
    program: &Program,
    functions: &mut Vec<FunctionEntry>,
    classes: &mut Vec<ClassEntry>,
) {
    if functions.iter().any(|f| f.name == "default") || classes.iter().any(|c| c.name == "default")
    {
        return;
    }
    for stmt in &program.body {
        let Statement::ExportDefaultDeclaration(e) = stmt else {
            continue;
        };
        let ExportDefaultDeclarationKind::Identifier(id) = &e.declaration else {
            continue;
        };
        let local = id.name.as_str();
        // Module-scope definitions sort first.
        if let Some(function) = functions.iter().find(|f| f.name == local) {
            let callee_span = function.lexical_span;
            functions.push(FunctionEntry {
                name: "default".to_string(),
                calls: vec![CallEdge {
                    callee: local.to_string(),
                    callee_span,
                    ..Default::default()
                }],
                ..Default::default()
            });
        } else if classes.iter().any(|c| c.name == local) {
            classes.push(ClassEntry {
                name: "default".to_string(),
                bases: vec![local.to_string()],
                ..Default::default()
            });
        }
        return;
    }
}

fn summarize_function<'a>(
    func: &TopFn<'a>,
    bindings: &Bindings,
    consts: &ParamEnv,
    known_bodies: &KnownBodies<'a>,
    returned_methods: &HashSet<String>,
    file: &str,
) -> FunctionEntry {
    let mut entry = summarize_named_body(
        func.name.clone(),
        func.is_async,
        func.params.clone(),
        func.formal_params,
        func.parameter_type_narrowing.clone(),
        func.body,
        func.process_scope,
        bindings,
        consts,
        known_bodies,
        returned_methods,
        file,
    );
    entry.lexical_span = Some((func.body.span.start, func.body.span.end));
    entry
}

#[allow(clippy::too_many_arguments)]
fn summarize_named_body<'a>(
    name: String,
    is_async: bool,
    params: Vec<String>,
    formal_params: &FormalParameters<'a>,
    parameter_type_narrowing: Vec<Vec<String>>,
    body: &FunctionBody<'a>,
    process_scope: Option<bool>,
    bindings: &Bindings,
    consts: &ParamEnv,
    known_bodies: &KnownBodies<'a>,
    returned_methods: &HashSet<String>,
    file: &str,
) -> FunctionEntry {
    let _walk = crate::limits::summary_walk();
    // Parameters resolve to symbolic Parameter nodes so a modeled call on a
    // parameter yields a parameterized effect the repository can specialize.
    let param_env: ParamEnv = params
        .iter()
        .filter(|p| !p.is_empty())
        .map(|p| (p.clone(), ResourceExpr::Parameter { name: p.clone() }))
        .collect();

    // Return-value inference resolves module constants but keeps parameters
    // symbolic, so `path.join(BASE, t)` becomes `Join[<BASE>, Parameter t]`.
    // A parameter that shadows a constant wins.
    let mut ret_env = consts.clone();
    ret_env.extend(param_env.iter().map(|(k, v)| (k.clone(), v.clone())));
    let returns = resolve::infer_returns(&body.statements, None, None, &ret_env, bindings)
        .map(SemanticValue::from);

    let mut local_names = super::function_local_binding_names(body);
    local_names.extend(params.iter().filter(|p| !p.is_empty()).cloned());
    let mut object_literal_vars = bindings.object_literal_vars.clone();
    let mut source_literals = bindings.source_literals.clone();
    for name in &local_names {
        object_literal_vars.remove(name);
        source_literals.remove(name);
    }

    let mut v = SummaryVisitor {
        bindings,
        param_env,
        control: summary_control(|graph| {
            super::control::build_function(graph, formal_params, body, &bindings.readonly_writes)
        }),
        object_literal_vars,
        source_literals,
        effects: Vec::new(),
        transfers: Vec::new(),
        boundaries: Vec::new(),
        calls: Vec::new(),
        instance_vars: HashMap::new(),
        instance_attrs: HashMap::new(),
        callable_attrs: HashMap::new(),
        returned_objects: HashMap::new(),
        pending_binds: None,
        stable_module_bindings: None,
        body_span: Some((body.span.start, body.span.end)),
        parameters: params.iter().filter(|p| !p.is_empty()).cloned().collect(),
        local_names,
        known_bodies,
        returned_methods,
        callback_sites: Default::default(),
        flushed_sites: 0,
        expanded_callbacks: HashSet::new(),
        array_elements: HashMap::new(),
        in_callback: false,
        callback_visits: 0,
        dynamic_namespaces: HashMap::new(),
        dynamic_chained_calls: HashSet::new(),
        nodes: 0,
        saturated: false,
        walk_depth: 0,
        process_runtime: process_scope.unwrap_or_else(|| bindings.process_runtime()),
        unsupported_process_receiver_reported: false,
        fact_file: file.to_string(),
        fact_function: name.clone(),
        site_ordinal: 0,
        site_origins: HashMap::new(),
        _marker: std::marker::PhantomData,
    };
    for parameter in &formal_params.items {
        if let Some(initializer) = &parameter.initializer {
            v.visit_expression(initializer);
        }
    }
    // Walk the body statements directly; function visits are no-ops so
    // nested definitions are not descended into (they are separate entries).
    for stmt in &body.statements {
        v.visit_statement(stmt);
    }
    v.flush_callbacks();

    let returns_instances = infer_returns_instances(&body.statements, bindings, &v.instance_vars);
    let control_flow = v.finish_control();

    // The function contributes coverage in whatever domains it touches; a
    // recorded boundary degrades those at apply time.
    let coverage = JS_DOMAINS
        .iter()
        .map(|d| (Domain::new(*d), CoverageLevel::Full))
        .collect();

    FunctionEntry {
        name,
        is_async,
        summary: Summary {
            control_flow,
            params,
            effects: v.effects,
            effect_models: Vec::new(),
            transfers: v.transfers,
            returns,
            boundaries: v.boundaries,
            coverage,
        },
        calls: v.calls,
        parameter_type_narrowing,
        returns_instances,
        ..Default::default()
    }
}

/// Class (as written) or namespace-import name a function returns, when every
/// `return` agrees. Used so a caller can type `const tool = getTool(); tool.m()`.
fn infer_returns_instances(
    stmts: &[Statement],
    bindings: &Bindings,
    instance_vars: &HashMap<String, SemanticValue>,
) -> Vec<Option<String>> {
    let mut values = Vec::new();
    let mut saw_bare = false;
    resolve::collect_returns(stmts, &mut values, &mut saw_bare);
    if saw_bare || values.is_empty() {
        return Vec::new();
    }
    let mut result: Option<String> = None;
    for expr in values {
        let class = instance_class_name(expr, bindings, instance_vars);
        match &result {
            None => result = class,
            Some(prev) if class.as_deref() == Some(prev) => {}
            _ => return Vec::new(),
        }
    }
    match result {
        Some(name) => vec![Some(name)],
        None => Vec::new(),
    }
}

fn instance_class_name(
    expr: &Expression,
    bindings: &Bindings,
    instance_vars: &HashMap<String, SemanticValue>,
) -> Option<String> {
    match unparen(expr) {
        Expression::Identifier(id) => {
            let name = id.name.as_str();
            if let Some(SemanticValue {
                kind:
                    SemanticValueKind::Object(crate::ObjectValue {
                        identity: ObjectIdentity::Class { name, .. },
                        ..
                    }),
                ..
            }) = instance_vars.get(name)
            {
                return Some(name.clone());
            }
            // A namespace/default import returned as a value is the module's
            // export object (`return npm`).
            if bindings.namespaces.contains_key(name) {
                return Some(name.to_string());
            }
            None
        }
        Expression::NewExpression(n) => new_class_name(n),
        Expression::AwaitExpression(a) => instance_class_name(&a.argument, bindings, instance_vars),
        _ => None,
    }
}

fn new_class_name(new_expr: &oxc_ast::ast::NewExpression) -> Option<String> {
    match unparen(&new_expr.callee) {
        Expression::Identifier(id) => Some(id.name.as_str().to_string()),
        _ => None,
    }
}

/// Collects import bindings in source order.
#[derive(Default)]
struct ImportCollector {
    imports: Vec<ImportBinding>,
    exports: Vec<ImportBinding>,
    /// `export { local as exported }` declarations resolved after imports have
    /// all been collected.
    local_exports: Vec<(String, String)>,
    /// Names declared by `export const` whose confirmed aliases are exported.
    exported_declarations: HashSet<String>,
    /// `const X = wrap('fs', _fs)` candidates: X may alias the external module
    /// (or the one named external export) `_fs` was bound to. Confirmed only
    /// when X is never rebound.
    aliases: Vec<(String, String, Option<String>)>,
    /// How many times each identifier is bound (declarator or assignment); a
    /// name bound more than once is ambiguous and never aliases.
    bound: std::collections::HashMap<String, u32>,
    module_loads: Vec<ModuleLoadEvidence>,
    function_depth: u32,
    walk_depth: u32,
}

impl ImportCollector {
    /// The external binding an identifier names — a whole-module
    /// (namespace/default/require) or named import of a non-relative
    /// specifier — as `(module, imported)`.
    fn external_binding(&self, name: &str) -> Option<(String, Option<String>)> {
        self.imports
            .iter()
            .find(|b| b.local == name && !b.module.starts_with('.'))
            .map(|b| (b.module.clone(), b.imported.clone()))
    }
}

impl<'a> Visit<'a> for ImportCollector {
    fn visit_expression(&mut self, it: &Expression<'a>) {
        if self.walk_depth >= MAX_WALK_DEPTH {
            return;
        }
        self.walk_depth += 1;
        walk::walk_expression(self, it);
        self.walk_depth -= 1;
    }

    fn visit_statement(&mut self, it: &Statement<'a>) {
        if self.walk_depth >= MAX_WALK_DEPTH {
            return;
        }
        self.walk_depth += 1;
        walk::walk_statement(self, it);
        self.walk_depth -= 1;
    }

    fn visit_import_declaration(&mut self, it: &ImportDeclaration<'a>) {
        let module = resolve::canonical_module(it.source.value.as_str());
        let Some(specifiers) = &it.specifiers else {
            // `import '@pkg/cli'` loads the module for its top-level effects.
            self.imports.push(ImportBinding {
                local: String::new(),
                module,
                imported: None,
            });
            return;
        };
        for spec in specifiers {
            match spec {
                ImportDeclarationSpecifier::ImportSpecifier(s) => {
                    *self
                        .bound
                        .entry(s.local.name.as_str().to_string())
                        .or_default() += 1;
                    self.imports.push(ImportBinding {
                        local: s.local.name.as_str().to_string(),
                        module: module.clone(),
                        imported: Some(s.imported.name().as_str().to_string()),
                    })
                }
                ImportDeclarationSpecifier::ImportDefaultSpecifier(s) => {
                    *self
                        .bound
                        .entry(s.local.name.as_str().to_string())
                        .or_default() += 1;
                    self.imports.push(ImportBinding {
                        local: s.local.name.as_str().to_string(),
                        module: module.clone(),
                        imported: Some("default".to_string()),
                    })
                }
                ImportDeclarationSpecifier::ImportNamespaceSpecifier(s) => {
                    *self
                        .bound
                        .entry(s.local.name.as_str().to_string())
                        .or_default() += 1;
                    self.imports.push(ImportBinding {
                        local: s.local.name.as_str().to_string(),
                        module: module.clone(),
                        imported: None,
                    })
                }
            }
        }
    }

    // `import('mod')` / `await import('mod')` loads the module. A bound form
    // (`const { init } = await import('./x')`) is also recorded on the
    // declarator; the empty-local binding here still executes the target.
    fn visit_import_expression(&mut self, it: &ImportExpression<'a>) {
        if let Expression::StringLiteral(s) = &it.source {
            self.imports.push(ImportBinding {
                local: String::new(),
                module: resolve::canonical_module(s.value.as_str()),
                imported: None,
            });
        }
        walk::walk_import_expression(self, it);
    }

    // `export { fs } from './vendor.ts'` re-exports names without a local
    // binding; recorded as import bindings so cross-file resolution can chase
    // the exported name into its defining module.
    fn visit_export_named_declaration(&mut self, it: &oxc_ast::ast::ExportNamedDeclaration<'a>) {
        if let Some(source) = &it.source {
            let module = resolve::canonical_module(source.value.as_str());
            for spec in &it.specifiers {
                let binding = ImportBinding {
                    local: spec.exported.name().as_str().to_string(),
                    module: module.clone(),
                    imported: Some(spec.local.name().as_str().to_string()),
                };
                self.imports.push(binding.clone());
                self.exports.push(binding);
            }
        } else {
            for spec in &it.specifiers {
                self.local_exports.push((
                    spec.exported.name().as_str().to_string(),
                    spec.local.name().as_str().to_string(),
                ));
            }
            if let Some(Declaration::VariableDeclaration(variable)) = &it.declaration {
                for declarator in &variable.declarations {
                    if let BindingPattern::BindingIdentifier(id) = &declarator.id {
                        self.exported_declarations
                            .insert(id.name.as_str().to_string());
                    }
                }
            }
        }
        walk::walk_export_named_declaration(self, it);
    }

    // `export * from './core.ts'`: every name of the target is re-exported.
    // Recorded under the reserved local "*" — never a real lookup key, but the
    // resolver follows it when a name is not bound directly.
    fn visit_export_all_declaration(&mut self, it: &oxc_ast::ast::ExportAllDeclaration<'a>) {
        let module = resolve::canonical_module(it.source.value.as_str());
        let local = match &it.exported {
            Some(name) => name.name().as_str().to_string(),
            None => "*".to_string(),
        };
        let binding = ImportBinding {
            local,
            module,
            imported: None,
        };
        self.imports.push(binding.clone());
        self.exports.push(binding);
    }

    fn visit_variable_declarator(&mut self, it: &VariableDeclarator<'a>) {
        if self.function_depth == 0 {
            count_binding_pattern(&it.id, &mut self.bound);
        }
        if let Some(init) = &it.init
            && let Some(module) = resolve::bound_module(init)
        {
            let commonjs = resolve::require_module(init).is_some();
            match &it.id {
                BindingPattern::BindingIdentifier(id) => {
                    let local = id.name.as_str().to_string();
                    if commonjs {
                        self.module_loads.push(ModuleLoadEvidence {
                            local: local.clone(),
                            module: module.clone(),
                            kind: ModuleLoadKind::CommonJs,
                        });
                    }
                    self.imports.push(ImportBinding {
                        local,
                        module,
                        imported: None,
                    })
                }
                BindingPattern::ObjectPattern(obj) => {
                    for prop in &obj.properties {
                        if let (Some(key), BindingPattern::BindingIdentifier(local)) =
                            (prop.key.static_name(), &prop.value)
                        {
                            let local = local.name.as_str().to_string();
                            if commonjs {
                                self.module_loads.push(ModuleLoadEvidence {
                                    local: local.clone(),
                                    module: module.clone(),
                                    kind: ModuleLoadKind::CommonJs,
                                });
                            }
                            self.imports.push(ImportBinding {
                                local,
                                module: module.clone(),
                                imported: Some(key.to_string()),
                            });
                        }
                    }
                }
                _ => {}
            }
        } else if let (BindingPattern::BindingIdentifier(id), Some(init)) = (&it.id, &it.init)
            && let Expression::CallExpression(call) = unparen(init)
        {
            // `export const fs = wrap('fs', _fs)` (zx's vendored wrappers):
            // a const initialized by a call handed exactly one external
            // import aliases what that import was bound to — the whole module
            // for a namespace import, one export for a named import. More
            // than one wrapped import is ambiguous and never aliases.
            let mut wrapped: Vec<(String, Option<String>)> = Vec::new();
            for arg in &call.arguments {
                if let Some(Expression::Identifier(a)) = arg.as_expression().map(unparen)
                    && let Some(binding) = self.external_binding(a.name.as_str())
                {
                    wrapped.push(binding);
                }
            }
            if let [(module, imported)] = wrapped.as_slice() {
                self.aliases.push((
                    id.name.as_str().to_string(),
                    module.clone(),
                    imported.clone(),
                ));
            }
        }
        walk::walk_variable_declarator(self, it);
    }

    fn visit_assignment_target(&mut self, it: &AssignmentTarget<'a>) {
        if self.function_depth == 0
            && let AssignmentTarget::AssignmentTargetIdentifier(id) = it
        {
            *self.bound.entry(id.name.as_str().to_string()).or_default() += 1;
        }
        walk::walk_assignment_target(self, it);
    }

    fn visit_function_body(&mut self, it: &FunctionBody<'a>) {
        self.function_depth += 1;
        walk::walk_function_body(self, it);
        self.function_depth -= 1;
    }
}

struct SummaryVisitor<'v, 'a> {
    control: ControlStack,
    bindings: &'v Bindings,
    param_env: ParamEnv,
    object_literal_vars: ObjectLiteralBindings,
    source_literals: HashMap<String, String>,
    effects: Vec<Effect>,
    /// Transfer pairings among `effects`, by slot.
    transfers: Vec<TransferBinding>,
    boundaries: Vec<Boundary>,
    calls: Vec<CallEdge>,
    /// Local → constructed value (`const shell = new Shell()`).
    instance_vars: HashMap<String, SemanticValue>,
    /// `(obj, prop)` → constructed value (`container.shell = new Shell()`).
    instance_attrs: HashMap<(String, String), SemanticValue>,
    /// Local aliases and collection properties that retain a callable's exact
    /// defining name across rebinding, destructuring, and object spread.
    callable_attrs: HashMap<(String, String), CallableRef>,
    /// Local → producer function for a statically returned object value.
    returned_objects: HashMap<String, String>,
    /// Call currently being recorded, so `const x = foo()` can attach binds.
    pending_binds: Option<Vec<(usize, String)>>,
    /// Module bindings that are never rebound. Only the module execution walk
    /// records constructor calls for singleton resolution.
    stable_module_bindings: Option<&'v HashMap<String, u32>>,
    /// Declared parameters are runtime values supplied by callers. They can
    /// dispatch only when composition binds one to an evidence-backed object.
    parameters: HashSet<String>,
    local_names: HashSet<String>,
    /// Bodies of functions defined in this file, walked when a later call
    /// passes the name as a callback (`const task = () => ...; show({task})`).
    known_bodies: &'v KnownBodies<'a>,
    returned_methods: &'v HashSet<String>,
    /// Each callback passed by name, in the order the walk met it, and how
    /// many of them `flush_callbacks` has handled.
    callback_sites: std::cell::RefCell<Vec<CallbackSite>>,
    flushed_sites: usize,
    /// Each distinct `(body, proven arguments)` expansion of a callback body,
    /// so a callback that passes itself on stops.
    expanded_callbacks: HashSet<String>,
    /// Resolved elements of each fixed array (see `Bindings::fixed_arrays`),
    /// by its binding's span start.
    array_elements: HashMap<u32, Vec<Option<ResourceExpr>>>,
    /// The span of the function body this visitor summarizes; None at module
    /// level. A callback declared inside it sees its bindings.
    body_span: Option<(u32, u32)>,
    in_callback: bool,
    callback_visits: u64,
    dynamic_namespaces: HashMap<String, Vec<String>>,
    dynamic_chained_calls: HashSet<u32>,
    nodes: u64,
    saturated: bool,
    walk_depth: u32,
    process_runtime: bool,
    unsupported_process_receiver_reported: bool,
    fact_file: String,
    fact_function: String,
    site_ordinal: u32,
    site_origins: HashMap<usize, ValueOrigin>,
    _marker: std::marker::PhantomData<&'a ()>,
}

impl<'a> Visit<'a> for SummaryVisitor<'_, 'a> {
    fn visit_variable_declaration(&mut self, it: &oxc_ast::ast::VariableDeclaration<'a>) {
        if it.kind.is_using() {
            self.opaque("resource disposal or asynchronous cleanup");
        }
        walk::walk_variable_declaration(self, it);
    }

    fn visit_expression(&mut self, it: &Expression<'a>) {
        if !self.enter_walk() {
            return;
        }
        let start = self.effects.len();
        let call_start = self.calls.len();
        let awaited_site = match it {
            Expression::AwaitExpression(awaited) => match unparen(&awaited.argument) {
                Expression::CallExpression(call) => Some(effinterp_proto::stable_hash(
                    effinterp_proto::CONDITION_SITE_HASH_DOMAIN,
                    &(&self.bindings.source_digest, call.span.start, call.span.end),
                )),
                _ => None,
            },
            _ => None,
        };
        walk::walk_expression(self, it);
        let guard = self.bindings.guards.at(effinterp_proto::ByteSpan {
            start: it.span().start,
            end: it.span().end,
        });
        for effect in &mut self.effects[start..] {
            effect.condition =
                effinterp_proto::Condition::compose(effect.condition.iter().chain(guard.iter()));
        }
        for call in &mut self.calls[call_start..] {
            if awaited_site.is_some() && call.call_site == awaited_site {
                call.awaited = true;
            }
            call.condition =
                effinterp_proto::Condition::compose(call.condition.iter().chain(guard.iter()));
            if call.call_site.is_none() {
                call.call_site = Some(effinterp_proto::stable_hash(
                    effinterp_proto::CONDITION_SITE_HASH_DOMAIN,
                    &(&self.bindings.source_digest, it.span().start, it.span().end),
                ));
            }
        }
        self.walk_depth -= 1;
    }

    fn visit_statement(&mut self, it: &Statement<'a>) {
        if !self.enter_walk() {
            return;
        }
        walk::walk_statement(self, it);
        self.walk_depth -= 1;
    }

    // Nested function definitions are separate entries; do not descend.
    fn visit_function(
        &mut self,
        _it: &oxc_ast::ast::Function<'a>,
        _flags: oxc_semantic::ScopeFlags,
    ) {
    }

    fn visit_arrow_function_expression(&mut self, _it: &oxc_ast::ast::ArrowFunctionExpression<'a>) {
    }

    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        if !self.charge() {
            return;
        }
        let dynamic_callback = self.bindings.dynamic_imports.callback(it).cloned();
        let effect_start = self.effects.len();
        let call_start = self.calls.len();
        let callbacks = self.callback_visits;
        self.handle_call(it);
        let callee = unparen(&it.callee);
        let resolved = resolve::resolve_callee(callee, self.bindings);
        let inert = resolved
            .as_ref()
            .is_some_and(|callee| is_inert_module_call(&callee.module, &callee.function, it))
            || ((is_inert_callee(callee) || resolve::is_get_builtin_module(callee))
                && !super::model::inert_base_name(callee).is_some_and(|name| {
                    self.local_names.contains(name) || self.bindings.declared.contains(name)
                }));
        let direct_delete = resolved
            .as_ref()
            .is_some_and(|callee| callee.module == "fs" && callee.function == "unlinkSync");
        let mut facts = if direct_delete {
            SiteFacts::known(
                (effect_start..self.effects.len())
                    .map(|slot| ControlFact::Effect(slot as u32))
                    .collect(),
            )
        } else if inert
            || resolved.as_ref().is_some_and(|callee| {
                super::model::has_call_model(&callee.module, &callee.function, it)
            })
        {
            SiteFacts::known(Vec::new())
        } else {
            SiteFacts::unknown()
        };
        if self.calls.len() == call_start + 1 {
            facts.facts.push(ControlFact::Call(call_start as u32));
            facts.throw_facts.push(ControlFact::Call(call_start as u32));
            facts.call_return = self.calls[call_start].arguments.iter().all(|argument| {
                matches!(
                    &argument.value.kind,
                    SemanticValueKind::Literal(_) | SemanticValueKind::Parameter(_)
                )
            });
        }
        if let Expression::Identifier(name) = callee
            && name.name == "require"
            && inert
        {
            facts.exit = match it.arguments.first() {
                Some(Argument::StringLiteral(source))
                    if super::model::is_node_builtin_module(source.value.as_str()) =>
                {
                    None
                }
                Some(Argument::StringLiteral(source)) => Some(ControlExit::Import {
                    module: source.value.to_string(),
                }),
                _ => Some(ControlExit::Unknown),
            };
        }
        walk::walk_call_expression(self, it);
        // An inline function/arrow passed as an argument — including nested
        // in an object/array (`spinner.show({ task: () => shell.exec() })`)
        // — may be invoked by the callee. Named definitions passed by
        // reference are recorded as `fn_args` for composition.
        if let Some(callback) = dynamic_callback {
            if let Some(expr) = it
                .arguments
                .first()
                .and_then(|argument| argument.as_expression())
            {
                self.follow_dynamic_import_callback(expr, &callback);
            }
        } else {
            for (index, arg) in it.arguments.iter().enumerate() {
                if let Some(expr) = arg.as_expression() {
                    let invocations = if index == 0 {
                        self.callback_invocations(it)
                    } else {
                        vec![Vec::new()]
                    };
                    for proven in &invocations {
                        self.follow_callback_expr(expr, proven);
                    }
                }
            }
        }
        if self.callback_visits != callbacks {
            facts.exit = Some(ControlExit::Unknown);
            facts.call_return = false;
        }
        if !self.in_callback {
            self.control
                .register(CAPTURE_SOURCE, true, super::control::span(it.span), facts);
        }
    }

    fn visit_import_expression(&mut self, it: &ImportExpression<'a>) {
        if !self
            .bindings
            .dynamic_imports
            .is_literal_import(it.span.start)
        {
            self.opaque("dynamic import target");
        }
        walk::walk_import_expression(self, it);
    }

    fn visit_new_expression(&mut self, it: &NewExpression<'a>) {
        let call_start = self.calls.len();
        if resolve::is_function_constructor(it)
            && !self.bindings.dynamic_imports.is_transparent_constructor(it)
        {
            self.opaque("dynamic code execution (Function)");
        }
        if let Some(binds) = self.pending_binds.take()
            && let Some(class) = new_class_name(it)
        {
            let arguments =
                positional_arguments(it.arguments.iter().map(|argument| self.arg_value(argument)));
            let origin = self.origin_for_node(it);
            self.calls.push(CallEdge {
                callee: class.clone(),
                arguments: arguments.clone(),
                receiver: Some(
                    SemanticValue::object(ObjectIdentity::Class {
                        name: class.clone(),
                        constructor: arguments,
                    })
                    .with_origin(Some(origin.clone())),
                ),
                results: binds
                    .into_iter()
                    .map(|(index, binding)| {
                        CallResult::new(
                            index,
                            Some(binding),
                            Some(origin.clone()),
                            Some(TypeRef::External {
                                path: class.clone(),
                            }),
                        )
                    })
                    .collect(),
                ..Default::default()
            });
        }
        if !self.in_callback && self.calls.len() == call_start + 1 {
            let mut facts = SiteFacts::unknown();
            facts.facts.push(ControlFact::Call(call_start as u32));
            facts.throw_facts.push(ControlFact::Call(call_start as u32));
            facts.call_return = true;
            self.control
                .register(CAPTURE_SOURCE, true, super::control::span(it.span), facts);
        }
        walk::walk_new_expression(self, it);
    }

    fn visit_variable_declarator(&mut self, it: &VariableDeclarator<'a>) {
        self.track_binding(&it.id, it.init.as_ref());
        walk::walk_variable_declarator(self, it);
        if let BindingPattern::BindingIdentifier(id) = &it.id {
            let name = id.name.as_str().to_string();
            self.object_literal_vars.remove(&name);
            self.source_literals.remove(&name);
            if let Some(init) = &it.init {
                if let Some(object) = object_literal(init, &self.object_literal_vars) {
                    self.object_literal_vars.insert(name.clone(), object);
                }
                let source = match unparen(init) {
                    Expression::StringLiteral(value) => Some(value.value.as_str().to_string()),
                    Expression::TemplateLiteral(value) if value.expressions.is_empty() => {
                        resolve::cooked_template_string(value)
                    }
                    _ => None,
                };
                if let Some(source) = source {
                    self.source_literals.insert(name, source);
                }
            }
        }
        self.pending_binds = None;
    }

    fn visit_assignment_expression(&mut self, it: &oxc_ast::ast::AssignmentExpression<'a>) {
        self.track_assignment_target(&it.left, &it.right);
        walk::walk_assignment_expression(self, it);
        if let AssignmentTarget::AssignmentTargetIdentifier(id) = &it.left {
            self.object_literal_vars.remove(id.name.as_str());
            self.source_literals.remove(id.name.as_str());
        }
        self.pending_binds = None;
    }

    fn visit_static_member_expression(&mut self, it: &StaticMemberExpression<'a>) {
        if self.charge()
            && let Some(name) = resolve::process_env_name(it)
            && !self.bindings.env_write_spans.contains(&it.span.start)
        {
            if self.process_runtime {
                self.env_effect("environment.read", &name, false);
            } else {
                self.unsupported_process_receiver();
            }
        }
        walk::walk_static_member_expression(self, it);
    }

    fn visit_computed_member_expression(
        &mut self,
        it: &oxc_ast::ast::ComputedMemberExpression<'a>,
    ) {
        if self.charge()
            && resolve::is_process_env(&it.object)
            && !self.bindings.env_write_spans.contains(&it.span.start)
        {
            if self.process_runtime {
                self.unknown_env_effect("environment.read", false);
            } else {
                self.unsupported_process_receiver();
            }
        }
        walk::walk_computed_member_expression(self, it);
    }

    fn visit_assignment_target(&mut self, it: &AssignmentTarget<'a>) {
        if let AssignmentTarget::StaticMemberExpression(m) = it
            && let Some(name) = resolve::process_env_name(m)
        {
            if self.process_runtime {
                self.env_effect("environment.write", &name, false);
            } else {
                self.unsupported_process_receiver();
            }
        }
        if let AssignmentTarget::ComputedMemberExpression(m) = it
            && resolve::is_process_env(&m.object)
        {
            if self.process_runtime {
                self.unknown_env_effect("environment.write", false);
            } else {
                self.unsupported_process_receiver();
            }
        }
        walk::walk_assignment_target(self, it);
    }

    fn visit_unary_expression(&mut self, it: &UnaryExpression<'a>) {
        walk::walk_unary_expression(self, it);
        if it.operator.as_str() != "delete" {
            return;
        }
        match unparen(&it.argument) {
            Expression::StaticMemberExpression(member) => {
                if let Some(name) = resolve::process_env_name(member) {
                    if self.process_runtime {
                        self.env_effect("environment.write", &name, true);
                    } else {
                        self.unsupported_process_receiver();
                    }
                }
            }
            Expression::ComputedMemberExpression(member)
                if resolve::is_process_env(&member.object) =>
            {
                if self.process_runtime {
                    if let Some(name) = super::literal_property_name(&member.expression) {
                        self.env_effect("environment.write", &name, true);
                    } else {
                        self.unknown_env_effect("environment.write", true);
                    }
                } else {
                    self.unsupported_process_receiver();
                }
            }
            _ => {}
        }
    }
}

impl<'a> SummaryVisitor<'_, 'a> {
    fn finish_control(&mut self) -> ControlFlow {
        if self.saturated {
            self.control.widen();
        }
        let finished = self.control.leave(0).expect("JavaScript summary frame");
        if let Some(limit) = finished.refused {
            self.boundaries.push(Boundary {
                reason: BoundaryReason::LIMIT_SATURATED,
                class: BoundaryClass::Limit,
                scope: BoundaryScope::Invocation,
                domains: JS_DOMAINS
                    .iter()
                    .map(|domain| Domain::new(*domain))
                    .collect(),
                provenance: Vec::new(),
                limit: Some(limit.to_string()),
                detail: Some("JavaScript summary control flow widened".to_string()),
                callee: None,
                affected_resource: None,
            });
        }
        finished.flow
    }

    fn handle_call(&mut self, call: &CallExpression<'a>) {
        if self.bindings.dynamic_imports.is_quiet_call(call) {
            return;
        }
        let callee = unparen(&call.callee);

        if let Some(kind) = resolve::dynamic_exec(callee) {
            self.opaque(&format!("dynamic code execution ({kind})"));
            return;
        }
        if super::model::object_assigns_process_env(call) {
            if !self.process_runtime {
                self.unsupported_process_receiver();
                return;
            }
            for argument in call.arguments.iter().skip(1) {
                let Some(keys) = argument.as_expression().and_then(|source| {
                    super::model::object_env_keys(source, &self.object_literal_vars)
                }) else {
                    self.unknown_env_effect("environment.write", false);
                    continue;
                };
                for key in keys {
                    match key {
                        Some(name) => self.env_effect("environment.write", &name, false),
                        None => self.unknown_env_effect("environment.write", false),
                    }
                }
            }
            return;
        }

        // A call resolving to a known binding: a modeled effect API contributes
        // effects; an inert module (`path.join`, including `require('path').join`)
        // is dropped; any other resolved import is a cross-file call edge.
        // Resolution precedes the inert-callee check so `require('fs').rm` is
        // not dropped just because `require` itself is inert.
        if let Some(mc) = resolve::resolve_callee(callee, self.bindings)
            && !(mc.module == "__global__"
                && mc.function == "fetch"
                && self.local_names.contains("fetch"))
        {
            if is_inert_module_call(&mc.module, &mc.function, call) {
                return;
            }
            if !super::model::has_call_model(&mc.module, &mc.function, call) {
                self.record_call(callee, call);
                return;
            }
            match mc.module.as_str() {
                "fs" | "fs/promises" => self.fs_effects(&mc.function, call),
                "child_process" => self.subprocess_effect(&mc.function, call),
                // Popular subprocess packages with an execFile-shaped API.
                "tinyexec" | "execa"
                    if matches!(mc.function.as_str(), "x" | "exec" | "execa" | "execaSync") =>
                {
                    self.subprocess_effect("execFile", call)
                }
                "http" | "https" if matches!(mc.function.as_str(), "request" | "get") => {
                    self.network_effect(call)
                }
                "http" | "https" => {}
                "__global__" if mc.function == "fetch" => self.network_effect(call),
                "node-fetch" | "node-fetch-native" if mc.function == "fetch" => {
                    self.network_effect(call)
                }
                _ => self.record_call(callee, call),
            }
            return;
        }

        // Inert built-ins (`console.log`, `require`, `getBuiltinModule`) have
        // no external effect and are not cross-file calls.
        if (is_inert_callee(callee) || resolve::is_get_builtin_module(callee))
            && !super::model::inert_base_name(callee).is_some_and(|name| {
                self.local_names.contains(name) || self.bindings.declared.contains(name)
            })
        {
            return;
        }

        // Not a known binding: a local-function call, an unknown global, or a
        // method on a local object. Record it as a call edge if it is nameable.
        if callee_string(callee).is_some() {
            self.record_call(callee, call);
        } else {
            // A computed or otherwise unnameable callee cannot be linked.
            self.opaque("call to an unnameable callee");
        }
    }

    /// Record an outgoing call for cross-file resolution: the callee as written
    /// and its arguments resolved in terms of this function's parameters.
    fn record_call(&mut self, callee: &Expression<'a>, call: &CallExpression<'a>) {
        let Some(name) = callee_string(callee) else {
            self.opaque("call to an unnameable callee");
            return;
        };
        if self.bindings.member_was_reassigned(&name) {
            return;
        }
        let names = self.dynamic_callee_names(&name);
        let dynamic_namespace = names.iter().any(|candidate| candidate != &name);
        let origin = self.origin_for_node(call);
        let args: Vec<_> = call.arguments.iter().map(|a| self.arg_value(a)).collect();
        let mut arguments = positional_arguments(args);
        let mut callback_args = self.callback_fn_args(call);
        for (index, argument) in call.arguments.iter().enumerate() {
            let Some(Expression::StaticMemberExpression(member)) =
                argument.as_expression().map(unparen)
            else {
                continue;
            };
            let Expression::Identifier(object) = unparen(&member.object) else {
                continue;
            };
            let Some(producer) = self.returned_objects.get(object.name.as_str()) else {
                continue;
            };
            let function = format!("{producer}.{}", member.property.name.as_str());
            if self.returned_methods.contains(&function) {
                callback_args.push(ValueArgument {
                    name: None,
                    index,
                    value: SemanticValue::callable(function),
                });
            }
        }
        merge_arguments(&mut arguments, callback_args);
        merge_arguments(&mut arguments, self.obj_args_of(call));
        let receiver = (!dynamic_namespace).then(|| self.recv_of(callee)).flatten();
        let binds = self.pending_binds.take().unwrap_or_default();
        let results = if binds.is_empty() {
            vec![CallResult::new(0, None, Some(origin), None)]
        } else {
            binds
                .into_iter()
                .map(|(index, binding)| {
                    CallResult::new(index, Some(binding), Some(origin.clone()), None)
                })
                .collect()
        };
        let binding = match unparen(callee) {
            Expression::Identifier(id) => self
                .bindings
                .reference_bindings
                .get(&id.span.start)
                .copied(),
            _ => None,
        };
        for name in names {
            self.calls.push(CallEdge {
                condition: None,
                call_site: None,
                callee: name,
                arguments: arguments.clone(),
                awaited: self.dynamic_chained_calls.contains(&call.span.start),
                effects_propagated: false,
                external_inert: None,
                lifecycle_registration: false,
                dynamic_target: matches!(
                    binding,
                    Some(CalleeBinding::Opaque | CalleeBinding::Rebound)
                ),
                callee_span: match binding {
                    Some(CalleeBinding::Function(span)) => Some(span),
                    _ => None,
                },
                receiver: receiver.clone(),
                results: results.clone(),
                writes: Vec::new(),
            });
        }
    }

    fn dynamic_callee_names(&self, name: &str) -> Vec<String> {
        let Some((head, member)) = name.split_once('.') else {
            return vec![name.to_string()];
        };
        self.dynamic_namespaces
            .get(head)
            .map(|aliases| {
                aliases
                    .iter()
                    .map(|alias| format!("{alias}.{member}"))
                    .collect()
            })
            .unwrap_or_else(|| vec![name.to_string()])
    }

    fn follow_dynamic_import_callback(
        &mut self,
        expr: &Expression<'a>,
        callback: &resolve::DynamicImportCallback,
    ) {
        let (body, params, process_runtime) = match unparen(expr) {
            Expression::FunctionExpression(function) => {
                let Some(body) = &function.body else {
                    return;
                };
                (
                    body.as_ref(),
                    function.params.as_ref(),
                    super::function_process_scope(body, &function.params)
                        .unwrap_or(self.process_runtime),
                )
            }
            Expression::ArrowFunctionExpression(function) => (
                function.body.as_ref(),
                function.params.as_ref(),
                super::function_process_scope(&function.body, &function.params)
                    .unwrap_or(self.process_runtime),
            ),
            _ => return,
        };
        let previous = self
            .dynamic_namespaces
            .insert(callback.parameter.clone(), callback.aliases.clone());
        let previous_chained = std::mem::replace(
            &mut self.dynamic_chained_calls,
            callback.chained_calls.clone(),
        );
        self.visit_callback_body(body, params, &[], true, process_runtime);
        self.dynamic_chained_calls = previous_chained;
        match previous {
            Some(value) => {
                self.dynamic_namespaces
                    .insert(callback.parameter.clone(), value);
            }
            None => {
                self.dynamic_namespaces.remove(&callback.parameter);
            }
        }
    }

    /// Follow inline functions nested in a call argument, including object
    /// property values and array elements (`{ task: () => ... }`).
    fn follow_callback_expr(&mut self, expr: &Expression<'a>, proven: &[Option<ResourceExpr>]) {
        match unparen(expr) {
            Expression::FunctionExpression(f) => {
                if let Some(body) = &f.body {
                    let process_runtime = super::function_process_scope(body, &f.params)
                        .unwrap_or(self.process_runtime);
                    self.visit_callback_body(body, &f.params, proven, true, process_runtime);
                }
            }
            Expression::ArrowFunctionExpression(a) => {
                let process_runtime = super::function_process_scope(&a.body, &a.params)
                    .unwrap_or(self.process_runtime);
                self.visit_callback_body(&a.body, &a.params, proven, true, process_runtime);
            }
            Expression::ObjectExpression(obj) => {
                for prop in &obj.properties {
                    if let oxc_ast::ast::ObjectPropertyKind::ObjectProperty(p) = prop {
                        self.follow_callback_expr(&p.value, &[]);
                    }
                }
            }
            Expression::ArrayExpression(arr) => {
                for el in &arr.elements {
                    if let Some(e) = el.as_expression() {
                        self.follow_callback_expr(e, &[]);
                    }
                }
            }
            _ => {}
        }
    }

    fn recv_of(&mut self, callee: &Expression<'a>) -> Option<SemanticValue> {
        let Expression::StaticMemberExpression(m) = unparen(callee) else {
            return None;
        };
        match unparen(&m.object) {
            Expression::Identifier(id) => {
                let name = id.name.as_str();
                if name == "this" {
                    return Some(SemanticValue::object(ObjectIdentity::Receiver));
                }
                if let Some(instance) = self.instance_vars.get(name) {
                    return Some(instance.clone());
                }
                if self.parameters.contains(name) {
                    return Some(SemanticValue::object(ObjectIdentity::Parameter {
                        name: name.to_string(),
                        fallback: None,
                    }));
                }
                // An import (`fs.writeFile`, `git.add`) is resolved as a
                // module member, not a typed receiver. A local may be typed
                // later from a callee's returned instance.
                if self.bindings.namespaces.contains_key(name)
                    || self.bindings.named.contains_key(name)
                {
                    return None;
                }
                Some(SemanticValue::object(ObjectIdentity::Local {
                    name: name.to_string(),
                    fallback: None,
                }))
            }
            Expression::NewExpression(n) => {
                let class = new_class_name(n)?;
                Some(
                    SemanticValue::object(ObjectIdentity::Class {
                        name: class,
                        constructor: positional_arguments(
                            n.arguments.iter().map(|argument| self.arg_value(argument)),
                        ),
                    })
                    .with_origin(Some(self.origin_for_node(n))),
                )
            }
            Expression::StaticMemberExpression(inner) => {
                let Expression::Identifier(obj) = unparen(&inner.object) else {
                    return None;
                };
                let prop = inner.property.name.as_str();
                if let Some(instance) = self
                    .instance_attrs
                    .get(&(obj.name.as_str().to_string(), prop.to_string()))
                {
                    return Some(instance.clone());
                }
                if self.instance_vars.contains_key(obj.name.as_str()) {
                    return Some(SemanticValue::object(ObjectIdentity::LocalProperty {
                        name: obj.name.as_str().to_string(),
                        property: prop.to_string(),
                    }));
                }
                None
            }
            _ => None,
        }
    }

    fn obj_args_of(&mut self, call: &CallExpression<'a>) -> Vec<ValueArgument> {
        let mut out = Vec::new();
        for (i, arg) in call.arguments.iter().enumerate() {
            let Some(expr) = arg.as_expression() else {
                continue;
            };
            if let Some(instance) = self.instance_ref_of(expr) {
                out.push(ValueArgument {
                    name: None,
                    index: i,
                    value: instance,
                });
            }
        }
        out
    }

    fn callback_fn_args(&self, call: &CallExpression<'a>) -> Vec<ValueArgument> {
        let mut out = Vec::new();
        for (index, argument) in call.arguments.iter().enumerate() {
            let Some(expr) = argument.as_expression() else {
                continue;
            };
            let invocations = if index == 0 {
                self.callback_invocations(call)
            } else {
                vec![Vec::new()]
            };
            self.collect_callback_args(expr, None, index, &invocations, &mut out);
        }
        out
    }

    /// The argument lists `call` proves for its first argument's callback,
    /// one per invocation: a timer's extra arguments (`setTimeout(cb, ms,
    /// ...args)`) or each element of a fixed array (`roots.forEach(cb)`).
    /// Any other call proves one invocation with no arguments.
    fn callback_invocations(&self, call: &CallExpression<'a>) -> Vec<Vec<Option<ResourceExpr>>> {
        match unparen(&call.callee) {
            Expression::Identifier(callee)
                if !self
                    .bindings
                    .reference_bindings
                    .contains_key(&callee.span.start)
                    && !self.bindings.declared.contains(callee.name.as_str()) =>
            {
                let first = match callee.name.as_str() {
                    "setTimeout" | "setInterval" => 2,
                    "setImmediate" => 1,
                    _ => return vec![Vec::new()],
                };
                vec![
                    call.arguments
                        .iter()
                        .skip(first)
                        .map(|argument| self.proven_resource(argument.as_expression()?))
                        .collect(),
                ]
            }
            Expression::StaticMemberExpression(member) => {
                let Expression::Identifier(receiver) = unparen(&member.object) else {
                    return vec![Vec::new()];
                };
                let elements = self
                    .bindings
                    .fixed_arrays
                    .get(&receiver.span.start)
                    .and_then(|binding| self.array_elements.get(binding));
                match elements {
                    Some(elements)
                        if !elements.is_empty() && elements.len() <= MAX_CALLBACK_EXPANSIONS =>
                    {
                        elements
                            .iter()
                            .map(|element| vec![element.clone()])
                            .collect()
                    }
                    _ => vec![Vec::new()],
                }
            }
            _ => vec![Vec::new()],
        }
    }

    fn proven_resource(&self, expr: &Expression<'a>) -> Option<ResourceExpr> {
        let resource = resolve::fs_resource(expr, None, None, &self.param_env, self.bindings);
        (!matches!(resource, ResourceExpr::Unresolved { .. })).then_some(resource)
    }

    /// The function body span a reference's own symbol binds to.
    fn reference_function(&self, id: &oxc_ast::ast::IdentifierReference<'a>) -> Option<(u32, u32)> {
        match self.bindings.reference_bindings.get(&id.span.start) {
            Some(CalleeBinding::Function(span)) => Some(*span),
            _ => None,
        }
    }

    /// The summarized function whose body has `span`.
    fn function_name(&self, span: (u32, u32)) -> Option<String> {
        self.known_bodies.iter().find_map(|(name, bodies)| {
            bodies
                .iter()
                .any(|body| (body.body.span.start, body.body.span.end) == span)
                .then(|| name.clone())
        })
    }

    fn collect_callback_args(
        &self,
        expr: &Expression<'a>,
        name: Option<String>,
        index: usize,
        invocations: &[Vec<Option<ResourceExpr>>],
        out: &mut Vec<ValueArgument>,
    ) {
        if let Expression::Identifier(id) = unparen(expr) {
            let object = id.name.as_str();
            let mut properties: Vec<_> = self
                .callable_attrs
                .iter()
                .filter(|((base, _), _)| base == object)
                .collect();
            if !properties.is_empty() && self.reference_function(id).is_none() {
                properties.sort_by(|((_, left), _), ((_, right), _)| left.cmp(right));
                for ((_, property), function) in properties {
                    self.callback_sites.borrow_mut().push(CallbackSite {
                        callable: function.clone(),
                        proven: Vec::new(),
                    });
                    out.push(ValueArgument {
                        name: Some(property.clone()),
                        index,
                        value: SemanticValue::callable(function.name.clone()),
                    });
                }
                return;
            }
        }
        if let Some(function) = self.callable_ref(expr) {
            self.callback_sites
                .borrow_mut()
                .extend(invocations.iter().map(|proven| CallbackSite {
                    callable: function.clone(),
                    proven: proven.clone(),
                }));
            out.push(ValueArgument {
                name,
                index,
                value: SemanticValue::callable(function.name),
            });
            return;
        }
        match unparen(expr) {
            Expression::ObjectExpression(object) => {
                for property in &object.properties {
                    match property {
                        oxc_ast::ast::ObjectPropertyKind::ObjectProperty(property) => {
                            let Some(key) = property.key.static_name() else {
                                continue;
                            };
                            self.collect_callback_args(
                                &property.value,
                                Some(key.to_string()),
                                index,
                                &[Vec::new()],
                                out,
                            );
                        }
                        oxc_ast::ast::ObjectPropertyKind::SpreadProperty(spread) => {
                            self.collect_callback_args(
                                &spread.argument,
                                name.clone(),
                                index,
                                &[Vec::new()],
                                out,
                            );
                        }
                    }
                }
            }
            Expression::ArrayExpression(array) => {
                for (element_index, element) in array.elements.iter().enumerate() {
                    if let Some(value) = element.as_expression() {
                        self.collect_callback_args(
                            value,
                            Some(element_index.to_string()),
                            index,
                            &[Vec::new()],
                            out,
                        );
                    }
                }
            }
            Expression::AwaitExpression(awaited) => {
                self.collect_callback_args(&awaited.argument, name, index, invocations, out)
            }
            _ => {}
        }
    }

    fn callable_ref(&self, expr: &Expression<'a>) -> Option<CallableRef> {
        let named = |name: String| CallableRef {
            name,
            span: None,
            rebound: false,
        };
        match unparen(expr) {
            // The function this reference's own symbol binds to, through
            // any `const alias = name`.
            Expression::Identifier(id) => {
                let span = self.reference_function(id);
                Some(CallableRef {
                    name: span
                        .and_then(|span| self.function_name(span))
                        .unwrap_or_else(|| id.name.as_str().to_string()),
                    span,
                    rebound: matches!(
                        self.bindings.reference_bindings.get(&id.span.start),
                        Some(CalleeBinding::Rebound)
                    ),
                })
            }
            Expression::StaticMemberExpression(member) => {
                let Expression::Identifier(object) = unparen(&member.object) else {
                    return None;
                };
                let object_name = object.name.as_str();
                let property = member.property.name.as_str();
                if let Some(function) = self
                    .callable_attrs
                    .get(&(object_name.to_string(), property.to_string()))
                {
                    return Some(function.clone());
                }
                if let Some(producer) = self.returned_objects.get(object_name) {
                    let function = format!("{producer}.{property}");
                    if self.returned_methods.contains(&function) {
                        return Some(named(function));
                    }
                }
                let SemanticValueKind::Object(crate::ObjectValue {
                    identity: ObjectIdentity::Class { name, .. },
                    ..
                }) = &self.instance_vars.get(object_name)?.kind
                else {
                    return None;
                };
                Some(named(format!("{name}.{property}")))
            }
            Expression::AwaitExpression(awaited) => self.callable_ref(&awaited.argument),
            _ => None,
        }
    }

    fn track_callable_properties(&mut self, target: &str, expr: &Expression<'a>) {
        match unparen(expr) {
            Expression::ObjectExpression(object) => {
                for property in &object.properties {
                    match property {
                        oxc_ast::ast::ObjectPropertyKind::ObjectProperty(property) => {
                            let Some(key) = property.key.static_name() else {
                                continue;
                            };
                            if let Some(function) = self.callable_ref(&property.value) {
                                self.callable_attrs
                                    .insert((target.to_string(), key.to_string()), function);
                            }
                        }
                        oxc_ast::ast::ObjectPropertyKind::SpreadProperty(spread) => {
                            let Expression::Identifier(source) = unparen(&spread.argument) else {
                                continue;
                            };
                            let source = source.name.as_str();
                            let copied: Vec<_> = self
                                .callable_attrs
                                .iter()
                                .filter(|((object, _), _)| object == source)
                                .map(|((_, property), function)| {
                                    ((target.to_string(), property.clone()), function.clone())
                                })
                                .collect();
                            self.callable_attrs.extend(copied);
                        }
                    }
                }
            }
            Expression::AwaitExpression(awaited) => {
                self.track_callable_properties(target, &awaited.argument)
            }
            _ => {}
        }
    }

    fn instance_ref_of(&mut self, expr: &Expression<'a>) -> Option<SemanticValue> {
        if let Some(new_expr) = ctor_expr_of(expr) {
            return Some(
                SemanticValue::object(ObjectIdentity::Class {
                    name: new_class_name(new_expr)?,
                    constructor: positional_arguments(
                        new_expr
                            .arguments
                            .iter()
                            .map(|argument| self.arg_value(argument)),
                    ),
                })
                .with_origin(Some(self.origin_for_node(new_expr))),
            );
        }
        match unparen(expr) {
            Expression::Identifier(id) => {
                let name = id.name.as_str();
                if let Some(instance) = self.instance_vars.get(name) {
                    return Some(instance.clone());
                }
                if self.parameters.contains(name) {
                    return Some(SemanticValue::object(ObjectIdentity::Parameter {
                        name: name.to_string(),
                        fallback: None,
                    }));
                }
                if name == "this" {
                    return Some(SemanticValue::object(ObjectIdentity::Receiver));
                }
                None
            }
            _ => None,
        }
    }

    fn origin_for_node<T>(&mut self, node: &T) -> ValueOrigin {
        let key = node as *const T as usize;
        if let Some(origin) = self.site_origins.get(&key) {
            return origin.clone();
        }
        let origin = ValueOrigin::Site {
            file: self.fact_file.clone(),
            function: self.fact_function.clone(),
            ordinal: self.site_ordinal,
            result_index: 0,
        };
        self.site_ordinal += 1;
        self.site_origins.insert(key, origin.clone());
        origin
    }

    fn track_binding(&mut self, id: &BindingPattern<'a>, init: Option<&Expression<'a>>) {
        match id {
            BindingPattern::BindingIdentifier(name) => {
                let local = name.name.as_str().to_string();
                self.instance_vars.remove(&local);
                self.returned_objects.remove(&local);
                self.callable_attrs
                    .retain(|(object, _), _| object != &local);
                let Some(init) = init else {
                    return;
                };
                if let Expression::ArrayExpression(array) = unparen(init) {
                    let elements = array
                        .elements
                        .iter()
                        .map(|element| self.proven_resource(element.as_expression()?))
                        .collect();
                    self.array_elements.insert(name.span.start, elements);
                }
                self.track_callable_properties(&local, init);
                if let Some(instance) = self.instance_ref_of(init) {
                    if self.stable_module_bindings.is_some_and(|bound| {
                        bound.get(&local) == Some(&1)
                            && matches!(unparen(init), Expression::NewExpression(_))
                    }) {
                        self.pending_binds = Some(vec![(0, local.clone())]);
                    }
                    self.instance_vars.insert(local, instance);
                } else if is_callish(init) {
                    self.pending_binds = Some(vec![(0, local)]);
                    if let Some(producer) = called_function(init)
                        && self.known_bodies.contains_key(&producer)
                    {
                        self.returned_objects
                            .insert(name.name.as_str().to_string(), producer);
                    }
                }
            }
            BindingPattern::ObjectPattern(obj) => {
                let Some(init) = init else {
                    return;
                };
                let Expression::Identifier(src) = unparen(init) else {
                    return;
                };
                let src = src.name.as_str();
                for prop in &obj.properties {
                    let Some(key) = prop.key.static_name() else {
                        continue;
                    };
                    let BindingPattern::BindingIdentifier(local) = &prop.value else {
                        continue;
                    };
                    if let Some(instance) = self
                        .instance_attrs
                        .get(&(src.to_string(), key.to_string()))
                        .cloned()
                    {
                        self.instance_vars
                            .insert(local.name.as_str().to_string(), instance);
                    }
                }
            }
            _ => {}
        }
    }

    /// Walk local function/arrow bodies that a call in this scope passed as a
    /// callback, under the current instance typing, so `const task = () =>
    /// shell.exec(); show({ task })` sees `shell` as the constructed class.
    fn flush_callbacks(&mut self) {
        loop {
            let sites: Vec<CallbackSite> =
                self.callback_sites.borrow()[self.flushed_sites..].to_vec();
            if sites.is_empty() {
                break;
            }
            self.flushed_sites += sites.len();
            for site in sites {
                let CallableRef {
                    name,
                    span,
                    rebound,
                } = site.callable;
                if rebound {
                    self.push_dynamic_callback(name);
                    continue;
                }
                let Some(bodies) = self.known_bodies.get(&name) else {
                    continue;
                };
                // Only the body the callback's reference binds to runs; a
                // namesake elsewhere in the module is never a stand-in.
                let function = span.and_then(|span| {
                    bodies
                        .iter()
                        .find(|body| (body.body.span.start, body.body.span.end) == span)
                        .copied()
                });
                let Some((function, span)) = function.zip(span) else {
                    self.push_dynamic_callback(name);
                    continue;
                };
                // Each distinct set of proven arguments is its own expansion;
                // past a small cap the callee is left to composition.
                let key = format!("{span:?}{:?}", site.proven);
                if self.expanded_callbacks.contains(&key) {
                    continue;
                }
                let prefix = format!("{span:?}");
                if self
                    .expanded_callbacks
                    .iter()
                    .filter(|seen| seen.starts_with(&prefix))
                    .count()
                    >= MAX_CALLBACK_EXPANSIONS
                {
                    self.push_dynamic_callback(name);
                    continue;
                }
                self.expanded_callbacks.insert(key);
                let nested = self
                    .body_span
                    .is_none_or(|outer| outer.0 <= span.0 && span.1 <= outer.1);
                let process_runtime = function
                    .process_scope
                    .unwrap_or_else(|| self.bindings.process_runtime());
                self.visit_callback_body(
                    function.body,
                    function.formals,
                    &site.proven,
                    nested,
                    process_runtime,
                );
            }
        }
    }

    fn push_dynamic_callback(&mut self, callee: String) {
        self.calls.push(CallEdge {
            callee,
            dynamic_target: true,
            ..Default::default()
        });
    }

    /// Walk a callback body in its own frame. Its formals see only the
    /// arguments the call site proved (`proven`, by position) and are
    /// otherwise unknown; a body declared outside the function being
    /// summarized (`nested == false`) sees none of that function's locals.
    fn visit_callback_body(
        &mut self,
        body: &FunctionBody<'a>,
        formals: &FormalParameters<'a>,
        proven: &[Option<ResourceExpr>],
        nested: bool,
        process_runtime: bool,
    ) {
        self.callback_visits += 1;
        let saved_env = self.param_env.clone();
        let saved_parameters = self.parameters.clone();
        let saved_sources = self.source_literals.clone();
        let saved_objects = self.object_literal_vars.clone();
        let saved_attrs = self.callable_attrs.clone();
        let saved_instances = self.instance_vars.clone();
        if !nested {
            self.param_env = ParamEnv::new();
            self.parameters.clear();
            self.source_literals = self.bindings.source_literals.clone();
            self.object_literal_vars = self.bindings.object_literal_vars.clone();
            self.callable_attrs.clear();
            self.instance_vars.clear();
        }
        for name in param_binding_names(formals) {
            self.param_env.remove(&name);
            self.parameters.remove(&name);
            self.source_literals.remove(&name);
            self.object_literal_vars.remove(&name);
            self.callable_attrs.retain(|(object, _), _| object != &name);
            self.instance_vars.remove(&name);
        }
        for (formal, value) in formals.items.iter().zip(proven) {
            if let (BindingPattern::BindingIdentifier(name), Some(value)) = (&formal.pattern, value)
            {
                self.param_env
                    .insert(name.name.as_str().to_string(), value.clone());
            }
        }
        let in_callback = std::mem::replace(&mut self.in_callback, true);
        let saved = self.process_runtime;
        self.process_runtime = process_runtime;
        for stmt in &body.statements {
            self.visit_statement(stmt);
        }
        self.process_runtime = saved;
        self.in_callback = in_callback;
        self.param_env = saved_env;
        self.parameters = saved_parameters;
        self.source_literals = saved_sources;
        self.object_literal_vars = saved_objects;
        self.callable_attrs = saved_attrs;
        self.instance_vars = saved_instances;
    }

    fn track_assignment_target(&mut self, left: &AssignmentTarget<'a>, right: &Expression<'a>) {
        match left {
            AssignmentTarget::AssignmentTargetIdentifier(id) => {
                let local = id.name.as_str().to_string();
                self.instance_vars.remove(&local);
                self.returned_objects.remove(&local);
                self.callable_attrs
                    .retain(|(object, _), _| object != &local);
                self.track_callable_properties(&local, right);
                if let Some(instance) = self.instance_ref_of(right) {
                    self.instance_vars.insert(local, instance);
                } else if is_callish(right) {
                    self.pending_binds = Some(vec![(0, local.clone())]);
                    if let Some(producer) = called_function(right)
                        && self.known_bodies.contains_key(&producer)
                    {
                        self.returned_objects.insert(local, producer);
                    }
                }
            }
            AssignmentTarget::StaticMemberExpression(m) => {
                let Expression::Identifier(obj) = unparen(&m.object) else {
                    return;
                };
                let key = (
                    obj.name.as_str().to_string(),
                    m.property.name.as_str().to_string(),
                );
                if let Some(instance) = self.instance_ref_of(right) {
                    self.instance_attrs.insert(key.clone(), instance);
                } else {
                    self.instance_attrs.remove(&key);
                }
                if let Some(callable) = self.callable_ref(right) {
                    self.callable_attrs.insert(key, callable);
                } else {
                    self.callable_attrs.remove(&key);
                }
            }
            _ => {}
        }
    }

    fn fs_effects(&mut self, function: &str, call: &CallExpression<'a>) {
        let Some((operation, append)) = fs_operation(function) else {
            return;
        };
        let Some(target) = call.arguments.first() else {
            return;
        };
        let resource = self.arg_resource(target);
        let mut attributes = BTreeMap::new();
        if append {
            attributes.insert("append".to_string(), AttrValue::Bool(true));
        }
        let recursive = fs_recursive_options(function).is_some_and(|index| {
            call_option_true(call, index, "recursive", &self.object_literal_vars)
        });
        let dest_operation = fs_dest_operation(function);
        if recursive && dest_operation.is_none() {
            attributes.insert("recursive".to_string(), AttrValue::Bool(true));
        }
        let first_slot = self.push_effect(operation, resource.clone(), attributes);
        // A copy pairs its source content read; a rename pairs the source
        // entry delete the `filesystem.move` layer stands for.
        let source_slot = match fs_transfer(function) {
            Some(FsTransferSource::ContentRead) => first_slot,
            Some(FsTransferSource::EntryDelete) => {
                self.push_effect("filesystem.delete", resource, BTreeMap::new())
            }
            None => None,
        };
        if let Some(op) = dest_operation
            && let Some(dest) = call.arguments.get(1)
        {
            let resource = self.arg_resource(dest);
            let attributes = if recursive {
                BTreeMap::from([("recursive".to_string(), AttrValue::Bool(true))])
            } else {
                BTreeMap::new()
            };
            let destination_slot = self.push_effect(op, resource, attributes);
            self.record_transfer(source_slot, destination_slot);
        }
    }

    fn network_effect(&mut self, call: &CallExpression<'a>) {
        let resource = match call.arguments.first().and_then(argument_expr) {
            Some(expr) => match unparen(expr) {
                Expression::Identifier(id) => self
                    .source_literals
                    .get(id.name.as_str())
                    .map(|value| network_source_literal(value))
                    .unwrap_or_else(|| resolve::url_resource(expr)),
                _ => resolve::url_resource(expr),
            },
            _ => unresolved_resource("network"),
        };
        self.push_effect("network.request", resource, BTreeMap::new());
    }

    fn env_effect(&mut self, operation: &str, name: &str, unset: bool) {
        if name.is_empty() {
            self.unknown_env_effect(operation, unset);
            return;
        }
        self.push_effect(
            operation,
            ResourceExpr::Concrete {
                identity: ResourceIdentity::EnvironmentVariable {
                    name: name.to_string(),
                },
            },
            unset
                .then(|| ("unset".to_string(), AttrValue::Bool(true)))
                .into_iter()
                .collect(),
        );
    }

    fn unknown_env_effect(&mut self, operation: &str, unset: bool) {
        self.push_effect(
            operation,
            unresolved_resource("environment"),
            unset
                .then(|| ("unset".to_string(), AttrValue::Bool(true)))
                .into_iter()
                .collect(),
        );
    }

    /// A function that spawns a subprocess: the spawned command is not composed
    /// into the summary (that is the execution frontend's job), so record an
    /// explicit boundary rather than fabricate or drop the effect.
    fn subprocess_effect(&mut self, function: &str, call: &CallExpression<'a>) {
        // The exec itself is a process effect (matching the Python summarizer);
        // the spawned command's own effects stay uncomposed, hence the boundary.
        // The first argument is the program when it is a string (`exec("git")`).
        let shell_source = matches!(
            function,
            "execFile" | "execFileSync" | "spawn" | "spawnSync"
        )
        .then(|| {
            call_option_shell(
                call,
                subprocess_options_index(call, &self.object_literal_vars),
                &self.object_literal_vars,
                &|_| None,
            )
        })
        .filter(|shell| *shell != ShellOption::Disabled)
        .map(|_| shell_command_source(call));
        if matches!(shell_source, Some(None)) {
            self.opaque("child_process shell with non-literal command");
            return;
        }
        let resource = if let Some(Some(source)) = shell_source {
            ResourceExpr::Concrete {
                identity: ResourceIdentity::Process {
                    executable: source,
                    path: None,
                    argv: Vec::new(),
                    cwd: None,
                },
            }
        } else {
            call.arguments
                .first()
                .and_then(argument_expr)
                .map(resolve::process_resource)
                .unwrap_or(unresolved_resource("process"))
        };
        self.push_effect("process.exec", resource.clone(), Attrs::new());
        self.boundaries.push(Boundary {
            reason: BoundaryReason::UNCOMPOSED_SUBPROCESS,
            class: BoundaryClass::Unmodeled,
            scope: BoundaryScope::Invocation,
            affected_resource: Some(resource),
            callee: None,
            domains: effinterp_proto::DOMAINS
                .iter()
                .map(|d| Domain::new(*d))
                .collect(),
            provenance: Vec::new(),
            limit: None,
            detail: Some("subprocess spawned inside a summarized function".to_string()),
        });
    }

    fn arg_resource(&self, arg: &Argument<'a>) -> ResourceExpr {
        match argument_expr(arg) {
            Some(expr) => super::source_string::summary_environment_path(
                expr,
                &self.param_env,
                self.process_runtime,
                self.bindings,
            )
            .unwrap_or_else(|| {
                resolve::fs_resource(expr, None, None, &self.param_env, self.bindings)
            }),
            None => unresolved_resource("filesystem"),
        }
    }

    fn arg_value(&self, arg: &Argument<'a>) -> SemanticValue {
        match argument_expr(arg).map(unparen) {
            Some(Expression::StringLiteral(value)) => {
                SemanticValue::source_literal(value.value.as_str())
            }
            Some(Expression::TemplateLiteral(value)) if value.expressions.is_empty() => {
                resolve::cooked_template_string(value).map_or_else(
                    || SemanticValue::from(self.arg_resource(arg)),
                    SemanticValue::source_literal,
                )
            }
            _ => SemanticValue::from(self.arg_resource(arg)),
        }
    }

    /// Push one effect and report its slot, so a transfer emitter can pair the
    /// endpoints it just produced.
    fn push_effect(
        &mut self,
        operation: &str,
        resource: ResourceExpr,
        attributes: Attrs,
    ) -> Option<u32> {
        // Provenance is filled where the summary is applied at a call site
        // (`dependency_calls::apply_function`, or repository composition).
        self.effects.push(Effect {
            request_assurance: effinterp_proto::RequestAssurance::Conservative,
            id: Default::default(),
            operation: Operation::new(operation),
            resource,
            attributes,
            modality: Modality::May,
            realm: ExecutionRealm::Host,
            condition: None,
            execution: effinterp_proto::ExecutionNodeRef(0),
            provenance: Vec::new(),
        });
        Some(self.effects.len() as u32 - 1)
    }

    fn record_transfer(&mut self, source: Option<u32>, destination: Option<u32>) {
        let (Some(source), Some(destination)) = (source, destination) else {
            return;
        };
        let binding = TransferBinding::new(source, destination);
        if !self.transfers.contains(&binding) {
            self.transfers.push(binding);
        }
    }

    fn opaque(&mut self, detail: &str) {
        self.boundaries.push(Boundary {
            reason: BoundaryReason::UNMODELED_DYNAMIC_CODE,
            class: BoundaryClass::Unresolved,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: JS_DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
            provenance: Vec::new(),
            limit: None,
            detail: Some(detail.to_string()),
        });
    }

    fn unsupported_process_receiver(&mut self) {
        if self.unsupported_process_receiver_reported {
            return;
        }
        self.unsupported_process_receiver_reported = true;
        self.boundaries.push(Boundary {
            reason: BoundaryReason::PARTIAL_ANALYSIS,
            class: BoundaryClass::Unmodeled,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: vec![Domain::new("environment")],
            provenance: Vec::new(),
            limit: None,
            detail: Some("process receiver is not runtime-backed".to_string()),
        });
    }

    fn enter_walk(&mut self) -> bool {
        if self.saturated {
            return false;
        }
        if self.walk_depth >= MAX_WALK_DEPTH {
            self.saturated = true;
            self.boundaries.push(Boundary {
                reason: BoundaryReason::PARTIAL_ANALYSIS,
                class: BoundaryClass::Unmodeled,
                scope: BoundaryScope::Invocation,
                affected_resource: None,
                callee: None,
                domains: JS_DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
                provenance: Vec::new(),
                limit: Some("max_walk_depth".to_string()),
                detail: Some("js summary walk depth bound reached".to_string()),
            });
            return false;
        }
        self.walk_depth += 1;
        true
    }

    /// Count one node against a fixed budget so an adversarial function body
    /// cannot make extraction unbounded.
    fn charge(&mut self) -> bool {
        if self.saturated {
            return false;
        }
        self.nodes += 1;
        if !crate::limits::summary_step() {
            self.saturated = true;
            self.boundaries.push(Boundary {
                reason: BoundaryReason::LIMIT_SATURATED,
                class: BoundaryClass::Limit,
                scope: BoundaryScope::Invocation,
                affected_resource: None,
                callee: None,
                domains: JS_DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
                provenance: Vec::new(),
                limit: Some("max_js_nodes".to_string()),
                detail: None,
            });
            return false;
        }
        true
    }
}

type Attrs = BTreeMap<String, AttrValue>;

/// The callee as written: an identifier name, or a dotted `base.prop` member
/// path. None for a computed or otherwise unnameable callee.
fn callee_string(expr: &Expression) -> Option<String> {
    match unparen(expr) {
        Expression::Identifier(id) => Some(id.name.as_str().to_string()),
        Expression::StaticMemberExpression(m) => {
            let base = callee_string(&m.object)?;
            Some(format!("{base}.{}", m.property.name.as_str()))
        }
        // `cli.command('init').action(init)` — skip the call so the chain
        // still names the method that received the callback.
        Expression::CallExpression(c) => callee_string(&c.callee),
        _ => None,
    }
}

/// The `new Foo()` selected by a wrapped expression when its class is unique.
fn ctor_expr_of<'a>(expr: &'a Expression<'a>) -> Option<&'a oxc_ast::ast::NewExpression<'a>> {
    match unparen(expr) {
        Expression::NewExpression(n) => Some(n),
        Expression::AwaitExpression(a) => ctor_expr_of(&a.argument),
        Expression::LogicalExpression(l) => {
            // `x || new Foo()` / `x ?? new Foo()`: unique constructor wins.
            match (ctor_expr_of(&l.left), ctor_expr_of(&l.right)) {
                (Some(a), Some(b)) if new_class_name(a) == new_class_name(b) => Some(a),
                (Some(a), None) => Some(a),
                (None, Some(b)) => Some(b),
                _ => None,
            }
        }
        Expression::ConditionalExpression(c) => {
            match (ctor_expr_of(&c.consequent), ctor_expr_of(&c.alternate)) {
                (Some(a), Some(b)) if new_class_name(a) == new_class_name(b) => Some(a),
                _ => None,
            }
        }
        _ => None,
    }
}

fn is_callish(expr: &Expression) -> bool {
    match unparen(expr) {
        Expression::CallExpression(_) => true,
        Expression::AwaitExpression(a) => is_callish(&a.argument),
        _ => false,
    }
}

fn called_function(expr: &Expression) -> Option<String> {
    match unparen(expr) {
        Expression::CallExpression(call) => callee_string(&call.callee),
        Expression::AwaitExpression(awaited) => called_function(&awaited.argument),
        _ => None,
    }
}
