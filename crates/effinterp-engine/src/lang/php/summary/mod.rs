//! PHP repository summaries for module bodies, functions, and methods.

mod body_effects;
mod call_edges;

use std::collections::HashMap;

use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CoverageLevel, Domain,
};
use tree_sitter::Node;

use crate::builder::KNOWN_DOMAINS;
use crate::module_summary::{CallEdge, ClassEntry, FunctionEntry, ImportBinding, ModuleSummary};
use crate::summary::Summary;
use crate::{ObjectIdentity, SemanticValue, ValueArgument};

use super::DOMAINS;
use super::file_context::{
    PhpFileContext, collect_php_file_context, php_constructed_class, resolve_php_class_name,
};
use super::syntax::{
    child_kind, first_string_literal, param_names, text, this_property, variable_name,
};
use body_effects::summarize_body;
use call_edges::PhpSummaryCalls;

/// Keep parameterized summaries for declared callables even if the file never calls them.
pub(super) fn summarize_ast(source: &str, tree: &tree_sitter::Tree) -> ModuleSummary {
    let root = tree.root_node();
    let ctx = collect_php_file_context(root, source);
    let classes = php_classes(root, source, &ctx);
    let mut functions = Vec::new();
    // Deterministic order: source order of top-level function definitions.
    let mut c = root.walk();
    for stmt in root.named_children(&mut c) {
        if stmt.kind() == "function_definition"
            && let Some(name_node) = child_kind(stmt, "name")
        {
            let name = text(name_node, source).to_string();
            let params = child_kind(stmt, "formal_parameters")
                .map(|p| param_names(p, source))
                .unwrap_or_default();
            let body = child_kind(stmt, "compound_statement");
            let (effects, boundaries, mut control_flow) = summarize_body(body, &params, source);
            let mut calls = PhpSummaryCalls::new(source, &ctx, &params, HashMap::new());
            if let Some(body) = body {
                calls.walk_body(body);
            }
            let (returns_instances, return_bindings) = calls.returned_instance();
            control_flow.bind_calls(&calls.sites);
            functions.push(FunctionEntry {
                name,
                summary: Summary {
                    control_flow,
                    params: params.clone(),
                    effects,
                    effect_models: Vec::new(),
                    transfers: Vec::new(),
                    returns: None,
                    boundaries,
                    coverage: DOMAINS
                        .iter()
                        .map(|d| (Domain::new(*d), CoverageLevel::Full))
                        .collect(),
                },
                calls: calls.edges,
                returns_instances,
                return_bindings,
                ..Default::default()
            });
        }
    }

    for class in &classes {
        for method in &class.methods {
            let key = format!("{}.{}", class.entry.name, method.name);
            let (effects, boundaries, mut control_flow) =
                summarize_body(Some(method.body), &method.params, source);
            let mut calls =
                PhpSummaryCalls::new(source, &ctx, &method.params, method.param_types.clone());
            calls.walk_body(method.body);
            let (returns_instances, return_bindings) = calls.returned_instance();
            control_flow.bind_calls(&calls.sites);
            functions.push(FunctionEntry {
                name: key,
                summary: Summary {
                    control_flow,
                    params: method.params.clone(),
                    effects,
                    effect_models: Vec::new(),
                    transfers: Vec::new(),
                    returns: None,
                    boundaries,
                    coverage: DOMAINS
                        .iter()
                        .map(|d| (Domain::new(*d), CoverageLevel::Full))
                        .collect(),
                },
                calls: calls.edges,
                returns_instances,
                return_bindings,
                ..Default::default()
            });
        }
    }

    for class in &classes {
        if class.entry.bases.as_slice() != [SYMFONY_CONSOLE_APPLICATION] {
            continue;
        }
        let Some(defaults) = functions
            .iter_mut()
            .find(|function| function.name == format!("{}.getDefaultCommands", class.entry.name))
        else {
            continue;
        };
        let Some(method) = class
            .methods
            .iter()
            .find(|method| method.name == "getDefaultCommands")
        else {
            continue;
        };
        let mut calls =
            PhpSummaryCalls::new(source, &ctx, &method.params, method.param_types.clone());
        calls.walk_body(method.body);
        if calls.registry_saturated {
            defaults.summary.boundaries.push(dynamic_dispatch_boundary(
                "php command registry candidate limit exceeded",
            ));
        }
        if calls.registry_dynamic {
            defaults.summary.boundaries.push(dynamic_dispatch_boundary(
                "php command registry contains an unresolved candidate",
            ));
        }
        if !calls.registry_saturated && !calls.returned_objects.is_empty() {
            defaults.calls.push(CallEdge {
                callee: "this.getDefaultCommands".to_string(),
                arguments: calls
                    .returned_objects
                    .into_iter()
                    .enumerate()
                    .map(|(index, value)| ValueArgument {
                        name: None,
                        index,
                        value,
                    })
                    .collect(),
                lifecycle_registration: true,
                receiver: Some(SemanticValue::object(ObjectIdentity::Receiver)),
                ..Default::default()
            });
        }
        let call_defaults = CallEdge {
            callee: "this.getDefaultCommands".to_string(),
            effects_propagated: false,
            receiver: Some(SemanticValue::object(ObjectIdentity::Receiver)),
            ..Default::default()
        };
        if !functions
            .iter()
            .any(|function| function.name == format!("{}.run", class.entry.name))
        {
            functions.push(FunctionEntry {
                name: format!("{}.run", class.entry.name),
                summary: Summary {
                    coverage: DOMAINS
                        .iter()
                        .map(|d| (Domain::new(*d), CoverageLevel::Full))
                        .collect(),
                    ..Default::default()
                },
                calls: vec![call_defaults],
                ..Default::default()
            });
        }
    }

    // Top-level (module) calls to user functions.
    let mut mc = root.walk();
    let top: Vec<Node> = root.named_children(&mut mc).collect();
    let mut module = PhpSummaryCalls::new(source, &ctx, &[], HashMap::new());
    for node in &top {
        module.walk(*node);
    }
    let (_, boundaries, mut module_control_flow) = summarize_body(Some(root), &[], source);
    module_control_flow.bind_calls(&module.sites);
    let module_control_flow = module_control_flow.calls_only();
    let module_calls = module.edges;

    let imports = extract_imports(root, source);
    let exports = imports
        .iter()
        .map(|binding| ImportBinding {
            local: "*".to_string(),
            module: binding.module.clone(),
            imported: None,
        })
        .collect();
    let mut summary = ModuleSummary {
        functions,
        module_calls,
        module_control_flow,
        module_boundaries: boundaries
            .into_iter()
            .filter(|boundary| boundary.limit.is_some())
            .collect(),
        imports,
        exports,
        classes: classes.into_iter().map(|class| class.entry).collect(),
        ..Default::default()
    };
    crate::module_summary::set_effects_propagated(&mut summary, |edge| {
        edge.callee != "this.getDefaultCommands" || edge.lifecycle_registration
    });
    summary
}

const SYMFONY_CONSOLE_APPLICATION: &str = "Symfony\\Component\\Console\\Application";

struct PhpClass<'a> {
    entry: ClassEntry,
    methods: Vec<PhpMethod<'a>>,
}

struct PhpMethod<'a> {
    name: String,
    params: Vec<String>,
    param_types: HashMap<String, String>,
    body: Node<'a>,
}

fn php_classes<'a>(root: Node<'a>, src: &str, ctx: &PhpFileContext) -> Vec<PhpClass<'a>> {
    let mut out = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "class_declaration" {
            let Some(short) = node.child_by_field_name("name") else {
                continue;
            };
            let name = resolve_php_class_name(ctx, text(short, src));
            let bases = child_kind(node, "base_clause")
                .and_then(|base| {
                    let mut cursor = base.walk();
                    base.named_children(&mut cursor)
                        .find(|child| matches!(child.kind(), "name" | "qualified_name"))
                        .map(|child| resolve_php_class_name(ctx, text(child, src)))
                })
                .into_iter()
                .collect();
            let mut methods = Vec::new();
            if let Some(body) = node.child_by_field_name("body") {
                let mut cursor = body.walk();
                for method in body
                    .named_children(&mut cursor)
                    .filter(|child| child.kind() == "method_declaration")
                {
                    let (Some(method_name), Some(method_body)) = (
                        method.child_by_field_name("name"),
                        child_kind(method, "compound_statement"),
                    ) else {
                        continue;
                    };
                    let parameters = child_kind(method, "formal_parameters");
                    let params = parameters
                        .map(|parameters| param_names(parameters, src))
                        .unwrap_or_default();
                    methods.push(PhpMethod {
                        name: text(method_name, src).to_string(),
                        params,
                        param_types: parameters
                            .map(|parameters| php_param_types(parameters, src, ctx))
                            .unwrap_or_default(),
                        body: method_body,
                    });
                }
            }
            let constructor = methods.iter().find(|method| method.name == "__construct");
            let mut attr_params = Vec::new();
            let mut attr_classes = Vec::new();
            if let Some(constructor) = constructor {
                collect_constructor_attrs(
                    constructor.body,
                    src,
                    ctx,
                    &constructor.params,
                    &mut attr_params,
                    &mut attr_classes,
                );
            }
            out.push(PhpClass {
                entry: ClassEntry {
                    name,
                    bases,
                    attr_params,
                    attr_classes,
                    ..Default::default()
                },
                methods,
            });
            continue;
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            stack.push(child);
        }
    }
    out.sort_by(|left, right| left.entry.name.cmp(&right.entry.name));
    out
}

fn php_param_types(parameters: Node, src: &str, ctx: &PhpFileContext) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let mut cursor = parameters.walk();
    for parameter in parameters.named_children(&mut cursor) {
        let Some(variable) = child_kind(parameter, "variable_name")
            .and_then(|variable| child_kind(variable, "name"))
        else {
            continue;
        };
        let mut type_cursor = parameter.walk();
        let Some(ty) = parameter.named_children(&mut type_cursor).find(|child| {
            matches!(
                child.kind(),
                "named_type" | "name" | "qualified_name" | "optional_type"
            )
        }) else {
            continue;
        };
        let written = text(ty, src).trim_start_matches('?');
        if !written.is_empty() {
            out.insert(
                text(variable, src).to_string(),
                resolve_php_class_name(ctx, written),
            );
        }
    }
    out
}

fn collect_constructor_attrs(
    body: Node,
    src: &str,
    ctx: &PhpFileContext,
    params: &[String],
    attr_params: &mut Vec<(String, String)>,
    attr_classes: &mut Vec<(String, String)>,
) {
    let mut stack = vec![body];
    while let Some(node) = stack.pop() {
        if node.kind() == "assignment_expression" {
            let (Some(left), Some(right)) = (
                node.child_by_field_name("left"),
                node.child_by_field_name("right"),
            ) else {
                continue;
            };
            if let Some(property) = this_property(left, src) {
                if let Some(variable) = variable_name(right, src)
                    && params.iter().any(|param| param == variable)
                {
                    attr_params.push((property, variable.to_string()));
                } else if let Some(class) = php_constructed_class(right, src, ctx) {
                    attr_classes.push((property, class));
                }
            }
        }
        if matches!(
            node.kind(),
            "function_definition" | "method_declaration" | "anonymous_function" | "arrow_function"
        ) && node.id() != body.id()
        {
            continue;
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            stack.push(child);
        }
    }
    attr_params.sort();
    attr_params.dedup();
    attr_classes.sort();
    attr_classes.dedup();
}

fn dynamic_dispatch_boundary(detail: &str) -> Boundary {
    Boundary {
        reason: BoundaryReason::DYNAMIC_DISPATCH,
        class: BoundaryClass::Unresolved,
        scope: BoundaryScope::Invocation,
        affected_resource: None,
        callee: None,
        domains: KNOWN_DOMAINS
            .iter()
            .map(|domain| Domain::new(*domain))
            .collect(),
        provenance: Vec::new(),
        limit: Some("max_php_command_registry_values".to_string()),
        detail: Some(detail.to_string()),
    }
}

fn extract_imports(root: Node, src: &str) -> Vec<ImportBinding> {
    let mut out = Vec::new();
    let mut stack = vec![root];
    while let Some(n) = stack.pop() {
        if matches!(
            n.kind(),
            "function_definition" | "method_declaration" | "anonymous_function" | "arrow_function"
        ) {
            continue;
        }
        if matches!(
            n.kind(),
            "if_statement"
                | "else_clause"
                | "while_statement"
                | "do_statement"
                | "for_statement"
                | "foreach_statement"
                | "switch_statement"
                | "case_statement"
                | "default_statement"
                | "try_statement"
                | "catch_clause"
                | "finally_clause"
                | "conditional_expression"
                | "match_expression"
        ) {
            continue;
        }
        if matches!(
            n.kind(),
            "require_expression"
                | "require_once_expression"
                | "include_expression"
                | "include_once_expression"
        ) {
            // The path may be a bare literal (`require 'util.php'`) or the
            // idiomatic `__DIR__ . '/util.php'` concatenation, so take the
            // first static string literal anywhere in the require's subtree.
            if let Some(path) = first_string_literal(n, src) {
                let local = path.rsplit('/').next().unwrap_or(&path).to_string();
                out.push(ImportBinding {
                    local,
                    module: path,
                    imported: None,
                });
            }
        }
        let mut c = n.walk();
        for ch in n.named_children(&mut c) {
            stack.push(ch);
        }
    }
    out
}
