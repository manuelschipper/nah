//! File-scoped PHP names and declaration values.

use std::collections::HashMap;

use effinterp_proto::ResourceExpr;
use tree_sitter::Node;

use crate::value::fs_path_resource;

use super::syntax::{child_kind, literal_string, text};

/// Per-file class names and declaration values, shared by both PHP walks.
#[derive(Default)]
pub(super) struct PhpFileContext {
    pub(super) namespace: Option<String>,
    uses: HashMap<String, String>,
    pub(super) consts: HashMap<String, HashMap<String, ResourceExpr>>,
    pub(super) static_props: HashMap<String, HashMap<String, ResourceExpr>>,
    pub(super) top_consts: HashMap<String, String>,
}

/// Collect the namespace, class imports, and literal declarations outside callable bodies.
pub(super) fn collect_php_file_context(root: Node, src: &str) -> PhpFileContext {
    let mut ctx = PhpFileContext::default();
    let mut stack = vec![root];
    while let Some(n) = stack.pop() {
        match n.kind() {
            "namespace_definition" => {
                if ctx.namespace.is_none()
                    && let Some(name) = n.child_by_field_name("name")
                {
                    ctx.namespace = Some(text(name, src).to_string());
                }
            }
            "namespace_use_declaration" => {
                // `use function`/`use const` imports are not class names.
                if n.child_by_field_name("type").is_none() {
                    let prefix = child_kind(n, "namespace_name").map(|p| text(p, src).to_string());
                    let mut clauses: Vec<Node> = Vec::new();
                    let mut c = n.walk();
                    for ch in n.named_children(&mut c) {
                        match ch.kind() {
                            "namespace_use_clause" => clauses.push(ch),
                            "namespace_use_group" => {
                                let mut g = ch.walk();
                                clauses.extend(
                                    ch.named_children(&mut g)
                                        .filter(|x| x.kind() == "namespace_use_clause"),
                                );
                            }
                            _ => {}
                        }
                    }
                    for clause in clauses {
                        let Some(target_node) = clause
                            .named_children(&mut clause.walk())
                            .find(|x| matches!(x.kind(), "name" | "qualified_name"))
                        else {
                            continue;
                        };
                        let mut target =
                            text(target_node, src).trim_start_matches('\\').to_string();
                        if let Some(p) = &prefix {
                            target = format!("{p}\\{target}");
                        }
                        let alias = clause
                            .child_by_field_name("alias")
                            .map(|a| text(a, src).to_string())
                            .unwrap_or_else(|| {
                                target.rsplit('\\').next().unwrap_or(&target).to_string()
                            });
                        ctx.uses.insert(alias, target);
                    }
                }
            }
            _ => {}
        }
        let mut c = n.walk();
        for ch in n.named_children(&mut c) {
            stack.push(ch);
        }
    }
    let mut stack = vec![(root, None::<String>)];
    while let Some((node, owner)) = stack.pop() {
        let owner = if matches!(node.kind(), "class_declaration" | "trait_declaration") {
            child_kind(node, "name").map(|name| {
                let name = text(name, src);
                match &ctx.namespace {
                    Some(namespace) => format!("{namespace}\\{name}"),
                    None => name.to_string(),
                }
            })
        } else {
            owner
        };
        if matches!(node.kind(), "function_definition" | "method_declaration") {
            continue;
        }
        if node.kind() == "const_declaration" {
            let mut cursor = node.walk();
            for element in node
                .named_children(&mut cursor)
                .filter(|child| child.kind() == "const_element")
            {
                let mut element_cursor = element.walk();
                let mut children = element.named_children(&mut element_cursor);
                let Some(name) = children.find(|child| child.kind() == "name") else {
                    continue;
                };
                let Some(value) = element
                    .named_children(&mut element.walk())
                    .find(|child| child.id() != name.id())
                    .and_then(|value| literal_path_expr(value, src))
                else {
                    continue;
                };
                if let Some(owner) = &owner {
                    ctx.consts
                        .entry(owner.clone())
                        .or_default()
                        .insert(text(name, src).to_string(), fs_path_resource(&value));
                } else {
                    ctx.top_consts.insert(text(name, src).to_string(), value);
                }
            }
        }
        if node.kind() == "property_declaration"
            && child_kind(node, "static_modifier").is_some()
            && let Some(owner) = &owner
        {
            let mut cursor = node.walk();
            for element in node
                .named_children(&mut cursor)
                .filter(|child| child.kind() == "property_element")
            {
                let Some(variable) = element.child_by_field_name("name") else {
                    continue;
                };
                let Some(value) = element
                    .child_by_field_name("default_value")
                    .and_then(|value| literal_path_expr(value, src))
                else {
                    continue;
                };
                let Some(name) = child_kind(variable, "name") else {
                    continue;
                };
                ctx.static_props
                    .entry(owner.clone())
                    .or_default()
                    .insert(text(name, src).to_string(), fs_path_resource(&value));
            }
        }
        let mut cursor = node.walk();
        let children: Vec<Node> = node.named_children(&mut cursor).collect();
        for child in children.into_iter().rev() {
            stack.push((child, owner.clone()));
        }
    }
    ctx
}

fn literal_path_expr(node: Node, src: &str) -> Option<String> {
    let mut value = String::new();
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        if let Some(part) = literal_string(node, src) {
            value.push_str(&part);
            continue;
        }
        if node.kind() != "binary_expression"
            || node
                .child_by_field_name("operator")
                .map(|operator| text(operator, src))
                != Some(".")
        {
            return None;
        }
        let mut cursor = node.walk();
        let children: Vec<Node> = node.named_children(&mut cursor).collect();
        stack.extend(children.into_iter().rev());
    }
    Some(value)
}

/// Resolve a class name as written to a fully-qualified name: a leading `\`
/// is absolute; otherwise the first segment resolves through the file's
/// imports, then the file's namespace.
pub(super) fn resolve_php_class_name(ctx: &PhpFileContext, raw: &str) -> String {
    if let Some(abs) = raw.strip_prefix('\\') {
        return abs.to_string();
    }
    let first = raw.split('\\').next().unwrap_or(raw);
    if let Some(u) = ctx.uses.get(first) {
        return format!("{u}{}", &raw[first.len()..]);
    }
    match &ctx.namespace {
        Some(ns) => format!("{ns}\\{raw}"),
        None => raw.to_string(),
    }
}

/// A bare name lives in the current file's function table. `Ns\fn` matches
/// only when this file declared that namespace.
pub(super) fn same_namespace(ctx: &PhpFileContext, fname: &str) -> bool {
    match fname.rsplit_once('\\') {
        None => true,
        Some((ns, _)) => ctx.namespace.as_deref() == Some(ns),
    }
}

/// Recover a written class name without resolving a computed constructor target.
pub(super) fn php_constructed_class(node: Node, src: &str, ctx: &PhpFileContext) -> Option<String> {
    if node.kind() != "object_creation_expression" {
        return None;
    }
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| matches!(child.kind(), "name" | "qualified_name"))
        .map(|class| resolve_php_class_name(ctx, text(class, src)))
}
