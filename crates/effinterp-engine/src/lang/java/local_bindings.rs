//! Java local bindings and the mutations that invalidate their recovered values.

use super::syntax::{bare_java_type, java_node_text};
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

/// An assignment is guarded only by constructs in its own declaration scope.
pub(super) fn is_guarded_java_assignment(n: Node, src: &[u8]) -> bool {
    let mut parent = n.parent();
    while let Some(node) = parent {
        if matches!(
            node.kind(),
            "method_declaration"
                | "constructor_declaration"
                | "lambda_expression"
                | "class_declaration"
        ) {
            return false;
        }
        if matches!(
            node.kind(),
            "if_statement"
                | "while_statement"
                | "do_statement"
                | "for_statement"
                | "enhanced_for_statement"
                | "switch_expression"
                | "ternary_expression"
                | "try_statement"
                | "try_with_resources_statement"
                | "catch_clause"
                | "finally_clause"
        ) || node.kind() == "binary_expression"
            && node
                .child_by_field_name("operator")
                .is_some_and(|operator| matches!(java_node_text(operator, src), "&&" | "||"))
        {
            return true;
        }
        parent = node.parent();
    }
    false
}

pub(super) fn tracked_local_type(ty: &str) -> bool {
    matches!(ty, "String" | "Path" | "File" | "URL" | "URI" | "var")
}

pub(super) fn tracked_initializer(
    node: Node,
    src: &[u8],
    constants: &HashMap<String, String>,
) -> bool {
    match node.kind() {
        "string_literal" | "identifier" | "binary_expression" | "array_initializer"
        | "array_access" => true,
        "parenthesized_expression" | "cast_expression" => node
            .child_by_field_name("value")
            .or_else(|| node.named_child(0))
            .is_some_and(|value| tracked_initializer(value, src, constants)),
        "field_access" => {
            let whole = java_node_text(node, src);
            node.child_by_field_name("object")
                .is_some_and(|object| object.kind() == "this")
                || whole
                    .rsplit('.')
                    .next()
                    .is_some_and(|field| constants.contains_key(field))
        }
        "object_creation_expression" => {
            let tracked_type = node
                .child_by_field_name("type")
                .map(|ty| bare_java_type(java_node_text(ty, src)))
                .is_some_and(|ty| matches!(ty.as_str(), "File" | "URL" | "URI"));
            tracked_type
                && node
                    .child_by_field_name("arguments")
                    .is_some_and(|arguments| {
                        let mut cursor = arguments.walk();
                        let count = arguments.named_children(&mut cursor).count();
                        count == 1
                            || count == 2
                                && node.child_by_field_name("type").is_some_and(|ty| {
                                    bare_java_type(java_node_text(ty, src)) == "File"
                                })
                    })
        }
        "method_invocation" => {
            let name = node
                .child_by_field_name("name")
                .map(|name| java_node_text(name, src))
                .unwrap_or("");
            let object = node.child_by_field_name("object");
            let receiver = object
                .map(|object| java_node_text(object, src))
                .and_then(|object| object.rsplit('.').next())
                .unwrap_or("");
            match name {
                "of" | "get" => true,
                "resolve" => object.is_some(),
                "getenv" | "getProperty" => receiver == "System",
                "format" => receiver == "String",
                "formatted" => object.is_some_and(|object| object.kind() == "string_literal"),
                "create" => receiver == "URI",
                "newBuilder" => receiver == "HttpRequest",
                "openConnection" | "build" | "POST" | "PUT" | "DELETE" | "GET" | "method" => {
                    object.is_some()
                }
                _ => false,
            }
        }
        _ => false,
    }
}

pub(super) fn assigned_local(left: Node, src: &[u8]) -> Option<(String, bool)> {
    match left.kind() {
        "identifier" => Some((java_node_text(left, src).to_string(), false)),
        "array_access" => left
            .child_by_field_name("array")
            .and_then(|array| assigned_local(array, src))
            .map(|(name, _)| (name, true)),
        _ => None,
    }
}

#[derive(Default)]
pub(super) struct JavaLocalMutations {
    pub(super) reassigned: bool,
    pub(super) array_element_assigned: bool,
}

/// Captured arrays can be written across declaration scopes. Local reassignment stays in scope.
pub(super) fn local_mutations(declaration: Node, name: &str, src: &[u8]) -> JavaLocalMutations {
    let mut root = declaration;
    while let Some(parent) = root.parent() {
        root = parent;
        if matches!(
            root.kind(),
            "method_declaration" | "constructor_declaration" | "lambda_expression"
        ) {
            break;
        }
    }
    // Captured arrays remain mutable inside lambdas and anonymous classes, while
    // ordinary local reassignment cannot cross those declaration scopes.
    let mut stack = vec![(root, false)];
    let mut mutations = JavaLocalMutations::default();
    while let Some((node, nested_scope)) = stack.pop() {
        let nested_scope = nested_scope
            || (node.id() != root.id()
                && matches!(
                    node.kind(),
                    "method_declaration"
                        | "constructor_declaration"
                        | "class_declaration"
                        | "lambda_expression"
                ));
        if node.kind() == "assignment_expression"
            && let Some((assigned, array_element)) = node
                .child_by_field_name("left")
                .and_then(|left| assigned_local(left, src))
            && assigned == name
        {
            if array_element {
                mutations.array_element_assigned = true;
            } else if !nested_scope {
                mutations.reassigned = true;
            }
        }
        if node.kind() == "update_expression"
            && let Some((assigned, array_element)) = node
                .named_child(0)
                .and_then(|target| assigned_local(target, src))
            && assigned == name
        {
            if array_element {
                mutations.array_element_assigned = true;
            } else if !nested_scope {
                mutations.reassigned = true;
            }
        }
        if mutations.reassigned && mutations.array_element_assigned {
            break;
        }
        let mut cursor = node.walk();
        let children: Vec<_> = node.named_children(&mut cursor).collect();
        stack.extend(
            children
                .into_iter()
                .rev()
                .map(|child| (child, nested_scope)),
        );
    }
    mutations
}

pub(super) fn tracked_giveups_in<'a>(
    node: Node,
    src: &[u8],
    giveups: &'a HashSet<String>,
) -> Vec<&'a str> {
    let mut names = Vec::new();
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        if node.kind() == "identifier"
            && let Some(name) = giveups.get(java_node_text(node, src))
        {
            names.push(name.as_str());
        }
        let mut cursor = node.walk();
        let children: Vec<_> = node.named_children(&mut cursor).collect();
        stack.extend(children.into_iter().rev());
    }
    names
}
