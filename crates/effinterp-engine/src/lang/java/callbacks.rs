//! Shared rules for when Java callbacks run and which values reach them.

use super::declarations::JavaFile;
use super::resource_recovery::recover_java_arguments;
use super::syntax::java_node_text;
use crate::lang::frontend::MAX_CALLBACK_VALUES;
use crate::value::unresolved_resource;
use effinterp_proto::ResourceExpr;
use std::collections::HashMap;
use tree_sitter::Node;

/// Java callback inputs use one unresolved value for a missing source or the tail beyond the cap.
pub(super) fn recover_java_callback_inputs(
    invocation: Node,
    file: &JavaFile,
    src: &[u8],
    env: &HashMap<String, ResourceExpr>,
    types: &HashMap<String, String>,
) -> Vec<ResourceExpr> {
    let Some(source) = callback_input_source(invocation, file, src) else {
        return vec![unresolved_resource("value")];
    };
    let mut args = recover_java_arguments(source, src, env, &file.constants, types);
    if args.len() > MAX_CALLBACK_VALUES {
        args.truncate(MAX_CALLBACK_VALUES);
        args.push(unresolved_resource("value"));
    }
    args
}

/// Recovers a JDK callback input source through an identity-preserving chain.
fn callback_input_source<'a>(
    invocation: Node<'a>,
    file: &JavaFile,
    src: &[u8],
) -> Option<Node<'a>> {
    // A concrete callback value is safe only when a known JDK source reaches
    // the callback through links that preserve element identity.
    let mut receiver = invocation.child_by_field_name("object");
    while let Some(call) = receiver.filter(|node| node.kind() == "method_invocation") {
        let name = call
            .child_by_field_name("name")
            .map(|node| java_node_text(node, src))
            .unwrap_or("");
        if let Some(owner) = call.child_by_field_name("object")
            && let Some(fqn) = file.jdk_fqn(java_node_text(owner, src))
            && matches!(
                (fqn.as_str(), name),
                ("java.util.List" | "java.util.Set", "of")
                    | ("java.util.stream.Stream", "of" | "ofNullable")
                    | ("java.util.Optional", "of" | "ofNullable")
                    | ("java.util.concurrent.CompletableFuture", "completedFuture")
            )
        {
            return Some(call);
        }
        if !matches!(
            name,
            "stream"
                | "parallelStream"
                | "filter"
                | "peek"
                | "distinct"
                | "sorted"
                | "limit"
                | "skip"
                | "takeWhile"
                | "dropWhile"
                | "sequential"
                | "parallel"
                | "unordered"
        ) {
            return None;
        }
        receiver = call.child_by_field_name("object");
    }
    None
}

pub(super) fn callback_method(name: &str) -> bool {
    matches!(
        name,
        "forEach"
            | "forEachOrdered"
            | "map"
            | "flatMap"
            | "filter"
            | "peek"
            | "reduce"
            | "collect"
            | "anyMatch"
            | "allMatch"
            | "noneMatch"
            | "ifPresent"
            | "orElseGet"
            | "runAsync"
            | "supplyAsync"
            | "thenRun"
            | "thenApply"
            | "thenAccept"
            | "thenCompose"
            | "whenComplete"
            | "handle"
            | "exceptionally"
            | "submit"
            | "execute"
            | "invokeAll"
    )
}

/// Lazy stream callbacks need a terminal operation in the enclosing expression.
pub(super) fn callbacks_execute_at(n: Node, name: &str, src: &[u8]) -> bool {
    if !callback_method(name) {
        return false;
    }
    if !matches!(name, "map" | "flatMap" | "filter" | "peek") {
        return true;
    }
    let mut ancestor = n.parent();
    while let Some(node) = ancestor {
        if node.kind() == "method_invocation"
            && node.child_by_field_name("name").is_some_and(|method| {
                matches!(
                    java_node_text(method, src),
                    "forEach"
                        | "forEachOrdered"
                        | "collect"
                        | "reduce"
                        | "count"
                        | "min"
                        | "max"
                        | "findFirst"
                        | "findAny"
                        | "anyMatch"
                        | "allMatch"
                        | "noneMatch"
                        | "toArray"
                        | "toList"
                )
            })
        {
            return true;
        }
        if matches!(
            node.kind(),
            "expression_statement"
                | "local_variable_declaration"
                | "return_statement"
                | "argument_list"
                | "method_declaration"
        ) {
            break;
        }
        ancestor = node.parent();
    }
    false
}

pub(super) fn java_callback_arguments(n: Node) -> Vec<Node> {
    let Some(arguments) = n.child_by_field_name("arguments") else {
        return Vec::new();
    };
    let mut cursor = arguments.walk();
    arguments
        .named_children(&mut cursor)
        .filter(|argument| matches!(argument.kind(), "lambda_expression" | "method_reference"))
        .collect()
}

pub(super) fn callback_bindings<'a>(
    n: Node<'a>,
    src: &[u8],
    callbacks: &HashMap<String, Vec<Node<'a>>>,
) -> Vec<Node<'a>> {
    let Some(arguments) = n.child_by_field_name("arguments") else {
        return Vec::new();
    };
    let mut cursor = arguments.walk();
    arguments
        .named_children(&mut cursor)
        .filter(|argument| argument.kind() == "identifier")
        .flat_map(|argument| {
            callbacks
                .get(java_node_text(argument, src))
                .cloned()
                .unwrap_or_default()
        })
        .collect()
}

pub(super) fn lambda_param_names(lambda: Node, src: &[u8]) -> Vec<String> {
    let Some(parameters) = lambda.child_by_field_name("parameters") else {
        return Vec::new();
    };
    if parameters.kind() == "identifier" {
        return vec![java_node_text(parameters, src).to_string()];
    }
    let mut cursor = parameters.walk();
    parameters
        .named_children(&mut cursor)
        .filter_map(|parameter| match parameter.kind() {
            "identifier" => Some(java_node_text(parameter, src).to_string()),
            "formal_parameter" | "spread_parameter" => parameter
                .child_by_field_name("name")
                .map(|name| java_node_text(name, src).to_string()),
            _ => None,
        })
        .collect()
}

pub(super) fn method_reference_parts<'a>(
    reference: Node,
    src: &'a [u8],
) -> Option<(&'a str, &'a str)> {
    let (receiver, method) = java_node_text(reference, src).rsplit_once("::")?;
    let receiver = receiver.trim();
    let method = method.trim();
    (!receiver.is_empty() && !method.is_empty() && method != "new").then_some((receiver, method))
}

/// Returns true when a distinct Java receiver or callback exceeds the candidate cap.
pub(super) fn push_node_candidate<'a>(
    candidates: &mut HashMap<String, Vec<Node<'a>>>,
    name: String,
    node: Node<'a>,
) -> bool {
    let bindings = candidates.entry(name).or_default();
    if bindings.iter().any(|candidate| candidate.id() == node.id()) {
        return false;
    }
    if bindings.len() >= MAX_CALLBACK_VALUES {
        return true;
    }
    bindings.push(node);
    false
}
