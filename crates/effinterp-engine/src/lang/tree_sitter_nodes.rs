//! Tree-sitter node helpers shared by the Java and PHP frontends.

use tree_sitter::Node;

use crate::control_flow::Span;

/// A tree-sitter node's byte range, as the span that keys control-flow sites.
pub(super) fn node_span(node: Node) -> Span {
    (node.start_byte() as u32, node.end_byte() as u32)
}

/// A node's named children, collected so the cursor does not outlive the call.
pub(super) fn named_children(node: Node) -> Vec<Node> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).collect()
}

/// The source text a node covers; empty when its range is not valid in `source`.
pub(super) fn node_text<'a>(node: Node, source: &'a str) -> &'a str {
    let start = node.start_byte();
    let end = node.end_byte().min(source.len());
    source.get(start..end).unwrap_or("")
}
