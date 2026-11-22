//! Source spellings and traversal of Java syntax nodes.

use tree_sitter::Node;

/// Strips generics, array brackets, and qualifiers from a written Java type.
pub(super) fn bare_java_type(text: &str) -> String {
    let t = text.split('<').next().unwrap_or(text);
    let t = t.trim_end_matches("[]").trim();
    t.rsplit('.').next().unwrap_or(t).to_string()
}

/// Returns an empty spelling when the node's source bytes cannot be read as UTF-8.
pub(super) fn java_node_text<'a>(n: Node, src: &'a [u8]) -> &'a str {
    n.utf8_text(src).unwrap_or("")
}

/// Visits every Java syntax node, including unnamed tokens, in source preorder.
pub(super) fn visit_java_syntax<'a>(n: Node<'a>, f: &mut impl FnMut(Node<'a>)) {
    let mut stack = vec![n];
    while let Some(n) = stack.pop() {
        f(n);
        let mut cursor = n.walk();
        let children: Vec<Node<'a>> = n.children(&mut cursor).collect();
        for c in children.into_iter().rev() {
            stack.push(c);
        }
    }
}

/// Reads the first named child of the Java argument list.
pub(super) fn first_argument(invocation: Node) -> Option<Node> {
    invocation
        .child_by_field_name("arguments")
        .and_then(|arguments| arguments.named_child(0))
}

pub(super) fn receiver_identifier<'a>(receiver: Node, src: &'a [u8]) -> Option<&'a str> {
    (receiver.kind() == "identifier").then(|| java_node_text(receiver, src))
}

pub(super) fn unquote_java_string(s: &str) -> String {
    s.trim_matches('"').to_string()
}
