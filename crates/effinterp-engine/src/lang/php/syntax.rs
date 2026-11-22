//! PHP tree-sitter node shapes shared by the invocation and summary walks.

use tree_sitter::Node;

/// Read a node from its original source, treating unavailable text as empty.
pub(super) fn text<'a>(n: Node, src: &'a str) -> &'a str {
    n.utf8_text(src.as_bytes()).unwrap_or("")
}

/// A named child with the given kind (tree-sitter-php fields are not always
/// present across versions, so navigate by kind).
pub(super) fn child_kind<'a>(n: Node<'a>, kind: &str) -> Option<Node<'a>> {
    let mut c = n.walk();
    n.named_children(&mut c).find(|ch| ch.kind() == kind)
}

/// Parameter names in declaration order, without the leading dollar sign.
pub(super) fn param_names(params: Node, src: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut c = params.walk();
    for p in params.named_children(&mut c) {
        if matches!(
            p.kind(),
            "simple_parameter" | "variadic_parameter" | "property_promotion_parameter"
        ) && let Some(v) = child_kind(p, "variable_name")
            && let Some(name) = child_kind(v, "name")
        {
            names.push(text(name, src).to_string());
        }
    }
    names
}

/// Callee of a function call: a bare `name` or a written `qualified_name`.
/// Variable / computed callees are None (dynamic).
pub(super) fn callable_name(n: Node, src: &str) -> Option<String> {
    let node = n
        .child_by_field_name("function")
        .filter(|f| matches!(f.kind(), "name" | "qualified_name"))
        .or_else(|| child_kind(n, "name"))
        .or_else(|| child_kind(n, "qualified_name"))?;
    Some(text(node, src).trim_start_matches('\\').to_string())
}

pub(super) fn array_values(n: Node) -> Vec<Node> {
    if n.kind() != "array_creation_expression" {
        return Vec::new();
    }
    let mut cursor = n.walk();
    n.named_children(&mut cursor)
        .filter(|child| child.kind() == "array_element_initializer")
        .filter_map(|element| {
            let mut cursor = element.walk();
            element.named_children(&mut cursor).last()
        })
        .collect()
}

/// Return argument expressions in source order, unwrapping named arguments.
pub(super) fn arg_nodes<'a>(call: Node<'a>) -> Vec<Node<'a>> {
    let Some(args) = child_kind(call, "arguments") else {
        return Vec::new();
    };
    let mut c = args.walk();
    args.named_children(&mut c)
        .filter_map(|a| {
            if a.kind() == "argument" {
                // The value follows an optional `name:` and `&` modifier.
                let mut cc = a.walk();
                a.named_children(&mut cc).last()
            } else {
                Some(a)
            }
        })
        .collect()
}

/// The value of a call's `name:` argument; named arguments may appear in any
/// order.
pub(super) fn named_argument<'a>(call: Node<'a>, name: &str, src: &str) -> Option<Node<'a>> {
    let args = child_kind(call, "arguments")?;
    let mut c = args.walk();
    args.named_children(&mut c)
        .filter(|a| a.kind() == "argument")
        .find(|a| {
            a.child_by_field_name("name")
                .is_some_and(|argument| text(argument, src) == name)
        })
        .and_then(|a| {
            let mut cc = a.walk();
            a.named_children(&mut cc).last()
        })
}

/// The first static string literal in `n`'s subtree, in pre-order. Used to pull
/// the path out of a `require`/`include` whose argument is a concatenation
/// (`__DIR__ . '/util.php'`) rather than a bare literal.
pub(super) fn first_string_literal(n: Node, src: &str) -> Option<String> {
    let mut stack = vec![n];
    while let Some(n) = stack.pop() {
        if let Some(s) = literal_string(n, src) {
            return Some(s);
        }
        let mut c = n.walk();
        let children: Vec<Node> = n.named_children(&mut c).collect();
        for ch in children.into_iter().rev() {
            stack.push(ch);
        }
    }
    None
}

/// A single-quoted `string` or a fully-literal `encapsed_string` (no
/// interpolation) as a Rust string, else None.
pub(super) fn literal_string(n: Node, src: &str) -> Option<String> {
    if !matches!(n.kind(), "string" | "encapsed_string") {
        return None;
    }
    let mut cursor = n.walk();
    if n.named_children(&mut cursor)
        .any(|part| !matches!(part.kind(), "string_content" | "escape_sequence"))
    {
        return None;
    }
    let raw = text(n, src).as_bytes();
    let quote = *raw.first()?;
    if !matches!(quote, b'\'' | b'"') || raw.last() != Some(&quote) {
        return None;
    }
    let mut bytes = raw.get(1..raw.len() - 1)?.iter().copied().peekable();
    let mut out = Vec::new();
    while let Some(byte) = bytes.next() {
        if byte != b'\\' {
            out.push(byte);
            continue;
        }
        let escaped = bytes.next()?;
        if quote == b'\'' {
            if !matches!(escaped, b'\'' | b'\\') {
                out.push(b'\\');
            }
            out.push(escaped);
            continue;
        }
        match escaped {
            b'n' => out.push(b'\n'),
            b'r' => out.push(b'\r'),
            b't' => out.push(b'\t'),
            b'v' => out.push(11),
            b'e' => out.push(27),
            b'f' => out.push(12),
            b'\\' | b'$' | b'"' => out.push(escaped),
            b'x' if bytes.peek().is_some_and(u8::is_ascii_hexdigit) => {
                let mut value = 0;
                for _ in 0..2 {
                    let Some(digit) = bytes.peek().and_then(|b| (*b as char).to_digit(16)) else {
                        break;
                    };
                    bytes.next();
                    value = value * 16 + digit as u8;
                }
                out.push(value);
            }
            b'0'..=b'7' => {
                let mut value = escaped - b'0';
                for _ in 0..2 {
                    let Some(digit @ b'0'..=b'7') = bytes.peek().copied() else {
                        break;
                    };
                    bytes.next();
                    value = value.wrapping_mul(8).wrapping_add(digit - b'0');
                }
                out.push(value);
            }
            b'u' if bytes.peek() == Some(&b'{') => {
                bytes.next();
                let mut value = 0u32;
                let mut digits = 0;
                loop {
                    let digit = bytes.next()?;
                    if digit == b'}' {
                        break;
                    }
                    value = value
                        .checked_mul(16)?
                        .checked_add((digit as char).to_digit(16)?)?;
                    digits += 1;
                }
                if digits == 0 {
                    return None;
                }
                let mut buffer = [0; 4];
                out.extend_from_slice(char::from_u32(value)?.encode_utf8(&mut buffer).as_bytes());
            }
            other => out.extend_from_slice(&[b'\\', other]),
        }
    }
    String::from_utf8(out).ok()
}

pub(super) fn this_property(node: Node, src: &str) -> Option<String> {
    if node.kind() != "member_access_expression" {
        return None;
    }
    let object = node.child_by_field_name("object")?;
    (variable_name(object, src) == Some("this"))
        .then(|| {
            node.child_by_field_name("name")
                .map(|name| text(name, src).to_string())
        })
        .flatten()
}

pub(super) fn scoped_value_parts(node: Node, src: &str) -> Option<(String, String)> {
    let scope = node.child_by_field_name("scope").or_else(|| {
        let mut cursor = node.walk();
        node.named_children(&mut cursor).next()
    })?;
    let name = node.child_by_field_name("name").or_else(|| {
        let mut cursor = node.walk();
        node.named_children(&mut cursor).last()
    })?;
    let name = if name.kind() == "variable_name" {
        child_kind(name, "name").map(|name| text(name, src))?
    } else {
        text(name, src)
    };
    Some((
        text(scope, src).trim_start_matches('\\').to_string(),
        name.trim_start_matches('$').to_string(),
    ))
}

pub(super) fn variable_name<'a>(node: Node, src: &'a str) -> Option<&'a str> {
    (node.kind() == "variable_name")
        .then(|| child_kind(node, "name").map(|name| text(name, src)))
        .flatten()
}
