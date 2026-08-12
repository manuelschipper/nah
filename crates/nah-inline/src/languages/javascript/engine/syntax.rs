//! JavaScript HIR shape, directive, mutation, and direct-call recognition.

use super::*;

pub(super) fn named_children(node: &HirNode) -> impl Iterator<Item = &HirNode> {
    node.children()
        .iter()
        .filter(|child| !matches!(child.kind(), HirKind::Token | HirKind::Comment))
}

pub(super) fn strict_directive(node: &HirNode, source: &str) -> bool {
    for statement in named_children(node) {
        if statement.kind() != HirKind::ExpressionStatement {
            return false;
        }
        let mut expressions = named_children(statement);
        let Some(expression) = expressions.next() else {
            return false;
        };
        if expression.kind() != HirKind::String || expressions.next().is_some() {
            return false;
        }
        let literal = source
            .get(expression.span().start()..expression.span().end())
            .unwrap_or_default();
        if matches!(literal, "'use strict'" | "\"use strict\"") {
            return true;
        }
    }
    false
}

pub(super) fn source_is_module(node: &HirNode) -> bool {
    named_children(node).any(|child| {
        matches!(
            child.kind(),
            HirKind::ImportStatement | HirKind::ExportStatement
        )
    })
}

pub(super) fn asynchronous_function(node: &HirNode, source: &str) -> bool {
    node.children().iter().any(|child| {
        child.kind() == HirKind::Token
            && source
                .get(child.span().start()..child.span().end())
                .is_some_and(|token| token == "async")
    })
}

pub(super) fn member_assignment_target(node: &HirNode) -> Option<&HirNode> {
    match node.kind() {
        HirKind::MemberExpression | HirKind::SubscriptExpression => Some(node),
        HirKind::ParenthesizedExpression | HirKind::TransparentExpression => named_children(node)
            .next()
            .and_then(member_assignment_target),
        _ => None,
    }
}

pub(super) fn prototype_mutation_target(source: &str) -> bool {
    let compact = source
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    let builtin_prototype = [
        "Object", "Number", "Boolean", "String", "Function", "Array", "Promise",
    ]
    .iter()
    .any(|root| {
        [
            format!("{root}.prototype"),
            format!("{root}['prototype']"),
            format!("{root}[\"prototype\"]"),
        ]
        .iter()
        .any(|prefix| {
            compact.strip_prefix(prefix).is_some_and(|suffix| {
                suffix.is_empty() || suffix.starts_with('.') || suffix.starts_with('[')
            })
        })
    });
    if builtin_prototype {
        return true;
    }
    let Some(segments) = simple_member_segments(&compact) else {
        return false;
    };
    segments.iter().any(|segment| segment == "__proto__")
}

pub(super) fn simple_member_segments(source: &str) -> Option<Vec<String>> {
    let bytes = source.as_bytes();
    let mut cursor = 0;
    let mut segments = Vec::new();
    while cursor < bytes.len() {
        if !segments.is_empty() {
            match bytes[cursor] {
                b'.' => cursor += 1,
                b'[' => {
                    cursor += 1;
                    let quote = *bytes.get(cursor)?;
                    if !matches!(quote, b'\'' | b'"') {
                        return None;
                    }
                    cursor += 1;
                    let start = cursor;
                    while bytes.get(cursor).is_some_and(|byte| *byte != quote) {
                        if bytes[cursor] == b'\\' {
                            return None;
                        }
                        cursor += 1;
                    }
                    let segment = source.get(start..cursor)?.to_owned();
                    cursor += 1;
                    if bytes.get(cursor) != Some(&b']') {
                        return None;
                    }
                    cursor += 1;
                    segments.push(segment);
                    continue;
                }
                _ => return None,
            }
        }
        let start = cursor;
        while bytes
            .get(cursor)
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$'))
        {
            cursor += 1;
        }
        if cursor == start {
            return None;
        }
        segments.push(source.get(start..cursor)?.to_owned());
    }
    Some(segments)
}

pub(super) fn direct_receiver_expression(node: &HirNode) -> bool {
    match node.kind() {
        HirKind::MemberExpression | HirKind::SubscriptExpression => true,
        HirKind::ParenthesizedExpression | HirKind::TransparentExpression => named_children(node)
            .next()
            .is_some_and(direct_receiver_expression),
        _ => false,
    }
}

pub(super) fn direct_call_identity(node: &HirNode) -> Option<usize> {
    match node.kind() {
        HirKind::CallExpression => Some(node as *const HirNode as usize),
        HirKind::ParenthesizedExpression | HirKind::TransparentExpression => {
            named_children(node).next().and_then(direct_call_identity)
        }
        _ => None,
    }
}

pub(super) fn direct_receiver_required(function: &KnownFunction) -> bool {
    matches!(
        function,
        KnownFunction::DenoCommand(_, _) | KnownFunction::BunFile(_, _)
    )
}

pub(super) fn source_mutates(node: &HirNode) -> bool {
    if matches!(
        node.kind(),
        HirKind::AssignmentExpression
            | HirKind::AugmentedAssignmentExpression
            | HirKind::UpdateExpression
            | HirKind::LexicalDeclaration
            | HirKind::VariableDeclaration
            | HirKind::FunctionDeclaration
            | HirKind::ClassDeclaration
            | HirKind::ImportStatement
            | HirKind::Unsupported
            | HirKind::Error
    ) {
        return true;
    }
    named_children(node).any(source_mutates)
}
