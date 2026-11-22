//! Python literal values.
//! Projection requires an AST shape that fixes the selected elements without evaluating Python.

use rustpython_parser::ast;
use rustpython_parser::ast::{Constant, Expr};

/// Whether subscripts are all a program does with `name` after binding it
/// once: every mention is that one `name = ...` statement or a read
/// `name[literal]`. Any other use (an alias, a call argument, a method, a
/// subscript store or delete, a mention inside a string that `exec` could
/// run) may change an element, so it fails.
pub(super) fn subscript_only(source: &str, name: &str) -> bool {
    use rustpython_parser::{Mode, Tok, lexer::lex};
    let Ok(mut tokens) = lex(source, Mode::Module)
        .map(|token| token.map(|(token, _)| token))
        .collect::<Result<Vec<_>, _>>()
    else {
        return false;
    };
    // Layout tokens say nothing about how a name is used.
    tokens.retain(|token| !matches!(token, Tok::Indent | Tok::Dedent));
    let named = |token: &Tok| matches!(token, Tok::Name { name: found } if found == name);
    // A mention the lexer does not see as a name is inside a string.
    if source.matches(name).count() != tokens.iter().filter(|token| named(token)).count() {
        return false;
    }
    let assigns = |token: &Tok| {
        matches!(
            token,
            Tok::Equal
                | Tok::ColonEqual
                | Tok::PlusEqual
                | Tok::MinusEqual
                | Tok::StarEqual
                | Tok::SlashEqual
                | Tok::PercentEqual
                | Tok::AmperEqual
                | Tok::VbarEqual
                | Tok::CircumflexEqual
                | Tok::LeftShiftEqual
                | Tok::RightShiftEqual
                | Tok::DoubleStarEqual
                | Tok::DoubleSlashEqual
                | Tok::AtEqual
        )
    };
    let mut bindings = 0;
    // One logical line at a time: a store can only be spelled within one.
    for line in tokens.split(|token| matches!(token, Tok::Newline | Tok::Semi)) {
        for (at, _) in line.iter().enumerate().filter(|(_, token)| named(token)) {
            if at == 0 && line.get(1) == Some(&Tok::Equal) {
                bindings += 1;
                continue;
            }
            let reads_element = matches!(
                line.get(at + 1..at + 4),
                Some([Tok::Lsqb, Tok::String { .. } | Tok::Int { .. }, Tok::Rsqb])
            );
            // A loop, `with`, `del` or declaration before it can make the
            // subscript a target.
            let targeted = line[..at].iter().any(|token| {
                matches!(
                    token,
                    Tok::For | Tok::Del | Tok::As | Tok::Global | Tok::Nonlocal | Tok::Import
                )
            });
            // So can an assignment after it, outside any bracket.
            let mut depth = 0i32;
            let stored = line[at + 1..].iter().any(|token| {
                match token {
                    Tok::Lpar | Tok::Lsqb | Tok::Lbrace => depth += 1,
                    Tok::Rpar | Tok::Rsqb | Tok::Rbrace => depth -= 1,
                    _ => {}
                }
                depth <= 0 && assigns(token)
            });
            if !reads_element || targeted || stored {
                return false;
            }
        }
    }
    bindings == 1
}

/// A literal subscript: `box[1]`, `box["status"]`.
#[derive(Clone, PartialEq)]
pub(super) enum ElementKey {
    Index(usize),
    Key(String),
}

/// The element a subscript's literal index or key selects.
pub(super) fn element_key(slice: &Expr) -> Option<ElementKey> {
    let Expr::Constant(constant) = slice else {
        return None;
    };
    match &constant.value {
        ast::Constant::Str(key) => Some(ElementKey::Key(key.clone())),
        ast::Constant::Int(index) => index.to_string().parse().ok().map(ElementKey::Index),
        _ => None,
    }
}

/// The elements of a literal list, tuple or dict display, each with the
/// subscript that selects it. `None` when unpacking or a computed key hides
/// which element a subscript selects.
pub(super) fn literal_elements(value: &Expr) -> Option<Vec<(ElementKey, &Expr)>> {
    fn positional(elements: &[Expr]) -> Option<Vec<(ElementKey, &Expr)>> {
        elements
            .iter()
            .enumerate()
            .map(|(index, element)| {
                (!element.is_starred_expr()).then_some((ElementKey::Index(index), element))
            })
            .collect()
    }
    match value {
        Expr::List(list) => positional(&list.elts),
        Expr::Tuple(tuple) => positional(&tuple.elts),
        Expr::Dict(dict) => dict
            .keys
            .iter()
            .zip(&dict.values)
            .map(|(key, value)| Some((element_key(key.as_ref()?)?, value)))
            .collect(),
        _ => None,
    }
}

/// The names of a `a, b = p, q` target each paired with its element of a
/// literal value of the same length, when neither side unpacks with `*`.
pub(super) fn literal_unpack<'v>(target: &Expr, value: &'v Expr) -> Vec<(String, &'v Expr)> {
    let names = match target {
        Expr::Tuple(tuple) => &tuple.elts,
        Expr::List(list) => &list.elts,
        _ => return Vec::new(),
    };
    let elements = match value {
        Expr::Tuple(tuple) => &tuple.elts,
        Expr::List(list) => &list.elts,
        _ => return Vec::new(),
    };
    if names.len() != elements.len()
        || elements
            .iter()
            .any(|element| matches!(element, Expr::Starred(_)))
    {
        return Vec::new();
    }
    names
        .iter()
        .zip(elements)
        .filter_map(|(name, element)| match name {
            Expr::Name(name) => Some((name.id.to_string(), element)),
            _ => None,
        })
        .collect()
}

/// A small non-negative integer literal (a port number), when the expression
/// is one and fits a `u16`.
pub(super) fn int_literal(expr: &Expr) -> Option<u16> {
    match expr {
        Expr::Constant(c) => match &c.value {
            Constant::Int(i) => i.to_string().parse::<u16>().ok(),
            _ => None,
        },
        _ => None,
    }
}

pub(super) fn unpack_assignment_elements(targets: &[Expr]) -> Option<&[Expr]> {
    match targets {
        [Expr::Tuple(tuple)] => Some(tuple.elts.as_slice()),
        [Expr::List(list)] => Some(list.elts.as_slice()),
        _ => None,
    }
}

pub(super) fn sequence_expr_elements(expr: &Expr) -> Option<&[Expr]> {
    match expr {
        Expr::Tuple(tuple) => Some(tuple.elts.as_slice()),
        Expr::List(list) => Some(list.elts.as_slice()),
        _ => None,
    }
}
