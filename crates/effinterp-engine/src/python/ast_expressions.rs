//! Python expression shape queries shared by walkers.

use std::collections::HashSet;

use rustpython_parser::ast;
use rustpython_parser::ast::Expr;

/// The callee of a call as written: a bare name or a dotted attribute chain
/// (`wipe`, `util.wipe`). None for anything more complex (a call result, a
/// subscript), which is never a cross-file linking candidate.
pub(super) fn callee_written(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Name(n) => Some(n.id.as_str().to_string()),
        Expr::Attribute(a) => {
            let base = callee_written(&a.value)?;
            Some(format!("{base}.{}", a.attr.as_str()))
        }
        _ => None,
    }
}

/// The immediate child expressions of `expr` that may themselves contain
/// effect calls. Deliberately partial: only the shapes that commonly wrap a
/// call (arguments, containers, operators, comprehensions).
/// A dictionary's keys precede its values in this traversal.
pub(super) fn child_exprs(expr: &Expr) -> Vec<&Expr> {
    let mut out: Vec<&Expr> = Vec::new();
    match expr {
        Expr::Call(c) => {
            out.push(&c.func);
            out.extend(c.args.iter());
            out.extend(c.keywords.iter().map(|k| &k.value));
        }
        Expr::Lambda(lambda) => out.extend(
            lambda
                .args
                .posonlyargs
                .iter()
                .chain(&lambda.args.args)
                .chain(&lambda.args.kwonlyargs)
                .filter_map(|arg| arg.default.as_deref()),
        ),
        Expr::BoolOp(b) => out.extend(b.values.iter()),
        Expr::BinOp(b) => {
            out.push(&b.left);
            out.push(&b.right);
        }
        Expr::UnaryOp(u) => out.push(&u.operand),
        Expr::IfExp(e) => {
            out.push(&e.test);
            out.push(&e.body);
            out.push(&e.orelse);
        }
        Expr::List(l) => out.extend(l.elts.iter()),
        Expr::Tuple(t) => out.extend(t.elts.iter()),
        Expr::Set(s) => out.extend(s.elts.iter()),
        Expr::Await(a) => out.push(&a.value),
        Expr::Starred(s) => out.push(&s.value),
        Expr::Subscript(s) => out.push(&s.value),
        Expr::Attribute(a) => out.push(&a.value),
        Expr::Compare(c) => {
            out.push(&c.left);
            out.extend(c.comparators.iter());
        }
        Expr::NamedExpr(n) => out.push(&n.value),
        Expr::Dict(d) => {
            out.extend(d.keys.iter().flatten());
            out.extend(d.values.iter());
        }
        Expr::JoinedStr(j) => out.extend(j.values.iter()),
        Expr::FormattedValue(f) => out.push(&f.value),
        Expr::Yield(y) => out.extend(y.value.as_deref()),
        Expr::YieldFrom(y) => out.push(&y.value),
        Expr::ListComp(c) => {
            out.push(&c.elt);
            out.extend(comprehension_exprs(&c.generators));
        }
        Expr::SetComp(c) => {
            out.push(&c.elt);
            out.extend(comprehension_exprs(&c.generators));
        }
        Expr::GeneratorExp(c) => {
            out.push(&c.elt);
            out.extend(comprehension_exprs(&c.generators));
        }
        Expr::DictComp(c) => {
            out.push(&c.key);
            out.push(&c.value);
            out.extend(comprehension_exprs(&c.generators));
        }
        _ => {}
    }
    out
}

pub(super) fn expression_uses_name(expr: &Expr, names: &HashSet<String>) -> bool {
    matches!(expr, Expr::Name(name) if names.contains(name.id.as_str()))
        || child_exprs(expr)
            .into_iter()
            .any(|child| expression_uses_name(child, names))
}

/// The executed subexpressions of comprehension generators: each iterable and
/// filter condition (the bound target is a binding pattern, not evaluated).
fn comprehension_exprs(generators: &[ast::Comprehension]) -> Vec<&Expr> {
    let mut out = Vec::new();
    for g in generators {
        out.push(&g.iter);
        out.extend(g.ifs.iter());
    }
    out
}
