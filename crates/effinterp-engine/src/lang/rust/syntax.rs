//! Shared Rust syntax queries. These inspect syntax without resolving names.

use syn::{Block, Expr, Local, Pat, Stmt};

/// The base identifier a method chain hangs off (`preprocessors` in
/// `preprocessors.iter().try_for_each(..)`), for element-typing closures.
pub(super) fn chain_base_ident(expr: &Expr) -> Option<String> {
    match expr {
        Expr::MethodCall(m) => chain_base_ident(&m.receiver),
        Expr::Reference(r) => chain_base_ident(&r.expr),
        Expr::Paren(p) => chain_base_ident(&p.expr),
        Expr::Try(t) => chain_base_ident(&t.expr),
        Expr::Path(p) => single_ident(&p.path),
        _ => None,
    }
}

pub(super) fn mutated_base_ident(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Field(field) => mutated_base_ident(&field.base),
        Expr::Index(index) => mutated_base_ident(&index.expr),
        Expr::MethodCall(call) => mutated_base_ident(&call.receiver),
        Expr::Reference(reference) => mutated_base_ident(&reference.expr),
        Expr::Paren(paren) => mutated_base_ident(&paren.expr),
        Expr::Group(group) => mutated_base_ident(&group.expr),
        Expr::Try(try_) => mutated_base_ident(&try_.expr),
        Expr::Path(path) => single_ident(&path.path),
        _ => None,
    }
}

pub(super) fn is_compound_assignment(operator: &syn::BinOp) -> bool {
    matches!(
        operator,
        syn::BinOp::AddAssign(_)
            | syn::BinOp::SubAssign(_)
            | syn::BinOp::MulAssign(_)
            | syn::BinOp::DivAssign(_)
            | syn::BinOp::RemAssign(_)
            | syn::BinOp::BitXorAssign(_)
            | syn::BinOp::BitAndAssign(_)
            | syn::BinOp::BitOrAssign(_)
            | syn::BinOp::ShlAssign(_)
            | syn::BinOp::ShrAssign(_)
    )
}

pub(super) fn path_segments(expr: &Expr) -> Option<Vec<String>> {
    if let Expr::Path(p) = expr {
        Some(
            p.path
                .segments
                .iter()
                .map(|s| s.ident.to_string())
                .collect(),
        )
    } else {
        None
    }
}

/// The single identifier a `let` pattern binds, looking through a type
/// ascription (`let x: T = ...`) and by-ref/mut markers.
pub(super) fn pat_ident(pat: &Pat) -> Option<String> {
    match pat {
        Pat::Ident(id) => Some(id.ident.to_string()),
        Pat::Type(pt) => pat_ident(&pt.pat),
        Pat::Reference(r) => pat_ident(&r.pat),
        _ => None,
    }
}

pub(super) fn single_ident(path: &syn::Path) -> Option<String> {
    if path.segments.len() == 1 {
        Some(path.segments[0].ident.to_string())
    } else {
        None
    }
}

pub(super) fn str_lit(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Lit(l) => match &l.lit {
            syn::Lit::Str(s) => Some(s.value()),
            _ => None,
        },
        Expr::Reference(r) => str_lit(&r.expr),
        _ => None,
    }
}

/// The argument expressions of a call/method-call, for recursing to find
/// nested effects (e.g. `remove_file(compute_path())`).
pub(super) fn call_arg_exprs(expr: &Expr) -> Vec<&Expr> {
    match expr {
        Expr::Call(c) => c.args.iter().collect(),
        Expr::MethodCall(m) => m.args.iter().collect(),
        _ => Vec::new(),
    }
}

/// Recognize a Rust closure expression through parentheses and groups.
pub(super) fn closure_expr(expr: &Expr) -> Option<&syn::ExprClosure> {
    match expr {
        Expr::Closure(closure) => Some(closure),
        Expr::Paren(paren) => closure_expr(&paren.expr),
        Expr::Group(group) => closure_expr(&group.expr),
        _ => None,
    }
}

/// Sub-expressions to recurse into for a generic (non-effect) expression.
/// Deliberately broad but bounded. Constructing a closure or async block does
/// not execute its body. Call and method arguments may invoke a closure, while
/// direct closure bindings and awaited async blocks are handled by the walkers.
pub(super) fn child_exprs(expr: &Expr) -> Vec<&Expr> {
    let mut out: Vec<&Expr> = Vec::new();
    match expr {
        Expr::Closure(_) | Expr::Async(_) => {}
        Expr::Call(c) => {
            if let Some(closure) = closure_expr(&c.func) {
                out.push(&closure.body);
            } else {
                out.push(&c.func);
            }
            for arg in &c.args {
                if let Expr::Closure(closure) = arg {
                    out.push(&closure.body);
                } else {
                    out.push(arg);
                }
            }
        }
        Expr::MethodCall(m) => {
            out.push(&m.receiver);
            for arg in &m.args {
                if let Expr::Closure(closure) = arg {
                    out.push(&closure.body);
                } else {
                    out.push(arg);
                }
            }
        }
        Expr::Binary(b) => {
            out.push(&b.left);
            out.push(&b.right);
        }
        Expr::Unary(u) => out.push(&u.expr),
        Expr::Reference(r) => out.push(&r.expr),
        Expr::Paren(p) => out.push(&p.expr),
        Expr::Group(g) => out.push(&g.expr),
        Expr::Field(f) => out.push(&f.base),
        Expr::Index(i) => {
            out.push(&i.expr);
            out.push(&i.index);
        }
        Expr::Try(t) => out.push(&t.expr),
        Expr::Await(a) => out.push(&a.base),
        Expr::Cast(c) => out.push(&c.expr),
        Expr::Assign(a) => {
            out.push(&a.left);
            out.push(&a.right);
        }
        Expr::Let(l) => out.push(&l.expr),
        Expr::If(i) => {
            out.push(&i.cond);
            out.extend(block_exprs(&i.then_branch));
            if let Some((_, else_e)) = &i.else_branch {
                out.push(else_e);
            }
        }
        Expr::While(w) => {
            out.push(&w.cond);
            out.extend(block_exprs(&w.body));
        }
        Expr::ForLoop(f) => {
            out.push(&f.expr);
            out.extend(block_exprs(&f.body));
        }
        Expr::Loop(l) => out.extend(block_exprs(&l.body)),
        Expr::Block(b) => out.extend(block_exprs(&b.block)),
        Expr::Unsafe(u) => out.extend(block_exprs(&u.block)),
        Expr::Match(m) => {
            out.push(&m.expr);
            for arm in &m.arms {
                out.push(&arm.body);
            }
        }
        Expr::Return(r) => {
            if let Some(e) = &r.expr {
                out.push(e);
            }
        }
        Expr::Array(a) => out.extend(a.elems.iter()),
        Expr::Tuple(t) => out.extend(t.elems.iter()),
        Expr::Struct(s) => {
            for f in &s.fields {
                out.push(&f.expr);
            }
        }
        _ => {}
    }
    out
}

pub(super) fn block_exprs(block: &Block) -> Vec<&Expr> {
    let mut out = Vec::new();
    for stmt in &block.stmts {
        match stmt {
            Stmt::Expr(e, _) => out.push(e),
            Stmt::Local(Local { init: Some(li), .. }) => out.push(&li.expr),
            _ => {}
        }
    }
    out
}
