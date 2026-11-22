//! Rust future and closure syntax shared by the execution and summary walks.

use std::collections::HashMap;

use syn::Expr;

use super::call_resolution::RustFunctions;
use super::syntax::{closure_expr, pat_ident, path_segments, single_ident};

#[derive(Clone)]
pub(super) struct RustClosure {
    pub(super) params: Vec<String>,
    pub(super) body: Expr,
}

fn future_def(expr: &Expr, fns: &RustFunctions<'_>) -> Option<Expr> {
    match expr {
        Expr::Async(_) => Some(expr.clone()),
        Expr::Call(call) => {
            let segments = path_segments(&call.func)?;
            (segments.len() == 1
                && fns
                    .get(&segments[0])
                    .is_some_and(|function| function.is_async))
            .then(|| expr.clone())
        }
        Expr::Group(group) => future_def(&group.expr, fns),
        Expr::Paren(paren) => future_def(&paren.expr, fns),
        _ => None,
    }
}

/// Recover a stored or directly constructed Rust future without walking its deferred body.
pub(super) fn bound_future(
    expr: &Expr,
    fns: &RustFunctions<'_>,
    futures: &HashMap<String, Expr>,
) -> Option<Expr> {
    future_def(expr, fns).or_else(|| future_name(expr).and_then(|name| futures.get(&name).cloned()))
}

pub(super) fn future_eager_arguments<'a>(expr: &'a Expr, fns: &RustFunctions<'_>) -> Vec<&'a Expr> {
    match expr {
        Expr::Call(call) => {
            let Some(segments) = path_segments(&call.func) else {
                return Vec::new();
            };
            if segments.len() == 1
                && fns
                    .get(&segments[0])
                    .is_some_and(|function| function.is_async)
            {
                call.args.iter().collect()
            } else {
                Vec::new()
            }
        }
        Expr::Group(group) => future_eager_arguments(&group.expr, fns),
        Expr::Paren(paren) => future_eager_arguments(&paren.expr, fns),
        _ => Vec::new(),
    }
}

pub(super) fn future_name(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Group(group) => future_name(&group.expr),
        Expr::Paren(paren) => future_name(&paren.expr),
        Expr::Path(path) => single_ident(&path.path),
        _ => None,
    }
}

pub(super) fn closure_def(expr: &Expr) -> Option<RustClosure> {
    let closure = closure_expr(expr)?;
    Some(RustClosure {
        params: closure.inputs.iter().filter_map(pat_ident).collect(),
        body: (*closure.body).clone(),
    })
}
