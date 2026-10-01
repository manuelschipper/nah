//! Which `return` statements of a function body can produce the value a
//! caller receives, and the parameter tests on the path to each.

use std::collections::{HashMap, HashSet};

use rustpython_parser::ast::{self, Expr, Ranged, Stmt, UnaryOp};
use rustpython_parser::text_size::TextRange;

use super::control::truthy;

/// A test of a parameter's truthiness, `(name, truthy)`, that holds on the
/// path to a return: `if flag:` gives `(flag, true)` in its body and
/// `(flag, false)` in its `else`. Only a parameter the body never rebinds
/// still holds the caller's argument there.
pub(super) type Guard = (String, bool);

/// The returns of `body` a normal call can complete with, by statement
/// range, each with the parameter guards on its path. A return after an
/// unconditional `return` or `raise`, in a literal-false branch, or in a
/// `try` whose `finally` always leaves the function, is not one: the
/// `finally`'s own returns replace it.
pub(super) fn reachable_returns(
    body: &[Stmt],
    params: &[String],
) -> HashMap<TextRange, Vec<Guard>> {
    let mut returns = HashMap::new();
    let rebound = super::rebound_body_names(body, false);
    let params = params
        .iter()
        .filter(|param| !rebound.contains(*param))
        .cloned()
        .collect();
    Reach { params }.block(body, &mut Vec::new(), &mut returns);
    returns
}

struct Reach {
    params: HashSet<String>,
}

impl Reach {
    /// Collect the returns of `stmts`; whether control may fall out the end.
    fn block(
        &self,
        stmts: &[Stmt],
        guards: &mut Vec<Guard>,
        out: &mut HashMap<TextRange, Vec<Guard>>,
    ) -> bool {
        stmts.iter().all(|stmt| self.stmt(stmt, guards, out))
    }

    /// Collect the returns of `stmt`; whether it may complete normally.
    fn stmt(
        &self,
        stmt: &Stmt,
        guards: &mut Vec<Guard>,
        out: &mut HashMap<TextRange, Vec<Guard>>,
    ) -> bool {
        match stmt {
            Stmt::Return(_) => {
                out.insert(stmt.range(), guards.clone());
                false
            }
            Stmt::Raise(_) | Stmt::Break(_) | Stmt::Continue(_) => false,
            Stmt::If(s) => {
                let guard = self.guard(&s.test);
                let mut falls = false;
                for (arm, body) in [(true, s.body.as_slice()), (false, s.orelse.as_slice())] {
                    if truthy(&s.test) == Some(!arm) {
                        continue;
                    }
                    let pushed = guard.clone().map(|(name, value)| (name, value == arm));
                    guards.extend(pushed.clone());
                    falls |= self.block(body, guards, out);
                    guards.truncate(guards.len() - usize::from(pushed.is_some()));
                }
                falls
            }
            Stmt::While(s) => {
                if truthy(&s.test) != Some(false) {
                    self.block(&s.body, guards, out);
                }
                self.block(&s.orelse, guards, out);
                true
            }
            Stmt::For(s) => {
                self.block(&s.body, guards, out);
                self.block(&s.orelse, guards, out);
                true
            }
            Stmt::AsyncFor(s) => {
                self.block(&s.body, guards, out);
                self.block(&s.orelse, guards, out);
                true
            }
            Stmt::With(s) => self.block(&s.body, guards, out),
            Stmt::AsyncWith(s) => self.block(&s.body, guards, out),
            Stmt::Try(s) => {
                self.try_stmt(&s.body, &s.handlers, &s.orelse, &s.finalbody, guards, out)
            }
            Stmt::TryStar(s) => {
                self.try_stmt(&s.body, &s.handlers, &s.orelse, &s.finalbody, guards, out)
            }
            Stmt::Match(s) => {
                for case in &s.cases {
                    self.block(&case.body, guards, out);
                }
                true
            }
            _ => true,
        }
    }

    /// A `try`: a `finally` that always leaves the function replaces every
    /// return before it; otherwise each part contributes its own.
    fn try_stmt(
        &self,
        body: &[Stmt],
        handlers: &[ast::ExceptHandler],
        orelse: &[Stmt],
        finalbody: &[Stmt],
        guards: &mut Vec<Guard>,
        out: &mut HashMap<TextRange, Vec<Guard>>,
    ) -> bool {
        let mut pending = HashMap::new();
        let mut falls =
            self.block(body, guards, &mut pending) && self.block(orelse, guards, &mut pending);
        for handler in handlers {
            let ast::ExceptHandler::ExceptHandler(handler) = handler;
            falls |= self.block(&handler.body, guards, &mut pending);
        }
        let mut finally = HashMap::new();
        let finally_falls = self.block(finalbody, guards, &mut finally);
        out.extend(finally);
        if !finally_falls {
            return false;
        }
        out.extend(pending);
        falls
    }

    /// The parameter a branch test reads as a bare truth value: `p` or
    /// `not p`.
    fn guard(&self, test: &Expr) -> Option<Guard> {
        match test {
            Expr::Name(name) if self.params.contains(name.id.as_str()) => {
                Some((name.id.to_string(), true))
            }
            Expr::UnaryOp(unary) if matches!(unary.op, UnaryOp::Not) => self
                .guard(&unary.operand)
                .map(|(name, value)| (name, !value)),
            _ => None,
        }
    }
}
