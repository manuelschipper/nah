//! Which `return` statements of a function body can produce the value a
//! caller receives, and the parameter tests on the path to each.

use std::collections::{HashMap, HashSet};

use rustpython_parser::ast::{self, CmpOp, Constant, Expr, Ranged, Stmt, UnaryOp};
use rustpython_parser::text_size::TextRange;

use super::control::truthy;

/// A test of one parameter that holds on the path to a return: `if flag:`
/// gives `flag` truthy in its body and not truthy in its `else`. Only a
/// parameter the body never rebinds still holds the caller's argument there.
#[derive(Clone, PartialEq)]
pub(super) struct Guard {
    pub(super) param: String,
    test: Test,
    holds: bool,
}

#[derive(Clone, PartialEq)]
enum Test {
    /// `if p:`
    Truthy,
    /// `if p == <literal>:`; `!=` is its negation.
    Equals(Constant),
    /// `if p is None:`; `is not None` is its negation.
    IsNone,
}

impl Guard {
    /// Whether a call passing `argument` for the parameter cannot take this
    /// path: only a literal argument decides it.
    pub(super) fn refuted_by(&self, argument: &Expr) -> bool {
        let Expr::Constant(argument) = argument else {
            return false;
        };
        let outcome = match &self.test {
            Test::Truthy => truthy(&Expr::Constant(argument.clone())),
            Test::Equals(literal) => literal_equals(&argument.value, literal),
            Test::IsNone => Some(argument.value.is_none()),
        };
        outcome == Some(!self.holds)
    }

    fn negated(&self) -> Self {
        Self {
            holds: !self.holds,
            ..self.clone()
        }
    }
}

/// `left == right` for two literals, when Python's answer does not depend
/// on numeric coercion (`True == 1`).
fn literal_equals(left: &Constant, right: &Constant) -> Option<bool> {
    let kind = |constant: &Constant| match constant {
        Constant::None => Some(0),
        Constant::Str(_) => Some(1),
        Constant::Bytes(_) => Some(2),
        Constant::Bool(_) | Constant::Int(_) => Some(3),
        _ => None,
    };
    let (left_kind, right_kind) = (kind(left)?, kind(right)?);
    if left_kind != right_kind {
        return Some(false);
    }
    if left_kind == 3 && std::mem::discriminant(left) != std::mem::discriminant(right) {
        return None;
    }
    Some(left == right)
}

/// The returns of `body` a normal call can complete with, by statement
/// range, each with the parameter guards on its path. A return after an
/// unconditional `return` or `raise`, in a literal-false branch, after a
/// loop that never completes, or in a `try` whose `finally` always leaves
/// the function, is not one: the `finally`'s own returns replace it.
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

/// Whether control may complete a statement normally, and the guards that
/// then hold beyond those it started with.
type Falls = Option<Vec<Guard>>;

impl Reach {
    /// Collect the returns of `stmts`. A statement that falls through only
    /// when a guard holds, such as `if public: return "ping"`, guards the
    /// statements after it.
    fn block(
        &self,
        stmts: &[Stmt],
        guards: &mut Vec<Guard>,
        out: &mut HashMap<TextRange, Vec<Guard>>,
    ) -> Falls {
        let depth = guards.len();
        for stmt in stmts {
            match self.stmt(stmt, guards, out) {
                Some(after) => guards.extend(after),
                None => {
                    guards.truncate(depth);
                    return None;
                }
            }
        }
        Some(guards.split_off(depth))
    }

    fn stmt(
        &self,
        stmt: &Stmt,
        guards: &mut Vec<Guard>,
        out: &mut HashMap<TextRange, Vec<Guard>>,
    ) -> Falls {
        match stmt {
            Stmt::Return(_) => {
                out.insert(stmt.range(), guards.clone());
                None
            }
            Stmt::Raise(_) | Stmt::Break(_) | Stmt::Continue(_) => None,
            Stmt::If(s) => {
                let guard = self.guard(&s.test);
                let mut falling = Vec::new();
                for (arm, body) in [(true, s.body.as_slice()), (false, s.orelse.as_slice())] {
                    if truthy(&s.test) == Some(!arm) {
                        continue;
                    }
                    let taken = guard
                        .as_ref()
                        .map(|guard| if arm { guard.clone() } else { guard.negated() });
                    let depth = guards.len();
                    guards.extend(taken.clone());
                    if let Some(after) = self.block(body, guards, out) {
                        falling.push(taken.into_iter().chain(after).collect());
                    }
                    guards.truncate(depth);
                }
                match falling.len() {
                    0 => None,
                    1 => falling.pop(),
                    _ => Some(Vec::new()),
                }
            }
            Stmt::While(s) => {
                if truthy(&s.test) != Some(false) {
                    self.block(&s.body, guards, out);
                }
                // `while True` without a `break` leaves only by return or raise.
                if truthy(&s.test) == Some(true) && !jumps(&s.body, false) {
                    return None;
                }
                self.block(&s.orelse, guards, out);
                Some(Vec::new())
            }
            Stmt::For(s) => {
                let body = self.block(&s.body, guards, out);
                // A first iteration that always leaves the function ends it.
                if body.is_none() && nonempty(&s.iter) && !jumps(&s.body, true) {
                    return None;
                }
                self.block(&s.orelse, guards, out);
                Some(Vec::new())
            }
            Stmt::AsyncFor(s) => {
                self.block(&s.body, guards, out);
                self.block(&s.orelse, guards, out);
                Some(Vec::new())
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
                Some(Vec::new())
            }
            _ => Some(Vec::new()),
        }
    }

    /// A `try`: each part contributes its returns, which complete only when
    /// the `finally` falls through, under the guards that let it.
    fn try_stmt(
        &self,
        body: &[Stmt],
        handlers: &[ast::ExceptHandler],
        orelse: &[Stmt],
        finalbody: &[Stmt],
        guards: &mut Vec<Guard>,
        out: &mut HashMap<TextRange, Vec<Guard>>,
    ) -> Falls {
        let mut pending = HashMap::new();
        let mut falls = match self.block(body, guards, &mut pending) {
            Some(after) => {
                let depth = guards.len();
                guards.extend(after);
                let falls = self.block(orelse, guards, &mut pending).is_some();
                guards.truncate(depth);
                falls
            }
            None => false,
        };
        for handler in handlers {
            let ast::ExceptHandler::ExceptHandler(handler) = handler;
            falls |= self.block(&handler.body, guards, &mut pending).is_some();
        }
        let mut finally = HashMap::new();
        let after = self.block(finalbody, guards, &mut finally);
        out.extend(finally);
        let after = after?;
        for (range, mut site) in pending {
            site.extend(after.iter().cloned());
            out.insert(range, site);
        }
        falls.then_some(after)
    }

    /// The parameter test a branch reads: `p`, `p == <literal>`,
    /// `p is None`, or their negations.
    fn guard(&self, test: &Expr) -> Option<Guard> {
        let param = |expr: &Expr| match expr {
            Expr::Name(name) if self.params.contains(name.id.as_str()) => Some(name.id.to_string()),
            _ => None,
        };
        match test {
            Expr::Name(_) => Some(Guard {
                param: param(test)?,
                test: Test::Truthy,
                holds: true,
            }),
            Expr::UnaryOp(unary) if matches!(unary.op, UnaryOp::Not) => {
                self.guard(&unary.operand).map(|guard| guard.negated())
            }
            Expr::Compare(compare) if compare.ops.len() == 1 => {
                let right = &compare.comparators[0];
                let (name, literal) = match (&*compare.left, right) {
                    (_, Expr::Constant(literal)) => (param(&compare.left)?, &literal.value),
                    (Expr::Constant(literal), _) => (param(right)?, &literal.value),
                    _ => return None,
                };
                let (test, holds) = match (&compare.ops[0], literal) {
                    (CmpOp::Eq, _) => (Test::Equals(literal.clone()), true),
                    (CmpOp::NotEq, _) => (Test::Equals(literal.clone()), false),
                    (CmpOp::Is, Constant::None) => (Test::IsNone, true),
                    (CmpOp::IsNot, Constant::None) => (Test::IsNone, false),
                    _ => return None,
                };
                Some(Guard {
                    param: name,
                    test,
                    holds,
                })
            }
            _ => None,
        }
    }
}

/// A literal list, tuple or string with at least one element.
fn nonempty(iter: &Expr) -> bool {
    match iter {
        Expr::List(list) => {
            !list.elts.is_empty() && !list.elts.iter().any(|elt| elt.is_starred_expr())
        }
        Expr::Tuple(tuple) => {
            !tuple.elts.is_empty() && !tuple.elts.iter().any(|elt| elt.is_starred_expr())
        }
        Expr::Constant(constant) => {
            matches!(&constant.value, Constant::Str(text) if !text.is_empty())
        }
        _ => false,
    }
}

/// Whether `body` holds a `break`, or with `continue` also a `continue`, of
/// the loop it belongs to.
fn jumps(body: &[Stmt], with_continue: bool) -> bool {
    body.iter().any(|stmt| match stmt {
        Stmt::Break(_) => true,
        Stmt::Continue(_) => with_continue,
        Stmt::If(s) => jumps(&s.body, with_continue) || jumps(&s.orelse, with_continue),
        Stmt::With(s) => jumps(&s.body, with_continue),
        Stmt::AsyncWith(s) => jumps(&s.body, with_continue),
        // A nested loop owns the jumps in its body, not its `else`.
        Stmt::While(s) => jumps(&s.orelse, with_continue),
        Stmt::For(s) => jumps(&s.orelse, with_continue),
        Stmt::AsyncFor(s) => jumps(&s.orelse, with_continue),
        Stmt::Try(s) => try_jumps(&s.body, &s.handlers, &s.orelse, &s.finalbody, with_continue),
        Stmt::TryStar(s) => try_jumps(&s.body, &s.handlers, &s.orelse, &s.finalbody, with_continue),
        Stmt::Match(s) => s.cases.iter().any(|case| jumps(&case.body, with_continue)),
        _ => false,
    })
}

fn try_jumps(
    body: &[Stmt],
    handlers: &[ast::ExceptHandler],
    orelse: &[Stmt],
    finalbody: &[Stmt],
    with_continue: bool,
) -> bool {
    [body, orelse, finalbody]
        .iter()
        .any(|part| jumps(part, with_continue))
        || handlers.iter().any(|handler| {
            let ast::ExceptHandler::ExceptHandler(handler) = handler;
            jumps(&handler.body, with_continue)
        })
}
