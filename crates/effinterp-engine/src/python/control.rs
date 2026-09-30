//! A Python callable's effect-directed control flow.
//!
//! Calls, decorator applications, context managers, and imports are the sites
//! that may run code. Exceptional edges enter handlers and cleanup separately
//! from normal continuations, because cleanup can suppress an exception.

use std::collections::HashSet;

use rustpython_parser::ast::{self, Constant, Expr, Ranged, Stmt};
use rustpython_parser::text_size::TextRange;

use crate::control_flow::{Catch, ControlExit, Exn, Frontier, Graph, Jump, Span, Symbol};

/// Which top-level entrypoint guard arm executes.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Entry {
    /// A function body: the guard is an ordinary branch.
    Callable,
    /// The file runs as the program, so `__name__ == "__main__"`.
    Main,
}

pub(super) fn span(range: TextRange) -> Span {
    (range.start().into(), range.end().into())
}

/// The span where a decorator's application, not its expression, registers.
pub(super) fn decorator_span(decorator: &Expr) -> Span {
    let end = decorator.range().end().into();
    (end, end)
}

/// The spans where a context manager's entry and its exception suppression
/// register. Both are empty, so neither collides with the manager expression.
pub(super) fn context_spans(item: &ast::WithItem) -> (Span, Span) {
    let (start, end) = span(item.context_expr.range());
    ((start, start), (end, end))
}

pub(super) fn build(graph: &mut Graph, body: &[Stmt], entry: Entry, extra_bound: &HashSet<String>) {
    graph.enable_exceptions();
    let start = graph.entry();
    let mut bound = extra_bound.clone();
    collect_bound(body, &mut bound);
    if bound.contains("*") {
        graph.widen();
        return;
    }
    let mut builder = Builder {
        graph,
        entry,
        local_annotations: entry == Entry::Callable,
        bound,
        current_caught: Exn::Unknown,
    };
    let end = builder.stmts(start, body);
    builder.graph.exit(end, ControlExit::Success);
}

struct Builder<'g> {
    graph: &'g mut Graph,
    entry: Entry,
    local_annotations: bool,
    bound: HashSet<String>,
    current_caught: Exn,
}

const PY_EXCEPTIONS: &[&str] = &[
    "BaseException",
    "Exception",
    "RuntimeError",
    "ValueError",
    "SystemExit",
    "TypeError",
    "AttributeError",
    "IndexError",
    "KeyError",
    "AssertionError",
    "ZeroDivisionError",
    "NameError",
    "StopIteration",
    "OSError",
];

fn insert_bound(bound: &mut HashSet<String>, name: String) {
    if name == "*" || PY_EXCEPTIONS.contains(&name.as_str()) {
        bound.insert(name);
    }
}

pub(super) fn collect_bound(body: &[Stmt], bound: &mut HashSet<String>) {
    let mut scan = BoundScan { depth: 0, steps: 0 };
    scan.body(body, bound);
}

struct BoundScan {
    depth: u32,
    steps: u64,
}

impl BoundScan {
    fn step(&mut self, bound: &mut HashSet<String>) -> bool {
        self.steps += 1;
        if bound.contains("*")
            || self.steps > crate::AnalysisLimits::default().max_causal_pairs
            || !crate::limits::summary_step()
        {
            insert_bound(bound, "*".into());
            return false;
        }
        true
    }

    fn body(&mut self, body: &[Stmt], bound: &mut HashSet<String>) {
        if self.depth >= 192 {
            insert_bound(bound, "*".into());
            return;
        }
        self.depth += 1;
        for stmt in body {
            if !self.step(bound) {
                return;
            }
            match stmt {
                Stmt::FunctionDef(def) => {
                    insert_bound(bound, def.name.to_string());
                }
                Stmt::AsyncFunctionDef(def) => {
                    insert_bound(bound, def.name.to_string());
                }
                Stmt::ClassDef(def) => {
                    insert_bound(bound, def.name.to_string());
                }
                Stmt::Assign(assign) => {
                    for target in &assign.targets {
                        if !self.step(bound) {
                            return;
                        }
                        self.target(target, bound);
                    }
                }
                Stmt::AnnAssign(assign) => self.target(&assign.target, bound),
                Stmt::AugAssign(assign) => self.target(&assign.target, bound),
                Stmt::For(stmt) => {
                    self.target(&stmt.target, bound);
                    self.body(&stmt.body, bound);
                    self.body(&stmt.orelse, bound);
                }
                Stmt::AsyncFor(stmt) => {
                    self.target(&stmt.target, bound);
                    self.body(&stmt.body, bound);
                    self.body(&stmt.orelse, bound);
                }
                Stmt::With(stmt) => {
                    for item in &stmt.items {
                        if !self.step(bound) {
                            return;
                        }
                        if let Some(target) = &item.optional_vars {
                            self.target(target, bound);
                        }
                    }
                    self.body(&stmt.body, bound);
                }
                Stmt::AsyncWith(stmt) => {
                    for item in &stmt.items {
                        if !self.step(bound) {
                            return;
                        }
                        if let Some(target) = &item.optional_vars {
                            self.target(target, bound);
                        }
                    }
                    self.body(&stmt.body, bound);
                }
                Stmt::If(stmt) => {
                    self.body(&stmt.body, bound);
                    self.body(&stmt.orelse, bound);
                }
                Stmt::While(stmt) => {
                    self.body(&stmt.body, bound);
                    self.body(&stmt.orelse, bound);
                }
                Stmt::Try(stmt) => {
                    self.body(&stmt.body, bound);
                    self.body(&stmt.orelse, bound);
                    self.body(&stmt.finalbody, bound);
                    for handler in &stmt.handlers {
                        if !self.step(bound) {
                            return;
                        }
                        let ast::ExceptHandler::ExceptHandler(handler) = handler;
                        if let Some(name) = &handler.name {
                            insert_bound(bound, name.to_string());
                        }
                        self.body(&handler.body, bound);
                    }
                }
                Stmt::TryStar(stmt) => {
                    self.body(&stmt.body, bound);
                    self.body(&stmt.orelse, bound);
                    self.body(&stmt.finalbody, bound);
                    for handler in &stmt.handlers {
                        if !self.step(bound) {
                            return;
                        }
                        let ast::ExceptHandler::ExceptHandler(handler) = handler;
                        if let Some(name) = &handler.name {
                            insert_bound(bound, name.to_string());
                        }
                        self.body(&handler.body, bound);
                    }
                }
                Stmt::Match(stmt) => {
                    insert_bound(bound, "*".into());
                    for case in &stmt.cases {
                        if !self.step(bound) {
                            return;
                        }
                        self.body(&case.body, bound);
                    }
                }
                Stmt::Global(stmt) => {
                    for name in &stmt.names {
                        if !self.step(bound) {
                            return;
                        }
                        insert_bound(bound, name.to_string());
                    }
                }
                Stmt::Nonlocal(stmt) => {
                    for name in &stmt.names {
                        if !self.step(bound) {
                            return;
                        }
                        insert_bound(bound, name.to_string());
                    }
                }
                Stmt::Import(import) => {
                    for alias in &import.names {
                        if !self.step(bound) {
                            return;
                        }
                        let name = alias.asname.as_ref().unwrap_or(&alias.name);
                        insert_bound(
                            bound,
                            name.as_str()
                                .split('.')
                                .next()
                                .unwrap_or(name.as_str())
                                .to_string(),
                        );
                    }
                }
                Stmt::ImportFrom(import) => {
                    for alias in &import.names {
                        if !self.step(bound) {
                            return;
                        }
                        if alias.name.as_str() == "*" {
                            insert_bound(bound, "*".into());
                            continue;
                        }
                        let name = alias.asname.as_ref().unwrap_or(&alias.name);
                        insert_bound(bound, name.to_string());
                    }
                }
                _ => {}
            }
        }
        self.depth -= 1;
    }
    fn target(&mut self, expr: &Expr, bound: &mut HashSet<String>) {
        if !self.step(bound) || self.depth >= 192 {
            insert_bound(bound, "*".into());
            return;
        }
        self.depth += 1;
        match expr {
            Expr::Name(name) => {
                insert_bound(bound, name.id.to_string());
            }
            Expr::Tuple(value) => {
                for element in &value.elts {
                    if !self.step(bound) {
                        return;
                    }
                    self.target(element, bound);
                }
            }
            Expr::List(value) => {
                for element in &value.elts {
                    if !self.step(bound) {
                        return;
                    }
                    self.target(element, bound);
                }
            }
            Expr::Starred(starred) => self.target(&starred.value, bound),
            _ => {}
        }
        self.depth -= 1;
    }
}

fn resolve_builtin(name: &str, bound: &HashSet<String>) -> Option<Symbol> {
    if !bound.contains("*") && !bound.contains(name) && PY_EXCEPTIONS.contains(&name) {
        Some(Symbol::py(name))
    } else {
        None
    }
}

fn raise_exn(expr: Option<&Expr>, bound: &HashSet<String>, current: &Exn) -> Exn {
    match expr {
        None => current.clone(),
        Some(Expr::Name(name)) => resolve_builtin(name.id.as_str(), bound)
            .map(Exn::named)
            .unwrap_or(Exn::Unknown),
        Some(Expr::Call(call)) => match call.func.as_ref() {
            Expr::Name(name) => resolve_builtin(name.id.as_str(), bound)
                .map(Exn::named)
                .unwrap_or(Exn::Unknown),
            _ => Exn::Unknown,
        },
        _ => Exn::Unknown,
    }
}

fn catch_names(elts: &[Expr], bound: &HashSet<String>) -> Catch {
    let mut names = Vec::new();
    for element in elts {
        match element {
            Expr::Name(name) => match resolve_builtin(name.id.as_str(), bound) {
                Some(symbol) => names.push(symbol),
                None => return Catch::Unknown,
            },
            _ => return Catch::Unknown,
        }
    }
    Catch::names(names)
}

fn catch_of(expr: Option<&Expr>, bound: &HashSet<String>) -> Catch {
    match expr {
        None => Catch::Any,
        Some(Expr::Name(name)) => resolve_builtin(name.id.as_str(), bound)
            .map(Catch::named)
            .unwrap_or(Catch::Unknown),
        Some(Expr::Tuple(value)) => catch_names(&value.elts, bound),
        Some(Expr::List(value)) => catch_names(&value.elts, bound),
        _ => Catch::Unknown,
    }
}

fn non_empty_literal(expr: &Expr) -> bool {
    match expr {
        Expr::List(list) => {
            !list.elts.is_empty() && !list.elts.iter().any(|e| matches!(e, Expr::Starred(_)))
        }
        Expr::Tuple(tuple) => {
            !tuple.elts.is_empty() && !tuple.elts.iter().any(|e| matches!(e, Expr::Starred(_)))
        }
        Expr::Constant(constant) => {
            matches!(&constant.value, Constant::Str(text) if !text.is_empty())
        }
        _ => false,
    }
}

pub(super) fn truthy(expr: &Expr) -> Option<bool> {
    let Expr::Constant(constant) = expr else {
        return None;
    };
    match &constant.value {
        Constant::Bool(value) => Some(*value),
        Constant::None => Some(false),
        Constant::Int(value) => Some(value.to_string() != "0"),
        Constant::Str(text) => Some(!text.is_empty()),
        _ => None,
    }
}

impl Builder<'_> {
    fn test(&mut self, at: Frontier, expr: &Expr) -> Frontier {
        let at = self.expr(at, expr);
        if matches!(expr, Expr::Constant(_)) {
            at
        } else {
            self.graph.may_throw(at)
        }
    }

    fn iterable(&mut self, at: Frontier, expr: &Expr) -> Frontier {
        let at = self.expr(at, expr);
        if matches!(expr, Expr::List(_) | Expr::Tuple(_))
            || matches!(expr, Expr::Constant(value) if matches!(value.value, Constant::Str(_) | Constant::Bytes(_)))
        {
            at
        } else {
            self.graph.may_throw(at)
        }
    }

    fn stmts(&mut self, mut at: Frontier, body: &[Stmt]) -> Frontier {
        if !self.graph.enter() {
            return None;
        }
        for stmt in body {
            at = self.stmt(at, stmt);
        }
        self.graph.leave();
        at
    }

    fn exprs<'e>(
        &mut self,
        mut at: Frontier,
        exprs: impl IntoIterator<Item = &'e Expr>,
    ) -> Frontier {
        for expr in exprs {
            at = self.expr(at, expr);
        }
        at
    }

    fn decorators(&mut self, at: Frontier, decorators: &[Expr]) -> Frontier {
        let mut at = at;
        // Decorators apply innermost first, after every expression evaluated.
        for decorator in decorators.iter().rev() {
            at = self.graph.site(at, decorator_span(decorator), true);
        }
        at
    }

    fn arguments(&mut self, at: Frontier, args: &ast::Arguments) -> Frontier {
        let defaults = args
            .posonlyargs
            .iter()
            .chain(&args.args)
            .chain(&args.kwonlyargs)
            .filter_map(|arg| arg.default.as_deref());
        self.exprs(at, defaults)
    }

    fn annotations(
        &mut self,
        mut at: Frontier,
        args: &ast::Arguments,
        returns: Option<&Expr>,
    ) -> Frontier {
        for annotation in args
            .posonlyargs
            .iter()
            .chain(&args.args)
            .chain(&args.kwonlyargs)
            .filter_map(|arg| arg.def.annotation.as_deref())
            .chain(
                args.vararg
                    .as_ref()
                    .and_then(|arg| arg.annotation.as_deref()),
            )
            .chain(
                args.kwarg
                    .as_ref()
                    .and_then(|arg| arg.annotation.as_deref()),
            )
            .chain(returns)
        {
            at = self.expr(at, annotation);
            at = self.graph.may_throw(at);
        }
        at
    }

    fn stmt(&mut self, at: Frontier, stmt: &Stmt) -> Frontier {
        at?;
        match stmt {
            Stmt::FunctionDef(def) => {
                let at = self.exprs(at, &def.decorator_list);
                let at = self.arguments(at, &def.args);
                let at = self.annotations(at, &def.args, def.returns.as_deref());
                self.decorators(at, &def.decorator_list)
            }
            Stmt::AsyncFunctionDef(def) => {
                let at = self.exprs(at, &def.decorator_list);
                let at = self.arguments(at, &def.args);
                let at = self.annotations(at, &def.args, def.returns.as_deref());
                self.decorators(at, &def.decorator_list)
            }
            Stmt::ClassDef(class) => {
                let at = self.exprs(at, &class.decorator_list);
                let at = self.exprs(at, &class.bases);
                let at = self.exprs(at, class.keywords.iter().map(|keyword| &keyword.value));
                let local_annotations = self.local_annotations;
                self.local_annotations = false;
                let at = self.stmts(at, &class.body);
                self.local_annotations = local_annotations;
                self.decorators(at, &class.decorator_list)
            }
            Stmt::Return(ret) => {
                let at = self.exprs(at, ret.value.as_deref());
                self.graph.jump(at, Jump::Return);
                None
            }
            Stmt::Delete(delete) => {
                let at = self.exprs(at, &delete.targets);
                self.graph.may_throw(at)
            }
            Stmt::Assign(assign) => {
                let mut at = self.expr(at, &assign.value);
                let length = match assign.value.as_ref() {
                    Expr::List(value)
                        if !value
                            .elts
                            .iter()
                            .any(|element| matches!(element, Expr::Starred(_))) =>
                    {
                        Some(value.elts.len())
                    }
                    Expr::Tuple(value)
                        if !value
                            .elts
                            .iter()
                            .any(|element| matches!(element, Expr::Starred(_))) =>
                    {
                        Some(value.elts.len())
                    }
                    _ => None,
                };
                for target in &assign.targets {
                    let elements = match target {
                        Expr::Tuple(value) => Some(&value.elts),
                        Expr::List(value) => Some(&value.elts),
                        _ => None,
                    };
                    if let (Some(length), Some(elements)) = (length, elements) {
                        let starred = elements
                            .iter()
                            .filter(|element| matches!(element, Expr::Starred(_)))
                            .count();
                        if (starred == 0 && length != elements.len())
                            || length < elements.len() - starred
                        {
                            return self.graph.abort(at, Exn::named(Symbol::py("ValueError")));
                        }
                    }
                    if elements.is_some() {
                        at = self.graph.may_throw(at);
                    }
                    at = self.expr(at, target);
                }
                at
            }
            Stmt::AugAssign(assign) => {
                let at = self.expr(at, &assign.target);
                let at = self.expr(at, &assign.value);
                self.graph.may_throw(at)
            }
            Stmt::AnnAssign(assign) => {
                let at = self.exprs(at, assign.value.as_deref());
                let at = self.expr(at, &assign.target);
                if self.local_annotations {
                    at
                } else {
                    let at = self.expr(at, &assign.annotation);
                    self.graph.may_throw(at)
                }
            }
            Stmt::TypeAlias(_) | Stmt::Pass(_) | Stmt::Global(_) | Stmt::Nonlocal(_) => at,
            Stmt::For(stmt) => self.for_loop(
                at,
                &stmt.iter,
                &stmt.target,
                &stmt.body,
                &stmt.orelse,
                false,
            ),
            Stmt::AsyncFor(stmt) => {
                self.for_loop(at, &stmt.iter, &stmt.target, &stmt.body, &stmt.orelse, true)
            }
            Stmt::While(stmt) => self.while_loop(at, &stmt.test, &stmt.body, &stmt.orelse),
            Stmt::If(stmt) => {
                let arm = match self.entry {
                    _ if super::is_type_checking_test(&stmt.test) => Some(false),
                    _ if truthy(&stmt.test).is_some() => truthy(&stmt.test),
                    Entry::Main if super::is_main_guard_test(&stmt.test) => Some(true),
                    _ => None,
                };
                match arm {
                    Some(true) => self.stmts(at, &stmt.body),
                    Some(false) => self.stmts(at, &stmt.orelse),
                    None => {
                        let test = self.test(at, &stmt.test);
                        let yes = self.stmts(test, &stmt.body);
                        let no = self.stmts(test, &stmt.orelse);
                        self.graph.join(&[yes, no])
                    }
                }
            }
            Stmt::With(stmt) => self.with(at, &stmt.items, &stmt.body),
            Stmt::AsyncWith(stmt) => self.with(at, &stmt.items, &stmt.body),
            Stmt::Match(stmt) => {
                let subject = self.expr(at, &stmt.subject);
                let mut ends = Vec::new();
                let mut exhaustive = false;
                for case in &stmt.cases {
                    let guarded = self.exprs(subject, case.guard.as_deref());
                    ends.push(self.stmts(guarded, &case.body));
                    exhaustive |= case.guard.is_none()
                        && matches!(&case.pattern, ast::Pattern::MatchAs(pattern)
                            if pattern.pattern.is_none());
                }
                if !exhaustive {
                    ends.push(subject);
                }
                self.graph.join(&ends)
            }
            Stmt::Raise(raise) => {
                let at = self.exprs(at, raise.exc.as_deref());
                let at = self.exprs(at, raise.cause.as_deref());
                let exn = raise_exn(raise.exc.as_deref(), &self.bound, &self.current_caught);
                self.graph.throw(at, exn);
                None
            }
            Stmt::Try(stmt) => self.try_stmt(
                at,
                &stmt.body,
                &stmt.handlers,
                &stmt.orelse,
                &stmt.finalbody,
            ),
            Stmt::TryStar(stmt) => self.try_stmt(
                at,
                &stmt.body,
                &stmt.handlers,
                &stmt.orelse,
                &stmt.finalbody,
            ),
            Stmt::Assert(assert) => {
                let at = self.test(at, &assert.test);
                // The message is evaluated only when the assertion fails.
                if truthy(&assert.test) != Some(true) {
                    let failed = self.exprs(at, assert.msg.as_deref());
                    self.graph
                        .throw(failed, Exn::named(Symbol::py("AssertionError")));
                }
                if truthy(&assert.test) == Some(false) {
                    None
                } else {
                    at
                }
            }
            Stmt::Import(import) => self.graph.site(at, span(import.range), true),
            Stmt::ImportFrom(import) => self.graph.site(at, span(import.range), true),
            Stmt::Expr(expr) => self.expr(at, &expr.value),
            Stmt::Break(_) => {
                self.graph.jump(at, Jump::Break(None));
                None
            }
            Stmt::Continue(_) => {
                self.graph.jump(at, Jump::Continue(None));
                None
            }
        }
    }

    fn for_loop(
        &mut self,
        at: Frontier,
        iter: &Expr,
        target: &Expr,
        body: &[Stmt],
        orelse: &[Stmt],
        asynchronous: bool,
    ) -> Frontier {
        let at = self.iterable(at, iter);
        if asynchronous {
            // Each step awaits the iterator's own code.
            self.graph.unknown(at);
        }
        let header = self.graph.header(at);
        self.graph.push_loop(None, true);
        let assigned = if matches!(target, Expr::Tuple(_) | Expr::List(_)) {
            self.graph.may_throw(header)
        } else {
            header
        };
        let assigned = self.expr(assigned, target);
        let end = self.stmts(assigned, body);
        let (breaks, continues) = self.graph.pop_loop();
        let back = self.graph.join(
            &std::iter::once(end)
                .chain(continues.into_iter().map(Some))
                .collect::<Vec<_>>(),
        );
        self.graph.backedge(back, header);
        // A non-empty literal runs the body before the loop can finish.
        let exhausted = if non_empty_literal(iter) {
            back
        } else {
            header
        };
        let orelse = self.stmts(exhausted, orelse);
        self.graph.join(
            &std::iter::once(orelse)
                .chain(breaks.into_iter().map(Some))
                .collect::<Vec<_>>(),
        )
    }

    fn while_loop(
        &mut self,
        at: Frontier,
        test: &Expr,
        body: &[Stmt],
        orelse: &[Stmt],
    ) -> Frontier {
        let header = self.graph.header(at);
        let tested = self.test(header, test);
        let truth = truthy(test);
        self.graph.push_loop(None, true);
        let end = self.stmts(if truth == Some(false) { None } else { tested }, body);
        let (breaks, continues) = self.graph.pop_loop();
        let back = self.graph.join(
            &std::iter::once(end)
                .chain(continues.into_iter().map(Some))
                .collect::<Vec<_>>(),
        );
        self.graph.backedge(back, header);
        let exhausted = if truth == Some(true) { None } else { tested };
        let orelse = self.stmts(exhausted, orelse);
        self.graph.join(
            &std::iter::once(orelse)
                .chain(breaks.into_iter().map(Some))
                .collect::<Vec<_>>(),
        )
    }

    fn with(&mut self, mut at: Frontier, items: &[ast::WithItem], body: &[Stmt]) -> Frontier {
        let mut suppressions = Vec::new();
        for item in items {
            at = self.expr(at, &item.context_expr);
            let (enter, suppress) = context_spans(item);
            at = self.graph.site(at, enter, true);
            if let Some(target) = &item.optional_vars {
                at = self.expr(at, target);
            }
            suppressions.push((at, suppress));
        }
        let mut end = self.stmts(at, body);
        // An unmodeled manager's exit may swallow an exception raised anywhere
        // inside, continuing after the statement.
        for (entered, suppress) in suppressions.into_iter().rev() {
            let suppressed = self.graph.site(entered, suppress, false);
            end = self.graph.join(&[end, suppressed]);
        }
        end
    }

    fn try_stmt(
        &mut self,
        at: Frontier,
        body: &[Stmt],
        handlers: &[ast::ExceptHandler],
        orelse: &[Stmt],
        finalbody: &[Stmt],
    ) -> Frontier {
        let cleanup = !finalbody.is_empty();
        if cleanup {
            self.graph.push_cleanup();
        }
        if !handlers.is_empty() {
            self.graph.push_catch();
        }
        let end = self.stmts(at, body);
        let thrown = if handlers.is_empty() {
            Vec::new()
        } else {
            self.graph.pop_catch()
        };
        self.graph.rethrow(&thrown);
        let mut ends = vec![self.stmts(end, orelse)];
        for handler in handlers {
            let ast::ExceptHandler::ExceptHandler(handler) = handler;
            let catch = catch_of(handler.type_.as_deref(), &self.bound);
            let saved = self.current_caught.clone();
            self.current_caught = match &catch {
                Catch::Named { names } => Exn::names(names.clone()),
                _ => Exn::Unknown,
            };
            let entry = self.graph.catch_handler(&thrown, catch);
            let matched = self.exprs(entry, handler.type_.as_deref());
            ends.push(self.stmts(matched, &handler.body));
            self.current_caught = saved;
        }
        let normal = self.graph.join(&ends);
        if !cleanup {
            return normal;
        }
        let (abrupt, pending): (Vec<_>, Vec<_>) = self
            .graph
            .pop_cleanup()
            .into_iter()
            .partition(|(_, jump)| *jump == Jump::Throw);
        let entry = self.graph.join(
            &std::iter::once(normal)
                .chain(pending.iter().map(|(from, _)| Some(*from)))
                .collect::<Vec<_>>(),
        );
        let end = self.stmts(entry, finalbody);
        self.graph.resume(end, pending);
        let thrown = self.graph.join(
            &abrupt
                .iter()
                .map(|(from, _)| Some(*from))
                .collect::<Vec<_>>(),
        );
        let exceptional_end = self.stmts(thrown, finalbody);
        self.graph.resume(exceptional_end, abrupt);
        normal.and(end)
    }

    fn comprehension(
        &mut self,
        at: Frontier,
        generators: &[ast::Comprehension],
        elements: &[&Expr],
    ) -> Frontier {
        let Some((first, rest)) = generators.split_first() else {
            return at;
        };
        // Only the outermost iterable is evaluated unconditionally.
        let evaluated = self.iterable(at, &first.iter);
        let mut optional = evaluated;
        for filter in &first.ifs {
            optional = self.test(optional, filter);
        }
        for generator in rest {
            optional = self.iterable(optional, &generator.iter);
            for filter in &generator.ifs {
                optional = self.test(optional, filter);
            }
        }
        let optional = self.exprs(optional, elements.iter().copied());
        self.graph.join(&[evaluated, optional])
    }

    fn expr(&mut self, at: Frontier, expr: &Expr) -> Frontier {
        at?;
        if !self.graph.enter() {
            return None;
        }
        let end = match expr {
            Expr::BoolOp(op) => {
                let Some((first, rest)) = op.values.split_first() else {
                    self.graph.leave();
                    return at;
                };
                let mut current = self.expr(at, first);
                let mut ends = Vec::new();
                let mut previous = first;
                for value in rest {
                    if !matches!(previous, Expr::Constant(_)) {
                        current = self.graph.may_throw(current);
                    }
                    ends.push(current);
                    current = self.expr(current, value);
                    previous = value;
                }
                ends.push(current);
                self.graph.join(&ends)
            }
            Expr::NamedExpr(named) => self.expr(at, &named.value),
            Expr::BinOp(op) => {
                let at = self.expr(at, &op.left);
                let at = self.expr(at, &op.right);
                let zero = matches!(op.right.as_ref(), Expr::Constant(value) if match &value.value {
                    Constant::Int(value) => value.to_string() == "0",
                    Constant::Float(value) => *value == 0.0,
                    _ => false,
                });
                let integers = [&*op.left, &*op.right].iter().all(|value| {
                    matches!(value,
                    Expr::Constant(value) if matches!(value.value, Constant::Int(_)))
                });
                if matches!(op.left.as_ref(), Expr::Constant(value) if matches!(value.value, Constant::Int(_) | Constant::Float(_)))
                    && zero
                    && matches!(
                        op.op,
                        ast::Operator::Div | ast::Operator::FloorDiv | ast::Operator::Mod
                    )
                {
                    self.graph
                        .abort(at, Exn::named(Symbol::py("ZeroDivisionError")))
                } else if integers
                    && matches!(
                        op.op,
                        ast::Operator::Add | ast::Operator::Sub | ast::Operator::Mult
                    )
                {
                    at
                } else {
                    self.graph.may_throw(at)
                }
            }
            Expr::UnaryOp(op) => {
                let at = self.expr(at, &op.operand);
                let safe = matches!(op.operand.as_ref(), Expr::Constant(value)
                    if matches!(op.op, ast::UnaryOp::Not)
                        || matches!(value.value, Constant::Int(_))
                        || (matches!(op.op, ast::UnaryOp::UAdd | ast::UnaryOp::USub)
                            && matches!(value.value, Constant::Float(_) | Constant::Complex { .. })));
                if safe { at } else { self.graph.may_throw(at) }
            }
            Expr::Lambda(lambda) => self.arguments(at, &lambda.args),
            Expr::IfExp(branch) => {
                let test = self.test(at, &branch.test);
                let yes = self.expr(test, &branch.body);
                let no = self.expr(test, &branch.orelse);
                self.graph.join(&[yes, no])
            }
            Expr::Dict(dict) => {
                let mut at = at;
                for (key, value) in dict.keys.iter().zip(&dict.values) {
                    at = self.exprs(at, key.as_ref());
                    at = self.expr(at, value);
                    if !matches!(key, Some(Expr::Constant(_))) {
                        at = self.graph.may_throw(at);
                    }
                }
                at
            }
            Expr::Set(set) => {
                let mut at = at;
                for element in &set.elts {
                    at = self.expr(at, element);
                    if !matches!(element, Expr::Constant(_)) {
                        at = self.graph.may_throw(at);
                    }
                }
                at
            }
            Expr::ListComp(comp) => self.comprehension(at, &comp.generators, &[&comp.elt]),
            Expr::SetComp(comp) => {
                let at = self.comprehension(at, &comp.generators, &[&comp.elt]);
                if matches!(comp.elt.as_ref(), Expr::Constant(_)) {
                    at
                } else {
                    self.graph.may_throw(at)
                }
            }
            Expr::DictComp(comp) => {
                let at = self.comprehension(at, &comp.generators, &[&comp.key, &comp.value]);
                if matches!(comp.key.as_ref(), Expr::Constant(_)) {
                    at
                } else {
                    self.graph.may_throw(at)
                }
            }
            // A generator evaluates only its outermost iterable until consumed.
            Expr::GeneratorExp(comp) => match comp.generators.first() {
                Some(first) => self.iterable(at, &first.iter),
                None => at,
            },
            Expr::Await(awaited) => {
                let at = self.expr(at, &awaited.value);
                self.graph.may_throw(at)
            }
            Expr::Yield(yielded) => {
                let at = self.exprs(at, yielded.value.as_deref());
                // The consumer may stop iterating here.
                self.graph.bypass(at);
                at
            }
            Expr::YieldFrom(yielded) => {
                let at = self.expr(at, &yielded.value);
                self.graph.bypass(at);
                at
            }
            Expr::Compare(compare) => {
                let at = self.expr(at, &compare.left);
                let mut current = at;
                let mut ends = Vec::new();
                let mut left = compare.left.as_ref();
                for (operator, value) in compare.ops.iter().zip(&compare.comparators) {
                    current = self.expr(current, value);
                    let integers = [left, value].iter().all(|expr| {
                        matches!(expr,
                        Expr::Constant(value) if matches!(value.value, Constant::Int(_)))
                    });
                    if !matches!(operator, ast::CmpOp::Is | ast::CmpOp::IsNot)
                        && (!integers || matches!(operator, ast::CmpOp::In | ast::CmpOp::NotIn))
                    {
                        current = self.graph.may_throw(current);
                    }
                    ends.push(current);
                    left = value;
                }
                self.graph.join(&ends)
            }
            Expr::Call(call) => {
                let at = match call.func.as_ref() {
                    Expr::Attribute(attribute)
                        if matches!(attribute.value.as_ref(), Expr::Constant(value) if value.value == Constant::None)
                            && !attribute.attr.as_str().starts_with("__") =>
                    {
                        self.expr(at, &call.func)
                    }
                    Expr::Attribute(attribute) => self.expr(at, &attribute.value),
                    callee => self.expr(at, callee),
                };
                let at = self.graph.lookup(at, span(call.range));
                let at = self.exprs(at, &call.args);
                let mut at = at;
                for keyword in &call.keywords {
                    at = self.expr(at, &keyword.value);
                    if keyword.arg.is_none() {
                        at = self.graph.may_throw(at);
                    }
                }
                self.graph.site(at, span(call.range), true)
            }
            Expr::FormattedValue(value) => {
                let at = self.expr(at, &value.value);
                let at = self.exprs(at, value.format_spec.as_deref());
                self.graph.may_throw(at)
            }
            Expr::JoinedStr(joined) => self.exprs(at, &joined.values),
            Expr::Constant(_) | Expr::Name(_) => at,
            Expr::Attribute(attribute) => {
                let at = self.expr(at, &attribute.value);
                if matches!(attribute.value.as_ref(), Expr::Constant(value) if value.value == Constant::None)
                    && !attribute.attr.as_str().starts_with("__")
                {
                    self.graph
                        .abort(at, Exn::named(Symbol::py("AttributeError")))
                } else {
                    self.graph.may_throw(at)
                }
            }
            Expr::Subscript(subscript) => {
                let at = self.expr(at, &subscript.value);
                let at = self.expr(at, &subscript.slice);
                let length = match subscript.value.as_ref() {
                    Expr::List(value)
                        if !value
                            .elts
                            .iter()
                            .any(|element| matches!(element, Expr::Starred(_))) =>
                    {
                        Some(value.elts.len())
                    }
                    Expr::Tuple(value)
                        if !value
                            .elts
                            .iter()
                            .any(|element| matches!(element, Expr::Starred(_))) =>
                    {
                        Some(value.elts.len())
                    }
                    _ => None,
                };
                let out_of_bounds = match (length, subscript.slice.as_ref()) {
                    (Some(length), Expr::Constant(value)) => match &value.value {
                        Constant::Int(index) => {
                            index.to_string().parse::<i64>().map_or(true, |index| {
                                index < -(length as i64) || index >= length as i64
                            })
                        }
                        _ => false,
                    },
                    _ => false,
                };
                if out_of_bounds
                    || matches!(subscript.value.as_ref(), Expr::Constant(value) if matches!(value.value, Constant::None | Constant::Bool(_) | Constant::Int(_) | Constant::Float(_) | Constant::Complex { .. } | Constant::Ellipsis))
                {
                    self.graph.abort(at, Exn::named(Symbol::py("IndexError")))
                } else {
                    self.graph.may_throw(at)
                }
            }
            Expr::Starred(starred) => self.iterable(at, &starred.value),
            Expr::List(list) => self.exprs(at, &list.elts),
            Expr::Tuple(tuple) => self.exprs(at, &tuple.elts),
            Expr::Slice(slice) => {
                let at = self.exprs(at, slice.lower.as_deref());
                let at = self.exprs(at, slice.upper.as_deref());
                self.exprs(at, slice.step.as_deref())
            }
        };
        self.graph.leave();
        end
    }
}
