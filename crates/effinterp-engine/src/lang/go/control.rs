//! A Go callable's effect-directed control flow.
//!
//! Calls are the sites that may run code. A deferred call runs when its
//! function returns, so its site is replayed before every return that follows
//! it; one registered on an optional path is replayed as optional. After a
//! deferred call that may `recover`, any later site may panic into a normal
//! return, which the walker decides at the `defer` statement. A goroutine may
//! never run before the program ends. Function literals are not executed where
//! they are written.

use effinterp_proto::{Boundary, BoundaryClass, BoundaryReason, BoundaryScope, Domain};
use gosyn::ast::{
    BlockStmt, Call, CaseClause, DeclStmt, Element, Expression, File, LiteralValue, Statement,
};
use gosyn::token::{Keyword, Operator};

use crate::control_flow::{
    ControlCaps, ControlExit, ControlFact, Frontier, Graph, Jump, SiteFacts, Span,
};

use super::GO_DOMAINS;
use super::call_resolution::{GO_BUILTINS, GoCallee};
use super::summary::GoFunc;
use super::walk_output::GoWalkOutput;
use super::walker::GoWalker;

pub(super) fn call_span(call: &Call) -> Span {
    (call.pos.0 as u32, call.pos.1 as u32)
}

/// Where the walker decides whether a `defer` may recover a panic.
pub(super) fn defer_span(pos: usize) -> Span {
    (pos as u32, pos as u32)
}

/// Where an executed body's guarantees register at a package entry.
pub(super) fn body_span(body: &BlockStmt) -> Span {
    (body.pos.0 as u32, body.pos.1 as u32)
}

pub(super) fn import_span(import: &gosyn::ast::Import) -> Span {
    (
        import.path.pos as u32,
        (import.path.pos + import.path.value.len()) as u32,
    )
}

/// Running a program: non-standard imports initialize, package variables
/// initialize, then the `init` functions and `main` run in order.
pub(super) fn build_program(
    graph: &mut Graph,
    file: &File,
    imports: &[Span],
    bodies: &[&BlockStmt],
) {
    let mut builder = GoControlFlowBuilder::new(graph);
    for span in imports {
        builder.at = builder.graph.site(builder.at, *span, true);
    }
    for decl in &file.decl {
        if let gosyn::ast::Declaration::Variable(variables) = decl {
            for value in variables.specs.iter().flat_map(|spec| &spec.values) {
                builder.expression(value);
            }
        }
    }
    for body in bodies {
        builder.at = builder.graph.site(builder.at, body_span(body), true);
    }
    builder.graph.exit(builder.at, ControlExit::Success);
}

pub(super) fn build_function(graph: &mut Graph, body: &BlockStmt) {
    let mut builder = GoControlFlowBuilder::new(graph);
    builder.statements(&body.list);
    let at = builder.at;
    builder.leave(at, Jump::Return);
}

struct Deferred {
    span: Span,
    optional: bool,
}

struct GoControlFlowBuilder<'g> {
    graph: &'g mut Graph,
    at: Frontier,
    /// A label waiting for the loop, switch, or select it names.
    label: Option<String>,
    deferred: Vec<Deferred>,
    /// `defer` statements that may recover a panic raised at a later site.
    recovers: Vec<Span>,
    /// The end of a switch clause that falls through into the next one.
    fallthrough: Frontier,
}

fn non_empty_range(expression: &Expression) -> bool {
    match expression {
        Expression::Paren(paren) => non_empty_range(&paren.expr),
        Expression::CompositeLit(literal) => {
            !literal.val.values.is_empty()
                && matches!(
                    &*literal.typ,
                    Expression::TypeArray(_) | Expression::TypeSlice(_)
                )
        }
        Expression::BasicLit(literal) => literal.value.parse::<u64>().is_ok_and(|n| n > 0),
        _ => false,
    }
}

fn always_true(statement: &Statement) -> bool {
    matches!(statement, Statement::Expr(expr)
        if matches!(&expr.expr, Expression::Ident(ident) if ident.name == "true"))
}

impl<'g> GoControlFlowBuilder<'g> {
    fn new(graph: &'g mut Graph) -> Self {
        let at = graph.entry();
        Self {
            graph,
            at,
            label: None,
            deferred: Vec::new(),
            recovers: Vec::new(),
            fallthrough: None,
        }
    }

    /// Leave the function from `at`: deferred calls run, latest first.
    fn leave(&mut self, at: Frontier, jump: Jump) {
        let mut at = at;
        for index in (0..self.deferred.len()).rev() {
            let Deferred { span, optional } = self.deferred[index];
            let run = self.graph.site(at, span, true);
            at = if optional {
                self.graph.join(&[at, run])
            } else {
                run
            };
        }
        self.graph.jump(at, jump);
    }

    fn site(&mut self, span: Span) {
        for recover in self.recovers.clone() {
            self.graph.guard(self.at, recover);
        }
        self.at = self.graph.site(self.at, span, true);
    }

    fn join_with(&mut self, others: Vec<u32>) {
        let mut frontiers = vec![self.at];
        frontiers.extend(others.into_iter().map(Some));
        self.at = self.graph.join(&frontiers);
    }

    /// Run a construct that may be skipped. Calls it defers become optional.
    fn nested(&mut self, run: impl FnOnce(&mut Self)) {
        let deferred = self.deferred.len();
        run(self);
        for entry in &mut self.deferred[deferred..] {
            entry.optional = true;
        }
    }

    fn statements(&mut self, statements: &[Statement]) {
        for statement in statements {
            self.statement(statement);
        }
    }

    fn call(&mut self, call: &Call) {
        self.operands(call);
        self.site(call_span(call));
    }

    /// A call's function value and arguments, evaluated where it stands.
    fn operands(&mut self, call: &Call) {
        match &*call.func {
            Expression::FuncLit(_) => {}
            func => self.expression(func),
        }
        for argument in &call.args {
            self.expression(argument);
        }
    }

    fn expression(&mut self, expression: &Expression) {
        if self.at.is_none() {
            return;
        }
        if !self.graph.enter() {
            self.at = None;
            return;
        }
        match expression {
            Expression::Call(call) => self.call(call),
            Expression::Paren(paren) => self.expression(&paren.expr),
            Expression::Operation(operation) => {
                self.expression(&operation.x);
                if let Some(y) = &operation.y {
                    if matches!(operation.op, Operator::AndAnd | Operator::OrOr) {
                        let start = self.at;
                        self.expression(y);
                        self.at = self.graph.join(&[start, self.at]);
                    } else {
                        self.expression(y);
                    }
                }
            }
            Expression::Star(star) => self.expression(&star.right),
            Expression::Index(index) => {
                self.expression(&index.left);
                self.expression(&index.index);
            }
            Expression::IndexList(index) => {
                self.expression(&index.left);
                for item in &index.indices {
                    self.expression(item);
                }
            }
            Expression::Slice(slice) => {
                self.expression(&slice.left);
                for item in slice.index.iter().flatten() {
                    self.expression(item);
                }
            }
            Expression::Selector(selector) => self.expression(&selector.x),
            Expression::TypeAssert(assert) => self.expression(&assert.left),
            Expression::CompositeLit(literal) => self.literal(&literal.val),
            Expression::List(items) => {
                for item in items {
                    self.expression(item);
                }
            }
            _ => {}
        }
        self.graph.leave();
    }

    fn literal(&mut self, literal: &LiteralValue) {
        if !self.graph.enter() {
            self.at = None;
            return;
        }
        for element in &literal.values {
            for part in element.key.iter().chain([&element.val]) {
                match part {
                    Element::Expr(Expression::FuncLit(_)) => {}
                    Element::Expr(expression) => self.expression(expression),
                    Element::LitValue(inner) => self.literal(inner),
                }
            }
        }
        self.graph.leave();
    }

    fn statement(&mut self, statement: &Statement) {
        if self.at.is_none() {
            return;
        }
        if !self.graph.enter() {
            self.at = None;
            return;
        }
        self.statement_inner(statement);
        self.graph.leave();
    }

    fn statement_inner(&mut self, statement: &Statement) {
        match statement {
            Statement::Expr(expression) => self.expression(&expression.expr),
            Statement::Assign(assign) => {
                for expression in assign.right.iter().chain(&assign.left) {
                    self.expression(expression);
                }
            }
            Statement::Declaration(DeclStmt::Variable(declaration)) => {
                for value in declaration.specs.iter().flat_map(|spec| &spec.values) {
                    self.expression(value);
                }
            }
            Statement::Declaration(DeclStmt::Const(declaration)) => {
                for value in declaration.specs.iter().flat_map(|spec| &spec.values) {
                    self.expression(value);
                }
            }
            Statement::Declaration(DeclStmt::Type(_)) | Statement::Empty(_) => {}
            Statement::IncDec(inc_dec) => self.expression(&inc_dec.expr),
            Statement::Send(send) => {
                self.expression(&send.chan);
                self.expression(&send.value);
            }
            Statement::Return(ret) => {
                for expression in &ret.ret {
                    self.expression(expression);
                }
                let at = self.at;
                self.leave(at, Jump::Return);
                self.at = None;
            }
            Statement::Block(block) => self.statements(&block.list),
            Statement::If(branch) => {
                self.nested(|builder| {
                    if let Some(init) = &branch.init {
                        builder.statement(init);
                    }
                    builder.expression(&branch.cond);
                    let test = builder.at;
                    builder.statements(&branch.body.list);
                    let yes = builder.at;
                    builder.at = test;
                    if let Some(otherwise) = &branch.else_ {
                        builder.statement(otherwise);
                    }
                    builder.at = builder.graph.join(&[yes, builder.at]);
                });
            }
            Statement::For(for_loop) => {
                let label = self.label.take();
                self.nested(|builder| {
                    if let Some(init) = &for_loop.init {
                        builder.statement(init);
                    }
                    builder.defer_in_loop(&for_loop.body);
                    let header = builder.graph.header(builder.at);
                    builder.at = header;
                    if let Some(cond) = &for_loop.cond {
                        builder.statement(cond);
                    }
                    let tested = builder.at;
                    builder.graph.push_loop(label, true);
                    builder.statements(&for_loop.body.list);
                    let (breaks, continues) = builder.graph.pop_loop();
                    builder.join_with(continues);
                    if let Some(post) = &for_loop.post {
                        builder.statement(post);
                    }
                    let back = builder.at;
                    builder.graph.backedge(back, header);
                    builder.at = match &for_loop.cond {
                        Some(cond) if !always_true(cond) => tested,
                        _ => None,
                    };
                    builder.join_with(breaks);
                });
            }
            Statement::Range(range) => {
                let label = self.label.take();
                self.nested(|builder| {
                    builder.expression(&range.expr);
                    builder.defer_in_loop(&range.body);
                    let header = builder.graph.header(builder.at);
                    builder.at = header;
                    builder.graph.push_loop(label, true);
                    builder.statements(&range.body.list);
                    let (breaks, continues) = builder.graph.pop_loop();
                    builder.join_with(continues);
                    let back = builder.at;
                    builder.graph.backedge(back, header);
                    builder.at = if non_empty_range(&range.expr) {
                        back
                    } else {
                        header
                    };
                    builder.join_with(breaks);
                });
            }
            Statement::Label(labeled) => match &*labeled.stmt {
                Statement::For(_)
                | Statement::Range(_)
                | Statement::Switch(_)
                | Statement::TypeSwitch(_)
                | Statement::Select(_) => {
                    self.label = Some(labeled.name.name.clone());
                    self.statement(&labeled.stmt);
                    self.label = None;
                }
                body => {
                    self.graph.push_block(labeled.name.name.clone());
                    self.statement(body);
                    let (breaks, _) = self.graph.pop_loop();
                    self.join_with(breaks);
                }
            },
            Statement::Switch(switch) => {
                let label = self.label.take();
                self.nested(|builder| {
                    if let Some(init) = &switch.init {
                        builder.statement(init);
                    }
                    if let Some(tag) = &switch.tag {
                        builder.expression(tag);
                    }
                    // Case expressions are tried in order until one matches;
                    // `default` runs only once all of them failed.
                    let mut chain = builder.at;
                    let mut entries = Vec::new();
                    for clause in &switch.block.body {
                        let mut matched = Vec::new();
                        for expression in &clause.list {
                            builder.at = chain;
                            builder.expression(expression);
                            chain = builder.at;
                            matched.push(chain);
                        }
                        entries
                            .push((!clause.list.is_empty()).then(|| builder.graph.join(&matched)));
                    }
                    let default = switch
                        .block
                        .body
                        .iter()
                        .any(|clause| clause.list.is_empty());
                    let entries = entries
                        .into_iter()
                        .map(|entry| entry.unwrap_or(chain))
                        .collect();
                    builder.clauses(
                        label,
                        &switch.block.body,
                        entries,
                        (!default).then_some(chain),
                    );
                });
            }
            Statement::TypeSwitch(switch) => {
                let label = self.label.take();
                self.nested(|builder| {
                    if let Some(init) = &switch.init {
                        builder.statement(init);
                    }
                    if let Some(tag) = &switch.tag {
                        builder.statement(tag);
                    }
                    let start = builder.at;
                    let default = switch
                        .block
                        .body
                        .iter()
                        .any(|clause| clause.list.is_empty());
                    let entries = switch.block.body.iter().map(|_| start).collect();
                    builder.clauses(
                        label,
                        &switch.block.body,
                        entries,
                        (!default).then_some(start),
                    );
                });
            }
            Statement::Select(select) => {
                let label = self.label.take();
                self.nested(|builder| {
                    let start = builder.at;
                    builder.graph.push_loop(label, false);
                    let mut ends = Vec::new();
                    // Exactly one clause runs; without clauses select blocks.
                    for clause in &select.body.body {
                        builder.at = start;
                        if let Some(comm) = &clause.comm {
                            builder.statement(comm);
                        }
                        builder.statements(&clause.body);
                        ends.push(builder.at);
                    }
                    let (breaks, _) = builder.graph.pop_loop();
                    builder.at = builder.graph.join(&ends);
                    builder.join_with(breaks);
                });
            }
            Statement::Go(go) => {
                self.operands(&go.call);
                // The goroutine may not run before the program ends; its
                // registered exit still says whether it may end the program.
                let start = self.at;
                self.site(call_span(&go.call));
                self.at = self.graph.join(&[start, self.at]);
            }
            Statement::Defer(defer) => {
                self.operands(&defer.call);
                self.deferred.push(Deferred {
                    span: call_span(&defer.call),
                    optional: false,
                });
                self.recovers.push(defer_span(defer.pos));
            }
            Statement::Branch(branch) => {
                let label = branch.ident.as_ref().map(|ident| ident.name.clone());
                match branch.key {
                    Keyword::Break => self.graph.jump(self.at, Jump::Break(label)),
                    Keyword::Continue => self.graph.jump(self.at, Jump::Continue(label)),
                    Keyword::FallThrough => self.fallthrough = self.at,
                    // Arbitrary jumps are not modeled.
                    _ => self.graph.widen(),
                }
                self.at = None;
            }
        }
    }

    /// Calls deferred in a loop body are pending from the second iteration on,
    /// so a return earlier in the body may already owe them.
    fn defer_in_loop(&mut self, body: &BlockStmt) {
        for statement in &body.list {
            if let Statement::Defer(defer) = statement {
                self.deferred.push(Deferred {
                    span: call_span(&defer.call),
                    optional: true,
                });
                self.recovers.push(defer_span(defer.pos));
            }
        }
        if body.list.iter().any(|statement| {
            !matches!(statement, Statement::Defer(_)) && contains_defer(statement, 0)
        }) {
            self.graph.widen();
        }
    }

    /// Switch clauses entered from `entries`; `skip` continues past the
    /// switch when no clause matched.
    fn clauses(
        &mut self,
        label: Option<String>,
        clauses: &[CaseClause],
        entries: Vec<Frontier>,
        skip: Option<Frontier>,
    ) {
        self.graph.push_loop(label, false);
        let mut ends = Vec::new();
        let mut fell: Frontier = None;
        for (clause, entry) in clauses.iter().zip(entries) {
            self.at = self.graph.join(&[entry, fell]);
            self.fallthrough = None;
            self.statements(&clause.body);
            ends.push(self.at);
            fell = self.fallthrough.take();
        }
        if let Some(skip) = skip {
            ends.push(skip);
        }
        let (breaks, _) = self.graph.pop_loop();
        self.at = self.graph.join(&ends);
        self.join_with(breaks);
    }
}

/// Whether a `defer` sits below `statement` outside any function literal.
fn contains_defer(statement: &Statement, depth: u32) -> bool {
    if depth >= crate::lang::frontend::MAX_WALK_DEPTH {
        return true;
    }
    let block = |block: &BlockStmt| block.list.iter().any(|s| contains_defer(s, depth + 1));
    match statement {
        Statement::Defer(_) => true,
        Statement::Block(inner) => block(inner),
        Statement::If(branch) => {
            block(&branch.body)
                || branch
                    .else_
                    .as_ref()
                    .is_some_and(|otherwise| contains_defer(otherwise, depth + 1))
        }
        Statement::For(for_loop) => block(&for_loop.body),
        Statement::Range(range) => block(&range.body),
        Statement::Label(labeled) => contains_defer(&labeled.stmt, depth + 1),
        Statement::Switch(switch) => switch
            .block
            .body
            .iter()
            .flat_map(|clause| clause.body.iter())
            .any(|s| contains_defer(s, depth + 1)),
        Statement::TypeSwitch(switch) => switch
            .block
            .body
            .iter()
            .flat_map(|clause| clause.body.iter())
            .any(|s| contains_defer(s, depth + 1)),
        Statement::Select(select) => select
            .body
            .body
            .iter()
            .flat_map(|clause| clause.body.iter())
            .any(|s| contains_defer(s, depth + 1)),
        _ => false,
    }
}

/// Whether a function body calls `recover`, which only a deferred call can
/// use to turn a panic into a normal return.
pub(super) fn calls_recover(block: &BlockStmt) -> bool {
    let mut found = false;
    let mut stack: Vec<&Statement> = block.list.iter().collect();
    let mut expressions: Vec<&Expression> = Vec::new();
    let mut budget = 100_000u32;
    while !found && budget > 0 && (!stack.is_empty() || !expressions.is_empty()) {
        budget -= 1;
        if let Some(expression) = expressions.pop() {
            match expression {
                Expression::Call(call) => {
                    if matches!(&*call.func, Expression::Ident(ident) if ident.name == "recover") {
                        found = true;
                    }
                    expressions.push(&call.func);
                    expressions.extend(&call.args);
                }
                Expression::FuncLit(literal) => stack.extend(&literal.body.list),
                Expression::Paren(paren) => expressions.push(&paren.expr),
                Expression::Operation(operation) => {
                    expressions.push(&operation.x);
                    expressions.extend(operation.y.as_deref());
                }
                Expression::Selector(selector) => expressions.push(&selector.x),
                _ => {}
            }
            continue;
        }
        let Some(statement) = stack.pop() else {
            break;
        };
        match statement {
            Statement::Expr(expression) => expressions.push(&expression.expr),
            Statement::Assign(assign) => expressions.extend(&assign.right),
            Statement::Declaration(DeclStmt::Variable(declaration)) => {
                expressions.extend(declaration.specs.iter().flat_map(|spec| &spec.values))
            }
            Statement::Return(ret) => expressions.extend(&ret.ret),
            Statement::Block(inner) => stack.extend(&inner.list),
            Statement::If(branch) => {
                expressions.push(&branch.cond);
                stack.extend(branch.init.as_deref());
                stack.extend(&branch.body.list);
                stack.extend(branch.else_.as_deref());
            }
            Statement::For(for_loop) => stack.extend(&for_loop.body.list),
            Statement::Range(range) => stack.extend(&range.body.list),
            Statement::Label(labeled) => stack.push(&labeled.stmt),
            Statement::Switch(switch) => stack.extend(
                switch
                    .block
                    .body
                    .iter()
                    .flat_map(|clause| clause.body.iter()),
            ),
            Statement::TypeSwitch(switch) => stack.extend(
                switch
                    .block
                    .body
                    .iter()
                    .flat_map(|clause| clause.body.iter()),
            ),
            Statement::Select(select) => stack.extend(
                select
                    .body
                    .body
                    .iter()
                    .flat_map(|clause| clause.body.iter()),
            ),
            Statement::Defer(defer) => expressions.push(&defer.call.func),
            Statement::Go(go) => expressions.push(&go.call.func),
            _ => {}
        }
    }
    // An exhausted scan proves nothing.
    found || budget == 0
}

/// How the frontend evaluated a call, for its control-flow site.
#[derive(Clone, Copy)]
pub(super) enum GoCallControlKind {
    /// A direct interaction whose local reachability is explicitly known.
    Sink,
    /// A modeled or known-inert standard-library call.
    Modeled,
    /// A body this file declares, entered at the call.
    Local,
    /// A call that never returns; `unknown` when it may end the program
    /// successfully.
    Exit,
    /// Code the frontend cannot see.
    Opaque,
}

impl GoWalker<'_, '_> {
    /// How a resolved call behaves at its control-flow site.
    pub(super) fn go_call_control_kind(
        &self,
        callee: &GoCallee,
        func: &Expression,
    ) -> GoCallControlKind {
        match callee {
            GoCallee::Pkg { path, method, .. } => match (path.as_str(), method.as_str()) {
                ("os", "Exit") => GoCallControlKind::Exit,
                (
                    "os",
                    "Remove" | "RemoveAll" | "Getenv" | "LookupEnv" | "Setenv" | "Unsetenv"
                    | "Clearenv",
                ) => GoCallControlKind::Sink,
                ("log", "Fatal" | "Fatalf" | "Fatalln" | "Panic" | "Panicf" | "Panicln")
                | ("runtime", "Goexit") => GoCallControlKind::Exit,
                ("fmt", "Print" | "Println" | "Printf" | "Sprint" | "Sprintln" | "Sprintf") => {
                    GoCallControlKind::Modeled
                }
                _ if matches!(
                    crate::external::classify_go_call(path, method),
                    Some(
                        crate::external::ExternalCall::Inert
                            | crate::external::ExternalCall::Modeled
                    )
                ) =>
                {
                    GoCallControlKind::Modeled
                }
                _ => GoCallControlKind::Opaque,
            },
            GoCallee::Local(_) | GoCallee::Dynamic(_) => GoCallControlKind::Local,
            GoCallee::Method { recv, method } => match self.go_receiver_import_path(recv) {
                Some(path)
                    if crate::external::is_go_stdlib(&path)
                        && matches!(
                            crate::external::classify_go_call(&path, method),
                            Some(
                                crate::external::ExternalCall::Inert
                                    | crate::external::ExternalCall::Modeled
                            )
                        ) =>
                {
                    GoCallControlKind::Modeled
                }
                None if self.go_receiver_method_key(recv, method).is_some() => {
                    GoCallControlKind::Local
                }
                _ => GoCallControlKind::Opaque,
            },
            GoCallee::MaybeSibling(_) => GoCallControlKind::Opaque,
            GoCallee::Unknown => match func {
                Expression::FuncLit(_) => GoCallControlKind::Local,
                Expression::Ident(id)
                    if GO_BUILTINS.contains(&id.name.as_str())
                        && !self.local_vars.contains(&id.name) =>
                {
                    if id.name == "panic" {
                        GoCallControlKind::Exit
                    } else {
                        GoCallControlKind::Modeled
                    }
                }
                _ => GoCallControlKind::Opaque,
            },
        }
    }

    /// What a call establishes at its site. Only a proven sink's own
    /// occurrences or one directly entered body's guarantees count; callbacks
    /// run under the callee's control, so they can only add an unknown exit.
    pub(super) fn go_call_site_facts(
        &self,
        kind: GoCallControlKind,
        applied: Vec<SiteFacts>,
        callbacks: std::ops::Range<usize>,
        entered: usize,
        escaped_callable: bool,
        modeled: std::ops::Range<usize>,
    ) -> SiteFacts {
        let slots = || match &self.out {
            GoWalkOutput::Plan { builder, .. } => builder.control_own_effects(modeled.clone()),
            GoWalkOutput::Capture(_) => modeled
                .clone()
                .map(|slot| ControlFact::Effect(slot as u32))
                .collect(),
        };
        let callback_facts = &applied[callbacks.clone()];
        let direct: Vec<&SiteFacts> = applied[..callbacks.start]
            .iter()
            .chain(&applied[callbacks.end..])
            .collect();
        let mut facts = match (kind, direct.as_slice()) {
            (GoCallControlKind::Sink, []) => SiteFacts::known(slots()),
            (GoCallControlKind::Modeled, []) => SiteFacts::known(Vec::new()),
            (GoCallControlKind::Local, [entered]) => (*entered).clone(),
            (GoCallControlKind::Exit, []) => SiteFacts {
                returns: false,
                ..SiteFacts::known(slots())
            },
            _ => SiteFacts::unknown(),
        };
        if escaped_callable
            || callback_facts.len() != entered
            || callback_facts
                .iter()
                .any(|callback| callback.exit.is_some() || callback.widen)
        {
            facts.exit = Some(ControlExit::Unknown);
        }
        facts
    }

    /// Whether a deferred call may recover a panic into a normal return.
    pub(super) fn deferred_may_recover(&self, call: &gosyn::ast::Call) -> bool {
        let mut target = &*call.func;
        while let Expression::Paren(paren) = target {
            target = &paren.expr;
        }
        let body_recovers =
            |function: Option<&GoFunc>| function.is_none_or(|f| calls_recover(&f.body));
        match target {
            Expression::FuncLit(literal) => calls_recover(&literal.body),
            Expression::Ident(id)
                if GO_BUILTINS.contains(&id.name.as_str())
                    && !self.local_vars.contains(&id.name) =>
            {
                id.name == "recover"
            }
            _ => match self.resolve_go_callee(target) {
                GoCallee::Pkg { path, .. } => !crate::external::is_go_stdlib(&path),
                GoCallee::Local(name) => body_recovers(self.named_go_function(&name)),
                GoCallee::Method { recv, method } => match self.go_receiver_import_path(&recv) {
                    Some(path) => !crate::external::is_go_stdlib(&path),
                    None => match self.go_receiver_method_key(&recv, &method) {
                        Some(key) => body_recovers(self.funcs.get(&key)),
                        None => true,
                    },
                },
                _ => true,
            },
        }
    }

    /// Begin a body's control-flow frame over plan or summary effect slots.
    pub(super) fn control_enter(&mut self, body: &BlockStmt) {
        match &mut self.out {
            GoWalkOutput::Plan { builder, .. } => {
                builder.control_enter(self.source, false, |graph| build_function(graph, body))
            }
            GoWalkOutput::Capture(cap) => {
                let limits = crate::AnalysisLimits::default();
                let (budget, caps) = match &self.analysis_budget {
                    Some((builder, _)) => (Some(builder.budget()), builder.control_caps()),
                    None => (
                        None,
                        ControlCaps {
                            nodes: limits.max_causal_nodes,
                            work: limits.max_causal_pairs,
                        },
                    ),
                };
                cap.control.enter(
                    self.source,
                    true,
                    Default::default(),
                    0,
                    0,
                    budget,
                    caps,
                    |graph| build_function(graph, body),
                );
            }
        }
    }

    /// Finish the body's frame and record what it guarantees to its caller.
    pub(super) fn control_leave(&mut self) {
        let finished = match &mut self.out {
            GoWalkOutput::Plan { builder, .. } => builder.control_leave(),
            GoWalkOutput::Capture(cap) => cap.control.leave(0).inspect(|finished| {
                if let Some(limit) = finished.refused {
                    cap.boundaries.push(Boundary {
                        reason: BoundaryReason::LIMIT_SATURATED,
                        class: BoundaryClass::Limit,
                        scope: BoundaryScope::Invocation,
                        affected_resource: None,
                        callee: None,
                        domains: GO_DOMAINS
                            .iter()
                            .map(|domain| Domain::new(*domain))
                            .collect(),
                        provenance: Vec::new(),
                        limit: Some(limit.to_string()),
                        detail: Some("go summary control flow widened".to_string()),
                    });
                }
                cap.flow = finished.flow.clone();
            }),
        };
        self.control_applications
            .push(finished.map_or_else(SiteFacts::unknown, |finished| {
                SiteFacts::call(&finished.requirements, Some)
            }));
    }

    pub(super) fn control_registered(&self) -> usize {
        match &self.out {
            GoWalkOutput::Plan { builder, .. } => builder.control_registered(),
            GoWalkOutput::Capture(cap) => cap.control.registered(),
        }
    }

    pub(super) fn control_register(&mut self, span: crate::control_flow::Span, facts: SiteFacts) {
        match &mut self.out {
            GoWalkOutput::Plan { builder, .. } => {
                builder.control_site(self.source, false, span, facts)
            }
            GoWalkOutput::Capture(cap) => cap.control.register(self.source, true, span, facts),
        }
    }

    pub(super) fn control_register_since(
        &mut self,
        span: crate::control_flow::Span,
        since: usize,
        facts: SiteFacts,
    ) {
        match &mut self.out {
            GoWalkOutput::Plan { builder, .. } => {
                builder.control_site_since(self.source, false, span, since, facts)
            }
            GoWalkOutput::Capture(cap) => {
                cap.control
                    .register_since(self.source, true, span, since, facts)
            }
        }
    }
}
