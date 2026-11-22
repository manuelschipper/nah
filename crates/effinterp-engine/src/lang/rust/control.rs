//! Effect-directed Rust control flow. Syntax establishes paths; the existing
//! walker supplies facts only for calls whose interaction or callee is proven.

use syn::spanned::Spanned;
use syn::visit::Visit;
use syn::{Block, Expr, Stmt};

use crate::control_flow::{Frontier, Graph, Jump, Span};
use crate::lang::frontend::MAX_WALK_DEPTH;

use super::syntax::child_exprs;

pub(super) fn span(value: &impl Spanned) -> Span {
    let range = value.span().byte_range();
    (range.start as u32, range.end as u32)
}

pub(super) fn build(graph: &mut Graph, body: &Block, opaque_cleanup: bool) {
    let mut builder = RustControlFlowBuilder {
        at: graph.entry(),
        graph,
    };
    if opaque_cleanup {
        builder.graph.unknown(builder.at);
    }
    builder.block(body);
    builder.graph.jump(builder.at, Jump::Return);
}

pub(super) fn build_expr(graph: &mut Graph, expr: &Expr) {
    let mut builder = RustControlFlowBuilder {
        at: graph.entry(),
        graph,
    };
    builder.expr(expr);
    builder.graph.jump(builder.at, Jump::Return);
}

struct RustControlFlowBuilder<'a> {
    at: Frontier,
    graph: &'a mut Graph,
}

impl RustControlFlowBuilder<'_> {
    fn block(&mut self, block: &Block) {
        for statement in &block.stmts {
            match statement {
                Stmt::Expr(expr, _) => self.expr(expr),
                Stmt::Local(local) => {
                    if let Some(init) = &local.init {
                        self.expr(&init.expr);
                        if let Some((_, diverge)) = &init.diverge {
                            let success = self.at;
                            self.expr(diverge);
                            self.at = self.graph.join(&[success, self.at]);
                        }
                    }
                }
                Stmt::Macro(_) => self.graph.widen(),
                Stmt::Item(_) => {}
            }
        }
    }

    fn expr(&mut self, expr: &Expr) {
        if self.at.is_none() || !self.graph.enter() {
            return;
        }
        self.inner(expr);
        self.graph.leave();
    }

    fn inner(&mut self, expr: &Expr) {
        match expr {
            Expr::Closure(_) | Expr::Async(_) | Expr::Const(_) => {}
            Expr::Call(call) => {
                // Evaluating a closure does not run its body. The call site's
                // registered callee facts account for an actual invocation.
                self.expr(&call.func);
                for argument in &call.args {
                    self.expr(argument);
                }
                self.at = self.graph.site(self.at, span(expr), true);
            }
            Expr::MethodCall(call) => {
                self.expr(&call.receiver);
                for argument in &call.args {
                    self.expr(argument);
                }
                self.at = self.graph.site(self.at, span(expr), true);
            }
            Expr::If(branch) => {
                self.expr(&branch.cond);
                let start = self.at;
                self.block(&branch.then_branch);
                let yes = self.at;
                self.at = start;
                if let Some((_, no)) = &branch.else_branch {
                    self.expr(no);
                }
                self.at = self.graph.join(&[yes, self.at]);
            }
            Expr::Binary(binary) if matches!(binary.op, syn::BinOp::And(_) | syn::BinOp::Or(_)) => {
                self.expr(&binary.left);
                let skip = self.at;
                self.expr(&binary.right);
                self.at = self.graph.join(&[skip, self.at]);
            }
            Expr::Return(return_) => {
                if let Some(value) = &return_.expr {
                    self.expr(value);
                }
                self.graph.jump(self.at, Jump::Return);
                self.at = None;
            }
            Expr::Try(try_) => {
                self.expr(&try_.expr);
                // Returning Err/None is normal source completion, so `?` may
                // bypass every later interaction.
                self.graph.jump(self.at, Jump::Return);
            }
            Expr::Break(break_) => {
                if let Some(value) = &break_.expr {
                    self.expr(value);
                }
                self.graph.jump(
                    self.at,
                    Jump::Break(break_.label.as_ref().map(ToString::to_string)),
                );
                self.at = None;
            }
            Expr::Continue(continue_) => {
                self.graph.jump(
                    self.at,
                    Jump::Continue(continue_.label.as_ref().map(ToString::to_string)),
                );
                self.at = None;
            }
            Expr::Loop(loop_) => {
                let header = self.graph.header(self.at);
                self.at = header;
                self.graph
                    .push_loop(loop_.label.as_ref().map(|l| l.name.to_string()), true);
                self.block(&loop_.body);
                let (breaks, continues) = self.graph.pop_loop();
                self.graph.backedge(self.at, header);
                for from in continues {
                    self.graph.backedge(Some(from), header);
                }
                self.at = self
                    .graph
                    .join(&breaks.into_iter().map(Some).collect::<Vec<_>>());
            }
            Expr::While(loop_) => {
                let header = self.graph.header(self.at);
                self.at = header;
                self.expr(&loop_.cond);
                let test = self.at;
                self.graph
                    .push_loop(loop_.label.as_ref().map(|l| l.name.to_string()), true);
                self.block(&loop_.body);
                let (breaks, continues) = self.graph.pop_loop();
                self.graph.backedge(self.at, header);
                for from in continues {
                    self.graph.backedge(Some(from), header);
                }
                let mut exits: Vec<_> = breaks.into_iter().map(Some).collect();
                let mut condition = loop_.cond.as_ref();
                for _ in 0..crate::lang::frontend::MAX_WALK_DEPTH {
                    condition = match condition {
                        Expr::Paren(paren) => &paren.expr,
                        Expr::Group(group) => &group.expr,
                        _ => break,
                    };
                }
                if !matches!(condition, Expr::Lit(lit) if matches!(&lit.lit, syn::Lit::Bool(b) if b.value))
                {
                    exits.push(test);
                }
                self.at = self.graph.join(&exits);
            }
            Expr::ForLoop(loop_) => {
                self.expr(&loop_.expr);
                // Non-array iterators may execute user code at each next().
                let nonempty_array =
                    matches!(loop_.expr.as_ref(), Expr::Array(a) if !a.elems.is_empty());
                if !matches!(loop_.expr.as_ref(), Expr::Array(_)) {
                    self.graph.unknown(self.at);
                }
                let start = self.at;
                let header = self.graph.header(start);
                self.at = header;
                self.graph
                    .push_loop(loop_.label.as_ref().map(|l| l.name.to_string()), true);
                self.block(&loop_.body);
                let (breaks, continues) = self.graph.pop_loop();
                let mut exits = vec![self.at];
                exits.extend(breaks.into_iter().map(Some));
                for from in continues {
                    self.graph.backedge(Some(from), header);
                    exits.push(Some(from));
                }
                self.graph.backedge(self.at, header);
                if !nonempty_array {
                    exits.push(start);
                }
                self.at = self.graph.join(&exits);
            }
            Expr::Match(match_) => {
                self.expr(&match_.expr);
                let start = self.at;
                let mut exits = Vec::new();
                for arm in &match_.arms {
                    self.at = start;
                    if let Some((_, guard)) = &arm.guard {
                        self.expr(guard);
                    }
                    self.expr(&arm.body);
                    exits.push(self.at);
                }
                self.at = self.graph.join(&exits);
            }
            Expr::Block(block) => {
                if let Some(label) = &block.label {
                    self.graph.push_block(label.name.to_string());
                    self.block(&block.block);
                    let (breaks, _) = self.graph.pop_loop();
                    let mut exits = vec![self.at];
                    exits.extend(breaks.into_iter().map(Some));
                    self.at = self.graph.join(&exits);
                } else {
                    self.block(&block.block);
                }
            }
            Expr::Await(await_) => {
                self.expr(&await_.base);
                self.at = self.graph.site(self.at, span(expr), true);
            }
            Expr::Unsafe(unsafe_) => {
                self.graph.unknown(self.at);
                self.block(&unsafe_.block);
            }
            Expr::TryBlock(_) | Expr::Verbatim(_) | Expr::Macro(_) => self.graph.widen(),
            _ => {
                for child in child_exprs(expr) {
                    self.expr(child);
                }
            }
        }
    }
}

/// Treat a Rust Drop impl anywhere in the file as opaque cleanup.
pub(super) fn has_drop_impl(file: &syn::File) -> bool {
    struct DropImpl(bool);
    impl<'ast> Visit<'ast> for DropImpl {
        fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
            self.0 |= item.trait_.as_ref().is_some_and(|(_, path, _)| {
                path.segments
                    .last()
                    .is_some_and(|segment| segment.ident == "Drop")
            });
            syn::visit::visit_item_impl(self, item);
        }
    }
    let mut visitor = DropImpl(false);
    visitor.visit_file(file);
    visitor.0
}

/// Collect Rust guard regions using the source bytes shared by all function scopes.
pub(super) fn rust_guard_regions(file: &syn::File, source: &str) -> crate::guards::GuardRegions {
    use effinterp_proto::{ByteSpan, ConditionKind};
    use syn::visit::Visit;
    fn span(value: impl Spanned) -> ByteSpan {
        let r = value.span().byte_range();
        ByteSpan {
            start: r.start as u32,
            end: r.end as u32,
        }
    }
    struct RustGuardRegionCollector<'a> {
        depth: usize,
        source: &'a str,
        guards: crate::guards::GuardRegions,
    }
    impl<'ast> Visit<'ast> for RustGuardRegionCollector<'_> {
        fn visit_block(&mut self, block: &'ast Block) {
            let stops = |body: &Block| {
                matches!(
                    body.stmts.last(),
                    Some(Stmt::Expr(
                        Expr::Return(_) | Expr::Break(_) | Expr::Continue(_),
                        _
                    ))
                )
            };
            for stmt in &block.stmts {
                if let Stmt::Expr(Expr::If(branch), _) = stmt {
                    let yes = stops(&branch.then_branch);
                    let no = branch
                        .else_branch
                        .as_ref()
                        .is_some_and(|(_, e)| match e.as_ref() {
                            Expr::Block(b) => stops(&b.block),
                            Expr::Return(_) => true,
                            _ => false,
                        });
                    if yes != no {
                        self.guards.add(
                            self.source,
                            span(branch),
                            ByteSpan {
                                start: span(branch).end,
                                end: span(block).end,
                            },
                            ConditionKind::Branch,
                            u32::from(yes),
                            2,
                            true,
                        );
                    }
                }
            }
            syn::visit::visit_block(self, block);
        }
        fn visit_expr(&mut self, expr: &'ast Expr) {
            if self.depth >= MAX_WALK_DEPTH as usize {
                self.guards.widen();
                return;
            }
            self.depth += 1;
            let origin = span(expr);
            match expr {
                Expr::If(i) => {
                    self.guards.add(
                        self.source,
                        origin,
                        span(&i.then_branch),
                        ConditionKind::Branch,
                        0,
                        2,
                        true,
                    );
                    if let Some((_, other)) = &i.else_branch {
                        self.guards.add(
                            self.source,
                            origin,
                            span(other),
                            ConditionKind::Branch,
                            1,
                            2,
                            true,
                        );
                    }
                }
                Expr::Closure(i) => self.guards.add(
                    self.source,
                    origin,
                    span(&i.body),
                    ConditionKind::Dispatch,
                    0,
                    2,
                    false,
                ),
                Expr::While(i) => self.guards.add(
                    self.source,
                    origin,
                    span(&i.body),
                    ConditionKind::Loop,
                    0,
                    2,
                    false,
                ),
                Expr::ForLoop(i) => self.guards.add(
                    self.source,
                    origin,
                    span(&i.body),
                    ConditionKind::Loop,
                    0,
                    2,
                    false,
                ),
                Expr::Match(i) => {
                    for (arm, body) in i.arms.iter().enumerate() {
                        self.guards.add(
                            self.source,
                            origin,
                            span(&body.body),
                            ConditionKind::Branch,
                            arm as u32,
                            i.arms.len() as u32
                                + u32::from(!i.arms.iter().any(|arm| {
                                    arm.guard.is_none() && matches!(arm.pat, syn::Pat::Wild(_))
                                })),
                            false,
                        );
                    }
                }
                Expr::Binary(i) if matches!(i.op, syn::BinOp::And(_) | syn::BinOp::Or(_)) => {
                    self.guards.add(
                        self.source,
                        origin,
                        span(&i.right),
                        ConditionKind::ShortCircuit,
                        u32::from(matches!(i.op, syn::BinOp::Or(_))),
                        2,
                        true,
                    )
                }
                _ => (),
            }
            syn::visit::visit_expr(self, expr);
            self.depth -= 1;
        }
    }
    let mut collector = RustGuardRegionCollector {
        depth: 0,
        source,
        guards: Default::default(),
    };
    collector.visit_file(file);
    collector.guards
}
