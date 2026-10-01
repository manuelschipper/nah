//! A Ruby body's effect-directed control flow.
//!
//! Method sends, safe-navigation sends, `super`, `yield`, and backtick
//! commands are the sites that may run code; `ENV` reads and writes are
//! modeled sites that run none. A block runs zero or more times inside the
//! send it is passed to. A `rescue` clause is entered from the start of its
//! body because anything inside may raise. Method definitions and `proc` or
//! `lambda` bodies are not executed where they are written.

use lib_ruby_parser::Node;
use lib_ruby_parser::nodes::Send;

use crate::control_flow::{Catch, ControlCaps, Exn, Frontier, Graph, Jump, Span, Symbol};

use super::model::assigned_proc;

pub(super) fn span(node: &Node) -> Span {
    let loc = node.expression();
    (loc.begin as u32, loc.end as u32)
}

pub(super) fn send_span(send: &Send) -> Span {
    (send.expression_l.begin as u32, send.expression_l.end as u32)
}

/// Bounds for a summary graph built without a live plan.
pub(super) fn summary_caps() -> ControlCaps {
    let limits = crate::limits::AnalysisLimits::default();
    ControlCaps {
        nodes: limits.max_causal_nodes,
        work: limits.max_causal_pairs,
    }
}

pub(super) fn build(graph: &mut Graph, statements: &[&Node], builtin_names: bool) {
    graph.enable_exceptions();
    let mut builder = Builder {
        at: graph.entry(),
        graph,
        builtin_names,
    };
    for statement in statements {
        builder.node(statement);
    }
    builder.graph.jump(builder.at, Jump::Return);
}

struct Builder<'g> {
    graph: &'g mut Graph,
    at: Frontier,
    builtin_names: bool,
}

/// A block passed to `proc` or `lambda` is stored, not run.
fn deferred_block(call: &Node) -> bool {
    match call {
        Node::Lambda(_) => true,
        Node::Send(send) => {
            send.recv.is_none() && matches!(send.method_name.as_str(), "proc" | "lambda")
        }
        _ => false,
    }
}

fn is_loop_send(call: &Node) -> bool {
    matches!(call, Node::Send(send) if send.recv.is_none() && send.method_name == "loop")
}

pub(super) fn constant_truth(node: &Node) -> Option<bool> {
    match node {
        Node::True(_) => Some(true),
        Node::False(_) | Node::Nil(_) => Some(false),
        Node::Begin(begin) if begin.statements.len() == 1 => constant_truth(&begin.statements[0]),
        _ => None,
    }
}

impl Builder<'_> {
    fn nodes<'n>(&mut self, nodes: impl IntoIterator<Item = &'n Node>) {
        for node in nodes {
            self.node(node);
        }
    }

    fn optional_node(&mut self, node: &Option<Box<Node>>) {
        if let Some(node) = node {
            self.node(node);
        }
    }

    fn site(&mut self, span: Span, opaque: bool) {
        self.at = self.graph.site(self.at, span, opaque);
    }

    fn join_with(&mut self, others: Vec<u32>) {
        let mut frontiers = vec![self.at];
        frontiers.extend(others.into_iter().map(Some));
        self.at = self.graph.join(&frontiers);
    }

    fn optional(&mut self, run: impl FnOnce(&mut Self)) {
        let start = self.at;
        run(self);
        self.at = self.graph.join(&[start, self.at]);
    }

    fn branches(&mut self, yes: &Option<Box<Node>>, no: &Option<Box<Node>>) {
        let test = self.at;
        self.optional_node(yes);
        let taken = self.at;
        self.at = test;
        self.optional_node(no);
        self.at = self.graph.join(&[taken, self.at]);
    }

    /// A loop body that `break` leaves and `next` continues.
    fn body(&mut self, body: Option<&Node>) -> (Vec<u32>, Vec<u32>) {
        self.graph.push_loop(None, true);
        if let Some(body) = body {
            self.node(body);
        }
        self.graph.pop_loop()
    }

    fn call_operands(&mut self, call: &Node) {
        match call {
            Node::Send(send) => {
                if let Some(recv) = &send.recv {
                    self.node(recv);
                }
                self.nodes(&send.args);
            }
            Node::CSend(send) => {
                self.node(&send.recv);
                self.nodes(&send.args);
            }
            Node::Super(call) => self.nodes(&call.args),
            _ => {}
        }
    }

    /// A send with a literal block: the block runs zero or more times while
    /// the send runs.
    fn block(&mut self, call: &Node, body: Option<&Node>) {
        if deferred_block(call) {
            return;
        }
        if is_loop_send(call) {
            // `loop` ends on `break`, or when its body raises StopIteration.
            let header = self.graph.header(self.at);
            self.at = header;
            let (breaks, continues) = self.body(body);
            self.join_with(continues);
            let back = self.at;
            self.graph.backedge(back, header);
            self.at = header;
            self.join_with(breaks);
            self.site(span(call), true);
            return;
        }
        let safe = matches!(call, Node::CSend(_));
        if let Node::CSend(send) = call {
            self.node(&send.recv);
        }
        let start = self.at;
        if safe {
            self.nodes(match call {
                Node::CSend(send) => send.args.as_slice(),
                _ => &[],
            });
        } else {
            self.call_operands(call);
        }
        let header = self.graph.header(self.at);
        self.at = header;
        let (breaks, continues) = self.body(body);
        self.join_with(continues);
        let back = self.at;
        self.graph.backedge(back, header);
        self.at = header;
        self.site(span(call), true);
        self.join_with(breaks);
        if safe {
            self.at = self.graph.join(&[start, self.at]);
        }
    }

    fn node(&mut self, node: &Node) {
        if self.at.is_none() {
            return;
        }
        if !self.graph.enter() {
            self.at = None;
            return;
        }
        self.node_inner(node);
        self.graph.leave();
    }

    fn node_inner(&mut self, node: &Node) {
        match node {
            Node::Begin(begin) => self.nodes(&begin.statements),
            Node::KwBegin(begin) => self.nodes(&begin.statements),
            Node::Send(send) => {
                self.call_operands(node);
                self.site(send_span(send), true);
            }
            Node::CSend(send) => {
                self.node(&send.recv);
                self.optional(|builder| {
                    builder.nodes(&send.args);
                    builder.site(span(node), true);
                });
            }
            Node::Super(call) => {
                self.nodes(&call.args);
                self.site(span(node), true);
            }
            Node::ZSuper(_) => self.site(span(node), true),
            Node::Yield(call) => {
                self.nodes(&call.args);
                self.site(span(node), true);
            }
            Node::Block(block) => self.block(&block.call, block.body.as_deref()),
            Node::Numblock(block) => self.block(&block.call, Some(&block.body)),
            Node::Lambda(_) | Node::Def(_) | Node::Defs(_) => {}
            Node::If(branch) => {
                self.node(&branch.cond);
                self.branches(&branch.if_true, &branch.if_false);
            }
            Node::IfMod(branch) => {
                self.node(&branch.cond);
                self.branches(&branch.if_true, &branch.if_false);
            }
            Node::IfTernary(branch) => {
                self.node(&branch.cond);
                let test = self.at;
                self.node(&branch.if_true);
                let taken = self.at;
                self.at = test;
                self.node(&branch.if_false);
                self.at = self.graph.join(&[taken, self.at]);
            }
            Node::And(and) => {
                self.node(&and.lhs);
                self.optional(|builder| builder.node(&and.rhs));
            }
            Node::Or(or) => {
                self.node(&or.lhs);
                self.optional(|builder| builder.node(&or.rhs));
            }
            Node::OrAsgn(assign) => {
                self.node(&assign.recv);
                self.optional(|builder| builder.node(&assign.value));
            }
            Node::AndAsgn(assign) => {
                self.node(&assign.recv);
                self.optional(|builder| builder.node(&assign.value));
            }
            Node::OpAsgn(assign) => {
                self.node(&assign.recv);
                self.node(&assign.value);
            }
            Node::While(repeat) => {
                self.repeat(&repeat.cond, repeat.body.as_deref(), true);
            }
            Node::Until(repeat) => {
                self.repeat(&repeat.cond, repeat.body.as_deref(), false);
            }
            Node::WhilePost(repeat) => self.repeat_post(&repeat.cond, &repeat.body),
            Node::UntilPost(repeat) => self.repeat_post(&repeat.cond, &repeat.body),
            Node::For(repeat) => {
                self.node(&repeat.iteratee);
                let header = self.graph.header(self.at);
                self.at = header;
                let (breaks, continues) = self.body(repeat.body.as_deref());
                self.join_with(continues);
                let back = self.at;
                self.graph.backedge(back, header);
                self.at = match &*repeat.iteratee {
                    Node::Array(array) if !array.elements.is_empty() => back,
                    _ => header,
                };
                self.join_with(breaks);
            }
            Node::Case(case) => {
                self.optional_node(&case.expr);
                let mut chain = self.at;
                let mut ends = Vec::new();
                for when in &case.when_bodies {
                    let Node::When(when) = when else {
                        continue;
                    };
                    let mut matched = Vec::new();
                    for pattern in &when.patterns {
                        self.at = chain;
                        self.node(pattern);
                        chain = self.at;
                        matched.push(chain);
                    }
                    self.at = self.graph.join(&matched);
                    self.optional_node(&when.body);
                    ends.push(self.at);
                }
                self.at = chain;
                self.optional_node(&case.else_body);
                ends.push(self.at);
                self.at = self.graph.join(&ends);
            }
            Node::CaseMatch(case) => {
                self.node(&case.expr);
                let start = self.at;
                let mut ends = Vec::new();
                for branch in &case.in_bodies {
                    self.at = start;
                    if let Node::InPattern(branch) = branch {
                        self.optional_node(&branch.guard);
                        self.optional_node(&branch.body);
                    }
                    ends.push(self.at);
                }
                // Without `else`, an unmatched value raises.
                if let Some(otherwise) = &case.else_body {
                    self.at = start;
                    self.node(otherwise);
                    ends.push(self.at);
                }
                self.at = self.graph.join(&ends);
            }
            Node::Rescue(rescue) => {
                self.graph.push_catch();
                self.optional_node(&rescue.body);
                let thrown = self.graph.pop_catch();
                self.graph.rethrow(&thrown);
                self.optional_node(&rescue.else_);
                let mut ends = vec![self.at];
                for handler in &rescue.rescue_bodies {
                    let catch = match handler {
                        Node::RescueBody(body) if self.builtin_names => {
                            ruby_catch(body.exc_list.as_deref())
                        }
                        _ => Catch::Unknown,
                    };
                    self.at = self.graph.catch_handler(&thrown, catch);
                    if let Node::RescueBody(handler) = handler {
                        self.optional_node(&handler.exc_list);
                        self.optional_node(&handler.body);
                    }
                    ends.push(self.at);
                }
                self.at = self.graph.join(&ends);
            }
            Node::Ensure(ensure) => {
                self.graph.push_cleanup();
                self.optional_node(&ensure.body);
                let normal = self.at;
                let (abrupt, pending): (Vec<_>, Vec<_>) = self
                    .graph
                    .pop_cleanup()
                    .into_iter()
                    .partition(|(_, jump)| *jump == Jump::Throw);
                self.join_with(pending.iter().map(|(from, _)| *from).collect());
                self.optional_node(&ensure.ensure);
                let end = self.at;
                self.graph.resume(end, pending);
                self.at = self.graph.join(
                    &abrupt
                        .iter()
                        .map(|(from, _)| Some(*from))
                        .collect::<Vec<_>>(),
                );
                self.optional_node(&ensure.ensure);
                self.graph.resume(self.at, abrupt);
                self.at = normal.and(end);
            }
            Node::Return(jump) => {
                self.nodes(&jump.args);
                self.graph.jump(self.at, Jump::Return);
                self.at = None;
            }
            Node::Break(jump) => {
                self.nodes(&jump.args);
                self.graph.jump(self.at, Jump::Break(None));
                self.at = None;
            }
            Node::Next(jump) => {
                self.nodes(&jump.args);
                self.graph.jump(self.at, Jump::Continue(None));
                self.at = None;
            }
            Node::Retry(_) | Node::Redo(_) => {
                self.graph.widen();
                self.at = None;
            }
            Node::Class(class) => {
                self.optional_node(&class.superclass);
                self.optional_node(&class.body);
            }
            Node::Module(module) => self.optional_node(&module.body),
            Node::SClass(class) => {
                self.node(&class.expr);
                self.optional_node(&class.body);
            }
            Node::Lvasgn(assign) => {
                if assigned_proc(node).is_none() {
                    self.optional_node(&assign.value);
                }
            }
            Node::Ivasgn(assign) => self.optional_node(&assign.value),
            Node::Gvasgn(assign) => self.optional_node(&assign.value),
            Node::Cvasgn(assign) => self.optional_node(&assign.value),
            Node::Casgn(assign) => self.optional_node(&assign.value),
            Node::Masgn(assign) => self.node(&assign.rhs),
            Node::Xstr(command) => {
                self.nodes(&command.parts);
                self.site(span(node), true);
            }
            Node::XHeredoc(command) => {
                self.nodes(&command.parts);
                self.site(span(node), true);
            }
            Node::Dstr(string) => self.nodes(&string.parts),
            Node::Heredoc(string) => self.nodes(&string.parts),
            Node::Regexp(regexp) => self.nodes(&regexp.parts),
            Node::Array(array) => self.nodes(&array.elements),
            Node::Hash(hash) => self.nodes(&hash.pairs),
            Node::Kwargs(hash) => self.nodes(&hash.pairs),
            Node::Pair(pair) => {
                self.node(&pair.key);
                self.node(&pair.value);
            }
            Node::Splat(splat) => self.optional_node(&splat.value),
            Node::Kwsplat(splat) => self.node(&splat.value),
            Node::BlockPass(pass) => self.optional_node(&pass.value),
            Node::Index(index) => {
                self.node(&index.recv);
                self.nodes(&index.indexes);
                self.site(span(node), true);
            }
            Node::IndexAsgn(index) => {
                self.node(&index.recv);
                self.nodes(&index.indexes);
                self.optional_node(&index.value);
                self.site(span(node), true);
            }
            Node::Irange(range) => {
                self.optional_node(&range.left);
                self.optional_node(&range.right);
            }
            Node::Erange(range) => {
                self.optional_node(&range.left);
                self.optional_node(&range.right);
            }
            _ => {}
        }
    }

    /// `while`/`until` with the test before each iteration.
    fn repeat(&mut self, cond: &Node, body: Option<&Node>, while_true: bool) {
        let header = self.graph.header(self.at);
        self.at = header;
        self.node(cond);
        let tested = self.at;
        let (breaks, continues) = self.body(body);
        self.join_with(continues);
        let back = self.at;
        self.graph.backedge(back, header);
        self.at = if constant_truth(cond) == Some(while_true) {
            None
        } else {
            tested
        };
        self.join_with(breaks);
    }

    /// `begin ... end while` runs its body before the first test.
    fn repeat_post(&mut self, cond: &Node, body: &Node) {
        let header = self.graph.header(self.at);
        self.at = header;
        let (breaks, continues) = self.body(Some(body));
        self.join_with(continues);
        self.node(cond);
        let tested = self.at;
        self.graph.backedge(tested, header);
        self.join_with(breaks);
    }
}

const RB_EXCEPTIONS: &[&str] = &[
    "Exception",
    "StandardError",
    "RuntimeError",
    "ArgumentError",
];

fn ruby_symbol(name: &str) -> Option<Symbol> {
    RB_EXCEPTIONS.contains(&name).then(|| Symbol::rb(name))
}

fn const_symbol(node: &Node) -> Option<Symbol> {
    match node {
        Node::Const(constant)
            if constant.scope.is_none()
                || matches!(constant.scope.as_deref(), Some(Node::Cbase(_))) =>
        {
            ruby_symbol(&constant.name)
        }
        _ => None,
    }
}

fn ruby_catch(exc_list: Option<&Node>) -> Catch {
    match exc_list {
        None => Catch::named(Symbol::rb("StandardError")),
        Some(Node::Array(array)) => {
            let mut names = Vec::new();
            for element in &array.elements {
                match const_symbol(element) {
                    Some(symbol) => names.push(symbol),
                    None => return Catch::Unknown,
                }
            }
            Catch::names(names)
        }
        Some(node) => match const_symbol(node) {
            Some(symbol) => Catch::named(symbol),
            None => Catch::Unknown,
        },
    }
}

pub(super) fn raise_exn(send: &Send, builtin_names: bool) -> Exn {
    if send.recv.is_some() {
        return Exn::Unknown;
    }
    match send.args.first() {
        // A bare raise can rethrow the active exception.
        None => Exn::Unknown,
        Some(Node::Str(_) | Node::Dstr(_) | Node::Heredoc(_)) => {
            Exn::named(Symbol::rb("RuntimeError"))
        }
        Some(node) if builtin_names => match const_symbol(node) {
            Some(symbol) => Exn::named(symbol),
            None => Exn::Unknown,
        },
        _ => Exn::Unknown,
    }
}

pub(super) fn exits(send: &Send) -> bool {
    send.recv.is_none()
        && matches!(
            send.method_name.as_str(),
            "exit" | "exit!" | "abort" | "raise" | "fail" | "throw"
        )
}
