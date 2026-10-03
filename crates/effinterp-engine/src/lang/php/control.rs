//! A PHP body's effect-directed control flow.
//!
//! Calls, method calls, constructions, backtick commands, and includes are
//! the sites that may run code; assignments and subscripts are modeled sites
//! that run none. Each operation that may raise adds a may-throw edge, and a
//! `throw` adds one carrying its thrown type; a `catch` is entered from the
//! frontiers its `try` body threw that its caught types can match.
//! Declarations and closure literals are not executed where they are written.

use tree_sitter::Node;

use crate::control_flow::{Catch, Exn, Frontier, Graph, Jump, Span, Symbol};

pub(super) fn span(node: Node) -> Span {
    (node.start_byte() as u32, node.end_byte() as u32)
}

pub(super) fn build(graph: &mut Graph, statements: &[Node], source: &str) {
    graph.enable_exceptions();
    let mut builder = PhpControlFlowBuilder {
        at: graph.entry(),
        graph,
        source,
    };
    for statement in statements {
        builder.node(*statement);
    }
    builder.graph.jump(builder.at, Jump::Return);
}

struct PhpControlFlowBuilder<'g, 's> {
    graph: &'g mut Graph,
    at: Frontier,
    source: &'s str,
}

fn named_children(node: Node) -> Vec<Node> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).collect()
}

fn literal_true(node: Node) -> bool {
    let mut node = node;
    while node.kind() == "parenthesized_expression" {
        match node.named_child(0) {
            Some(inner) => node = inner,
            None => return false,
        }
    }
    node.kind() == "boolean" && node.start_byte() + 4 == node.end_byte()
}

impl PhpControlFlowBuilder<'_, '_> {
    fn site(&mut self, node: Node, opaque: bool) {
        self.at = self.graph.site(self.at, span(node), opaque);
    }

    fn children(&mut self, node: Node) {
        for child in named_children(node) {
            self.node(child);
        }
    }

    fn field(&mut self, node: Node, name: &str) {
        if let Some(child) = node.child_by_field_name(name) {
            self.node(child);
        }
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

    fn loop_body(&mut self, body: Option<Node>) -> (Vec<u32>, Vec<u32>) {
        self.graph.push_loop(None, true);
        if let Some(body) = body {
            self.node(body);
        }
        self.graph.pop_loop()
    }

    /// A jump that names how many enclosing loops it leaves; only one level
    /// is modeled.
    fn level_jump(&mut self, node: Node, jump: Jump) {
        if named_children(node).is_empty() {
            self.graph.jump(self.at, jump);
        } else {
            self.graph.widen();
        }
        self.at = None;
    }

    fn node(&mut self, node: Node) {
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

    fn node_inner(&mut self, node: Node) {
        match node.kind() {
            "function_definition"
            | "method_declaration"
            | "class_declaration"
            | "interface_declaration"
            | "trait_declaration"
            | "enum_declaration"
            | "anonymous_function"
            | "arrow_function" => {}
            "function_call_expression"
            | "member_call_expression"
            | "scoped_call_expression"
            | "object_creation_expression"
            | "shell_command_expression" => {
                self.children(node);
                self.site(node, true);
            }
            "nullsafe_member_call_expression" => {
                self.field(node, "object");
                self.optional(|builder| {
                    builder.field(node, "arguments");
                    builder.site(node, true);
                });
            }
            "require_expression"
            | "include_expression"
            | "require_once_expression"
            | "include_once_expression" => self.site(node, true),
            "subscript_expression"
            | "member_access_expression"
            | "nullsafe_member_access_expression"
            | "unary_op_expression" => {
                self.children(node);
                self.site(node, false);
                self.at = self.graph.may_throw(self.at);
            }
            "augmented_assignment_expression" => {
                self.children(node);
                self.site(node, false);
                self.at = self.graph.may_throw(self.at);
            }
            "assignment_expression" => {
                self.children(node);
                self.site(node, false);
            }
            "binary_expression" => {
                self.field(node, "left");
                let short_circuit = node
                    .child_by_field_name("operator")
                    .is_some_and(|op| matches!(op.kind(), "&&" | "||" | "and" | "or" | "??"));
                if short_circuit {
                    self.optional(|builder| builder.field(node, "right"));
                } else {
                    self.field(node, "right");
                }
                if node
                    .child_by_field_name("operator")
                    .is_some_and(|op| matches!(op.kind(), "/" | "%"))
                    || !["left", "right"].iter().all(|field| {
                        node.child_by_field_name(field)
                            .is_some_and(|value| matches!(value.kind(), "integer" | "float"))
                    })
                {
                    self.at = self.graph.may_throw(self.at);
                }
            }
            "conditional_expression" => {
                self.field(node, "condition");
                let test = self.at;
                self.field(node, "body");
                let taken = self.at;
                self.at = test;
                self.field(node, "alternative");
                self.at = self.graph.join(&[taken, self.at]);
            }
            "match_expression" => {
                self.field(node, "condition");
                self.at = self.graph.may_throw(self.at);
                let start = self.at;
                let mut ends = Vec::new();
                if let Some(block) = node.child_by_field_name("body") {
                    for arm in named_children(block) {
                        self.at = start;
                        self.children(arm);
                        ends.push(self.at);
                    }
                }
                // An unmatched value throws.
                self.at = self.graph.join(&ends);
            }
            "if_statement" => {
                self.field(node, "condition");
                let mut test = self.at;
                self.field(node, "body");
                let mut ends = vec![self.at];
                let mut cursor = node.walk();
                let alternatives: Vec<Node> = node
                    .children_by_field_name("alternative", &mut cursor)
                    .collect();
                for alternative in alternatives {
                    self.at = test;
                    if alternative.kind() == "else_if_clause" {
                        self.field(alternative, "condition");
                        test = self.at;
                    } else {
                        test = None;
                    }
                    self.field(alternative, "body");
                    ends.push(self.at);
                }
                ends.push(test);
                self.at = self.graph.join(&ends);
            }
            "while_statement" => {
                let header = self.graph.header(self.at);
                self.at = header;
                self.field(node, "condition");
                let tested = self.at;
                let (breaks, continues) = self.loop_body(node.child_by_field_name("body"));
                self.join_with(continues);
                let back = self.at;
                self.graph.backedge(back, header);
                self.at = match node.child_by_field_name("condition") {
                    Some(condition) if literal_true(condition) => None,
                    _ => tested,
                };
                self.join_with(breaks);
            }
            "do_statement" => {
                let header = self.graph.header(self.at);
                self.at = header;
                let (breaks, continues) = self.loop_body(node.child_by_field_name("body"));
                self.join_with(continues);
                self.field(node, "condition");
                let tested = self.at;
                self.graph.backedge(tested, header);
                self.at = match node.child_by_field_name("condition") {
                    Some(condition) if literal_true(condition) => None,
                    _ => tested,
                };
                self.join_with(breaks);
            }
            "for_statement" => {
                self.field(node, "initialize");
                let header = self.graph.header(self.at);
                self.at = header;
                self.field(node, "condition");
                let tested = self.at;
                let (breaks, continues) = self.loop_body(node.child_by_field_name("body"));
                self.join_with(continues);
                self.field(node, "update");
                let back = self.at;
                self.graph.backedge(back, header);
                self.at = node.child_by_field_name("condition").and(tested);
                self.join_with(breaks);
            }
            "foreach_statement" => {
                let body = node.child_by_field_name("body");
                let iterated = named_children(node)
                    .into_iter()
                    .find(|child| Some(*child) != body);
                if let Some(iterated) = iterated {
                    self.node(iterated);
                }
                let header = self.graph.header(self.at);
                self.at = header;
                let (breaks, continues) = self.loop_body(body);
                self.join_with(continues);
                let back = self.at;
                self.graph.backedge(back, header);
                let non_empty = iterated.is_some_and(|iterated| {
                    iterated.kind() == "array_creation_expression"
                        && iterated.named_child_count() > 0
                });
                self.at = if non_empty { back } else { header };
                self.join_with(breaks);
            }
            "switch_statement" => {
                self.field(node, "condition");
                let discriminant = self.at;
                self.graph.push_loop(None, true);
                let mut chain = discriminant;
                let mut previous = None;
                let mut default = false;
                if let Some(block) = node.child_by_field_name("body") {
                    for case in named_children(block) {
                        let entry = if case.kind() == "default_statement" {
                            default = true;
                            discriminant
                        } else {
                            self.at = chain;
                            self.field(case, "value");
                            chain = self.at;
                            chain
                        };
                        self.at = self.graph.join(&[entry, previous]);
                        for statement in named_children(case) {
                            if Some(statement) != case.child_by_field_name("value") {
                                self.node(statement);
                            }
                        }
                        previous = self.at;
                    }
                }
                let (breaks, continues) = self.graph.pop_loop();
                self.at = self
                    .graph
                    .join(&[previous, if default { None } else { chain }]);
                self.join_with(breaks);
                self.join_with(continues);
            }
            "try_statement" => {
                let clauses = named_children(node);
                let finally = clauses
                    .iter()
                    .find(|clause| clause.kind() == "finally_clause")
                    .copied();
                if finally.is_some() {
                    self.graph.push_cleanup();
                }
                let catches = clauses.iter().any(|clause| clause.kind() == "catch_clause");
                if catches {
                    self.graph.push_catch();
                }
                self.field(node, "body");
                let mut ends = vec![self.at];
                let thrown = if catches {
                    self.graph.pop_catch()
                } else {
                    Vec::new()
                };
                self.graph.rethrow(&thrown);
                for clause in clauses
                    .iter()
                    .filter(|clause| clause.kind() == "catch_clause")
                {
                    let catch = php_catch(*clause, self.source, self.graph);
                    self.at = self.graph.catch_handler(&thrown, catch);
                    self.field(*clause, "body");
                    ends.push(self.at);
                }
                let normal = self.graph.join(&ends);
                let Some(finally) = finally else {
                    self.at = normal;
                    return;
                };
                let (abrupt, pending): (Vec<_>, Vec<_>) = self
                    .graph
                    .pop_cleanup()
                    .into_iter()
                    .partition(|(_, jump)| *jump == Jump::Throw);
                self.at = normal;
                self.join_with(pending.iter().map(|(from, _)| *from).collect());
                self.field(finally, "body");
                let end = self.at;
                self.graph.resume(end, pending);
                self.at = self.graph.join(
                    &abrupt
                        .iter()
                        .map(|(from, _)| Some(*from))
                        .collect::<Vec<_>>(),
                );
                self.field(finally, "body");
                self.graph.resume(self.at, abrupt);
                self.at = normal.and(end);
            }
            "return_statement" => {
                self.children(node);
                self.graph.jump(self.at, Jump::Return);
                self.at = None;
            }
            "break_statement" => self.level_jump(node, Jump::Break(None)),
            "continue_statement" => self.level_jump(node, Jump::Continue(None)),
            "throw_expression" => {
                self.children(node);
                let thrown = php_throw_exn(node, self.source, self.graph);
                self.graph.throw(self.at, thrown);
                self.at = None;
            }
            "exit_statement" => {
                self.children(node);
                self.at = None;
            }
            _ => self.children(node),
        }
    }
}

const PHP_EXCEPTIONS: &[&str] = &["Throwable", "Exception", "Error", "ValueError", "TypeError"];

fn node_text<'a>(node: Node, source: &'a str) -> &'a str {
    let start = node.start_byte();
    let end = node.end_byte().min(source.len());
    source.get(start..end).unwrap_or("")
}

fn simple_name(text: &str) -> &str {
    text.trim().strip_prefix('\\').unwrap_or(text.trim())
}

fn php_symbol(name: &str) -> Option<Symbol> {
    PHP_EXCEPTIONS.contains(&name).then(|| Symbol::php(name))
}

fn collect_php_types(node: Node, source: &str, out: &mut Vec<String>, depth: u32) {
    if depth > 8 {
        return;
    }
    match node.kind() {
        "compound_statement" | "variable_name" => {}
        "name" | "qualified_name" => {
            let name = simple_name(node_text(node, source));
            if !name.is_empty() {
                out.push(name.to_string());
            }
        }
        _ => {
            for child in named_children(node) {
                collect_php_types(child, source, out, depth + 1);
            }
        }
    }
}

fn php_catch(clause: Node, source: &str, graph: &mut Graph) -> Catch {
    if !global_exception_names(clause, graph) {
        return Catch::Unknown;
    }
    let mut names = Vec::new();
    collect_php_types(clause, source, &mut names, 0);
    if names.iter().any(|name| name == "Throwable") {
        return Catch::Any;
    }
    let mut symbols = Vec::new();
    for name in names {
        match php_symbol(&name) {
            Some(symbol) => symbols.push(symbol),
            None => return Catch::Unknown,
        }
    }
    Catch::names(symbols)
}

fn php_throw_exn(node: Node, source: &str, graph: &mut Graph) -> Exn {
    let Some(expr) = named_children(node).into_iter().next() else {
        return Exn::Unknown;
    };
    match expr.kind() {
        "null" => Exn::named(Symbol::php("Error")),
        "object_creation_expression" => {
            if !global_exception_names(node, graph) {
                return Exn::Unknown;
            }
            let mut names = Vec::new();
            collect_php_types(expr, source, &mut names, 0);
            match names.first() {
                Some(name) => php_symbol(name).map(Exn::named).unwrap_or(Exn::Unknown),
                None => Exn::Unknown,
            }
        }
        _ => Exn::Unknown,
    }
}

fn global_exception_names(mut node: Node, graph: &mut Graph) -> bool {
    while let Some(parent) = node.parent() {
        if !graph.scan_step() {
            return false;
        }
        node = parent;
    }
    let mut cursor = node.walk();
    let mut work = 0;
    loop {
        work += 1;
        if work > crate::AnalysisLimits::default().max_causal_pairs || !graph.scan_step() {
            return false;
        }
        if matches!(
            cursor.node().kind(),
            "namespace_definition" | "namespace_use_declaration"
        ) {
            return false;
        }
        if cursor.goto_first_child() {
            continue;
        }
        loop {
            if cursor.goto_next_sibling() {
                break;
            }
            if !cursor.goto_parent() {
                return true;
            }
        }
    }
}
