//! A Java method body's effect-directed control flow.
//!
//! Method invocations and object creations are the sites that may run code.
//! A `catch` is entered from the start of its `try` because anything inside
//! may throw, and closing a try-with-resources resource runs its `close`.
//! Lambdas and nested class bodies are not executed where they are written.

use tree_sitter::Node;

use crate::control_flow::{Catch, ControlExit, Exn, Frontier, Graph, Jump, Symbol};
use crate::lang::tree_sitter_nodes::{named_children, node_span, node_text};

/// Running a class: static initialization, then `main`.
pub(super) fn build_program(graph: &mut Graph, root: Node, main: Option<Node>, source: &str) {
    let mut builder = JavaControlFlowBuilder::new(graph, source);
    if runs_static_code(root, 0) {
        builder.graph.unknown(builder.at);
    }
    match main {
        Some(main) => builder.site(main, true),
        // Without one `main`, nothing this walk proves runs.
        None => builder.graph.unknown(builder.at),
    }
    builder.graph.exit(builder.at, ControlExit::Success);
}

pub(super) fn build_body(graph: &mut Graph, body: Node, source: &str) {
    let mut builder = JavaControlFlowBuilder::new(graph, source);
    builder.node(body);
    builder.graph.jump(builder.at, Jump::Return);
}

/// Static initializers and field initializers run before `main`.
pub(super) fn runs_static_code(node: Node, depth: u32) -> bool {
    if depth >= crate::lang::frontend::MAX_WALK_DEPTH {
        return true;
    }
    match node.kind() {
        "static_initializer" => true,
        "field_declaration" => contains_call(node, depth),
        "method_declaration" | "constructor_declaration" | "lambda_expression" => false,
        _ => named_children(node)
            .into_iter()
            .any(|child| runs_static_code(child, depth + 1)),
    }
}

fn contains_call(node: Node, depth: u32) -> bool {
    if depth >= crate::lang::frontend::MAX_WALK_DEPTH {
        return true;
    }
    matches!(
        node.kind(),
        "method_invocation" | "object_creation_expression"
    ) || named_children(node)
        .into_iter()
        .any(|child| contains_call(child, depth + 1))
}

struct JavaControlFlowBuilder<'g, 's> {
    graph: &'g mut Graph,
    at: Frontier,
    source: &'s str,
}

fn literal_true(node: Node) -> bool {
    let mut node = node;
    while node.kind() == "parenthesized_expression" {
        match node.named_child(0) {
            Some(inner) => node = inner,
            None => return false,
        }
    }
    node.kind() == "true"
}

impl<'g, 's> JavaControlFlowBuilder<'g, 's> {
    fn new(graph: &'g mut Graph, source: &'s str) -> Self {
        graph.enable_exceptions();
        let at = graph.entry();
        Self { graph, at, source }
    }

    fn site(&mut self, node: Node, opaque: bool) {
        self.at = self.graph.site(self.at, node_span(node), opaque);
    }

    fn children(&mut self, node: Node) {
        for child in named_children(node) {
            self.node(child);
        }
    }

    fn field(&mut self, node: Node, name: &str) {
        let mut cursor = node.walk();
        let fields: Vec<Node> = node.children_by_field_name(name, &mut cursor).collect();
        for child in fields {
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
            "lambda_expression"
            | "class_body"
            | "class_declaration"
            | "interface_declaration"
            | "enum_declaration"
            | "record_declaration"
            | "method_reference" => {}
            "method_invocation"
            | "object_creation_expression"
            | "explicit_constructor_invocation" => {
                self.children(node);
                self.site(node, true);
            }
            "binary_expression" => {
                self.field(node, "left");
                let short_circuit = node
                    .child_by_field_name("operator")
                    .is_some_and(|op| matches!(op.kind(), "&&" | "||"));
                if short_circuit {
                    self.optional(|builder| builder.field(node, "right"));
                } else {
                    self.field(node, "right");
                }
                if node
                    .child_by_field_name("operator")
                    .is_some_and(|op| matches!(op.kind(), "/" | "%"))
                {
                    self.at = self.graph.may_throw(self.at);
                }
            }
            "array_access" | "field_access" | "cast_expression" => {
                self.children(node);
                self.at = self.graph.may_throw(self.at);
            }
            "ternary_expression" => {
                self.field(node, "condition");
                let test = self.at;
                self.field(node, "consequence");
                let taken = self.at;
                self.at = test;
                self.field(node, "alternative");
                self.at = self.graph.join(&[taken, self.at]);
            }
            // Assertions are disabled unless the JVM enables them.
            "assert_statement" => self.optional(|builder| builder.children(node)),
            "if_statement" => {
                self.field(node, "condition");
                let test = self.at;
                self.field(node, "consequence");
                let taken = self.at;
                self.at = test;
                self.field(node, "alternative");
                self.at = self.graph.join(&[taken, self.at]);
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
                self.field(node, "init");
                let header = self.graph.header(self.at);
                self.at = header;
                self.field(node, "condition");
                let tested = self.at;
                let (breaks, continues) = self.loop_body(node.child_by_field_name("body"));
                self.join_with(continues);
                self.field(node, "update");
                let back = self.at;
                self.graph.backedge(back, header);
                self.at = match node.child_by_field_name("condition") {
                    Some(condition) if !literal_true(condition) => tested,
                    _ => None,
                };
                self.join_with(breaks);
            }
            "enhanced_for_statement" => {
                self.field(node, "value");
                let header = self.graph.header(self.at);
                self.at = header;
                let (breaks, continues) = self.loop_body(node.child_by_field_name("body"));
                self.join_with(continues);
                let back = self.at;
                self.graph.backedge(back, header);
                self.at = header;
                self.join_with(breaks);
            }
            // Labeled jumps widen, so a label changes no structure.
            "labeled_statement" => self.children(node),
            "break_statement" | "continue_statement" => {
                if node.named_child_count() > 0 {
                    // A labeled jump.
                    self.graph.widen();
                } else if node.kind() == "break_statement" {
                    self.graph.jump(self.at, Jump::Break(None));
                } else {
                    self.graph.jump(self.at, Jump::Continue(None));
                }
                self.at = None;
            }
            "switch_expression" | "switch_statement" => {
                self.field(node, "condition");
                let discriminant = self.at;
                self.graph.push_loop(None, false);
                let mut previous = None;
                let mut default = false;
                let mut ends = Vec::new();
                if let Some(block) = node.child_by_field_name("body") {
                    for group in named_children(block) {
                        let mut labels = Vec::new();
                        let mut statements = Vec::new();
                        for child in named_children(group) {
                            if child.kind() == "switch_label" {
                                labels.push(child);
                            } else {
                                statements.push(child);
                            }
                        }
                        default |= labels.iter().any(|label| label.named_child_count() == 0);
                        let rule = group.kind() == "switch_rule";
                        self.at = self.graph.join(&[discriminant, previous]);
                        for label in labels {
                            // Guards of pattern labels may run code.
                            self.children(label);
                        }
                        for statement in statements {
                            self.node(statement);
                        }
                        if rule {
                            ends.push(self.at);
                            previous = None;
                        } else {
                            previous = self.at;
                        }
                    }
                }
                let (breaks, _) = self.graph.pop_loop();
                ends.push(previous);
                if !default {
                    ends.push(discriminant);
                }
                self.at = self.graph.join(&ends);
                self.join_with(breaks);
            }
            "yield_statement" => {
                self.children(node);
                self.graph.jump(self.at, Jump::Break(None));
                self.at = None;
            }
            "try_statement" | "try_with_resources_statement" => {
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
                if let Some(resources) = node.child_by_field_name("resources") {
                    self.node(resources);
                }
                self.field(node, "body");
                if node.kind() == "try_with_resources_statement" {
                    // Closing a resource runs its `close`.
                    self.graph.unknown(self.at);
                }
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
                    let catch = java_catch(*clause, self.source, self.graph);
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
                self.children(finally);
                let end = self.at;
                self.graph.resume(end, pending);
                self.at = self.graph.join(
                    &abrupt
                        .iter()
                        .map(|(from, _)| Some(*from))
                        .collect::<Vec<_>>(),
                );
                self.children(finally);
                self.graph.resume(self.at, abrupt);
                self.at = normal.and(end);
            }
            "return_statement" => {
                self.children(node);
                self.graph.jump(self.at, Jump::Return);
                self.at = None;
            }
            "throw_statement" => {
                self.children(node);
                let thrown = java_throw_exn(node, self.source, self.graph);
                self.graph.throw(self.at, thrown);
                self.at = None;
            }
            _ => self.children(node),
        }
    }
}

const JAVA_EXCEPTIONS: &[&str] = &[
    "Throwable",
    "Exception",
    "RuntimeException",
    "Error",
    "NullPointerException",
];

fn simple_name(text: &str) -> &str {
    text.trim()
        .strip_prefix("java.lang.")
        .unwrap_or(text.trim())
}

fn java_symbol(name: &str) -> Option<Symbol> {
    JAVA_EXCEPTIONS.contains(&name).then(|| Symbol::java(name))
}

fn collect_type_names(node: Node, source: &str, out: &mut Vec<String>, depth: u32) {
    if depth > 8 {
        return;
    }
    match node.kind() {
        "block" | "identifier" => {}
        "type_identifier" | "scoped_type_identifier" | "generic_type" => {
            let name = simple_name(node_text(node, source));
            if !name.is_empty() {
                out.push(name.trim_end_matches(['>', ' ']).to_string());
            }
        }
        _ => {
            for child in named_children(node) {
                collect_type_names(child, source, out, depth + 1);
            }
        }
    }
}

fn java_catch(clause: Node, source: &str, graph: &mut Graph) -> Catch {
    if !builtin_exception_names(clause, source, graph) {
        return Catch::Unknown;
    }
    let mut names = Vec::new();
    for child in named_children(clause) {
        if child.kind() == "catch_formal_parameter" {
            for part in named_children(child) {
                if part.kind() != "identifier" {
                    collect_type_names(part, source, &mut names, 0);
                }
            }
        }
    }
    names.retain(|name| !name.is_empty());
    if names.iter().any(|name| name == "Throwable") {
        return Catch::Any;
    }
    let mut symbols = Vec::new();
    for name in names {
        match java_symbol(&name) {
            Some(symbol) => symbols.push(symbol),
            None => return Catch::Unknown,
        }
    }
    Catch::names(symbols)
}

fn java_throw_exn(node: Node, source: &str, graph: &mut Graph) -> Exn {
    let Some(expr) = named_children(node).into_iter().next() else {
        return Exn::Unknown;
    };
    match expr.kind() {
        "null_literal" => Exn::named(Symbol::java("NullPointerException")),
        "object_creation_expression" => {
            if !builtin_exception_names(node, source, graph) {
                return Exn::Unknown;
            }
            let ty = expr.child_by_field_name("type").unwrap_or(expr);
            let mut names = Vec::new();
            collect_type_names(ty, source, &mut names, 0);
            match names.first() {
                Some(name) => java_symbol(name).map(Exn::named).unwrap_or(Exn::Unknown),
                None => Exn::Unknown,
            }
        }
        _ => Exn::Unknown,
    }
}

fn builtin_exception_names(mut node: Node, source: &str, graph: &mut Graph) -> bool {
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
        let current = cursor.node();
        if current.kind() == "type_parameter" {
            return false;
        }
        if matches!(
            current.kind(),
            "class_declaration" | "interface_declaration" | "enum_declaration"
        ) && let Some(name) = current.child_by_field_name("name")
            && JAVA_EXCEPTIONS.contains(&node_text(name, source))
        {
            return false;
        }
        if current.kind() == "import_declaration" {
            let text = node_text(current, source).trim_end_matches(';').trim();
            if !text
                .strip_prefix("import ")
                .is_some_and(|path| path.trim_start().starts_with("java.lang."))
                && (text.ends_with('*')
                    || JAVA_EXCEPTIONS
                        .iter()
                        .any(|name| text.ends_with(&format!(".{name}"))))
            {
                return false;
            }
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
