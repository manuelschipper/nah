use std::collections::BTreeSet;

use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CausalAssurance, Domain,
};
use lib_ruby_parser::Node;
use lib_ruby_parser::nodes::Send;

use crate::builder::KNOWN_DOMAINS;

use super::super::syntax::ruby_constant_path;
use super::RubyWalker;

/// A call that writes its arguments to the program's standard output.
pub(super) fn prints_to_stdout(s: &Send) -> bool {
    let stdout_receiver = match s.recv.as_deref() {
        None => true,
        Some(Node::Gvar(global)) => global.name == "$stdout",
        Some(Node::Const(constant)) => constant.scope.is_none() && constant.name == "STDOUT",
        _ => false,
    };
    stdout_receiver
        && match s.method_name.as_str() {
            "puts" | "print" | "p" | "pp" | "printf" => true,
            "write" | "<<" => s.recv.is_some(),
            _ => false,
        }
}

/// A `File`/`IO` call that returns a whole file's text, which an output call
/// printing it writes out byte for byte.
pub(super) fn file_read_call(call: &Send) -> bool {
    matches!(
        call.recv.as_deref().and_then(ruby_constant_path).as_deref(),
        Some("File" | "IO")
    ) && matches!(call.method_name.as_str(), "read" | "binread" | "readlines")
}

/// The arguments of a `printf`-style call whose text the output contains: a
/// literal format's plain `%s` arguments. `None` when the format is not a
/// literal this reading follows.
pub(super) fn formatted_arguments(args: &[Node]) -> Option<Vec<&Node>> {
    let Some(Node::Str(format)) = args.first() else {
        return None;
    };
    let indices = crate::lang::frontend::format_text_arguments(
        &format.value.to_string_lossy(),
        &[
            'a', 'A', 'b', 'B', 'c', 'd', 'e', 'E', 'f', 'g', 'G', 'i', 'o', 'u', 'x', 'X',
        ],
    )?;
    Some(
        indices
            .into_iter()
            .filter_map(|index| args.get(index + 1))
            .collect(),
    )
}

/// A file read or backtick span with whether a value holds its bytes verbatim.
pub(super) type RubyOutputSource = ((usize, usize), bool);

/// The backtick spans and local names whose bytes an expression's value
/// carries. Only forms that keep the text pass them on: interpolation,
/// concatenation, a branch's result, whitespace trimming and conversions to a
/// string. A length, a predicate or any other computation over captured
/// output does not carry its bytes. Each source is paired with whether its
/// bytes reach the value verbatim; a format this reading cannot follow may or
/// may not print them.
pub(super) fn ruby_backtick_sources(node: &Node) -> (Vec<RubyOutputSource>, Vec<(String, bool)>) {
    value_sources(node, &|node| match node {
        Node::Xstr(x) => Some((x.expression_l.begin, x.expression_l.end)),
        Node::XHeredoc(x) => Some((x.expression_l.begin, x.expression_l.end)),
        _ => None,
    })
}

/// The `File.read`-style calls and the locals whose text an expression's
/// value holds, read as [`ruby_backtick_sources`] reads backticks.
pub(super) fn ruby_file_read_sources(node: &Node) -> (Vec<RubyOutputSource>, Vec<(String, bool)>) {
    value_sources(node, &|node| match node {
        Node::Send(read) if file_read_call(read) => {
            Some((read.expression_l.begin, read.expression_l.end))
        }
        _ => None,
    })
}

/// The spans `source` names and the locals an expression's value holds the
/// text of, each with whether the text is held unchanged.
fn value_sources(
    node: &Node,
    source: &dyn Fn(&Node) -> Option<(usize, usize)>,
) -> (Vec<RubyOutputSource>, Vec<(String, bool)>) {
    let mut spans = Vec::new();
    let mut locals = Vec::new();
    let mut stack = vec![(node, true)];
    while let Some((node, exact)) = stack.pop() {
        let mut next: Vec<&Node> = Vec::new();
        if let Some(span) = source(node) {
            spans.push((span, exact));
            continue;
        }
        match node {
            Node::Lvar(local) => locals.push((local.name.clone(), exact)),
            Node::Dstr(string) => next.extend(string.parts.iter()),
            Node::Heredoc(string) => next.extend(string.parts.iter()),
            Node::Array(array) => next.extend(array.elements.iter()),
            Node::Begin(begin) => next.extend(begin.statements.last()),
            Node::IfTernary(branch) => next.extend([&*branch.if_true, &*branch.if_false]),
            Node::If(branch) => next.extend(
                branch
                    .if_true
                    .as_deref()
                    .into_iter()
                    .chain(branch.if_false.as_deref()),
            ),
            Node::Or(or) => next.extend([&*or.lhs, &*or.rhs]),
            // Captured text is truthy, so `a && b` yields `b`.
            Node::And(and) => next.push(&and.rhs),
            Node::Send(send) => match (send.recv.as_deref(), send.method_name.as_str()) {
                (
                    Some(receiver),
                    "strip" | "lstrip" | "rstrip" | "chomp" | "to_s" | "to_str" | "dup" | "freeze"
                    | "itself" | "upcase" | "downcase",
                ) if send.args.is_empty() => next.push(receiver),
                // A separator or line ending changes where the text is cut,
                // not whose text it is.
                (Some(receiver), "lines" | "chomp") => next.push(receiver),
                // The separator is written between the elements.
                (Some(receiver), "+" | "join") => {
                    next.push(receiver);
                    next.extend(send.args.iter());
                }
                (None, "format" | "sprintf") => match formatted_arguments(&send.args) {
                    Some(printed) => next.extend(printed),
                    None => stack.extend(send.args.iter().map(|arg| (arg, false))),
                },
                _ => {}
            },
            _ => {}
        }
        stack.extend(next.into_iter().map(|child| (child, exact)));
    }
    (spans, locals)
}

impl RubyWalker<'_> {
    /// An output call prints these arguments. A `File.read`-style call among
    /// them binds its reads once the walk reaches it; a local that last held
    /// one binds the reads that call already emitted.
    pub(super) fn print_reads(&mut self, args: &[&Node], assurance: CausalAssurance, call: &Send) {
        for argument in args {
            let (reads, locals) = ruby_file_read_sources(argument);
            let printed = |exact: bool| match exact {
                true => assurance,
                false => CausalAssurance::Conservative,
            };
            // An inline read is walked after this call; it binds itself then.
            for (span, exact) in reads {
                self.printed_reads.insert(span, printed(exact));
            }
            for (local, exact) in locals {
                let reads = self
                    .read_locals
                    .get(&local)
                    .into_iter()
                    .flatten()
                    .filter_map(|span| self.read_effects.get(span))
                    .flatten()
                    .copied()
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect();
                self.bind_reads_to_stdout(
                    reads,
                    printed(exact),
                    (call.expression_l.begin, call.expression_l.end),
                );
            }
        }
    }

    /// These file reads send their bytes to the program's stdout.
    pub(super) fn bind_reads_to_stdout(
        &mut self,
        reads: Vec<u32>,
        assurance: CausalAssurance,
        (begin, end): (usize, usize),
    ) {
        if reads.is_empty() {
            return;
        }
        let node = self.span(begin, end);
        self.builder.flow_stage(crate::flow::FlowStage {
            execution: Some(self.builder.current_execution()),
            bindings: reads
                .iter()
                .map(|read| crate::flow::PortBinding {
                    assurance,
                    from: crate::flow::BindEnd::Effect(*read),
                    to: crate::flow::BindEnd::Port(effinterp_proto::Port::Stdout),
                })
                .collect(),
            effects: reads,
            provenance: vec![node],
        });
    }

    /// An output call prints these arguments to the program's stdout. Its
    /// backticks, which run after it in this walk, keep that stdout, and a
    /// local holding earlier captured output reconnects that command's stdout.
    /// When the call does not print its arguments `exact`ly, as with a format
    /// this reading cannot follow, captured output raises a boundary instead
    /// of an exact flow.
    pub(super) fn print_captures(&mut self, args: &[&Node], exact: bool, call: &Send) {
        let mut uncertain = false;
        for argument in args {
            let (spans, locals) = ruby_backtick_sources(argument);
            for (span, verbatim) in spans {
                if exact && verbatim {
                    self.printed_captures.insert(span);
                } else {
                    uncertain = true;
                }
            }
            for (local, verbatim) in locals {
                for (span, held) in self.capture_locals.get(&local).cloned().unwrap_or_default() {
                    if !(exact && verbatim && held) {
                        uncertain = true;
                    } else if let Some((child, stdout)) = self.captured_outputs.get(&span).cloned()
                    {
                        self.builder.set_execution_stdout(child, stdout);
                    }
                }
            }
        }
        if uncertain {
            let node = self.span(call.expression_l.begin, call.expression_l.end);
            self.builder.boundary(Boundary {
                reason: BoundaryReason::DYNAMIC_SOURCE,
                class: BoundaryClass::Unresolved,
                scope: BoundaryScope::Invocation,
                affected_resource: None,
                callee: None,
                domains: KNOWN_DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
                provenance: vec![node],
                limit: None,
                detail: None,
            });
        }
    }
}
