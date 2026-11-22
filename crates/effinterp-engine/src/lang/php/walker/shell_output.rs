//! PHP shell execution and the output that can reach the program's stdout.

use std::collections::{BTreeMap, HashMap};

use effinterp_proto::{BoundaryClass, BoundaryReason, ResourceExpr, ResourceIdentity, Subject};
use tree_sitter::Node;

use crate::nest::Transition;

use super::super::syntax::{arg_nodes, callable_name, child_kind, literal_string, text};
use super::PhpWalker;

/// A construct that writes its arguments to the program's standard output.
pub(super) fn prints_to_stdout(n: Node, src: &str) -> bool {
    match n.kind() {
        "echo_statement" | "print_intrinsic" => true,
        "function_call_expression" => matches!(
            callable_name(n, src)
                .map(|name| name.to_ascii_lowercase())
                .as_deref(),
            Some("printf" | "print_r")
        ),
        _ => false,
    }
}

/// The arguments of a `printf`-style call whose text the output contains: a
/// literal format's plain `%s` arguments. `None` when the format is not a
/// literal this reading follows.
fn formatted_arguments<'a>(args: &[Node<'a>], src: &str) -> Option<Vec<Node<'a>>> {
    let format = literal_string(*args.first()?, src)?;
    let indices = crate::lang::frontend::format_text_arguments(
        &format,
        &[
            'b', 'c', 'd', 'e', 'E', 'f', 'F', 'g', 'G', 'h', 'H', 'o', 'u', 'x', 'X',
        ],
    )?;
    Some(
        indices
            .into_iter()
            .filter_map(|index| args.get(index + 1).copied())
            .collect(),
    )
}

/// The truth value PHP gives a literal: `true`/`false`/`null`, a number, or
/// a string, looking through parentheses.
pub(super) fn literal_truth(node: Node, src: &str) -> Option<bool> {
    match node.kind() {
        "parenthesized_expression" => literal_truth(node.named_child(0)?, src),
        "boolean" | "null" => Some(text(node, src).eq_ignore_ascii_case("true")),
        "integer" | "float" => text(node, src)
            .parse::<f64>()
            .ok()
            .map(|value| value != 0.0),
        _ => literal_string(node, src).map(|value| !value.is_empty() && value != "0"),
    }
}

/// A capture site's span, with whether a value holds its bytes verbatim.
pub(super) type PhpHeldCapture = ((usize, usize), bool);

/// A scope's captured output by local, and its locals' literal truth values.
pub(super) type PhpValueFacts = (HashMap<String, Vec<PhpHeldCapture>>, HashMap<String, bool>);

/// The capture sites (backticks, `shell_exec`, `exec`) and local names whose
/// bytes an expression's value carries. Only forms that keep the text pass
/// them on: interpolation, `.` concatenation, a branch's result, whitespace
/// trimming and string conversion. A length, a comparison or any other
/// computation over captured output does not carry its bytes.
pub(super) fn capture_sources(node: Node, src: &str) -> (Vec<PhpHeldCapture>, Vec<(String, bool)>) {
    let mut spans = Vec::new();
    let mut locals = Vec::new();
    // Each source is paired with whether its bytes reach the value verbatim;
    // a format this reading cannot follow may or may not print them.
    let mut stack = vec![(node, true)];
    while let Some((node, exact)) = stack.pop() {
        match node.kind() {
            "shell_command_expression" => spans.push(((node.start_byte(), node.end_byte()), exact)),
            "variable_name" => locals.push((text(node, src).to_string(), exact)),
            "function_call_expression" => {
                let args = arg_nodes(node);
                match callable_name(node, src)
                    .map(|name| name.to_ascii_lowercase())
                    .as_deref()
                {
                    Some("shell_exec" | "exec") => {
                        spans.push(((node.start_byte(), node.end_byte()), exact))
                    }
                    Some("trim" | "ltrim" | "rtrim" | "strval") => {
                        stack.extend(args.first().map(|arg| (*arg, exact)))
                    }
                    Some("sprintf") => match formatted_arguments(&args, src) {
                        Some(printed) => stack.extend(printed.into_iter().map(|arg| (arg, exact))),
                        None => stack.extend(args.into_iter().map(|arg| (arg, false))),
                    },
                    _ => {}
                }
            }
            "binary_expression"
                if node
                    .child_by_field_name("operator")
                    .is_some_and(|operator| matches!(text(operator, src), "." | "??")) =>
            {
                stack.extend(node.child_by_field_name("left").map(|side| (side, exact)));
                stack.extend(node.child_by_field_name("right").map(|side| (side, exact)));
            }
            "conditional_expression" => {
                // `a ?: b` yields `a` itself when it is truthy.
                match node.child_by_field_name("body") {
                    Some(body) => stack.push((body, exact)),
                    None => stack.extend(
                        node.child_by_field_name("condition")
                            .map(|condition| (condition, exact)),
                    ),
                }
                stack.extend(
                    node.child_by_field_name("alternative")
                        .map(|alternative| (alternative, exact)),
                );
            }
            "encapsed_string" | "heredoc" | "heredoc_body" | "parenthesized_expression" => {
                let mut cursor = node.walk();
                stack.extend(node.named_children(&mut cursor).map(|child| (child, exact)));
            }
            _ => {}
        }
    }
    (spans, locals)
}

impl<'a, 'b> PhpWalker<'a, 'b> {
    /// A `captured` command returns its stdout to the program, as backticks,
    /// `shell_exec` and `exec` do, so it does not reach the program's stdout.
    pub(super) fn nest_php_shell_command(
        &mut self,
        cmd: String,
        site: Node<'a>,
        environment: BTreeMap<String, Option<ResourceExpr>>,
        captured: bool,
    ) {
        let node = self.span(site);
        let source_cwd = self.nest.current_source_cwd();
        let span = (site.start_byte(), site.end_byte());
        let captured = captured && !self.printed_captures.contains(&span);
        let child = self.builder.next_execution();
        let inherited_stdout = self.builder.inherited_execution_streams().stdout;
        {
            let subject = Subject::Shell {
                source: cmd,
                cwd: self.runtime_cwd.map(str::to_string),
                context: Default::default(),
            };
            let runtime_cwd = crate::nest::subject_cwd(&subject).map(str::to_string);
            let mut transition = Transition::file(subject)
                .source_cwd(source_cwd.as_deref())
                .runtime_cwd(runtime_cwd.as_deref())
                .cwd(self.runtime_cwd_resource.clone(), self.cwd_node)
                .environment(environment, BTreeMap::new(), Default::default());
            if captured {
                transition = transition.streams(effinterp_proto::ExecutionStreams {
                    stdout: None,
                    ..self.builder.inherited_execution_streams()
                });
            }
            self.nest
                .nest(self.builder, transition, &[node], self.depth);
        };
        if captured && child != self.builder.next_execution() {
            self.captured_outputs
                .insert(span, (child, inherited_stdout));
        }
    }

    /// An output call prints its arguments to the program's stdout. Its
    /// capture sites, which run after it in this walk, keep that stdout, and a
    /// local holding earlier captured output reconnects that command's stdout.
    /// When this reading cannot tell whether captured bytes are printed
    /// verbatim (a format it cannot follow, an unknown `print_r` mode), the
    /// call raises a boundary instead of an exact flow.
    pub(super) fn print_php_captured_output(&mut self, call: Node<'a>) {
        let args = arg_nodes(call);
        let (printed, exact) = match call.kind() {
            "echo_statement" | "print_intrinsic" => {
                let mut cursor = call.walk();
                (call.named_children(&mut cursor).collect(), true)
            }
            _ if callable_name(call, self.src)
                .is_some_and(|name| name.eq_ignore_ascii_case("printf")) =>
            {
                match formatted_arguments(&args, self.src) {
                    Some(printed) => (printed, true),
                    None => (args, false),
                }
            }
            // `print_r($value, true)` returns the text instead of printing it.
            _ => match args.get(1).map(|mode| self.mode_truth(*mode)) {
                Some(Some(true)) => return,
                Some(None) => (args.into_iter().take(1).collect(), false),
                None | Some(Some(false)) => (args.into_iter().take(1).collect(), true),
            },
        };
        let mut uncertain = false;
        for expression in printed {
            let (spans, locals) = capture_sources(expression, self.src);
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
            self.opaque(
                BoundaryReason::DYNAMIC_SOURCE,
                BoundaryClass::Unresolved,
                call,
            );
        }
    }

    /// The PHP truth value of a literal or of a local a definite assignment
    /// gave a literal.
    fn mode_truth(&self, mode: Node) -> Option<bool> {
        literal_truth(mode, self.src).or_else(|| {
            (mode.kind() == "variable_name")
                .then(|| self.truth_locals.get(text(mode, self.src)).copied())
                .flatten()
        })
    }

    /// A shell command string: a literal string, or an interpolated string with
    /// concrete params substituted (unknown `$vars` left for the shell frontend).
    pub(super) fn command_string(
        &self,
        arg: Option<Node<'a>>,
        env: &HashMap<String, ResourceExpr>,
    ) -> Option<(String, BTreeMap<String, Option<ResourceExpr>>)> {
        let a = arg?;
        let mut values = env.clone();
        values.extend(self.locals.clone());
        match a.kind() {
            "string" => literal_string(a, self.src).map(|cmd| (cmd, BTreeMap::new())),
            // A `$cmd` bound to literal text.
            "variable_name" => {
                match child_kind(a, "name").and_then(|name| values.get(text(name, self.src))) {
                    Some(ResourceExpr::Concrete {
                        identity: ResourceIdentity::FsPath { path },
                    }) => Some((path.clone(), BTreeMap::new())),
                    _ => None,
                }
            }
            "encapsed_string" => Some((
                self.interpolate(a, &values),
                self.php_interpolation_environment(a, &values),
            )),
            _ => None,
        }
    }
}
