//! Effect-directed Ruby frontend.
//!
//! Parses Ruby with `lib-ruby-parser` (a mature Rust port of the MRI parser)
//! and walks the AST for calls that reach an effect boundary — `system`/
//! backticks/`exec`/`spawn`, `File`/`FileUtils`/`Dir`/`IO`/`Open3`, `ENV`,
//! `Net::HTTP`. It does not interpret Ruby; it follows only what reaches an
//! effect, keeps non-literal arguments symbolic, and records an explicit
//! boundary for anything dynamic (`eval`, `send`, `define_method`).
//!
//! Like the Python and JS frontends it distinguishes module EXECUTION (top-
//! level statements plus methods reached by a call) from the callable surface
//! (per-`def` parameterized summaries exposed through `module_summaries`), and
//! specializes a called method's effects with the caller's arguments.

mod call_resolution;
mod control;
mod file_context;
mod guard_regions;
mod load_path;
mod model;
mod module_load;
mod receiver_types;
mod resource_bindings;
mod spawn_resources;
mod summary;
mod summary_capture;
mod syntax;
mod walk;

use std::borrow::Cow;

use lib_ruby_parser::{Node, Parser, ParserOptions};

use crate::builder::PlanBuilder;
use crate::lang::depth::ruby_nesting_exceeds;
use crate::lang::frontend::{
    Frontend, FrontendInput, MAX_WALK_DEPTH, ParseFailure, ParseOutcome, WalkOutcome,
};
use crate::limits::DEFAULT_MAX_RUBY_NODES;
use crate::nest::Nest;

use summary::summarize_ast;
use syntax::{ruby_ast_children, ruby_literal_string, ruby_top_statements};

const DOMAINS: [&str; 4] = ["environment", "filesystem", "network", "process"];
/// Bound on the same-file inline stack (recursive/mutually recursive methods).
const MAX_INLINE_DEPTH: usize = 16;
const MAX_CALL_SITE_APPLICATIONS: usize = 64;

/// Parse Ruby source into an AST root, or None on a catastrophic parse or when
/// the source nests deeper than the walk limit.
///
/// lib-ruby-parser descends recursively, and even dropping a deeply nested
/// `Box<Node>` recurses once per level, so a source nested past the native
/// stack overflows the whole hook. The nesting pre-check refuses such source
/// before the AST is ever built, which the callers surface as a limit
/// boundary; every caller already treats `None` as an unanalyzable parse.
fn parse(source: &str) -> Option<Box<Node>> {
    if ruby_nesting_exceeds(source) {
        return None;
    }
    let source = mask_embedded_documents(source);
    let options = ParserOptions {
        buffer_name: "(ruby)".to_string(),
        record_tokens: false,
        ..Default::default()
    };
    Parser::new(source.as_bytes(), options).do_parse().ast
}

/// lib-ruby-parser rejects a final `=end` without a trailing newline even
/// though MRI accepts it. Mask complete embedded-document regions while
/// preserving byte offsets so the AST and source provenance stay aligned.
fn mask_embedded_documents(source: &str) -> Cow<'_, str> {
    let marker = |line: &str, name: &str| {
        line.strip_prefix(name)
            .is_some_and(|tail| tail.is_empty() || tail.starts_with(char::is_whitespace))
    };
    let mut spans = Vec::new();
    let mut opened = None;
    let mut offset = 0usize;
    for line in source.split_inclusive('\n') {
        let text = line.trim_end_matches(['\r', '\n']);
        if opened.is_none() && marker(text, "=begin") {
            opened = Some(offset);
        }
        offset += line.len();
        if opened.is_some() && marker(text, "=end") {
            spans.push((opened.take().unwrap(), offset));
        }
    }
    if let Some(line) = source.get(offset..)
        && !line.is_empty()
    {
        if opened.is_none() && marker(line, "=begin") {
            opened = Some(offset);
        }
        if opened.is_some() && marker(line, "=end") {
            spans.push((opened.take().unwrap(), source.len()));
        }
    }
    if spans.is_empty() || opened.is_some() {
        return Cow::Borrowed(source);
    }
    let mut masked = source.as_bytes().to_vec();
    for (start, end) in spans {
        for byte in &mut masked[start..end] {
            if !matches!(*byte, b'\r' | b'\n') {
                *byte = b' ';
            }
        }
        masked[start..start + 3].copy_from_slice(b"nil");
    }
    Cow::Owned(String::from_utf8(masked).unwrap())
}

/// Classify parsed Ruby top-level statements; malformed source leaves discovery unknown.
pub fn ruby_runs_top_level(source: &str) -> Option<bool> {
    if ruby_nesting_exceeds(source) {
        return None;
    }
    let source = mask_embedded_documents(source);
    let result = Parser::new(source.as_bytes(), ParserOptions::default()).do_parse();
    if result
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.is_error())
    {
        return None;
    }
    fn declaration(node: &Node) -> bool {
        match node {
            Node::Class(_)
            | Node::Module(_)
            | Node::Def(_)
            | Node::Defs(_)
            | Node::SClass(_)
            | Node::Casgn(_)
            | Node::Str(_) => true,
            Node::Send(send) => {
                if send.recv.is_none() {
                    return matches!(
                        send.method_name.as_str(),
                        "require"
                            | "require_relative"
                            | "load"
                            | "autoload"
                            | "sig"
                            | "private_constant"
                            | "module_function"
                            | "requires_ancestor"
                            | "include"
                            | "extend"
                            | "private"
                            | "public"
                            | "protected"
                    ) || send.method_name.starts_with("attr_");
                }
                let receiver = match send.recv.as_deref() {
                    Some(Node::Send(inner))
                        if inner.method_name == "singleton_class" && inner.args.is_empty() =>
                    {
                        inner.recv.as_deref()
                    }
                    receiver => receiver,
                };
                matches!(receiver, Some(Node::Const(_)))
                    && matches!(send.method_name.as_str(), "prepend" | "include" | "extend")
            }
            Node::Block(block) => matches!(block.call.as_ref(), Node::Send(send)
                if send.recv.is_none() && send.method_name == "sig"),
            _ => false,
        }
    }
    Some(result.ast.as_deref().is_some_and(|root| {
        ruby_top_statements(root)
            .into_iter()
            .any(|node| !declaration(node))
    }))
}

pub(crate) struct RubyFrontend;

impl Frontend for RubyFrontend {
    const LANGUAGE: &'static str = "ruby";
    const DOMAINS: &'static [&'static str] = &DOMAINS;
    type Ast<'a> = Box<Node>;
    fn nesting_exceeds(&self, source: &str) -> bool {
        ruby_nesting_exceeds(source)
    }
    fn parse<'a>(&'a self, source: &'a str) -> ParseOutcome<Self::Ast<'a>> {
        let ast = parse(source);
        let failure = ast.is_none().then(|| ParseFailure {
            detail: "Ruby source did not parse".to_string(),
        });
        ParseOutcome { ast, failure }
    }
    fn walk<'a>(
        &'a self,
        builder: &mut PlanBuilder,
        nest: &Nest,
        input: &FrontendInput,
        root: &Self::Ast<'a>,
    ) -> WalkOutcome {
        walk::walk_ruby(builder, nest, input, root)
    }
    fn summarize<'a>(
        &'a self,
        source: &str,
        ast: &Self::Ast<'a>,
        _file: &str,
        _scope: crate::ScopeKey,
        _value_limits: crate::ValueLimits,
    ) -> crate::module_summary::ModuleSummary {
        summarize_ast(source, ast)
    }
}

/// Literal gem dependencies and gemspec require paths; dynamic declarations carry no evidence.
pub fn ruby_package_metadata(source: &str) -> (Vec<String>, Vec<(String, String)>) {
    let mut paths = Vec::new();
    let mut gems = Vec::new();
    let Some(root) = parse(source) else {
        return (paths, gems);
    };
    let mut pending = vec![(root.as_ref(), 0)];
    let mut visited = 0;
    while let Some((node, depth)) = pending.pop() {
        visited += 1;
        if visited > DEFAULT_MAX_RUBY_NODES || depth >= MAX_WALK_DEPTH {
            break;
        }
        if let Node::Send(send) = node {
            if send.method_name == "require_paths="
                && send.recv.is_some()
                && let [Node::Array(array)] = send.args.as_slice()
            {
                paths.extend(array.elements.iter().filter_map(ruby_literal_string));
            }
            if ((send.method_name == "gem" && send.recv.is_none())
                || (matches!(
                    send.method_name.as_str(),
                    "add_dependency" | "add_runtime_dependency"
                ) && send.recv.is_some()))
                && let Some(name) = send.args.first().and_then(ruby_literal_string)
            {
                gems.push((
                    name,
                    send.args
                        .get(1)
                        .and_then(ruby_literal_string)
                        .unwrap_or_default(),
                ));
            }
        }
        if !matches!(node, Node::Def(_) | Node::Defs(_)) {
            pending.extend(
                ruby_ast_children(node)
                    .into_iter()
                    .map(|child| (child, depth + 1)),
            );
        }
    }
    (paths, gems)
}
