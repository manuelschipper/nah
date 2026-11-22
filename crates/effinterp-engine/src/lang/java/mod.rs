//! Effect-directed Java frontend.
//!
//! Parses Java source with `tree-sitter-java` (a concrete syntax tree) and
//! walks it for calls into effect-relevant JDK APIs — `java.nio.file.Files`,
//! `java.io.File`/streams, `Runtime.exec`/`ProcessBuilder`, JDBC
//! (`Statement`/`Connection`), `java.net`/`HttpClient`, and
//! `System.getenv`/`getProperty`. It does not interpret Java; it follows only
//! what reaches an effect boundary, keeps non-literal arguments symbolic,
//! resolves an API through the receiver's static type (declared local/param/
//! field types, imports, or fully-qualified names) — and records an explicit
//! boundary for reflection and for unmodeled calls into effectful JDK
//! packages. Curated-inert JDK types (String, Collections, ...) stay quiet.
//!
//! ## Execution, not source presence
//!
//! The Java execution walk starts at methods named `main` and recognized
//! framework entry points, then follows same-file calls. Methods the walk
//! never reaches still have parameterized summaries for cross-file composition.
//! [`walker`] and [`summary`] are the two paths entered by `JavaFrontend`.

mod call_resolution;
mod callbacks;
mod control;
mod declarations;
mod local_bindings;
mod model;
mod resource_recovery;
mod summary;
mod syntax;
mod walker;

use crate::builder::PlanBuilder;
use crate::lang::frontend::{Frontend, FrontendInput, ParseFailure, ParseOutcome, WalkOutcome};
use crate::nest::Nest;
use summary::summarize_ast;
use syntax::visit_java_syntax;
use tree_sitter::{Node, Parser, Tree};
use walker::walk_java_execution;

const JAVA_DOMAINS: [&str; 5] = [
    "environment",
    "filesystem",
    "network",
    "process",
    "database",
];

const MAX_CALL_DEPTH: u64 = 64;
const MAX_SUMMARY_EFFECTS: usize = 128;
const MAX_SUMMARY_BOUNDARIES: usize = 16;

pub(crate) struct JavaFrontend;

impl Frontend for JavaFrontend {
    const LANGUAGE: &'static str = "java";
    const DOMAINS: &'static [&'static str] = &JAVA_DOMAINS;
    type Ast<'a> = Tree;
    fn parse<'a>(&'a self, source: &'a str) -> ParseOutcome<Self::Ast<'a>> {
        let ast = parse(source)
            .filter(|tree| !tree.root_node().has_error() || has_any_method(tree.root_node()));
        let failure = ast.is_none().then(|| ParseFailure {
            detail: "java source did not parse".to_string(),
        });
        ParseOutcome { ast, failure }
    }
    // Java's summary extractor also retains declarations in damaged trees
    // without methods; execution rejects those trees.
    fn parse_summary<'a>(&'a self, source: &'a str) -> Option<Self::Ast<'a>> {
        parse(source)
    }

    fn walk<'a>(
        &'a self,
        builder: &mut PlanBuilder,
        nest: &Nest,
        input: &FrontendInput,
        tree: &Self::Ast<'a>,
    ) -> WalkOutcome {
        walk_java_execution(builder, nest, input, tree)
    }
    fn summarize<'a>(
        &'a self,
        source: &str,
        ast: &Self::Ast<'a>,
        file: &str,
        scope: crate::ScopeKey,
        _value_limits: crate::ValueLimits,
    ) -> crate::module_summary::ModuleSummary {
        summarize_ast(source, ast, file, scope)
    }
}

fn parse(source: &str) -> Option<Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_java::LANGUAGE.into())
        .ok()?;
    parser.parse(source, None)
}

fn has_any_method(root: Node) -> bool {
    let mut found = false;
    visit_java_syntax(root, &mut |n| {
        if n.kind() == "method_declaration" {
            found = true;
        }
    });
    found
}
