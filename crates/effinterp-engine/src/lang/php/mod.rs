//! Effect-directed PHP frontend.
//!
//! Invocation planning walks reached statements and calls. Repository indexing
//! also extracts parameterized summaries for functions that were never called.

mod control;
mod file_context;
mod summary;
mod syntax;
mod walker;

use effinterp_proto::ProvenanceRef;

use crate::builder::PlanBuilder;
use crate::lang::frontend::{Frontend, FrontendInput, ParseFailure, ParseOutcome, WalkOutcome};
use crate::limits::DEFAULT_MAX_PHP_NODES;
use crate::module_summary::ModuleSummary;
use crate::nest::Nest;

use summary::summarize_ast;
pub(crate) use walker::PhpSourceState;
use walker::walk_php_file;

const DOMAINS: [&str; 4] = ["environment", "filesystem", "network", "process"];

const CALL_DEPTH_LIMIT: u64 = 64;
const MAX_COMMAND_REGISTRY_VALUES: usize = 64;
/// Bound on classes visited while resolving one method through inheritance.
const CLASS_CHAIN_LIMIT: u64 = 8;

fn parse(source: &str) -> Option<tree_sitter::Tree> {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_php::LANGUAGE_PHP.into())
        .ok()?;
    parser.parse(source, None)
}

pub(crate) struct PhpFrontend<'a> {
    inc: std::cell::RefCell<&'a mut PhpSourceState>,
    root_file: bool,
}

impl Frontend for PhpFrontend<'_> {
    const LANGUAGE: &'static str = "php";
    const DOMAINS: &'static [&'static str] = &DOMAINS;
    type Ast<'a>
        = tree_sitter::Tree
    where
        Self: 'a;

    fn parse<'a>(&'a self, source: &'a str) -> ParseOutcome<Self::Ast<'a>> {
        let ast = parse(source);
        let detail = match &ast {
            None => Some("could not parse php"),
            Some(tree) if tree.root_node().has_error() => Some("php source has syntax errors"),
            Some(_) => None,
        };
        ParseOutcome {
            ast,
            failure: detail.map(|detail| ParseFailure {
                detail: detail.to_string(),
            }),
        }
    }
    fn walk<'a>(
        &'a self,
        builder: &mut PlanBuilder,
        nest: &Nest,
        input: &FrontendInput,
        tree: &Self::Ast<'a>,
    ) -> WalkOutcome {
        let mut inc = self.inc.borrow_mut();
        walk_php_file(builder, nest, input, tree, &mut inc, self.root_file)
    }
    fn summarize<'a>(
        &'a self,
        source: &str,
        ast: &Self::Ast<'a>,
        _file: &str,
        _scope: crate::ScopeKey,
        _value_limits: crate::ValueLimits,
    ) -> ModuleSummary {
        summarize_ast(source, ast)
    }
}

impl<'a> PhpFrontend<'a> {
    pub(crate) fn new(inc: &'a mut PhpSourceState) -> Self {
        Self {
            inc: std::cell::RefCell::new(inc),
            root_file: true,
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn analyze_file(
    builder: &mut PlanBuilder,
    nest: &Nest,
    source: &str,
    source_cwd: Option<&str>,
    runtime_cwd: Option<&str>,
    cwd_node: Option<ProvenanceRef>,
    scope: Option<ProvenanceRef>,
    depth: u64,
    inc: &mut PhpSourceState,
    root_file: bool,
) {
    crate::lang::frontend::run(
        &PhpFrontend {
            inc: std::cell::RefCell::new(inc),
            root_file,
        },
        builder,
        nest,
        FrontendInput {
            source,
            source_cwd,
            runtime_cwd,
            cwd_node,
            scope,
            depth,
        },
    );
}
