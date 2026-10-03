//! Pluggable source-language frontends reached through the generic
//! `Subject::Source { language, .. }`. Each language is an effect-directed
//! frontend module here. The frontends share the summary IR, nesting, and
//! module-summary machinery the Python/JS frontends established.

mod cmd;
mod conditions;
pub(crate) mod depth;
pub(crate) mod frontend;
pub(crate) mod go;
pub(crate) mod java;
mod julia;
mod lua;
pub(crate) mod perl;
pub(crate) mod php;
mod powershell;
mod r;
pub(crate) mod ruby;
pub(crate) mod rust;
mod source_text;
mod swift;
mod tree_sitter_nodes;

/// See [`rust::is_entry_macro_line`].
pub fn rust_is_entry_macro_line(trimmed: &str) -> bool {
    rust::is_entry_macro_line(trimmed)
}

/// See [`rust::DEFERRED_COMMAND`].
pub const RUST_DEFERRED_COMMAND: &str = rust::DEFERRED_COMMAND;

/// Scope the Rust branch groups inside a callee's returned value to one call site
/// (`scope`), and tag each returned alternative, so values correlated by one
/// call's branches are not joined with another call's.
pub fn scope_rust_branch_groups(value: &crate::SemanticValue, scope: &str) -> crate::SemanticValue {
    rust::scope_rust_branch_groups(value, scope)
}

use effinterp_proto::{ProvenanceRef, SourceDialect};

use crate::builder::PlanBuilder;
use crate::nest::Nest;

/// Analyze validated inline source in the named language.
#[allow(clippy::too_many_arguments)]
pub(crate) fn analyze(
    builder: &mut PlanBuilder,
    nest: &Nest,
    language: &str,
    dialect: Option<SourceDialect>,
    source: &str,
    source_cwd: Option<&str>,
    runtime_cwd: Option<&str>,
    cwd_node: Option<ProvenanceRef>,
    scope: Option<ProvenanceRef>,
    depth: u64,
) {
    match language {
        "perl" => {
            perl::analyze(
                builder,
                nest,
                source,
                runtime_cwd,
                scope,
                &Default::default(),
                depth,
            );
            return;
        }
        "powershell" => {
            powershell::analyze(builder, nest, source, runtime_cwd, scope);
            return;
        }
        "lua" => {
            lua::analyze(builder, nest, source, runtime_cwd, scope, depth);
            return;
        }
        "r" => {
            r::analyze(builder, nest, source, runtime_cwd, scope, depth);
            return;
        }
        "julia" => {
            julia::analyze(builder, nest, source, runtime_cwd, scope, depth);
            return;
        }
        "cmd" => {
            cmd::analyze(builder, nest, source, runtime_cwd, scope);
            return;
        }
        "swift" => {
            swift::analyze(builder, nest, source, runtime_cwd, scope);
            return;
        }
        _ => {}
    }
    use crate::module_summary::Lang;
    let lang = match language {
        "python" => Lang::Python,
        "js" => Lang::Js(dialect.expect("validated JS source dialect")),
        "go" => Lang::Go,
        "ruby" => Lang::Ruby,
        "rust" => Lang::Rust,
        "java" => Lang::Java,
        "php" => Lang::Php,
        _ => unreachable!("validated source language"),
    };
    let input = frontend::FrontendInput {
        source,
        source_cwd,
        runtime_cwd,
        cwd_node,
        scope,
        depth,
    };
    match lang {
        Lang::Python if dialect == Some(SourceDialect::Ipython) => crate::python::ipython::analyze(
            builder,
            nest,
            source,
            source_cwd,
            runtime_cwd,
            cwd_node,
            scope,
            depth,
        ),
        Lang::Python if dialect == Some(SourceDialect::PrimeAgent) => frontend::run(
            &crate::python::PythonFrontend::prime_agent(),
            builder,
            nest,
            input,
        ),
        Lang::Python => frontend::run(&crate::python::PythonFrontend, builder, nest, input),
        Lang::Js(dialect) => frontend::run(
            &crate::js::JsFrontend {
                allocator: oxc_allocator::Allocator::default(),
                dialect,
            },
            builder,
            nest,
            input,
        ),
        Lang::Go => frontend::run(&go::GoFrontend, builder, nest, input),
        Lang::Ruby => frontend::run(&ruby::RubyFrontend, builder, nest, input),
        Lang::Rust => frontend::run(&rust::RustFrontend, builder, nest, input),
        Lang::Java => frontend::run(&java::JavaFrontend, builder, nest, input),
        Lang::Php => frontend::run(
            &php::PhpFrontend::new(&mut php::IncludeState::default()),
            builder,
            nest,
            input,
        ),
    }
}
