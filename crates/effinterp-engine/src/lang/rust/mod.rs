//! Effect-directed Rust frontend, parsed with `syn` (native, no MSRV concern).
//!
//! It walks Rust source for calls that reach an external-resource boundary —
//! `std::fs`, `std::net`, `std::process::Command`, `std::env`, and a few common
//! crates —
//! resolving them by `use` path so a method on an unknown value never triggers
//! a model. It does not interpret Rust; it follows only what reaches an effect,
//! keeps non-literal arguments symbolic, and records an explicit boundary for
//! anything it cannot resolve (macros it can't expand, dynamic dispatch,
//! `unsafe`). Bounded declarative entry macros (`path::bin!(crate)`,
//! `main!(crate)`, `entry!(crate)`) are treated as a `fn main` that hands off
//! to the named crate — not a general macro expander.
//!
//! ## Execution, not source presence
//!
//! `analyze` describes what EXECUTING the source does: effects reachable from
//! `fn main` through a within-file call graph. A defined-but-uncalled function
//! contributes nothing to execution — it contributes a *callable* summary
//! instead (see [`crate::module_summary::module_summaries`]), so the repository can specialize it with
//! a caller's arguments across files.

mod call_resolution;
mod control;
mod deferred_calls;
mod macros;
mod model;
mod summary;
mod syntax;
mod value_facts;
mod walker;

use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CoverageLevel, Domain, ProvenanceRef,
};

use crate::builder::PlanBuilder;
use crate::lang::frontend::{Frontend, FrontendInput, ParseFailure, ParseOutcome, WalkOutcome};
use crate::limits::DEFAULT_MAX_RUST_NODES;
use crate::nest::Nest;

pub(crate) use macros::is_entry_macro_line;
pub(crate) use model::DEFERRED_COMMAND;
pub(super) use value_facts::scope_rust_branch_groups;

/// Effect domains this frontend can surface.
const RUST_DOMAINS: [&str; 5] = ["environment", "filesystem", "git", "network", "process"];

/// Deepest expression nesting visited while recovering value facts.
const MAX_VALUE_DEPTH: usize = 48;

/// Deepest chain of local-function summaries composed, guarding recursion on
/// top of the per-analysis visiting set.
const MAX_CALL_DEPTH: usize = 64;

pub(crate) struct RustFrontend;

impl Frontend for RustFrontend {
    const LANGUAGE: &'static str = "rust";
    const DOMAINS: &'static [&'static str] = &RUST_DOMAINS;
    type Ast<'a> = syn::File;
    fn parse<'a>(&'a self, source: &'a str) -> ParseOutcome<Self::Ast<'a>> {
        match syn::parse_file(source) {
            Ok(ast) => ParseOutcome {
                ast: Some(ast),
                failure: None,
            },
            Err(err) => ParseOutcome {
                ast: None,
                failure: Some(ParseFailure {
                    detail: err.to_string(),
                }),
            },
        }
    }
    fn parse_failure(
        &self,
        builder: &mut PlanBuilder,
        scope: Option<ProvenanceRef>,
        failure: &ParseFailure,
    ) {
        for domain in RUST_DOMAINS {
            builder.declare_coverage(Domain::new(domain), CoverageLevel::None);
        }
        builder.boundary(Boundary {
            reason: BoundaryReason::PARSE_ERROR,
            class: BoundaryClass::ParseFailure,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: RUST_DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
            provenance: scope.as_slice().to_vec(),
            limit: None,
            detail: Some(failure.detail.clone()),
        });
    }
    fn walk<'a>(
        &'a self,
        builder: &mut PlanBuilder,
        nest: &Nest,
        input: &FrontendInput,
        file: &Self::Ast<'a>,
    ) -> WalkOutcome {
        walker::walk_rust_file(builder, nest, input, file)
    }
    fn summarize<'a>(
        &'a self,
        source: &str,
        ast: &Self::Ast<'a>,
        _file: &str,
        _scope: crate::ScopeKey,
        value_limits: crate::ValueLimits,
    ) -> crate::module_summary::ModuleSummary {
        summary::summarize_ast(source, ast, value_limits)
    }
}

fn over_budget(nodes: &mut u64) -> bool {
    if !crate::limits::summary_step() {
        return true;
    }
    *nodes += 1;
    *nodes > crate::limits::invocation_node_limit(DEFAULT_MAX_RUST_NODES)
}

fn simple_boundary(
    reason: BoundaryReason,
    class: BoundaryClass,
    domains: &[&str],
    detail: &str,
) -> Boundary {
    Boundary {
        reason,
        class,
        scope: BoundaryScope::Invocation,
        affected_resource: None,
        callee: None,
        domains: domains.iter().map(|d| Domain::new(*d)).collect(),
        provenance: Vec::new(),
        limit: None,
        detail: Some(detail.to_string()),
    }
}
