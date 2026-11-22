//! Effect-directed JavaScript/TypeScript frontend.
//!
//! Uses the `oxc` parser (pinned to 0.116, the last release building on this
//! toolchain) to produce an AST, then walks it looking only for calls that
//! reach effect boundaries: `fs`, `child_process`, `http`/`https`/`fetch`,
//! and `process.env`. Module ownership is tracked through imports and
//! `require`, so a bare `.rm(...)` on an unknown object never triggers a
//! model. Everything unresolved — dynamic `require`, `eval`, `Function`,
//! computed access, non-literal values — becomes a typed boundary rather
//! than a guessed effect. TypeScript is parsed with the same API by turning
//! on the TS source type; type annotations are ignored.
//!
//! ## Execution, not source presence
//!
//! The plan describes what EXECUTING the module does, not the union of
//! effects present anywhere in source. A function body contributes effects
//! only when a call reaches it: top-level statements run, and calls into
//! locally defined functions, immediately-invoked function expressions, and
//! callbacks passed as arguments are followed transitively (bounded, with a
//! cycle guard). A defined-but-never-called function contributes nothing.
//! Callbacks are followed conservatively — a missed real effect is worse for
//! a security-adjacent consumer than an over-reported `may`. A call that
//! resolves to neither a modeled API nor a local function, and whose callee
//! is not a known-inert builtin, records an `unresolved_call` boundary
//! spanning every domain it could reach, so it is never silently dropped.
//!
//! [`walker::walk_js_program`] composes the execution walk. [`ast_visit`]
//! dispatches syntax nodes to the call, control-flow and value owners.

use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CoverageLevel, Domain, Effect,
    ProvenanceRef, ResourceExpr, SourceDialect,
};
use oxc_allocator::Allocator;
use oxc_parser::Parser;
use oxc_span::{SourceType, Span};

use crate::builder::PlanBuilder;
use crate::lang::frontend::{
    Frontend, FrontendInput, MAX_WALK_DEPTH, ParseFailure, ParseOutcome, WalkOutcome,
};
use crate::nest::Nest;
use walker::JsWalker;

mod aggregate_alias;
mod aggregate_mutations;
mod aggregate_source_string_members;
mod ast_visit;
mod binding_paths;
mod bindings;
mod boundaries;
mod call_arguments;
mod call_body;
mod call_reachability;
mod callable_bindings;
mod callback_dispatch;
mod class_initializers;
mod collect;
mod console;
mod control;
mod destructuring_defaults;
mod expression_values;
mod flow_tracking;
mod guard_regions;
mod identifier_references;
mod literal_members;
mod model;
mod module_load;
mod module_scope;
mod optional_chain;
mod plus_coercion;
mod printed_environment;
mod resolve;
mod source_string;
mod source_string_state;
mod summarize;
mod summary_load_sites;
mod walker;

pub(crate) use model::is_node_builtin_module;
pub use module_scope::js_runs_module_scope_call;
pub(crate) use module_scope::runtime_imports;

const JS_DOMAINS: [&str; 4] = ["environment", "filesystem", "network", "process"];

const MAX_FLOW_SLOTS: usize = 512;

/// The effects a call into a modeled external JS module performs, for
/// cross-file composition: a repo-file re-export chain may end at an external
/// module (zx's `export const fs = wrap('fs', _fs)`), and the composer then
/// needs the modeled effect for `<module>.<function>` at the original call
/// site. `args` are the caller's already-lowered argument resources. None when
/// the module/function pair is not modeled — the caller must stay loud.
pub fn js_external_effects(
    module: &str,
    function: &str,
    args: &[ResourceExpr],
) -> Option<Vec<Effect>> {
    model::external_effects(module, function, args)
}

pub(crate) struct JsFrontend {
    pub allocator: Allocator,
    pub dialect: SourceDialect,
}

impl Frontend for JsFrontend {
    const LANGUAGE: &'static str = "js";
    const DOMAINS: &'static [&'static str] = &JS_DOMAINS;
    type Ast<'a> = oxc_ast::ast::Program<'a>;
    fn nesting_exceeds(&self, source: &str) -> bool {
        crate::lang::depth::js_nesting_exceeds(source)
    }
    fn parse<'a>(&'a self, source: &'a str) -> ParseOutcome<Self::Ast<'a>> {
        let source_type = match self.dialect {
            SourceDialect::Js => SourceType::mjs(),
            SourceDialect::Ts => SourceType::ts(),
            SourceDialect::Ipython => {
                unreachable!("validated JavaScript dialect")
            }
        };
        let parsed = Parser::new(&self.allocator, source, source_type).parse();
        let failure = parsed.errors.first().map(|err| ParseFailure {
            detail: err.to_string(),
        });
        ParseOutcome {
            ast: Some(parsed.program),
            failure,
        }
    }
    fn parse_failure(
        &self,
        builder: &mut PlanBuilder,
        scope: Option<ProvenanceRef>,
        failure: &ParseFailure,
    ) {
        for domain in JS_DOMAINS {
            builder.declare_coverage(Domain::new(domain), CoverageLevel::Partial);
        }
        builder.boundary(Boundary {
            reason: BoundaryReason::PARSE_ERROR,
            class: BoundaryClass::ParseFailure,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: JS_DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
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
        program: &Self::Ast<'a>,
    ) -> WalkOutcome {
        walker::walk_js_program(builder, nest, input, program, self.dialect)
    }
    fn summarize<'a>(
        &'a self,
        source: &str,
        ast: &Self::Ast<'a>,
        file: &str,
        scope: crate::ScopeKey,
        _value_limits: crate::ValueLimits,
    ) -> crate::module_summary::ModuleSummary {
        summarize::summarize_ast(source, ast, file, scope)
    }
}

impl<'a> JsWalker<'_, 'a> {
    /// Enter one Visit frame; false at the walk-depth bound. The node that
    /// would pass the bound is skipped with a boundary and the walk resumes
    /// at its next sibling, so one deep expression does not hide the
    /// statements after it. The recursion stays within the bound either way.
    fn enter_walk(&mut self) -> bool {
        if self.saturated {
            return false;
        }
        if self.walk_depth >= MAX_WALK_DEPTH {
            if std::mem::replace(&mut self.depth_stopped, true) {
                return false;
            }
            for domain in JS_DOMAINS {
                self.builder
                    .declare_coverage(Domain::new(domain), CoverageLevel::Partial);
            }
            self.builder.boundary(Boundary {
                reason: BoundaryReason::PARTIAL_ANALYSIS,
                class: BoundaryClass::Unmodeled,
                scope: BoundaryScope::Invocation,
                affected_resource: None,
                callee: None,
                domains: JS_DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
                provenance: self.scope.as_slice().to_vec(),
                limit: Some("max_walk_depth".to_string()),
                detail: Some("js walk depth bound reached".to_string()),
            });
            return false;
        }
        self.walk_depth += 1;
        true
    }

    /// Count one node against the frontend cap and the whole-analysis step
    /// budget; false once either is saturated.
    fn charge(&mut self, span: Span) -> bool {
        self.observe_state_budget(span);
        if self.saturated {
            return false;
        }
        if !crate::nest::charge_analysis_steps(
            self.builder,
            self.nest.budget,
            1,
            Some((span.start, span.end)),
        ) {
            self.saturated = true;
            return false;
        }
        self.nodes += 1;
        if self.nodes > self.max_nodes {
            self.saturated = true;
            for domain in JS_DOMAINS {
                self.builder
                    .declare_coverage(Domain::new(domain), CoverageLevel::Partial);
            }
            self.builder.boundary(Boundary {
                reason: BoundaryReason::LIMIT_SATURATED,
                class: BoundaryClass::Limit,
                scope: BoundaryScope::Invocation,
                affected_resource: None,
                callee: None,
                domains: JS_DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
                provenance: self.scope.as_slice().to_vec(),
                limit: Some("max_js_nodes".to_string()),
                detail: None,
            });
            return false;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use effinterp_proto::{ResourceExpr, ResourceIdentity, Subject};

    /// A chain deeper than the walk bound is skipped with its boundary, and
    /// the statement after it is still read.
    #[test]
    fn a_depth_stop_skips_one_expression_and_resumes_at_the_next_statement() {
        let plan = crate::Engine::new()
            .analyze(&Subject::Source {
                language: "js".into(),
                source: format!(
                    "let x=1{};\nrequire('fs').rmSync('/etc/sudoers')\n",
                    "\n+1".repeat(300)
                ),
                dialect: Some(effinterp_proto::SourceDialect::Js),
                cwd: Some("/w".into()),
                context: Default::default(),
            })
            .unwrap();
        assert!(
            plan.boundaries
                .iter()
                .any(|boundary| boundary.limit.as_deref() == Some("max_walk_depth"))
        );
        assert!(plan.effects.iter().any(|effect| {
            effect.operation.as_str() == "filesystem.delete"
                && matches!(
                    &effect.resource,
                    ResourceExpr::Concrete {
                        identity: ResourceIdentity::FsPath { path }
                    } if path == "/etc/sudoers"
                )
        }));
    }
}
