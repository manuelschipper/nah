//! Boundaries for calls and dynamic code the JavaScript walk cannot resolve.

use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CalleeReference, CoverageLevel, Domain,
    ResourceExpr,
};
use oxc_ast::ast::Expression;
use oxc_span::Span;

use super::walker::JsWalker;
use super::{JS_DOMAINS, model, resolve};
use crate::builder::KNOWN_DOMAINS;

impl<'a> JsWalker<'_, 'a> {
    /// A call we cannot resolve to a summary or trusted model. It could reach
    /// any domain, so opacity is declared across all of them.
    pub(super) fn unresolved_call(
        &mut self,
        span: Span,
        name: &str,
        callee: Option<&Expression<'a>>,
    ) {
        let node = self.span_node(span);
        let callee = callee
            .filter(|callee| {
                !model::inert_base_name(callee).is_some_and(|name| {
                    self.active_bodies
                        .last()
                        .is_some_and(|body| body.local_names.contains(name))
                })
            })
            .and_then(|callee| resolve::resolve_callee_reference(callee, self.bindings))
            .map(|callee| CalleeReference {
                module: callee.module,
                symbol: callee.function,
            });
        self.builder.global_opacity(CoverageLevel::Partial);
        self.builder.boundary(Boundary {
            reason: BoundaryReason::UNRESOLVED_CALL,
            class: BoundaryClass::Unresolved,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee,
            domains: KNOWN_DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
            provenance: vec![node],
            limit: None,
            detail: Some(format!("call to unresolved {name}")),
        });
    }

    pub(super) fn unmodeled_dynamic(&mut self, span: Span, detail: &str) {
        let node = self.span_node(span);
        for domain in JS_DOMAINS {
            self.builder
                .declare_coverage(Domain::new(domain), CoverageLevel::Partial);
        }
        self.builder.boundary(Boundary {
            reason: BoundaryReason::UNMODELED_DYNAMIC,
            class: BoundaryClass::Unmodeled,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: JS_DOMAINS
                .iter()
                .map(|domain| Domain::new(*domain))
                .collect(),
            provenance: vec![node],
            limit: None,
            detail: Some(detail.to_string()),
        });
    }
    pub(super) fn opaque(&mut self, span: Span, detail: &str) {
        self.opaque_needing(span, detail, Vec::new());
    }

    /// An opaque boundary that names the environment variables whose host
    /// values would resolve it, so the host is asked for them.
    pub(super) fn opaque_needing(&mut self, span: Span, detail: &str, variables: Vec<String>) {
        let mut variables = variables
            .into_iter()
            .map(|name| ResourceExpr::Concrete {
                identity: effinterp_proto::ResourceIdentity::EnvironmentVariable { name },
            })
            .collect::<Vec<_>>();
        let affected_resource = match variables.len() {
            0 => None,
            1 => variables.pop(),
            _ => Some(ResourceExpr::Union {
                alternatives: variables,
            }),
        };
        let node = self.span_node(span);
        for domain in JS_DOMAINS {
            self.builder
                .declare_coverage(Domain::new(domain), CoverageLevel::Partial);
        }
        self.builder.boundary(Boundary {
            reason: BoundaryReason::UNMODELED_DYNAMIC_CODE,
            class: BoundaryClass::Unresolved,
            scope: BoundaryScope::Invocation,
            affected_resource,
            callee: None,
            domains: JS_DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
            provenance: vec![node],
            limit: None,
            detail: Some(detail.to_string()),
        });
    }
}
