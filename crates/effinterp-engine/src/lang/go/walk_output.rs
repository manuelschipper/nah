//! Go walk output in a live plan or a summary capture.

use std::collections::BTreeMap;

use effinterp_proto::{
    AttrValue, Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CoverageLevel, Domain,
    Effect, Modality, Operation, ProvenanceKind, ProvenanceRef, ResourceExpr, Subject,
};

use crate::SemanticValue;
use crate::builder::PlanBuilder;
use crate::control_flow::{ControlFlow, ControlStack};
use crate::module_summary::CallEdge;
use crate::nest::{Nest, Transition};
use crate::paths::fs_resource_uses_cwd;
use crate::resource_transfer::TransferBinding;
use crate::value::anchor_fs_text_concat;

use super::MAX_SUMMARY_ITEMS;
use super::walker::GoWalker;

/// The effects, edges, and control flow of one Go summary walk, using relative slots.
#[derive(Default)]
pub(super) struct GoSummaryCapture {
    pub(super) control: ControlStack,
    pub(super) flow: ControlFlow,
    pub(super) call_sites: BTreeMap<crate::control_flow::Span, u32>,
    pub(super) effects: Vec<Effect>,
    /// Transfer pairings among `effects`, by slot.
    pub(super) transfers: Vec<TransferBinding>,
    pub(super) boundaries: Vec<Boundary>,
    pub(super) coverage: Vec<(Domain, CoverageLevel)>,
    pub(super) edges: Vec<CallEdge>,
    pub(super) returns: Vec<SemanticValue>,
}

/// Send Go walk facts to the plan builder or capture relative slots for summary application.
pub(super) enum GoWalkOutput<'a, 'b> {
    Plan {
        builder: &'a mut PlanBuilder,
        nest: &'a Nest<'b>,
        cwd: Option<&'a str>,
        cwd_node: Option<ProvenanceRef>,
        depth: u64,
    },
    Capture(&'a mut GoSummaryCapture),
}

impl GoWalker<'_, '_> {
    /// Record Go source provenance for a byte span in the live plan.
    /// Summary capture returns a placeholder until the summary is applied.
    pub(super) fn record_go_source_provenance(&mut self, span: (u32, u32)) -> ProvenanceRef {
        match &mut self.out {
            GoWalkOutput::Plan { builder, .. } => builder.node(
                ProvenanceKind::SourceSpan {
                    start: span.0,
                    end: span.1,
                },
                self.scope.as_slice(),
            ),
            GoWalkOutput::Capture(_) => ProvenanceRef(0),
        }
    }

    /// Emit a Go effect with conservative request assurance.
    pub(super) fn emit_go_effect(
        &mut self,
        op: &str,
        resource: ResourceExpr,
        attrs: &[(&str, bool)],
        node: ProvenanceRef,
    ) {
        self.emit_go_effect_slot(op, resource, attrs, node);
    }

    /// Emit a Go effect from enabled boolean attributes and report its slot when retained.
    pub(super) fn emit_go_effect_slot(
        &mut self,
        op: &str,
        resource: ResourceExpr,
        attrs: &[(&str, bool)],
        node: ProvenanceRef,
    ) -> Option<u32> {
        let attributes = attrs
            .iter()
            .filter(|(_, on)| *on)
            .map(|(k, _)| (k.to_string(), AttrValue::Bool(true)))
            .collect();
        self.emit_go_prebuilt_effect(Effect {
            request_assurance: effinterp_proto::RequestAssurance::Conservative,
            id: Default::default(),
            operation: Operation::new(op),
            resource,
            attributes,
            modality: Modality::May,
            execution: effinterp_proto::ExecutionNodeRef(0),
            condition: None,
            realm: effinterp_proto::ExecutionRealm::Host,
            provenance: vec![node],
        })
    }

    pub(super) fn push_condition(&mut self, condition: effinterp_proto::Condition) {
        let mut condition = Some(condition);
        if let GoWalkOutput::Plan { builder, .. } = &mut self.out {
            builder.bind_source_condition(&mut condition);
        }
        self.conditions.push(condition.unwrap());
    }

    /// Add the current conditions to a prebuilt Go effect and report its slot
    /// in the receiving effect list so a transfer can pair its endpoints.
    pub(super) fn emit_go_prebuilt_effect(&mut self, mut effect: Effect) -> Option<u32> {
        effect.condition = effinterp_proto::Condition::compose(
            effect.condition.iter().chain(self.conditions.iter()),
        );
        if effect.operation.domain() == "filesystem" {
            effect.resource = anchor_fs_text_concat(
                effect.resource,
                match &self.out {
                    GoWalkOutput::Plan { cwd, .. } => {
                        cwd.map(|cwd| crate::paths::resolve_fs_path(cwd, None))
                    }
                    GoWalkOutput::Capture(_) => None,
                },
            );
        }
        let value = SemanticValue::from(&effect.resource);
        crate::lower_effect_value(&mut effect, &value);
        let uses_cwd =
            effect.operation.domain() == "filesystem" && fs_resource_uses_cwd(&effect.resource);
        match &mut self.out {
            GoWalkOutput::Plan {
                builder, cwd_node, ..
            } => {
                if uses_cwd {
                    effect.provenance.extend(*cwd_node);
                }
                builder.effect(effect)
            }
            GoWalkOutput::Capture(cap) => {
                if cap.effects.len() < MAX_SUMMARY_ITEMS {
                    cap.effects.push(effect);
                    Some(cap.effects.len() as u32 - 1)
                } else {
                    None
                }
            }
        }
    }

    /// Record that `source` is the source side of one modeled transfer whose
    /// destination side is `destination`, in whichever effect list received
    /// them.
    pub(super) fn record_transfer(&mut self, source: Option<u32>, destination: Option<u32>) {
        let (Some(source), Some(destination)) = (source, destination) else {
            return;
        };
        let binding = TransferBinding::new(source, destination);
        match &mut self.out {
            GoWalkOutput::Plan { builder, .. } => builder.transfer_binding(binding),
            GoWalkOutput::Capture(cap) => {
                if !cap.transfers.contains(&binding) {
                    cap.transfers.push(binding);
                }
            }
        }
    }

    pub(super) fn out_boundary(&mut self, boundary: Boundary) {
        match &mut self.out {
            GoWalkOutput::Plan { builder, .. } => {
                builder.boundary(boundary);
            }
            GoWalkOutput::Capture(cap) => cap.boundaries.push(boundary),
        }
    }

    pub(super) fn out_coverage(&mut self, domain: Domain, level: CoverageLevel) {
        match &mut self.out {
            GoWalkOutput::Plan { builder, .. } => builder.declare_coverage(domain, level),
            GoWalkOutput::Capture(cap) => cap.coverage.push((domain, level)),
        }
    }

    pub(super) fn nest_subject(&mut self, subject: Subject, node: ProvenanceRef) {
        match &mut self.out {
            GoWalkOutput::Plan {
                builder,
                nest,
                depth,
                ..
            } => nest.nest(
                builder,
                Transition::file(subject)
                    .source_cwd(nest.current_runtime_cwd().as_deref())
                    .runtime_cwd(nest.current_runtime_cwd().as_deref())
                    .cwd(builder.current_execution_cwd(), nest.current_cwd_node()),
                &[node],
                *depth,
            ),
            // A subprocess/SQL inside a summarized function needs the call
            // site's bindings to compose; record it as an opaque boundary.
            GoWalkOutput::Capture(_) => self.record_go_opaque_boundary(
                BoundaryReason::UNCOMPOSED_SUBPROCESS,
                BoundaryClass::Unmodeled,
                "process",
                node,
            ),
        }
    }

    /// Record an invocation-wide Go boundary for one affected domain.
    pub(super) fn record_go_opaque_boundary(
        &mut self,
        reason: BoundaryReason,
        class: BoundaryClass,
        domain: &str,
        node: ProvenanceRef,
    ) {
        self.out_boundary(Boundary {
            reason,
            class,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: vec![Domain::new(domain)],
            provenance: vec![node],
            limit: None,
            detail: None,
        });
    }

    pub(super) fn effects_len(&self) -> usize {
        match &self.out {
            GoWalkOutput::Plan { builder, .. } => builder.effects_len(),
            GoWalkOutput::Capture(cap) => cap.effects.len(),
        }
    }
}
