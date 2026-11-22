use std::collections::BTreeMap;

use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, BoundaryScope, Domain, ProvenanceRef, ResourceExpr,
};

use crate::builder::PlanBuilder;
use crate::models::InvocationCtx;
use crate::word::Word;

/// Record an unresolved socket handler when its command cannot be recovered.
pub(super) fn socket_handler_boundary(
    builder: &mut PlanBuilder,
    provenance: &[ProvenanceRef],
    detail: &str,
) {
    builder.boundary(Boundary {
        reason: BoundaryReason::UNRECOVERABLE_SOURCE,
        class: BoundaryClass::Unresolved,
        scope: BoundaryScope::Invocation,
        affected_resource: None,
        callee: None,
        domains: crate::builder::KNOWN_DOMAINS
            .iter()
            .map(|domain| Domain::new(*domain))
            .collect(),
        provenance: provenance.to_vec(),
        limit: None,
        detail: Some(detail.into()),
    });
}

/// A socket handler's stdin and stdout belong to the connection. Its effects stay
/// optional because the peer may never arrive.
#[allow(clippy::too_many_arguments)]
pub(super) fn analyze_socket_handler(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    provenance: &[ProvenanceRef],
    subject: effinterp_proto::Subject,
    input: Option<u32>,
    output: Option<u32>,
    environment: BTreeMap<String, Option<ResourceExpr>>,
    stderr_to_output: bool,
    // The directory the handler starts in, as a repository- or host-anchored
    // base for resolving its script source. `None` means the handler's cwd is
    // unknown, so a relative source cannot be found rather than falling back to
    // the parent's file.
    runtime_cwd: Option<&str>,
) {
    use crate::flow::{BindEnd, FlowStage, PortBinding};
    use effinterp_proto::{ExecutionEdgeKind, ExecutionStreams, Port};
    // With socat's `stderr` option the handler's standard error is the
    // connection, not socat's own.
    let stderr = if stderr_to_output {
        Default::default()
    } else {
        builder.inherited_execution_streams().stderr
    };
    // A handler that changes directory (`chdir=`) starts there, not in
    // socat's own cwd.
    let subject_cwd = match &subject {
        effinterp_proto::Subject::Exec { cwd, .. }
        | effinterp_proto::Subject::Shell { cwd, .. } => cwd.as_deref(),
        _ => ctx.cwd,
    };
    let cwd = match subject_cwd {
        Some(path) if subject_cwd != ctx.cwd => Some(ctx.resolve_fs_word(&Word::literal(path))),
        _ => ctx.cwd_resource(),
    };
    let transition = crate::nest::Transition::file(subject.clone())
        .kind(ExecutionEdgeKind::Launch)
        .cwd(cwd, ctx.cwd_node)
        .runtime_cwd(runtime_cwd)
        .environment(environment, BTreeMap::new(), Default::default())
        .streams(ExecutionStreams {
            stderr,
            ..Default::default()
        });
    let Some(frame) = ctx.nest.begin(builder, transition, provenance, ctx.depth) else {
        return;
    };
    crate::nest::analyze_subject(
        builder,
        ctx.nest,
        &subject,
        Some(frame.scope),
        ctx.cwd_node,
        ctx.depth + 1,
    );
    let mut bindings = Vec::new();
    if let Some(effect) = input {
        bindings.push(PortBinding {
            assurance: effinterp_proto::CausalAssurance::Exact,
            from: BindEnd::Effect(effect),
            to: BindEnd::Port(Port::Stdin),
        });
    }
    if let Some(effect) = output {
        let ports = if stderr_to_output {
            &[Port::Stdout, Port::Stderr][..]
        } else {
            &[Port::Stdout][..]
        };
        for port in ports {
            bindings.push(PortBinding {
                assurance: effinterp_proto::CausalAssurance::Exact,
                from: BindEnd::Port(port.clone()),
                to: BindEnd::Effect(effect),
            });
        }
    }
    builder.flow_stage(FlowStage {
        execution: Some(frame.execution),
        effects: input.into_iter().chain(output).collect(),
        bindings,
        provenance: provenance.to_vec(),
    });
    frame.end(builder);
}
