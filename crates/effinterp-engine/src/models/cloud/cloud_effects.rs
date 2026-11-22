use effinterp_proto::{AttrValue, Effect, Modality, Operation, ProvenanceRef, ResourceExpr};

use crate::builder::PlanBuilder;
use crate::models::InvocationCtx;
use crate::models::common::arg_node;
use crate::resource_transfer::TransferBinding;
use crate::value::unresolved_resource;

use super::cloud_scope::{apply_cloud_scope, cloud_environment};

/// One object-store interaction. The returned slot lets a transfer emitter
/// pair the endpoint it just produced.
#[allow(clippy::too_many_arguments)]
pub(super) fn object_store_effect(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    index: u32,
    operation: &str,
    resource: ResourceExpr,
    recursive: bool,
    delete: bool,
    connect: bool,
    attributes: std::collections::BTreeMap<String, AttrValue>,
) -> Option<u32> {
    object_store_upload_effect(
        builder, ctx, model_node, index, operation, resource, recursive, delete, connect,
        attributes, None,
    )
}

/// An object-store interaction that may also upload local bytes: the CLI
/// sends what the `upload` reads produced to the provider's endpoint, so the
/// write carries a `network.upload` on that endpoint, bound to each read, as
/// scp's remote destination does. An empty list still uploads (stdin).
#[allow(clippy::too_many_arguments)]
pub(super) fn object_store_upload_effect(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    index: u32,
    operation: &str,
    resource: ResourceExpr,
    recursive: bool,
    delete: bool,
    connect: bool,
    attributes: std::collections::BTreeMap<String, AttrValue>,
    upload: Option<&[u32]>,
) -> Option<u32> {
    cloud_request_effect(
        builder,
        ctx,
        model_node,
        index,
        operation,
        resource,
        recursive,
        delete,
        connect,
        attributes,
        upload,
        effinterp_proto::RequestAssurance::Conservative,
    )
}

/// `object_store_upload_effect` with the request assurance its caller established.
#[allow(clippy::too_many_arguments)]
pub(super) fn cloud_request_effect(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    index: u32,
    operation: &str,
    resource: ResourceExpr,
    recursive: bool,
    delete: bool,
    connect: bool,
    mut attributes: std::collections::BTreeMap<String, AttrValue>,
    upload: Option<&[u32]>,
    request_assurance: effinterp_proto::RequestAssurance,
) -> Option<u32> {
    let arg = arg_node(builder, ctx, index);
    let mut provenance = vec![arg, model_node];
    let mut resource = resource;
    apply_cloud_scope(builder, ctx, &mut provenance, &mut resource);
    if connect {
        cloud_network_effect(builder, ctx, &provenance, &resource, "network.connect");
    }
    if let Some(sources) = upload
        && let Some(sink) =
            cloud_network_effect(builder, ctx, &provenance, &resource, "network.upload")
    {
        for source in sources {
            builder.transfer_binding(TransferBinding::new(*source, sink));
        }
    }
    if recursive {
        attributes.insert(
            "recursive".to_string(),
            effinterp_proto::AttrValue::Bool(true),
        );
    }
    if delete {
        attributes.insert("delete".to_string(), AttrValue::Bool(true));
    }
    builder.effect(Effect {
        request_assurance,
        id: Default::default(),
        operation: Operation::new(operation),
        resource,
        attributes,
        modality: Modality::May,
        realm: effinterp_proto::ExecutionRealm::Host,
        condition: None,
        execution: effinterp_proto::ExecutionNodeRef(0),
        provenance,
    })
}

/// Cloud effects scope the resource first and record the connection before the cloud operation.
pub(super) fn cloud_effect(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    index: u32,
    operation: &str,
    resource: ResourceExpr,
) {
    let arg = arg_node(builder, ctx, index);
    let mut provenance = vec![arg, model_node];
    let mut resource = resource;
    apply_cloud_scope(builder, ctx, &mut provenance, &mut resource);
    if operation.starts_with("network.") {
        cloud_network_effect(builder, ctx, &provenance, &resource, operation);
        return;
    }
    if operation.starts_with("cloud.") {
        cloud_network_effect(builder, ctx, &provenance, &resource, "network.connect");
    }
    builder.effect(Effect {
        request_assurance: effinterp_proto::RequestAssurance::Conservative,
        id: Default::default(),
        operation: Operation::new(operation),
        resource,
        attributes: Default::default(),
        modality: Modality::May,
        realm: effinterp_proto::ExecutionRealm::Host,
        condition: None,
        execution: effinterp_proto::ExecutionNodeRef(0),
        provenance,
    });
}

/// A symbolic cloud resource of an unknown identity, for a non-literal target.
pub(super) fn symbolic_cloud() -> ResourceExpr {
    unresolved_resource("cloud")
}

/// Cloud network effects inherit endpoint evidence from the affected resource's scope.
pub(super) fn cloud_network_effect(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    provenance: &[ProvenanceRef],
    resource: &ResourceExpr,
    operation: &str,
) -> Option<u32> {
    let mut provenance = provenance.to_vec();
    let mut scope =
        effinterp_proto::ResourceScope::new(effinterp_proto::NamespaceKind::Unsupported);
    fn collect(scope: &mut effinterp_proto::ResourceScope, resource: &ResourceExpr) {
        match resource {
            ResourceExpr::Concrete { identity } => {
                if let Some(source) = identity.scope() {
                    scope.access.extend(source.access.clone());
                }
            }
            ResourceExpr::Join { parts }
            | ResourceExpr::Union {
                alternatives: parts,
            } => {
                for part in parts {
                    collect(scope, part);
                }
            }
            _ => {}
        }
    }
    collect(&mut scope, resource);
    if scope.access.is_empty()
        && ctx.argv[0]
            .as_literal()
            .and_then(|command| command.rsplit('/').next())
            == Some("aws")
    {
        if let Some(endpoint) = crate::models::scope::scope_option(
            builder,
            ctx,
            &mut provenance,
            &["--endpoint-url"],
            true,
            "network",
        ) {
            crate::models::scope::endpoint_evidence(
                &mut scope,
                effinterp_proto::ScopeEvidenceKind::Endpoint,
                endpoint,
            );
        } else {
            // Preserve the same supplied endpoint evidence as the cloud resource scope.
            for name in [
                "AWS_ENDPOINT_URL",
                "AWS_ENDPOINT_URL_S3",
                "AWS_ENDPOINT_URL_EC2",
                "AWS_ENDPOINT_URL_RDS",
            ] {
                if let Some(endpoint) = cloud_environment(builder, ctx, &mut provenance, name) {
                    crate::models::scope::endpoint_evidence(
                        &mut scope,
                        effinterp_proto::ScopeEvidenceKind::Endpoint,
                        effinterp_proto::ScopeValue::value(endpoint),
                    );
                    crate::models::scope::scope_boundary(builder, &provenance, "network");
                }
            }
        }
    }
    crate::models::infrastructure::emit(
        builder,
        &provenance,
        operation,
        crate::models::scope::network_resource(&scope),
    )
}
