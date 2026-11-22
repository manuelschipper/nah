use effinterp_proto::{
    AttrValue, Boundary, BoundaryClass, BoundaryReason, BoundaryScope, Domain, Effect, Modality,
    Operation, ProvenanceRef, ResourceExpr, ResourceIdentity,
};

use crate::builder::PlanBuilder;
use crate::models::InvocationCtx;
use crate::models::args::scan_literal_flags;
use crate::models::common::{arg_node, boundary, environment_boundary};
use crate::value::unresolved_resource;
use crate::word::Word;

use super::super::aws_request_input::aws_request_shape;
use super::super::cloud_args::CLOUD_LITERAL_FLAGS;
use super::super::cloud_effects::{cloud_effect, cloud_request_effect, symbolic_cloud};
use super::{AZURE_DEVOPS, CloudResourceDelete, UNSTATED};

/// Identifies an AWS resource delete by its named flag, keeping an unspecified identity symbolic.
pub(in crate::models::cloud) fn aws_resource_delete_by_flag(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    provider: &str,
    service: &str,
    kind: &str,
    flag: &str,
) {
    let scanned = scan_literal_flags(ctx.argv, &CLOUD_LITERAL_FLAGS);
    let r = match scanned
        .values_of(&[flag])
        .first()
        .map(|(_, value)| *value)
        .and_then(Word::as_literal)
    {
        Some(id) => ResourceExpr::Concrete {
            identity: ResourceIdentity::CloudResource {
                scope: Box::new(effinterp_proto::cloud_scope(Some(provider), service, kind)),
                provider: Some(provider.into()),
                service: service.into(),
                kind: kind.into(),
                id: Some(id.to_string()),
            },
        },
        None => symbolic_cloud(),
    };
    cloud_effect(builder, ctx, model_node, 2, "cloud.resource.delete", r);
}

/// A reviewed cloud resource delete. A managed-database delete also records
/// whether a final snapshot is taken and whether automated backups outlive the resource, where
/// the options and the vendor's documentation establish them. Without an
/// established request the verb keeps its earlier handling: RDS instance
/// deletion and gcloud's SQL chain still emit their delete, the other verbs a
/// boundary. AWS skeleton generation sends no request at all.
pub(in crate::models::cloud) fn cloud_resource_delete_effect(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    delete: &CloudResourceDelete,
) {
    let shape = (delete.provider == "aws")
        .then(|| aws_request_shape(ctx.argv))
        .flatten();
    if shape == Some("skeleton") {
        environment_boundary(
            builder,
            model_node,
            BoundaryReason::REVIEWED_COMMAND_SURFACE,
            BoundaryClass::Unmodeled,
            &["cloud", "network"],
            "AWS CLI skeleton generation prints a request template and sends no request",
        );
        return;
    }
    // Readable input was expanded into options before dispatch; `AwsCommandModel::apply`
    // records the boundary for input it could not read.
    let request = if shape == Some("input") {
        None
    } else {
        delete.request(ctx.argv)
    };
    let qualified = |id: &str| delete.qualified.matches(id);
    let Some((arguments, ids, containers, read_from_file)) = request else {
        boundary(
            builder,
            model_node,
            BoundaryReason::PARTIAL_ANALYSIS,
            BoundaryClass::Unmodeled,
            &["cloud", "network"],
            "cloud resource delete options or identifier are unresolved",
        );
        match (delete.service, delete.kind) {
            ("rds", "db") => aws_resource_delete_by_flag(
                builder,
                ctx,
                model_node,
                "aws",
                "rds",
                "db",
                "--db-instance-identifier",
            ),
            ("sql", _) if delete.provider == "gcp" => cloud_effect(
                builder,
                ctx,
                model_node,
                *delete.path.last().unwrap() as u32,
                "cloud.resource.delete",
                symbolic_cloud(),
            ),
            _ => {}
        }
        return;
    };
    if arguments.unknown {
        boundary(
            builder,
            model_node,
            BoundaryReason::PARTIAL_ANALYSIS,
            BoundaryClass::Unmodeled,
            &["cloud", "network"],
            "cloud resource delete options or identifier are unresolved",
        );
    }
    if delete
        .keeps_data
        .is_some_and(|pair| arguments.switch(pair) == Some(true))
    {
        boundary(
            builder,
            model_node,
            BoundaryReason::PARTIAL_ANALYSIS,
            BoundaryClass::Unmodeled,
            &["cloud", "network"],
            "the request keeps the resource's data and deletes only its replicas",
        );
        return;
    }
    let mut attributes = std::collections::BTreeMap::new();
    if let (Some(pair), Some(final_snapshot)) = (delete.skip_final, delete.final_snapshot) {
        let skipped = arguments.switch(pair) == Some(true);
        let named = arguments.value(&[final_snapshot]).is_some();
        // Skipping while naming the final snapshot is a request error, and
        // naming neither is one for a standalone instance or cluster. An Aurora
        // cluster member takes neither, so the request says nothing about
        // backups then.
        if skipped == named {
            boundary(
                builder,
                model_node,
                BoundaryReason::PARTIAL_ANALYSIS,
                BoundaryClass::Unmodeled,
                &["cloud", "network"],
                "managed-database final snapshot choice is not established",
            );
        } else {
            attributes.insert("final_snapshot".to_string(), AttrValue::Bool(!skipped));
            match delete.automated_backups_retained(&arguments) {
                Some(retained) => {
                    attributes.insert(
                        "automated_backups_retained".to_string(),
                        AttrValue::Bool(retained),
                    );
                }
                None => environment_boundary(
                    builder,
                    model_node,
                    BoundaryReason::LIVE_INVENTORY,
                    BoundaryClass::Unmodeled,
                    &["cloud", "network"],
                    "automated-backup retention depends on cluster membership or account backup policy",
                ),
            }
        }
    }
    if let Some(flag) = delete.final_backup
        && arguments.switches.contains(&flag)
    {
        attributes.insert("final_backup".to_string(), AttrValue::Bool(true));
    }
    // The resource ID is its containing resources' names and its own, joined
    // by `/`. A fully qualified operand is the whole ID; the containers it
    // names replace any given separately. A container the CLI takes from its
    // configuration is left out of the ID.
    if containers.contains(&None) && !ids.iter().all(|id| qualified(id)) {
        boundary(
            builder,
            model_node,
            BoundaryReason::PARTIAL_ANALYSIS,
            BoundaryClass::Unmodeled,
            &["cloud", "network"],
            "the containing resource is not named in the arguments",
        );
    }
    let names = || ids.iter().chain(containers.iter().flatten());
    // Snapshot and backup verbs keep such a name as written; the resource it
    // names is still the file's content.
    if names().any(|name| delete.names_file(name)) {
        builder.boundary(Boundary {
            reason: BoundaryReason::INPUT_DETERMINED_ARGUMENTS,
            class: BoundaryClass::Unresolved,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: vec![Domain::new("cloud"), Domain::new("network")],
            provenance: vec![model_node],
            limit: None,
            detail: Some("the CLI reads the resource name from a file Nah does not read".into()),
        });
    }
    if names().any(|name| *name == UNSTATED) {
        builder.boundary(Boundary {
            reason: if read_from_file {
                BoundaryReason::INPUT_DETERMINED_ARGUMENTS
            } else {
                BoundaryReason::PARTIAL_ANALYSIS
            },
            class: BoundaryClass::Unresolved,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: vec![Domain::new("cloud"), Domain::new("network")],
            provenance: vec![model_node],
            limit: None,
            detail: Some(if read_from_file {
                "the CLI reads the resource name from a file Nah does not read".into()
            } else {
                "the cloud resource name is an expansion".into()
            }),
        });
    }
    // Every word is one this verb documents and every name is literal, so the
    // request is the one argv states: help, dry runs and unread input never
    // reach here, and an undocumented option may change what it selects.
    let request_assurance = if delete.stated(&arguments, &ids, &containers) {
        effinterp_proto::RequestAssurance::Exact
    } else {
        effinterp_proto::RequestAssurance::Conservative
    };
    for id in ids {
        // The request names one resource of this kind whatever its name.
        let id = if id == UNSTATED
            || !qualified(id) && containers.iter().flatten().any(|name| *name == UNSTATED)
        {
            None
        } else if qualified(id) {
            Some(id.to_string())
        } else {
            Some(
                containers
                    .iter()
                    .flatten()
                    .copied()
                    .chain([id])
                    .collect::<Vec<_>>()
                    .join("/"),
            )
        };
        let resource = ResourceExpr::Concrete {
            identity: ResourceIdentity::CloudResource {
                scope: Box::new(effinterp_proto::cloud_scope(
                    Some(delete.provider),
                    delete.service,
                    delete.kind,
                )),
                provider: Some(delete.provider.into()),
                service: delete.service.into(),
                kind: delete.kind.into(),
                id,
            },
        };
        cloud_request_effect(
            builder,
            ctx,
            model_node,
            *delete.path.last().unwrap() as u32,
            "cloud.resource.delete",
            resource,
            false,
            false,
            true,
            attributes.clone(),
            None,
            request_assurance,
        );
    }
}

/// A reviewed azure-devops extension delete, stated as the hosted request it
/// sends. A repository or team project delete removes whole repositories; a
/// pipeline, or a work item deleted with `--destroy`, is a resource inside a
/// project. Without `--destroy` a work item only moves to the recycle bin.
/// The CLI asks before deleting and, with no terminal to ask on, refuses
/// without `--yes`, so only a confirmed request surely deletes.
pub(in crate::models::cloud) fn azure_devops_delete(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    delete: &CloudResourceDelete,
) {
    let Some((arguments, ids, containers, _)) = delete.request(ctx.argv) else {
        boundary(
            builder,
            model_node,
            BoundaryReason::PARTIAL_ANALYSIS,
            BoundaryClass::Unmodeled,
            &["network"],
            "Azure DevOps delete options or identifier are unresolved",
        );
        return;
    };
    if delete.kind == "work_item" && !arguments.switches.contains(&"--destroy") {
        boundary(
            builder,
            model_node,
            BoundaryReason::UNMODELED_SUBCOMMAND,
            BoundaryClass::Unmodeled,
            &["network"],
            "a work item deleted without --destroy moves to the recycle bin",
        );
        return;
    }
    let stated = delete.stated(&arguments, &ids, &containers);
    if !stated {
        boundary(
            builder,
            model_node,
            BoundaryReason::PARTIAL_ANALYSIS,
            BoundaryClass::Unmodeled,
            &["network"],
            "Azure DevOps delete options or identifier are unresolved",
        );
    }
    let repository = matches!(delete.kind, "repository" | "project");
    // Whatever repository an expansion names, the request deletes a whole one.
    let exact = stated || repository && !arguments.unknown && arguments.ambiguous.is_empty();
    let text = |value: &str| AttrValue::String(value.into());
    let mut attributes = std::collections::BTreeMap::from([
        ("method".to_string(), text("DELETE")),
        ("delete".to_string(), AttrValue::Bool(true)),
        ("hosted_provider".to_string(), text(AZURE_DEVOPS)),
        (
            "hosted_target_kind".to_string(),
            text(if repository { "repository" } else { "resource" }),
        ),
        ("hosted_object_kind".to_string(), text(delete.kind)),
        (
            "hosted_scope".to_string(),
            text(if delete.kind == "project" {
                "organization"
            } else {
                "project"
            }),
        ),
    ]);
    if ids[0] != UNSTATED {
        attributes.insert("hosted_target".to_string(), text(ids[0]));
    }
    let confirmed = arguments
        .switches
        .iter()
        .any(|flag| matches!(*flag, "--yes" | "-y"));
    let provenance = vec![
        arg_node(builder, ctx, *delete.path.last().unwrap() as u32),
        model_node,
    ];
    builder.effect(Effect {
        request_assurance: if exact {
            effinterp_proto::RequestAssurance::Exact
        } else {
            effinterp_proto::RequestAssurance::Conservative
        },
        id: Default::default(),
        operation: Operation::new("network.delete_request"),
        resource: unresolved_resource("network"),
        attributes,
        modality: if confirmed {
            Modality::MustOnSuccess
        } else {
            Modality::May
        },
        realm: effinterp_proto::ExecutionRealm::Host,
        condition: None,
        execution: effinterp_proto::ExecutionNodeRef(0),
        provenance,
    });
}
