use effinterp_proto::{
    AttrValue, BoundaryClass, BoundaryReason, Effect, Modality, Operation, ProvenanceRef,
    ResourceExpr, ResourceIdentity,
};

use crate::builder::PlanBuilder;
use crate::models::InvocationCtx;
use crate::models::common::{arg_node, boundary, environment_boundary};
use crate::word::Word;

use super::cloud_args::aws_service_after_globals;
use super::cloud_effects::{cloud_network_effect, symbolic_cloud};
use super::cloud_scope::apply_cloud_scope;
use super::resource_delete::aws_resource_delete_by_flag;

/// EC2 lifecycle requests distinguish permission checks from operations that change the instance.
pub(super) fn ec2_lifecycle(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model: ProvenanceRef,
    verb_index: usize,
) {
    // Snapshots and volumes carry their own identifier flag instead of the
    // instance-id list the instance lifecycle verbs share.
    if let Some((kind, flag)) = match ctx.argv.get(verb_index).and_then(Word::as_literal) {
        Some("delete-snapshot") => Some(("snapshot", "--snapshot-id")),
        Some("delete-volume") => Some(("volume", "--volume-id")),
        _ => None,
    } {
        aws_resource_delete_by_flag(builder, ctx, model, "aws", "ec2", kind, flag);
        return;
    }
    let operation = match ctx.argv.get(verb_index).and_then(Word::as_literal) {
        Some("run-instances") => "cloud.resource.create",
        Some("describe-instances") => "cloud.resource.read",
        Some("create-tags") => "cloud.resource.update",
        Some("start-instances") => "cloud.resource.start",
        Some("stop-instances") => "cloud.resource.stop",
        Some("reboot-instances") => "cloud.resource.restart",
        Some("terminate-instances") => "cloud.resource.delete",
        _ => {
            boundary(
                builder,
                model,
                BoundaryReason::UNMODELED_SUBCOMMAND,
                BoundaryClass::Unmodeled,
                &["cloud", "network"],
                "aws ec2 subcommand",
            );
            return;
        }
    };
    let mut ids = Vec::new();
    let mut dry_run = false;
    let mut skeleton = false;
    let mut uncertain = false;
    // An option the lifecycle verbs share but termination does not document,
    // or an unresolved word among the instance IDs, which may be an option
    // (`--instance-ids i-1 "$EXTRA"` with `EXTRA=--dry-run`).
    let mut unread = false;
    let mut i = verb_index + 1;
    while i < ctx.argv.len() {
        let word = &ctx.argv[i];
        let raw = word.render_raw();
        let (flag, assigned) = word
            .split_assignment()
            .map_or((raw.as_str(), None), |(flag, value)| (flag, Some(value)));
        match flag {
            "--dry-run" => {
                dry_run = assigned.is_none()
                    || assigned.as_ref().and_then(Word::as_literal) == Some("true");
                if assigned
                    .as_ref()
                    .is_some_and(|v| !matches!(v.as_literal(), Some("true" | "false")))
                {
                    uncertain = true;
                }
            }
            "--no-dry-run" => dry_run = false,
            "--generate-cli-skeleton" => {
                skeleton = true;
                if assigned.is_none()
                    && ctx.argv.get(i + 1).is_some_and(|w| {
                        matches!(w.as_literal(), Some("input" | "output" | "yaml-input"))
                    })
                {
                    i += 1;
                }
            }
            "--instance-ids" | "--resources" => {
                let resources = flag == "--resources";
                unread |= resources;
                // argparse stores a list option, so a repeated one replaces
                // the earlier list rather than adding to it.
                ids.retain(|(list, _, _)| *list != resources);
                if let Some(value) = assigned {
                    unread |= value.as_literal().is_none();
                    ids.push((resources, i as u32, value));
                } else {
                    let start = i;
                    i += 1;
                    while i < ctx.argv.len() && !ctx.argv[i].render_raw().starts_with('-') {
                        unread |= ctx.argv[i].as_literal().is_none();
                        ids.push((resources, i as u32, ctx.argv[i].clone()));
                        i += 1;
                    }
                    if i == start + 1 {
                        uncertain = true;
                    }
                    continue;
                }
            }
            "--tags" => {
                unread = true;
                if assigned.is_none() {
                    let start = i;
                    i += 1;
                    while i < ctx.argv.len() && !ctx.argv[i].render_raw().starts_with('-') {
                        i += 1;
                    }
                    if i == start + 1 {
                        uncertain = true;
                    }
                    continue;
                }
            }
            "--region"
            | "--endpoint-url"
            | "--profile"
            | "--image-id"
            | "--count"
            | "--min-count"
            | "--max-count"
            | "--instance-type"
            | "--key-name"
            | "--subnet-id"
            | "--output"
            | "--query"
            | "--cli-read-timeout"
            | "--cli-connect-timeout" => {
                unread |= matches!(
                    flag,
                    "--image-id"
                        | "--count"
                        | "--min-count"
                        | "--max-count"
                        | "--instance-type"
                        | "--key-name"
                        | "--subnet-id"
                );
                if assigned.is_none() {
                    if ctx
                        .argv
                        .get(i + 1)
                        .is_some_and(|w| !w.render_raw().starts_with('-'))
                    {
                        i += 1;
                    } else {
                        uncertain = true;
                    }
                }
            }
            "--force"
            | "--no-force"
            | "--hibernate"
            | "--no-hibernate"
            | "--skip-os-shutdown"
            | "--no-skip-os-shutdown"
            | "--no-cli-pager"
            | "--no-paginate"
            | "--no-sign-request"
            | "--no-verify-ssl" => unread |= matches!(flag, "--hibernate" | "--no-hibernate"),
            _ => {
                uncertain = true;
                break;
            }
        }
        i += 1;
    }
    let mut provenance = vec![model];
    for index in 1..ctx.argv.len() {
        provenance.push(arg_node(builder, ctx, index as u32));
    }
    if uncertain {
        boundary(
            builder,
            model,
            BoundaryReason::PARTIAL_ANALYSIS,
            BoundaryClass::Unmodeled,
            &["cloud", "network"],
            "EC2 options, input indirection or required values are unresolved",
        );
    }
    for word in ctx.argv.iter().skip(verb_index + 1) {
        match word.as_literal() {
            Some("--dry-run" | "--dry-run=true") => dry_run = true,
            Some("--no-dry-run" | "--dry-run=false") => dry_run = false,
            Some(value)
                if value == "--generate-cli-skeleton"
                    || value.starts_with("--generate-cli-skeleton=") =>
            {
                skeleton = true
            }
            _ => {}
        }
    }
    if skeleton {
        return;
    }
    cloud_network_effect(
        builder,
        ctx,
        &provenance,
        &symbolic_cloud(),
        "network.request",
    );
    if dry_run && operation != "cloud.resource.read" {
        return;
    }
    if ids.is_empty() || operation == "cloud.resource.create" {
        crate::models::infrastructure::emit(builder, &provenance, operation, symbolic_cloud());
        if operation == "cloud.resource.create" || operation == "cloud.resource.read" {
            environment_boundary(
                builder,
                model,
                BoundaryReason::LIVE_INVENTORY,
                BoundaryClass::Unmodeled,
                &["cloud", "network"],
                "EC2 created identities or instance inventory are unresolved",
            );
        } else {
            boundary(
                builder,
                model,
                BoundaryReason::PARTIAL_ANALYSIS,
                BoundaryClass::Unmodeled,
                &["cloud", "network"],
                "EC2 created identities or instance inventory are unresolved",
            );
        }
        return;
    }
    // An ID read from a file, JSON or an empty word is input Nah does not
    // read, so no instance in that effective list is an exact target.
    let instance_id = |word: &Word| {
        word.as_literal()
            .filter(|id| {
                !id.is_empty()
                    && !id.starts_with(['[', '{'])
                    && !id.starts_with("file://")
                    && !id.starts_with("fileb://")
                    && !id.chars().any(char::is_whitespace)
            })
            .map(str::to_string)
    };
    let ids_readable = ids.iter().all(|(_, _, word)| instance_id(word).is_some());
    for (_, _, word) in ids {
        let id = instance_id(&word);
        let id = id.as_deref();
        if id.is_none() {
            boundary(
                builder,
                model,
                BoundaryReason::PARTIAL_ANALYSIS,
                BoundaryClass::Unmodeled,
                &["cloud", "network"],
                "EC2 resource ID input is symbolic or indirect",
            );
        }
        let mut resource = id.map_or_else(symbolic_cloud, |id| ResourceExpr::Concrete {
            identity: ResourceIdentity::CloudResource {
                scope: Box::new(effinterp_proto::cloud_scope(
                    Some("aws"),
                    "ec2",
                    if operation == "cloud.resource.update" && !id.starts_with("i-") {
                        "resource"
                    } else {
                        "instance"
                    },
                )),
                provider: Some("aws".into()),
                service: "ec2".into(),
                kind: if operation == "cloud.resource.update" && !id.starts_with("i-") {
                    "resource"
                } else {
                    "instance"
                }
                .into(),
                id: Some(id.into()),
            },
        });
        let mut provenance = provenance.clone();
        apply_cloud_scope(builder, ctx, &mut provenance, &mut resource);
        let mut attributes = std::collections::BTreeMap::new();
        if operation == "cloud.resource.update" {
            attributes.insert("tag_update".into(), AttrValue::Bool(true));
        }
        // A termination whose every word was read as an option termination
        // documents and whose effective instance list is literal is the
        // request argv states.
        let request_assurance = if operation == "cloud.resource.delete"
            && !uncertain
            && !unread
            && ids_readable
            && aws_service_after_globals(ctx.argv) == Some(verb_index - 1)
        {
            effinterp_proto::RequestAssurance::Exact
        } else {
            effinterp_proto::RequestAssurance::Conservative
        };
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
        });
    }
}
