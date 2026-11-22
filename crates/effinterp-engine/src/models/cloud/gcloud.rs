use effinterp_proto::{
    AttrValue, BoundaryClass, BoundaryReason, ProvenanceRef, ResourceExpr, ResourceIdentity,
};

use crate::builder::PlanBuilder;
use crate::models::args::{FlagSpec, scan_literal_flags};
use crate::models::common::{Attrs, boundary};
use crate::models::{CommandModel, InvocationCtx, credential};
use crate::value::unresolved_resource;
use crate::word::Word;

use super::cloud_args::{
    CLOUD_LITERAL_FLAGS, CLOUD_SCOPE_FLAGS, GCLOUD_COMMON_VALUES, cloud_has_short_option,
    cloud_operands,
};
use super::cloud_coverage::declare_cloud_common;
use super::cloud_effects::{cloud_effect, object_store_effect, symbolic_cloud};
use super::object_store_target::object_store_target;
use super::object_store_transfer::{object_store_stdin_upload, object_store_transfer};
use super::remote_commands::gcloud_ssh;
use super::resource_delete::{
    cloud_resource_delete, cloud_resource_delete_effect, cloud_resource_delete_resolved,
};

/// Whether the command group is `secrets`, on the GA, alpha or beta track.
/// Global flags may sit on either side of the track.
fn gcloud_secrets_group(argv: &[Word]) -> bool {
    let command = crate::models::scope::command_position(argv, CLOUD_SCOPE_FLAGS);
    let group = |start: usize| {
        argv.get(start..).and_then(|rest| {
            rest.get(crate::models::scope::command_position(
                rest,
                CLOUD_SCOPE_FLAGS,
            ))
            .and_then(Word::as_literal)
        })
    };
    match argv.get(command).and_then(Word::as_literal) {
        Some("secrets") => true,
        Some("alpha" | "beta") => group(command) == Some("secrets"),
        _ => false,
    }
}

/// The argv index of a Cloud SQL backup restore's verb, on any track. A
/// restore replaces the data of the existing instance it restores to, which
/// `gcloud sql backups restore` names with its required --restore-instance and
/// `sql instances restore-backup` as its operand beside the required
/// --backup-id. The db family has no Cloud SQL instance identity, so the
/// overwritten data stays unresolved.
fn gcloud_sql_restore(argv: &[Word]) -> Option<usize> {
    let global_values: Vec<&str> = GCLOUD_COMMON_VALUES
        .iter()
        .chain(CLOUD_SCOPE_FLAGS)
        .copied()
        .collect();
    let words: Vec<usize> = crate::models::args::scan_detached(
        argv,
        &FlagSpec {
            value_flags: &global_values,
            known_flags: &[],
            allow_abbreviation: false,
        },
        false,
    )
    .operands
    .iter()
    .map(|(index, _)| *index as usize)
    .collect();
    let at = |offset: usize| {
        words
            .get(offset)
            .and_then(|&index| argv[index].as_literal())
    };
    let track = usize::from(matches!(at(0), Some("alpha" | "beta")));
    let required = match (at(track), at(track + 1), at(track + 2)) {
        (Some("sql"), Some("backups"), Some("restore")) => "--restore-instance",
        (Some("sql"), Some("instances"), Some("restore-backup")) => "--backup-id",
        _ => return None,
    };
    // An attached value may be an expansion (`--restore-instance="$X"`).
    let given = |flag: &str| {
        argv.iter().any(|word| {
            word.as_literal() == Some(flag)
                || word
                    .literal_prefix()
                    .strip_prefix(flag)
                    .is_some_and(|rest| rest.starts_with('='))
        })
    };
    (given(required) && !given("--help") && !given("-h")).then(|| words[track + 2])
}

/// gcloud dispatch checks reviewed delete grammars across GA, alpha, and beta tracks.
pub(super) struct GcloudCommandModel;

impl CommandModel for GcloudCommandModel {
    fn domains(&self) -> &'static [&'static str] {
        &crate::builder::KNOWN_DOMAINS
    }

    fn id(&self) -> &'static str {
        "cloud/gcloud@v0"
    }
    fn command_names(&self) -> &'static [&'static str] {
        &["gcloud"]
    }
    // `gcloud secrets versions access` prints the value it reads.
    fn causal_bindings(&self, argv: &[Word]) -> Vec<crate::models::ModelCausalBinding> {
        if gcloud_secrets_group(argv) {
            credential::read_output(false)
        } else {
            object_store_stdin_upload(argv)
        }
    }
    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        let scanned = scan_literal_flags(ctx.argv, &CLOUD_LITERAL_FLAGS);
        if gcloud_secrets_group(ctx.argv) {
            let covered = credential::gcloud_secrets(builder, ctx, model_node);
            declare_cloud_common(builder, ctx, model_node, covered);
            return;
        }
        declare_cloud_common(
            builder,
            ctx,
            model_node,
            cloud_resource_delete_resolved(ctx.argv),
        );
        // `--help` or `-h` anywhere before `--` prints the command's help and
        // runs nothing else.
        let help = ctx
            .argv
            .iter()
            .skip(1)
            .take_while(|word| word.as_literal() != Some("--"))
            .any(|word| matches!(word.as_literal(), Some("--help" | "-h")));
        if help || ctx.argv.get(1).and_then(Word::as_literal) == Some("--version") {
            return;
        }
        if let Some(delete) = cloud_resource_delete(ctx.argv) {
            cloud_resource_delete_effect(builder, ctx, model_node, &delete);
            return;
        }
        if let Some(verb) = gcloud_sql_restore(ctx.argv) {
            object_store_effect(
                builder,
                ctx,
                model_node,
                verb as u32,
                "database.write",
                unresolved_resource("db"),
                false,
                false,
                true,
                Attrs::from([("action".into(), AttrValue::String("overwrite".into()))]),
            );
            return;
        }
        let argv = ctx.argv;
        let command = crate::models::scope::command_position(argv, CLOUD_SCOPE_FLAGS);
        let group = argv.get(command).and_then(Word::as_literal);
        match group {
            // `gcloud storage cp|mv` recurse with -r, -R or --recursive.
            Some("storage")
                if matches!(
                    argv.get(command + 1).and_then(Word::as_literal),
                    Some("cp" | "mv")
                ) =>
            {
                object_store_transfer(
                    builder,
                    ctx,
                    model_node,
                    command + 2,
                    false,
                    scanned.has(&["--recursive"])
                        || cloud_has_short_option(argv, command + 2, &['r', 'R']),
                );
            }
            // Without -r, rsync still uploads the source's top-level files, so
            // its read covers the whole directory.
            Some("storage")
                if argv.get(command + 1).and_then(Word::as_literal) == Some("rsync") =>
            {
                object_store_transfer(
                    builder,
                    ctx,
                    model_node,
                    command + 2,
                    scanned.has(&["--delete-unmatched-destination-objects"]),
                    true,
                );
            }
            Some("storage") => {
                if argv.get(command + 1).and_then(Word::as_literal) == Some("buckets")
                    && argv.get(command + 2).and_then(Word::as_literal) == Some("delete")
                {
                    for (index, target) in cloud_operands(argv, command + 3) {
                        object_store_effect(
                            builder,
                            ctx,
                            model_node,
                            index,
                            "cloud.object.delete",
                            object_store_target(target).unwrap_or_else(symbolic_cloud),
                            false,
                            false,
                            true,
                            Default::default(),
                        );
                    }
                } else if argv.get(command + 1).and_then(Word::as_literal) == Some("rm") {
                    // `gcloud storage rm` spells its recursion -r, -R or
                    // --recursive; without it a prefix keeps its objects.
                    let recursive = scanned.has(&["--recursive"])
                        || cloud_has_short_option(argv, command + 2, &['r', 'R']);
                    for (i, w) in cloud_operands(
                        argv,
                        crate::models::scope::command_position(argv, CLOUD_SCOPE_FLAGS) + 2,
                    ) {
                        if let Some(r) = object_store_target(w) {
                            object_store_effect(
                                builder,
                                ctx,
                                model_node,
                                i,
                                "cloud.object.delete",
                                r,
                                recursive,
                                false,
                                true,
                                Default::default(),
                            );
                        } else {
                            object_store_effect(
                                builder,
                                ctx,
                                model_node,
                                i,
                                "cloud.object.delete",
                                symbolic_cloud(),
                                false,
                                false,
                                true,
                                Default::default(),
                            );
                        }
                    }
                } else {
                    boundary(
                        builder,
                        model_node,
                        BoundaryReason::UNMODELED_SUBCOMMAND,
                        BoundaryClass::Unmodeled,
                        &["cloud", "network"],
                        "gcloud storage subcommand",
                    );
                }
            }
            Some("compute") => {
                if argv.get(command + 1).and_then(Word::as_literal) == Some("ssh") {
                    gcloud_ssh(builder, ctx, model_node, Some(3), 4, None);
                } else {
                    let collection = argv
                        .get(command + 1)
                        .and_then(Word::as_literal)
                        .unwrap_or("unknown-subtype");
                    let kind = if collection == "instances" {
                        "instance"
                    } else {
                        collection
                    };
                    resource_delete_chain(builder, ctx, model_node, "gcp", "compute", kind)
                }
            }
            Some("cloud-shell")
                if argv.get(command + 1).and_then(Word::as_literal) == Some("ssh") =>
            {
                gcloud_ssh(builder, ctx, model_node, None, 3, Some("cloud-shell"));
            }
            // Cloud SQL's documented deletes are `cloud_resource_delete`'s. Any other
            // `delete` word names no resource Nah can place, so it keeps an
            // unresolved delete.
            Some("sql") => match argv.iter().position(|w| w.as_literal() == Some("delete")) {
                Some(pos) => {
                    boundary(
                        builder,
                        model_node,
                        BoundaryReason::UNMODELED_SUBCOMMAND,
                        BoundaryClass::Unmodeled,
                        &["cloud", "network"],
                        "gcloud sql delete outside its documented verbs",
                    );
                    cloud_effect(
                        builder,
                        ctx,
                        model_node,
                        pos as u32,
                        "cloud.resource.delete",
                        symbolic_cloud(),
                    );
                }
                None => boundary(
                    builder,
                    model_node,
                    BoundaryReason::UNMODELED_SUBCOMMAND,
                    BoundaryClass::Unmodeled,
                    &["cloud", "network"],
                    "gcloud non-delete verb",
                ),
            },
            _ => boundary(
                builder,
                model_node,
                BoundaryReason::UNMODELED_SUBCOMMAND,
                BoundaryClass::Unmodeled,
                &["cloud", "network"],
                "gcloud group",
            ),
        }
    }
}

/// gcloud `<group> <kind...> delete NAME`: find `delete` then the name operand.
fn resource_delete_chain(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    provider: &str,
    service: &str,
    kind: &str,
) {
    let argv = ctx.argv;
    let Some(pos) = argv.iter().position(|w| w.as_literal() == Some("delete")) else {
        boundary(
            builder,
            model_node,
            BoundaryReason::UNMODELED_SUBCOMMAND,
            BoundaryClass::Unmodeled,
            &["cloud", "network"],
            "gcloud non-delete verb",
        );
        return;
    };
    match cloud_operands(argv, pos + 1).first() {
        Some((i, w)) if w.as_literal().is_some() => {
            let r = ResourceExpr::Concrete {
                identity: ResourceIdentity::CloudResource {
                    scope: Box::new(effinterp_proto::cloud_scope(Some(provider), service, kind)),
                    provider: Some(provider.into()),
                    service: service.into(),
                    kind: kind.into(),
                    id: Some(w.as_literal().unwrap().to_string()),
                },
            };
            cloud_effect(builder, ctx, model_node, *i, "cloud.resource.delete", r);
        }
        _ => cloud_effect(
            builder,
            ctx,
            model_node,
            pos as u32,
            "cloud.resource.delete",
            symbolic_cloud(),
        ),
    }
}
