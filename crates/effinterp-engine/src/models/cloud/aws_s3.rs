use effinterp_proto::{
    AttrValue, Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CoverageLevel, Domain,
    Field, ProvenanceRef, ResourceExpr, ResourceIdentity, ResourcePattern,
};

use crate::builder::PlanBuilder;
use crate::models::InvocationCtx;
use crate::models::args::{FlagSpec, scan, scan_literal_flags};
use crate::models::common::{
    Attrs, boundary, environment_boundary, fs_arg_effect, program_input_attrs,
};
use crate::word::Word;

use super::cloud_args::{CLOUD_LITERAL_FLAGS, CLOUD_SCOPE_FLAGS, cloud_operands};
use super::cloud_effects::{object_store_effect, symbolic_cloud};
use super::object_store_target::object_store_target;
use super::object_store_transfer::object_store_transfer;

/// AWS S3 high-level verbs preserve object identity through symbolic buckets and keys.
pub(super) fn aws_s3(builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
    let scanned = scan_literal_flags(ctx.argv, &CLOUD_LITERAL_FLAGS);
    let argv = ctx.argv;
    let command = crate::models::scope::command_position(argv, CLOUD_SCOPE_FLAGS);
    let sub = argv.get(command + 1).and_then(Word::as_literal);
    let recursive = scanned.has(&["--recursive"]);
    // A filter decides which keys under the prefix the sweep reaches; the
    // pattern is matched against the listing, not against argv.
    let filtered = scanned
        .flags
        .iter()
        .any(|flag| matches!(flag.name, "--exclude" | "--include"));
    // `--dryrun` makes cp, mv, rm and sync print each operation they would
    // perform and perform none: nothing is uploaded, written or deleted. A
    // recursive or sync run still lists the S3 side to decide what it would
    // do. argparse never takes a `-`-prefixed word as a flag's value, so a
    // literal `--dryrun` before `--` is always the flag. An unknown word
    // could expand to `--`, so it also ends the proven option prefix.
    let dry_run = argv
        .iter()
        .skip(command + 2)
        .map_while(|word| word.as_literal().filter(|literal| *literal != "--"))
        .any(|literal| literal == "--dryrun");
    if dry_run && matches!(sub, Some("cp" | "mv" | "rm" | "sync")) {
        if recursive || sub == Some("sync") {
            for (i, w) in cloud_operands(argv, command + 2) {
                if let Some(r) = object_store_target(w) {
                    object_store_effect(
                        builder,
                        ctx,
                        model_node,
                        i,
                        "cloud.object.read",
                        r,
                        true,
                        false,
                        true,
                        Default::default(),
                    );
                }
            }
        }
        environment_boundary(
            builder,
            model_node,
            BoundaryReason::REVIEWED_COMMAND_SURFACE,
            BoundaryClass::Unmodeled,
            &["filesystem", "network", "process"],
            "aws s3 --dryrun displays the operations without performing them",
        );
        return;
    }
    match sub {
        Some("rm") => {
            if recursive && filtered {
                boundary(
                    builder,
                    model_node,
                    BoundaryReason::PARTIAL_ANALYSIS,
                    BoundaryClass::Unresolved,
                    &["cloud"],
                    "a removal filter bounds which keys under the prefix are deleted",
                );
            }
            for (i, w) in cloud_operands(
                argv,
                crate::models::scope::command_position(argv, CLOUD_SCOPE_FLAGS) + 2,
            ) {
                object_store_effect(
                    builder,
                    ctx,
                    model_node,
                    i,
                    "cloud.object.delete",
                    object_store_target(w).unwrap_or_else(symbolic_cloud),
                    recursive && !filtered,
                    false,
                    true,
                    Default::default(),
                );
            }
        }
        Some("rb") => {
            // `rb` removes the bucket and nothing else: without `--force` the
            // bucket must already be empty, so only `--force` establishes the
            // deletion of the objects under it.
            let force = scanned.has(&["--force"]);
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
                        force,
                        false,
                        true,
                        Default::default(),
                    );
                }
            }
        }
        Some("cp") | Some("mv") => {
            object_store_transfer(builder, ctx, model_node, command + 2, false, recursive)
        }
        // `aws s3 sync` always walks the source directory.
        Some("sync") => object_store_transfer(
            builder,
            ctx,
            model_node,
            command + 2,
            scanned.has(&["--delete"]),
            true,
        ),
        _ => boundary(
            builder,
            model_node,
            BoundaryReason::UNMODELED_SUBCOMMAND,
            BoundaryClass::Unmodeled,
            &["cloud", "network"],
            "aws s3 subcommand",
        ),
    }
}

pub(super) const AWS_S3API_SPEC: FlagSpec = FlagSpec {
    allow_abbreviation: false,
    value_flags: &[
        "--bucket",
        "--key",
        "--delete",
        "--versioning-configuration",
        "--profile",
        "--region",
        "--endpoint-url",
    ],
    known_flags: &["--quiet", "--only-show-errors"],
};

/// AWS S3 API verbs read the bucket and any object key from separate options.
pub(super) fn aws_s3api(builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
    let scanned = scan(ctx.argv, &AWS_S3API_SPEC);
    let command = crate::models::scope::command_position(ctx.argv, CLOUD_SCOPE_FLAGS);
    let sub = ctx.argv.get(command + 1).and_then(Word::as_literal);
    match sub {
        // `delete-bucket` removes the bucket resource alone and fails unless
        // it is already empty; neither verb deletes a tree of objects.
        Some("delete-object") | Some("delete-bucket") => {
            if let Some(bucket) = scanned
                .values_of(&["--bucket"])
                .first()
                .map(|(_, value)| *value)
                .and_then(Word::as_literal)
            {
                let key = scanned
                    .values_of(&["--key"])
                    .first()
                    .map(|(_, value)| *value)
                    .and_then(Word::as_literal)
                    .map(str::to_string);
                let r = ResourceExpr::Concrete {
                    identity: ResourceIdentity::ObjectStore {
                        scope: Box::new(effinterp_proto::object_scope(Some("aws"))),
                        provider: Some("aws".into()),
                        bucket: bucket.to_string(),
                        key,
                    },
                };
                object_store_effect(
                    builder,
                    ctx,
                    model_node,
                    (command + 1) as u32,
                    "cloud.object.delete",
                    r,
                    false,
                    false,
                    true,
                    Default::default(),
                );
            } else {
                object_store_effect(
                    builder,
                    ctx,
                    model_node,
                    (command + 1) as u32,
                    "cloud.object.delete",
                    symbolic_cloud(),
                    false,
                    false,
                    true,
                    Default::default(),
                );
            }
        }
        Some("delete-objects") => {
            let bucket = scanned.value_of(&["--bucket"]).and_then(Word::as_literal);
            let manifest = scanned.flags.iter().find(|flag| flag.name == "--delete");
            let (Some(bucket), Some(manifest)) = (bucket, manifest) else {
                boundary(
                    builder,
                    model_node,
                    BoundaryReason::MISSING_REQUIRED_ARGUMENTS,
                    BoundaryClass::Unmodeled,
                    &["cloud", "filesystem", "network"],
                    "aws s3api delete-objects requires --bucket and --delete",
                );
                return;
            };
            let manifest_word = manifest.value.as_ref().unwrap();
            let Some(path) = manifest_word
                .as_literal()
                .and_then(|value| value.strip_prefix("file://"))
            else {
                boundary(
                    builder,
                    model_node,
                    BoundaryReason::UNSUPPORTED_SOURCE,
                    BoundaryClass::Unsupported,
                    &["cloud", "filesystem"],
                    "aws s3api delete-objects manifest is not a file:// source",
                );
                return;
            };
            let source = Word::literal(path);
            let source_resource = ctx.resolve_fs_word(&source);
            fs_arg_effect(
                builder,
                ctx,
                model_node,
                manifest.value_index.unwrap_or(manifest.index),
                &source,
                "filesystem.read",
                source_resource.clone(),
                program_input_attrs(),
            );
            builder.boundary_with_coverage(
                Boundary {
                    reason: BoundaryReason::UNRESOLVED_SOURCE,
                    class: BoundaryClass::Unresolved,
                    scope: BoundaryScope::Invocation,
                    affected_resource: Some(source_resource),
                    callee: None,
                    domains: vec![Domain::new("filesystem"), Domain::new("cloud")],
                    provenance: vec![model_node],
                    limit: None,
                    detail: Some(
                        "aws s3api delete-objects manifest contents are not supplied".into(),
                    ),
                },
                CoverageLevel::Partial,
            );
            let attributes = Attrs::from([
                ("selection".into(), AttrValue::String("manifest".into())),
                ("manifest".into(), AttrValue::String(path.into())),
            ]);
            object_store_effect(
                builder,
                ctx,
                model_node,
                (command + 1) as u32,
                "cloud.object.delete",
                ResourceExpr::Pattern {
                    pattern: ResourcePattern::ObjectStore {
                        provider: Field::Exact {
                            value: "aws".into(),
                        },
                        bucket: bucket.into(),
                        key_prefix: None,
                    },
                },
                false,
                false,
                true,
                attributes,
            );
        }
        Some("put-bucket-versioning")
            if scanned.has(&["--bucket"]) && !scanned.has(&["--versioning-configuration"]) =>
        {
            environment_boundary(
                builder,
                model_node,
                BoundaryReason::REVIEWED_COMMAND_SURFACE,
                BoundaryClass::Unmodeled,
                &["cloud", "network"],
                "aws rejects put-bucket-versioning without --versioning-configuration",
            );
        }
        _ => boundary(
            builder,
            model_node,
            BoundaryReason::UNMODELED_SUBCOMMAND,
            BoundaryClass::Unmodeled,
            &["cloud", "network"],
            "aws s3api subcommand",
        ),
    }
}
