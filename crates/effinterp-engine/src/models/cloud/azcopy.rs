use effinterp_proto::{BoundaryClass, BoundaryReason, ProvenanceRef};

use crate::builder::PlanBuilder;
use crate::models::common::boundary;
use crate::models::{CommandModel, InvocationCtx};
use crate::word::Word;

use super::cloud_args::{azcopy_flag, cloud_operands};
use super::cloud_coverage::declare_cloud_common;
use super::cloud_effects::{object_store_effect, symbolic_cloud};
use super::object_store_target::object_store_target;
use super::object_store_transfer::{object_store_dry_run, object_store_transfer};

/// AzCopy routes `copy` and `sync` through the object store transfer model.
/// Its options carry their value with `=`, so a bare flag means true.
pub(super) struct AzcopyCommandModel;

impl CommandModel for AzcopyCommandModel {
    fn domains(&self) -> &'static [&'static str] {
        &crate::builder::KNOWN_DOMAINS
    }

    fn id(&self) -> &'static str {
        "cloud/azcopy@v0"
    }
    fn command_names(&self) -> &'static [&'static str] {
        &["azcopy"]
    }
    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        declare_cloud_common(builder, ctx, model_node, false);
        let argv = ctx.argv;
        let verb = argv.get(1).and_then(Word::as_literal);
        // `--dry-run` makes copy, sync and remove print each operation they
        // would perform and perform none.
        if matches!(verb, Some("rm" | "remove" | "cp" | "copy" | "sync")) && azcopy_dry_run(argv) {
            object_store_dry_run(
                builder,
                ctx,
                model_node,
                2,
                "azcopy --dry-run lists the operations without performing them",
            );
            return;
        }
        match verb {
            Some("rm" | "remove") => {
                for (i, w) in cloud_operands(argv, 2) {
                    object_store_effect(
                        builder,
                        ctx,
                        model_node,
                        i,
                        "cloud.object.delete",
                        object_store_target(w).unwrap_or_else(symbolic_cloud),
                        azcopy_flag(argv, "--recursive"),
                        false,
                        true,
                        Default::default(),
                    );
                }
            }
            Some("cp" | "copy") => object_store_transfer(
                builder,
                ctx,
                model_node,
                2,
                false,
                azcopy_flag(argv, "--recursive"),
            ),
            // azcopy sync uploads the source's top-level files even with
            // `--recursive=false`, so its read covers the whole directory.
            Some("sync") => object_store_transfer(
                builder,
                ctx,
                model_node,
                2,
                azcopy_flag(argv, "--delete-destination"),
                true,
            ),
            _ => boundary(
                builder,
                model_node,
                BoundaryReason::UNMODELED_SUBCOMMAND,
                BoundaryClass::Unmodeled,
                &["cloud", "network"],
                "azcopy subcommand",
            ),
        }
    }
}

/// Whether AzCopy's `--dry-run` ends up on. Its flag parser sets the boolean
/// at each occurrence, so the last wins, and reads an `=VALUE` as Go's
/// `strconv.ParseBool` does; options end at `--`. A word before that which is
/// not literal could turn it off, and a value Go does not parse makes AzCopy
/// refuse the command, so neither proves it on.
fn azcopy_dry_run(argv: &[Word]) -> bool {
    let mut on = false;
    for word in argv.iter().skip(1) {
        let Some(literal) = word.as_literal() else {
            return false;
        };
        if literal == "--" {
            break;
        }
        let (name, value) = literal
            .split_once('=')
            .map_or((literal, None), |(name, value)| (name, Some(value)));
        if name != "--dry-run" {
            continue;
        }
        on = match value {
            None | Some("1" | "t" | "T" | "TRUE" | "true" | "True") => true,
            Some("0" | "f" | "F" | "FALSE" | "false" | "False") => false,
            Some(_) => return false,
        };
    }
    on
}
