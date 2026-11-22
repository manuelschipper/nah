use effinterp_proto::{BoundaryClass, BoundaryReason, ProvenanceRef};

use crate::builder::PlanBuilder;
use crate::models::common::boundary;
use crate::models::{CommandModel, InvocationCtx};
use crate::word::Word;

use super::cloud_args::{azcopy_flag, cloud_operands};
use super::cloud_coverage::declare_cloud_common;
use super::cloud_effects::{object_store_effect, symbolic_cloud};
use super::object_store_target::object_store_target;
use super::object_store_transfer::object_store_transfer;

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
        match argv.get(1).and_then(Word::as_literal) {
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
