use effinterp_proto::{BoundaryClass, BoundaryReason, ProvenanceRef};

use crate::builder::PlanBuilder;
use crate::models::common::boundary;
use crate::models::{CommandModel, InvocationCtx};
use crate::word::Word;

use super::cloud_args::{GSUTIL_GLOBAL_FLAGS, cloud_has_short_option, cloud_operands};
use super::cloud_coverage::declare_cloud_common;
use super::cloud_effects::{object_store_effect, symbolic_cloud};
use super::object_store_target::object_store_target;
use super::object_store_transfer::{object_store_stdin_upload, object_store_transfer};

/// gsutil dispatch skips global option values before interpreting the storage verb.
pub(super) struct GsutilCommandModel;

impl CommandModel for GsutilCommandModel {
    fn domains(&self) -> &'static [&'static str] {
        &crate::builder::KNOWN_DOMAINS
    }

    fn id(&self) -> &'static str {
        "cloud/gsutil@v0"
    }
    fn command_names(&self) -> &'static [&'static str] {
        &["gsutil"]
    }
    fn causal_bindings(&self, argv: &[Word]) -> Vec<crate::models::ModelCausalBinding> {
        object_store_stdin_upload(argv)
    }
    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        declare_cloud_common(builder, ctx, model_node, false);
        if matches!(
            ctx.argv.get(1).and_then(Word::as_literal),
            Some("--help" | "--version")
        ) {
            return;
        }
        let argv = ctx.argv;
        // gsutil takes its own options before the subcommand (`gsutil -m rm`).
        let command = crate::models::scope::command_position(argv, GSUTIL_GLOBAL_FLAGS);
        let sub = argv.get(command).and_then(Word::as_literal);
        match sub {
            Some("rb") => {
                for (index, target) in cloud_operands(argv, command + 1) {
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
            }
            Some("rm") => {
                for (i, w) in cloud_operands(argv, command + 1) {
                    if let Some(r) = object_store_target(w) {
                        object_store_effect(
                            builder,
                            ctx,
                            model_node,
                            i,
                            "cloud.object.delete",
                            r,
                            cloud_has_short_option(argv, command + 1, &['r', 'R']),
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
            }
            Some("cp") | Some("mv") => object_store_transfer(
                builder,
                ctx,
                model_node,
                command + 1,
                false,
                cloud_has_short_option(argv, command + 1, &['r', 'R']),
            ),
            // Without -r, rsync still uploads the source's top-level files, so
            // its read covers the whole directory.
            Some("rsync") => object_store_transfer(
                builder,
                ctx,
                model_node,
                command + 1,
                cloud_has_short_option(argv, command + 1, &['d']),
                true,
            ),
            _ => boundary(
                builder,
                model_node,
                BoundaryReason::UNMODELED_SUBCOMMAND,
                BoundaryClass::Unmodeled,
                &["cloud", "network"],
                "gsutil subcommand",
            ),
        }
    }
}
