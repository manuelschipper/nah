use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CoverageLevel, Domain, ProvenanceRef,
};

use crate::builder::PlanBuilder;
use crate::models::args::{FlagSpec, scan};
use crate::models::common::{boundary, environment_boundary, fs_arg_effect, program_input_attrs};
use crate::models::{CommandModel, InvocationCtx};

use super::cloud_effects::{object_store_effect, symbolic_cloud};
use super::object_store_target::object_store_target;

const S3CMD_SPEC: FlagSpec = FlagSpec {
    allow_abbreviation: false,
    value_flags: &["-c", "--config"],
    known_flags: &["-r", "--recursive", "-n", "--dry-run"],
};

/// s3cmd delete recognizes literal S3 targets and leaves unreviewed options partial.
pub(super) struct S3cmdCommandModel;

impl CommandModel for S3cmdCommandModel {
    fn domains(&self) -> &'static [&'static str] {
        &["cloud", "filesystem", "network", "process"]
    }

    fn id(&self) -> &'static str {
        "s3tools/s3cmd@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["s3cmd"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, node: ProvenanceRef) {
        let scanned = scan(ctx.argv, &S3CMD_SPEC);
        let operands = scanned
            .operands
            .iter()
            .filter_map(|(index, word)| word.as_literal().map(|value| (*index, word, value)))
            .collect::<Vec<_>>();
        if !scanned.unknown_flags.is_empty()
            || operands.len() != 2
            || !matches!(operands[0].2, "del" | "rm")
        {
            boundary(
                builder,
                node,
                BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                BoundaryClass::Unmodeled,
                &["cloud", "filesystem", "network", "process"],
                "s3cmd deletion arguments are outside the reviewed grammar",
            );
            return;
        }
        builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);
        let config = scanned
            .flags
            .iter()
            .rev()
            .find(|flag| matches!(flag.name, "-c" | "--config"));
        let config_resource = config.map(|config| {
            let word = config.value.as_ref().unwrap();
            let resource = ctx.resolve_fs_word(word);
            fs_arg_effect(
                builder,
                ctx,
                node,
                config.value_index.unwrap_or(config.index),
                word,
                "filesystem.read",
                resource.clone(),
                program_input_attrs(),
            );
            resource
        });
        builder.boundary_with_coverage(
            Boundary {
                reason: BoundaryReason::ENVIRONMENT_CONFIGURATION,
                class: BoundaryClass::Unresolved,
                scope: BoundaryScope::Invocation,
                affected_resource: config_resource,
                callee: None,
                domains: vec![
                    Domain::new("filesystem"),
                    Domain::new("cloud"),
                    Domain::new("network"),
                ],
                provenance: vec![node],
                limit: None,
                detail: Some("s3cmd endpoint and credentials require runtime configuration".into()),
            },
            CoverageLevel::Partial,
        );
        if scanned.has(&["-n", "--dry-run"]) {
            environment_boundary(
                builder,
                node,
                BoundaryReason::REVIEWED_COMMAND_SURFACE,
                BoundaryClass::Unmodeled,
                &["cloud", "network"],
                "s3cmd dry-run performs no permanent changes",
            );
            return;
        }
        let (index, word, _) = operands[1];
        object_store_effect(
            builder,
            ctx,
            node,
            index,
            "cloud.object.delete",
            object_store_target(word).unwrap_or_else(symbolic_cloud),
            scanned.has(&["-r", "--recursive"]),
            false,
            true,
            Default::default(),
        );
    }
}
