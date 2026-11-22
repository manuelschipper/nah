use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, BoundaryScope, Domain, ProvenanceRef,
};

use crate::builder::PlanBuilder;
use crate::models::common::boundary;
use crate::models::{CommandModel, InvocationCtx, credential};
use crate::word::Word;

use super::aws_ec2::ec2_lifecycle;
use super::aws_request_input::{AwsRequestInput, aws_request_input};
use super::aws_s3::{aws_s3, aws_s3api};
use super::cloud_args::{CLOUD_SCOPE_FLAGS, aws_service_after_globals};
use super::cloud_coverage::declare_cloud_common;
use super::object_store_transfer::object_store_stdin_upload;
use super::remote_commands::aws_ssm_remote_command;
use super::resource_delete::{
    aws_resource_delete_by_flag, cloud_resource_delete, cloud_resource_delete_effect,
    cloud_resource_delete_resolved,
};

/// AWS CLI dispatch expands readable request input before interpreting the service verb.
pub(super) struct AwsCommandModel;

impl CommandModel for AwsCommandModel {
    fn domains(&self) -> &'static [&'static str] {
        &crate::builder::KNOWN_DOMAINS
    }

    fn id(&self) -> &'static str {
        "cloud/aws@v0"
    }
    fn command_names(&self) -> &'static [&'static str] {
        &["aws"]
    }
    // Secrets Manager and Parameter Store reads print the value they read,
    // so it can reach the next stage of a pipeline.
    fn causal_bindings(&self, argv: &[Word]) -> Vec<crate::models::ModelCausalBinding> {
        match argv
            .get(crate::models::scope::command_position(
                argv,
                CLOUD_SCOPE_FLAGS,
            ))
            .and_then(Word::as_literal)
        {
            Some("secretsmanager" | "ssm") => credential::read_output(false),
            _ => object_store_stdin_upload(argv),
        }
    }
    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        if matches!(
            ctx.argv.get(1).and_then(Word::as_literal),
            Some("--help" | "--version")
        ) {
            declare_cloud_common(builder, ctx, model_node, false);
            return;
        }
        let input = aws_request_input(builder, ctx);
        let expanded;
        let ctx = match &input {
            AwsRequestInput::Read { argv, provenance } => {
                expanded = InvocationCtx {
                    argv,
                    stdin: ctx.stdin,
                    argv_provenance: Some(provenance),
                    cwd: ctx.cwd,
                    cwd_resource: ctx.cwd_resource.clone(),
                    runtime_cwd: ctx.runtime_cwd,
                    scope: ctx.scope,
                    cwd_node: ctx.cwd_node,
                    nest: ctx.nest,
                    depth: ctx.depth,
                    model_stack: ctx.model_stack.clone(),
                };
                &expanded
            }
            AwsRequestInput::Unreadable => {
                builder.boundary(Boundary {
                    reason: BoundaryReason::INPUT_DETERMINED_ARGUMENTS,
                    class: BoundaryClass::Unresolved,
                    scope: BoundaryScope::Invocation,
                    affected_resource: None,
                    callee: None,
                    domains: vec![Domain::new("cloud"), Domain::new("network")],
                    provenance: vec![model_node],
                    limit: None,
                    detail: Some(
                        "AWS CLI request input supplies parameters Nah does not read".into(),
                    ),
                });
                ctx
            }
            AwsRequestInput::Absent => ctx,
        };
        let argv = ctx.argv;
        let command = crate::models::scope::command_position(argv, CLOUD_SCOPE_FLAGS);
        let service = argv.get(command).and_then(Word::as_literal);
        let credential_covered = match service {
            Some("secretsmanager") => {
                Some(credential::aws_secretsmanager(builder, ctx, model_node))
            }
            Some("ssm")
                if matches!(
                    argv.get(command + 1).and_then(Word::as_literal),
                    Some(
                        "get-parameter"
                            | "get-parameters"
                            | "get-parameters-by-path"
                            | "put-parameter"
                            | "delete-parameter"
                            | "delete-parameters"
                            | "describe-parameters"
                    )
                ) =>
            {
                Some(credential::aws_ssm_parameters(builder, ctx, model_node))
            }
            _ => None,
        };
        declare_cloud_common(
            builder,
            ctx,
            model_node,
            credential_covered.unwrap_or_else(|| cloud_resource_delete_resolved(argv)),
        );
        if credential_covered.is_some() {
            return;
        }
        if let Some(delete) = cloud_resource_delete(argv) {
            cloud_resource_delete_effect(builder, ctx, model_node, &delete);
            return;
        }
        // The scope reading takes a reviewed global option's separate value
        // (`aws --output json ec2 ...`) as the service; termination is read
        // with every reviewed global option, as the other deletes are.
        if let Some(service) = aws_service_after_globals(argv)
            && argv.get(service).and_then(Word::as_literal) == Some("ec2")
            && argv.get(service + 1).and_then(Word::as_literal) == Some("terminate-instances")
        {
            ec2_lifecycle(builder, ctx, model_node, service + 1);
            return;
        }
        match service {
            Some("s3") => aws_s3(builder, ctx, model_node),
            Some("s3api") => aws_s3api(builder, ctx, model_node),
            Some("ec2") => ec2_lifecycle(builder, ctx, model_node, command + 1),
            Some("rds") => boundary(
                builder,
                model_node,
                BoundaryReason::UNMODELED_SUBCOMMAND,
                BoundaryClass::Unmodeled,
                &["cloud", "network"],
                "aws rds subcommand",
            ),
            Some("cloudformation") => {
                if argv.get(command + 1).and_then(Word::as_literal) == Some("delete-stack") {
                    aws_resource_delete_by_flag(
                        builder,
                        ctx,
                        model_node,
                        "aws",
                        "cloudformation",
                        "stack",
                        "--stack-name",
                    );
                } else {
                    boundary(
                        builder,
                        model_node,
                        BoundaryReason::UNMODELED_SUBCOMMAND,
                        BoundaryClass::Unmodeled,
                        &["cloud", "network"],
                        "aws cloudformation subcommand",
                    );
                }
            }
            Some("ssm") => aws_ssm_remote_command(builder, ctx, model_node),
            _ => boundary(
                builder,
                model_node,
                BoundaryReason::UNMODELED_SUBCOMMAND,
                BoundaryClass::Unmodeled,
                &["cloud", "network"],
                "aws service",
            ),
        }
    }
}
