use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, BoundaryScope, Domain, ProvenanceRef, ResourceExpr,
    ResourceIdentity,
};

use crate::builder::PlanBuilder;
use crate::models::InvocationCtx;
use crate::word::Word;

use super::resource_delete::cloud_resource_delete;

/// Cloud scope applies supplied options and environment before qualifying names and normalizing identities.
pub(super) fn apply_cloud_scope(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    provenance: &mut Vec<ProvenanceRef>,
    resource: &mut ResourceExpr,
) {
    use crate::models::scope::{access_value, endpoint_evidence, scope_boundary, scope_option};
    use effinterp_proto::{ScopeDimension, ScopeEvidenceKind, ScopeValue};
    if let ResourceExpr::Join { parts }
    | ResourceExpr::Union {
        alternatives: parts,
    } = resource
    {
        for part in parts {
            apply_cloud_scope(builder, ctx, provenance, part);
        }
        return;
    }
    let ResourceExpr::Concrete { identity } = resource else {
        return;
    };
    let provider = match identity {
        ResourceIdentity::ObjectStore { provider, .. }
        | ResourceIdentity::CloudResource { provider, .. } => provider.clone(),
        _ => return,
    };
    let scope = identity.scope_mut().unwrap();
    match provider.as_deref() {
        Some("aws") => {
            let region = scope_option(builder, ctx, provenance, &["--region"], true, "cloud")
                .or_else(|| {
                    cloud_environment(builder, ctx, provenance, "AWS_REGION").map(ScopeValue::value)
                })
                .or_else(|| {
                    cloud_environment(builder, ctx, provenance, "AWS_DEFAULT_REGION")
                        .map(ScopeValue::value)
                });
            if let Some(region) = region {
                access_value(scope, ScopeEvidenceKind::RequestRegion, region.clone());
                if scope.kind == effinterp_proto::NamespaceKind::AwsRegional {
                    scope.identity.insert(ScopeDimension::Region, region);
                }
            }
            if let Some(profile) =
                scope_option(builder, ctx, provenance, &["--profile"], true, "cloud")
            {
                access_value(scope, ScopeEvidenceKind::Profile, profile);
            }
            if let Some(endpoint) =
                scope_option(builder, ctx, provenance, &["--endpoint-url"], true, "cloud")
            {
                endpoint_evidence(scope, ScopeEvidenceKind::Endpoint, endpoint);
            } else {
                for name in [
                    "AWS_ENDPOINT_URL",
                    "AWS_ENDPOINT_URL_S3",
                    "AWS_ENDPOINT_URL_EC2",
                    "AWS_ENDPOINT_URL_RDS",
                ] {
                    if let Some(endpoint) = cloud_environment(builder, ctx, provenance, name) {
                        endpoint_evidence(
                            scope,
                            ScopeEvidenceKind::Endpoint,
                            ScopeValue::value(endpoint),
                        );
                        scope_boundary(builder, provenance, "cloud");
                    }
                }
            }
            if let Some(config) = cloud_environment(builder, ctx, provenance, "AWS_CONFIG_FILE") {
                access_value(
                    scope,
                    ScopeEvidenceKind::ConfigurationFile,
                    ScopeValue::value(config),
                );
                scope_boundary(builder, provenance, "cloud");
            }
        }
        Some("gcp") => {
            for (flag, dimension) in [
                ("--project", ScopeDimension::Project),
                ("--zone", ScopeDimension::Zone),
                ("--region", ScopeDimension::Region),
            ] {
                if let Some(value) = scope_option(builder, ctx, provenance, &[flag], true, "cloud")
                    && !matches!(
                        scope.identity.get(&dimension),
                        Some(ScopeValue::NotApplicable)
                    )
                {
                    scope.identity.insert(dimension, value);
                }
            }
            for flag in ["--configuration", "--flags-file"] {
                if let Some(value) = scope_option(builder, ctx, provenance, &[flag], true, "cloud")
                {
                    access_value(scope, ScopeEvidenceKind::ConfigurationFile, value);
                    scope_boundary(builder, provenance, "cloud");
                }
            }
        }
        Some("azure") => {
            // Azure CLI reads an `@file` value from that file. The managed-
            // database deletes W1d added leave such a scope unresolved; DB-BAK's
            // verbs keep their literal reading.
            let strict_names =
                cloud_resource_delete(ctx.argv).is_some_and(|delete| delete.strict_names);
            for (flags, dimension) in [
                (&["--subscription"][..], ScopeDimension::Subscription),
                (
                    &["--resource-group", "-g"][..],
                    ScopeDimension::ResourceGroup,
                ),
                (&["--account-name"][..], ScopeDimension::StorageAccount),
            ] {
                if let Some(value) = scope_option(builder, ctx, provenance, flags, true, "cloud") {
                    if strict_names
                        && matches!(&value, ScopeValue::Value(v) if matches!(v.as_ref(), ResourceExpr::Literal { value } if value.starts_with('@')))
                    {
                        scope.identity.insert(dimension, ScopeValue::Unknown);
                        builder.boundary(Boundary {
                            reason: BoundaryReason::INPUT_DETERMINED_ARGUMENTS,
                            class: BoundaryClass::Unresolved,
                            scope: BoundaryScope::Invocation,
                            affected_resource: None,
                            callee: None,
                            domains: vec![Domain::new("cloud")],
                            provenance: provenance.clone(),
                            limit: None,
                            detail: Some(
                                "the CLI reads the scope option's value from a file Nah does not read"
                                    .into(),
                            ),
                        });
                    } else if dimension == ScopeDimension::Subscription
                        && matches!(&value, ScopeValue::Value(v) if matches!(v.as_ref(), ResourceExpr::Literal { value } if !subscription_uuid(value)))
                    {
                        access_value(scope, ScopeEvidenceKind::SubscriptionName, value);
                    } else if !matches!(
                        scope.identity.get(&dimension),
                        Some(ScopeValue::NotApplicable)
                    ) {
                        if matches!(scope.identity.get(&dimension), Some(ScopeValue::Value(previous)) if ScopeValue::Value(previous.clone()) != value)
                        {
                            scope.identity.insert(dimension, ScopeValue::Unknown);
                            scope_boundary(builder, provenance, "cloud");
                        } else {
                            scope.identity.insert(dimension, value);
                        }
                    }
                }
            }
        }
        _ => {}
    }
    if provider.as_deref() == Some("azure")
        && ctx.argv.iter().any(|word| {
            word.as_literal().is_some_and(|s| {
                s == "--connection-string" || s.starts_with("--connection-string=")
            })
        })
    {
        if !matches!(
            scope.identity.get(&ScopeDimension::StorageAccount),
            Some(ScopeValue::NotApplicable)
        ) {
            scope
                .identity
                .insert(ScopeDimension::StorageAccount, ScopeValue::Unknown);
        }
        access_value(
            scope,
            ScopeEvidenceKind::UnresolvedConfiguration,
            ScopeValue::Unknown,
        );
        scope_boundary(builder, provenance, "cloud");
    }
    let gsutil_short_options = ctx.argv[0].as_literal().map(crate::models::args::basename)
        == Some("gsutil")
        && ctx
            .argv
            .iter()
            .skip(1)
            .filter_map(Word::as_literal)
            .filter(|word| word.starts_with('-'))
            .all(|word| {
                word.strip_prefix('-').is_some_and(|letters| {
                    !letters.is_empty()
                        && letters
                            .chars()
                            .all(|letter| matches!(letter, 'm' | 'q' | 'r' | 'R' | 'd'))
                })
            });
    if !gsutil_short_options {
        // Azure CLI's argparse reads `-nVALUE` as `-n VALUE`.
        let attached_names = ctx
            .argv
            .iter()
            .skip(1)
            .filter_map(Word::as_literal)
            .filter(|word| provider.as_deref() == Some("azure") && word.len() > 2)
            .filter(|word| word.starts_with("-n") && !word.contains('='));
        let supported = [
            "--region",
            "--endpoint-url",
            "--profile",
            "--project",
            "--zone",
            "--subscription",
            "--resource-group",
            "-g",
            "--account-name",
            "--configuration",
            "--flags-file",
            "--instance-ids",
            "--db-instance-identifier",
            "--skip-final-snapshot",
            "--final-db-snapshot-identifier",
            "--delete-automated-backups",
            "--bucket",
            "--key",
            "--recursive",
            "--delete",
            "--quiet",
            "--force",
            "--dryrun",
            "--exclude",
            "--include",
            "--only-show-errors",
            "--debug",
            "--verbose",
            "--bypass-immutability-policy",
            "--acquire-policy-token",
            "--change-reference",
            "--no-progress",
            "--name",
            "-n",
            "--container-name",
            "-c",
            "--blob-url",
            "--file",
            "-f",
            "--ids",
            "--yes",
            "-y",
            "--no-wait",
            "--output",
            "-o",
            "--query",
            "--auth-mode",
            "--account-key",
            "--connection-string",
            "--sas-token",
            "--no-verify-ssl",
            "--no-sign-request",
            "--snapshot-id",
            "--volume-id",
            "--source",
            "--delete-unmatched-destination-objects",
            "--delete-destination",
            "--config",
            "--fast-list",
            "-m",
            "-r",
            "-R",
            "-q",
        ]
        .into_iter()
        .chain(attached_names)
        .chain(
            cloud_resource_delete(ctx.argv)
                .map_or_else(Vec::new, |delete| delete.options().collect()),
        )
        .collect::<Vec<_>>();
        crate::models::scope::unmodeled_scope_options(
            builder, ctx, provenance, scope, &supported, "cloud",
        );
    }
    qualify_cloud_name(identity, builder, provenance);
    if let Some(scope) = identity.scope_mut() {
        effinterp_proto::normalize_scope(scope, effinterp_proto::PathPlatform::Posix);
    }
}

fn subscription_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, c)| {
            if [8, 13, 18, 23].contains(&i) {
                c == b'-'
            } else {
                c.is_ascii_hexdigit()
            }
        })
}

fn qualify_cloud_name(
    identity: &mut ResourceIdentity,
    builder: &mut PlanBuilder,
    provenance: &[ProvenanceRef],
) {
    use effinterp_proto::{ScopeDimension, ScopeValue};
    let (scope, name) = match identity {
        ResourceIdentity::ObjectStore { scope, bucket, .. } => (scope, bucket),
        ResourceIdentity::CloudResource {
            scope,
            id: Some(id),
            ..
        } => (scope, id),
        _ => return,
    };
    let text = name.clone();
    if scope.kind == effinterp_proto::NamespaceKind::S3Bucket
        && ["--x-s3", "-s3alias", "--ol-s3", "--table-s3"]
            .iter()
            .any(|suffix| text.ends_with(suffix))
    {
        scope.kind = effinterp_proto::NamespaceKind::Unsupported;
        scope.identity = effinterp_proto::ResourceScope::<ResourceExpr>::new(scope.kind).identity;
        crate::models::scope::scope_boundary(builder, provenance, "cloud");
    }
    let mut fields = Vec::new();
    if text.starts_with("arn:") {
        let parts: Vec<_> = text.splitn(6, ':').collect();
        if parts.len() == 6 && matches!(parts[1], "aws" | "aws-cn" | "aws-us-gov") {
            match (scope.kind, parts[2], parts[5]) {
                (effinterp_proto::NamespaceKind::S3Bucket, "s3", bucket)
                    if parts[3].is_empty()
                        && parts[4].is_empty()
                        && !bucket.contains(['/', ':'])
                        && !bucket.is_empty() =>
                {
                    fields.push((ScopeDimension::Partition, parts[1]));
                    *name = bucket.to_string();
                }
                (effinterp_proto::NamespaceKind::AwsRegional, "ec2", target)
                    if target.starts_with("instance/") =>
                {
                    fields.extend([
                        (ScopeDimension::Partition, parts[1]),
                        (ScopeDimension::Account, parts[4]),
                        (ScopeDimension::Region, parts[3]),
                    ]);
                    *name = target[9..].to_string();
                }
                (effinterp_proto::NamespaceKind::AwsRegional, "rds", target)
                    if target.starts_with("db:") =>
                {
                    fields.extend([
                        (ScopeDimension::Partition, parts[1]),
                        (ScopeDimension::Account, parts[4]),
                        (ScopeDimension::Region, parts[3]),
                    ]);
                    *name = target[3..].to_string();
                }
                _ => {
                    scope.kind = effinterp_proto::NamespaceKind::Unsupported;
                    scope.identity =
                        effinterp_proto::ResourceScope::<ResourceExpr>::new(scope.kind).identity;
                    crate::models::scope::scope_boundary(builder, provenance, "cloud");
                }
            }
        } else {
            scope.kind = effinterp_proto::NamespaceKind::Unsupported;
            scope.identity =
                effinterp_proto::ResourceScope::<ResourceExpr>::new(scope.kind).identity;
            crate::models::scope::scope_boundary(builder, provenance, "cloud");
        }
    } else if scope.kind == effinterp_proto::NamespaceKind::GceZonal {
        let path = text
            .strip_prefix("https://www.googleapis.com/compute/v1/")
            .unwrap_or(&text);
        let parts: Vec<_> = path.split('/').collect();
        if let [
            "projects",
            project,
            location_kind,
            location,
            "instances",
            instance,
        ] = parts.as_slice()
        {
            if *location_kind == "regions" {
                scope.kind = effinterp_proto::NamespaceKind::GceRegional;
                scope.identity =
                    effinterp_proto::ResourceScope::<ResourceExpr>::new(scope.kind).identity;
            }
            if matches!(*location_kind, "zones" | "regions") {
                fields.push((ScopeDimension::Project, *project));
                fields.push((
                    if *location_kind == "zones" {
                        ScopeDimension::Zone
                    } else {
                        ScopeDimension::Region
                    },
                    *location,
                ));
                *name = instance.to_string();
            }
        }
    } else if scope.kind == effinterp_proto::NamespaceKind::AzureVm {
        let parts: Vec<_> = text.split('/').collect();
        if let [
            "",
            "subscriptions",
            subscription,
            "resourceGroups",
            group,
            "providers",
            "Microsoft.Compute",
            "virtualMachines",
            instance,
        ] = parts.as_slice()
        {
            fields.extend([
                (ScopeDimension::Subscription, *subscription),
                (ScopeDimension::ResourceGroup, *group),
            ]);
            *name = instance.to_string();
        }
    }
    for (dimension, value) in fields {
        if value.is_empty() {
            continue;
        }
        let value = ScopeValue::value(ResourceExpr::Literal {
            value: value.to_string(),
        });
        if matches!(scope.identity.get(&dimension), Some(ScopeValue::Value(previous)) if ScopeValue::Value(previous.clone()) != value)
        {
            scope.identity.insert(dimension, ScopeValue::Unknown);
            crate::models::scope::scope_boundary(builder, provenance, "cloud");
        } else {
            scope.identity.insert(dimension, value);
        }
    }
}

/// Reads cloud environment evidence and attaches the provenance available for the invocation.
pub(super) fn cloud_environment(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    provenance: &mut Vec<ProvenanceRef>,
    name: &str,
) -> Option<ResourceExpr> {
    let value = ctx.environment_value(name)?;
    if let Some(node) = ctx.nest.current_environment_node(name) {
        provenance.push(node);
    } else if ctx.tracks_host_context_environment() {
        provenance.push(builder.node(
            effinterp_proto::ProvenanceKind::HostContext {
                name: format!("env.{name}"),
            },
            &[],
        ));
    }
    Some(value)
}
