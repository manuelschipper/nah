//! Cloud CLI models: object-store and cloud-resource destructive operations.

use effinterp_engine::Engine;
use effinterp_proto::{
    AttrValue, BoundaryClass, CoverageLevel, Domain, Effect, ExecutionRealm, Plan, ResourceExpr,
    ResourceIdentity, Subject, validate_plan,
};

fn exec(argv: &[&str]) -> Plan {
    let plan = Engine::new()
        .analyze(&Subject::Exec {
            argv: argv.iter().map(|s| s.to_string()).collect(),
            cwd: Some("/w".to_string()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    if plan
        .effects
        .iter()
        .any(|effect| effect.operation.domain() == "cloud")
    {
        assert!(has_operation(&plan, "process.exec"));
        assert!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.domain() == "network"),
            "{argv:?}"
        );
    }

    plan
}

fn shell(source: &str) -> Plan {
    let plan = Engine::new()
        .analyze(&Subject::Shell {
            source: source.to_string(),
            cwd: Some("/w".to_string()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap_or_else(|error| panic!("invalid plan for {source:?}: {error:?}"));
    plan
}

fn effect<'a>(plan: &'a Plan, operation: &str) -> &'a Effect {
    plan.effects
        .iter()
        .find(|effect| effect.operation.0 == operation)
        .unwrap_or_else(|| panic!("missing {operation}"))
}

fn has_operation(plan: &Plan, operation: &str) -> bool {
    plan.effects
        .iter()
        .any(|effect| effect.operation.0 == operation)
}

fn object(plan: &Plan, op: &str) -> Option<ResourceIdentity> {
    plan.effects
        .iter()
        .find(|e| e.operation.0 == op)
        .and_then(|e| match &e.resource {
            ResourceExpr::Concrete { identity } => Some(identity.clone()),
            _ => None,
        })
}

#[test]
fn aws_s3_rm_deletes_an_object() {
    let plan = exec(&["aws", "s3", "rm", "s3://prod-bucket/data.db"]);
    assert!(
        matches!(&effect(&plan, "network.connect").resource, ResourceExpr::Unresolved { family } if family.0 == "network")
    );
    assert_eq!(
        object(&plan, "cloud.object.delete"),
        Some(ResourceIdentity::ObjectStore {
            scope: Box::new(effinterp_proto::object_scope(Some("aws"))),
            provider: Some("aws".into()),
            bucket: "prod-bucket".into(),
            key: Some("data.db".into()),
        })
    );
}

#[test]
fn aws_s3_rm_recursive_prefix() {
    let plan = exec(&["aws", "s3", "rm", "--recursive", "s3://b/prefix/"]);
    let del = plan
        .effects
        .iter()
        .find(|e| e.operation.0 == "cloud.object.delete")
        .unwrap();
    assert_eq!(
        del.attributes.get("recursive"),
        Some(&effinterp_proto::AttrValue::Bool(true))
    );
    assert_eq!(
        object(&plan, "cloud.object.delete"),
        Some(ResourceIdentity::ObjectStore {
            scope: Box::new(effinterp_proto::object_scope(Some("aws"))),
            provider: Some("aws".into()),
            bucket: "b".into(),
            key: Some("prefix/".into()),
        })
    );
}

#[test]
fn aws_ec2_terminate_deletes_instances() {
    let plan = exec(&[
        "aws",
        "ec2",
        "terminate-instances",
        "--instance-ids",
        "i-abc123",
    ]);
    assert_eq!(
        object(&plan, "cloud.resource.delete"),
        Some(ResourceIdentity::CloudResource {
            scope: Box::new(effinterp_proto::cloud_scope(Some("aws"), "ec2", "instance")),
            provider: Some("aws".into()),
            service: "ec2".into(),
            kind: "instance".into(),
            id: Some("i-abc123".into()),
        })
    );
}

#[test]
fn aws_rds_delete_db() {
    let plan = exec(&[
        "aws",
        "rds",
        "delete-db-instance",
        "--db-instance-identifier",
        "prod-db",
    ]);
    assert!(matches!(
        object(&plan, "cloud.resource.delete"),
        Some(ResourceIdentity::CloudResource { id, .. }) if id.as_deref() == Some("prod-db")
    ));
}

/// The AWS CLI keeps the last occurrence of a repeated option and of a
/// `--x`/`--no-x` pair, so a wrapper that appends an override changes what the
/// delete keeps, and repeating the same identifier names one snapshot.
#[test]
fn aws_database_delete_options_take_their_last_occurrence() {
    let recovery = |options: &[&str]| {
        let mut argv = vec![
            "aws",
            "rds",
            "delete-db-instance",
            "--db-instance-identifier",
            "prod",
        ];
        argv.extend(options);
        let plan = exec(&argv);
        let attributes = &effect(&plan, "cloud.resource.delete").attributes;
        (
            attributes.get("final_snapshot").cloned(),
            attributes.get("automated_backups_retained").cloned(),
        )
    };
    assert_eq!(
        recovery(&[
            "--no-skip-final-snapshot",
            "--skip-final-snapshot",
            "--no-delete-automated-backups",
            "--delete-automated-backups",
        ]),
        (Some(AttrValue::Bool(false)), Some(AttrValue::Bool(false)))
    );
    assert_eq!(
        recovery(&[
            "--skip-final-snapshot",
            "--no-skip-final-snapshot",
            "--final-db-snapshot-identifier",
            "prod-final",
            "--delete-automated-backups",
            "--no-delete-automated-backups",
        ]),
        (Some(AttrValue::Bool(true)), Some(AttrValue::Bool(true)))
    );

    let plan = exec(&[
        "aws",
        "rds",
        "delete-db-snapshot",
        "--db-snapshot-identifier",
        "nightly",
        "--db-snapshot-identifier",
        "nightly",
    ]);
    assert!(matches!(
        object(&plan, "cloud.resource.delete"),
        Some(ResourceIdentity::CloudResource { kind, id, .. }) if kind == "snapshot" && id.as_deref() == Some("nightly")
    ));
}

/// A managed-database delete names each resource inside its containers, so a
/// database on one server is not mistaken for a server, and a fully qualified
/// operand is the whole ID. Options the CLI accepts without changing the
/// target (attached short values, waiting, logging, accounts) keep the delete,
/// global ones also between the command words, and so does an option the model
/// does not document, whose possible value names nothing; a request that keeps
/// the data (ElastiCache's effective
/// retained primary), reads a name from a file, names an unplaceable path, or
/// whose command words are an option's value deletes nothing.
#[test]
fn managed_database_deletes_name_each_resource_in_its_containers() {
    let deleted = |plan: Plan| {
        plan.effects
            .iter()
            .filter(|effect| effect.operation.0 == "cloud.resource.delete")
            .map(|effect| match &effect.resource {
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::CloudResource { kind, id, .. },
                } => format!("{kind}/{}", id.as_deref().unwrap_or("?")),
                ResourceExpr::Unresolved { .. } => "unresolved".into(),
                other => panic!("{other:?}"),
            })
            .collect::<Vec<_>>()
    };
    for (command, expected) in [
        (
            "az sql db delete -g rg -s srv -n app",
            &["database/srv/app"][..],
        ),
        ("az sql db delete -g rg -s srv -napp", &["database/srv/app"]),
        (
            "az sql db delete -g rg -s srv -n=old -napp",
            &["database/srv/app"],
        ),
        // A name the CLI reads from a file still deletes one resource of
        // the kind; Nah does not read the file, so its ID is unstated.
        (
            "az sql db delete -g rg -s srv -n @name.txt",
            &["database/?"],
        ),
        (
            "az cosmosdb delete -g rg -n acct --no-wait",
            &["account/acct"],
        ),
        (
            "az cosmosdb sql database delete -g rg -a acct -n db --no-wait",
            &["database/acct/db"],
        ),
        (
            "gcloud sql databases delete app --instance=prod",
            &["database/prod/app"],
        ),
        ("gcloud sql instances --quiet delete x", &["instance/x"]),
        ("gcloud sql --project p instances delete x", &["instance/x"]),
        (
            "gcloud sql --quiet databases delete app -i prod",
            &["database/prod/app"],
        ),
        (
            "gcloud sql --quiet ssl client-certs delete c --instance=prod",
            &["client-cert/prod/c"],
        ),
        (
            "gcloud sql users delete bob --instance=prod --host=%",
            &["user/prod/bob"],
        ),
        (
            "gcloud sql ssl-certs delete c -i prod",
            &["ssl-cert/prod/c"],
        ),
        (
            "gcloud sql ssl client-certs delete c --instance=prod --async",
            &["client-cert/prod/c"],
        ),
        (
            "gcloud bigtable instances delete a b",
            &["instance/a", "instance/b"],
        ),
        (
            "gcloud spanner databases delete projects/p/instances/i/databases/d --instance=i",
            &["database/projects/p/instances/i/databases/d"],
        ),
        (
            "gcloud spanner databases delete d --instance=i",
            &["database/i/d"],
        ),
        ("gcloud spanner databases delete a/b --instance=i", &[]),
        ("gcloud bigtable tables delete t --instance=a/b", &[]),
        (
            "gcloud spanner instances delete prod --log-http",
            &["instance/prod"],
        ),
        (
            "gcloud --account user@example.com spanner instances delete prod",
            &["instance/prod"],
        ),
        (
            "gcloud --flags-file f.yaml spanner instances delete prod",
            &[],
        ),
        (
            "gcloud --no-user-output-enabled spanner instances delete prod",
            &["instance/prod"],
        ),
        (
            "gcloud spanner instances delete prod --no-user-output-enabled",
            &["instance/prod"],
        ),
        (
            "gcloud spanner instances delete prod --no-log-http",
            &["instance/prod"],
        ),
        (
            "gcloud sql --no-log-http instances delete x",
            &["instance/x"],
        ),
        // An option the model does not document keeps the named target, but
        // the word after it may be its value and is never one.
        ("gcloud sql instances delete x --bogus", &["instance/x"]),
        (
            "gcloud bigtable instances delete --http-timeout 30 prod",
            &["instance/prod"],
        ),
        (
            "gcloud bigtable instances delete --weird 30 prod staging",
            &["instance/prod", "instance/staging"],
        ),
        ("gcloud sql instances delete --weird 30", &["unresolved"]),
        (
            "gcloud sql --universe-domain googleapis.com instances delete x",
            &["instance/x"],
        ),
        // Between command words, the reading that takes an undocumented
        // option's word as its value names the verb.
        ("gcloud sql instances --weird v delete x", &["instance/x"]),
        (
            "gcloud sql --weird v --other w instances delete x",
            &["instance/x"],
        ),
        // A value of the verb's own identifier option is not its verb.
        (
            "aws rds --db-instance-identifier delete-db-instance describe-db-instances",
            &[],
        ),
        ("aws rds --db-instance-identifier delete-db-instance", &[]),
        (
            "aws dynamodb delete-table --table-name orders",
            &["table/orders"],
        ),
        (
            "aws dynamodb delete-table --table-name arn:aws:dynamodb:us-east-1:1:table/orders",
            &["table/arn:aws:dynamodb:us-east-1:1:table/orders"],
        ),
        (
            "aws dynamodb delete-table --table-name arn:aws:s3:us-east-1:1:table/orders",
            &[],
        ),
        (
            "aws dynamodb delete-table --table-name arn:aws:dynamodb:us-east-1:1:table/a/b",
            &[],
        ),
        (
            "aws dynamodb delete-table --table-name file://name.txt",
            &["table/?"],
        ),
        (
            "aws keyspaces delete-table --keyspace-name fileb://ks --table-name t",
            &["table/?"],
        ),
        (
            "aws elasticache delete-replication-group --replication-group-id g",
            &["replication-group/g"],
        ),
        (
            "aws elasticache delete-replication-group --replication-group-id g --retain-primary-cluster",
            &[],
        ),
        (
            "aws elasticache delete-replication-group --replication-group-id g --retain-primary-cluster --no-retain-primary-cluster",
            &["replication-group/g"],
        ),
        (
            "aws elasticache delete-replication-group --replication-group-id g --no-retain-primary-cluster --retain-primary-cluster",
            &[],
        ),
    ] {
        assert_eq!(
            deleted(exec(&command.split(' ').collect::<Vec<_>>())),
            expected,
            "{command}"
        );
    }
    // An expansion attached to an option is that option's value: it states
    // the name only for the option that names the resource, never as an
    // operand after an option the model does not document.
    for (source, expected) in [
        (
            r#"gcloud spanner databases delete d --instance="$(cat x)""#,
            &["database/?"][..],
        ),
        (
            r#"gcloud sql instances delete --weird="$(cat x)""#,
            &["unresolved"],
        ),
    ] {
        assert_eq!(deleted(shell(source)), expected, "{source}");
    }

    // A scope option Azure CLI reads from a file keeps the delete but leaves
    // that scope unresolved.
    use effinterp_proto::{ScopeDimension as D, ScopeValue as V};
    for (command, dimension) in [
        (
            "az sql db delete -g @group.txt -s srv -n app",
            D::ResourceGroup,
        ),
        (
            "az sql db delete -g rg -s srv -n app --subscription @sub.json",
            D::Subscription,
        ),
    ] {
        let plan = exec(&command.split(' ').collect::<Vec<_>>());
        let Some(ResourceIdentity::CloudResource { scope, id, .. }) =
            object(&plan, "cloud.resource.delete")
        else {
            panic!("{command}");
        };
        assert_eq!(id.as_deref(), Some("srv/app"));
        assert_eq!(
            scope.identity.get(&dimension),
            Some(&V::Unknown),
            "{command}"
        );
        assert!(scope.access.is_empty(), "{command}");
        assert!(plan.boundaries.iter().any(|boundary| boundary.reason
            == effinterp_proto::BoundaryReason::INPUT_DETERMINED_ARGUMENTS));
    }
}

#[test]
fn aws_cloudformation_delete_stack_names_the_stack() {
    let plan = exec(&[
        "aws",
        "cloudformation",
        "delete-stack",
        "--stack-name",
        "prod",
    ]);
    assert!(matches!(
        object(&plan, "cloud.resource.delete"),
        Some(ResourceIdentity::CloudResource { id, kind, .. }) if id.as_deref() == Some("prod") && kind == "stack"
    ));
}

#[test]
fn s3_cp_mixes_object_and_local() {
    let plan = exec(&["aws", "s3", "cp", "local.txt", "s3://b/remote.txt"]);
    assert!(
        plan.effects
            .iter()
            .any(|e| e.operation.0 == "filesystem.read")
    );
    assert!(
        plan.effects
            .iter()
            .any(|e| e.operation.0 == "cloud.object.write")
    );
}

#[test]
fn aws_s3_dryrun_requires_a_proven_option_prefix() {
    for (command, operation) in [
        (
            r#"aws s3 cp secret.txt "$X" --dryrun s3://bucket/k"#,
            "network.upload",
        ),
        (
            r#"aws s3 cp "$X" --dryrun s3://bucket/k"#,
            "cloud.object.write",
        ),
        (
            r#"aws s3 mv "$X" --dryrun s3://bucket/k"#,
            "cloud.object.write",
        ),
        (
            r#"aws s3 rm "$X" --dryrun s3://bucket/k"#,
            "cloud.object.delete",
        ),
        (
            r#"aws s3 sync "$X" --dryrun s3://bucket/k --delete"#,
            "cloud.object.delete",
        ),
    ] {
        let plan = shell(command);
        assert!(has_operation(&plan, operation), "{command}");
    }
    for command in [
        "aws s3 cp local.txt --dryrun s3://bucket/k",
        r#"aws s3 cp --dryrun "$X" s3://bucket/k"#,
        "aws s3 rm --dryrun s3://bucket/k",
    ] {
        let plan = shell(command);
        for operation in [
            "cloud.object.write",
            "filesystem.delete",
            "cloud.object.delete",
        ] {
            assert!(!has_operation(&plan, operation), "{command}: {operation}");
        }
    }
}

#[test]
fn aws_s3_symbolic_key_and_bucket_remain_object_targets() {
    let key = shell("aws s3 cp secret.txt s3://bucket/$PREFIX/k");
    assert_eq!(
        effect(&key, "cloud.object.write").resource,
        ResourceExpr::Join {
            parts: vec![
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::ObjectStore {
                        scope: Box::new(effinterp_proto::object_scope(Some("aws"))),
                        provider: Some("aws".into()),
                        bucket: "bucket".into(),
                        key: None,
                    },
                },
                ResourceExpr::Environment {
                    name: "PREFIX".into(),
                },
                ResourceExpr::Literal { value: "/k".into() },
            ],
        }
    );
    assert!(!has_operation(&key, "filesystem.write"));

    let bucket = shell("aws s3 cp secret.txt s3://$BUCKET/k");
    assert_eq!(
        effect(&bucket, "cloud.object.write").resource,
        ResourceExpr::Join {
            parts: vec![
                ResourceExpr::Literal {
                    value: "s3://".into(),
                },
                ResourceExpr::Environment {
                    name: "BUCKET".into(),
                },
                ResourceExpr::Literal { value: "/k".into() },
            ],
        }
    );
    assert!(!has_operation(&bucket, "filesystem.write"));
}

#[test]
fn aws_s3_sync_and_mv_keep_symbolic_object_roles() {
    let sync = shell("aws s3 sync ./dir s3://$BUCKET/");
    assert_eq!(
        effect(&sync, "cloud.object.write").resource,
        ResourceExpr::Join {
            parts: vec![
                ResourceExpr::Literal {
                    value: "s3://".into(),
                },
                ResourceExpr::Environment {
                    name: "BUCKET".into(),
                },
                ResourceExpr::Literal { value: "/".into() },
            ],
        }
    );
    assert!(has_operation(&sync, "filesystem.read"));
    assert!(!has_operation(&sync, "filesystem.write"));

    let mv = shell("aws s3 mv s3://bucket/$KEY ./local");
    assert!(matches!(
        &effect(&mv, "cloud.object.read").resource,
        ResourceExpr::Join { parts }
            if matches!(
                parts.as_slice(),
                [
                    ResourceExpr::Concrete {
                        identity: ResourceIdentity::ObjectStore { bucket, key: None, .. }
                    },
                    ResourceExpr::Environment { name }
                ] if bucket == "bucket" && name == "KEY"
            )
    ));
    assert!(matches!(
        &effect(&mv, "filesystem.write").resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path }
        } if path == "/w/local"
    ));
    assert!(!has_operation(&mv, "filesystem.read"));
}

#[test]
fn symbolic_object_removals_preserve_known_bucket_parts() {
    for (source, scheme, variable) in [
        ("aws s3 rm s3://bucket/$KEY", "aws", "KEY"),
        ("gsutil rm gs://bucket/$KEY", "gcp", "KEY"),
        ("gcloud storage rm gs://bucket/$KEY", "gcp", "KEY"),
    ] {
        let plan = shell(source);
        assert!(matches!(
            &effect(&plan, "cloud.object.delete").resource,
            ResourceExpr::Join { parts }
                if matches!(
                    parts.as_slice(),
                    [
                        ResourceExpr::Concrete {
                            identity: ResourceIdentity::ObjectStore {
                                provider: Some(provider),
                                bucket,
                                key: None,
                                ..
                            }
                        },
                        ResourceExpr::Environment { name }
                    ] if provider == scheme && bucket == "bucket" && name == variable
                )
        ));
    }

    let bucket = shell("aws s3 rm s3://$BUCKET/k");
    assert!(matches!(
        &effect(&bucket, "cloud.object.delete").resource,
        ResourceExpr::Join { parts }
            if matches!(
                parts.as_slice(),
                [
                    ResourceExpr::Literal { value },
                    ResourceExpr::Environment { name },
                    ResourceExpr::Literal { value: key },
                ] if value == "s3://" && name == "BUCKET" && key == "/k"
            )
    ));

    for source in [
        "gsutil rm gs://$BUCKET/k",
        "gcloud storage rm gs://$BUCKET/k",
    ] {
        let plan = shell(source);
        assert!(matches!(
            &effect(&plan, "cloud.object.delete").resource,
            ResourceExpr::Join { parts }
                if matches!(
                    parts.as_slice(),
                    [
                        ResourceExpr::Literal { value },
                        ResourceExpr::Environment { name },
                        ResourceExpr::Literal { value: key },
                    ] if value == "gs://" && name == "BUCKET" && key == "/k"
                )
        ));
    }
}

#[test]
fn gsutil_symbolic_transfers_and_remote_delete_attributes_are_modeled() {
    let cp = shell("gsutil cp f gs://$BUCKET/k");
    assert!(matches!(
        &effect(&cp, "cloud.object.write").resource,
        ResourceExpr::Join { parts }
            if matches!(
                parts.as_slice(),
                [
                    ResourceExpr::Literal { value },
                    ResourceExpr::Environment { name },
                    ResourceExpr::Literal { value: key },
                ] if value == "gs://" && name == "BUCKET" && key == "/k"
            )
    ));
    assert!(!has_operation(&cp, "filesystem.write"));

    let download = shell("gsutil cp gs://$BUCKET/k ./local");
    assert!(matches!(
        &effect(&download, "cloud.object.read").resource,
        ResourceExpr::Join { parts }
            if matches!(
                parts.as_slice(),
                [
                    ResourceExpr::Literal { value },
                    ResourceExpr::Environment { name },
                    ResourceExpr::Literal { value: key },
                ] if value == "gs://" && name == "BUCKET" && key == "/k"
            )
    ));
    assert!(matches!(
        &effect(&download, "filesystem.write").resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path }
        } if path == "/w/local"
    ));

    for plan in [
        exec(&["aws", "s3", "sync", "--delete", "./dir", "s3://b/p"]),
        shell("gsutil rsync -d ./dir gs://bucket/$PREFIX"),
    ] {
        assert_eq!(
            effect(&plan, "cloud.object.write").attributes.get("delete"),
            Some(&AttrValue::Bool(true))
        );
        assert!(!has_operation(&plan, "filesystem.write"));
    }
}

#[test]
fn ambiguous_cloud_destination_is_an_object_write_with_partial_filesystem_coverage() {
    let plan = shell("aws s3 cp secret.txt $DEST");
    assert_eq!(
        effect(&plan, "cloud.object.write").resource,
        ResourceExpr::Environment {
            name: "DEST".into(),
        }
    );
    assert!(!has_operation(&plan, "filesystem.write"));
    let boundary = plan
        .boundaries
        .iter()
        .find(|boundary| boundary.reason.as_str() == "unresolved_transfer_target")
        .expect("unresolved transfer boundary");
    assert_eq!(boundary.class, BoundaryClass::Unresolved);
    assert_eq!(
        boundary.domains,
        vec![
            Domain::new("cloud"),
            Domain::new("filesystem"),
            Domain::new("network")
        ]
    );
    assert_eq!(
        plan.coverage
            .0
            .get(&Domain::new("filesystem"))
            .map(|claim| &claim.level),
        Some(&CoverageLevel::Partial)
    );
}

#[test]
fn az_blob_upload_and_download_model_files_and_objects() {
    let upload = exec(&[
        "az",
        "storage",
        "blob",
        "upload",
        "--file",
        "f",
        "--container-name",
        "c",
        "--name",
        "k",
    ]);
    assert!(matches!(
        &effect(&upload, "filesystem.read").resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path }
        } if path == "/w/f"
    ));
    assert!(matches!(
        &effect(&upload, "cloud.object.write").resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::ObjectStore {
                provider: Some(provider),
                bucket,
                key: Some(key),
                ..
            }
        } if provider == "azure" && bucket == "c" && key == "k"
    ));

    let download = exec(&[
        "az", "storage", "blob", "download", "-f", "out", "-c", "c", "-n", "k",
    ]);
    assert!(matches!(
        &effect(&download, "cloud.object.read").resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::ObjectStore { bucket, key: Some(key), .. }
        } if bucket == "c" && key == "k"
    ));
    assert!(matches!(
        &effect(&download, "filesystem.write").resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path }
        } if path == "/w/out"
    ));

    let derived_name = exec(&[
        "az",
        "storage",
        "blob",
        "upload",
        "--file",
        "f",
        "--container-name",
        "c",
    ]);
    assert!(matches!(
        &effect(&derived_name, "cloud.object.write").resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::ObjectStore { bucket, key: None, .. }
        } if bucket == "c"
    ));
}

#[test]
fn az_blob_symbolic_container_and_name_keep_object_shape() {
    let container = shell("az storage blob upload --file f --container-name $C --name k");
    assert_eq!(
        effect(&container, "cloud.object.write").resource,
        ResourceExpr::Join {
            parts: vec![
                ResourceExpr::Literal {
                    value: "az://".into(),
                },
                ResourceExpr::Environment { name: "C".into() },
                ResourceExpr::Literal { value: "/k".into() },
            ],
        }
    );

    let name = shell("az storage blob upload --file f --container-name c --name $N");
    assert_eq!(
        effect(&name, "cloud.object.write").resource,
        ResourceExpr::Join {
            parts: vec![
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::ObjectStore {
                        scope: Box::new(effinterp_proto::object_scope(Some("azure"))),
                        provider: Some("azure".into()),
                        bucket: "c".into(),
                        key: None,
                    },
                },
                ResourceExpr::Environment { name: "N".into() },
            ],
        }
    );
}

#[test]
fn other_az_blob_verbs_remain_bounded() {
    let plan = exec(&[
        "az",
        "storage",
        "blob",
        "copy",
        "start",
        "--source-uri",
        "https://x",
    ]);
    assert!(
        plan.boundaries
            .iter()
            .any(|boundary| boundary.reason.as_str() == "unmodeled_subcommand")
    );
    assert!(!has_operation(&plan, "cloud.object.write"));
}

#[test]
fn object_shaped_operands_never_become_filesystem_resources() {
    for source in [
        "aws s3 cp f s3://bucket/$KEY",
        "aws s3 cp f s3://$BUCKET/k",
        "aws s3 mv s3://bucket/$KEY local",
        "gsutil cp f gs://$BUCKET/k",
        "gsutil rsync -r ./dir gs://bucket/$PREFIX",
        "az storage blob upload --file f --container-name $C --name k",
    ] {
        let plan = shell(source);
        assert!(
            plan.effects
                .iter()
                .filter(|effect| effect.operation.0.starts_with("filesystem."))
                .all(|effect| !resource_contains_object_shape(&effect.resource))
        );
    }
}

fn resource_contains_object_shape(resource: &ResourceExpr) -> bool {
    match resource {
        ResourceExpr::Concrete {
            identity: ResourceIdentity::ObjectStore { .. },
        } => true,
        ResourceExpr::Literal { value } => ["s3://", "gs://", "az://"]
            .iter()
            .any(|prefix| value.starts_with(prefix)),
        ResourceExpr::Property { base, .. } => resource_contains_object_shape(base),
        ResourceExpr::Join { parts } => parts.iter().any(resource_contains_object_shape),
        ResourceExpr::Union { alternatives } => {
            alternatives.iter().any(resource_contains_object_shape)
        }
        _ => false,
    }
}

#[test]
fn gcloud_and_gsutil() {
    let g = exec(&["gcloud", "storage", "rm", "gs://b/k"]);
    assert!(matches!(
        object(&g, "cloud.object.delete"),
        Some(ResourceIdentity::ObjectStore { provider: Some(p), .. }) if p == "gcp"
    ));
    let c = exec(&["gcloud", "compute", "instances", "delete", "web-1"]);
    assert!(matches!(
        object(&c, "cloud.resource.delete"),
        Some(ResourceIdentity::CloudResource { id, .. }) if id.as_deref() == Some("web-1")
    ));
    let gs = exec(&["gsutil", "cp", "gs://b/k", "local"]);
    assert!(
        gs.effects
            .iter()
            .any(|e| e.operation.0 == "cloud.object.read")
    );
    assert!(
        gs.effects
            .iter()
            .any(|e| e.operation.0 == "filesystem.write")
    );
}

#[test]
fn az_blob_and_vm_delete() {
    let b = exec(&[
        "az",
        "storage",
        "blob",
        "delete",
        "--container-name",
        "c",
        "--name",
        "k",
    ]);
    assert!(matches!(
        object(&b, "cloud.object.delete"),
        Some(ResourceIdentity::ObjectStore { bucket, .. }) if bucket == "c"
    ));
    let v = exec(&["az", "vm", "delete", "--name", "myvm"]);
    assert!(matches!(
        object(&v, "cloud.resource.delete"),
        Some(ResourceIdentity::CloudResource { id, .. }) if id.as_deref() == Some("myvm")
    ));
}

#[test]
fn symbolic_target_stays_symbolic() {
    // A non-literal bucket (shell var) resolves to a symbolic cloud resource,
    // never a fabricated concrete one — the plan still validates.
    let plan = Engine::new()
        .analyze(&Subject::Shell {
            source: "aws s3 rm \"$BUCKET_URL\"".to_string(),
            cwd: Some("/w".to_string()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    assert!(
        plan.effects
            .iter()
            .any(|e| e.operation.0 == "cloud.object.delete"
                && matches!(e.resource, ResourceExpr::Unresolved { .. }))
    );
}

#[test]
fn unknown_subcommand_is_a_boundary() {
    let plan = exec(&["aws", "s3", "presign", "s3://b/k"]);
    assert!(
        plan.boundaries
            .iter()
            .any(|b| b.reason.as_str() == "unmodeled_subcommand")
    );
}

#[test]
fn gcloud_ssh_commands_run_in_the_instance_realm() {
    for argv in [
        &[
            "gcloud",
            "compute",
            "ssh",
            "vm",
            "--zone",
            "z",
            "--command",
            "rm -rf /x",
        ][..],
        &["gcloud", "compute", "ssh", "user@vm", "--command=rm -rf /x"][..],
        &["gcloud", "compute", "ssh", "vm", "--", "rm", "-rf", "/x"][..],
    ] {
        let plan = exec(argv);
        assert!(plan.effects.iter().any(|effect| {
            effect.operation.0 == "filesystem.delete"
                && effect.realm
                    == (ExecutionRealm::Remote {
                        endpoint: "gce:vm".to_string(),
                    })
        }));
        assert!(has_operation(&plan, "network.connect"));
        assert!(
            plan.boundaries
                .iter()
                .any(|boundary| boundary.reason.as_str() == "partial_analysis")
        );
        assert!(
            !plan
                .boundaries
                .iter()
                .any(|boundary| boundary.reason.as_str() == "unmodeled_subcommand")
        );
    }

    let interactive = exec(&["gcloud", "compute", "ssh", "vm"]);
    assert!(has_operation(&interactive, "network.connect"));
    assert!(!has_operation(&interactive, "filesystem.delete"));

    let cloud_shell = exec(&["gcloud", "cloud-shell", "ssh", "--command", "rm -rf /x"]);
    assert!(cloud_shell.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.delete"
            && effect.realm
                == (ExecutionRealm::Remote {
                    endpoint: "gce:cloud-shell".to_string(),
                })
    }));
}

#[test]
fn aws_ssm_start_session_recovers_shorthand_and_json_commands() {
    for parameters in ["command=rm -rf /x", r#"{"command":["rm -rf /x"]}"#] {
        let plan = exec(&[
            "aws",
            "ssm",
            "start-session",
            "--target",
            "i-1",
            "--document-name",
            "AWS-StartInteractiveCommand",
            "--parameters",
            parameters,
        ]);
        assert!(plan.effects.iter().any(|effect| {
            effect.operation.0 == "filesystem.delete"
                && effect.realm
                    == (ExecutionRealm::Remote {
                        endpoint: "ssm:i-1".to_string(),
                    })
        }));
    }

    let dynamic = shell(
        "aws ssm start-session --target i-1 --document-name AWS-StartInteractiveCommand --parameters command=\"$CMD\"",
    );
    assert!(
        dynamic
            .boundaries
            .iter()
            .any(|boundary| boundary.reason.as_str() == "unrecoverable_source")
    );
    assert!(!has_operation(&dynamic, "filesystem.delete"));
}

#[test]
fn aws_ssm_send_command_runs_each_line_on_each_instance() {
    let plan = exec(&[
        "aws",
        "ssm",
        "send-command",
        "--instance-ids",
        "i-1",
        "i-2",
        "--document-name",
        "AWS-RunShellScript",
        "--parameters",
        r#"commands=["rm -rf /x"]"#,
    ]);
    for endpoint in ["ssm:i-1", "ssm:i-2"] {
        assert!(plan.effects.iter().any(|effect| {
            effect.operation.0 == "filesystem.delete"
                && effect.realm
                    == (ExecutionRealm::Remote {
                        endpoint: endpoint.to_string(),
                    })
        }));
    }
    assert_eq!(
        plan.effects
            .iter()
            .filter(|effect| effect.operation.0 == "network.connect")
            .count(),
        2
    );

    let parameter = exec(&["aws", "ssm", "get-parameter", "--name", "/api"]);
    assert_eq!(
        object(&parameter, "credential.read"),
        Some(ResourceIdentity::CredentialStore {
            provider: "aws-ssm".into(),
            store: None,
            path: Some("/api".into()),
        })
    );
}

#[test]
fn az_vm_run_command_runs_scripts_in_the_vm_realm() {
    let plan = exec(&[
        "az",
        "vm",
        "run-command",
        "invoke",
        "-g",
        "rg",
        "-n",
        "vm",
        "--command-id",
        "RunShellScript",
        "--scripts",
        "cd /tmp",
        "rm -rf /x",
    ]);
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.delete"
            && effect.realm
                == (ExecutionRealm::Remote {
                    endpoint: "azure-vm:vm".to_string(),
                })
    }));
}

#[test]
fn cloud_op_on_wrong_identity_is_rejected() {
    use effinterp_proto::Operation;
    let mut plan = exec(&["aws", "s3", "rm", "s3://b/k"]);
    // A cloud.object.* targeting a filesystem path is incoherent.
    plan.effects[0].operation = Operation::new("cloud.object.delete");
    plan.effects[0].resource = ResourceExpr::Concrete {
        identity: ResourceIdentity::FsPath {
            path: "/etc/passwd".into(),
        },
    };
    plan.stamp_effect_ids().unwrap();
    assert!(validate_plan(&plan).is_err());
}

#[test]
fn cloud_scope_retains_deployment_identity_and_supplied_region_precedence() {
    use effinterp_proto::{
        ScopeDimension as D, ScopeMatch, ScopeValue as V, compare_scoped_identity,
    };
    let identity = |argv: &[&str]| object(&exec(argv), "cloud.resource.delete").unwrap();
    let a = identity(&[
        "gcloud",
        "--project",
        "project-a",
        "compute",
        "instances",
        "delete",
        "web",
        "--zone=us-central1-a",
    ]);
    let b = identity(&[
        "gcloud",
        "compute",
        "instances",
        "delete",
        "web",
        "--project",
        "project-b",
        "--zone",
        "us-central1-a",
    ]);
    assert_eq!(compare_scoped_identity(&a, &b), Some(ScopeMatch::None));
    let full = identity(&[
        "gcloud",
        "compute",
        "instances",
        "delete",
        "projects/project-a/zones/us-central1-a/instances/web",
    ]);
    assert_eq!(a, full);
    let a = identity(&[
        "aws",
        "--profile",
        "prod",
        "--region=eu-west-1",
        "ec2",
        "terminate-instances",
        "--instance-ids",
        "i-1",
    ]);
    assert_eq!(a.scope().unwrap().identity[&D::Account], V::Unknown);
    assert_eq!(
        a.scope().unwrap().identity[&D::Region],
        V::value(ResourceExpr::Literal {
            value: "eu-west-1".into()
        })
    );
    let plan = shell(
        "AWS_DEFAULT_REGION=us-west-2 AWS_REGION=eu-west-1 aws ec2 terminate-instances --instance-ids i-1",
    );
    let b = object(&plan, "cloud.resource.delete").unwrap();
    assert_eq!(a.scope().unwrap().identity, b.scope().unwrap().identity);
    let plan = shell("aws ec2 terminate-instances --instance-ids i-1 --region $REGION");
    let symbolic = object(&plan, "cloud.resource.delete").unwrap();
    assert!(
        matches!(&symbolic.scope().unwrap().identity[&D::Region], V::Value(value) if matches!(value.as_ref(), ResourceExpr::Environment { name } if name == "REGION"))
    );
    let from_environment = object(
        &shell("AWS_REGION=$REGION aws ec2 terminate-instances --instance-ids i-1"),
        "cloud.resource.delete",
    )
    .unwrap();
    assert_eq!(
        from_environment.scope().unwrap().identity[&D::Region],
        symbolic.scope().unwrap().identity[&D::Region]
    );
    let loop_plan = shell(
        "for REGION in us-east-1 eu-west-1; do aws ec2 terminate-instances --instance-ids i-1 --region \"$REGION\"; done",
    );
    let loop_deletes: Vec<_> = loop_plan
        .effects
        .iter()
        .filter(|effect| effect.operation.0 == "cloud.resource.delete")
        .collect();
    assert_eq!(loop_deletes.len(), 2);
    for expected in ["us-east-1", "eu-west-1"] {
        assert!(loop_deletes.iter().any(|effect| {
            matches!(
                &effect.resource,
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::CloudResource { scope, .. }
                }
                    if matches!(scope.identity.get(&D::Region), Some(V::Value(value))
                        if matches!(value.as_ref(), ResourceExpr::Literal { value } if value == expected))
            )
        }));
    }
    for source in [
        "AWS_REGION= aws ec2 terminate-instances --instance-ids i-1",
        "export AWS_DEFAULT_REGION=\"\"; aws ec2 terminate-instances --instance-ids i-1",
        "R=\"\"; AWS_REGION=$R aws ec2 terminate-instances --instance-ids i-1",
        "AWS_REGION= aws ec2 terminate-instances --instance-ids arn:aws:ec2:eu-west-1:123456789012:instance/i-1",
        "for REGION in eu-west-1 ''; do AWS_REGION=$REGION aws ec2 terminate-instances --instance-ids i-1; done",
    ] {
        let plan = shell(source);
        if source.contains("for REGION") {
            let deletes: Vec<_> = plan
                .effects
                .iter()
                .filter(|effect| effect.operation.0 == "cloud.resource.delete")
                .collect();
            assert_eq!(deletes.len(), 2);
            assert!(deletes.iter().any(|effect| {
                matches!(
                    &effect.resource,
                    ResourceExpr::Concrete {
                        identity: ResourceIdentity::CloudResource { scope, .. }
                    }
                        if scope.identity.get(&D::Region) == Some(&V::Unknown)
                )
            }));
            assert!(deletes.iter().any(|effect| {
                matches!(
                    &effect.resource,
                    ResourceExpr::Concrete {
                        identity: ResourceIdentity::CloudResource { scope, .. }
                    }
                        if matches!(scope.identity.get(&D::Region), Some(V::Value(value))
                            if matches!(value.as_ref(), ResourceExpr::Literal { value } if value == "eu-west-1"))
                )
            }));
            continue;
        }
        let target = object(&plan, "cloud.resource.delete").unwrap();
        assert!(matches!(&target, ResourceIdentity::CloudResource {
            provider: Some(provider), service, kind, id, ..
        } if provider == "aws" && service == "ec2" && kind == "instance" && id.as_deref() == Some("i-1")));
        assert_eq!(target.scope().unwrap().identity[&D::Region], V::Unknown);
        if source.contains("arn:aws") {
            assert_eq!(
                target.scope().unwrap().identity[&D::Account],
                V::value(ResourceExpr::Literal {
                    value: "123456789012".into(),
                })
            );
        }
        assert!(plan.boundaries.iter().any(|boundary| boundary.reason
            == effinterp_proto::BoundaryReason::UNRECOGNIZED_ARGUMENTS
            && !boundary.provenance.is_empty()));
        assert!(
            plan.boundaries.iter().all(
                |boundary| boundary.reason != effinterp_proto::BoundaryReason::UNTYPED_RESOURCE
            )
        );
    }
    let blob = |account: &str| {
        object(
            &exec(&[
                "az",
                "storage",
                "blob",
                "delete",
                "--container-name",
                "c",
                "--name",
                "k",
                "--account-name",
                account,
            ]),
            "cloud.object.delete",
        )
        .unwrap()
    };
    assert_eq!(
        compare_scoped_identity(&blob("one"), &blob("two")),
        Some(ScopeMatch::None)
    );
    let s3 = |profile: &str, region: &str| {
        object(
            &exec(&[
                "aws",
                "s3",
                "rm",
                "s3://bucket/key",
                "--profile",
                profile,
                "--region",
                region,
            ]),
            "cloud.object.delete",
        )
        .unwrap()
    };
    assert_eq!(
        s3("one", "eu-west-1").scope().unwrap().identity,
        s3("two", "us-east-1").scope().unwrap().identity
    );
}

#[test]
fn composed_scope_parameters_preserve_known_companion_fields_and_union_conflicts() {
    use effinterp_proto::{ScopeDimension as D, ScopeMatch, ScopeValue as V, compare_scope};
    let mut identity = effinterp_proto::cloud_scope(Some("aws"), "ec2", "instance");
    identity.identity.insert(
        D::Partition,
        V::value(ResourceExpr::Literal {
            value: "aws".into(),
        }),
    );
    identity.identity.insert(
        D::Account,
        V::value(ResourceExpr::Literal {
            value: "111111111111".into(),
        }),
    );
    identity.identity.insert(
        D::Region,
        V::value(ResourceExpr::Parameter {
            name: "region".into(),
        }),
    );
    let resource = ResourceExpr::Concrete {
        identity: ResourceIdentity::CloudResource {
            scope: Box::new(identity.clone()),
            provider: Some("aws".into()),
            service: "ec2".into(),
            kind: "instance".into(),
            id: Some("i-1".into()),
        },
    };
    let binding = std::collections::HashMap::from([(
        "region".into(),
        ResourceExpr::Union {
            alternatives: vec![
                ResourceExpr::Literal {
                    value: "eu-west-1".into(),
                },
                ResourceExpr::Literal {
                    value: "eu-west-2".into(),
                },
            ],
        },
    )]);
    let ResourceExpr::Concrete { identity: composed } =
        effinterp_engine::substitute_resource_expr(&resource, &binding)
    else {
        panic!()
    };
    let actual = composed.scope().unwrap();
    assert_eq!(actual.identity[&D::Account], identity.identity[&D::Account]);
    assert!(
        matches!(&actual.identity[&D::Region], V::Value(v) if matches!(v.as_ref(), ResourceExpr::Union { .. }))
    );
    identity.identity.insert(
        D::Region,
        V::value(ResourceExpr::Literal {
            value: "us-east-1".into(),
        }),
    );
    assert_eq!(compare_scope(&identity, actual), ScopeMatch::None);
}

#[test]
fn ec2_lifecycle_verbs_preserve_ids_and_permission_check_modes() {
    for (verb, op) in [
        ("describe-instances", "read"),
        ("create-tags", "update"),
        ("start-instances", "start"),
        ("stop-instances", "stop"),
        ("reboot-instances", "restart"),
        ("terminate-instances", "delete"),
    ] {
        let flag = if verb == "create-tags" {
            "--resources"
        } else {
            "--instance-ids"
        };
        let plan = exec(&[
            "aws",
            "--region",
            "us-west-2",
            "ec2",
            verb,
            flag,
            "i-one",
            "i-two",
        ]);
        let operation = format!("cloud.resource.{op}");
        assert_eq!(
            plan.effects
                .iter()
                .filter(|e| e.operation.as_str() == operation)
                .count(),
            2
        );
        for mode in ["--dry-run", "--generate-cli-skeleton"] {
            let plan = exec(&["aws", "ec2", verb, flag, "i-one", mode]);
            if op != "read" || mode == "--generate-cli-skeleton" {
                assert!(!has_operation(&plan, &operation));
            }
            if mode == "--dry-run" {
                assert!(has_operation(&plan, "network.request"));
            }
        }
    }
    let plan = exec(&[
        "aws",
        "ec2",
        "run-instances",
        "--image-id",
        "ami-image",
        "--count",
        "2",
    ]);
    assert!(has_operation(&plan, "cloud.resource.create"));
    assert!(matches!(
        effect(&plan, "cloud.resource.create").resource,
        ResourceExpr::Unresolved { .. }
    ));
    assert!(plan.boundaries.iter().any(|boundary| {
        boundary.class == effinterp_proto::BoundaryClass::Unmodeled
            && boundary.reason == effinterp_proto::BoundaryReason::LIVE_INVENTORY
    }));
    let missing_ids = exec(&["aws", "ec2", "terminate-instances"]);
    assert!(
        !missing_ids
            .boundaries
            .iter()
            .any(|boundary| { boundary.reason == effinterp_proto::BoundaryReason::LIVE_INVENTORY })
    );
    for indirect in ["file://instances.json", r#"["i-one"]"#] {
        let plan = exec(&[
            "aws",
            "ec2",
            "terminate-instances",
            "--instance-ids",
            indirect,
        ]);
        assert!(matches!(
            effect(&plan, "cloud.resource.delete").resource,
            ResourceExpr::Unresolved { .. }
        ));
        assert!(!plan.boundaries.is_empty());
    }
}

#[test]
fn cloud_transport_preserves_explicit_endpoints_and_local_absence() {
    let scoped = shell(
        "AWS_ENDPOINT_URL_EC2=https://control.example aws ec2 stop-instances --instance-ids i-1",
    );
    assert!(
        matches!(&effect(&scoped, "network.request").resource, ResourceExpr::Concrete { identity: ResourceIdentity::NetworkEndpoint { host, .. } } if host == "control.example")
    );
    assert!(!has_operation(&scoped, "network.connect"));

    for argv in [
        vec![
            "aws",
            "--endpoint-url",
            "https://control.example:8443",
            "s3",
            "rm",
            "s3://bucket/key",
        ],
        vec![
            "aws",
            "--endpoint-url",
            "https://control.example:8443",
            "ec2",
            "stop-instances",
            "--instance-ids",
            "i-1",
        ],
        vec![
            "az",
            "storage",
            "blob",
            "delete",
            "--blob-url",
            "https://control.blob.core.windows.net/c/k",
        ],
    ] {
        let plan = exec(&argv);
        let network: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.domain() == "network")
            .collect();
        assert_eq!(network.len(), 1);
        assert!(
            matches!(&network[0].resource, ResourceExpr::Concrete { identity: ResourceIdentity::NetworkEndpoint { host, .. } } if host.starts_with("control."))
        );
    }
    for argv in [
        vec!["aws", "s3", "cp", "./one", "./two"],
        vec!["aws", "--help"],
        vec!["gsutil", "--version"],
    ] {
        let plan = exec(&argv);
        assert!(
            !plan
                .effects
                .iter()
                .any(|effect| effect.operation.domain() == "network")
        );
    }
    let plan = shell("aws s3 cp ./one $DEST");
    assert!(!has_operation(&plan, "network.connect"));
    assert_ne!(
        plan.coverage
            .0
            .get(&Domain::new("network"))
            .map(|claim| &claim.level),
        Some(&CoverageLevel::Full)
    );
}

/// A synchronizing or recursive removal is the destructive half of these
/// object-store CLIs: the deletion must survive the transfer they also do.
#[test]
fn synchronizing_and_recursive_removals_delete_the_destination() {
    for (argv, bucket) in [
        (
            vec!["aws", "s3", "sync", "build/", "s3://site", "--delete"],
            "site",
        ),
        (
            vec![
                "aws",
                "s3",
                "sync",
                "build/",
                "s3://site",
                "--delete",
                "--exclude",
                "*.map",
            ],
            "site",
        ),
        (
            vec![
                "gcloud",
                "storage",
                "rsync",
                "build/",
                "gs://site",
                "--delete-unmatched-destination-objects",
            ],
            "site",
        ),
        (
            vec!["gsutil", "-m", "rsync", "-dr", "build/", "gs://site"],
            "site",
        ),
        (
            vec!["gsutil", "-m", "rm", "-R", "gs://bucket/prefix"],
            "bucket",
        ),
        (
            vec![
                "azcopy",
                "sync",
                "build",
                "https://account.blob.core.windows.net/site",
                "--delete-destination=true",
            ],
            "site",
        ),
        (
            vec![
                "azcopy",
                "rm",
                "https://account.blob.core.windows.net/site",
                "--recursive=true",
            ],
            "site",
        ),
        (vec!["rclone", "purge", "remote:old"], "remote"),
        (vec!["rclone", "delete", "remote:old"], "remote"),
        (
            vec![
                "rclone",
                "--config",
                "/tmp/rclone.conf",
                "sync",
                ".",
                "remote:mirror",
            ],
            "remote",
        ),
    ] {
        let plan = exec(&argv);
        if argv[0] == "rclone" {
            assert!(!plan.coverage.is_full(&Domain::new("cloud")));
            assert!(plan.boundaries.iter().any(|boundary| {
                boundary.reason == effinterp_proto::BoundaryReason::ENVIRONMENT_CONFIGURATION
                    && boundary.class == BoundaryClass::Unresolved
                    && boundary.domains.contains(&Domain::new("cloud"))
            }));
        }

        assert!(
            matches!(
                object(&plan, "cloud.object.delete"),
                Some(ResourceIdentity::ObjectStore { bucket: named, .. }) if named == bucket
            ),
            "{argv:?}: {:?}",
            plan.effects
        );
        if argv.contains(&"--exclude") {
            let deletion = plan
                .effects
                .iter()
                .find(|effect| effect.operation.0 == "cloud.object.delete")
                .expect("filtered synchronization deletion");
            assert_eq!(
                deletion.attributes.get("filter_value_0"),
                Some(&AttrValue::String("*.map".into()))
            );
        }
    }
    // Copying, a dry run and an explicitly disabled delete remove nothing.
    for argv in [
        vec!["aws", "s3", "sync", "build/", "s3://site"],
        vec!["gsutil", "-m", "rsync", "-r", "build/", "gs://site"],
        vec!["gcloud", "storage", "rsync", "build/", "gs://site"],
        vec![
            "azcopy",
            "sync",
            "build",
            "https://account.blob.core.windows.net/site",
            "--delete-destination=false",
        ],
        vec!["rclone", "copy", ".", "remote:copy"],
        vec!["rclone", "sync", ".", "remote:mirror", "--dry-run"],
    ] {
        let plan = exec(&argv);
        assert!(
            !has_operation(&plan, "cloud.object.delete"),
            "{argv:?}: {:?}",
            plan.effects
        );
    }
    // An rclone operand without a `remote:` prefix is an ordinary local path.
    let plan = exec(&["rclone", "purge", "/srv/cache"]);
    assert!(!has_operation(&plan, "cloud.object.delete"));
    assert!(has_operation(&plan, "filesystem.delete"));
}

/// Snapshots, disks and storage accounts are deleted by their own identifier
/// option rather than the instance-id list the lifecycle verbs share.
#[test]
fn cloud_snapshot_disk_and_account_deletions_name_their_resource() {
    for (argv, operation, name) in [
        (
            vec!["aws", "ec2", "delete-snapshot", "--snapshot-id", "snap-1"],
            "cloud.resource.delete",
            "snap-1",
        ),
        (
            vec!["aws", "ec2", "delete-volume", "--volume-id", "vol-1"],
            "cloud.resource.delete",
            "vol-1",
        ),
        (
            vec!["az", "snapshot", "delete", "-n", "snap-1", "-g", "prod"],
            "cloud.resource.delete",
            "snap-1",
        ),
        (
            vec!["az", "disk", "delete", "--name", "disk-1", "--yes"],
            "cloud.resource.delete",
            "disk-1",
        ),
        (
            vec![
                "az", "storage", "account", "delete", "--name", "scratch", "--yes",
            ],
            "cloud.resource.delete",
            "scratch",
        ),
        (
            vec![
                "az",
                "storage",
                "container",
                "delete",
                "--account-name",
                "prod",
                "--name",
                "backups",
            ],
            "cloud.object.delete",
            "backups",
        ),
        (
            vec![
                "az",
                "storage",
                "blob",
                "delete-batch",
                "--account-name",
                "prod",
                "--source",
                "artifacts",
            ],
            "cloud.object.delete",
            "artifacts",
        ),
    ] {
        let plan = exec(&argv);
        let named = match object(&plan, operation) {
            Some(ResourceIdentity::CloudResource { id: Some(id), .. }) => id,
            Some(ResourceIdentity::ObjectStore { bucket, .. }) => bucket,
            other => panic!("{argv:?}: {other:?}"),
        };
        assert_eq!(named, name, "{argv:?}");
    }
    // Reading and syncing blobs are not removals.
    for argv in [
        vec![
            "az",
            "storage",
            "blob",
            "sync",
            "--account-name",
            "prod",
            "--container",
            "site",
        ],
        vec!["az", "storage", "account", "show", "--name", "scratch"],
    ] {
        let plan = exec(&argv);
        assert!(!has_operation(&plan, "cloud.object.delete"), "{argv:?}");
        assert!(!has_operation(&plan, "cloud.resource.delete"), "{argv:?}");
    }
}

#[test]
fn az_global_arguments_and_joined_container_names() {
    for source in [
        "az --subscription prod --debug storage container delete --name backups --auth-mode login --only-show-errors --output json --query deleted --verbose",
        "az storage container delete --account-name=prod --name=backups",
        "az storage container delete -nbackups --bypass-immutability-policy --acquire-policy-token --change-reference ticket",
    ] {
        let plan = shell(source);
        let delete = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "cloud.object.delete")
            .unwrap_or_else(|| panic!("{source}"));
        assert!(
            matches!(&delete.resource, ResourceExpr::Concrete {
                identity: ResourceIdentity::ObjectStore { bucket, .. },
            } if bucket == "backups"),
            "{source}"
        );
        assert_eq!(
            delete.attributes.get("recursive"),
            Some(&AttrValue::Bool(true)),
            "{source}"
        );
        assert!(plan.coverage.is_full(&Domain::new("cloud")), "{source}");
        assert!(
            plan.boundaries.is_empty(),
            "{source}: {:?}",
            plan.boundaries
        );
    }
    // A global argument before the group is not the group.
    let unknown = shell("az --subscription prod storage container list");
    assert_eq!(
        unknown.coverage.level(&Domain::new("cloud")),
        Some(CoverageLevel::Partial)
    );
}
