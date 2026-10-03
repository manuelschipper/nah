//! Declarative definitions for the infrastructure guards, including the
//! storage guards that belong to the infrastructure family.

use effinterp_matcher::{
    Assertion, AttributePredicate, AttributeTest, Query, RealmPredicate, ResourcePredicate,
    ResourceVariant, SelectionShape, TextPredicate,
};
use effinterp_proto::{ExecutionAssurance, RequestAssurance};
use nah_proto::effects::Domain;

use crate::registry::{GuardDefinition, GuardFamily, engine_only};
use crate::shared_queries::{
    bool_attr, present_attr, resource_family, resource_selection, resource_variant, string_attr,
    string_one_of, success_path_effect,
};

pub(crate) fn infra_container_reset() -> GuardDefinition {
    GuardDefinition {
        id: "infra-container-reset",
        reason: "infra-container-reset blocked a complete Podman runtime reset; keep the runtime state intact and ask the operator to perform any deliberate reset",
        family: GuardFamily::Infrastructure,
        default_enabled: true,
        domain: Domain::Container,
        gap_code: Some("semantic-fields-unavailable"),
        clauses: engine_only(Query::new(success_path_effect(
            "container.remove",
            ResourcePredicate::Any,
            vec![
                string_attr("scope", "system"),
                string_attr("mode", "reset"),
                bool_attr("volumes", true),
                bool_attr("active", true),
                bool_attr("dry_run", false),
            ],
            None,
            None,
        ))),
    }
}

pub(crate) fn infra_container_volume_delete() -> GuardDefinition {
    GuardDefinition {
        id: "infra-container-volume-delete",
        reason: "infra-container-volume-delete blocked container volume deletion; narrow the cleanup or ask the operator to perform the reviewed prune or teardown",
        family: GuardFamily::Infrastructure,
        default_enabled: false,
        domain: Domain::Container,
        gap_code: Some("semantic-fields-unavailable"),
        clauses: engine_only(Query::new(Assertion::Any {
            assertions: vec![
                success_path_effect(
                    "container.remove",
                    ResourcePredicate::Any,
                    vec![
                        string_attr("scope", "compose"),
                        present_attr("volumes"),
                        bool_attr("volumes", true),
                        bool_attr("active", true),
                        bool_attr("dry_run", false),
                    ],
                    None,
                    None,
                ),
                success_path_effect(
                    "container.remove",
                    ResourcePredicate::Any,
                    vec![
                        string_attr("scope", "system"),
                        string_attr("mode", "prune"),
                        bool_attr("volumes", true),
                        bool_attr("active", true),
                        bool_attr("dry_run", false),
                    ],
                    None,
                    None,
                ),
                success_path_effect(
                    "container.remove",
                    ResourcePredicate::Any,
                    vec![
                        string_attr("scope", "volume"),
                        string_attr("mode", "prune"),
                        bool_attr("volumes", true),
                        bool_attr("all", true),
                        bool_attr("active", true),
                        bool_attr("dry_run", false),
                    ],
                    None,
                    None,
                ),
            ],
        })),
    }
}

/// Infrastructure teardown: a whole-stack infrastructure-as-code destroy, or
/// a reviewed provider or platform CLI delete of a `CLOUD_RESOURCES` kind.
/// Only an exact request counts: the engine marks one when every option of
/// the invocation is one the reviewed table documents and the resource is
/// named literally or is the one the CLI is linked to. Help, dry runs and
/// unknown options leave the request conservative, and the call delegates.
/// A CLI delete that states its `mode` is IaC teardown and reaches only the
/// whole-stack clauses.
pub(crate) fn infra_iac_destroy() -> GuardDefinition {
    let controls = vec![
        string_attr("mode", "destroy"),
        bool_attr("whole_stack", true),
        bool_attr("active", true),
        bool_attr("preview", false),
        bool_attr("help", false),
        bool_attr("dry_run", false),
    ];
    let mut unresolved_controls = controls.clone();
    unresolved_controls.push(present_attr("mode"));
    let mut assertions = vec![
        success_path_effect(
            "cloud.resource.delete",
            resource_variant(ResourceVariant::ManagedInfrastructure),
            controls,
            Some(RequestAssurance::Exact),
            None,
        ),
        success_path_effect(
            "cloud.resource.delete",
            resource_family("cloud"),
            unresolved_controls,
            Some(RequestAssurance::Exact),
            None,
        ),
    ];
    for (provider, service, kinds) in CLOUD_RESOURCES {
        for kind in *kinds {
            assertions.push(effect_without_attribute(
                "cloud.resource.delete",
                ResourcePredicate::CloudResource {
                    provider: Some(TextPredicate::Equals((*provider).into())),
                    service: Some(TextPredicate::Equals((*service).into())),
                    kind: Some(TextPredicate::Equals((*kind).into())),
                },
                vec![],
                Some(RequestAssurance::Exact),
                None,
                "mode",
            ));
        }
    }
    GuardDefinition {
        id: "infra-iac-destroy",
        reason: "infra-iac-destroy blocked tearing down provisioned infrastructure; keep it intact and ask the operator to perform the teardown",
        family: GuardFamily::Infrastructure,
        default_enabled: false,
        domain: Domain::Infrastructure,
        gap_code: Some("infrastructure-destruction-mode-unavailable"),
        clauses: engine_only(Query::new(Assertion::Any { assertions })),
    }
}

/// Provisioned cloud and hosted-platform resources whose deletion the engine's
/// reviewed command tables establish: `(provider, service, kinds)` as the
/// models name them. Snapshots, backups, disks and storage volumes are the
/// storage guards', object storage and secrets stores have their own guards,
/// Cloud SQL users and certificates hold no data, and Timestream deletes only
/// an empty database.
const CLOUD_RESOURCES: &[(&str, &str, &[&str])] = &[
    (
        "aws",
        "ec2",
        &["instance", "vpc", "subnet", "security-group"],
    ),
    ("aws", "rds", &["db", "cluster"]),
    ("aws", "docdb", &["cluster"]),
    ("aws", "docdb-elastic", &["cluster"]),
    ("aws", "neptune", &["cluster"]),
    ("aws", "redshift", &["cluster"]),
    ("aws", "redshift-serverless", &["namespace"]),
    ("aws", "dynamodb", &["table"]),
    ("aws", "keyspaces", &["keyspace", "table"]),
    ("aws", "timestream", &["table"]),
    (
        "aws",
        "elasticache",
        &["cache-cluster", "replication-group", "serverless-cache"],
    ),
    ("aws", "memorydb", &["cluster"]),
    ("aws", "lightsail", &["relational-database"]),
    ("aws", "dsql", &["cluster"]),
    ("aws", "eks", &["cluster"]),
    ("aws", "efs", &["file-system"]),
    ("aws", "kinesis", &["stream"]),
    ("aws", "logs", &["log-group"]),
    ("aws", "cloudtrail", &["trail"]),
    ("aws", "route53", &["hosted-zone"]),
    ("aws", "elbv2", &["load-balancer"]),
    ("aws", "cloudfront", &["distribution"]),
    ("aws", "lambda", &["function"]),
    ("aws", "ecr", &["repository"]),
    ("aws", "iam", &["user", "role", "group"]),
    ("aws", "cloudformation", &["stack"]),
    ("gcp", "compute", &["instance", "network", "firewall-rule"]),
    ("gcp", "sql", &["instance", "database"]),
    ("gcp", "spanner", &["instance", "database"]),
    ("gcp", "firestore", &["database"]),
    ("gcp", "bigtable", &["instance", "table"]),
    ("gcp", "alloydb", &["cluster"]),
    ("gcp", "redis", &["instance", "cluster"]),
    ("gcp", "container", &["cluster"]),
    ("gcp", "dataproc", &["cluster"]),
    ("gcp", "functions", &["function"]),
    ("gcp", "run", &["service"]),
    ("gcp", "dns", &["managed-zone"]),
    ("gcp", "iam", &["service-account"]),
    ("gcp", "projects", &["project"]),
    ("azure", "group", &["resource-group"]),
    ("azure", "vm", &["instance"]),
    ("azure", "aks", &["cluster"]),
    ("azure", "acr", &["registry"]),
    ("azure", "webapp", &["app"]),
    ("azure", "functionapp", &["app"]),
    ("azure", "network", &["vnet", "dns-zone"]),
    ("azure", "ad", &["service-principal", "application"]),
    ("azure", "sql", &["database", "server", "managed-instance"]),
    (
        "azure",
        "cosmosdb",
        &[
            "account",
            "database",
            "keyspace",
            "container",
            "collection",
            "graph",
            "table",
        ],
    ),
    ("azure", "postgres", &["server", "database"]),
    ("azure", "mysql", &["server", "database"]),
    ("azure", "redis", &["cache"]),
    ("digitalocean", "compute", &["droplet"]),
    ("digitalocean", "databases", &["cluster", "database"]),
    ("fly", "mpg", &["cluster"]),
    ("heroku", "postgresql", &["addon"]),
    ("heroku", "redis", &["addon"]),
    ("neon", "postgres", &["project", "branch", "database"]),
    ("planetscale", "database", &["database", "branch"]),
    ("turso", "database", &["database", "group"]),
    ("upstash", "redis", &["database"]),
    ("upstash", "vector", &["index"]),
    ("upstash", "search", &["index"]),
    ("cloudflare", "workers", &["worker"]),
    ("cloudflare", "d1", &["database"]),
    ("cloudflare", "kv", &["namespace"]),
    ("cloudflare", "queues", &["queue"]),
    ("cloudflare", "hyperdrive", &["config"]),
    ("cloudflare", "pages", &["project"]),
    ("supabase", "projects", &["project"]),
    ("supabase", "branches", &["branch"]),
    ("supabase", "functions", &["function"]),
    ("railway", "project", &["project"]),
    ("railway", "environment", &["environment"]),
    ("railway", "volume", &["volume"]),
    ("railway", "service", &["service"]),
    ("railway", "function", &["function"]),
    ("modal", "app", &["app"]),
    ("modal", "environment", &["environment"]),
    ("modal", "volume", &["volume"]),
    ("modal", "dict", &["dict"]),
    ("modal", "queue", &["queue"]),
    ("kamal", "deployment", &["deployment"]),
    ("kamal", "app", &["app"]),
    ("kamal", "accessory", &["accessory"]),
    ("kamal", "proxy", &["proxy"]),
    ("fastly", "service", &["service"]),
];

pub(crate) fn infra_k8s_delete() -> GuardDefinition {
    let controls = vec![
        string_attr("mode", "delete"),
        bool_attr("active", true),
        bool_attr("preview", false),
        bool_attr("help", false),
        bool_attr("dry_run", false),
    ];
    let branch = |mut attributes: Vec<AttributePredicate>, resource| {
        attributes.extend(controls.clone());
        success_path_effect(
            "container.resource.delete",
            resource,
            attributes,
            None,
            Some(ExecutionAssurance::Exact),
        )
    };
    GuardDefinition {
        id: "infra-k8s-delete",
        reason: "infra-k8s-delete blocked a reviewed broad Kubernetes deletion; narrow the selection or ask the operator to perform the cluster change",
        family: GuardFamily::Infrastructure,
        default_enabled: false,
        domain: Domain::Container,
        gap_code: Some("kubernetes-scope-and-selection-unavailable"),
        clauses: engine_only(Query::new(Assertion::Any {
            assertions: vec![
                branch(
                    vec![string_one_of("scope", &["namespace", "cluster"])],
                    resource_variant(ResourceVariant::KubernetesResource),
                ),
                branch(
                    vec![
                        string_attr("scope", "namespaced"),
                        string_attr("selection", "whole"),
                    ],
                    ResourcePredicate::KubernetesResource {
                        namespace: None,
                        selection: Some(SelectionShape::Whole),
                    },
                ),
                branch(
                    vec![
                        string_attr("scope", "namespaced"),
                        string_attr("selection", "pattern"),
                        required_attr("selector"),
                    ],
                    ResourcePredicate::KubernetesResource {
                        namespace: None,
                        selection: Some(SelectionShape::Pattern),
                    },
                ),
            ],
        })),
    }
}

pub(crate) fn storage_backup_destroy() -> GuardDefinition {
    let operations = [
        "filesystem.delete",
        "filesystem.write",
        "filesystem.move",
        "cloud.object.delete",
    ];
    let mut assertions = Vec::new();
    for operation in operations {
        assertions.push(success_path_effect(
            operation,
            ResourcePredicate::Any,
            vec![
                present_attr("backup_action"),
                string_attr("backup_action", "delete_repository"),
                bool_attr("whole_repository", true),
            ],
            None,
            None,
        ));
        for action in [
            "delete_archive",
            "delete_snapshot",
            "delete_backup",
            "delete_backup_set",
        ] {
            for control in ["unsafe_allow_remove_all", "all_requested"] {
                assertions.push(success_path_effect(
                    operation,
                    ResourcePredicate::Any,
                    vec![
                        present_attr("backup_action"),
                        string_attr("backup_action", action),
                        bool_attr(control, true),
                    ],
                    None,
                    None,
                ));
            }
        }
    }
    GuardDefinition {
        id: "storage-backup-destroy",
        reason: "storage-backup-destroy blocked deletion of a complete backup repository or every selected backup; keep the recovery set intact and ask the operator to perform any deliberate repository removal",
        family: GuardFamily::Infrastructure,
        default_enabled: true,
        domain: Domain::Storage,
        gap_code: Some("semantic-fields-unavailable"),
        clauses: engine_only(Query::new(Assertion::Any { assertions })),
    }
}

pub(crate) fn storage_recursive_delete() -> GuardDefinition {
    GuardDefinition {
        id: "storage-recursive-delete",
        reason: "storage-recursive-delete blocked broad remote deletion or destination-deleting synchronization; narrow the selection or ask the operator to perform the reviewed cleanup",
        family: GuardFamily::Infrastructure,
        default_enabled: false,
        domain: Domain::Storage,
        gap_code: Some("semantic-fields-unavailable"),
        clauses: engine_only(Query::new(Assertion::Any {
            assertions: vec![
                success_path_effect(
                    "cloud.object.delete",
                    unbounded_selection(resource_variant(ResourceVariant::ObjectStore)),
                    vec![present_attr("recursive"), bool_attr("recursive", true)],
                    None,
                    Some(ExecutionAssurance::Exact),
                ),
                success_path_effect(
                    "cloud.object.write",
                    unbounded_selection(resource_variant(ResourceVariant::ObjectStore)),
                    vec![bool_attr("delete", true)],
                    None,
                    Some(ExecutionAssurance::Exact),
                ),
                remote_filesystem_delete(),
                success_path_effect(
                    "filesystem.delete",
                    unbounded_selection(ResourcePredicate::Any),
                    vec![
                        present_attr("contents_only"),
                        required_attr("contents_only"),
                        bool_attr("contents_only", true),
                        bool_attr("delete", true),
                        bool_attr("active", true),
                        bool_attr("dry_run", false),
                        bool_attr("recursive", true),
                    ],
                    None,
                    Some(ExecutionAssurance::Exact),
                ),
                effect_without_attribute(
                    "cloud.resource.delete",
                    ResourcePredicate::CloudResource {
                        provider: None,
                        service: Some(TextPredicate::Equals("storage".into())),
                        kind: Some(TextPredicate::Equals("account".into())),
                    },
                    vec![],
                    None,
                    Some(ExecutionAssurance::Exact),
                    "mode",
                ),
            ],
        })),
    }
}

pub(crate) fn storage_snapshot_delete() -> GuardDefinition {
    let backup_operations = [
        "filesystem.delete",
        "filesystem.write",
        "filesystem.move",
        "cloud.object.delete",
    ];
    let mut assertions = Vec::new();
    for operation in backup_operations {
        assertions.push(success_path_effect(
            operation,
            ResourcePredicate::Any,
            vec![
                present_attr("backup_action"),
                string_one_of(
                    "backup_action",
                    &[
                        "delete_archive",
                        "delete_snapshot",
                        "delete_backup",
                        "delete_backup_set",
                    ],
                ),
                bool_attr("unsafe_allow_remove_all", false),
                bool_attr("all_requested", false),
            ],
            None,
            None,
        ));
    }
    for resource in [
        ResourcePredicate::StorageVolume {
            manager: Some(TextPredicate::Equals("btrfs".into())),
            name: None,
        },
        ResourcePredicate::StorageVolume {
            manager: Some(TextPredicate::Equals("zfs".into())),
            name: Some(TextPredicate::Contains("@".into())),
        },
        ResourcePredicate::StorageVolume {
            manager: Some(TextPredicate::Equals("zfs".into())),
            name: Some(TextPredicate::Contains("#".into())),
        },
    ] {
        assertions.push(nondry_effect("system.storage_destroy", resource, vec![]));
    }
    assertions.push(nondry_effect(
        "system.storage_destroy",
        resource_variant(ResourceVariant::StorageVolume),
        vec![
            string_attr("mode", "rollback"),
            bool_attr("newer_snapshots_destroyed", true),
        ],
    ));
    for provider in ["aws", "gcp", "azure", "heroku"] {
        for kind in [
            "snapshot",
            "snapshots",
            "volume",
            "volumes",
            "disk",
            "disks",
            "backup",
        ] {
            assertions.push(effect_without_attribute(
                "cloud.resource.delete",
                ResourcePredicate::CloudResource {
                    provider: Some(TextPredicate::Equals(provider.into())),
                    service: None,
                    kind: Some(TextPredicate::Equals(kind.into())),
                },
                vec![],
                None,
                Some(ExecutionAssurance::Exact),
                "mode",
            ));
        }
    }
    // A managed-database delete that skips its final snapshot, or removes its
    // automated backups with it, discards recovery points the service would
    // otherwise keep.
    for attribute in ["final_snapshot", "automated_backups_retained"] {
        assertions.push(effect_without_attribute(
            "cloud.resource.delete",
            ResourcePredicate::Any,
            vec![present_attr(attribute), bool_attr(attribute, false)],
            None,
            Some(ExecutionAssurance::Exact),
            "mode",
        ));
    }
    // A BigQuery table snapshot and ClickHouse detached parts are recovery
    // copies of a table rather than its live data.
    assertions.push(nondry_effect(
        "database.schema_drop",
        resource_family("db"),
        vec![
            present_attr("object_kind"),
            string_attr("object_kind", "table_snapshot"),
        ],
    ));
    assertions.push(nondry_effect(
        "database.truncate",
        resource_family("db"),
        vec![present_attr("detached"), bool_attr("detached", true)],
    ));
    GuardDefinition {
        id: "storage-snapshot-delete",
        reason: "storage-snapshot-delete blocked snapshot, backup, archive, volume, or retention deletion; keep the recovery point intact and ask the operator to perform the reviewed removal",
        family: GuardFamily::Infrastructure,
        default_enabled: false,
        domain: Domain::Storage,
        gap_code: Some("storage-target-kind-and-mode-unavailable"),
        clauses: engine_only(Query::new(Assertion::Any { assertions })),
    }
}

fn nondry_effect(
    operation: &str,
    resource: ResourcePredicate,
    attributes: Vec<AttributePredicate>,
) -> Assertion {
    let mut explicit = attributes.clone();
    explicit.push(bool_attr("dry_run", false));
    Assertion::Any {
        assertions: vec![
            success_path_effect(operation, resource.clone(), explicit, None, None),
            Assertion::All {
                assertions: vec![
                    success_path_effect(operation, resource.clone(), attributes, None, None),
                    Assertion::Not {
                        assertion: Box::new(success_path_effect(
                            operation,
                            resource,
                            vec![present_attr("dry_run")],
                            None,
                            None,
                        )),
                    },
                ],
            },
        ],
    }
}

fn effect_without_attribute(
    operation: &str,
    resource: ResourcePredicate,
    attributes: Vec<AttributePredicate>,
    request_assurance: Option<RequestAssurance>,
    execution_assurance: Option<ExecutionAssurance>,
    absent: &str,
) -> Assertion {
    Assertion::All {
        assertions: vec![
            success_path_effect(
                operation,
                resource,
                attributes,
                request_assurance,
                execution_assurance,
            ),
            Assertion::Not {
                assertion: Box::new(success_path_effect(
                    operation,
                    ResourcePredicate::Any,
                    vec![present_attr(absent)],
                    None,
                    None,
                )),
            },
        ],
    }
}

fn remote_filesystem_delete() -> Assertion {
    let mut assertion = success_path_effect(
        "filesystem.delete",
        unbounded_selection(resource_variant(ResourceVariant::FsPath)),
        vec![
            present_attr("contents_only"),
            required_attr("contents_only"),
            bool_attr("contents_only", true),
            bool_attr("active", true),
            bool_attr("dry_run", false),
            bool_attr("recursive", true),
        ],
        None,
        Some(ExecutionAssurance::Exact),
    );
    if let Assertion::Effect { selector, .. } = &mut assertion {
        selector.realm = Some(RealmPredicate::Remote);
    }
    assertion
}

fn unbounded_selection(resource: ResourcePredicate) -> ResourcePredicate {
    ResourcePredicate::All {
        predicates: vec![
            resource,
            ResourcePredicate::Not {
                predicate: Box::new(ResourcePredicate::AnyOf {
                    predicates: vec![
                        resource_selection(SelectionShape::NamedSet),
                        resource_selection(SelectionShape::Pattern),
                    ],
                }),
            },
        ],
    }
}

fn required_attr(name: &str) -> AttributePredicate {
    AttributePredicate {
        name: name.into(),
        test: AttributeTest::RequiredPresent,
    }
}
