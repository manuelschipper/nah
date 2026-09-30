//! Declarative definition for the database-destruction guard.

use effinterp_matcher::{
    Assertion, AttributePredicate, ConditionPredicate, OperationMatch, Query, ResourcePredicate,
    Selector, TextPredicate,
};
use nah_proto::effects::Domain;

use crate::registry::{GuardDefinition, GuardFamily, engine_only};
use crate::shared_queries::{bool_attr, family, present_attr, string_attr, string_one_of};

/// Managed-database resources whose deletion removes live data, as the
/// engine's cloud models name them: `(provider, service, kind)`. Timestream
/// databases are absent because the service only deletes an empty one.
const DB_RESOURCES: &[(&str, &str, &[&str])] = &[
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
    ("gcp", "sql", &["instance", "database"]),
    ("gcp", "spanner", &["instance", "database"]),
    ("gcp", "firestore", &["database"]),
    ("gcp", "bigtable", &["instance", "table"]),
    ("gcp", "alloydb", &["cluster"]),
    ("gcp", "redis", &["instance", "cluster"]),
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
    ("neon", "postgres", &["project", "branch", "database"]),
    ("planetscale", "database", &["database", "branch"]),
    ("turso", "database", &["database", "group"]),
    ("cloudflare", "d1", &["database"]),
    ("mongodb", "atlas", &["cluster", "serverless"]),
    ("upstash", "redis", &["database"]),
    ("upstash", "vector", &["index"]),
    ("upstash", "search", &["index"]),
    ("supabase", "projects", &["project"]),
    ("supabase", "branches", &["branch"]),
    ("heroku", "postgresql", &["addon"]),
    ("heroku", "redis", &["addon"]),
    ("fly", "mpg", &["cluster"]),
    ("digitalocean", "databases", &["cluster", "database"]),
];

pub(crate) fn db_destroy() -> GuardDefinition {
    let mut assertions = vec![
        // A view, external or foreign table, index, sequence, function or
        // role holds no data of its own, and a table snapshot is a recovery
        // copy that storage-snapshot-delete owns. A drop whose kind is
        // unknown stays indeterminate.
        destroys(
            "database.schema_drop",
            family("db"),
            vec![string_one_of(
                "object_kind",
                &[
                    "database",
                    "schema",
                    "keyspace",
                    "table",
                    "materialized_view",
                    "collection",
                    "owned_objects",
                    "database_objects",
                ],
            )],
            &["temporary"],
        ),
        // ClickHouse detached parts are a recovery copy that
        // storage-snapshot-delete owns.
        destroys("database.truncate", family("db"), vec![], &["detached"]),
        destroys(
            "database.write",
            family("db"),
            vec![
                string_attr("action", "delete"),
                present_attr("filtered"),
                bool_attr("filtered", false),
            ],
            &[],
        ),
        destroys(
            "database.write",
            family("db"),
            vec![string_attr("action", "overwrite")],
            &[],
        ),
        destroys(
            "database.schema_write",
            family("db"),
            vec![
                present_attr("replaces_existing"),
                bool_attr("replaces_existing", true),
                string_one_of(
                    "object_kind",
                    &["table", "schema", "database", "materialized_view"],
                ),
            ],
            &[],
        ),
        destroys(
            "database.schema_write",
            family("db"),
            vec![
                present_attr("drops_column"),
                bool_attr("drops_column", true),
            ],
            &[],
        ),
    ];
    // A whole-stack infrastructure-as-code teardown is infra-iac-destroy's;
    // a targeted or unresolved one may still reach a database.
    let whole_stack = Assertion::Not {
        assertion: Box::new(effect(
            "cloud.resource.delete",
            ResourcePredicate::Any,
            vec![present_attr("whole_stack"), bool_attr("whole_stack", true)],
        )),
    };
    for (provider, service, kinds) in DB_RESOURCES {
        for kind in *kinds {
            assertions.push(Assertion::All {
                assertions: vec![
                    destroys(
                        "cloud.resource.delete",
                        ResourcePredicate::CloudResource {
                            provider: Some(TextPredicate::Equals((*provider).into())),
                            service: Some(TextPredicate::Equals((*service).into())),
                            kind: Some(TextPredicate::Equals((*kind).into())),
                        },
                        vec![],
                        &[],
                    ),
                    whole_stack.clone(),
                ],
            });
        }
    }
    GuardDefinition {
        id: "db-destroy",
        reason: "db-destroy blocked deletion or replacement of database data; confirm the target environment and ask the operator to perform the reviewed drop, reset, or delete",
        family: GuardFamily::Infrastructure,
        default_enabled: false,
        domain: Domain::Database,
        gap_code: Some("database-destruction-scope-unavailable"),
        clauses: engine_only(Query::new(Assertion::Any { assertions })),
    }
}

/// A success-path `operation` on `resource` with `attributes`, unless the
/// effect states `dry_run` or any of `excluded` as true. An absent exclusion
/// counts as false.
fn destroys(
    operation: &str,
    resource: ResourcePredicate,
    attributes: Vec<AttributePredicate>,
    excluded: &[&str],
) -> Assertion {
    let mut assertions = vec![effect(operation, resource, attributes)];
    for name in ["dry_run"].iter().chain(excluded) {
        assertions.push(Assertion::Not {
            assertion: Box::new(effect(
                operation,
                ResourcePredicate::Any,
                vec![present_attr(name), bool_attr(name, true)],
            )),
        });
    }
    Assertion::All { assertions }
}

fn effect(
    operation: &str,
    resource: ResourcePredicate,
    attributes: Vec<AttributePredicate>,
) -> Assertion {
    Assertion::Effect {
        selector: Selector {
            operation: OperationMatch::Exact(operation.into()),
            resource,
            attributes,
            request_assurance: None,
            condition: Some(ConditionPredicate::SuccessPath),
            modality: None,
            execution_assurance: None,
            realm: None,
        },
        closure: None,
    }
}
