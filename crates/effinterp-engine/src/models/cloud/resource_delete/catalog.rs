use crate::word::Word;

use super::{AZURE_DEVOPS, AutomatedBackups, CloudResourceDelete, Qualified};

const AZURE_DEVOPS_PROJECT_VALUES: &[&str] =
    &["--org", "--organization", "--project", "-p", "--detect"];

/// Selects a documented delete verb and rejects command words read as option values.
pub(super) fn resource_delete_row(
    argv: &[Word],
    tool: &str,
    words: &[usize],
    (common_values, common_switches, scope_values): (
        &'static [&'static str],
        &'static [&'static str],
        &'static [&'static str],
    ),
) -> Option<CloudResourceDelete> {
    use AutomatedBackups::*;
    // gcloud's alpha and beta tracks take the GA command words after the
    // track word.
    let track = usize::from(
        tool == "gcloud"
            && matches!(
                words.first().and_then(|&index| argv[index].as_literal()),
                Some("alpha" | "beta")
            ),
    );
    let at = |offset: usize| {
        words
            .get(track + offset)
            .and_then(|&index| argv[index].as_literal())
    };
    let aws_resource = |service: &'static str,
                        kind: &'static str,
                        id_flags: &'static [&'static str],
                        skip_final: (&'static str, &'static str),
                        final_snapshot: &'static str,
                        backups: AutomatedBackups| CloudResourceDelete {
        provider: "aws",
        service,
        kind,
        path: words[..2].to_vec(),
        id_flags,
        parents: &[],
        many: false,
        final_backup: None,
        keeps_data: None,
        qualified: Qualified::None,
        strict_names: false,
        slash_names: false,
        values: &[],
        switches: &[],
        common_values: &[],
        common_switches: &[],
        scope_values: &[],
        skip_final: Some(skip_final),
        final_snapshot: Some(final_snapshot),
        backups,
    };
    let point = |provider: &'static str,
                 service: &'static str,
                 kind: &'static str,
                 start: usize,
                 id_flags: &'static [&'static str],
                 values: &'static [&'static str],
                 switches: &'static [&'static str]| CloudResourceDelete {
        provider,
        service,
        kind,
        path: words[..track + start].to_vec(),
        id_flags,
        parents: &[],
        many: false,
        final_backup: None,
        keeps_data: None,
        qualified: Qualified::None,
        strict_names: false,
        slash_names: false,
        values,
        switches,
        common_values: &[],
        common_switches: &[],
        scope_values: &[],
        skip_final: None,
        final_snapshot: None,
        backups: NotApplicable,
    };
    // A live resource delete that makes no claim about the resource's backups.
    // Its names are checked before they become an ID.
    let resource = |provider: &'static str,
                    service: &'static str,
                    kind: &'static str,
                    start: usize,
                    id_flags: &'static [&'static str],
                    parents: &'static [&'static [&'static str]],
                    values: &'static [&'static str],
                    switches: &'static [&'static str]| CloudResourceDelete {
        parents,
        strict_names: true,
        ..point(provider, service, kind, start, id_flags, values, switches)
    };
    const SKIP: (&str, &str) = ("--skip-final-snapshot", "--no-skip-final-snapshot");
    const RETAIN_PRIMARY: (&str, &str) =
        ("--retain-primary-cluster", "--no-retain-primary-cluster");
    let mut delete = match (tool, at(0), at(1), at(2), at(3)) {
        ("aws", Some("rds"), Some("delete-db-instance"), ..) => aws_resource(
            "rds",
            "db",
            &["--db-instance-identifier"],
            SKIP,
            "--final-db-snapshot-identifier",
            Explicit,
        ),
        ("aws", Some("rds"), Some("delete-db-cluster"), ..) => aws_resource(
            "rds",
            "cluster",
            &["--db-cluster-identifier"],
            SKIP,
            "--final-db-snapshot-identifier",
            Explicit,
        ),
        ("aws", Some("docdb" | "neptune"), Some("delete-db-cluster"), ..) => aws_resource(
            if at(0) == Some("docdb") {
                "docdb"
            } else {
                "neptune"
            },
            "cluster",
            &["--db-cluster-identifier"],
            SKIP,
            "--final-db-snapshot-identifier",
            Removed,
        ),
        ("aws", Some("redshift"), Some("delete-cluster"), ..) => CloudResourceDelete {
            values: &["--final-cluster-snapshot-retention-period"],
            ..aws_resource(
                "redshift",
                "cluster",
                &["--cluster-identifier"],
                (
                    "--skip-final-cluster-snapshot",
                    "--no-skip-final-cluster-snapshot",
                ),
                "--final-cluster-snapshot-identifier",
                Removed,
            )
        },
        ("aws", Some("rds"), Some("delete-db-snapshot"), ..) => point(
            "aws",
            "rds",
            "snapshot",
            2,
            &["--db-snapshot-identifier"],
            &[],
            &[],
        ),
        (
            "aws",
            Some(service @ ("rds" | "docdb" | "neptune")),
            Some("delete-db-cluster-snapshot"),
            ..,
        ) => point(
            "aws",
            match service {
                "rds" => "rds",
                "docdb" => "docdb",
                _ => "neptune",
            },
            "snapshot",
            2,
            &["--db-cluster-snapshot-identifier"],
            &[],
            &[],
        ),
        ("aws", Some("rds"), Some("delete-db-instance-automated-backup"), ..) => point(
            "aws",
            "rds",
            "backup",
            2,
            &["--dbi-resource-id", "--db-instance-automated-backups-arn"],
            &[],
            &[],
        ),
        ("aws", Some("rds"), Some("delete-db-cluster-automated-backup"), ..) => point(
            "aws",
            "rds",
            "backup",
            2,
            &["--db-cluster-resource-id"],
            &[],
            &[],
        ),
        ("aws", Some("redshift"), Some("delete-cluster-snapshot"), ..) => point(
            "aws",
            "redshift",
            "snapshot",
            2,
            &["--snapshot-identifier"],
            &["--snapshot-cluster-identifier"],
            &[],
        ),
        ("aws", Some("dynamodb"), Some("delete-backup"), ..) => {
            point("aws", "dynamodb", "backup", 2, &["--backup-arn"], &[], &[])
        }
        ("gcloud", Some("sql"), Some("backups"), Some("delete"), _) => point(
            "gcp",
            "sql",
            "backup",
            3,
            &[],
            &["--instance", "-i"],
            &["--async"],
        ),
        ("gcloud", Some("spanner"), Some("backups"), Some("delete"), _) => {
            point("gcp", "spanner", "backup", 3, &[], &["--instance"], &[])
        }
        ("gcloud", Some("alloydb"), Some("backups"), Some("delete"), _) => point(
            "gcp",
            "alloydb",
            "backup",
            3,
            &[],
            &["--region"],
            &["--async"],
        ),
        ("az", Some("sql"), Some("db"), Some("ltr-backup"), Some("delete")) => point(
            "azure",
            "sql",
            "backup",
            4,
            &["--name", "-n"],
            &["--location", "-l", "--server", "-s", "--database", "-d"],
            &["--yes", "-y"],
        ),
        ("az", Some("postgres"), Some("flexible-server"), Some("backup"), Some("delete")) => point(
            "azure",
            "postgres",
            "backup",
            4,
            &["--name", "-n"],
            &["--resource-group", "-g", "--server-name", "-s"],
            &["--yes", "-y"],
        ),
        ("az", Some("mysql"), Some("flexible-server"), Some("backup"), Some("delete")) => point(
            "azure",
            "mysql",
            "backup",
            4,
            &["--backup-name", "-b"],
            &["--resource-group", "-g", "--name", "-n"],
            &[],
        ),
        // --table-name also takes the table's ARN.
        ("aws", Some("dynamodb"), Some("delete-table"), ..) => CloudResourceDelete {
            qualified: Qualified::Arn {
                service: "dynamodb",
                resource: "table",
            },
            ..resource(
                "aws",
                "dynamodb",
                "table",
                2,
                &["--table-name"],
                &[],
                &[],
                &[],
            )
        },
        ("aws", Some("redshift-serverless"), Some("delete-namespace"), ..) => resource(
            "aws",
            "redshift-serverless",
            "namespace",
            2,
            &["--namespace-name"],
            &[],
            &["--final-snapshot-name", "--final-snapshot-retention-period"],
            &[],
        ),
        // Deleting a keyspace deletes all of its tables.
        ("aws", Some("keyspaces"), Some("delete-keyspace"), ..) => resource(
            "aws",
            "keyspaces",
            "keyspace",
            2,
            &["--keyspace-name"],
            &[],
            &[],
            &[],
        ),
        ("aws", Some("keyspaces"), Some("delete-table"), ..) => resource(
            "aws",
            "keyspaces",
            "table",
            2,
            &["--table-name"],
            &[&["--keyspace-name"]],
            &[],
            &[],
        ),
        // Timestream refuses to delete a database that still has tables.
        ("aws", Some("timestream-write"), Some("delete-database"), ..) => resource(
            "aws",
            "timestream",
            "database",
            2,
            &["--database-name"],
            &[],
            &[],
            &[],
        ),
        ("aws", Some("timestream-write"), Some("delete-table"), ..) => resource(
            "aws",
            "timestream",
            "table",
            2,
            &["--table-name"],
            &[&["--database-name"]],
            &[],
            &[],
        ),
        ("aws", Some("elasticache"), Some("delete-cache-cluster"), ..) => resource(
            "aws",
            "elasticache",
            "cache-cluster",
            2,
            &["--cache-cluster-id"],
            &[],
            &["--final-snapshot-identifier"],
            &[],
        ),
        // An effective --retain-primary-cluster deletes only the read
        // replicas and keeps the primary's data.
        ("aws", Some("elasticache"), Some("delete-replication-group"), ..) => CloudResourceDelete {
            keeps_data: Some(RETAIN_PRIMARY),
            ..resource(
                "aws",
                "elasticache",
                "replication-group",
                2,
                &["--replication-group-id"],
                &[],
                &["--final-snapshot-identifier"],
                &[RETAIN_PRIMARY.0, RETAIN_PRIMARY.1],
            )
        },
        ("aws", Some("elasticache"), Some("delete-serverless-cache"), ..) => resource(
            "aws",
            "elasticache",
            "serverless-cache",
            2,
            &["--serverless-cache-name"],
            &[],
            &["--final-snapshot-name"],
            &[],
        ),
        // --cluster-arn takes only the cluster's ARN.
        ("aws", Some("docdb-elastic"), Some("delete-cluster"), ..) => CloudResourceDelete {
            qualified: Qualified::Arn {
                service: "docdb-elastic",
                resource: "cluster",
            },
            ..resource(
                "aws",
                "docdb-elastic",
                "cluster",
                2,
                &["--cluster-arn"],
                &[],
                &[],
                &[],
            )
        },
        ("aws", Some("lightsail"), Some("delete-relational-database"), ..) => resource(
            "aws",
            "lightsail",
            "relational-database",
            2,
            &["--relational-database-name"],
            &[],
            &["--final-relational-database-snapshot-name"],
            &["--skip-final-snapshot", "--no-skip-final-snapshot"],
        ),
        ("aws", Some("dsql"), Some("delete-cluster"), ..) => resource(
            "aws",
            "dsql",
            "cluster",
            2,
            &["--identifier"],
            &[],
            &["--client-token"],
            &[],
        ),
        ("aws", Some("memorydb"), Some("delete-cluster"), ..) => resource(
            "aws",
            "memorydb",
            "cluster",
            2,
            &["--cluster-name"],
            &[],
            &["--final-snapshot-name", "--multi-region-cluster-name"],
            &[],
        ),
        ("gcloud", Some("sql"), Some("instances"), Some("delete"), _) => CloudResourceDelete {
            final_backup: Some("--enable-final-backup"),
            ..resource(
                "gcp",
                "sql",
                "instance",
                3,
                &[],
                &[],
                &[
                    "--final-backup-description",
                    "--final-backup-expiry-time",
                    "--final-backup-retention-days",
                ],
                &["--async", "--enable-final-backup"],
            )
        },
        ("gcloud", Some("sql"), Some("databases"), Some("delete"), _) => resource(
            "gcp",
            "sql",
            "database",
            3,
            &[],
            &[&["--instance", "-i"]],
            &[],
            &[],
        ),
        // An instance's users and certificates hold no data; each is named
        // inside its instance, never as the instance itself.
        ("gcloud", Some("sql"), Some("users"), Some("delete"), _) => resource(
            "gcp",
            "sql",
            "user",
            3,
            &[],
            &[&["--instance", "-i"]],
            &["--host"],
            &["--async"],
        ),
        ("gcloud", Some("sql"), Some("ssl-certs"), Some("delete"), _) => resource(
            "gcp",
            "sql",
            "ssl-cert",
            3,
            &[],
            &[&["--instance", "-i"]],
            &[],
            &["--async"],
        ),
        ("gcloud", Some("sql"), Some("ssl"), Some("client-certs"), Some("delete")) => resource(
            "gcp",
            "sql",
            "client-cert",
            4,
            &[],
            &[&["--instance", "-i"]],
            &[],
            &["--async"],
        ),
        ("gcloud", Some("spanner"), Some("instances"), Some("delete"), _) => {
            resource("gcp", "spanner", "instance", 3, &[], &[], &[], &[])
        }
        ("gcloud", Some("spanner"), Some("databases"), Some("delete"), _) => CloudResourceDelete {
            qualified: Qualified::Path(&["projects", "instances", "databases"]),
            ..resource(
                "gcp",
                "spanner",
                "database",
                3,
                &[],
                &[&["--instance"]],
                &[],
                &[],
            )
        },
        ("gcloud", Some("firestore"), Some("databases"), Some("delete"), _) => resource(
            "gcp",
            "firestore",
            "database",
            3,
            &["--database"],
            &[],
            &["--etag"],
            &[],
        ),
        // `cbt deleteinstance` names the same resource.
        ("gcloud", Some("bigtable"), Some("instances"), Some("delete"), _) => CloudResourceDelete {
            many: true,
            qualified: Qualified::Path(&["projects", "instances"]),
            ..resource("gcp", "bigtable", "instance", 3, &[], &[], &[], &[])
        },
        ("gcloud", Some("bigtable"), Some("tables"), Some("delete"), _) => CloudResourceDelete {
            qualified: Qualified::Path(&["projects", "instances", "tables"]),
            ..resource(
                "gcp",
                "bigtable",
                "table",
                3,
                &[],
                &[&["--instance"]],
                &[],
                &[],
            )
        },
        // --force also deletes the cluster's instances; without it the delete
        // fails while any remain.
        ("gcloud", Some("alloydb"), Some("clusters"), Some("delete"), _) => resource(
            "gcp",
            "alloydb",
            "cluster",
            3,
            &[],
            &[],
            &["--region"],
            &["--async", "--force"],
        ),
        ("gcloud", Some("redis"), Some("instances"), Some("delete"), _) => CloudResourceDelete {
            qualified: Qualified::Path(&["projects", "locations", "instances"]),
            ..resource(
                "gcp",
                "redis",
                "instance",
                3,
                &[],
                &[],
                &["--region"],
                &["--async"],
            )
        },
        ("gcloud", Some("redis"), Some("clusters"), Some("delete"), _) => CloudResourceDelete {
            qualified: Qualified::Path(&["projects", "locations", "clusters"]),
            ..resource(
                "gcp",
                "redis",
                "cluster",
                3,
                &[],
                &[],
                &["--region"],
                &["--async"],
            )
        },
        ("az", Some("sql"), Some("db"), Some("delete"), _) => resource(
            "azure",
            "sql",
            "database",
            3,
            &["--name", "-n"],
            &[&["--server", "-s"]],
            &["--resource-group", "-g"],
            &["--yes", "-y", "--no-wait"],
        ),
        ("az", Some("sql"), Some("mi"), Some("delete"), _) => resource(
            "azure",
            "sql",
            "managed-instance",
            3,
            &["--name", "-n"],
            &[],
            &["--resource-group", "-g"],
            &["--yes", "-y", "--no-wait"],
        ),
        ("az", Some("sql"), Some("server"), Some("delete"), _) => resource(
            "azure",
            "sql",
            "server",
            3,
            &["--name", "-n"],
            &[],
            &["--resource-group", "-g"],
            &["--yes", "-y"],
        ),
        ("az", Some("cosmosdb"), Some("delete"), ..) => resource(
            "azure",
            "cosmosdb",
            "account",
            2,
            &["--name", "-n"],
            &[],
            &["--resource-group", "-g"],
            &["--yes", "-y", "--no-wait"],
        ),
        ("az", Some("cosmosdb"), Some("table"), Some("delete"), _) => resource(
            "azure",
            "cosmosdb",
            "table",
            3,
            &["--name", "-n"],
            &[&["--account-name", "-a"]],
            &["--resource-group", "-g"],
            &["--yes", "-y"],
        ),
        (
            "az",
            Some("cosmosdb"),
            Some(api @ ("sql" | "mongodb" | "cassandra" | "gremlin")),
            Some(collection),
            Some("delete"),
        ) => {
            // Each API names its top-level container and the collection in it.
            const ACCOUNT: &[&[&str]] = &[&["--account-name", "-a"]];
            const DATABASE: &[&[&str]] = &[&["--account-name", "-a"], &["--database-name", "-d"]];
            const KEYSPACE: &[&[&str]] = &[&["--account-name", "-a"], &["--keyspace-name", "-k"]];
            let (kind, parents) = match (api, collection) {
                ("sql" | "mongodb" | "gremlin", "database") => ("database", ACCOUNT),
                ("cassandra", "keyspace") => ("keyspace", ACCOUNT),
                ("sql", "container") => ("container", DATABASE),
                ("mongodb", "collection") => ("collection", DATABASE),
                ("gremlin", "graph") => ("graph", DATABASE),
                ("cassandra", "table") => ("table", KEYSPACE),
                _ => return None,
            };
            resource(
                "azure",
                "cosmosdb",
                kind,
                4,
                &["--name", "-n"],
                parents,
                &["--resource-group", "-g"],
                &["--yes", "-y"],
            )
        }
        (
            "az",
            Some(service @ ("postgres" | "mysql")),
            Some("flexible-server"),
            Some("delete"),
            _,
        ) => resource(
            "azure",
            if service == "postgres" {
                "postgres"
            } else {
                "mysql"
            },
            "server",
            3,
            &["--name", "-n"],
            &[],
            &["--resource-group", "-g"],
            &["--yes", "-y"],
        ),
        // MySQL names the database with --database-name, PostgreSQL with --name.
        ("az", Some("postgres"), Some("flexible-server"), Some("db"), Some("delete")) => resource(
            "azure",
            "postgres",
            "database",
            4,
            &["--name", "-n"],
            &[&["--server-name", "-s"]],
            &["--resource-group", "-g"],
            &["--yes", "-y"],
        ),
        ("az", Some("mysql"), Some("flexible-server"), Some("db"), Some("delete")) => resource(
            "azure",
            "mysql",
            "database",
            4,
            &["--database-name", "-d"],
            &[&["--server-name", "-s"]],
            &["--resource-group", "-g"],
            &["--yes", "-y"],
        ),
        ("az", Some("redis"), Some("delete"), ..) => resource(
            "azure",
            "redis",
            "cache",
            2,
            &["--name", "-n"],
            &[],
            &["--resource-group", "-g"],
            &["--yes", "-y"],
        ),
        // Provisioned resources outside the managed databases. Each verb
        // deletes the one resource its identifier option or operand names.
        ("aws", Some("ec2"), Some(verb @ ("delete-vpc" | "delete-subnet")), ..) => resource(
            "aws",
            "ec2",
            if verb == "delete-vpc" {
                "vpc"
            } else {
                "subnet"
            },
            2,
            if verb == "delete-vpc" {
                &["--vpc-id"]
            } else {
                &["--subnet-id"]
            },
            &[],
            &[],
            &["--no-dry-run"],
        ),
        ("aws", Some("ec2"), Some("delete-security-group"), ..) => resource(
            "aws",
            "ec2",
            "security-group",
            2,
            &["--group-id", "--group-name"],
            &[],
            &[],
            &["--no-dry-run"],
        ),
        ("aws", Some("eks"), Some("delete-cluster"), ..) => {
            resource("aws", "eks", "cluster", 2, &["--name"], &[], &[], &[])
        }
        ("aws", Some("efs"), Some("delete-file-system"), ..) => resource(
            "aws",
            "efs",
            "file-system",
            2,
            &["--file-system-id"],
            &[],
            &[],
            &[],
        ),
        ("aws", Some("kinesis"), Some("delete-stream"), ..) => resource(
            "aws",
            "kinesis",
            "stream",
            2,
            &["--stream-name"],
            &[],
            &[],
            &[
                "--enforce-consumer-deletion",
                "--no-enforce-consumer-deletion",
            ],
        ),
        ("aws", Some("logs"), Some("delete-log-group"), ..) => CloudResourceDelete {
            slash_names: true,
            ..resource(
                "aws",
                "logs",
                "log-group",
                2,
                &["--log-group-name"],
                &[],
                &[],
                &[],
            )
        },
        ("aws", Some("cloudtrail"), Some("delete-trail"), ..) => {
            resource("aws", "cloudtrail", "trail", 2, &["--name"], &[], &[], &[])
        }
        ("aws", Some("route53"), Some("delete-hosted-zone"), ..) => {
            resource("aws", "route53", "hosted-zone", 2, &["--id"], &[], &[], &[])
        }
        ("aws", Some("elbv2"), Some("delete-load-balancer"), ..) => CloudResourceDelete {
            slash_names: true,
            ..resource(
                "aws",
                "elbv2",
                "load-balancer",
                2,
                &["--load-balancer-arn"],
                &[],
                &[],
                &[],
            )
        },
        ("aws", Some("cloudfront"), Some("delete-distribution"), ..) => resource(
            "aws",
            "cloudfront",
            "distribution",
            2,
            &["--id"],
            &[],
            &["--if-match"],
            &[],
        ),
        // A --qualifier deletes one version of the function, not the function.
        ("aws", Some("lambda"), Some("delete-function"), ..) => resource(
            "aws",
            "lambda",
            "function",
            2,
            &["--function-name"],
            &[],
            &[],
            &[],
        ),
        ("aws", Some("ecr"), Some("delete-repository"), ..) => CloudResourceDelete {
            slash_names: true,
            ..resource(
                "aws",
                "ecr",
                "repository",
                2,
                &["--repository-name"],
                &[],
                &["--registry-id"],
                &["--force", "--no-force"],
            )
        },
        ("aws", Some("iam"), Some(verb @ ("delete-user" | "delete-role" | "delete-group")), ..) => {
            let (kind, flag): (&str, &'static [&'static str]) = match verb {
                "delete-user" => ("user", &["--user-name"]),
                "delete-role" => ("role", &["--role-name"]),
                _ => ("group", &["--group-name"]),
            };
            resource("aws", "iam", kind, 2, flag, &[], &[], &[])
        }
        // --retain-resources lists resources to keep and takes several values,
        // so it stays undocumented here.
        ("aws", Some("cloudformation"), Some("delete-stack"), ..) => CloudResourceDelete {
            slash_names: true,
            ..resource(
                "aws",
                "cloudformation",
                "stack",
                2,
                &["--stack-name"],
                &[],
                &["--role-arn", "--client-request-token", "--deletion-mode"],
                &[],
            )
        },
        // --delete-disks and --keep-disks choose what happens to the attached
        // disks; the instances are deleted either way.
        ("gcloud", Some("compute"), Some("instances"), Some("delete"), _) => CloudResourceDelete {
            many: true,
            qualified: Qualified::Path(&["projects", "zones", "instances"]),
            ..resource(
                "gcp",
                "compute",
                "instance",
                3,
                &[],
                &[],
                &["--zone", "--delete-disks", "--keep-disks"],
                &[],
            )
        },
        (
            "gcloud",
            Some("compute"),
            Some(collection @ ("networks" | "firewall-rules")),
            Some("delete"),
            _,
        ) => CloudResourceDelete {
            many: true,
            ..resource(
                "gcp",
                "compute",
                if collection == "networks" {
                    "network"
                } else {
                    "firewall-rule"
                },
                3,
                &[],
                &[],
                &[],
                &[],
            )
        },
        ("gcloud", Some("container"), Some("clusters"), Some("delete"), _) => CloudResourceDelete {
            many: true,
            ..resource(
                "gcp",
                "container",
                "cluster",
                3,
                &[],
                &[],
                &["--zone", "-z", "--region", "--location"],
                &["--async"],
            )
        },
        ("gcloud", Some("dataproc"), Some("clusters"), Some("delete"), _) => resource(
            "gcp",
            "dataproc",
            "cluster",
            3,
            &[],
            &[],
            &["--region", "--graceful-decommission-timeout"],
            &["--async"],
        ),
        ("gcloud", Some("functions"), Some("delete"), ..) => resource(
            "gcp",
            "functions",
            "function",
            2,
            &[],
            &[],
            &["--region"],
            &["--gen2", "--no-gen2"],
        ),
        ("gcloud", Some("run"), Some("services"), Some("delete"), _) => resource(
            "gcp",
            "run",
            "service",
            3,
            &[],
            &[],
            &["--region"],
            &["--async"],
        ),
        ("gcloud", Some("dns"), Some("managed-zones"), Some("delete"), _) => {
            resource("gcp", "dns", "managed-zone", 3, &[], &[], &[], &[])
        }
        ("gcloud", Some("iam"), Some("service-accounts"), Some("delete"), _) => {
            resource("gcp", "iam", "service-account", 3, &[], &[], &[], &[])
        }
        ("gcloud", Some("projects"), Some("delete"), ..) => {
            resource("gcp", "projects", "project", 2, &[], &[], &[], &[])
        }
        // A resource group delete removes every resource in the group.
        ("az", Some("group"), Some("delete"), ..) => resource(
            "azure",
            "group",
            "resource-group",
            2,
            &["--name", "-n", "--resource-group", "-g"],
            &[],
            &["--force-deletion-types", "-f"],
            &["--yes", "-y", "--no-wait"],
        ),
        ("az", Some("vm"), Some("delete"), ..) => resource(
            "azure",
            "vm",
            "instance",
            2,
            &["--name", "-n"],
            &[],
            &["--resource-group", "-g", "--force-deletion"],
            &["--yes", "-y", "--no-wait"],
        ),
        ("az", Some("aks"), Some("delete"), ..) => resource(
            "azure",
            "aks",
            "cluster",
            2,
            &["--name", "-n"],
            &[],
            &["--resource-group", "-g"],
            &["--yes", "-y", "--no-wait"],
        ),
        ("az", Some("acr"), Some("delete"), ..) => resource(
            "azure",
            "acr",
            "registry",
            2,
            &["--name", "-n"],
            &[],
            &["--resource-group", "-g"],
            &["--yes", "-y"],
        ),
        // A --slot deletes one deployment slot, not the app.
        ("az", Some(service @ ("webapp" | "functionapp")), Some("delete"), ..) => resource(
            "azure",
            if service == "webapp" {
                "webapp"
            } else {
                "functionapp"
            },
            "app",
            2,
            &["--name", "-n"],
            &[],
            &["--resource-group", "-g"],
            if service == "webapp" {
                &[
                    "--keep-empty-plan",
                    "--keep-metrics",
                    "--keep-dns-registration",
                ]
            } else {
                &[]
            },
        ),
        ("az", Some("network"), Some("vnet"), Some("delete"), _) => resource(
            "azure",
            "network",
            "vnet",
            3,
            &["--name", "-n"],
            &[],
            &["--resource-group", "-g"],
            &["--no-wait"],
        ),
        ("az", Some("network"), Some("dns"), Some("zone"), Some("delete")) => resource(
            "azure",
            "network",
            "dns-zone",
            4,
            &["--name", "-n"],
            &[],
            &["--resource-group", "-g"],
            &["--yes", "-y"],
        ),
        ("az", Some("ad"), Some(object @ ("sp" | "app")), Some("delete"), _) => resource(
            "azure",
            "ad",
            if object == "sp" {
                "service-principal"
            } else {
                "application"
            },
            3,
            &["--id"],
            &[],
            &[],
            &[],
        ),
        // A management group takes its policy and role assignments with it;
        // Azure refuses to delete one that still has children.
        ("az", Some("account"), Some("management-group"), Some("delete"), _) => resource(
            "azure",
            "account",
            "management-group",
            3,
            &["--name", "-n"],
            &[],
            &[],
            &["--no-register"],
        ),
        // Cancelling a subscription disables every resource in it, and Azure
        // deletes them once the subscription is not reactivated in time.
        ("az", Some("account"), Some("subscription"), Some("cancel"), _) => resource(
            "azure",
            "account",
            "subscription",
            3,
            &["--id", "--subscription-id"],
            &[],
            &[],
            &["--yes", "-y"],
        ),
        // The azure-devops extension's deletes are hosted Git requests, which
        // `azure_devops_delete` emits.
        ("az", Some(group @ ("repos" | "pipelines")), Some("delete"), ..) => {
            let (service, kind) = if group == "repos" {
                ("repos", "repository")
            } else {
                ("pipelines", "pipeline")
            };
            resource(
                AZURE_DEVOPS,
                service,
                kind,
                2,
                &["--id"],
                &[],
                AZURE_DEVOPS_PROJECT_VALUES,
                &["--yes", "-y"],
            )
        }
        ("az", Some("devops"), Some("project"), Some("delete"), _) => resource(
            AZURE_DEVOPS,
            "devops",
            "project",
            3,
            &["--id"],
            &[],
            &["--org", "--organization", "--detect"],
            &["--yes", "-y"],
        ),
        ("az", Some("boards"), Some("work-item"), Some("delete"), _) => resource(
            AZURE_DEVOPS,
            "boards",
            "work_item",
            3,
            &["--id"],
            &[],
            AZURE_DEVOPS_PROJECT_VALUES,
            &["--yes", "-y", "--destroy"],
        ),
        _ => return None,
    };
    (
        delete.common_values,
        delete.common_switches,
        delete.scope_values,
    ) = (common_values, common_switches, scope_values);
    // A command word that follows one of the verb's own value options is that
    // option's value (`aws rds --db-instance-identifier delete-db-instance`),
    // so the words do not name this verb.
    if delete.path.iter().any(|&index| {
        argv[index - 1]
            .as_literal()
            .is_some_and(|flag| delete.takes_value(flag))
    }) {
        return None;
    }
    Some(delete)
}
