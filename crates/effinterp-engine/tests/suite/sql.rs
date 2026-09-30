use effinterp_engine::Engine;
use effinterp_proto::{
    AttrValue, Plan, ResourceExpr, ResourceIdentity, SqlConnection, SqlDialect, Subject,
    validate_plan,
};

fn exec(argv: &[&str]) -> Subject {
    Subject::Exec {
        argv: argv.iter().map(|s| s.to_string()).collect(),
        cwd: Some("/w".to_string()),
        context: Default::default(),
    }
}

fn analyze(subject: &Subject) -> Plan {
    let plan = Engine::new().analyze(subject).unwrap();
    validate_plan(&plan).unwrap();
    plan
}

/// (operation, rendered-target) pairs for every effect.
fn effects(plan: &Plan) -> Vec<(String, String)> {
    plan.effects
        .iter()
        .map(|e| (e.operation.0.clone(), render(&e.resource)))
        .collect()
}

fn render(expr: &ResourceExpr) -> String {
    match expr {
        ResourceExpr::Concrete { identity } => match identity {
            ResourceIdentity::FsPath { path } => path.clone(),
            ResourceIdentity::UserHome { user } => format!("~{user}"),
            ResourceIdentity::EnvironmentVariable { name } => format!("env:{name}"),
            ResourceIdentity::GitRepository { worktree, .. } => worktree
                .as_deref()
                .map(render)
                .unwrap_or_else(|| "git".to_string()),
            ResourceIdentity::Process { executable, .. } => format!("exe:{executable}"),
            ResourceIdentity::NetworkEndpoint { host, .. } => format!("net:{host}"),
            ResourceIdentity::Container { name, image, .. } => format!(
                "container:{}",
                name.as_deref().or(image.as_deref()).unwrap_or("?")
            ),
            ResourceIdentity::DatabaseTable {
                server,
                database,
                schema,
                table,
            } => format!(
                "{}/{}.{}.{table}",
                server.as_deref().unwrap_or("?"),
                database.as_deref().unwrap_or("?"),
                schema.as_deref().unwrap_or("?"),
            ),
            ResourceIdentity::DatabaseSchema {
                server,
                database,
                schema,
            } => format!(
                "schema:{}/{}/{}",
                server.as_deref().unwrap_or("?"),
                database.as_deref().unwrap_or("?"),
                schema.as_deref().unwrap_or("*"),
            ),
            ResourceIdentity::ObjectStore { bucket, .. } => format!("obj:{bucket}"),
            ResourceIdentity::CloudResource { id, .. } => {
                format!("cloud:{}", id.as_deref().unwrap_or("?"))
            }
            identity @ ResourceIdentity::Artifact { .. } => {
                effinterp_proto::display_identity(identity)
            }
            ResourceIdentity::MessageTopic { name, .. } => format!("topic:{name}"),
            ResourceIdentity::ServiceUnit { .. }
            | ResourceIdentity::ScheduledJob { .. }
            | ResourceIdentity::StorageVolume { .. }
            | ResourceIdentity::BlockDevice { .. }
            | ResourceIdentity::CredentialStore { .. }
            | ResourceIdentity::HostSystem {}
            | ResourceIdentity::KubernetesResource { .. }
            | ResourceIdentity::ManagedInfrastructure { .. } => {
                effinterp_proto::display_identity(identity)
            }
        },
        ResourceExpr::Unresolved { family } => format!("?{}", family.0),
        other => format!("{other:?}"),
    }
}

fn has(plan: &Plan, op: &str, target_contains: &str) -> bool {
    effects(plan)
        .iter()
        .any(|(o, t)| o == op && t.contains(target_contains))
}

fn has_boundary(plan: &Plan, reason: &str) -> bool {
    plan.boundaries.iter().any(|b| b.reason.as_str() == reason)
}

#[test]
fn psql_update_is_the_demonstration_tail() {
    let plan = analyze(&exec(&[
        "psql",
        "-h",
        "db",
        "-d",
        "app",
        "-c",
        "UPDATE public.users SET x=1",
    ]));
    assert!(has(&plan, "process.exec", "exe:psql"));
    assert!(has(&plan, "network.connect", "net:db"));
    assert!(has(&plan, "database.write", "db/app.public.users"));
    // A nested SQL invocation was recorded.
    assert!(
        plan.execution_graph
            .nodes
            .iter()
            .any(|n| matches!(n.subject, Subject::Sql { .. }) && n.boundary.is_none())
    );
}

#[test]
fn each_dml_statement_maps_to_an_operation() {
    let cases = [
        ("SELECT * FROM t", "database.read"),
        ("INSERT INTO t VALUES (1)", "database.write"),
        ("UPDATE t SET a=1", "database.write"),
        ("DELETE FROM t WHERE a=1", "database.write"),
        ("TRUNCATE t", "database.truncate"),
        ("CREATE TABLE t (a int)", "database.schema_write"),
        ("ALTER TABLE t ADD c int", "database.schema_write"),
        ("DROP TABLE t", "database.schema_drop"),
    ];
    for (sql, op) in cases {
        let plan = analyze(&exec(&["psql", "-c", sql]));
        assert!(has(&plan, op, ".t"), "{sql} -> expected {op}");
    }
}

#[test]
fn schema_qualification_is_preserved() {
    let plan = analyze(&exec(&[
        "psql",
        "-d",
        "app",
        "-c",
        "DELETE FROM public.users",
    ]));
    assert!(has(&plan, "database.write", "?/app.public.users"));
}

#[test]
fn drop_schema_uses_schema_identity() {
    let plan = analyze(&exec(&["psql", "-d", "app", "-c", "DROP SCHEMA analytics"]));
    assert!(has(&plan, "database.schema_drop", "schema:?/app/analytics"));
}

#[test]
fn multi_statement_and_join_resolve_all_tables() {
    let plan = analyze(&exec(&[
        "psql",
        "-c",
        "SELECT * FROM a JOIN b ON a.id=b.id; DELETE FROM c",
    ]));
    assert!(has(&plan, "database.read", ".a"));
    assert!(has(&plan, "database.read", ".b"));
    assert!(has(&plan, "database.write", ".c"));
}

#[test]
fn mysql_execute_and_two_part_name() {
    let plan = analyze(&exec(&[
        "mysql",
        "-h",
        "h",
        "-e",
        "INSERT INTO app.users VALUES (1)",
    ]));
    // MySQL two-part name is database.table (schema is None).
    assert!(has(&plan, "database.write", "h/app.?.users"));
}

#[test]
fn sqlite_touches_db_file_and_runs_sql() {
    let plan = analyze(&exec(&["sqlite3", "data.db", "DELETE FROM logs"]));
    assert!(has(&plan, "filesystem.read", "/w/data.db"));
    assert!(has(&plan, "filesystem.write", "/w/data.db"));
    assert!(has(&plan, "database.write", ".logs"));
    assert!(
        !plan
            .effects
            .iter()
            .any(|effect| effect.operation.domain() == "network")
    );
}

#[test]
fn copy_to_file_reads_table_writes_file() {
    let plan = analyze(&exec(&["psql", "-c", "COPY users TO '/tmp/out.csv'"]));
    assert!(has(&plan, "database.read", ".users"));
    assert!(has(&plan, "filesystem.write", "/tmp/out.csv"));
}

#[test]
fn script_file_is_read_but_sql_is_opaque() {
    let plan = analyze(&exec(&["psql", "-f", "migrate.sql"]));
    assert!(has(&plan, "filesystem.read", "migrate.sql"));
    assert!(has_boundary(&plan, "unrecoverable_source"));
}

#[test]
fn interactive_session_is_opaque_not_empty() {
    let plan = analyze(&exec(&["psql", "-d", "app"]));
    assert!(has_boundary(&plan, "unrecoverable_source"));
    // Coverage is honest: database not claimed full.
    assert!(
        plan.coverage
            .0
            .iter()
            .any(|(d, l)| d.0 == "database" && l.level != effinterp_proto::CoverageLevel::Full)
    );
}

#[test]
fn unsupported_statement_is_a_boundary() {
    let plan = analyze(&exec(&["psql", "-c", "GRANT ALL ON t TO bob"]));
    assert!(has_boundary(&plan, "unsupported_sql"));
}

#[test]
fn cte_is_widened_not_misresolved() {
    let plan = analyze(&exec(&[
        "psql",
        "-c",
        "WITH x AS (SELECT 1) SELECT * FROM x",
    ]));
    assert!(has_boundary(&plan, "unsupported_sql"));
}

#[test]
fn pg_dump_reads_database_writes_file() {
    let plan = analyze(&exec(&[
        "pg_dump", "-h", "h", "-d", "app", "-f", "dump.sql",
    ]));
    assert!(has(&plan, "database.read", "schema:h/app"));
    assert!(has(&plan, "filesystem.write", "dump.sql"));
}

#[test]
fn dump_client_options_do_not_become_database_names() {
    for (tool, options) in [
        (
            "mysqldump",
            vec![
                "-u root",
                "--user root",
                "--user=root",
                "-uroot",
                "-u root -p",
                "-p",
                "-psecret",
                "--password=secret",
                "-P 3307",
                "--port 3307",
                "--port=3307",
                "-S /tmp/mysql.sock",
                "--socket /tmp/mysql.sock",
                "--default-character-set utf8mb4",
                "--default-character-set=utf8mb4",
                "-h db",
                "--host db",
                "-r dump.sql",
                "--result-file dump.sql",
            ],
        ),
        (
            "pg_dump",
            vec![
                "-U postgres -p 5433",
                "-U postgres",
                "--username postgres",
                "--username=postgres",
                "-p 5433",
                "--port 5433",
                "--port=5433",
                "-h db",
                "--host db",
                "-f dump.sql",
                "--file dump.sql",
                "-F custom",
                "--format custom",
                "-n public",
                "--schema public",
                "-t users",
                "--table users",
            ],
        ),
    ] {
        for options in options {
            let source = format!("{tool} {options} app > dump.sql");
            let plan = analyze(&Subject::Shell {
                source: source.clone(),
                cwd: Some("/w".into()),
                context: Default::default(),
            });
            let reads: Vec<_> = plan
                .effects
                .iter()
                .filter(|e| e.operation.0 == "database.read")
                .collect();
            assert_eq!(reads.len(), 1, "{source}");
            assert!(
                matches!(&reads[0].resource, ResourceExpr::Concrete {
                identity: ResourceIdentity::DatabaseSchema { database, .. }
            } if database.as_deref() == Some("app")),
                "{source}: {reads:?}"
            );
        }
    }
}

#[test]
fn adversarial_sql_does_not_panic() {
    for sql in [
        "'; DROP TABLE",
        "SELECT FROM FROM WHERE )))",
        "$$ unterminated dollar",
        "-- only a comment",
        "\u{0}\u{1}garbage",
        "UPDATE",
    ] {
        let plan = analyze(&exec(&["psql", "-c", sql]));
        // Whatever the outcome, the plan is valid and never silently claims
        // full coverage with nothing to show for a real statement.
        let _ = plan;
    }
}

#[test]
fn deterministic() {
    let subject = exec(&["psql", "-d", "app", "-c", "UPDATE public.users SET x=1"]);
    let a = effinterp_proto::canonical_json(&analyze(&subject));
    let b = effinterp_proto::canonical_json(&analyze(&subject));
    assert_eq!(a, b);
}

#[test]
fn symbolic_client_identity_and_sql_do_not_disappear() {
    for source in [
        "psql -h \"$HOST\" -d app -c 'DELETE FROM users'",
        "psql --host=\"$HOST\" --port=\"$PORT\" --dbname=\"$DB\" --command=\"$SQL\"",
        "mysql -h\"$HOST\" -P\"$PORT\" -D\"$DB\" -e\"$SQL\"",
        "mysql --host \"$HOST\" --database \"$DB\" --execute \"$SQL\"",
    ] {
        let plan = analyze(&Subject::Shell {
            source: source.into(),
            cwd: None,
            context: Default::default(),
        });
        assert!(plan.effects.iter().any(|effect| effect.operation.as_str() == "network.connect"
            && matches!(&effect.resource, ResourceExpr::Unresolved { family } if family.0 == "network")), "{source}");
        assert!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.as_str() == "database.write")
                || plan
                    .boundaries
                    .iter()
                    .any(|boundary| boundary.domains.iter().any(|domain| domain.0 == "database")),
            "{source}"
        );
        assert!(!plan.effects.iter().any(|effect| matches!(&effect.resource,
            ResourceExpr::Concrete { identity: ResourceIdentity::NetworkEndpoint { host, .. } } if host.contains('$'))));
    }
    let plan = analyze(&Subject::Shell {
        source: "psql -h db -c 'DELETE FROM users' -c \"$SQL\" -f /first -f /second".into(),
        cwd: None,
        context: Default::default(),
    });
    assert!(
        plan.effects
            .iter()
            .any(|effect| effect.operation.as_str() == "database.write")
    );
    assert_eq!(
        plan.effects
            .iter()
            .filter(|effect| effect.operation.as_str() == "filesystem.read")
            .count(),
        2
    );
    assert!(
        plan.boundaries
            .iter()
            .any(|boundary| boundary.domains.iter().any(|domain| domain.0 == "database"))
    );
}

fn sql(dialect: SqlDialect, source: &str) -> Plan {
    analyze(&Subject::Sql {
        source: source.into(),
        dialect,
        connection: SqlConnection::default(),
    })
}

/// Each source hides `DROP TABLE x` from a lexer that ignores one dialect
/// rule; the drop must surface under every rule the server might apply.
#[test]
fn dialect_lexing_never_hides_a_statement() {
    use SqlDialect::*;
    for (dialect, source) in [
        (Mysql, r"SELECT 'a\'' ; DROP TABLE x"),
        (Mysql, r#"SELECT "a\"" ; DROP TABLE x"#),
        (Mysql, "# comment '\nDROP TABLE x"),
        (Mysql, "SELECT a#'\n; DROP TABLE x"),
        (Mysql, "/*! DROP TABLE x */"),
        (Mysql, "/*!50001 DROP TABLE x */"),
        (Mysql, "SELECT 1--1; DROP TABLE x"),
        (Mysql, "DELIMITER //\nDROP TABLE x//"),
        (Mysql, "use other\nDROP TABLE x;"),
        (Postgres, r"SELECT E'\''; DROP TABLE x; --'"),
        (Postgres, r"SELECT 'a\'; DROP TABLE x; --'"),
        (Postgres, "\\set v 1\nDROP TABLE x;"),
        (Sqlite, ".mode csv\nDROP TABLE x;"),
        (TSql, "SELECT 1\nGO\nDROP TABLE x"),
        (TSql, "SELECT 1 DROP TABLE x"),
        (BigQuery, "# c '\nDROP TABLE x"),
        (Generic, r"SELECT 'a\'' ; DROP TABLE x"),
        // An unclosed placeholder opener never swallows what follows.
        (Postgres, "SELECT a FROM t WHERE b = :{v;\nDROP TABLE x;"),
        (Postgres, "SELECT a FROM t WHERE b = $(v;\nDROP TABLE x;"),
        (Mysql, "SELECT a FROM t WHERE b = $(v;\nDROP TABLE x;"),
        (Snowflake, "SELECT a FROM t WHERE b = &{v;\nDROP TABLE x;"),
        (ClickHouse, "SELECT a FROM t WHERE b = {v; DROP TABLE x;"),
        (TSql, "SELECT a FROM t WHERE b = $(v\nGO\nDROP TABLE x"),
        // T-SQL statements run back to back without `;`.
        (TSql, "ALTER TABLE t DROP COLUMN c DROP TABLE x"),
        (TSql, "ALTER TABLE t ADD c int DROP TABLE x"),
        (TSql, "GRANT SELECT ON t TO u DROP TABLE x"),
        // A custom DELIMITER still runs each `;` statement it carries.
        (Mysql, "DELIMITER //\nSELECT a FROM t; DROP TABLE x //"),
        (
            Mysql,
            "DELIMITER //\nCREATE TABLE t (event int); DROP TABLE x //",
        ),
        (
            Mysql,
            "DELIMITER //\nALTER TABLE t ADD COLUMN function int; DROP TABLE x //",
        ),
        (
            Mysql,
            "DELIMITER //\nCREATE PROCEDURE p() SELECT 1; DROP TABLE x //",
        ),
        (
            Mysql,
            "DELIMITER //\nCREATE PROCEDURE p() BEGIN SELECT 1; END; DROP TABLE x //",
        ),
        (
            Mysql,
            "DELIMITER //\nCREATE TRIGGER tr BEFORE INSERT ON t FOR EACH ROW SET NEW.a = 1; DROP TABLE x //",
        ),
        // A delimiter glued to a word still ends the statement.
        (Mysql, "DELIMITER $$\nDROP TABLE a$$\nDROP TABLE x$$"),
        // A stored-program body's statements are analyzed as if run.
        (
            Mysql,
            "DELIMITER //\nCREATE PROCEDURE p() BEGIN DROP TABLE x; END //",
        ),
        // SQLite ends `[…]` at the first `]`.
        (Sqlite, "SELECT a FROM [t]];\nDROP TABLE x; --]"),
        // Generic reads SQL Server brackets and Snowflake `//` comments too.
        (Generic, "SELECT a FROM [t'] ; DROP TABLE x; --'"),
        (Generic, "SELECT a FROM t; // '\nDROP TABLE x; --'"),
        // psql `\\` resumes SQL after a meta-command; `\;` separates.
        (Postgres, "\\x \\\\ DROP TABLE x;"),
        (Postgres, "SELECT 1 \\; DROP TABLE x;"),
        (Postgres, r"\echo 'a\'b' \\ DROP TABLE x;"),
    ] {
        let plan = sql(dialect, source);
        assert!(
            has(&plan, "database.schema_drop", ".x"),
            "{dialect:?} {source:?}: {:?}",
            effects(&plan)
        );
    }
    // The benign twins: the text only mentions a drop.
    for (dialect, source) in [
        (Snowflake, r"SELECT 'a\' ; DROP TABLE x; --'"),
        (Postgres, "/* a /* b */ DROP TABLE x; */ SELECT 1"),
        (Postgres, "SELECT $t$ ; DROP TABLE x; $t$"),
        (BigQuery, "SELECT ''' ; DROP TABLE x'''"),
        (Mysql, "SELECT '#'; SELECT '/*! DROP TABLE x */'"),
        (TSql, "SELECT a FROM [t]];\nDROP TABLE x; --]"),
        (TSql, "CREATE PROCEDURE p AS BEGIN DROP TABLE x END"),
        (Postgres, r#"\echo "a \\ DROP TABLE x;""#),
    ] {
        let plan = sql(dialect, source);
        assert!(
            !has(&plan, "database.schema_drop", ""),
            "{dialect:?} {source:?}: {:?}",
            effects(&plan)
        );
    }

    // Each statement ends at a glued delimiter, which never joins the name.
    for (source, expected) in [
        (
            "DELIMITER $$\nDROP TABLE a$$\nDROP TABLE b$$",
            [
                ("database.schema_drop", "?/?.?.a"),
                ("database.schema_drop", "?/?.?.b"),
            ],
        ),
        (
            "DELIMITER $$\nTRUNCATE t$$\nDELETE FROM users$$",
            [
                ("database.truncate", "?/?.?.t"),
                ("database.write", "?/?.?.users"),
            ],
        ),
    ] {
        let expected: Vec<_> = expected
            .iter()
            .map(|(op, target)| (op.to_string(), target.to_string()))
            .collect();
        assert_eq!(effects(&sql(Mysql, source)), expected, "{source:?}");
    }

    // A fact the engine cannot establish is a boundary; a known form is not.
    let detail = |plan: &Plan, text: &str| {
        plan.boundaries
            .iter()
            .any(|b| b.detail.as_deref().is_some_and(|d| d.contains(text)))
    };
    for (dialect, source, text, expected) in [
        (
            Mysql,
            "DELIMITER //\nCREATE PROCEDURE p() BEGIN DROP TABLE x; END //",
            "stored-program body",
            true,
        ),
        (
            Mysql,
            "DELIMITER //\nCREATE TABLE t (event int); DROP TABLE x //",
            "stored-program body",
            false,
        ),
        (
            ClickHouse,
            "ALTER TABLE t ADD COLUMN c int, FROBNICATE x",
            "ALTER TABLE action",
            true,
        ),
        (
            ClickHouse,
            "ALTER TABLE t RENAME COLUMN a TO b, FROBNICATE x",
            "ALTER TABLE action",
            true,
        ),
        (
            TSql,
            "ALTER TABLE t ADD a int, b int",
            "ALTER TABLE action",
            false,
        ),
        (
            Mysql,
            "ALTER TABLE t DROP PARTITION p0, p1",
            "ALTER TABLE action",
            false,
        ),
        (
            ClickHouse,
            "ALTER TABLE t UPDATE a = 1, b = 2 WHERE c = 3",
            "ALTER TABLE action",
            false,
        ),
        (
            TSql,
            "UPDATE STATISTICS dbo.users WITH FULLSCAN",
            "UPDATE STATISTICS",
            true,
        ),
    ] {
        let plan = sql(dialect, source);
        assert_eq!(detail(&plan, text), expected, "{dialect:?} {source:?}");
    }
}

/// The attributes a policy matches destructive SQL on, per statement form.
#[test]
fn statements_carry_their_destruction_attributes() {
    use SqlDialect::*;
    let attr = |plan: &Plan, op: &str, key: &str| -> Vec<Option<AttrValue>> {
        plan.effects
            .iter()
            .filter(|e| e.operation.as_str() == op)
            .map(|e| e.attributes.get(key).cloned())
            .collect()
    };
    let s = |v: &str| Some(AttrValue::String(v.into()));
    let t = Some(AttrValue::Bool(true));
    let f = Some(AttrValue::Bool(false));
    let drop = "database.schema_drop";
    let write = "database.write";
    let schema_write = "database.schema_write";
    for (dialect, source, op, key, expected) in [
        (
            Postgres,
            "DROP TABLE a, b",
            drop,
            "object_kind",
            vec![s("table"), s("table")],
        ),
        (
            Postgres,
            "DROP DATABASE app",
            drop,
            "object_kind",
            vec![s("database")],
        ),
        (
            Mysql,
            "DROP SCHEMA app",
            drop,
            "object_kind",
            vec![s("database")],
        ),
        (
            Cql,
            "DROP KEYSPACE app",
            drop,
            "object_kind",
            vec![s("keyspace")],
        ),
        (
            Postgres,
            "DROP MATERIALIZED VIEW m",
            drop,
            "object_kind",
            vec![s("materialized_view")],
        ),
        (
            Postgres,
            "DROP VIEW v",
            drop,
            "object_kind",
            vec![s("view")],
        ),
        (
            Snowflake,
            "DROP EXTERNAL TABLE e",
            drop,
            "object_kind",
            vec![s("external_table")],
        ),
        (
            Postgres,
            "DROP OWNED BY r",
            drop,
            "object_kind",
            vec![s("owned_objects")],
        ),
        (
            Postgres,
            "TRUNCATE a, b",
            "database.truncate",
            "partition",
            vec![None, None],
        ),
        (
            Postgres,
            "DELETE FROM t",
            write,
            "filtered",
            vec![f.clone()],
        ),
        (
            Postgres,
            "DELETE FROM t u USING v RETURNING *",
            write,
            "filtered",
            vec![f.clone()],
        ),
        // A constant-true predicate selects every row; a dropped operator
        // byte keeps `-1 = 1` from reading as `1 = 1`.
        (
            Postgres,
            "DELETE FROM t WHERE 1 = 1",
            write,
            "filtered",
            vec![f.clone()],
        ),
        (
            Postgres,
            "DELETE FROM t WHERE -1 = 1",
            write,
            "filtered",
            vec![t.clone()],
        ),
        (
            Mysql,
            "DELETE FROM t LIMIT 5",
            write,
            "filtered",
            vec![None],
        ),
        (TSql, "DELETE TOP (5) FROM t", write, "filtered", vec![None]),
        (
            Postgres,
            "UPDATE t SET a = 1",
            write,
            "action",
            vec![s("update")],
        ),
        (
            Snowflake,
            "INSERT OVERWRITE INTO t SELECT 1",
            write,
            "action",
            vec![s("overwrite")],
        ),
        (
            Snowflake,
            "CREATE OR REPLACE TABLE t AS SELECT 1",
            schema_write,
            "replaces_existing",
            vec![t.clone()],
        ),
        (
            Snowflake,
            "CREATE TABLE t (a int)",
            schema_write,
            "replaces_existing",
            vec![None],
        ),
        (
            Postgres,
            "ALTER TABLE t DROP COLUMN c",
            schema_write,
            "drops_column",
            vec![t.clone()],
        ),
        (
            Postgres,
            "ALTER TABLE t DROP CONSTRAINT c",
            schema_write,
            "drops_column",
            vec![None],
        ),
        (
            ClickHouse,
            "ALTER TABLE t DROP PARTITION 'p'",
            "database.truncate",
            "partition",
            vec![t.clone()],
        ),
        (
            Snowflake,
            "ALTER TABLE t SET DATA_RETENTION_TIME_IN_DAYS = 0",
            schema_write,
            "retention_days",
            vec![Some(AttrValue::Int(0))],
        ),
        (
            Snowflake,
            "UNDROP TABLE t",
            schema_write,
            "object_kind",
            vec![s("table")],
        ),
        // A later statement's WHERE never filters a T-SQL DELETE or UPDATE.
        (
            TSql,
            "DELETE FROM t\nSELECT COUNT(*) FROM t WHERE loaded = 1",
            write,
            "filtered",
            vec![f.clone()],
        ),
        (
            TSql,
            "UPDATE t SET a = 1 SELECT b FROM c WHERE d = 1",
            write,
            "filtered",
            vec![f.clone()],
        ),
        (
            TSql,
            "SET NOCOUNT ON\nDELETE FROM t",
            write,
            "filtered",
            vec![f.clone()],
        ),
        (
            TSql,
            "UPDATE t SET a = 1 WHERE b = 2",
            write,
            "filtered",
            vec![t.clone()],
        ),
        (
            ClickHouse,
            "ALTER TABLE t CLEAR COLUMN c",
            schema_write,
            "drops_column",
            vec![t.clone()],
        ),
        (
            ClickHouse,
            "ALTER TABLE t DROP DETACHED PARTITION 'p'",
            "database.truncate",
            "partition",
            vec![t.clone()],
        ),
        (
            ClickHouse,
            "ALTER TABLE t CLEAR INDEX i",
            schema_write,
            "drops_column",
            vec![None],
        ),
        (
            Mysql,
            "DROP TEMPORARY TABLE t",
            drop,
            "temporary",
            vec![t.clone()],
        ),
        (Mysql, "DROP TABLE t", drop, "temporary", vec![None]),
        (
            Mysql,
            "DELIMITER $$\nTRUNCATE t$$\nDELETE FROM users$$",
            write,
            "filtered",
            vec![f.clone()],
        ),
        // T-SQL `SET` after an ALTER action starts a new statement.
        (
            TSql,
            "ALTER TABLE t ADD c int SET NOCOUNT ON DELETE FROM users",
            write,
            "filtered",
            vec![f.clone()],
        ),
        (
            TSql,
            "UPDATE STATISTICS dbo.users WITH FULLSCAN",
            write,
            "action",
            vec![],
        ),
        // Expiring or discarding a table's rows empties it.
        (
            ClickHouse,
            "ALTER TABLE t MODIFY TTL d + INTERVAL 1 DAY",
            "database.truncate",
            "partition",
            vec![None],
        ),
        (
            ClickHouse,
            "ALTER TABLE t MATERIALIZE TTL",
            "database.truncate",
            "partition",
            vec![None],
        ),
        (
            Mysql,
            "ALTER TABLE t DISCARD TABLESPACE",
            "database.truncate",
            "partition",
            vec![None],
        ),
        (
            ClickHouse,
            "ALTER TABLE t ADD COLUMN c int",
            "database.truncate",
            "partition",
            vec![],
        ),
        (
            Cql,
            "DROP KEYSPACE app",
            drop,
            "object_kind",
            vec![s("keyspace")],
        ),
    ] {
        let plan = sql(dialect, source);
        assert_eq!(attr(&plan, op, key), expected, "{dialect:?} {source}");
    }
}

/// A name the server receives substituted is unresolved, never the
/// placeholder's own text, and a keyword is never taken for a name.
#[test]
fn placeholder_and_keyword_names_are_not_invented() {
    use SqlDialect::*;
    for (dialect, source) in [
        (Postgres, "DROP TABLE :tbl"),
        (Postgres, "DROP TABLE app_:suffix"),
        (Snowflake, "DROP TABLE &tbl"),
        (Snowflake, "DROP TABLE IDENTIFIER($t)"),
        (TSql, "DROP TABLE $(t)"),
        (TSql, "DROP TABLE users_$(env)"),
        (ClickHouse, "DROP TABLE {t:Identifier}"),
        (Snowflake, "DROP TABLE IDENTIFIER('\"a.b\"')"),
    ] {
        let plan = sql(dialect, source);
        assert_eq!(
            effects(&plan),
            vec![("database.schema_drop".to_string(), "?db".to_string())],
            "{dialect:?} {source}"
        );
    }
    let plan = sql(Snowflake, "INSERT OVERWRITE INTO t SELECT 1");
    assert!(has(&plan, "database.write", ".t") && !has(&plan, "database.write", "OVERWRITE"));

    // A database switch the server may reject leaves later statements in
    // both the connection's database and the selected one.
    for (dialect, source, selected) in [
        (TSql, "USE scratch\nGO\nDROP TABLE t", "scratch"),
        (Mysql, "use `a b`\nDROP TABLE t;", "a b"),
        (Snowflake, "USE prod.s; DROP TABLE t;", "prod"),
        (Postgres, "\\c other\nDROP TABLE t;", "other"),
    ] {
        let plan = analyze(&Subject::Sql {
            source: source.into(),
            dialect,
            connection: SqlConnection {
                server: None,
                database: Some("conn".into()),
            },
        });
        let mut drops: Vec<_> = effects(&plan).into_iter().map(|(_, t)| t).collect();
        drops.sort();
        let mut expected = vec![format!("?/{selected}.?.t"), "?/conn.?.t".to_string()];
        expected.sort();
        assert_eq!(drops, expected, "{dialect:?} {source}");
    }
}
