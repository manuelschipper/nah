//! Database administration clients that state their effect in argv rather
//! than in SQL: `dropdb` and `mysqladmin`.

use effinterp_proto::{
    AttrValue, CoverageLevel, Domain, ProvenanceRef, ResourceExpr, ResourceIdentity,
};

use crate::builder::PlanBuilder;
use crate::models::args::{FlagSpec, scan_with_value_indices};
use crate::models::common::{Attrs, arg_node, unrecognized_arguments_boundary};
use crate::models::{CommandModel, InvocationCtx};
use crate::value::unresolved_resource;
use crate::word::Word;

use super::sql_client_run::{client_words, flag_lists, scan_client};
use super::sql_client_spec::{CLIENT, ClientSpec};
use super::{
    CLIENT_DOMAINS, client_host_and_port, connect_effect, database_effect,
    db_client_unmodeled_subcommand, object_kind_attrs, unrecognized_operands,
};

/// A database a client drops by name (`dropdb app`, `mysqladmin drop app`).
fn drop_database(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    server: &Option<String>,
    name: (usize, &Word),
    context: &[usize],
) {
    let mut provenance = vec![model_node, arg_node(builder, ctx, name.0 as u32)];
    if ctx.tracks_host_context_environment() {
        provenance.extend(
            context
                .iter()
                .map(|index| arg_node(builder, ctx, *index as u32)),
        );
    }
    let resource = match name.1.as_literal() {
        Some(database) => ResourceExpr::Concrete {
            identity: ResourceIdentity::DatabaseSchema {
                server: server.clone(),
                database: Some(database.to_string()),
                schema: None,
            },
        },
        None => unresolved_resource("db"),
    };
    database_effect(
        builder,
        "database.schema_drop",
        resource,
        object_kind_attrs("database"),
        provenance,
    );
}

pub(super) struct Dropdb;

impl CommandModel for Dropdb {
    fn domains(&self) -> &'static [&'static str] {
        &crate::builder::KNOWN_DOMAINS
    }

    fn id(&self) -> &'static str {
        "postgres/dropdb@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["dropdb"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);
        let scanned = scan_with_value_indices(
            ctx.argv,
            &FlagSpec {
                allow_abbreviation: false,
                value_flags: &[
                    "-h",
                    "--host",
                    "-p",
                    "--port",
                    "-U",
                    "--username",
                    "--maintenance-db",
                ],
                known_flags: &[
                    "-e",
                    "--echo",
                    "-i",
                    "--interactive",
                    "--if-exists",
                    "-f",
                    "--force",
                    "-w",
                    "--no-password",
                    "-W",
                    "--password",
                    "-V",
                    "--version",
                    "-?",
                    "--help",
                ],
            },
            true,
        );
        if scanned.has(&["-V", "--version", "-?", "--help"]) && scanned.unknown_flags.is_empty() {
            return;
        }
        if !scanned.unknown_flags.is_empty() {
            for domain in CLIENT_DOMAINS {
                builder.declare_coverage(Domain::new(*domain), CoverageLevel::Partial);
            }
            unrecognized_arguments_boundary(
                builder,
                model_node,
                CLIENT_DOMAINS,
                &scanned.unknown_flags,
            );
        }
        let (server, server_index, port, port_index) =
            client_host_and_port(&scanned, &["-h", "--host"], &["-p", "--port"]);
        connect_effect(
            builder,
            ctx,
            model_node,
            &server,
            port,
            Some("postgresql"),
            &[server_index, port_index]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>(),
        );
        let Some(&(index, name)) = scanned.operands.first() else {
            return;
        };
        let extra = scanned.operands[1..]
            .iter()
            .map(|(_, word)| word.as_literal().unwrap_or("?"))
            .collect::<Vec<_>>();
        unrecognized_operands(builder, model_node, &extra);
        drop_database(
            builder,
            ctx,
            model_node,
            &server,
            (index as usize, name),
            &server_index.into_iter().collect::<Vec<_>>(),
        );
    }
}

/// mysqladmin commands that only report server state.
const MYSQLADMIN_READS: &[&str] = &[
    "ping",
    "status",
    "extended-status",
    "processlist",
    "variables",
    "version",
];

/// Every mysqladmin command; a command may be abbreviated to a unique prefix.
const MYSQLADMIN_COMMANDS: &[&str] = &[
    "create",
    "debug",
    "drop",
    "extended-status",
    "flush-hosts",
    "flush-logs",
    "flush-privileges",
    "flush-status",
    "flush-tables",
    "flush-threads",
    "kill",
    "password",
    "ping",
    "processlist",
    "purge",
    "reload",
    "refresh",
    "shutdown",
    "start-replica",
    "start-slave",
    "status",
    "stop-replica",
    "stop-slave",
    "variables",
    "version",
];

const MYSQLADMIN: ClientSpec = ClientSpec {
    host: &["-h", "--host"],
    port: &["-P", "--port"],
    values: &[
        "-u",
        "--user",
        "-S",
        "--socket",
        "-c",
        "--count",
        "-i",
        "--sleep",
        "--connect-timeout",
        "--shutdown-timeout",
        "--defaults-file",
        "--defaults-extra-file",
        "--defaults-group-suffix",
        "--login-path",
        "--protocol",
        "--default-auth",
        "--plugin-dir",
        "--character-sets-dir",
        "--default-character-set",
        "--bind-address",
        "--compression-algorithms",
        "--zstd-compression-level",
        "--ssl-ca",
        "--ssl-capath",
        "--ssl-cert",
        "--ssl-cipher",
        "--ssl-crl",
        "--ssl-crlpath",
        "--ssl-key",
        "--ssl-mode",
        "--tls-version",
        "--tls-ciphersuites",
        "--server-public-key-path",
    ],
    switches: &[
        "-f",
        "--force",
        "-s",
        "--silent",
        "-v",
        "--verbose",
        "-r",
        "--relative",
        "-E",
        "--vertical",
        "-C",
        "--compress",
        "-b",
        "--no-beep",
        "-T",
        "--debug-info",
        "--no-defaults",
        "--print-defaults",
        "--enable-cleartext-plugin",
        "--get-server-public-key",
        "--show-warnings",
        "--ssl",
        "--skip-ssl",
        "-w",
        "--wait",
    ],
    help: &["-?", "--help", "-V", "--version"],
    attached_only: &["-p", "--password"],
    ..CLIENT
};

pub(super) struct Mysqladmin;

impl CommandModel for Mysqladmin {
    fn domains(&self) -> &'static [&'static str] {
        &crate::builder::KNOWN_DOMAINS
    }

    fn id(&self) -> &'static str {
        "mysql/mysqladmin@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["mysqladmin"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);
        let words = client_words(ctx.argv, &MYSQLADMIN);
        let flags = flag_lists(&MYSQLADMIN);
        let scanned = scan_client(&words, &flags, &MYSQLADMIN);
        if scanned.has(MYSQLADMIN.help) && scanned.unknown_flags.is_empty() {
            return;
        }
        if !scanned.unknown_flags.is_empty() {
            for domain in CLIENT_DOMAINS {
                builder.declare_coverage(Domain::new(*domain), CoverageLevel::Partial);
            }
            unrecognized_arguments_boundary(
                builder,
                model_node,
                CLIENT_DOMAINS,
                &scanned.unknown_flags,
            );
        }
        let (server, server_index, port, port_index) =
            client_host_and_port(&scanned, MYSQLADMIN.host, MYSQLADMIN.port);
        connect_effect(
            builder,
            ctx,
            model_node,
            &server,
            port,
            None,
            &[server_index, port_index]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>(),
        );
        let context = server_index.into_iter().collect::<Vec<_>>();
        let mut operands = scanned.operands.iter();
        let mut unmodeled = Vec::new();
        while let Some(&(_, word)) = operands.next() {
            let Some(text) = word.as_literal() else {
                unmodeled.push("?".to_string());
                continue;
            };
            // mysqladmin matches command names without regard to case.
            let lower = text.to_ascii_lowercase();
            let mut matches = MYSQLADMIN_COMMANDS
                .iter()
                .filter(|command| command.starts_with(lower.as_str()));
            let command = match (matches.next(), matches.next()) {
                (Some(command), None) => *command,
                _ if MYSQLADMIN_COMMANDS.contains(&lower.as_str()) => lower.as_str(),
                _ => {
                    unmodeled.push(text.to_string());
                    continue;
                }
            };
            match command {
                "create" | "drop" => {
                    let Some(&(name_index, name)) = operands.next() else {
                        continue;
                    };
                    if command == "drop" {
                        drop_database(
                            builder,
                            ctx,
                            model_node,
                            &server,
                            (name_index as usize, name),
                            &context,
                        );
                        continue;
                    }
                    let resource = match name.as_literal() {
                        Some(database) => ResourceExpr::Concrete {
                            identity: ResourceIdentity::DatabaseSchema {
                                server: server.clone(),
                                database: Some(database.to_string()),
                                schema: None,
                            },
                        },
                        None => unresolved_resource("db"),
                    };
                    let arg = arg_node(builder, ctx, name_index);
                    database_effect(
                        builder,
                        "database.write",
                        resource,
                        Attrs::from([("action".to_string(), AttrValue::String("create".into()))]),
                        vec![model_node, arg],
                    );
                }
                command if MYSQLADMIN_READS.contains(&command) => {}
                command => unmodeled.push(command.to_string()),
            }
        }
        if !unmodeled.is_empty() {
            db_client_unmodeled_subcommand(
                builder,
                model_node,
                &format!("mysqladmin commands not modeled: {}", unmodeled.join(", ")),
            );
        }
    }
}
