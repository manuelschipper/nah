//! Message-queue / topic CLIs: Kafka, RabbitMQ, MQTT (mosquitto), NATS, and
//! Redis pub/sub. Publishing to, consuming from, or purging a queue/topic is a
//! real agent-effect class. Effects target a typed `MessageTopic` identity;
//! every messaging CLI reaches a broker over the network. A non-literal topic
//! stays symbolic; anything unclear is an honest boundary.

use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CoverageLevel, Domain, Effect,
    Modality, Operation, ProvenanceRef, ResourceExpr, ResourceIdentity,
};

use crate::models::args::{FlagSpec, scan_literal_flags};
use crate::value::unresolved_resource;

use crate::builder::PlanBuilder;
use crate::models::common::arg_node;
use crate::models::common::boundary;
use crate::models::{CommandModel, InvocationCtx};
use crate::word::Word;

pub(super) fn messaging_models() -> Vec<Box<dyn CommandModel>> {
    vec![
        Box::new(Kafka),
        Box::new(RabbitmqCtl),
        Box::new(RabbitmqAdmin),
        Box::new(Mosquitto),
        Box::new(Nats),
        Box::new(RedisCli),
    ]
}

fn declare_common(builder: &mut PlanBuilder, model_node: ProvenanceRef) {
    builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);
    builder.declare_coverage(Domain::new("network"), CoverageLevel::Full);
    builder.boundary(Boundary {
        reason: BoundaryReason::PARTIAL_ANALYSIS,
        class: BoundaryClass::Unmodeled,
        scope: BoundaryScope::Invocation,
        affected_resource: None,
        callee: None,
        domains: vec![Domain::new("messaging")],
        provenance: vec![model_node],
        limit: None,
        detail: Some("messaging model covers selected operations".to_string()),
    });
}

/// A literal name identifies a typed topic with unknown namespace scope.
/// Unrecoverable names remain symbolic messaging resources.
fn topic(system: &str, name: &Word) -> ResourceExpr {
    match name.as_literal() {
        Some(n) => ResourceExpr::Concrete {
            identity: ResourceIdentity::MessageTopic {
                scope: Box::new(effinterp_proto::messaging_scope(Some(system))),
                system: Some(system.to_string()),
                name: n.to_string(),
            },
        },
        None => unresolved_resource("messaging"),
    }
}

fn topic_effect(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    index: u32,
    operation: &str,
    resource: ResourceExpr,
) {
    let arg = arg_node(builder, ctx, index);
    let mut provenance = vec![arg, model_node];
    let mut resource = resource;
    apply_messaging_scope(builder, ctx, &mut provenance, &mut resource);
    // A symbolic topic still has the broker selected by this invocation.
    let mut scoped = resource.clone();
    if !matches!(scoped, ResourceExpr::Concrete { .. }) {
        let command = ctx.argv[0]
            .as_literal()
            .unwrap_or("")
            .rsplit('/')
            .next()
            .unwrap_or("");
        let system = if command.starts_with("kafka-") {
            "kafka"
        } else if command.starts_with("rabbitmq") {
            "rabbitmq"
        } else if command.starts_with("mosquitto_") {
            "mqtt"
        } else if command == "nats" {
            "nats"
        } else {
            "redis"
        };
        scoped = topic(system, &Word::literal(""));
        apply_messaging_scope(builder, ctx, &mut provenance, &mut scoped);
    }
    let endpoint = match &scoped {
        ResourceExpr::Concrete { identity } => {
            identity.scope().map(crate::models::scope::network_resource)
        }
        _ => None,
    }
    .unwrap_or_else(|| unresolved_resource("network"));
    super::infrastructure::emit(builder, &provenance, "network.connect", endpoint);

    builder.effect(Effect {
        request_assurance: effinterp_proto::RequestAssurance::Conservative,
        id: Default::default(),
        operation: Operation::new(operation),
        resource,
        attributes: Default::default(),
        modality: Modality::May,
        realm: effinterp_proto::ExecutionRealm::Host,
        condition: None,
        execution: effinterp_proto::ExecutionNodeRef(0),
        provenance,
    });
}

// ---- Kafka: kafka-console-producer / -consumer / kafka-topics(.sh) ----

struct Kafka;

impl CommandModel for Kafka {
    fn domains(&self) -> &'static [&'static str] {
        &["messaging", "network", "process"]
    }

    fn id(&self) -> &'static str {
        "kafka/cli@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &[
            "kafka-console-producer",
            "kafka-console-producer.sh",
            "kafka-console-consumer",
            "kafka-console-consumer.sh",
            "kafka-topics",
            "kafka-topics.sh",
        ]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        let scanned = scan_literal_flags(ctx.argv, &FLAGS);
        declare_common(builder, model_node);
        if matches!(
            ctx.argv.get(1).and_then(Word::as_literal),
            Some("--help" | "--version")
        ) {
            return;
        }
        let prog = ctx.argv[0].as_literal().unwrap_or("");
        let topic_arg = scanned.values_of(&["--topic"]).first().copied();
        let Some((index, name)) = topic_arg else {
            boundary(
                builder,
                model_node,
                BoundaryReason::UNMODELED_SUBCOMMAND,
                BoundaryClass::Unmodeled,
                &["messaging", "network"],
                "kafka command without a resolvable --topic",
            );
            return;
        };
        let resource = topic("kafka", name);
        if prog.starts_with("kafka-topics") {
            if scanned.has(&["--delete"]) {
                topic_effect(
                    builder,
                    ctx,
                    model_node,
                    index,
                    "messaging.delete",
                    resource,
                );
            } else if scanned.has(&["--create"]) {
                topic_effect(
                    builder,
                    ctx,
                    model_node,
                    index,
                    "messaging.create",
                    resource,
                );
            } else {
                topic_effect(
                    builder,
                    ctx,
                    model_node,
                    index,
                    "messaging.consume",
                    resource,
                );
            }
        } else if prog.contains("consumer") {
            topic_effect(
                builder,
                ctx,
                model_node,
                index,
                "messaging.consume",
                resource,
            );
        } else {
            topic_effect(
                builder,
                ctx,
                model_node,
                index,
                "messaging.publish",
                resource,
            );
        }
    }
}

// ---- RabbitMQ: rabbitmqctl (purge_queue / delete_queue) ----

struct RabbitmqCtl;

impl CommandModel for RabbitmqCtl {
    fn domains(&self) -> &'static [&'static str] {
        &["messaging", "network", "process"]
    }

    fn id(&self) -> &'static str {
        "rabbitmq/rabbitmqctl@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["rabbitmqctl"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        declare_common(builder, model_node);
        if matches!(
            ctx.argv.get(1).and_then(Word::as_literal),
            Some("--help" | "--version")
        ) {
            return;
        }
        // rabbitmqctl [global opts] SUBCOMMAND [QUEUE]
        let i = crate::models::scope::command_position(
            ctx.argv,
            &["-n", "--node", "-p", "--vhost", "-t", "--timeout"],
        );
        let Some(sub) = ctx.argv.get(i).and_then(Word::as_literal) else {
            boundary(
                builder,
                model_node,
                BoundaryReason::UNMODELED_SUBCOMMAND,
                BoundaryClass::Unmodeled,
                &["messaging", "network"],
                "RabbitMQ operation is unresolved",
            );
            return;
        };
        let op = match sub {
            "purge_queue" => "messaging.purge",
            "delete_queue" => "messaging.delete",
            _ => {
                boundary(
                    builder,
                    model_node,
                    BoundaryReason::UNMODELED_SUBCOMMAND,
                    BoundaryClass::Unmodeled,
                    &["messaging", "network"],
                    &format!("rabbitmqctl {sub}"),
                );
                return;
            }
        };
        if let Some(queue) = ctx.argv.get(i + 1) {
            topic_effect(
                builder,
                ctx,
                model_node,
                (i + 1) as u32,
                op,
                topic("rabbitmq", queue),
            );
        }
    }
}

// ---- rabbitmqadmin: declare/delete queue, publish ----

struct RabbitmqAdmin;

impl CommandModel for RabbitmqAdmin {
    fn domains(&self) -> &'static [&'static str] {
        &["messaging", "network", "process"]
    }

    fn id(&self) -> &'static str {
        "rabbitmq/rabbitmqadmin@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["rabbitmqadmin"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        declare_common(builder, model_node);
        if matches!(
            ctx.argv.get(1).and_then(Word::as_literal),
            Some("--help" | "--version")
        ) {
            return;
        }
        // rabbitmqadmin <verb> <object> [key=value ...]
        let i = crate::models::scope::command_position(
            ctx.argv,
            &[
                "-H",
                "--host",
                "-P",
                "--port",
                "-V",
                "--vhost",
                "-u",
                "--username",
                "-p",
                "--password",
                "-c",
                "--config",
                "-U",
                "--base-uri",
                "--path-prefix",
                "-N",
                "--node",
            ],
        );
        let verb = ctx.argv.get(i).and_then(Word::as_literal);
        let object = ctx.argv.get(i + 1).and_then(Word::as_literal);
        // The topic/queue is a name=... key-value operand.
        let named = ctx.argv.iter().enumerate().find_map(|(idx, w)| {
            w.as_literal()
                .and_then(|t| t.strip_prefix("name="))
                .map(|n| (idx as u32, n.to_string()))
        });
        let op = match (verb, object) {
            (Some("declare"), Some("queue")) => "messaging.create",
            (Some("delete"), Some("queue")) => "messaging.delete",
            (Some("publish"), _) => "messaging.publish",
            _ => {
                boundary(
                    builder,
                    model_node,
                    BoundaryReason::UNMODELED_SUBCOMMAND,
                    BoundaryClass::Unmodeled,
                    &["messaging", "network"],
                    "rabbitmqadmin command",
                );
                return;
            }
        };
        let (index, resource) = match named {
            Some((idx, n)) => (
                idx,
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::MessageTopic {
                        scope: Box::new(effinterp_proto::messaging_scope(Some("rabbitmq"))),
                        system: Some("rabbitmq".to_string()),
                        name: n,
                    },
                },
            ),
            None => (0, unresolved_resource("messaging")),
        };
        topic_effect(builder, ctx, model_node, index, op, resource);
    }
}

// ---- MQTT: mosquitto_pub / mosquitto_sub ----

struct Mosquitto;

impl CommandModel for Mosquitto {
    fn domains(&self) -> &'static [&'static str] {
        &["messaging", "network", "process"]
    }

    fn id(&self) -> &'static str {
        "mqtt/mosquitto@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["mosquitto_pub", "mosquitto_sub"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        let scanned = scan_literal_flags(ctx.argv, &FLAGS);
        declare_common(builder, model_node);
        if matches!(
            ctx.argv.get(1).and_then(Word::as_literal),
            Some("--help" | "--version")
        ) {
            return;
        }
        let publish = ctx.argv[0].as_literal() == Some("mosquitto_pub");
        let op = if publish {
            "messaging.publish"
        } else {
            "messaging.consume"
        };
        match scanned.values_of(&["-t", "--topic"]).first().copied() {
            Some((index, name)) => {
                topic_effect(builder, ctx, model_node, index, op, topic("mqtt", name))
            }
            None => boundary(
                builder,
                model_node,
                BoundaryReason::UNMODELED_SUBCOMMAND,
                BoundaryClass::Unmodeled,
                &["messaging", "network"],
                "mosquitto without a resolvable -t topic",
            ),
        }
    }
}

// ---- NATS: nats pub SUBJECT / nats sub SUBJECT ----

struct Nats;

impl CommandModel for Nats {
    fn domains(&self) -> &'static [&'static str] {
        &["messaging", "network", "process"]
    }

    fn id(&self) -> &'static str {
        "nats/cli@v0"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &["nats"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        declare_common(builder, model_node);
        if matches!(
            ctx.argv.get(1).and_then(Word::as_literal),
            Some("--help" | "--version")
        ) {
            return;
        }
        let i = crate::models::scope::command_position(
            ctx.argv,
            &[
                "-s",
                "--server",
                "--context",
                "--creds",
                "--user",
                "--password",
                "--token",
            ],
        );
        let sub = ctx.argv.get(i).and_then(Word::as_literal);
        let op = match sub {
            Some("pub" | "publish" | "req" | "request") => "messaging.publish",
            Some("sub" | "subscribe") => "messaging.consume",
            _ => {
                boundary(
                    builder,
                    model_node,
                    BoundaryReason::UNMODELED_SUBCOMMAND,
                    BoundaryClass::Unmodeled,
                    &["messaging", "network"],
                    "nats command",
                );
                return;
            }
        };
        if let Some(subject) = ctx.argv.get(i + 1) {
            topic_effect(
                builder,
                ctx,
                model_node,
                (i + 1) as u32,
                op,
                topic("nats", subject),
            );
        }
    }
}

// ---- Redis: redis-cli PUBLISH / LPUSH / RPUSH; keyspace flushes ----

struct RedisCli;

impl CommandModel for RedisCli {
    fn domains(&self) -> &'static [&'static str] {
        &["database", "messaging", "network", "process"]
    }

    fn id(&self) -> &'static str {
        "redis/redis-cli@v0"
    }

    // Valkey and KeyDB ship redis-cli under their own names.
    fn command_names(&self) -> &'static [&'static str] {
        &["redis-cli", "valkey-cli", "keydb-cli"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        declare_common(builder, model_node);
        // redis-cli [-h host -p port ...] COMMAND args
        let plan =
            super::datastore::redis_plan(ctx.argv, ctx.stdin.map(|stdin| stdin.word.as_literal()));
        if plan.help {
            return;
        }
        super::datastore::emit_redis_plan(builder, ctx, model_node, &plan);
        let Some(i) = plan.command else {
            return;
        };
        let cmd = ctx.argv[i].as_literal().unwrap_or_default();
        // Redis verbs we treat as messaging; the channel/queue is the next arg.
        let op = match cmd.to_ascii_uppercase().as_str() {
            "PUBLISH" | "SPUBLISH" | "LPUSH" | "RPUSH" | "XADD" => "messaging.publish",
            "SUBSCRIBE" | "PSUBSCRIBE" | "BLPOP" | "BRPOP" => "messaging.consume",
            _ => {
                // redis-cli does much more than messaging; the rest is opaque.
                boundary(
                    builder,
                    model_node,
                    BoundaryReason::UNMODELED_SUBCOMMAND,
                    BoundaryClass::Unmodeled,
                    &["messaging", "network"],
                    &format!("redis-cli {cmd}"),
                );
                return;
            }
        };
        if let Some(channel) = ctx.argv.get(i + 1) {
            topic_effect(
                builder,
                ctx,
                model_node,
                (i + 1) as u32,
                op,
                topic("redis", channel),
            );
        }
    }
}

fn apply_messaging_scope(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    provenance: &mut Vec<ProvenanceRef>,
    resource: &mut ResourceExpr,
) {
    use crate::models::scope::{access_value, endpoint_evidence, scope_boundary, scope_option};
    use effinterp_proto::{ScopeDimension, ScopeEvidenceKind, ScopeValue};
    let ResourceExpr::Concrete {
        identity: ResourceIdentity::MessageTopic { system, scope, .. },
    } = resource
    else {
        return;
    };
    let command = ctx
        .argv
        .first()
        .and_then(Word::as_literal)
        .and_then(|command| command.rsplit('/').next())
        .unwrap_or("");
    match system.as_deref() {
        Some("kafka") => {
            if let Some(value) = scope_option(
                builder,
                ctx,
                provenance,
                &["--bootstrap-server", "--broker-list"],
                true,
                "messaging",
            ) {
                endpoint_evidence(scope, ScopeEvidenceKind::Seed, value);
            }
            for flag in ["--producer.config", "--consumer.config", "--command-config"] {
                if let Some(value) =
                    scope_option(builder, ctx, provenance, &[flag], true, "messaging")
                {
                    access_value(scope, ScopeEvidenceKind::ConfigurationFile, value);
                    scope_boundary(builder, provenance, "messaging");
                }
            }
        }
        Some("rabbitmq") => {
            if command == "rabbitmqadmin"
                && ctx
                    .argv
                    .iter()
                    .any(|word| word.as_literal() == Some("publish"))
            {
                **scope = effinterp_proto::ResourceScope::new(
                    effinterp_proto::NamespaceKind::Unsupported,
                );
                scope_boundary(builder, provenance, "messaging");
            }
            if command == "rabbitmqctl" {
                if let Some(value) = scope_option(
                    builder,
                    ctx,
                    provenance,
                    &["-n", "--node"],
                    true,
                    "messaging",
                ) {
                    access_value(scope, ScopeEvidenceKind::Node, value);
                }
                if let Some(value) = scope_option(
                    builder,
                    ctx,
                    provenance,
                    &["-p", "--vhost"],
                    true,
                    "messaging",
                ) {
                    scope.identity.insert(ScopeDimension::Namespace, value);
                }
            } else {
                host_port_scope(
                    builder,
                    ctx,
                    provenance,
                    scope,
                    &["-H", "--host"],
                    &["-P", "--port"],
                    true,
                );
                if let Some(base) = scope_option(
                    builder,
                    ctx,
                    provenance,
                    &["-U", "--base-uri"],
                    true,
                    "messaging",
                ) {
                    let port = scope.access.iter().find_map(|e| match &e.value {
                        ResourceExpr::Concrete {
                            identity: ResourceIdentity::NetworkEndpoint { port, .. },
                        } => *port,
                        _ => None,
                    });
                    scope
                        .access
                        .retain(|e| e.kind != ScopeEvidenceKind::Endpoint);
                    endpoint_evidence(scope, ScopeEvidenceKind::Endpoint, base);
                    for evidence in &mut scope.access {
                        if let ResourceExpr::Concrete {
                            identity:
                                ResourceIdentity::NetworkEndpoint {
                                    port: base_port,
                                    path,
                                    ..
                                },
                        } = &mut evidence.value
                        {
                            if base_port.is_none() {
                                *base_port = port;
                            }
                            *path = None;
                        }
                    }
                }
                if let Some(prefix) = scope_option(
                    builder,
                    ctx,
                    provenance,
                    &["--path-prefix"],
                    true,
                    "messaging",
                ) {
                    if let ScopeValue::Value(prefix) = prefix {
                        for evidence in &mut scope.access {
                            if let (
                                ResourceExpr::Literal { value },
                                ResourceExpr::Concrete {
                                    identity: ResourceIdentity::NetworkEndpoint { path, .. },
                                },
                            ) = (prefix.as_ref(), &mut evidence.value)
                            {
                                *path = Some(value.clone());
                            } else {
                                evidence.value = ResourceExpr::Join {
                                    parts: vec![evidence.value.clone(), *prefix.clone()],
                                };
                            }
                        }
                    } else {
                        access_value(
                            scope,
                            ScopeEvidenceKind::UnresolvedConfiguration,
                            ScopeValue::Unknown,
                        );
                    }
                }
                if let Some(context) = scope_option(
                    builder,
                    ctx,
                    provenance,
                    &["-N", "--node"],
                    true,
                    "messaging",
                ) {
                    access_value(scope, ScopeEvidenceKind::Context, context);
                    scope_boundary(builder, provenance, "messaging");
                }
                if let Some(value) = scope_option(
                    builder,
                    ctx,
                    provenance,
                    &["-V", "--vhost"],
                    true,
                    "messaging",
                ) {
                    scope.identity.insert(ScopeDimension::Namespace, value);
                }
                if let Some(value) = scope_option(
                    builder,
                    ctx,
                    provenance,
                    &["-c", "--config"],
                    true,
                    "messaging",
                ) {
                    access_value(scope, ScopeEvidenceKind::ConfigurationFile, value);
                    scope_boundary(builder, provenance, "messaging");
                }
            }
        }
        Some("mqtt") => host_port_scope(
            builder,
            ctx,
            provenance,
            scope,
            &["-h", "--host"],
            &["-p", "--port"],
            false,
        ),
        Some("nats") => {
            if let Some(value) = scope_option(
                builder,
                ctx,
                provenance,
                &["-s", "--server"],
                true,
                "messaging",
            ) {
                endpoint_evidence(scope, ScopeEvidenceKind::Seed, value);
            }
            if let Some(value) =
                scope_option(builder, ctx, provenance, &["--context"], true, "messaging")
            {
                access_value(scope, ScopeEvidenceKind::Context, value);
                scope_boundary(builder, provenance, "messaging");
            }
            if let Some(value) =
                scope_option(builder, ctx, provenance, &["--creds"], true, "messaging")
            {
                access_value(scope, ScopeEvidenceKind::ConfigurationFile, value);
                scope_boundary(builder, provenance, "messaging");
            }
        }
        Some("redis") => {
            let position = super::datastore::redis_plan(ctx.argv, None)
                .command
                .unwrap_or(ctx.argv.len());
            let cmd = ctx
                .argv
                .get(position)
                .and_then(Word::as_literal)
                .unwrap_or("")
                .to_ascii_uppercase();
            let key = matches!(cmd.as_str(), "LPUSH" | "RPUSH" | "BLPOP" | "BRPOP" | "XADD");
            if key {
                **scope =
                    effinterp_proto::ResourceScope::new(effinterp_proto::NamespaceKind::RedisKey);
            }
            if cmd == "SPUBLISH" {
                **scope = effinterp_proto::ResourceScope::new(
                    effinterp_proto::NamespaceKind::Unsupported,
                );
                scope_boundary(builder, provenance, "messaging");
            }
            let database = scope_option(builder, ctx, provenance, &["-n"], false, "messaging");
            let uri = scope_option(builder, ctx, provenance, &["-u"], false, "messaging");
            host_port_scope(builder, ctx, provenance, scope, &["-h"], &["-p"], false);
            if let Some(uri) = uri {
                if !scope.access.is_empty() {
                    scope_boundary(builder, provenance, "messaging");
                    access_value(
                        scope,
                        ScopeEvidenceKind::UnresolvedConfiguration,
                        ScopeValue::Unknown,
                    );
                }
                if let ScopeValue::Value(value) = &uri
                    && let ResourceExpr::Literal { value } = value.as_ref()
                    && key
                    && let Some((_, rest)) = value.split_once("://")
                    && let Some((_, db)) = rest.split_once('/')
                    && !db.is_empty()
                {
                    if db.parse::<u32>().is_ok() {
                        scope.identity.insert(
                            ScopeDimension::Namespace,
                            ScopeValue::value(ResourceExpr::Literal {
                                value: db.to_string(),
                            }),
                        );
                    } else {
                        scope_boundary(builder, provenance, "messaging");
                    }
                }
                endpoint_evidence(scope, ScopeEvidenceKind::Endpoint, uri);
                // The URI database selects Redis keys, not channels or a different server.
                for evidence in &mut scope.access {
                    if let ResourceExpr::Concrete {
                        identity: ResourceIdentity::NetworkEndpoint { path, .. },
                    } = &mut evidence.value
                    {
                        *path = None;
                    }
                }
            }
            if key && let Some(database) = database {
                if matches!(scope.identity.get(&ScopeDimension::Namespace), Some(ScopeValue::Value(value)) if ScopeValue::Value(value.clone()) != database)
                {
                    scope
                        .identity
                        .insert(ScopeDimension::Namespace, ScopeValue::Unknown);
                    scope_boundary(builder, provenance, "messaging");
                } else {
                    scope.identity.insert(ScopeDimension::Namespace, database);
                }
            }
        }
        _ => {}
    }
    crate::models::scope::unmodeled_scope_options(
        builder,
        ctx,
        provenance,
        scope,
        &[
            "--topic",
            "--bootstrap-server",
            "--broker-list",
            "--producer.config",
            "--consumer.config",
            "--command-config",
            "--delete",
            "--create",
            "--describe",
            "--list",
            "--from-beginning",
            "--group",
            "--partition",
            "--replication-factor",
            "--partitions",
            "--property",
            "-n",
            "--node",
            "-p",
            "--vhost",
            "-t",
            "--timeout",
            "-H",
            "--host",
            "-U",
            "--base-uri",
            "--path-prefix",
            "-N",
            "--ssl",
            "-P",
            "--port",
            "-V",
            "-u",
            "--username",
            "--password",
            "-c",
            "--config",
            "-h",
            "--context",
            "-s",
            "--server",
            "--creds",
            "--user",
            "--pass",
            "--token",
            "-a",
            "-m",
            "--message",
            "-f",
            "--file",
            "-q",
            "--qos",
            "-r",
            "--retain",
            "-d",
            "--debug",
            "--tls",
            "--cacert",
            "--cert",
            "--key",
            "--tls-ciphers",
            "--raw",
            "--no-auth-warning",
        ],
        "messaging",
    );
    effinterp_proto::normalize_scope(scope, effinterp_proto::PathPlatform::Posix);
}

fn host_port_scope(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    provenance: &mut Vec<ProvenanceRef>,
    scope: &mut effinterp_proto::ResourceScope,
    host_flags: &[&str],
    port_flags: &[&str],
    equals: bool,
) {
    use crate::models::scope::{access_value, endpoint_evidence, scope_boundary, scope_option};
    use effinterp_proto::{ScopeEvidenceKind, ScopeValue};
    let host = scope_option(builder, ctx, provenance, host_flags, equals, "messaging");
    let port = scope_option(builder, ctx, provenance, port_flags, equals, "messaging");
    match (host, port) {
        (Some(ScopeValue::Value(host)), Some(ScopeValue::Value(port))) => {
            let endpoint = match (host.as_ref(), port.as_ref()) {
                (ResourceExpr::Literal { value: host }, ResourceExpr::Literal { value: port })
                    if port.parse::<u16>().is_ok() =>
                {
                    let host = if host.contains(':') && !host.starts_with('[') {
                        format!("[{host}]")
                    } else {
                        host.clone()
                    };
                    ResourceExpr::Literal {
                        value: format!("{host}:{port}"),
                    }
                }
                (ResourceExpr::Literal { .. }, ResourceExpr::Literal { .. }) => {
                    scope_boundary(builder, provenance, "messaging");
                    unresolved_resource("network")
                }
                _ => ResourceExpr::Join {
                    parts: vec![*host, ResourceExpr::Literal { value: ":".into() }, *port],
                },
            };
            endpoint_evidence(
                scope,
                ScopeEvidenceKind::Endpoint,
                ScopeValue::value(endpoint),
            );
        }
        (Some(host), None) => endpoint_evidence(scope, ScopeEvidenceKind::Endpoint, host),
        (None, None) => {}
        _ => access_value(scope, ScopeEvidenceKind::Endpoint, ScopeValue::Unknown),
    }
}

const FLAGS: FlagSpec<'static> = FlagSpec {
    allow_abbreviation: false,
    value_flags: &["--topic", "-t"],
    known_flags: &["--delete", "--create"],
};
