use effinterp_engine::Engine;
use effinterp_proto::{Plan, ResourceExpr, ResourceIdentity, Subject, validate_plan};

fn analyze(argv: &[&str]) -> Plan {
    let plan = Engine::new()
        .analyze(&Subject::Exec {
            argv: argv.iter().map(|s| s.to_string()).collect(),
            cwd: Some("/w".to_string()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap_or_else(|e| panic!("invalid plan for {argv:?}: {e:?}"));
    if plan
        .effects
        .iter()
        .any(|effect| effect.operation.domain() == "messaging")
    {
        assert!(has_op(&plan, "process.exec"));
        let connections: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "network.connect")
            .collect();
        assert_eq!(connections.len(), 1, "{argv:?}");
        let semantic = plan
            .effects
            .iter()
            .find(|effect| effect.operation.domain() == "messaging")
            .unwrap();
        assert_eq!(connections[0].realm, semantic.realm);
        assert_eq!(connections[0].provenance, semantic.provenance);
        assert_eq!(connections[0].condition, semantic.condition);
    }

    plan
}

fn topic_effect(plan: &Plan, op: &str) -> Option<(Option<String>, String)> {
    plan.effects
        .iter()
        .find(|e| e.operation.0 == op)
        .and_then(|e| match &e.resource {
            ResourceExpr::Concrete {
                identity: ResourceIdentity::MessageTopic { system, name, .. },
            } => Some((system.clone(), name.clone())),
            _ => None,
        })
}

fn has_op(plan: &Plan, op: &str) -> bool {
    plan.effects.iter().any(|e| e.operation.0 == op)
}

#[test]
fn kafka_producer_publishes_to_topic() {
    let plan = analyze(&["kafka-console-producer", "--topic", "orders"]);
    assert!(
        matches!(&plan.effects.iter().find(|effect| effect.operation.0 == "network.connect").unwrap().resource,
        ResourceExpr::Unresolved { family } if family.0 == "network")
    );
    assert_eq!(
        topic_effect(&plan, "messaging.publish"),
        Some((Some("kafka".into()), "orders".into()))
    );
}

#[test]
fn kafka_consumer_consumes() {
    let plan = analyze(&[
        "kafka-console-consumer",
        "--topic",
        "orders",
        "--from-beginning",
    ]);
    assert!(has_op(&plan, "messaging.consume"));
}

#[test]
fn kafka_topics_delete() {
    let plan = analyze(&["kafka-topics", "--delete", "--topic", "orders"]);
    assert_eq!(
        topic_effect(&plan, "messaging.delete"),
        Some((Some("kafka".into()), "orders".into()))
    );
}

#[test]
fn rabbitmqctl_purge_and_delete() {
    let plan = analyze(&["rabbitmqctl", "purge_queue", "jobs"]);
    assert_eq!(
        topic_effect(&plan, "messaging.purge"),
        Some((Some("rabbitmq".into()), "jobs".into()))
    );
    let plan = analyze(&["rabbitmqctl", "delete_queue", "jobs"]);
    assert!(has_op(&plan, "messaging.delete"));
}

#[test]
fn rabbitmqadmin_declare_queue() {
    let plan = analyze(&[
        "rabbitmqadmin",
        "declare",
        "queue",
        "name=jobs",
        "durable=true",
    ]);
    assert_eq!(
        topic_effect(&plan, "messaging.create"),
        Some((Some("rabbitmq".into()), "jobs".into()))
    );
}

#[test]
fn mosquitto_pub_and_sub() {
    let plan = analyze(&[
        "mosquitto_pub",
        "-h",
        "broker.example",
        "-p",
        "1883",
        "-t",
        "sensors/temp",
        "-m",
        "21",
    ]);
    assert!(plan.effects.iter().any(|effect| effect.operation.0 == "network.connect" && matches!(&effect.resource,
        ResourceExpr::Concrete { identity: ResourceIdentity::NetworkEndpoint { host, port: Some(1883), .. } } if host == "broker.example")));
    assert_eq!(
        topic_effect(&plan, "messaging.publish"),
        Some((Some("mqtt".into()), "sensors/temp".into()))
    );
    let help = analyze(&["mosquitto_pub", "--help", "-t", "sensors/temp"]);
    assert!(!has_op(&help, "network.connect"));
    assert!(!has_op(&help, "messaging.publish"));
    let plan = analyze(&["mosquitto_sub", "-t", "sensors/temp"]);
    assert!(has_op(&plan, "messaging.consume"));
}

#[test]
fn nats_pub() {
    let plan = analyze(&["nats", "pub", "events.orders", "hi"]);
    assert_eq!(
        topic_effect(&plan, "messaging.publish"),
        Some((Some("nats".into()), "events.orders".into()))
    );
}

#[test]
fn redis_publish_and_lpush() {
    let plan = analyze(&["redis-cli", "PUBLISH", "events", "hi"]);
    assert_eq!(
        topic_effect(&plan, "messaging.publish"),
        Some((Some("redis".into()), "events".into()))
    );
    // Connection flags before the verb are skipped.
    let plan = analyze(&[
        "redis-cli",
        "-h",
        "broker",
        "-p",
        "6379",
        "LPUSH",
        "jobs",
        "x",
    ]);
    assert!(has_op(&plan, "messaging.publish"));
    // Non-messaging verb stays opaque.
    let plan = analyze(&["redis-cli", "GET", "somekey"]);
    assert!(!has_op(&plan, "messaging.publish"));
    assert!(
        plan.boundaries
            .iter()
            .any(|b| b.reason.as_str() == "unmodeled_subcommand")
    );
}

#[test]
fn symbolic_topic_stays_symbolic() {
    // A non-literal topic (from a shell variable) must not fabricate a name.
    let plan = Engine::new()
        .analyze(&Subject::Shell {
            source:
                "kafka-console-producer --bootstrap-server broker.example:9092 --topic \"$TOPIC\""
                    .to_string(),
            cwd: Some("/w".to_string()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    assert!(plan.effects.iter().any(|effect| effect.operation.0 == "network.connect" && matches!(&effect.resource,
        ResourceExpr::Concrete { identity: ResourceIdentity::NetworkEndpoint { host, port: Some(9092), .. } } if host == "broker.example")));

    assert!(plan.effects.iter().any(|e| {
        e.operation.0 == "messaging.publish"
            && matches!(&e.resource, ResourceExpr::Unresolved { .. })
    }));
}

#[test]
fn messaging_op_on_wrong_identity_is_rejected() {
    use effinterp_proto::{Effect, Modality, Operation};
    let mut plan = analyze(&["kafka-console-producer", "--topic", "orders"]);
    // Corrupt: a messaging op targeting a filesystem path must fail validation.
    plan.effects.push(Effect {
        request_assurance: effinterp_proto::RequestAssurance::Conservative,
        id: Default::default(),
        operation: Operation::new("messaging.publish"),
        resource: ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath {
                path: "/tmp/x".into(),
            },
        },
        attributes: Default::default(),
        modality: Modality::May,
        realm: Default::default(),
        condition: None,
        execution: effinterp_proto::ExecutionNodeRef(0),
        provenance: vec![],
    });
    plan.stamp_effect_ids().unwrap();
    assert!(validate_plan(&plan).is_err());
}

#[test]
fn messaging_scope_retains_namespace_seed_sets_and_redis_target_category() {
    use effinterp_proto::{
        NamespaceKind, ScopeDimension as D, ScopeMatch, ScopeValue as V, compare_scoped_identity,
    };
    let identity = |argv: &[&str]| {
        analyze(argv)
            .effects
            .into_iter()
            .find_map(|effect| {
                if effect.operation.domain() != "messaging" {
                    return None;
                }
                match effect.resource {
                    ResourceExpr::Concrete { identity } => Some(identity),
                    _ => None,
                }
            })
            .unwrap()
    };
    for database in ["abc", "4294967296", ""] {
        let plan = analyze(&[
            "redis-cli",
            "-h",
            "broker",
            "-n",
            database,
            "LPUSH",
            "orders",
            "x",
        ]);
        let target = plan
            .effects
            .iter()
            .find_map(|effect| match &effect.resource {
                ResourceExpr::Concrete {
                    identity: target @ ResourceIdentity::MessageTopic { .. },
                } => Some(target),
                _ => None,
            })
            .unwrap();
        assert!(
            matches!(target, ResourceIdentity::MessageTopic { system: Some(system), name, .. }
            if system == "redis" && name == "orders")
        );
        let scope = target.scope().unwrap();
        assert_eq!(scope.kind, NamespaceKind::RedisKey);
        assert_eq!(scope.identity[&D::Namespace], V::Unknown);
        assert!(!scope.access.is_empty());
        assert!(plan.boundaries.iter().any(|boundary| boundary.reason
            == effinterp_proto::BoundaryReason::UNRECOGNIZED_ARGUMENTS
            && !boundary.provenance.is_empty()));
        assert!(
            plan.boundaries.iter().all(
                |boundary| boundary.reason != effinterp_proto::BoundaryReason::UNTYPED_RESOURCE
            )
        );
    }
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../fixtures/rabbitmqadmin_scope.json")).unwrap();
    let argv: Vec<_> = fixture["argv"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    let queue = identity(&argv);
    assert_eq!(
        queue.scope().unwrap().identity[&D::Namespace],
        V::value(ResourceExpr::Literal {
            value: fixture["namespace"].as_str().unwrap().into()
        })
    );
    let a = identity(&[
        "kafka-console-producer",
        "--topic",
        "Orders",
        "--bootstrap-server",
        "B:9092,a:9092,a:9092",
    ]);
    let b = identity(&[
        "kafka-console-producer",
        "--topic",
        "Orders",
        "--bootstrap-server=a:9092,b:9092",
    ]);
    assert_eq!(a, b);
    let c = identity(&[
        "kafka-console-producer",
        "--topic",
        "Orders",
        "--bootstrap-server",
        "alias:9092",
    ]);
    assert_eq!(compare_scoped_identity(&a, &c), Some(ScopeMatch::Possible));
    let a = identity(&[
        "rabbitmqctl",
        "-n",
        "rabbit@node",
        "-p",
        "/",
        "purge_queue",
        "orders",
    ]);
    assert_eq!(
        a,
        identity(&[
            "/usr/sbin/rabbitmqctl",
            "-n",
            "rabbit@node",
            "-p",
            "/",
            "purge_queue",
            "orders",
        ])
    );
    let b = identity(&["rabbitmqctl", "--vhost=tenant", "delete_queue", "orders"]);
    assert_eq!(compare_scoped_identity(&a, &b), Some(ScopeMatch::None));
    let a = identity(&["redis-cli", "-n", "1", "PUBLISH", "orders", "x"]);
    let b = identity(&["redis-cli", "-n", "2", "PUBLISH", "orders", "x"]);
    assert_eq!(a, b);
    let key = identity(&[
        "redis-cli",
        "-u",
        "redis://user:secret@LOCALHOST:6379/2",
        "LPUSH",
        "orders",
        "x",
    ]);
    assert_eq!(key.scope().unwrap().kind, NamespaceKind::RedisKey);
    assert_eq!(
        key.scope().unwrap().identity[&D::Namespace],
        V::value(ResourceExpr::Literal { value: "2".into() })
    );
    assert_eq!(compare_scoped_identity(&a, &key), Some(ScopeMatch::None));
    let scope = serde_json::to_string(key.scope().unwrap()).unwrap();
    assert!(!scope.contains("secret"));
    assert!(!scope.contains("user"));
    assert!(
        key.scope()
            .unwrap()
            .access
            .iter()
            .any(|e| e.origin.is_some())
    );
    for argv in [
        vec![
            "mosquitto_pub",
            "-h",
            "MQTT.example",
            "-p",
            "1884",
            "-t",
            "Orders",
        ],
        vec![
            "nats",
            "-s",
            "nats://example:4223",
            "--context",
            "prod",
            "pub",
            "Orders",
            "x",
        ],
    ] {
        assert!(!identity(&argv).scope().unwrap().access.is_empty());
    }
}
