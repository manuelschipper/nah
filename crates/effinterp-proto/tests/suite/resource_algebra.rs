use effinterp_proto::{
    Condition, ContainerStorage, PathPlatform, ResourceExpr, ResourceFamily, ResourceIdentity,
    display_identity, filesystem_path, normalize_resource,
};

#[test]
fn composed_conditions_are_canonical_and_widen_explicitly() {
    let atom = |start| {
        Condition::from_source(
            "abcdef",
            effinterp_proto::ByteSpan {
                start,
                end: start + 1,
            },
            effinterp_proto::ConditionKind::Branch,
            0,
            2,
            true,
            true,
        )
    };
    let a = atom(0);
    let b = atom(1);
    let composed = Condition::compose([&a, &b, &a]).unwrap();
    assert_eq!(composed.atoms().len(), 2);
    assert_eq!(Some(composed), Condition::compose([&b, &a]));
    let terms: Vec<_> = (0..64)
        .map(|ordinal| {
            let mut term = atom(0);
            if let Condition::Atom { atom } = &mut term {
                atom.origin.ordinal = ordinal;
            }
            term
        })
        .collect();
    assert_eq!(Condition::compose(&terms), Some(Condition::Widened));
}

fn path(value: &str) -> ResourceExpr {
    ResourceExpr::Concrete {
        identity: ResourceIdentity::FsPath {
            path: value.to_string(),
        },
    }
}

#[test]
fn relative_paths_retain_their_cwd_derivation() {
    let derived = filesystem_path("logs/app.log", None, PathPlatform::Posix);
    assert!(matches!(
        derived,
        ResourceExpr::Join { ref parts }
            if matches!(parts.as_slice(), [ResourceExpr::Parameter { name }, ResourceExpr::Concrete { .. }] if name == "cwd")
    ));
    let exact = filesystem_path(
        "logs/../app.log",
        Some(path("/srv/service")),
        PathPlatform::Posix,
    );
    assert_eq!(exact, path("/srv/service/app.log"));
}

#[test]
fn joins_flatten_without_erasing_symbolic_parts_and_unions_are_canonical() {
    let symbolic = ResourceExpr::Join {
        parts: vec![
            ResourceExpr::Join {
                parts: vec![
                    path("/srv"),
                    ResourceExpr::Parameter {
                        name: "tenant".into(),
                    },
                ],
            },
            path("data"),
        ],
    };
    let normalized = normalize_resource(symbolic, PathPlatform::Posix);
    assert!(matches!(
        normalized,
        ResourceExpr::Join { ref parts }
            if parts.len() == 3 && matches!(&parts[1], ResourceExpr::Parameter { name } if name == "tenant")
    ));

    let union = ResourceExpr::Union {
        alternatives: vec![path("/b"), path("/a"), path("/b")],
    };
    assert_eq!(
        normalize_resource(union, PathPlatform::Posix),
        ResourceExpr::Union {
            alternatives: vec![path("/a"), path("/b")]
        }
    );

    let empty = ResourceExpr::Join { parts: Vec::new() };
    assert_eq!(
        normalize_resource(empty.clone(), PathPlatform::Posix),
        empty
    );

    let concrete = ResourceExpr::Join {
        parts: vec![path("/home/u"), path("/data")],
    };
    assert_eq!(
        normalize_resource(concrete, PathPlatform::Posix),
        path("/home/u/data")
    );
}

#[test]
fn container_storage_and_database_scope_remain_distinct() {
    let container = ResourceIdentity::Container {
        runtime: "DOCKER://".into(),
        name: Some("/worker".into()),
        image: Some("example/worker:v1".into()),
        storage: vec![ContainerStorage::BindMount {
            host_path: ResourceExpr::Parameter {
                name: "host".into(),
            },
            container_path: path("/data/./input"),
            read_only: false,
        }],
    };
    let normalized = normalize_resource(
        ResourceExpr::Concrete {
            identity: container,
        },
        PathPlatform::Posix,
    );
    assert!(matches!(
        &normalized,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::Container { runtime, name: Some(name), image: Some(image), storage }
        } if runtime == "docker" && name == "worker" && image == "example/worker:v1" && matches!(
            &storage[0],
            ContainerStorage::BindMount { host_path: ResourceExpr::Parameter { name }, container_path, read_only: false }
                if name == "host" && container_path == &path("/data/input")
        )
    ));
    let ResourceExpr::Concrete { identity } = &normalized else {
        unreachable!()
    };
    assert_eq!(
        display_identity(identity),
        "container:docker:worker [image=example/worker:v1]"
    );

    for name in ["/", "//", "///"] {
        let normalized = normalize_resource(
            ResourceExpr::Concrete {
                identity: ResourceIdentity::Container {
                    runtime: "docker".into(),
                    name: Some(name.into()),
                    image: None,
                    storage: Vec::new(),
                },
            },
            PathPlatform::Posix,
        );
        assert!(matches!(normalized, ResourceExpr::Concrete {
            identity: ResourceIdentity::Container { name: Some(ref kept), .. }
        } if kept == name));
    }

    let a = ResourceIdentity::DatabaseTable {
        server: Some("DB.EXAMPLE.".into()),
        database: Some("app".into()),
        schema: Some("public".into()),
        table: "users".into(),
    };
    let b = ResourceIdentity::DatabaseTable {
        server: Some("db.example".into()),
        database: Some("audit".into()),
        schema: Some("public".into()),
        table: "users".into(),
    };
    assert_ne!(
        normalize_resource(ResourceExpr::Concrete { identity: a }, PathPlatform::Posix),
        normalize_resource(ResourceExpr::Concrete { identity: b }, PathPlatform::Posix)
    );
}

#[test]
fn container_runtime_path_aliases_normalize_to_one_identity() {
    let identity = |runtime: &str| ResourceExpr::Concrete {
        identity: ResourceIdentity::Container {
            runtime: runtime.into(),
            name: None,
            image: Some("alpine".into()),
            storage: Vec::new(),
        },
    };
    assert_eq!(
        normalize_resource(identity("docker"), PathPlatform::Posix),
        normalize_resource(identity("/usr/bin/docker"), PathPlatform::Posix)
    );
}

#[test]
fn exact_patterns_and_unknowns_never_collapse() {
    for (input, expected, target) in [
        ("/work/./x//*.rs", "/work/x/*.rs", "/work/x/a.rs"),
        (r"\/work/\./x\//*.rs", r"\/work/x\/*.rs", "/work/x/a.rs"),
        (
            r"/work/./a\\//\[b\]/*.rs",
            r"/work/a\\/\[b\]/*.rs",
            r"/work/a\/[b]/x.rs",
        ),
        ("/./", "/", "/"),
        ("/w/x/../build/*", "/w/build/*", "/w/build/o.o"),
        ("/w/../y/*.rs", "/y/*.rs", "/y/a.rs"),
        ("/w/x/../../../../*.rs", "/*.rs", "/a.rs"),
        (r"/w/\[ab\]/../*.rs", "/w/*.rs", "/w/a.rs"),
        (r"/w/\.\./y/*.rs", "/y/*.rs", "/y/a.rs"),
        (r"/w\/x\/..\/y/*.rs", r"/w\/y/*.rs", "/w/y/a.rs"),
        (r"/w/a\\b/../*.rs", "/w/*.rs", "/w/a.rs"),
    ] {
        let resource = normalize_resource(
            ResourceExpr::Pattern {
                pattern: effinterp_proto::ResourcePattern::FsPath {
                    glob: input.into(),
                    narrowing: Default::default(),
                },
            },
            PathPlatform::Posix,
        );
        let ResourceExpr::Pattern {
            pattern: effinterp_proto::ResourcePattern::FsPath { glob: pattern, .. },
        } = &resource
        else {
            panic!("expected pattern")
        };
        assert_eq!(pattern, expected);
        assert_eq!(effinterp_proto::glob_match(pattern, target), Ok(true));
        assert_eq!(
            normalize_resource(resource.clone(), PathPlatform::Posix),
            resource
        );
    }
    for input in [
        "/work/*/../x",
        r"/work/./x\",
        "/work/./[bad",
        "/work/../[bad",
        "/work/../a**b",
        "/work/*/x/../a",
        "/work/**/../a",
        "/work/[ab]/../x",
        r"/work/../x\",
    ] {
        let resource = ResourceExpr::Pattern {
            pattern: effinterp_proto::ResourcePattern::FsPath {
                glob: input.into(),
                narrowing: Default::default(),
            },
        };
        assert_eq!(
            normalize_resource(resource.clone(), PathPlatform::Posix),
            resource
        );
    }
    for (input, prefix, tail) in [
        ("../*.rs", "../", "*.rs"),
        ("a/../../build/*", "a/../../build/", "*"),
        (r"/\[ab\]/../*.rs", "/[ab]/../", "*.rs"),
    ] {
        let cwd = ResourceExpr::Parameter { name: "cwd".into() };
        let glob = |pattern: &str| ResourceExpr::Pattern {
            pattern: effinterp_proto::ResourcePattern::FsPath {
                glob: pattern.into(),
                narrowing: Default::default(),
            },
        };
        let normalized = normalize_resource(
            ResourceExpr::Join {
                parts: vec![cwd.clone(), glob(input)],
            },
            PathPlatform::Posix,
        );
        assert_eq!(
            normalized,
            ResourceExpr::Join {
                parts: vec![cwd, path(prefix), glob(tail)],
            }
        );
        assert_eq!(
            normalize_resource(normalized.clone(), PathPlatform::Posix),
            normalized
        );
        assert_eq!(effinterp_proto::validate_glob(tail), Ok(()));
    }
    let glob = |pattern: &str| ResourceExpr::Pattern {
        pattern: effinterp_proto::ResourcePattern::FsPath {
            glob: pattern.into(),
            narrowing: Default::default(),
        },
    };
    let through_wildcard = ResourceExpr::Join {
        parts: vec![
            glob("/work/*"),
            ResourceExpr::Join {
                parts: vec![
                    ResourceExpr::Parameter {
                        name: "name".into(),
                    },
                    glob("/../*.rs"),
                ],
            },
        ],
    };
    let normalized = normalize_resource(through_wildcard, PathPlatform::Posix);
    let ResourceExpr::Join { parts } = &normalized else {
        panic!("expected join")
    };
    assert_eq!(parts.last(), Some(&glob("/../*.rs")));
    assert_eq!(
        normalize_resource(normalized.clone(), PathPlatform::Posix),
        normalized
    );
    let exact = path("/tmp/build-1");
    let pattern = ResourceExpr::Pattern {
        pattern: effinterp_proto::ResourcePattern::FsPath {
            glob: "/tmp/build-*".into(),
            narrowing: Default::default(),
        },
    };
    let unknown = ResourceExpr::Unresolved {
        family: ResourceFamily::new("filesystem"),
    };
    assert_ne!(
        normalize_resource(exact, PathPlatform::Posix),
        normalize_resource(pattern.clone(), PathPlatform::Posix)
    );
    assert_eq!(
        normalize_resource(unknown.clone(), PathPlatform::Posix),
        unknown
    );
}

#[test]
fn join_fragments_survive_until_binding() {
    let literal = |value: &str| ResourceExpr::Literal {
        value: value.into(),
    };
    for (tail, expected) in [
        (path("/../x"), "/x"),
        (path("/.cache/../x"), "/home/x"),
        (literal("x"), "/homex"),
        (path("/x"), "/home/x"),
        (literal(".tgz"), "/home.tgz"),
    ] {
        let symbolic = ResourceExpr::Join {
            parts: vec![
                ResourceExpr::Environment {
                    name: "HOME".into(),
                },
                ResourceExpr::Join {
                    parts: vec![tail.clone()],
                },
            ],
        };
        let normalized = normalize_resource(symbolic, PathPlatform::Posix);
        assert_eq!(
            normalize_resource(normalized.clone(), PathPlatform::Posix),
            normalized
        );
        let ResourceExpr::Join { mut parts } = normalized else {
            panic!()
        };
        assert_eq!(parts[1], tail);
        parts[0] = path("/home");
        assert_eq!(
            normalize_resource(ResourceExpr::Join { parts }, PathPlatform::Posix),
            path(expected)
        );
    }
    for (parts, expected) in [
        (vec![path("/"), path("x")], "/x"),
        (vec![path("/home/"), literal("x")], "/home/x"),
        (vec![path("/home"), path("a/../"), literal("x")], "/home/x"),
        (vec![path("foo"), literal("bar")], "foobar"),
        (vec![path("/home"), literal("")], "/home"),
    ] {
        assert_eq!(
            normalize_resource(ResourceExpr::Join { parts }, PathPlatform::Posix),
            path(expected)
        );
    }
    let nested = ResourceExpr::Join {
        parts: vec![
            ResourceExpr::Environment {
                name: "HOME".into(),
            },
            ResourceExpr::Union {
                alternatives: vec![ResourceExpr::Join {
                    parts: vec![path("/../x")],
                }],
            },
        ],
    };
    let normalized = normalize_resource(nested, PathPlatform::Posix);
    assert_eq!(
        normalized,
        ResourceExpr::Join {
            parts: vec![
                ResourceExpr::Environment {
                    name: "HOME".into()
                },
                path("/../x")
            ]
        }
    );
    assert_eq!(
        normalize_resource(normalized.clone(), PathPlatform::Posix),
        normalized
    );
    let text = ResourceExpr::Join {
        parts: vec![literal("foo"), literal("bar")],
    };
    assert_eq!(normalize_resource(text.clone(), PathPlatform::Posix), text);
}

#[test]
fn network_canonicalization_preserves_case_sensitive_fields() {
    for (host, expected) in [
        ("EXAMPLE.COM.", "example.com"),
        ("EXAMPLE.COM..", "example.com.."),
        ("User@EXAMPLE.COM.", "User@example.com"),
        ("[FE80::AB%ZoneA]", "[fe80::ab%ZoneA]"),
    ] {
        let resource = ResourceExpr::Concrete {
            identity: ResourceIdentity::NetworkEndpoint {
                host: host.into(),
                scheme: Some("HTTPS".into()),
                port: Some(443),
                path: Some("/Case?Q=X".into()),
            },
        };
        let expected = ResourceExpr::Concrete {
            identity: ResourceIdentity::NetworkEndpoint {
                host: expected.into(),
                scheme: Some("https".into()),
                port: Some(443),
                path: Some("/Case?Q=X".into()),
            },
        };
        assert_eq!(normalize_resource(resource, PathPlatform::Posix), expected);
        assert_eq!(
            normalize_resource(expected.clone(), PathPlatform::Posix),
            expected
        );
    }
}

#[test]
fn wildcard_parents_collapse_only_on_request() {
    use effinterp_proto::collapse_wildcard_parents;
    for (input, expected) in [
        ("/work/*/../x", Some("/work/x")),
        ("/work/*/x/../a", Some("/work/*/a")),
        ("/work/[ab]/../x", Some("/work/x")),
        ("/tmp/*/../../etc/x", Some("/etc/x")),
        // No parent crosses a wildcard.
        ("/work/x/../*.rs", None),
        ("/work/*.rs", None),
        // `**` may select no directory, and `.*` may name `..` itself.
        ("/work/**/../a", None),
        ("/work/.*/../a", None),
    ] {
        assert_eq!(
            collapse_wildcard_parents(input).as_deref(),
            expected,
            "{input}"
        );
    }
}

#[test]
fn filesystem_globs_are_segmented_validated_and_bounded() {
    use effinterp_proto::{MatchReason, glob_match, validate_glob};
    for (pattern, text, expected) in [
        ("/tmp/*", "/tmp/a/b", false),
        ("/tmp/*", "/tmp/.hidden", false),
        ("/tmp/*.*", "/tmp/.hidden", false),
        ("/tmp/.*", "/tmp/.hidden", true),
        ("/tmp/**", "/tmp/a/b", true),
        ("/tmp/**", "/tmp/.hidden/x", true),
        ("/tmp/**", "/tmp", true),
        ("/tmp/**/x", "/tmp/x", true),
        ("/tmp/**/x", "/tmp/.hidden/x", true),
        ("/tmp/?", "/tmp/é", true),
        ("/tmp/[a-z]", "/tmp/k", true),
        ("/tmp/[a-]", "/tmp/-", true),
        ("/tmp/[]]", "/tmp/]", true),
        ("/tmp/[!a-z]", "/tmp/9", true),
        ("/tmp/.[[:lower:]]sh", "/tmp/.ssh", true),
        ("/tmp/[[:alpha:]]*", "/tmp/.ssh", false),
        ("/tmp/[[:alpha:]]", "/tmp/9", false),
        ("/tmp/[![:alpha:]]", "/tmp/9", true),
        ("/tmp/[[:digit:][:upper:]]", "/tmp/A", true),
        ("/tmp/[[=s=]]", "/tmp/s", true),
        ("/tmp/[[.a.]-c]", "/tmp/b", true),
        (r"/tmp/\*", "/tmp/*", true),
        (r"/tmp\/x", "/tmp/x", true),
        (r"/tmp/a\\/x", r"/tmp/a\/x", true),
        ("/work/**", "/worker/x", false),
    ] {
        assert_eq!(glob_match(pattern, text), Ok(expected), "{pattern}: {text}");
    }
    for pattern in [
        "[",
        "[]",
        "[z-a]",
        "[[:foo:]]",
        "[[:alpha:]",
        "[[.ab.]]",
        "a\\",
        "a**b",
        "a/**x",
        "*/../x",
        r"*/\.\./x",
    ] {
        assert_eq!(
            validate_glob(pattern),
            Err(MatchReason::InvalidInput),
            "{pattern}"
        );
        assert_eq!(glob_match(pattern, "x"), Err(MatchReason::InvalidInput));
    }
    let pattern = "*a".repeat(1024);
    assert_eq!(validate_glob(&pattern), Ok(()));
    assert_eq!(
        glob_match(&pattern, &"a".repeat(1024)),
        Err(MatchReason::Limit)
    );
    assert_eq!(
        glob_match("*", &"a".repeat(65_536)),
        Err(MatchReason::Limit)
    );
}

#[test]
fn namespace_scope_matching_keeps_conflicts_unknowns_and_access_distinct() {
    use effinterp_proto::{
        NamespaceKind, ResourceScope, ScopeDimension, ScopeEvidence, ScopeEvidenceKind, ScopeMatch,
        ScopeValue, compare_scope,
    };
    let literal = |s: &str| ScopeValue::value(ResourceExpr::Literal { value: s.into() });
    let mut a = ResourceScope::new(NamespaceKind::AwsRegional);
    a.identity.insert(ScopeDimension::Partition, literal("aws"));
    a.identity
        .insert(ScopeDimension::Account, literal("111111111111"));
    let mut b = a.clone();
    assert_eq!(compare_scope(&a, &b), ScopeMatch::Possible);
    b.identity
        .insert(ScopeDimension::Account, literal("222222222222"));
    assert_eq!(compare_scope(&a, &b), ScopeMatch::None);
    b = a.clone();
    a.identity
        .insert(ScopeDimension::Region, literal("eu-west-1"));
    b.identity
        .insert(ScopeDimension::Region, literal("eu-west-1"));
    assert_eq!(compare_scope(&a, &b), ScopeMatch::Exact);
    b.access.push(ScopeEvidence {
        kind: ScopeEvidenceKind::Profile,
        value: ResourceExpr::Literal {
            value: "other-profile".into(),
        },
        origin: None,
    });
    assert_eq!(compare_scope(&a, &b), ScopeMatch::Exact);
    a.identity.insert(ScopeDimension::Region, ScopeValue::Any);
    b.identity
        .insert(ScopeDimension::Region, ScopeValue::Unknown);
    assert_eq!(compare_scope(&a, &b), ScopeMatch::Exact);
    assert!(!a.valid_dimensions(false));
    assert!(a.valid_dimensions(true));
    a.identity
        .insert(ScopeDimension::Account, literal("333333333333"));
    assert_eq!(compare_scope(&a, &b), ScopeMatch::None);
    let mut channel = ResourceScope::new(NamespaceKind::RedisChannel);
    channel
        .identity
        .insert(ScopeDimension::Namespace, literal("1"));
    assert!(!channel.valid_dimensions(false));
    let mut queue = ResourceScope::new(NamespaceKind::RabbitQueue);
    queue
        .identity
        .insert(ScopeDimension::Namespace, literal(""));
    let mut other = queue.clone();
    other
        .identity
        .insert(ScopeDimension::Namespace, literal("/"));
    assert_eq!(compare_scope(&queue, &other), ScopeMatch::None);

    channel.access.push(ScopeEvidence {
        kind: ScopeEvidenceKind::Endpoint,
        value: ResourceExpr::Union {
            alternatives: vec![
                ResourceExpr::Literal {
                    value: "redis://user:secret@HOST:6379/1".into(),
                },
                ResourceExpr::Join {
                    parts: vec![
                        ResourceExpr::Literal {
                            value: "redis://user:secret@".into(),
                        },
                        ResourceExpr::Environment {
                            name: "HOST".into(),
                        },
                    ],
                },
            ],
        },
        origin: None,
    });
    effinterp_proto::normalize_scope(&mut channel, PathPlatform::Posix);
    assert!(!serde_json::to_string(&channel).unwrap().contains("secret"));
    let normalized = channel.clone();
    effinterp_proto::normalize_scope(&mut channel, PathPlatform::Posix);
    assert_eq!(channel, normalized);
}

#[test]
fn condition_bounds_and_identity_exclude_only_display_evidence() {
    use effinterp_proto::{ByteSpan, ConditionEvidence, ConditionKind};
    let guard = Condition::from_source(
        "secret predicate",
        ByteSpan { start: 0, end: 16 },
        ConditionKind::Branch,
        0,
        2,
        true,
        true,
    );
    let mut edited = guard.clone();
    if let Condition::Atom { atom } = &mut edited {
        atom.evidence = ConditionEvidence::Source {
            path: Some("/private/source".into()),
            excerpt: Some("different display".into()),
        };
    }
    assert_eq!(guard.identity_key(), edited.identity_key());
    let effect_identity = |condition: Condition| effinterp_proto::EffectIdentity {
        request_assurance: effinterp_proto::RequestAssurance::Conservative,
        operation: effinterp_proto::Operation::new("filesystem.delete"),
        resource: path("/target"),
        realm: Default::default(),
        modality: effinterp_proto::Modality::May,
        attributes: Default::default(),
        condition: Some(condition),
        occurrence: effinterp_proto::EffectOccurrence {
            subject_digest: "subject".into(),
            realm: Default::default(),
            ordinal: 0,
        },
    };
    let identities = |condition: Condition| {
        let effect = effect_identity(condition);
        let fact = effinterp_proto::FactIdentity {
            request_assurance: effinterp_proto::RequestAssurance::Conservative,
            operation: effect.operation.clone(),
            resource: effect.resource.clone(),
            realm: effect.realm.clone(),
            modality: effect.modality,
            attributes: effect.attributes.clone(),
            condition: effect.condition.clone(),
            provenance_roots: vec![],
            dispatch: None,
        };
        (
            effinterp_proto::EffectId::derive(&effect),
            effinterp_proto::FactId::derive(&fact),
        )
    };
    assert_eq!(identities(guard.clone()), identities(edited.clone()));
    let mut opposite = guard.clone();
    if let Condition::Atom { atom } = &mut opposite {
        atom.arm = 1;
        atom.polarity = Some(false);
    }
    assert_ne!(identities(guard.clone()), identities(opposite));
    edited.rebind("call one");
    assert_ne!(guard.identity_key(), edited.identity_key());
    assert_ne!(identities(guard.clone()), identities(edited.clone()));
    assert_eq!(guard.identity(), guard.redacted().identity());
    let mut wrong_arm = serde_json::to_value(&guard).unwrap();
    wrong_arm["atom"]["arm"] = serde_json::json!(2);
    assert!(serde_json::from_value::<Condition>(wrong_arm).is_err());
    let mut wrong_span = serde_json::to_value(&guard).unwrap();
    wrong_span["atom"]["origin"]["span"]["start"] = serde_json::json!(17);
    assert!(serde_json::from_value::<Condition>(wrong_span).is_err());
    let oversized = serde_json::json!({"kind":"all","conditions":vec![serde_json::to_value(&guard).unwrap();64]});
    assert!(serde_json::from_value::<Condition>(oversized).is_err());
    let mut nested = serde_json::to_value(&guard).unwrap();
    for _ in 0..16 {
        nested = serde_json::json!({"kind":"all","conditions":[nested,{"kind":"widened"}]});
    }
    assert!(serde_json::from_value::<Condition>(nested).is_err());
    assert!(serde_json::from_str::<Condition>(r#"{"expression":"old condition"}"#).is_err());
    let unicode = "é".repeat(200);
    let bounded = Condition::from_source(
        &unicode,
        ByteSpan {
            start: 0,
            end: unicode.len() as u32,
        },
        ConditionKind::Branch,
        0,
        2,
        true,
        true,
    );
    let Condition::Atom { atom } = bounded else {
        panic!("bounded source atom")
    };
    let ConditionEvidence::Source {
        excerpt: Some(text),
        ..
    } = atom.evidence
    else {
        panic!("source evidence")
    };
    assert_eq!(text.len(), 256);
}

#[test]
fn infrastructure_identities_round_trip_symbolic_fields_through_the_query_schema() {
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../../analysis-v1.schema.json")).unwrap();
    let resource_schema =
        serde_json::json!({"$ref":"#/$defs/resource_expression", "$defs":schema["$defs"]});
    let validator = jsonschema::validator_for(&resource_schema).unwrap();
    for identity in [
        ResourceIdentity::KubernetesResource {
            api_group: "apps".into(),
            kind: "Deployment".into(),
            name: Box::new(ResourceExpr::Environment {
                name: "DEPLOYMENT".into(),
            }),
            namespace: effinterp_proto::KubernetesNamespace::Namespaced {
                namespace: Box::new(ResourceExpr::Literal {
                    value: "prod".into(),
                }),
            },
            server: Box::new(ResourceExpr::Parameter {
                name: "cluster".into(),
            }),
            context: Box::new(ResourceExpr::Literal {
                value: "west".into(),
            }),
        },
        ResourceIdentity::ManagedInfrastructure {
            tool: "terraform".into(),
            configuration_root: Box::new(path("/work/./app")),
            workspace: Box::new(ResourceExpr::Environment {
                name: "TF_WORKSPACE".into(),
            }),
            resource_type: Some("aws_instance".into()),
            address: Some("aws_instance.web".into()),
            instance: Box::new(ResourceExpr::Unresolved {
                family: ResourceFamily::new("value"),
            }),
        },
    ] {
        let resource = normalize_resource(ResourceExpr::Concrete { identity }, PathPlatform::Posix);
        let json = serde_json::to_value(&resource).unwrap();
        assert!(validator.is_valid(&json), "{json}");
        let domain = effinterp_proto::resource_domain(&resource).unwrap();
        let mut errors = Vec::new();
        effinterp_proto::validate_effect_resource(
            0,
            &effinterp_proto::Operation::new(format!("{domain}.resource.delete")),
            &resource,
            &mut errors,
        );
        assert!(errors.is_empty(), "{errors:?}");
    }
}

#[test]
fn filesystem_narrowing_is_optional_on_the_wire_and_survives_normalization() {
    use effinterp_proto::{FsEntryKind, FsNarrowing, ResourcePattern};
    let pattern = |glob: &str, narrowing: FsNarrowing| ResourceExpr::Pattern {
        pattern: ResourcePattern::FsPath {
            glob: glob.into(),
            narrowing,
        },
    };
    // A selection that leaves nothing out keeps the wire form it always had,
    // and a document written before the field existed still reads.
    let plain = pattern("/w/**", FsNarrowing::default());
    let wire = serde_json::to_value(&plain).unwrap();
    assert_eq!(
        wire,
        serde_json::json!({"expr": "pattern", "pattern": {"family": "fs_path", "glob": "/w/**"}})
    );
    assert_eq!(serde_json::from_value::<ResourceExpr>(wire).unwrap(), plain);

    let narrowing = FsNarrowing {
        kinds: vec![FsEntryKind::Directory],
        excluded_names: vec!["nap.*".into()],
        ..Default::default()
    };
    let narrowed = pattern("/w/./**", narrowing.clone());
    assert_eq!(
        serde_json::from_value::<ResourceExpr>(serde_json::to_value(&narrowed).unwrap()).unwrap(),
        narrowed
    );
    assert_eq!(
        normalize_resource(narrowed, PathPlatform::Posix),
        pattern("/w/**", narrowing.clone())
    );
    assert!(narrowing.admits(FsEntryKind::Directory, "guards"));
    assert!(!narrowing.admits(FsEntryKind::File, "guards"));
    assert!(!narrowing.admits(FsEntryKind::Directory, "nap.d"));

    // A glob's trailing separator selects directories and links to them;
    // normalization drops the separator and keeps what it said.
    assert_eq!(
        normalize_resource(
            pattern("/w/*/", FsNarrowing::default()),
            PathPlatform::Posix
        ),
        pattern(
            "/w/*",
            FsNarrowing {
                kinds: vec![FsEntryKind::Directory, FsEntryKind::Symlink],
                ..Default::default()
            }
        )
    );
}
