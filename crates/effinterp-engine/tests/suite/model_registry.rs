#![allow(clippy::disallowed_methods)]

use effinterp_engine::{Catalog, Engine, RegistryError, compile_registry};
use effinterp_model_schema::canonical_document_json;
use effinterp_model_schema::{
    CandidateDocument, Declaration, DeclarationDocument, EffectSourceDeclaration, OperandSelection,
    document_content_identity,
};
use effinterp_proto::{
    BoundaryClass, BoundaryReason, CoverageLevel, Domain, HostContext, ProvenanceKind,
    ResourceExpr, ResourceIdentity, Subject, validate_plan,
};
use serde_json::{Value, json};

const COMMAND_DECLARATIONS: &str = include_str!("../../models/v1/builtin.json");
const REGISTRY_SOURCE: &str = include_str!("../../src/models/registry.rs");

fn promoted_document_identities() -> Vec<String> {
    fn collect(directory: &std::path::Path, identities: &mut Vec<String>) {
        for entry in std::fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                collect(&path, identities);
            } else if path.extension().and_then(|extension| extension.to_str()) == Some("json") {
                let source = std::fs::read_to_string(&path).unwrap();
                let document: DeclarationDocument = serde_json::from_str(&source).unwrap();
                identities.push(document.identity);
            }
        }
    }

    let mut identities = Vec::new();
    collect(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("models/v1"),
        &mut identities,
    );
    identities.sort();
    identities
}

fn command(id: &str, name: &str, operation: &str) -> Value {
    json!({
        "kind": "command",
        "id": id,
        "commands": [name],
        "effects": [{
            "source": {"kind": "operands", "selection": "all"},
            "emit": [{
                "operation": operation,
                "resource": {"kind": "filesystem", "path": {"kind": "current"}}
            }]
        }]
    })
}

fn document(entries: Vec<Value>) -> String {
    document_with_fragments(entries, json!({}))
}

fn document_with_fragments(entries: Vec<Value>, fragments: Value) -> String {
    let candidate: CandidateDocument = serde_json::from_value(json!({
        "schema": "effinterp/model-candidate/v1",
        "provenance": {
            "author": "human",
            "sources": [{
                "uri": "test:fixture",
                "digest": "blake3:0000000000000000000000000000000000000000000000000000000000000000"
            }]
        },
        "applicability": {
            "platforms": [{"kind": "any"}],
            "versions": [{"target": "test", "requirement": "=1"}]
        },
        "assurance": "fixture_verified",
        "fragments": fragments,
        "evidence": {
            "fixtures": [{"kind": "registry", "name": "test", "expected_entries": ["test"]}],
            "negative_tests": [{
                "name": "negative",
                "subject": {"kind": "exec", "argv": ["true"], "cwd": "."},
                "absent_operations": ["filesystem.delete"]
            }],
            "mutation_tests": [{"name": "mutation", "mutation": "drop_first_effect"}],
            "expected_facts": ["filesystem.read"],
            "expected_boundaries": []
        },
        "entries": entries
    }))
    .unwrap();
    let mut promoted = candidate.promoted(String::new());
    promoted.identity = document_content_identity(&promoted);
    canonical_document_json(&promoted).unwrap()
}

#[test]
fn unsupported_arguments_class_is_required() {
    let mut value: Value = serde_json::from_str(COMMAND_DECLARATIONS).unwrap();
    let unsupported = value["entries"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find_map(|entry| entry.get_mut("unsupported"))
        .unwrap();
    unsupported.as_object_mut().unwrap().remove("class");
    let source = serde_json::to_string(&value).unwrap();
    assert!(matches!(
        compile_registry(&[&source]),
        Err(RegistryError::Json(_))
    ));
    let mut entry = command(
        "test/boundary-class@v1",
        "boundary-class",
        "filesystem.read",
    );
    entry["boundaries"] =
        json!([{"reason":"cluster_api","class":"unmodeled","domains":["network"]}]);
    let mut source: Value = serde_json::from_str(&document(vec![entry])).unwrap();
    source["entries"][0]["boundaries"][0]
        .as_object_mut()
        .unwrap()
        .remove("class");
    assert!(matches!(
        compile_registry(&[&serde_json::to_string(&source).unwrap()]),
        Err(RegistryError::Json(_))
    ));
}

#[test]
fn v1_language_compiles_fragments_modes_subcommands_invocations_and_typed_resources() {
    let unknown_scope =
        effinterp_proto::ResourceScope::<Value>::new(effinterp_proto::NamespaceKind::Unsupported);
    let mut messaging_scope =
        effinterp_proto::ResourceScope::<Value>::new(effinterp_proto::NamespaceKind::RabbitQueue);
    messaging_scope.identity.insert(
        effinterp_proto::ScopeDimension::Namespace,
        effinterp_proto::ScopeValue::value(json!({"kind":"literal","value":"tenant"})),
    );
    messaging_scope.access.push(effinterp_proto::ScopeEvidence {
        kind: effinterp_proto::ScopeEvidenceKind::Endpoint,
        value: json!({"kind":"literal","value":"BROKER:5672"}),
        origin: None,
    });
    let fragment = json!({
        "effects": [{
            "source": {"kind": "argument", "index": 3},
            "emit": [
                {
                    "operation": "filesystem.read",
                    "resource": {
                        "kind": "filesystem",
                        "path": {
                            "kind": "join",
                            "separator": "/",
                            "parts": [
                                {"kind": "literal", "value": "/root"},
                                {"kind": "basename", "value": {"kind": "current"}}
                            ]
                        }
                    }
                },
                {
                    "operation": "process.signal",
                    "resource": {"kind": "process", "executable": {"kind": "current"}}
                },
                {
                    "operation": "network.request",
                    "resource": {"kind": "network", "host": {"kind": "current"}}
                },
                {
                    "operation": "container.remove",
                    "resource": {
                        "kind": "container",
                        "runtime": {"kind": "literal", "value": "docker"},
                        "name": {"kind": "current"}
                    }
                },
                {
                    "operation": "database.write",
                    "resource": {"kind": "database_table", "table": {"kind": "current"}}
                },
                {
                    "operation": "cloud.object.delete",
                    "resource": {"kind": "object_store", "bucket": {"kind": "current"}, "scope": unknown_scope}
                },
                {
                    "operation": "messaging.publish",
                    "resource": {"kind": "messaging", "system": {"kind":"literal","value":"rabbitmq"}, "name": {"kind": "current"}, "scope": messaging_scope}
                },
                {
                    "operation": "environment.read",
                    "resource": {
                        "kind": "environment_variable",
                        "name": {"kind": "literal", "value": "MODEL_VALUE"}
                    }
                },
                {
                    "operation": "git.read",
                    "resource": {
                        "kind": "git_repository",
                        "worktree": {"kind": "cwd"},
                        "pathspec": {"kind": "current"}
                    }
                }
            ]
        }],
        "bindings": [{
            "from": {"kind": "effect", "operation": "filesystem.read"},
            "to": {"kind": "port", "port": "stdout"}
        }]
    });
    let source = document_with_fragments(
        vec![
            json!({
                "kind": "command",
                "id": "test/language@v1",
                "commands": ["model-language"],
                "fragments": ["typed-resources"],
                "flags": [{"names": ["--mode"], "takes_value": false}],
                "invocations": [{
                    "when": {"flag_present": ["--mode"]},
                    "argv": [
                        {"kind": "literal", "value": "nested-delete"},
                        {"kind": "literal", "value": "/nested"}
                    ]
                }],
                "subcommands": [{
                    "names": ["emit"],
                    "index": 0,
                    "positionals": [{"name": "target", "index": 0, "required": true}],
                    "effects": [{
                        "source": {"kind": "positional", "name": "target"},
                        "emit": [{
                            "operation": "filesystem.write",
                            "resource": {"kind": "filesystem", "path": {"kind": "current"}}
                        }]
                    }]
                }],
                "modes": [{
                    "name": "metadata",
                    "when": {"flag_present": ["--mode"]},
                    "effects": [{
                        "source": {"kind": "argument", "index": 3},
                        "emit": [{
                            "operation": "filesystem.metadata",
                            "resource": {"kind": "filesystem", "path": {"kind": "current"}}
                        }]
                    }]
                }]
            }),
            command("test/nested@v1", "nested-delete", "filesystem.delete"),
        ],
        json!({"typed-resources": fragment}),
    );
    let registry = compile_registry(&[&source]).unwrap();
    let engine = Engine::with_catalog(Catalog::from_registry(registry).unwrap());
    let plan = engine
        .analyze(&Subject::Exec {
            argv: vec![
                "model-language".into(),
                "--mode".into(),
                "emit".into(),
                "item".into(),
            ],
            cwd: Some("/work".into()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    let handwritten = analyze(
        [
            "rabbitmqadmin",
            "-H",
            "BROKER",
            "-P",
            "5672",
            "-V",
            "tenant",
            "declare",
            "queue",
            "name=item",
        ]
        .into_iter()
        .map(str::to_string)
        .collect(),
    );
    let declared = plan
        .effects
        .iter()
        .find(|e| e.operation.0 == "messaging.publish")
        .unwrap();
    let modeled = handwritten
        .effects
        .iter()
        .find(|e| e.operation.0 == "messaging.create")
        .unwrap();
    assert_eq!(declared.resource, modeled.resource);

    for operation in [
        "cloud.object.delete",
        "container.remove",
        "database.write",
        "environment.read",
        "filesystem.delete",
        "filesystem.metadata",
        "filesystem.read",
        "filesystem.write",
        "git.read",
        "messaging.publish",
        "network.request",
        "process.signal",
    ] {
        assert!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.0 == operation),
            "missing {operation}"
        );
    }
    assert!(plan.effects.iter().any(|effect| matches!(
        &effect.resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::EnvironmentVariable { .. }
        }
    )));
    assert!(plan.effects.iter().any(|effect| matches!(
        &effect.resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::GitRepository {
                worktree: Some(_),
                pathspec: Some(_),
                ..
            }
        }
    )));
}

fn analyze(argv: Vec<String>) -> effinterp_proto::Plan {
    let plan = Engine::new()
        .analyze(&Subject::Exec {
            argv,
            cwd: Some("/work".to_string()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    plan
}

#[test]
fn structural_fields_are_closed() {
    let mut source: Value = serde_json::from_str(&document(vec![command(
        "test/read@v1",
        "read-one",
        "filesystem.read",
    )]))
    .unwrap();
    source["entries"][0]["surprise"] = json!(true);
    let source = serde_json::to_string(&source).unwrap();
    assert!(matches!(
        compile_registry(&[&source]),
        Err(RegistryError::Json(_))
    ));
}

#[test]
fn declarations_are_sorted_before_digests_and_compilation() {
    let first = document(vec![command("test/a@v1", "a-one", "filesystem.read")]);
    let second = document(vec![command("test/b@v1", "b-one", "filesystem.write")]);
    let forward = compile_registry(&[&first, &second]).unwrap();
    let reverse = compile_registry(&[&second, &first]).unwrap();
    assert_eq!(forward.command_ids(), vec!["test/a@v1", "test/b@v1"]);
    assert_eq!(forward.command_ids(), reverse.command_ids());
    assert_eq!(forward.declaration_digests(), reverse.declaration_digests());
    assert_eq!(forward.model_set_digest(), reverse.model_set_digest());
}

#[test]
fn duplicate_ids_and_command_ownership_are_rejected() {
    let duplicate = document(vec![
        command("test/same@v1", "one", "filesystem.read"),
        command("test/same@v1", "two", "filesystem.read"),
    ]);
    assert!(matches!(
        compile_registry(&[&duplicate]),
        Err(RegistryError::InvalidDeclaration { id, detail })
            if id == "document" && detail.contains("duplicate entry id")
    ));

    let overlap = document(vec![
        command("test/one@v1", "owned", "filesystem.read"),
        command("test/two@v1", "owned", "filesystem.read"),
    ]);
    assert!(matches!(
        compile_registry(&[&overlap]),
        Err(RegistryError::InvalidDeclaration { id, detail })
            if id == "document" && detail.contains("command \"owned\" owned by both")
    ));
}

#[test]
fn invalid_operations_resources_and_flag_grammars_are_rejected() {
    let mut invalid_pattern = command("test/pattern@v1", "pattern-one", "filesystem.read");
    invalid_pattern["effects"][0]["emit"][0]["resource"] = json!({"kind":"pattern","pattern":{"family":"fs_path","glob":{"kind":"literal","value":"/work/[abc"}}});
    assert!(matches!(
        compile_registry(&[&document(vec![invalid_pattern])]),
        Err(RegistryError::InvalidDeclaration { .. })
    ));
    let unregistered = document(vec![command(
        "test/future@v1",
        "future",
        "filesystem.future",
    )]);
    assert!(matches!(
        compile_registry(&[&unregistered]),
        Err(RegistryError::InvalidDeclaration { .. })
    ));
    let mut wrong_cloud = command("test/cloud@v1", "cloud-one", "cloud.object.delete");
    wrong_cloud["effects"][0]["emit"][0]["resource"] = json!({
        "kind": "cloud", "scope": effinterp_proto::ResourceScope::<Value>::new(effinterp_proto::NamespaceKind::Unsupported),
        "service": {"kind": "literal", "value": "compute"},
        "resource_kind": {"kind": "literal", "value": "instance"},
        "id": {"kind": "current"}
    });
    assert!(matches!(
        compile_registry(&[&document(vec![wrong_cloud])]),
        Err(RegistryError::InvalidDeclaration { .. })
    ));

    let mut wrong_kubernetes =
        command("test/kubernetes@v1", "cluster", "container.resource.delete");
    wrong_kubernetes["effects"][0]["emit"][0]["resource"] = json!({
        "kind":"container", "runtime":{"kind":"literal","value":"docker"},
        "name":{"kind":"current"}
    });
    assert!(matches!(
        compile_registry(&[&document(vec![wrong_kubernetes])]),
        Err(RegistryError::InvalidDeclaration { .. })
    ));

    let malformed = document(vec![command(
        "test/malformed@v1",
        "malformed",
        "Filesystem.read",
    )]);
    assert!(matches!(
        compile_registry(&[&malformed]),
        Err(RegistryError::InvalidDeclaration { .. })
    ));

    let wrong_resource = document(vec![command(
        "test/network@v1",
        "network-one",
        "network.request",
    )]);
    assert!(matches!(
        compile_registry(&[&wrong_resource]),
        Err(RegistryError::InvalidDeclaration { .. })
    ));

    for positionals in [
        json!([]),
        json!([{"name": "other", "index": 0, "variadic": true}]),
    ] {
        let mut entry = command("test/stdio@v1", "stdio-one", "filesystem.read");
        entry["positionals"] = positionals;
        entry["effects"][0]["when"] = json!({"positional_may_be_stdio": ["input"]});
        assert!(matches!(
            compile_registry(&[&document(vec![entry])]),
            Err(RegistryError::InvalidDeclaration { .. })
        ));
    }

    for flags in [json!([]), json!([{"names": ["-o"], "takes_value": false}])] {
        let mut entry = command("test/stdio@v1", "stdio-one", "filesystem.read");
        entry["flags"] = flags;
        entry["effects"][0]["when"] = json!({"flag_value_may_be_stdio": ["-o"]});
        assert!(matches!(
            compile_registry(&[&document(vec![entry])]),
            Err(RegistryError::InvalidDeclaration { .. })
        ));
    }

    let mut ambiguous = command("test/flags@v1", "flags-one", "filesystem.read");
    ambiguous["flags"] = json!([{"names": ["-ab"], "takes_value": false}]);
    let ambiguous = document(vec![ambiguous]);
    assert!(matches!(
        compile_registry(&[&ambiguous]),
        Err(RegistryError::InvalidDeclaration { .. })
    ));
}

#[test]
fn invalid_boundary_reason_codes_are_rejected() {
    let mut boundary = command("test/boundary@v1", "boundary", "filesystem.read");
    boundary["boundaries"] = json!([{
        "reason": "invalid-reason",
        "class": "unmodeled",
        "domains": ["filesystem"]
    }]);
    assert!(matches!(
        compile_registry(&[&document(vec![boundary])]),
        Err(RegistryError::InvalidDeclaration { .. })
    ));

    let mut unsupported = command("test/unsupported@v1", "unsupported", "filesystem.read");
    unsupported["unsupported"] = json!({
        "reason": "9invalid",
        "class": "unmodeled",
        "domains": ["filesystem"],
        "unknown_flags": true,
        "extra_operands": true
    });
    assert!(matches!(
        compile_registry(&[&document(vec![unsupported])]),
        Err(RegistryError::InvalidDeclaration { .. })
    ));
}

#[test]
fn inert_behavior_is_exact_and_rejects_conflicting_declarations() {
    let mut inert = command("test/inert@v1", "inert-one", "filesystem.read");
    inert["inert"] = json!(true);
    inert["effects"] = json!([]);
    inert["flags"] = json!([{"names": ["--known"], "takes_value": false}]);
    inert["unsupported"] = json!({
        "reason": "unrecognized_arguments",
        "class": "unmodeled",
        "domains": ["filesystem", "process"],
        "unknown_flags": true,
        "extra_operands": true
    });
    let registry = compile_registry(&[&document(vec![inert.clone()])]).unwrap();
    let engine = Engine::with_catalog(Catalog::from_registry(registry).unwrap());
    let exact = engine
        .analyze(&Subject::Exec {
            argv: vec!["inert-one".into(), "--known".into()],
            cwd: Some("/work".into()),
            context: Default::default(),
        })
        .unwrap();
    assert!(exact.boundaries.is_empty());
    assert_eq!(
        exact
            .coverage
            .0
            .get(&Domain::new("filesystem"))
            .map(|coverage| coverage.level)
            .unwrap_or(CoverageLevel::None),
        CoverageLevel::None
    );
    assert_eq!(
        exact.coverage.0[&Domain::new("process")].level,
        CoverageLevel::Full
    );

    let unsupported = engine
        .analyze(&Subject::Exec {
            argv: vec!["inert-one".into(), "--unknown".into()],
            cwd: Some("/work".into()),
            context: Default::default(),
        })
        .unwrap();
    assert!(
        unsupported
            .boundaries
            .iter()
            .any(|boundary| { boundary.reason == BoundaryReason::UNRECOGNIZED_ARGUMENTS })
    );

    let mut invalid = Vec::new();
    let mut with_effect = inert.clone();
    with_effect["effects"] = command("unused", "unused", "filesystem.read")["effects"].clone();
    invalid.push(with_effect);
    let mut with_invocation = inert.clone();
    with_invocation["invocations"] = json!([{"argv": [{"kind": "literal", "value": "true"}]}]);
    invalid.push(with_invocation);
    let mut with_boundary = inert.clone();
    with_boundary["boundaries"] =
        json!([{"reason": "unmodeled_dynamic", "class": "unmodeled", "domains": ["process"]}]);
    invalid.push(with_boundary);
    for entry in invalid {
        assert!(matches!(
            compile_registry(&[&document(vec![entry])]),
            Err(RegistryError::InvalidDeclaration { .. })
        ));
    }
}

#[test]
fn declarative_boundaries_preserve_class_and_detail() {
    let mut entry = command(
        "test/boundary-metadata@v1",
        "boundary-metadata",
        "filesystem.read",
    );
    entry["boundaries"] = json!([{
        "reason": "input_determined_arguments",
        "class": "unresolved",
        "domains": ["filesystem"],
        "detail": "checked paths are read from the checksum file"
    }]);
    let registry = compile_registry(&[&document(vec![entry])]).unwrap();
    let plan = Engine::with_catalog(Catalog::from_registry(registry).unwrap())
        .analyze(&Subject::Exec {
            argv: vec!["boundary-metadata".into(), "/work/sums".into()],
            cwd: Some("/work".into()),
            context: Default::default(),
        })
        .unwrap();
    let boundary = plan
        .boundaries
        .iter()
        .find(|boundary| boundary.reason.as_str() == "input_determined_arguments")
        .unwrap();
    assert_eq!(boundary.class, BoundaryClass::Unresolved);
    assert_eq!(
        boundary.detail.as_deref(),
        Some("checked paths are read from the checksum file")
    );

    let mut malformed: Value = serde_json::from_str(&document(vec![command(
        "test/empty-detail@v1",
        "empty-detail",
        "filesystem.read",
    )]))
    .unwrap();
    malformed["entries"][0]["boundaries"] = json!([{
        "reason": "input_determined_arguments",
        "class": "unresolved",
        "domains": ["filesystem"],
        "detail": ""
    }]);
    let mut document: DeclarationDocument = serde_json::from_value(malformed).unwrap();
    document.identity = document_content_identity(&document);
    let source = canonical_document_json(&document).unwrap();
    assert!(matches!(
        compile_registry(&[&source]),
        Err(RegistryError::InvalidDeclaration { .. })
    ));
}

#[test]
fn declarative_context_defaults_repository_hosts_and_file_stems_are_precise() {
    let entry = json!({
        "kind": "command",
        "id": "test/context-values@v1",
        "commands": ["context-values"],
        "flags": [{"names": ["--repo"], "takes_value": true}],
        "positionals": [{"name": "source", "index": 0, "required": true}],
        "effects": [{
            "source": {"kind": "positional", "name": "source"},
            "emit": [{
                "operation": "network.request",
                "resource": {
                    "kind": "network",
                    "host": {
                        "kind": "repository_host",
                        "value": {"kind": "flag_value", "flags": ["--repo"]},
                        "default": {
                            "kind": "environment_default",
                            "name": "GH_HOST",
                            "default": "github.com"
                        }
                    }
                }
            }, {
                "operation": "filesystem.write",
                "resource": {
                    "kind": "basename_in_cwd",
                    "value": {"kind": "file_stem", "value": {"kind": "current"}}
                }
            }]
        }],
        "unsupported": {
            "reason": "unrecognized_arguments",
            "class": "unmodeled",
            "domains": ["filesystem", "network", "process"],
            "unknown_flags": true,
            "extra_operands": true
        }
    });
    let registry = compile_registry(&[&document(vec![entry])]).unwrap();
    let engine = Engine::with_catalog(Catalog::from_registry(registry).unwrap());
    let analyze = |argv: Vec<&str>, context: HostContext| {
        engine
            .analyze(&Subject::Exec {
                argv: argv.into_iter().map(str::to_string).collect(),
                cwd: Some("/work".into()),
                context,
            })
            .unwrap()
    };

    let unknown = analyze(
        vec!["context-values", "src/main.rs"],
        HostContext::default(),
    );
    assert!(unknown.effects.iter().any(|effect| {
        effect.operation.0 == "network.request"
            && matches!(
                effect.resource,
                ResourceExpr::Unresolved { ref family } if family.0 == "network"
            )
    }));

    let absent = analyze(
        vec!["context-values", "src/main.rs"],
        HostContext {
            env: std::collections::BTreeMap::from([("PATH".into(), "/bin".into())]),
            ..HostContext::default()
        },
    );
    assert!(
        !absent
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "network.request")
    );
    assert!(
        !absent
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "filesystem.write")
    );

    let context_host = analyze(
        vec!["context-values", "src/main.rs"],
        HostContext {
            env: std::collections::BTreeMap::from([("GH_HOST".into(), "github.example".into())]),
            ..HostContext::default()
        },
    );
    assert!(context_host.effects.iter().any(|effect| matches!(
        &effect.resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::NetworkEndpoint { host, .. }
        } if host == "github.example"
    )));

    let override_host = analyze(
        vec![
            "context-values",
            "--repo",
            "git.example/owner/repo",
            "src/main.rs",
        ],
        HostContext::default(),
    );
    assert!(override_host.effects.iter().any(|effect| matches!(
        &effect.resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::NetworkEndpoint { host, .. }
        } if host == "git.example"
    )));
}

#[test]
fn rejected_root_positionals_preserve_declared_boundary_domains() {
    let mut entry = command(
        "test/literal-reader@v1",
        "literal-reader",
        "filesystem.read",
    );
    entry["positionals"] = json!([{
        "name": "database", "index": 0, "required": true,
        "allowed_literals": ["passwd"]
    }]);
    let registry = compile_registry(&[&document(vec![entry])]).unwrap();
    let engine = Engine::with_catalog(Catalog::from_registry(registry).unwrap());
    for source in [
        "literal-reader",
        "literal-reader hosts",
        "literal-reader \"$DB\"",
    ] {
        let plan = engine
            .analyze(&Subject::Shell {
                source: source.into(),
                cwd: None,
                context: Default::default(),
            })
            .unwrap();
        validate_plan(&plan).unwrap();
        let boundary = plan
            .boundaries
            .iter()
            .find(|boundary| boundary.reason == BoundaryReason::UNRECOGNIZED_ARGUMENTS)
            .unwrap();
        assert_eq!(boundary.class, BoundaryClass::Unmodeled);
        assert_eq!(boundary.domains, vec![Domain::new("filesystem")]);
        for domain in &boundary.domains {
            assert_eq!(
                plan.coverage.0[domain].level,
                CoverageLevel::Partial,
                "{source}"
            );
        }
        assert!(
            plan.effects
                .iter()
                .all(|effect| effect.operation.0 != "filesystem.read")
        );
    }
}

#[test]
fn declarative_flag_value_conditions_match_reviewed_literals() {
    let mut entry = command("test/method@v1", "method", "network.request");
    entry["flags"] = json!([{"names": ["--method"], "takes_value": true}]);
    entry["effects"] = json!([{
        "source": {"kind": "argument", "index": 0},
        "when": {"flag_value_in": [{
            "flags": ["--method"],
            "allowed_literals": ["GET"]
        }]},
        "emit": [{
            "operation": "network.request",
            "resource": {"kind": "unresolved", "family": "network"}
        }]
    }, {
        "source": {"kind": "argument", "index": 0},
        "when": {"flag_value_in": [{
            "flags": ["--method"],
            "allowed_literals": ["POST"]
        }]},
        "emit": [{
            "operation": "network.upload",
            "resource": {"kind": "unresolved", "family": "network"}
        }]
    }]);
    let registry = compile_registry(&[&document(vec![entry.clone()])]).unwrap();
    let engine = Engine::with_catalog(Catalog::from_registry(registry).unwrap());
    for (method, expected, absent) in [
        ("GET", "network.request", "network.upload"),
        ("POST", "network.upload", "network.request"),
    ] {
        let plan = engine
            .analyze(&Subject::Exec {
                argv: vec!["method".into(), "--method".into(), method.into()],
                cwd: Some("/work".into()),
                context: Default::default(),
            })
            .unwrap();
        assert!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.0 == expected)
        );
        assert!(
            plan.effects
                .iter()
                .all(|effect| effect.operation.0 != absent)
        );
    }

    let plan = engine
        .analyze(&Subject::Exec {
            argv: vec!["method".into(), "--method".into(), "HEAD".into()],
            cwd: None,
            context: Default::default(),
        })
        .unwrap();
    assert!(
        plan.boundaries
            .iter()
            .any(|boundary| boundary.reason.as_str() == "unrecognized_arguments")
    );
    assert_ne!(
        plan.coverage.0[&Domain::new("network")].level,
        CoverageLevel::Full
    );

    entry["effects"][0]["when"]["flag_value_in"][0]["allowed_literals"] = json!([]);
    assert!(matches!(
        compile_registry(&[&document(vec![entry])]),
        Err(RegistryError::InvalidDeclaration { .. })
    ));
}

// The hosted request guard depends on both request proof and MustOnSuccess;
// a conflicting method or unknown control must not inherit either fact.
#[test]
fn declarative_exact_delete_request_requires_one_known_method() {
    let mut entry = command("test/delete-request@v1", "method", "network.delete_request");
    entry["flags"] = json!([
        {"names":["--method"],"takes_value":true},
        {"names":["--header"],"takes_value":true}
    ]);
    entry["effects"] = json!([{
        "source":{"kind":"argument","index":0},
        "when":{
            "arguments_literal":true,
            "unknown_flags_present":false,
            "flag_absent":["--header"],
            "flag_occurrence":{"flags":["--method"],"present":true,"max_occurrences":1},
            "flag_value_in":[{"flags":["--method"],"allowed_literals":["DELETE"]}]
        },
        "emit":[{"operation":"network.delete_request",
            "resource":{"kind":"unresolved","family":"network"},
            "request_assurance":"exact",
            "modality":"must-on-success"}]
    }]);
    let registry = compile_registry(&[&document(vec![entry])]).unwrap();
    let engine = Engine::with_catalog(Catalog::from_registry(registry).unwrap());
    let plan = engine
        .analyze(&Subject::Exec {
            argv: vec!["method".into(), "--method".into(), "DELETE".into()],
            cwd: Some("/work".into()),
            context: Default::default(),
        })
        .unwrap();
    let effect = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "network.delete_request")
        .unwrap();
    assert_eq!(
        effect.request_assurance,
        effinterp_proto::RequestAssurance::Exact
    );
    assert_eq!(effect.modality, effinterp_proto::Modality::MustOnSuccess);

    for argv in [
        vec!["method", "--method", "DELETE", "--method", "DELETE"],
        vec!["method", "--method", "POST"],
        vec!["method", "--method", "DELETE", "--header", "X: y"],
    ] {
        let plan = engine
            .analyze(&Subject::Exec {
                argv: argv.into_iter().map(String::from).collect(),
                cwd: Some("/work".into()),
                context: Default::default(),
            })
            .unwrap();
        assert!(
            plan.effects
                .iter()
                .all(|effect| effect.operation.0 != "network.delete_request")
        );
    }
}

#[test]
fn declarative_permission_modes_match_the_gnu_request_grammar() {
    let mut entry = command("test/chmod-mode@v1", "mode", "filesystem.metadata");
    entry["positionals"] = json!([{
        "name":"spec",
        "index":0,
        "dashed_operand":{"allowed_chars":"ugoarwxXst01234567+-=,"}
    }]);
    entry["effects"][0]["when"] = json!({
        "literal_values":[{"source":{"kind":"positional","name":"spec"},
            "shape":{"kind":"permission_mode"},"allow_missing":false,"matches":true}]
    });
    let registry = compile_registry(&[&document(vec![entry])]).unwrap();
    let engine = Engine::with_catalog(Catalog::from_registry(registry).unwrap());
    for (mode, expected) in [
        ("000", true),
        ("755", true),
        ("0000004755", true),
        ("u=rw,go=r", true),
        ("a=,+rwX", true),
        ("u+r-w,g=u", true),
        ("+110", true),
        ("+110,u+w", true),
        ("-6000", true),
        ("=755", true),
        ("-w", true),
        ("", false),
        ("888", false),
        ("10000", false),
        ("u", false),
        ("u+q", false),
        ("u+110", false),
        ("u+r,,g+w", false),
        ("u+ug", false),
        ("755,u+w", false),
        ("u+rw g+r", false),
    ] {
        let plan = engine
            .analyze(&Subject::Exec {
                argv: vec!["mode".into(), mode.into(), "target".into()],
                cwd: Some("/work".into()),
                context: Default::default(),
            })
            .unwrap();
        assert_eq!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.0 == "filesystem.metadata"),
            expected,
            "{mode:?}"
        );
    }
}

// Raw option occurrence must reject disabled sibling flags without treating a
// post-separator target as an option; symbolic arguments cannot certify syntax.
#[test]
fn declarative_literal_and_raw_option_guards_preserve_syntax_uncertainty() {
    let mut entry = command("test/guard@v1", "guard", "filesystem.read");
    entry["flags"] = json!([{"names":["--sibling"],"takes_value":false,"boolean":true}]);
    entry["positionals"] = json!([{"name":"target","index":0}]);
    entry["effects"][0]["source"] = json!({"kind":"argument","index":0});
    entry["effects"][0]["when"] = json!({
        "arguments_literal":true,
        "flag_occurrence":{"flags":["--sibling"],"present":false},
        "literal_values":[{"source":{"kind":"positional","name":"target"},
            "shape":{"kind":"nonempty"},"allow_missing":false,"matches":true}]
    });
    let registry = compile_registry(&[&document(vec![entry.clone()])]).unwrap();
    let engine = Engine::with_catalog(Catalog::from_registry(registry).unwrap());
    for (source, expected) in [
        ("guard value", true),
        ("guard value --sibling=false", false),
        ("guard -- --sibling=false", true),
        ("guard ''", false),
        ("guard", false),
        ("guard \"$TARGET\"", false),
    ] {
        let plan = engine
            .analyze(&Subject::Shell {
                source: source.into(),
                cwd: Some("/work".into()),
                context: Default::default(),
            })
            .unwrap();
        assert_eq!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.0 == "filesystem.read"),
            expected,
            "{source}"
        );
    }
    // Invalid enum values and empty assignment sides must prevent a request
    // from receiving the same evidence as an accepted invocation.
    let mut controls = entry.clone();
    controls["flags"] = json!([
        {"names":["--output"],"takes_value":true},
        {"names":["--override-env"],"takes_value":true}
    ]);
    controls["effects"][0]["when"] = json!({"literal_values":[
        {"source":{"kind":"flag_values","flags":["--output"]},
         "shape":{"kind":"one_of","values":["default","json"]},
         "allow_missing":true,"matches":true},
        {"source":{"kind":"flag_values","flags":["--override-env"]},
         "shape":{"kind":"nonempty_assignment"},"allow_missing":true,"matches":true}
    ]});
    let registry = compile_registry(&[&document(vec![controls])]).unwrap();
    let engine = Engine::with_catalog(Catalog::from_registry(registry).unwrap());
    for (source, expected) in [
        ("guard --output=json --override-env=dev=prod", true),
        ("guard --output=default --override-env=dev=prod=extra", true),
        ("guard --output=invalid", false),
        ("guard --output=invalid --output=json", false),
        ("guard --override-env==prod", false),
        ("guard --override-env=dev=", false),
        ("guard --override-env=dev", false),
        ("guard --output=\"$FORMAT\"", false),
    ] {
        let plan = engine
            .analyze(&Subject::Shell {
                source: source.into(),
                cwd: Some("/work".into()),
                context: Default::default(),
            })
            .unwrap();
        assert_eq!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.0 == "filesystem.read"),
            expected,
            "{source}"
        );
    }
    for invalid in [
        json!({"flag_occurrence":{"flags":[],"present":false}}),
        json!({"flag_occurrence":{"flags":["--undeclared"],"present":false}}),
        json!({"literal_values":[{"source":{"kind":"positional","name":"unknown"},"shape":{"kind":"nonempty"},"allow_missing":true,"matches":true}]}),
        json!({"literal_values":[{"source":{"kind":"flag_values","flags":["--sibling"]},"shape":{"kind":"integer"},"allow_missing":true,"matches":true}]}),
        json!({"literal_values":[{"source":{"kind":"positional","name":"target"},"shape":{"kind":"slash_path","max_components":0},"allow_missing":true,"matches":true}]}),
        json!({"literal_values":[{"source":{"kind":"positional","name":"target"},"shape":{"kind":"go_template_subset","allowed_functions":["bad-name"]},"allow_missing":true,"matches":true}]}),
        json!({"literal_values":[{"source":{"kind":"positional","name":"target"},"shape":{"kind":"go_template_subset","allowed_functions":["print","print"]},"allow_missing":true,"matches":true}]}),
        json!({"flag_value_assignments":[{"flags":[],"values":"query_compatible","matches":true}]}),
        json!({"flag_value_assignments":[{"flags":["--sibling"],"raw_flags":["--sibling"],"values":"query_compatible","matches":true}]}),
        json!({"flag_value_assignments":[{"flags":["--sibling"],"raw_flags":["--undeclared"],"values":"query_compatible","matches":true}]}),
        json!({"flag_value_keys_unique":[{"flags":[],"matches":true}]}),
        json!({"raw_mutually_exclusive":[{"flags":["--sibling"],"matches":true}]}),
    ] {
        entry["effects"][0]["when"] = invalid;
        assert!(matches!(
            compile_registry(&[&document(vec![entry.clone()])]),
            Err(RegistryError::InvalidDeclaration { .. })
        ));
    }

    // A reviewed request route must not certify a duplicated method option;
    // accepting the last value would hide a conflicting request control.
    entry["effects"][0]["when"] = json!({
        "flag_occurrence":{"flags":["--sibling"],"present":true,"max_occurrences":1}
    });
    let registry = compile_registry(&[&document(vec![entry.clone()])]).unwrap();
    let engine = Engine::with_catalog(Catalog::from_registry(registry).unwrap());
    for (source, expected) in [
        ("guard --sibling", true),
        ("guard --sibling --sibling", false),
    ] {
        let plan = engine
            .analyze(&Subject::Shell {
                source: source.into(),
                cwd: Some("/work".into()),
                context: Default::default(),
            })
            .unwrap();
        assert_eq!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.0 == "filesystem.read"),
            expected,
            "{source}"
        );
    }

    entry["flags"] = json!([
        {"names":["--template"],"takes_value":true},
        {"names":["--field"],"takes_value":true},
        {"names":["--raw-field"],"takes_value":true},
        {"names":["--paginate"],"takes_value":false,"boolean":true},
        {"names":["--input"],"takes_value":true}
    ]);
    entry["effects"][0]["when"] = json!({
        "arguments_literal":true,
        "literal_values":[{"source":{"kind":"flag_values","flags":["--template"]},
            "shape":{"kind":"go_template_subset","allowed_functions":["printf"]},"allow_missing":true,"matches":true}],
        "flag_value_assignments":[{"flags":["--field"],"raw_flags":["--raw-field"],"values":"query_compatible","matches":true}],
        "raw_mutually_exclusive":[{"flags":["--paginate","--input"],"matches":true}]
    });
    let registry = compile_registry(&[&document(vec![entry.clone()])]).unwrap();
    let engine = Engine::with_catalog(Catalog::from_registry(registry).unwrap());
    for (source, expected) in [
        ("guard value --template '}}'", true),
        ("guard value --template '{{1_000}}'", true),
        ("guard value --template '{{\"literal\"}}'", true),
        ("guard value --template '{{0x1.fp2}}'", true),
        ("guard value --template '{{range .}}{{break}}{{end}}'", true),
        ("guard value --template '{{printf \"%s\" \"value\"}}'", true),
        ("guard value --template '{{break}}'", false),
        ("guard value --template '{{else}}'", false),
        ("guard value --template '{{. | unknownfunc}}'", false),
        ("guard value --template '{{. |}}'", false),
        ("guard value --template '{{08}}'", false),
        ("guard value --template '{{0x}}'", false),
        ("guard value --template '{{1__2}}'", false),
        ("guard value --template '{{(.)}}'", false),
        ("guard value --template '{{printf (.}}'", false),
        ("guard value --template '{{$missing}}'", false),
        ("guard value --template '{{printf \"%s\" \"\\/\"}}'", false),
        (
            "guard value --template '{{printf \"%s\" \"\\uD800\\uDC00\"}}'",
            false,
        ),
        ("guard value --template \"{{'\n'}}\"", false),
        ("guard value --template '{{18446744073709551616}}'", false),
        ("guard value --template '{{0x1.fp9999999}}'", false),
        ("guard value --template '{{\u{a0}.\u{a0}}}'", false),
        ("guard value --template '{{\u{b}.\u{b}}}'", false),
        ("guard value --field 'a=1' --field 'b=[2]'", true),
        ("guard value --field 'items=[1,true,\"x\"]'", true),
        ("guard value --field 'items=[]'", true),
        ("guard value --field 'item=null'", true),
        ("guard value --raw-field 'data={\"audit\":true}'", true),
        (
            "guard value --field 'data={\"audit\":true}' --field data=ok",
            true,
        ),
        ("guard value --field 'ids[]=null' --field 'ids[]=2'", true),
        ("guard value --field 'data={'", false),
        ("guard value --field 'data={\"audit\":true}'", false),
        ("guard value --field 'items=[null]'", false),
        ("guard value --field 'items=[[1]]'", false),
        ("guard value --field 'items=[{\"id\":1}]'", false),
        (
            "guard value --field data=ok --field 'data={\"audit\":true}'",
            false,
        ),
        ("guard value --field 'ids[]=[1]' --field 'ids[]=2'", false),
        ("guard value --field 'ids=[1]' --raw-field 'ids[]=2'", false),
        (
            "guard value --field 'data={\"audit\":true}' --raw-field data=ok",
            false,
        ),
        ("guard value --paginate=false", true),
        ("guard value --paginate --paginate=false", true),
        ("guard value --paginate=false --input body", false),
    ] {
        let plan = engine
            .analyze(&Subject::Shell {
                source: source.into(),
                cwd: Some("/work".into()),
                context: Default::default(),
            })
            .unwrap();
        assert_eq!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.0 == "filesystem.read"),
            expected,
            "{source}"
        );
    }

    // The same fields carried in a request body instead of the URL: a body
    // renders every value that was read, so only an unreadable one is refused.
    entry["effects"][0]["when"]["flag_value_assignments"] = json!([
        {"flags":["--field"],"raw_flags":["--raw-field"],"values":"json_body_compatible","matches":true}
    ]);
    let registry = compile_registry(&[&document(vec![entry.clone()])]).unwrap();
    let engine = Engine::with_catalog(Catalog::from_registry(registry).unwrap());
    for (source, expected) in [
        ("guard value --field 'data={\"audit\":true}'", true),
        ("guard value --field 'items=[null]'", true),
        ("guard value --field 'items=[[1]]'", true),
        ("guard value --field 'ids=[1]' --raw-field 'ids[]=2'", true),
        ("guard value --field 'data={'", false),
        ("guard value --field nameonly", false),
    ] {
        let plan = engine
            .analyze(&Subject::Shell {
                source: source.into(),
                cwd: Some("/work".into()),
                context: Default::default(),
            })
            .unwrap();
        assert_eq!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.0 == "filesystem.read"),
            expected,
            "{source}"
        );
    }

    // A shape an option carries at most once however often it is repeated.
    entry["effects"][0]["when"] = json!({
        "value_multiplicity":[{"source":{"kind":"flag_values","flags":["--field"]},
            "shape":{"kind":"suffix","value":"=@-"},"max_matching":1,"matches":true}]
    });
    let registry = compile_registry(&[&document(vec![entry])]).unwrap();
    let engine = Engine::with_catalog(Catalog::from_registry(registry).unwrap());
    for (source, expected) in [
        ("guard value", true),
        ("guard value --field 'a=@-'", true),
        ("guard value --field 'a=@-' --field b=plain", true),
        // A symbolic value may or may not be the shape, so it cannot establish
        // that the limit was passed.
        ("guard value --field 'a=@-' --field \"b=$OTHER\"", true),
        ("guard value --field 'a=@-' --field 'b=@-'", false),
    ] {
        let plan = engine
            .analyze(&Subject::Shell {
                source: source.into(),
                cwd: Some("/work".into()),
                context: Default::default(),
            })
            .unwrap();
        assert_eq!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.0 == "filesystem.read"),
            expected,
            "{source}"
        );
    }
}

#[test]
fn non_variadic_surfaces_must_disclose_surplus_operands() {
    let mut bounded = command("test/bounded@v1", "bounded", "filesystem.read");
    bounded["positionals"] = json!([{
        "name": "input",
        "index": 0,
        "variadic": false,
        "required": true
    }]);
    bounded["effects"][0]["source"] = json!({"kind": "positional", "name": "input"});
    bounded["unsupported"] = json!({
        "reason": "unrecognized_arguments",
        "class": "unmodeled",
        "domains": ["filesystem", "process"],
        "unknown_flags": true,
        "extra_operands": false
    });
    let bounded = document(vec![bounded]);
    assert!(matches!(
        compile_registry(&[&bounded]),
        Err(RegistryError::InvalidDeclaration { .. })
    ));
}

#[test]
fn effect_free_evidence_must_expect_a_boundary() {
    let mut declaration: DeclarationDocument = serde_json::from_str(&document(vec![command(
        "test/evidence@v1",
        "evidence",
        "filesystem.read",
    )]))
    .unwrap();
    declaration.evidence.expected_facts.clear();
    declaration.evidence.expected_boundaries.clear();
    declaration.identity = document_content_identity(&declaration);
    let source = canonical_document_json(&declaration).unwrap();
    assert!(matches!(
        compile_registry(&[&source]),
        Err(RegistryError::InvalidDeclaration { .. })
    ));

    declaration
        .evidence
        .expected_boundaries
        .push("unrecognized_arguments".to_string());
    declaration.identity = document_content_identity(&declaration);
    let source = canonical_document_json(&declaration).unwrap();
    assert!(compile_registry(&[&source]).is_ok());
}

#[test]
fn lifecycle_matching_conflicts_are_rejected() {
    let signature = json!({
        "target": {"kind": "method", "name": "run", "receiver_type": "example.Application"},
        "role": "dispatches",
        "evidence": "typed_receiver"
    });
    let source = document(vec![
        json!({
            "kind": "lifecycle",
            "id": "test/first",
            "lang": "python",
            "signatures": [signature.clone()]
        }),
        json!({
            "kind": "lifecycle",
            "id": "test/second",
            "lang": "python",
            "signatures": [signature]
        }),
    ]);
    assert!(matches!(
        compile_registry(&[&source]),
        Err(RegistryError::LifecycleConflict { .. })
    ));
}

#[test]
fn library_api_declarations_are_revisioned_and_structurally_validated() {
    let api = json!({
        "kind": "library_api",
        "id": "test/python-open@v1",
        "lang": "python",
        "symbols": [{
            "target": {"kind": "function", "name": "open"},
            "operation": "filesystem.read"
        }]
    });
    let registry = compile_registry(&[&document(vec![api.clone()])]).unwrap();
    assert!(
        registry
            .declaration_digests()
            .contains_key("test/python-open@v1")
    );
    let plan = Engine::with_catalog(Catalog::from_registry(registry).unwrap())
        .analyze(&Subject::Source {
            dialect: None,
            language: "python".into(),
            source: "open(\"/tmp/f\").read()".into(),
            cwd: None,
            context: Default::default(),
        })
        .unwrap();
    assert_eq!(plan.effects[0].operation.0, "filesystem.read");
    assert!(plan.effects[0].provenance.iter().any(|reference| {
        matches!(
            &plan.provenance[reference.0 as usize].kind,
            ProvenanceKind::ModelApplication { model }
                if model.starts_with("test/python-open@v1#blake3:")
        )
    }));

    let alias = json!({
        "kind": "library_api",
        "id": "test/js-require-read@v1",
        "lang": "js",
        "symbols": [{
            "target": {"kind": "function", "name": "unused.read"},
            "aliases": ["require(\"fs\").readFileSync"],
            "operation": "filesystem.read"
        }]
    });
    let registry = compile_registry(&[&document(vec![alias])]).unwrap();
    let plan = Engine::with_catalog(Catalog::from_registry(registry).unwrap())
        .analyze(&Subject::Source {
            dialect: Some(effinterp_proto::SourceDialect::Js),
            language: "js".into(),
            source: "require(\"fs\").readFileSync(\"/tmp/f\")".into(),
            cwd: None,
            context: Default::default(),
        })
        .unwrap();
    assert!(plan.effects[0].provenance.iter().any(|reference| {
        matches!(
            &plan.provenance[reference.0 as usize].kind,
            ProvenanceKind::ModelApplication { model }
                if model.starts_with("test/js-require-read@v1#blake3:")
        )
    }));

    let mut empty = api;
    empty["symbols"] = json!([]);
    assert!(matches!(
        compile_registry(&[&document(vec![empty])]),
        Err(RegistryError::InvalidDeclaration { .. })
    ));
}

#[test]
fn library_api_attribution_requires_an_exact_code_call() {
    for (language, source, operation) in [
        (
            "go",
            "package main; import \"os\"; func main(){ // os.ReadFile(path)\n os.Open(\"/tmp/a\") }",
            "filesystem.read",
        ),
        (
            "rust",
            "fn main(){ let _ = \"std::fs::read_to_string(x)\"; std::fs::read(\"/tmp/a\"); }",
            "filesystem.read",
        ),
        (
            "python",
            "import shutil\nshutil.copy(\"open(x)\", \"/tmp/b\")",
            "filesystem.read",
        ),
        (
            "python",
            "import subprocess\nf = open(\"/tmp/out\", \"w\")\nsubprocess.run([\"cat\", \"/etc/passwd\"])",
            "filesystem.read",
        ),
        (
            "rust",
            "fn helper(p: &str) -> String { std::fs::read_to_string(p).unwrap() }\nfn main(){ std::process::Command::new(\"cat\").arg(\"/etc/passwd\").status().unwrap(); }",
            "filesystem.read",
        ),
    ] {
        let plan = Engine::new()
            .analyze(&Subject::Source {
                dialect: None,
                language: language.into(),
                source: source.into(),
                cwd: Some("/work".into()),
                context: Default::default(),
            })
            .unwrap();
        assert!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.0 == operation)
        );
        assert!(plan.provenance.iter().all(|node| {
            !matches!(
                &node.kind,
                ProvenanceKind::ModelApplication { model } if model.starts_with("p18b/stdlib/")
            )
        }));
    }
}

#[test]
fn library_api_attribution_uses_language_specific_call_spans() {
    for (language, source, expected) in [
        ("python", "n = 4 // 2\nf = open(\"/etc/hosts\").read()", 1),
        (
            "rust",
            "fn main(){ #[allow(unused)] let _ = std::fs::read_to_string(\"/etc/hosts\"); }",
            1,
        ),
        (
            "rust",
            "fn main(){ let _ = std::fs::read_to_string(\"/etc/hosts\"); let _ = std::fs::read_to_string(\"/etc/passwd\"); }",
            2,
        ),
        (
            "rust",
            "fn pick<'a>(value: &'a str) -> &'a str { value } fn main(){ let _ = std::fs::read_to_string(\"/etc/hosts\"); }",
            1,
        ),
        (
            "python",
            "import shutil\nshutil.copy(open(\"/etc/hosts\").name, \"/tmp/b\")",
            1,
        ),
        (
            "python",
            "import pathlib\nopen(pathlib.Path(\"/etc/passwd\").read_text())",
            1,
        ),
    ] {
        let plan = Engine::new()
            .analyze(&Subject::Source {
                dialect: None,
                language: language.into(),
                source: source.into(),
                cwd: Some("/work".into()),
                context: Default::default(),
            })
            .unwrap();
        let attributed = plan
            .effects
            .iter()
            .filter(|effect| {
                effect.provenance.iter().any(|reference| {
                    matches!(
                        &plan.provenance[reference.0 as usize].kind,
                        ProvenanceKind::ModelApplication { model }
                            if model.starts_with("p18b/stdlib/")
                    )
                })
            })
            .count();
        assert_eq!(attributed, expected, "{language}: {source}");
    }
}

#[test]
fn library_api_attribution_stays_with_its_execution_subject() {
    for source in [
        "open(\"/var/log/app.log\", \"a\").write(\"start\")\nimport subprocess\nsubprocess.run([\"python3\", \"-c\", \"open(\\\"/etc/passwd\\\")\"])",
        "open(\"/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\")\nimport subprocess\nsubprocess.run([\"python3\", \"-c\", \"import pathlib; pathlib.Path(\\\"/etc/shadow\\\").read_text()\"])",
    ] {
        let plan = Engine::new()
            .analyze(&Subject::Source {
                dialect: None,
                language: "python".into(),
                source: source.into(),
                cwd: Some("/work".into()),
                context: Default::default(),
            })
            .unwrap();
        let nested = plan
            .effects
            .iter()
            .find(|effect| effect.execution.0 != 0 && effect.operation.0 == "filesystem.read")
            .unwrap();
        let applications = nested
            .provenance
            .iter()
            .filter(|reference| {
                matches!(
                    &plan.provenance[reference.0 as usize].kind,
                    ProvenanceKind::ModelApplication { model }
                        if model.starts_with("p18b/stdlib/python-filesystem-read@v1#blake3:")
                )
            })
            .count();
        assert!(applications <= 1, "{source}");
        assert_eq!(
            applications,
            usize::from(source.contains("open(\\\"/etc/passwd\\\")"))
        );
    }
}

#[test]
fn library_api_attribution_survives_function_summaries() {
    let plan = Engine::new()
        .analyze(&Subject::Source {
            dialect: None,
            language: "python".into(),
            source: "def read():\n    return open(\"/a/b\")\nread()".into(),
            cwd: Some("/work".into()),
            context: Default::default(),
        })
        .unwrap();
    let read = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.read")
        .unwrap();
    assert!(read.provenance.iter().any(|reference| {
        matches!(
            &plan.provenance[reference.0 as usize].kind,
            ProvenanceKind::ModelApplication { model }
                if model.starts_with("p18b/stdlib/python-filesystem-read@v1#blake3:")
        )
    }));
}

#[test]
fn library_api_aliases_cover_imported_java_calls() {
    let plan = Engine::new()
        .analyze(&Subject::Source { dialect: None,
            language: "java".into(),
            source: "import java.nio.file.Files; import java.nio.file.Path; class App { public static void main(String[] args) throws Exception { Files.readAllBytes(Path.of(\"/tmp/f\")); } }".into(),
            cwd: Some("/work".into()),
            context: Default::default(),
        })
        .unwrap();
    let read = plan
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.read")
        .unwrap();
    assert!(read.provenance.iter().any(|reference| {
        matches!(
            &plan.provenance[reference.0 as usize].kind,
            ProvenanceKind::ModelApplication { model }
                if model.starts_with("p18b/stdlib/java-filesystem-read@v1#blake3:")
        )
    }));
}

#[test]
fn declaration_content_changes_model_and_set_digests() {
    let a = document(vec![command(
        "test/content@v1",
        "content-a",
        "filesystem.read",
    )]);
    let b = document(vec![command(
        "test/content@v1",
        "content-b",
        "filesystem.read",
    )]);
    let a = compile_registry(&[&a]).unwrap();
    let b = compile_registry(&[&b]).unwrap();
    assert_ne!(a.declaration_digests(), b.declaration_digests());
    assert_ne!(a.model_set_digest(), b.model_set_digest());
}

#[test]
fn production_provenance_carries_declaration_id_and_digest() {
    let plan = analyze(vec!["rm".into(), "file".into()]);
    let model = plan
        .provenance
        .iter()
        .find_map(|node| match &node.kind {
            ProvenanceKind::ModelApplication { model } => Some(model),
            _ => None,
        })
        .unwrap();
    let digest = Catalog::builtin()
        .find("rm")
        .unwrap()
        .declaration_digest()
        .unwrap()
        .to_string();
    assert_eq!(model, &format!("coreutils/rm@v1#blake3:{digest}"));
    assert_eq!(digest.len(), 64);
}

#[test]
fn production_registry_uses_only_bundled_declarations() {
    assert_eq!(
        Catalog::builtin().document_identities(),
        promoted_document_identities()
    );
    for runtime_lookup in ["std::fs", "std::env", "current_dir", "std::net"] {
        assert!(
            !REGISTRY_SOURCE.contains(runtime_lookup),
            "registry source contains runtime lookup {runtime_lookup}"
        );
    }
}

#[test]
fn declaration_generated_operand_flag_and_unsupported_cases_conform() {
    let document: DeclarationDocument = serde_json::from_str(COMMAND_DECLARATIONS).unwrap();
    for entry in document.entries {
        let Declaration::Command(command) = entry else {
            continue;
        };
        for executable in &command.commands {
            for flag in &command.behavior.flags {
                for name in &flag.names {
                    let mut argv = vec![executable.clone(), name.clone()];
                    if flag.takes_value {
                        argv.push("flag-value".into());
                    }
                    if command.id == "coreutils/chmod@v1"
                        && !flag.names.iter().any(|name| name == "--reference")
                    {
                        argv.push("0644".into());
                    }
                    argv.extend(["operand-a".into(), "operand-b".into(), "destination".into()]);
                    let plan = analyze(argv);
                    assert!(
                        !plan.boundaries.iter().any(|boundary| {
                            boundary.reason == BoundaryReason::UNRECOGNIZED_ARGUMENTS
                        }),
                        "{} ({executable}) rejected declared flag {name}",
                        command.id
                    );
                    let inert = command
                        .modes
                        .iter()
                        .any(|mode| mode.behavior.inert && mode.when.flag_present.contains(name));
                    assert!(
                        inert
                            || plan
                                .effects
                                .iter()
                                .any(|effect| effect.operation.0 != "process.exec"),
                        "{} ({executable}) accepted declared flag {name} without a semantic effect or inert mode",
                        command.id
                    );
                }
            }

            for (rule_index, rule) in command.behavior.effects.iter().enumerate() {
                let mut argv = vec![executable.clone()];
                // A literal condition on a flag's value supplies a value of its shape.
                for condition in &rule.when.literal_values {
                    let EffectSourceDeclaration::FlagValues { flags } = &condition.source else {
                        continue;
                    };
                    let shape = serde_json::to_value(&condition.shape).unwrap();
                    if shape["kind"] == "permission_mode" && condition.matches {
                        let mode = match shape["grant"].as_str() {
                            Some("world_write") => "0777",
                            Some("setuid") => "4755",
                            Some("setgid") => "2755",
                            _ => "0644",
                        };
                        argv.extend([flags[0].clone(), mode.into()]);
                    }
                }
                let mut add_flag = |name: &str| {
                    if argv.iter().any(|argument| argument == name) {
                        return;
                    }
                    argv.push(name.to_string());
                    if command.behavior.flags.iter().any(|flag| {
                        flag.takes_value && flag.names.iter().any(|known| known == name)
                    }) {
                        argv.push("flag-value".into());
                    }
                };
                if let Some(name) = rule.when.flag_present.first() {
                    add_flag(name);
                }
                if let Some(name) = rule.when.flag_value_present.first() {
                    add_flag(name);
                }
                if let EffectSourceDeclaration::FlagValues { flags }
                | EffectSourceDeclaration::FlagRequirementPaths { flags, .. } = &rule.source
                {
                    add_flag(&flags[0]);
                }
                for emission in &rule.emit {
                    for attribute in emission.attributes.values() {
                        let declaration = serde_json::to_value(attribute).unwrap();
                        if declaration["kind"] == "flag_present" {
                            add_flag(declaration["flags"][0].as_str().unwrap());
                        }
                    }
                }
                let base_operands = match rule.source {
                    EffectSourceDeclaration::FlagValues { .. }
                    | EffectSourceDeclaration::FlagFileFields { .. }
                    | EffectSourceDeclaration::FlagRequirementPaths { .. } => 1,
                    EffectSourceDeclaration::Operands {
                        selection: OperandSelection::All,
                    } => 1,
                    EffectSourceDeclaration::Operands {
                        selection: OperandSelection::AllButLast | OperandSelection::LastIfMultiple,
                    } => 2,
                    EffectSourceDeclaration::Operands {
                        selection: OperandSelection::Single,
                    } => 1,
                    EffectSourceDeclaration::Positional { .. }
                    | EffectSourceDeclaration::Argument { .. } => 1,
                };
                let operand_count = base_operands.max(rule.when.min_operands.unwrap_or(0));
                let positional_consumed = command.behavior.positionals.iter().any(|positional| {
                    !positional
                        .unless_value_flags
                        .iter()
                        .any(|name| argv.iter().any(|argument| argument == name))
                });
                let captured = if positional_consumed {
                    let captured = rule
                        .when
                        .literal_values
                        .iter()
                        .find_map(|condition| {
                            let shape = serde_json::to_value(&condition.shape).unwrap();
                            match shape["kind"].as_str() {
                                Some("permission_mode") => match shape["grant"].as_str() {
                                    Some("world_write") => Some("0777"),
                                    Some("setuid") => Some("4755"),
                                    Some("setgid") => Some("2755"),
                                    _ => Some("0644"),
                                },
                                // chmod's unknown-mode rule: an empty mode.
                                Some("nonempty") if !condition.matches => Some(""),
                                _ => None,
                            }
                        })
                        .unwrap_or("captured-value");
                    argv.push(captured.into());
                    captured
                } else {
                    "captured-value"
                };
                argv.extend((0..operand_count).map(|index| format!("operand-{index}")));
                let plan = analyze(argv);
                for emission in &rule.emit {
                    let expected_attributes = emission
                        .attributes
                        .iter()
                        .map(|(name, declaration)| {
                            let declaration = serde_json::to_value(declaration).unwrap();
                            let value = match declaration["kind"].as_str().unwrap() {
                                // The invoked command's own name, as chgrp and
                                // chown state their action.
                                "value"
                                    if declaration["value"]
                                        == json!({"kind": "basename", "value": {"kind": "argument", "index": 0}}) =>
                                {
                                    json!(executable)
                                }
                                "value" => json!(captured),
                                "constant_bool" => declaration["value"].clone(),
                                "constant_int" | "constant_string" => declaration["value"].clone(),
                                "flag_absent" | "flag_present" => json!(true),
                                kind => panic!("unexpected attribute kind {kind}"),
                            };
                            (name.clone(), value)
                        })
                        .collect::<serde_json::Map<_, _>>();
                    assert!(
                        plan.effects.iter().any(|effect| {
                            effect.operation.0 == emission.operation
                                && serde_json::to_value(&effect.attributes).unwrap()
                                    == Value::Object(expected_attributes.clone())
                        }),
                        "{} ({executable}) rule {rule_index} did not emit {} with its declared attributes",
                        command.id,
                        emission.operation
                    );
                }
            }

            if command.behavior.unsupported.is_some() {
                let plan = analyze(vec![
                    executable.clone(),
                    "--definitely-unsupported".into(),
                    "operand-a".into(),
                    "operand-b".into(),
                ]);
                assert!(
                    plan.boundaries.iter().any(|boundary| {
                        boundary.reason == BoundaryReason::UNRECOGNIZED_ARGUMENTS
                    })
                );
            }
        }
    }
}

#[test]
fn declared_short_boolean_equals_belongs_to_the_final_cluster_flag() {
    let mut entry = command("test/short-bool@v1", "bool-command", "filesystem.read");
    entry["flags"] = json!([
        {"names":["-i"],"takes_value":false,"boolean":true},
        {"names":["-y"],"takes_value":false,"boolean":true}
    ]);
    entry["effects"][0]["when"] = json!({"unknown_flags_present":false});
    entry["effects"][0]["emit"][0]["attributes"] = json!({
        "include":{"kind":"flag_enabled","flags":["-i"]},
        "yes":{"kind":"flag_enabled","flags":["-y"]}
    });
    entry["unsupported"] = json!({
        "reason":"unrecognized_arguments",
        "class":"unmodeled",
        "domains":["filesystem"],
        "unknown_flags":true,
        "extra_operands":false
    });
    let registry = compile_registry(&[&document(vec![entry])]).unwrap();
    let engine = Engine::with_catalog(Catalog::from_registry(registry).unwrap());
    for (flag, expected) in [
        ("-iy=false", json!({"include":true,"yes":false})),
        ("-yi=false", json!({"include":false,"yes":true})),
    ] {
        let plan = engine
            .analyze(&Subject::Exec {
                argv: vec!["bool-command".into(), flag.into(), "value".into()],
                cwd: Some("/work".into()),
                context: Default::default(),
            })
            .unwrap();
        let effect = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.read")
            .unwrap_or_else(|| panic!("missing effect for {flag}"));
        assert_eq!(serde_json::to_value(&effect.attributes).unwrap(), expected);
    }

    for flag in ["-iy=maybe", "-ixy=false"] {
        let plan = engine
            .analyze(&Subject::Exec {
                argv: vec!["bool-command".into(), flag.into(), "value".into()],
                cwd: Some("/work".into()),
                context: Default::default(),
            })
            .unwrap();
        assert!(
            !plan
                .effects
                .iter()
                .any(|effect| effect.operation.0 == "filesystem.read"),
            "{flag}"
        );
    }
}

#[test]
fn long_flags_never_alias_declared_short_flags() {
    for (argv, expected) in [
        (vec!["rm", "--force", "file"], json!({"force": true})),
        (
            vec!["rm", "--recursive", "file"],
            json!({"recursive": true}),
        ),
        (vec!["rm", "--interactive", "file"], json!({})),
        (vec!["rm", "--verbose", "file"], json!({})),
        (vec!["rm", "--preserve-root", "file"], json!({})),
        (vec!["rm", "--one-file-system", "file"], json!({})),
        (vec!["mkdir", "--parents", "dir"], json!({"parents": true})),
        (vec!["mkdir", "--preserve", "dir"], json!({})),
    ] {
        let argv_unknown_rm = argv[0] == "rm" && !matches!(argv[1], "--force" | "--recursive");
        let plan = analyze(argv.into_iter().map(str::to_string).collect());
        let effect = plan
            .effects
            .iter()
            .find(|effect| effect.operation.domain() == "filesystem");
        if argv_unknown_rm {
            assert!(effect.is_none());
            assert!(
                plan.boundaries
                    .iter()
                    .any(|boundary| boundary.reason == BoundaryReason::UNRECOGNIZED_ARGUMENTS)
            );
            continue;
        }
        let attributes = &effect.expect("modeled filesystem operation").attributes;
        assert_eq!(serde_json::to_value(attributes).unwrap(), expected);
    }
}

#[test]
fn reference_flag_rejects_a_conflicting_dashed_mode() {
    let plan = analyze(
        ["chmod", "--reference=ref", "-w", "f"]
            .into_iter()
            .map(str::to_string)
            .collect(),
    );
    assert!(plan.boundaries.iter().any(|boundary| {
        boundary.reason == BoundaryReason::UNRECOGNIZED_ARGUMENTS
            && boundary
                .detail
                .as_deref()
                .is_some_and(|detail| detail.contains("cannot combine"))
    }));
    assert!(
        !plan
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "filesystem.metadata"
                && effect.request_assurance == effinterp_proto::RequestAssurance::Exact)
    );
}

fn v2_engine(entries: Vec<Value>) -> Engine {
    let registry = compile_registry(&[
        &document(entries),
        COMMAND_DECLARATIONS,
        include_str!("../../models/v1/apis/python.json"),
    ])
    .unwrap();
    Engine::with_catalog(Catalog::from_registry(registry).unwrap())
}

fn v2_analyze(engine: &Engine, source: &str, context: HostContext) -> effinterp_proto::Plan {
    let plan = engine
        .analyze(&Subject::Shell {
            source: source.into(),
            cwd: Some("/work".into()),
            context,
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    plan
}

#[test]
fn v2_language_selectors_preserve_values_and_environment_provenance() {
    let mut entry = command("test/selectors@v1", "selector", "filesystem.write");
    entry["effects"][0]["emit"][0]["resource"] =
        json!({"kind":"filesystem","path":{"kind":"stem","value":{"kind":"current"}}});
    let engine = v2_engine(vec![entry]);
    for (input, expected) in [
        ("src/main.rs", "main"),
        (".bashrc", ".bashrc"),
        ("a.tar.gz", "a.tar"),
    ] {
        let plan = v2_analyze(
            &engine,
            &format!("selector {input}"),
            HostContext::default(),
        );
        assert!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.as_str() == "filesystem.write"
                    && effect.resource
                        == ResourceExpr::Concrete {
                            identity: ResourceIdentity::FsPath {
                                path: format!("/work/{expected}")
                            }
                        })
        );
    }
    for (component, expected) in [
        ("host", "github.com"),
        ("owner", "o"),
        ("name", "n"),
        ("path", "/o/n.git"),
    ] {
        let mut entry = command("test/url@v1", "selector", "process.signal");
        entry["effects"][0]["emit"][0]["resource"] = json!({"kind":"value","value":{"kind":"url_component","component":component,"value":{"kind":"current"}}});
        let engine = v2_engine(vec![entry]);
        for input in [
            "https://github.com/o/n.git",
            "git@github.com:o/n.git",
            "github.com/o/n.git",
            "o/n.git",
        ] {
            let plan = v2_analyze(
                &engine,
                &format!("selector {input}"),
                HostContext::default(),
            );
            let effect = plan
                .effects
                .iter()
                .find(|effect| effect.operation.as_str() == "process.signal")
                .unwrap();
            if component == "host" && input == "o/n.git" {
                assert!(matches!(effect.resource, ResourceExpr::Unresolved { .. }));
            } else {
                assert_eq!(
                    effect.resource,
                    ResourceExpr::Literal {
                        value: expected.into()
                    }
                );
            }
        }
    }
    let mut entry = command("test/env@v1", "selector", "process.signal");
    entry["effects"][0]["source"] = json!({"kind":"argument","index":0});
    entry["effects"][0]["emit"][0]["resource"] = json!({"kind":"value","value":{"kind":"env_or_default","name":"GH_HOST","default":"github.com"}});
    let engine = v2_engine(vec![entry]);
    let mut context = HostContext::default();
    context.env.insert("GH_HOST".into(), "ghe.corp".into());
    let plan = v2_analyze(&engine, "selector", context);
    let effect = plan
        .effects
        .iter()
        .find(|effect| effect.operation.as_str() == "process.signal")
        .unwrap();
    assert_eq!(
        effect.resource,
        ResourceExpr::Literal {
            value: "ghe.corp".into()
        }
    );
    assert!(effect.provenance.iter().any(|reference| matches!(
        plan.provenance[reference.0 as usize].kind,
        ProvenanceKind::HostContext { .. }
    )));
    let plan = v2_analyze(&engine, "selector", HostContext::default());
    assert!(plan.effects.iter().any(|effect| effect.resource
        == ResourceExpr::Union {
            alternatives: vec![
                ResourceExpr::Environment {
                    name: "GH_HOST".into()
                },
                ResourceExpr::Literal {
                    value: "github.com".into()
                }
            ]
        }));

    let mut entry = command("test/config-path@v1", "config-path", "filesystem.read");
    entry["effects"][0]["source"] = json!({"kind":"argument","index":0});
    entry["effects"][0]["emit"][0]["resource"] = json!({
        "kind": "union",
        "alternatives": [
            {
                "kind": "in_directory",
                "directory": {"kind": "environment", "name": "CONFIG_DIR"},
                "entry": {"kind": "literal", "value": "config.yml"}
            },
            {
                "kind": "in_directory",
                "directory": {"kind": "environment", "name": "HOME"},
                "entry": {"kind": "literal", "value": ".config/tool/config.yml"}
            }
        ]
    });
    let engine = v2_engine(vec![entry]);
    let plan = v2_analyze(
        &engine,
        "config-path",
        HostContext {
            env: std::collections::BTreeMap::from([("HOME".into(), "/home/test".into())]),
            ..HostContext::default()
        },
    );
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.as_str() == "filesystem.read"
            && effect.resource
                == ResourceExpr::Join {
                    parts: vec![
                        ResourceExpr::Environment {
                            name: "HOME".into(),
                        },
                        ResourceExpr::Concrete {
                            identity: ResourceIdentity::FsPath {
                                path: "/.config/tool/config.yml".into(),
                            },
                        },
                    ],
                }
    }));

    for (kind, dimension, mut resource, operation) in [
        (
            effinterp_proto::NamespaceKind::AzureBlob,
            effinterp_proto::ScopeDimension::StorageAccount,
            json!({"kind":"object_store","provider":{"kind":"literal","value":"azure"},"bucket":{"kind":"literal","value":"objects"}}),
            "cloud.object.read",
        ),
        (
            effinterp_proto::NamespaceKind::GceZonal,
            effinterp_proto::ScopeDimension::Project,
            json!({"kind":"cloud","provider":{"kind":"literal","value":"gcp"},"service":{"kind":"literal","value":"compute"},"resource_kind":{"kind":"literal","value":"instance"},"id":{"kind":"literal","value":"web"}}),
            "cloud.resource.delete",
        ),
        (
            effinterp_proto::NamespaceKind::RabbitQueue,
            effinterp_proto::ScopeDimension::Namespace,
            json!({"kind":"messaging","system":{"kind":"literal","value":"rabbitmq"},"name":{"kind":"literal","value":"orders"}}),
            "messaging.consume",
        ),
    ] {
        let mut scope = effinterp_proto::ResourceScope::<Value>::new(kind);
        scope.identity.insert(
            dimension,
            effinterp_proto::ScopeValue::value(
                json!({"kind":"env_or_default","name":"TARGET_SCOPE","default":"candidate"}),
            ),
        );
        scope.access.push(effinterp_proto::ScopeEvidence {
            kind: effinterp_proto::ScopeEvidenceKind::Endpoint,
            value: json!({"kind":"env_or_default","name":"TARGET_ENDPOINT","default":"candidate:5672"}),
            origin: None,
        });
        resource["scope"] = serde_json::to_value(scope).unwrap();
        let mut entry = command("test/scoped-env@v2", "selector", operation);
        entry["effects"][0]["source"] = json!({"kind":"argument","index":0});
        entry["effects"][0]["emit"][0]["resource"] = resource;
        let engine = v2_engine(vec![entry]);
        for supplied in [true, false] {
            let mut context = HostContext::default();
            if supplied {
                context.env.insert("TARGET_SCOPE".into(), "tenant".into());
                context
                    .env
                    .insert("TARGET_ENDPOINT".into(), "broker:5672".into());
            }
            let plan = v2_analyze(&engine, "selector", context);
            let effect = plan
                .effects
                .iter()
                .find(|effect| effect.operation.as_str() == operation)
                .unwrap();
            let ResourceExpr::Concrete { identity } = &effect.resource else {
                panic!("scoped identity was lost: {:?}", effect.resource);
            };
            let scope = identity.scope().unwrap();
            let effinterp_proto::ScopeValue::Value(value) = &scope.identity[&dimension] else {
                panic!("scope expression was lost");
            };
            if supplied {
                assert_eq!(
                    value.as_ref(),
                    &ResourceExpr::Literal {
                        value: "tenant".into()
                    }
                );
                assert_eq!(
                    scope.access[0].value,
                    ResourceExpr::Concrete {
                        identity: ResourceIdentity::NetworkEndpoint {
                            host: "broker".into(),
                            scheme: None,
                            port: Some(5672),
                            path: None,
                        }
                    }
                );
                for name in ["TARGET_SCOPE", "TARGET_ENDPOINT"] {
                    assert!(effect.provenance.iter().any(|reference| matches!(
                        &plan.provenance[reference.0 as usize].kind,
                        ProvenanceKind::HostContext { name: actual } if actual == name
                    )));
                }
            } else {
                for expr in [value.as_ref(), &scope.access[0].value] {
                    let ResourceExpr::Union { alternatives } = expr else {
                        panic!("absent environment lost its alternatives: {expr:?}");
                    };
                    assert!(
                        alternatives
                            .iter()
                            .any(|value| matches!(value, ResourceExpr::Environment { .. }))
                    );
                    assert!(alternatives.iter().any(|value| matches!(
                        value,
                        ResourceExpr::Literal { .. } | ResourceExpr::Concrete { .. }
                    )));
                }
            }
        }
    }
}

#[test]
fn unknown_flags_do_not_invalidate_reviewed_selector_values() {
    let entry = json!({
        "kind": "command",
        "id": "test/selector-boundary@v1",
        "commands": ["selector-boundary"],
        "flags": [
            {"names": ["--method", "-X"], "takes_value": true},
            {"names": ["--paginate"], "takes_value": false}
        ],
        "positionals": [{"name": "endpoint", "index": 0, "required": true}],
        "effects": [{
            "source": {"kind": "positional", "name": "endpoint"},
            "when": {
                "flag_absent": ["--paginate"],
                "flag_value_in": [{"flags": ["--method", "-X"], "allowed_literals": ["GET"]}]
            },
            "emit": [{
                "operation": "network.request",
                "resource": {"kind": "network", "host": {"kind": "literal", "value": "example.com"}}
            }]
        }],
        "unsupported": {
            "reason": "unrecognized_arguments",
            "class": "unmodeled",
            "domains": ["network"],
            "unknown_flags": true,
            "extra_operands": true
        }
    });
    let engine = v2_engine(vec![entry]);
    let plan = v2_analyze(
        &engine,
        "selector-boundary --unknown -X GET endpoint",
        HostContext::default(),
    );
    assert!(
        plan.boundaries.iter().any(|boundary| {
            boundary.detail.as_deref() == Some("unrecognized flags: --unknown")
        })
    );
    assert!(!plan.boundaries.iter().any(|boundary| {
        boundary
            .detail
            .as_deref()
            .is_some_and(|detail| detail.starts_with("unreviewed flag value"))
    }));

    let plan = v2_analyze(
        &engine,
        "selector-boundary --paginate -X GET endpoint",
        HostContext::default(),
    );
    assert!(!plan.boundaries.iter().any(|boundary| {
        boundary
            .detail
            .as_deref()
            .is_some_and(|detail| detail.starts_with("unreviewed flag value"))
    }));
}

#[test]
fn v2_language_verb_trees_conditions_and_shared_tail() {
    let leaf = json!({"names":["c"],"index":0,"flags":[{"names":["-n"],"takes_value":true}],"positionals":[{"name":"path","index":0,"required":true}],"effects":[{"source":{"kind":"positional","name":"path"},"emit":[{"operation":"filesystem.delete","resource":{"kind":"filesystem","path":{"kind":"current"}}}]}]});
    let entry = json!({"kind":"command","id":"test/tree@v1","commands":["tool"],"single_dash_long_flags":true,"flags":[{"names":["-auto-approve"],"takes_value":false}],"boundaries":[{"when":{"subcommand_matched":false},"reason":"unmodeled_subcommand","class":"unmodeled","domains":["process"]}],"subcommands":[{"names":["a"],"index":0,"subcommands":[{"names":["b"],"index":0,"subcommands":[leaf]}]}]});
    let engine = v2_engine(vec![entry]);
    for source in [
        "tool a b c x",
        "tool -n prod a b c x",
        "tool -auto-approve a b c x",
    ] {
        let plan = v2_analyze(&engine, source, HostContext::default());
        assert!(
            plan.boundaries.is_empty(),
            "{source}: {:?}",
            plan.boundaries
        );
        assert!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.as_str() == "filesystem.delete")
        );
    }
    let plan = v2_analyze(&engine, "tool zzz", HostContext::default());
    assert!(
        plan.boundaries
            .iter()
            .any(|boundary| boundary.reason.as_str() == "unmodeled_subcommand")
    );

    let mut entry = command("test/action@v1", "action", "filesystem.delete");
    entry["flags"] = json!([{"names":["--action","-X"],"takes_value":true}]);
    entry["effects"][0]["when"] =
        json!({"flag_value_equals":[{"flags":["--action","-X"],"value":"destroy"}]});
    entry["boundaries"] = json!([
        {"when":{"flag_value_symbolic":["--action"]},"reason":"input_determined_arguments","class":"unresolved","domains":["filesystem"]},
        {"when":{"unknown_flags_present":true},"reason":"cluster_api","class":"unsupported","domains":["network","container"],"detail":"unknown cluster flags"}
    ]);
    let engine = v2_engine(vec![entry]);
    for (source, deletes) in [
        ("action --action destroy x", true),
        ("action -X destroy --action read x", false),
        ("action --action '$ACTION' x", false),
    ] {
        let plan = v2_analyze(&engine, source, HostContext::default());
        assert_eq!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.as_str() == "filesystem.delete"),
            deletes
        );
    }
    let plan = v2_analyze(&engine, "action --action $ACTION x", HostContext::default());
    assert!(
        plan.boundaries
            .iter()
            .any(|boundary| boundary.class == BoundaryClass::Unresolved
                && boundary.reason.as_str() == "input_determined_arguments")
    );
    let plan = v2_analyze(&engine, "action --bogus x", HostContext::default());
    assert!(
        plan.boundaries
            .iter()
            .any(|boundary| boundary.class == BoundaryClass::Unsupported
                && boundary.domains == vec![Domain::new("network"), Domain::new("container")]
                && boundary.detail.as_deref() == Some("unknown cluster flags"))
    );

    let entry = json!({"kind":"command","id":"test/mode-tail@v1","commands":["launcher"],"unsupported":{"reason":"unrecognized_arguments","class":"unmodeled","domains":["process"],"unknown_flags":true,"extra_operands":false},"modes":[{"name":"child","when":{"unknown_flags_present":false},"positionals":[{"name":"command","index":0,"variadic":true}],"invocations":[{"argv":[],"argv_tail":"command"}]}]});
    let engine = v2_engine(vec![entry]);
    let plan = v2_analyze(&engine, "launcher rm -f x", HostContext::default());
    assert!(plan.boundaries.is_empty());
    assert!(
        plan.effects
            .iter()
            .any(|effect| effect.operation.as_str() == "filesystem.delete")
    );

    let plan = analyze(vec![
        "pipx".into(),
        "run".into(),
        "black".into(),
        "--check".into(),
        ".".into(),
    ]);
    assert!(
        !plan
            .boundaries
            .iter()
            .any(|boundary| boundary.reason == BoundaryReason::UNRECOGNIZED_ARGUMENTS)
    );
}

#[test]
fn v2_language_nested_source_realm_and_cwd() {
    struct Resolver;
    impl effinterp_engine::SourceResolver for Resolver {
        fn source_mutation_disjoint(
            &self,
            _: &effinterp_proto::ResourceExpr,
            _: effinterp_engine::SourceRequest<'_>,
        ) -> bool {
            true
        }

        fn siblings(&self, _: &str) -> Option<Vec<String>> {
            None
        }
        fn resolve(
            &self,
            _: effinterp_engine::SourceRequest<'_>,
        ) -> effinterp_engine::SourceResponse {
            effinterp_engine::SourceResponse::Source(b"import os\nos.remove('victim')".to_vec())
        }
    }
    let mut source = json!({"kind":"command","id":"test/source@v1","commands":["source-tool"],"flags":[{"names":["-e"],"takes_value":true}],"positionals":[{"name":"script","index":0}],"nested_source":[{"language":"python","from":{"kind":"flag_values","flags":["-e"]}},{"language":"python","from":{"kind":"positional","name":"script"}},{"language":"python","from":{"kind":"stdin"}}]});
    source["effects"] = json!([{"source":{"kind":"positional","name":"script"},"emit":[{"operation":"process.code_execution","resource":{"kind":"process","executable":{"kind":"literal","value":"python"}},"attributes":{"source":{"kind":"constant_string","value":"file"}}}]}]);
    let realm = json!({"kind":"command","id":"test/realm@v1","commands":["realm-tool"],"positionals":[{"name":"pod","index":0,"required":true},{"name":"command","index":1,"required":true,"variadic":true}],"invocations":[{"argv":[],"argv_tail":"command","realm":{"kind":"kubernetes","namespace":{"kind":"literal","value":"prod"},"pod":{"kind":"positional","name":"pod"}}}]});
    let cwd = json!({"kind":"command","id":"test/cwd@v1","commands":["cwd-tool"],"positionals":[{"name":"cwd","index":0,"required":true},{"name":"command","index":1,"variadic":true,"required":true}],"invocations":[{"argv":[],"argv_tail":"command","cwd":{"kind":"positional","name":"cwd"}}]});
    let engine = v2_engine(vec![source, realm, cwd]).with_resolver(Box::new(Resolver));
    for source in [
        "source-tool -e 'import os; os.remove(\"victim\")'",
        "source-tool script.py",
        "source-tool <<'PY'\nimport os; os.remove(\"victim\")\nPY",
    ] {
        let plan = v2_analyze(&engine, source, HostContext::default());
        assert!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.as_str() == "filesystem.delete"),
            "{source}: {:?}",
            plan.boundaries
        );
        if source == "source-tool script.py" {
            assert!(
                plan.effects
                    .iter()
                    .any(|effect| effect.operation.as_str() == "process.code_execution")
            );
            assert!(
                !plan
                    .boundaries
                    .iter()
                    .any(|boundary| boundary.reason.as_str() == "dynamic_source")
            );
            assert!(
                plan.effects
                    .iter()
                    .any(|effect| effect.operation.as_str() == "filesystem.read")
            );
        }
    }
    let plan = v2_analyze(&engine, "source-tool -e $CODE", HostContext::default());
    assert!(
        plan.boundaries
            .iter()
            .any(|boundary| boundary.reason.as_str() == "dynamic_source"
                && boundary.class == BoundaryClass::Unresolved)
    );
    for (source, pod) in [
        ("realm-tool web rm victim", "web"),
        ("realm-tool $POD rm victim", "$POD"),
    ] {
        let plan = v2_analyze(&engine, source, HostContext::default());
        assert!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.as_str() == "filesystem.delete"
                    && effect.realm
                        == effinterp_proto::ExecutionRealm::Kubernetes {
                            namespace: Some("prod".into()),
                            pod: pod.into(),
                            container: None
                        })
        );
    }
    let plan = v2_analyze(&engine, "cwd-tool subdir rm victim", HostContext::default());
    assert!(
        plan.effects
            .iter()
            .any(|effect| effect.operation.as_str() == "filesystem.delete"
                && effect.resource
                    == ResourceExpr::Concrete {
                        identity: ResourceIdentity::FsPath {
                            path: "/work/subdir/victim".into()
                        }
                    })
    );
}

#[test]
fn v2_language_rejects_invalid_boundaries_selectors_and_nesting() {
    let base = command("test/invalid@v1", "tool", "filesystem.read");
    let mut invalid = Vec::new();
    for (reason, class, domains, detail) in [
        ("cluster_api", "limit", vec!["network"], None),
        ("cluster_api", "parse_failure", vec!["network"], None),
        ("dynamic_source", "unmodeled", vec!["process"], None),
        (
            "dynamic_source",
            "unresolved",
            vec!["process"],
            Some("detail"),
        ),
        ("cluster_api", "unmodeled", vec!["filesystm"], None),
        ("cluster_api", "unmodeled", vec!["network"], Some("")),
    ] {
        let mut entry = base.clone();
        entry["boundaries"] =
            json!([{"reason":reason,"class":class,"domains":domains,"detail":detail}]);
        invalid.push(entry);
    }
    let mut entry = base.clone();
    entry["nested_source"] = json!([{"language":"unknown","from":{"kind":"stdin"}}]);
    invalid.push(entry);
    let mut entry = base.clone();
    entry["effects"][0]["emit"][0]["resource"]["path"] =
        json!({"kind":"env_or_default","name":"GH_HOST","default":""});
    invalid.push(entry);
    let mut entry = base.clone();
    entry["invocations"] = json!([{"argv":[{"kind":"literal","value":"true"}],"realm":{"kind":"kubernetes","pod":{"kind":"positional","name":"missing"}}}]);
    invalid.push(entry);
    let mut entry = base.clone();
    entry["subcommands"] = json!([{"names":["a"],"index":0,"boundaries":[{"when":{"subcommand_matched":false},"reason":"cluster_api","class":"unmodeled","domains":["network"]}]}]);
    invalid.push(entry);
    let mut entry = base.clone();
    entry["subcommands"] = json!([{"names":["a"],"index":0,"subcommands":[{"names":["b"],"index":0,"subcommands":[{"names":["c"],"index":0,"subcommands":[{"names":["d"],"index":0}]}]}]}]);
    invalid.push(entry);
    let mut tail = json!({"kind":"command","id":"test/tail@v1","commands":["tool"],"positionals":[{"name":"command","index":0,"variadic":true}],"invocations":[{"argv":[],"argv_tail":"command","when":{"tail_has_options":{"present":false,"except":[{"head":"rm","allowed_chars":"rRf"}]}}}]});
    assert!(compile_registry(&[&document(vec![tail.clone()])]).is_ok());
    tail["invocations"][0]["when"]["tail_has_options"]["except"][0]["allowed_chars"] = json!("");
    invalid.push(tail.clone());
    tail["invocations"][0]["when"]["tail_has_options"]["except"][0]["allowed_chars"] = json!("rRf");
    let mut multiple = tail.clone();
    multiple["invocations"]
        .as_array_mut()
        .unwrap()
        .push(tail["invocations"][0].clone());
    invalid.push(multiple);
    tail["invocations"][0]
        .as_object_mut()
        .unwrap()
        .remove("argv_tail");
    tail["invocations"][0]["argv"] = json!([{"kind":"literal","value":"true"}]);
    invalid.push(tail);
    let mut entry = base.clone();
    entry["effects"][0]["include_suffixes"] = json!([""]);
    invalid.push(entry);
    let mut entry = base.clone();
    entry["effects"][0]["emit"][0]["resource"] = json!({"kind":"filesystem","path":{"kind":"before_delimiter","value":{"kind":"current"},"delimiter":""}});
    invalid.push(entry);
    let mut entry = base.clone();
    entry["effects"][0]["when"] = json!({"flag_all_present":["--undeclared"]});
    invalid.push(entry);
    let mut entry = base.clone();
    entry["positionals"] = json!([{"name":"args","index":0,"variadic":true}]);
    entry["invocations"] = json!([{"argv":[],"argv_tail":"args","prefix_assignments":true,"cwd":{"kind":"literal","value":"/elsewhere"}}]);
    invalid.push(entry);
    let mut entry = base;
    entry["flags"] = json!([{"names":["-f"],"takes_value":false}]);
    entry["effects"][0]["when"] = json!({"flag_value_equals":[{"flags":["-f"],"value":"destroy"}]});
    invalid.push(entry);
    for entry in invalid {
        assert!(
            matches!(
                compile_registry(&[&document(vec![entry.clone()])]),
                Err(RegistryError::InvalidDeclaration { .. })
            ),
            "{entry}"
        );
    }
}

#[test]
fn documents_extend_builtin_effects_and_catalog_identity_without_overrides() {
    let source = document(vec![command(
        "test/zzz-tool@v1",
        "zzz-tool",
        "filesystem.read",
    )]);
    let subject = Subject::Exec {
        argv: vec!["zzz-tool".into(), "/work/input".into()],
        cwd: Some("/work".into()),
        context: Default::default(),
    };
    let first = Engine::with_documents(&[&source], effinterp_engine::default_limits())
        .unwrap()
        .analyze(&subject)
        .unwrap();
    let second = Engine::with_documents(&[&source], effinterp_engine::default_limits())
        .unwrap()
        .analyze(&subject)
        .unwrap();
    assert!(
        first
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "filesystem.read")
    );
    assert!(first.boundaries.is_empty());
    assert_eq!(first.analysis.model_set, second.analysis.model_set);
    assert_ne!(
        first.analysis.model_set,
        Engine::new().analyze(&subject).unwrap().analysis.model_set
    );
    let registry = effinterp_engine::compile_registry_with_builtin(&[&source]).unwrap();
    assert_eq!(
        registry.document_identities().len(),
        promoted_document_identities().len() + 1
    );
    for name in ["rm", "docker"] {
        let source = document(vec![command("test/conflict@v1", name, "filesystem.read")]);
        assert!(matches!(
            Engine::with_documents(&[&source], effinterp_engine::default_limits()),
            Err(effinterp_engine::EngineError::InvalidModels(detail))
                if detail.contains(name) && detail.contains("test/conflict@v1")
        ));
    }
    assert!(matches!(
        effinterp_engine::compile_registry_with_builtin(&[&source, &source]),
        Err(RegistryError::DuplicateId(_))
    ));
}

#[test]
fn semantic_values_preserve_nested_typed_patterns() {
    use effinterp_proto::{Field, ResourceExpr, ResourcePattern, TextField};
    let resource = ResourceExpr::Pattern {
        pattern: ResourcePattern::Process {
            executable: TextField::Glob { glob: "py*".into() },
            argv_prefix: vec![ResourceExpr::Pattern {
                pattern: ResourcePattern::NetworkEndpoint {
                    host_glob: "*.example".into(),
                    scheme: Field::Exact {
                        value: "https".into(),
                    },
                    port: effinterp_proto::PortField::Exact { value: 8443 },
                    path_prefix: Some("/api".into()),
                },
            }],
        },
    };
    let value = effinterp_engine::SemanticValue::from(resource.clone());
    assert_eq!(value.lower_resource(), resource);
}

#[test]
fn artifact_declarations_compile_deterministically_and_reject_incompatible_shapes() {
    let mut entry = command(
        "test/artifact-delete@v1",
        "artifact-fixture-delete",
        "artifact.delete",
    );
    entry["effects"][0]["emit"][0]["resource"] = json!({
        "kind":"artifact", "ecosystem":"github-release",
        "endpoint":{"kind":"literal","value":"github.com"},
        "name":{"kind":"literal","value":"acme/api"},
        "reference":{"kind":"tag","value":{"kind":"current"}}
    });
    let source = document(vec![entry.clone()]);
    let first = compile_registry(&[&source]).unwrap();
    let second = compile_registry(&[&source]).unwrap();
    assert_eq!(first.model_set_digest(), second.model_set_digest());
    let engine = Engine::with_catalog(Catalog::from_registry(first).unwrap());
    let subject = Subject::Exec {
        argv: vec!["artifact-fixture-delete".into(), "v2".into()],
        cwd: None,
        context: Default::default(),
    };
    let plan = engine.analyze(&subject).unwrap();
    validate_plan(&plan).unwrap();
    assert_eq!(
        effinterp_proto::canonical_json(&plan),
        effinterp_proto::canonical_json(&engine.analyze(&subject).unwrap())
    );
    assert!(
        plan.effects
            .iter()
            .any(|e| e.operation.as_str() == "artifact.delete"
                && matches!(
                    &e.resource,
                    ResourceExpr::Concrete {
                        identity: ResourceIdentity::Artifact { .. }
                    }
                ))
    );
    let mut cwd = entry.clone();
    cwd["effects"][0]["emit"][0]["resource"]["endpoint"] = json!({"kind":"cwd"});
    assert!(compile_registry(&[&document(vec![cwd])]).is_err());
    let mut deep = entry.clone();
    let mut value = json!({"kind":"current"});
    for _ in 0..40 {
        value = json!({"kind":"property","base":value,"name":"tag"});
    }
    deep["effects"][0]["emit"][0]["resource"]["reference"]["value"] = value;
    assert!(compile_registry(&[&document(vec![deep])]).is_err());
    entry["effects"][0]["emit"][0]["operation"] = json!("filesystem.delete");
    assert!(compile_registry(&[&document(vec![entry])]).is_err());
}

#[test]
fn stdout_value_bindings_require_resource_producers() {
    let mut entry = command("test/captured@v1", "captured", "filesystem.create");
    entry["bindings"] = json!([{
        "stdout_value": true,
        "from": {"kind": "effect", "operation": "filesystem.create"},
        "to": {"kind": "port", "port": "stdout"}
    }]);
    let source = document(vec![entry.clone()]);
    let registry = compile_registry(&[&source]).unwrap();
    let catalog = Catalog::from_registry(registry).unwrap();
    let bindings = catalog
        .find("captured")
        .unwrap()
        .stdout_value_bindings(&[effinterp_engine::Word::literal("captured")]);
    assert_eq!(bindings.len(), 1);
    for (end, replacement) in [
        ("from", json!({"kind":"port", "port":"stdin"})),
        ("to", json!({"kind":"port", "port":"stderr"})),
    ] {
        let mut invalid = entry.clone();
        invalid["bindings"][0][end] = replacement;
        assert!(matches!(
            compile_registry(&[&document(vec![invalid])]),
            Err(RegistryError::InvalidDeclaration { .. })
        ));
    }
}

#[test]
fn component_lifecycle_requires_one_paired_dispatch() {
    let target = json!({"kind":"function", "name":"Fire", "import_path":"fire"});
    let register = json!({"target": target, "role":"registers", "evidence":"exact_import", "component":0, "params":["component"]});
    let dispatch = json!({"target": target, "role":"dispatches", "evidence":"exact_import"});
    let entry = |signatures: Vec<Value>| json!({"kind":"lifecycle", "id":"test/component", "lang":"python", "signatures":signatures});
    assert!(
        compile_registry(&[&document(vec![entry(vec![
            register.clone(),
            dispatch.clone()
        ])])])
        .is_ok()
    );
    for signatures in [
        vec![register.clone()],
        vec![register, dispatch.clone(), dispatch],
    ] {
        assert!(matches!(
            compile_registry(&[&document(vec![entry(signatures)])]),
            Err(RegistryError::InvalidDeclaration { .. })
        ));
    }
}

#[test]
fn repeatable_go_options_keep_every_value() {
    // A Go flag parser keeps the last value of a string option the model
    // reads, but every value of an array option.
    let writes = |repeatable: bool| {
        let source = document(vec![json!({
            "kind": "command",
            "id": "test/go-tool@v1",
            "commands": ["go-tool"],
            "flags": [
                {"names": ["--quiet"], "takes_value": false, "boolean": true},
                {"names": ["--path"], "takes_value": true, "repeatable": repeatable}
            ],
            "effects": [{
                "source": {"kind": "flag_values", "flags": ["--path"]},
                "when": {"literal_values": [{
                    "source": {"kind": "flag_values", "flags": ["--path"]},
                    "shape": {"kind": "one_of", "values": ["/ok"]},
                    "allow_missing": false,
                    "matches": true
                }]},
                "emit": [{
                    "operation": "filesystem.write",
                    "resource": {"kind": "filesystem", "path": {"kind": "current"}},
                    "attributes": {"path": {"kind": "value", "value": {"kind": "flag_value", "flags": ["--path"]}}}
                }]
            }]
        })]);
        let registry = compile_registry(&[&source]).unwrap();
        let engine = Engine::with_catalog(Catalog::from_registry(registry).unwrap());
        let plan = engine
            .analyze(&Subject::Exec {
                argv: ["go-tool", "--path", "/bad", "--path", "/ok"]
                    .map(String::from)
                    .to_vec(),
                cwd: Some("/work".into()),
                context: Default::default(),
            })
            .unwrap();
        validate_plan(&plan).unwrap();
        plan.effects
            .iter()
            .filter(|effect| effect.operation.0 == "filesystem.write")
            .count()
    };
    assert_ne!(writes(false), 0);
    assert_eq!(writes(true), 0);
}
