// The fixture loader reads frozen documents from disk; the crate itself stays pure.
#![allow(clippy::disallowed_methods)]

use std::fs;
use std::path::PathBuf;

use effinterp_proto::{
    CoverageLevel, DOMAINS, Domain, Operation, Plan, ResourceExpr, ResourceFamily,
    ResourceIdentity, ValidationError, canonical_json, from_plan_json, validate_effect_resource,
    validate_plan,
};

fn fixture_paths() -> Vec<PathBuf> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures");
    let mut paths: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|path| path.is_file())
        .collect();
    paths.sort();
    assert!(!paths.is_empty());
    paths
}

fn load(name: &str) -> Plan {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join(name);
    from_plan_json(&fs::read_to_string(path).unwrap()).unwrap()
}

fn plan_with_target(operation: &str, resource: ResourceExpr) -> Plan {
    let mut plan = load("exec-rm-recursive.json");
    let domain = operation.split_once('.').unwrap().0;
    plan.coverage.0.insert(
        Domain::new(domain),
        effinterp_proto::CoverageClaim {
            level: CoverageLevel::Full,
            gaps: Vec::new(),
        },
    );
    plan.effects[1].operation = Operation::new(operation);
    plan.effects[1].resource = resource;
    plan.stamp_effect_ids().unwrap();
    plan
}

fn effect_resource_errors(operation: &str, resource: ResourceExpr) -> Vec<ValidationError> {
    let mut errors = Vec::new();
    validate_effect_resource(0, &Operation::new(operation), &resource, &mut errors);
    errors
}

/// Every fixture is stored in canonical form: parse -> validate -> serialize
/// must reproduce the file byte for byte.
#[test]
fn fixtures_roundtrip_canonically() {
    for path in fixture_paths() {
        let text = fs::read_to_string(&path).unwrap();
        let plan = from_plan_json(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        validate_plan(&plan).unwrap_or_else(|e| panic!("{}: {e:?}", path.display()));
        assert_eq!(
            canonical_json(&plan),
            text,
            "{} is not canonical",
            path.display()
        );
    }
}

#[test]
fn serialization_is_deterministic() {
    for path in fixture_paths() {
        let plan = from_plan_json(&fs::read_to_string(&path).unwrap()).unwrap();
        let a = canonical_json(&plan);
        let b = canonical_json(&from_plan_json(&a).unwrap());
        assert_eq!(a, b);
    }
}

#[test]
fn execution_stdin_reference_and_value_are_mutually_exclusive() {
    use effinterp_proto::{
        ExecutionStream, ExecutionStreamRef, ExecutionStreamValue, ResourceExpr,
    };

    let mut plan = load("exec-rm-recursive.json");
    plan.execution_graph.nodes[0].streams.stdin = Some(ExecutionStreamRef {
        node: plan.execution_graph.entry,
        stream: ExecutionStream::Stdin,
    });
    plan.execution_graph.nodes[0].streams.stdin_value = Some(ExecutionStreamValue {
        value: ResourceExpr::Literal {
            value: "input".to_string(),
        },
        provenance: Vec::new(),
    });
    let errors = validate_plan(&plan).unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| matches!(error, ValidationError::ConflictingStdinSources { node: 0 }))
    );
}

#[test]
fn subjects_roundtrip_host_context() {
    use std::collections::BTreeMap;

    use effinterp_proto::{HostContext, SourceDialect, Subject};

    let context = HostContext {
        env: BTreeMap::from([
            ("HOME".to_string(), "/home/test".to_string()),
            ("TOKEN".to_string(), "value".to_string()),
        ]),
        ..Default::default()
    };
    let subjects = [
        Subject::Exec {
            argv: vec!["true".to_string()],
            cwd: None,
            context: context.clone(),
        },
        Subject::Shell {
            source: "true".to_string(),
            cwd: None,
            context: context.clone(),
        },
        Subject::Source {
            dialect: None,
            language: "python".into(),
            source: "pass".to_string(),
            cwd: None,
            context: context.clone(),
        },
        Subject::Source {
            dialect: Some(SourceDialect::Ipython),
            language: "python".into(),
            source: "!true".to_string(),
            cwd: None,
            context: context.clone(),
        },
        Subject::Source {
            language: "js".into(),
            source: "void 0".to_string(),
            dialect: Some(SourceDialect::Js),
            cwd: None,
            context: context.clone(),
        },
        Subject::Source {
            dialect: None,
            language: "ruby".to_string(),
            source: "nil".to_string(),
            cwd: None,
            context,
        },
    ];

    for subject in subjects {
        let json = serde_json::to_string(&subject).unwrap();
        assert_eq!(serde_json::from_str::<Subject>(&json).unwrap(), subject);
    }
}

#[test]
fn tool_call_subjects_have_a_closed_typed_wire_shape() {
    use effinterp_proto::{FileReadArgs, HostContext, LineRange, Subject, ToolCall};

    let subject = Subject::ToolCall {
        call: ToolCall::FileRead(FileReadArgs {
            path: "src/lib.rs".to_string(),
            range: Some(LineRange {
                start_line: 3,
                end_line: Some(8),
            }),
        }),
        cwd: Some("/work".to_string()),
        context: HostContext::default(),
    };
    let value = serde_json::to_value(&subject).unwrap();
    assert_eq!(
        value,
        serde_json::json!({
            "kind": "tool_call",
            "tool": "file.read",
            "args": {
                "path": "src/lib.rs",
                "range": { "start_line": 3, "end_line": 8 }
            },
            "cwd": "/work"
        })
    );
    assert_eq!(serde_json::from_value::<Subject>(value).unwrap(), subject);

    for invalid in [
        serde_json::json!({"kind":"tool_call","tool":"file.read","args":{"path":""}}),
        serde_json::json!({"kind":"tool_call","tool":"file.read","args":{"path":"x","range":{"start_line":0}}}),
        serde_json::json!({"kind":"tool_call","tool":"file.read","args":{"path":"x","extra":true}}),
        serde_json::json!({"kind":"tool_call","tool":"file.edit","args":{"path":"x","old":"a","new":"b","count":0}}),
        serde_json::json!({"kind":"tool_call","tool":"fs.grep","args":{"pattern":"x","paths":[]}}),
        serde_json::json!({"kind":"tool_call","tool":"runtime.read","args":{"path":"x"}}),
        serde_json::json!({"kind":"tool_call","tool":"file.write","args":{"path":"x"}}),
        serde_json::json!({"kind":"tool_call","tool":"file.delete","args":{"path":""}}),
        serde_json::json!({"kind":"tool_call","tool":"file.delete","args":{"path":"x","recursive":true}}),
    ] {
        assert!(serde_json::from_value::<Subject>(invalid).is_err());
    }
}

#[test]
fn unknown_tool_args_remain_opaque_and_subject_validation_is_semantic() {
    use effinterp_proto::{
        FileEditArgs, Subject, ToolCall, UnknownToolArgs, ValidationError, canonical_hash,
    };

    let unknown: Subject = serde_json::from_value(serde_json::json!({
        "kind": "tool_call",
        "tool": "tool.unknown",
        "args": {"name":"RuntimeTool","args":{"nested":[1,true,null]}},
    }))
    .unwrap();
    assert!(matches!(
        &unknown,
        Subject::ToolCall {
            call: ToolCall::Unknown(UnknownToolArgs { name, args }),
            ..
        } if name == "RuntimeTool" && args["nested"][1] == true
    ));
    assert_eq!(canonical_hash(&unknown), canonical_hash(&unknown.clone()));

    let mut plan = load("exec-rm-recursive.json");
    plan.subject = Subject::ToolCall {
        call: ToolCall::FileEdit(FileEditArgs {
            path: "x".to_string(),
            old: "a".to_string(),
            new: "b".to_string(),
            count: Some(0),
        }),
        cwd: None,
        context: Default::default(),
    };
    assert!(
        validate_plan(&plan)
            .unwrap_err()
            .iter()
            .any(|error| matches!(error, ValidationError::InvalidSubject { .. }))
    );
}

#[test]
fn native_batch_edit_and_find_validate_their_complete_fields() {
    use effinterp_proto::{Subject, ToolCall, TransferDirection};

    let batch: Subject = serde_json::from_value(serde_json::json!({
        "kind": "tool_call",
        "tool": "file.edit_batch",
        "args": {
            "path": "/work/file",
            "edits": [
                {"old":"one","new":"ONE"},
                {"old":"two","new":"TWO"}
            ]
        }
    }))
    .unwrap();
    assert!(
        matches!(batch, Subject::ToolCall { call: ToolCall::FileEditBatch(args), .. }
        if args.path == "/work/file" && args.edits.len() == 2)
    );

    let find: Subject = serde_json::from_value(serde_json::json!({
        "kind": "tool_call",
        "tool": "fs.find",
        "args": {"pattern":"*.rs","root":"/work/src","limit":10}
    }))
    .unwrap();
    assert!(
        matches!(find, Subject::ToolCall { call: ToolCall::FsFind(args), .. }
        if args.pattern == "*.rs" && args.root == "/work/src" && args.limit == Some(10))
    );

    for invalid in [
        serde_json::json!({
            "kind":"tool_call", "tool":"file.edit_batch",
            "args":{"path":"/work/file","edits":[]}
        }),
        serde_json::json!({
            "kind":"tool_call", "tool":"fs.find",
            "args":{"pattern":"*.rs","root":"/work","limit":0}
        }),
        serde_json::json!({
            "kind":"tool_call", "tool":"fs.find",
            "args":{"pattern":"*.rs","root":""}
        }),
        serde_json::json!({
            "kind":"tool_call", "tool":"file.transfer",
            "args":{"path":"/work/file","direction":"upload","remote":"https://example.invalid"}
        }),
        serde_json::json!({
            "kind":"tool_call", "tool":"mcp.call",
            "args":{"server":{"kind":"unknown"},"tool":"","arguments":{}}
        }),
        serde_json::json!({
            "kind":"tool_call", "tool":"mcp.call",
            "args":{"server":{"kind":"known","transport":{"kind":"http","host":"mcp.example","path":"mcp"}},"tool":"query","arguments":{}}
        }),
        serde_json::json!({
            "kind":"tool_call", "tool":"mcp.call",
            "args":{"server":{"kind":"known","transport":{"kind":"stdio","source":{"kind":"npm","spec":""}}},"tool":"query","arguments":{}}
        }),
    ] {
        assert!(serde_json::from_value::<Subject>(invalid).is_err());
    }

    let transfer: Subject = serde_json::from_value(serde_json::json!({
        "kind": "tool_call",
        "tool": "file.transfer",
        "args": {"path":"/work/file","direction":"download"}
    }))
    .unwrap();
    assert!(matches!(
        transfer,
        Subject::ToolCall { call: ToolCall::FileTransfer(args), .. }
            if args.path == "/work/file" && args.direction == TransferDirection::Download
    ));
}

#[test]
fn tool_argument_provenance_serializes_by_name() {
    use effinterp_proto::ProvenanceKind;

    assert_eq!(
        serde_json::to_value(ProvenanceKind::ToolArgument {
            name: "paths[2]".to_string(),
        })
        .unwrap(),
        serde_json::json!({"kind":"tool_argument","name":"paths[2]"})
    );
}

#[test]
fn boundary_reason_codes_match_the_protocol_pattern() {
    use effinterp_proto::BoundaryReason;

    assert!(BoundaryReason::is_valid_code("archive_7z_failed"));
    assert!(BoundaryReason::NO_ENTRY_POINT.is_valid());
    let encoded = serde_json::to_string(&BoundaryReason::NO_ENTRY_POINT).unwrap();
    assert_eq!(encoded, "\"no_entry_point\"");
    assert_eq!(
        serde_json::from_str::<BoundaryReason>(&encoded).unwrap(),
        BoundaryReason::NO_ENTRY_POINT
    );
    assert!(!BoundaryReason::is_valid_code("7z_failed"));
    assert!(!BoundaryReason::is_valid_code("1"));
}

#[test]
fn validate_effect_resource_reports_each_failure_class() {
    let errors = effect_resource_errors(
        "network.request",
        ResourceExpr::Concrete {
            identity: ResourceIdentity::NetworkEndpoint {
                host: String::new(),
                scheme: None,
                port: None,
                path: None,
            },
        },
    );
    assert!(matches!(
        errors.as_slice(),
        [ValidationError::EmptyResourceIdentity { effect: 0 }]
    ));

    let errors = effect_resource_errors(
        "filesystem.read",
        ResourceExpr::Concrete {
            identity: ResourceIdentity::EnvironmentVariable { name: "X".into() },
        },
    );
    assert!(errors.iter().any(|error| matches!(
        error,
        ValidationError::IncompatibleResourceFamily {
            effect: 0,
            identity: "environment-variable",
            ..
        }
    )));

    let errors = effect_resource_errors(
        "network.request",
        ResourceExpr::Unresolved {
            family: ResourceFamily::new("filesystem"),
        },
    );
    assert!(errors.iter().any(|error| matches!(
        error,
        ValidationError::IncompatibleResourceFamily {
            effect: 0,
            identity: "unresolved",
            ..
        }
    )));

    let errors = effect_resource_errors(
        "filesystem.delete",
        ResourceExpr::Join {
            parts: vec![
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::EnvironmentVariable { name: "A".into() },
                },
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath {
                        path: "cache".into(),
                    },
                },
            ],
        },
    );
    assert!(errors.iter().any(|error| matches!(
        error,
        ValidationError::IncompatibleResourceFamily {
            effect: 0,
            identity: "join",
            ..
        }
    )));

    let errors = effect_resource_errors(
        "git.read",
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath {
                path: "/srv/repo".into(),
            },
        },
    );
    assert!(errors.iter().any(|error| matches!(
        error,
        ValidationError::IncompatibleResourceFamily {
            effect: 0,
            identity: "filesystem-path",
            ..
        }
    )));

    let errors =
        effect_resource_errors("filesystem.read", ResourceExpr::Join { parts: Vec::new() });
    assert!(
        errors
            .iter()
            .any(|error| matches!(error, ValidationError::EmptyResourceParts { effect: 0 }))
    );

    let errors = effect_resource_errors(
        "filesystem.read",
        ResourceExpr::Pattern {
            pattern: effinterp_proto::ResourcePattern::FsPath {
                glob: String::new(),
            },
        },
    );
    assert!(
        errors
            .iter()
            .any(|error| matches!(error, ValidationError::EmptyPattern { effect: 0 }))
    );

    for resource in [
        ResourceExpr::Pattern {
            pattern: effinterp_proto::ResourcePattern::FsPath {
                glob: "bad**glob".into(),
            },
        },
        ResourceExpr::Join {
            parts: vec![
                ResourceExpr::Parameter { name: "cwd".into() },
                ResourceExpr::Pattern {
                    pattern: effinterp_proto::ResourcePattern::FsPath { glob: "[".into() },
                },
            ],
        },
    ] {
        assert!(
            effect_resource_errors("filesystem.read", resource)
                .iter()
                .any(|error| matches!(error, ValidationError::InvalidPattern { .. }))
        );
    }

    assert!(
        effect_resource_errors(
            "filesystem.read",
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path: "/x".into() },
            },
        )
        .is_empty()
    );
}

#[test]
fn unresolved_domain_family_is_root_compatible_for_every_domain() {
    for domain in DOMAINS {
        assert!(
            effect_resource_errors(
                &format!("{domain}.read"),
                ResourceExpr::Unresolved {
                    family: ResourceFamily::new(domain),
                },
            )
            .is_empty()
        );
    }
}

#[test]
fn boundary_class_is_required() {
    let plan = load("symbolic-widened.json");
    let mut value = serde_json::to_value(plan).unwrap();
    value["boundaries"][0]
        .as_object_mut()
        .unwrap()
        .remove("class");
    assert!(serde_json::from_value::<Plan>(value).is_err());
}

#[test]
fn symbolic_fixture_retains_protocol_examples() {
    use effinterp_proto::{Modality, ResourceExpr};

    let plan = load("symbolic-widened.json");
    assert!(matches!(
        plan.effects[0].resource,
        ResourceExpr::Join { .. }
    ));
    assert!(plan.effects[0].condition.is_some());
    assert!(matches!(
        plan.effects[1].resource,
        ResourceExpr::Pattern { .. }
    ));
    assert_eq!(plan.effects[1].modality, Modality::MustOnSuccess);
    assert!(matches!(
        plan.effects[2].resource,
        ResourceExpr::Union { .. }
    ));
    assert!(matches!(
        plan.effects[3].resource,
        ResourceExpr::Unresolved { .. }
    ));
}

#[test]
fn rejects_wrong_schema() {
    let mut plan = load("exec-rm-recursive.json");
    plan.schema = "effinterp/plan/v0".into();
    let errors = validate_plan(&plan).unwrap_err();
    assert!(matches!(errors[0], ValidationError::WrongSchema { .. }));
}

#[test]
fn rejects_boundary_contradicting_full_coverage() {
    use effinterp_proto::{Boundary, BoundaryClass, BoundaryReason, Domain};
    let mut plan = load("exec-rm-recursive.json");
    // filesystem coverage is Full in this fixture; a boundary claiming
    // filesystem opacity contradicts that.
    plan.boundaries.push(Boundary {
        reason: BoundaryReason::UNMODELED_COMMAND,
        class: BoundaryClass::Unmodeled,
        scope: effinterp_proto::BoundaryScope::Invocation,
        domains: vec![Domain::new("filesystem")],
        affected_resource: None,
        callee: None,
        provenance: Vec::new(),
        limit: None,
        detail: None,
    });
    let errors = validate_plan(&plan).unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, ValidationError::BoundaryContradictsCoverage { .. }))
    );
}

#[test]
fn non_full_coverage_requires_retained_boundary_evidence() {
    use effinterp_proto::{CoverageLevel, Domain};
    let mut plan = load("exec-rm-recursive.json");
    plan.coverage.0.insert(
        Domain::new("filesystem"),
        effinterp_proto::CoverageClaim {
            level: CoverageLevel::None,
            gaps: Vec::new(),
        },
    );
    let errors = validate_plan(&plan).unwrap_err();
    assert!(errors.iter().any(|error| matches!(
        error,
        ValidationError::UnexplainedCoverage { domain } if domain == "filesystem"
    )));

    plan.causality.coverage.level = CoverageLevel::Partial;
    let errors = validate_plan(&plan).unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| matches!(error, ValidationError::UnexplainedCausalityCoverage))
    );
}

#[test]
fn affected_resource_domain_must_be_declared() {
    use effinterp_proto::{Boundary, BoundaryClass, BoundaryReason, CoverageLevel, Domain};
    let mut plan = load("exec-rm-recursive.json");
    plan.coverage.0.insert(
        Domain::new("network"),
        effinterp_proto::CoverageClaim {
            level: CoverageLevel::Partial,
            gaps: Vec::new(),
        },
    );
    plan.boundaries.push(Boundary {
        reason: BoundaryReason::UNRESOLVED_CALL,
        class: BoundaryClass::Unresolved,
        scope: effinterp_proto::BoundaryScope::Invocation,
        domains: vec![Domain::new("network")],
        affected_resource: Some(plan.effects[1].resource.clone()),
        callee: None,
        provenance: Vec::new(),
        limit: None,
        detail: None,
    });
    let errors = validate_plan(&plan).unwrap_err();
    assert!(errors.iter().any(|error| matches!(
        error,
        ValidationError::BoundaryResourceDomainMismatch { .. }
    )));
}

#[test]
fn rejects_malformed_boundary_reason() {
    let plan = load("symbolic-widened.json");
    let mut value = serde_json::to_value(plan).unwrap();
    value["boundaries"][0]["reason"] = serde_json::Value::String("Bad Reason".into());
    let plan: Plan = serde_json::from_value(value).unwrap();
    let errors = validate_plan(&plan).unwrap_err();
    assert!(errors.iter().any(|error| matches!(
        error,
        ValidationError::MalformedBoundaryReason { boundary: 0, .. }
    )));
}

#[test]
fn rejects_invalid_boundary_domain_and_limit() {
    use effinterp_proto::{BoundaryClass, Domain};

    let mut plan = load("symbolic-widened.json");
    plan.boundaries[0].domains.push(Domain::new("unknown"));
    plan.boundaries[1].class = BoundaryClass::Unmodeled;
    let errors = validate_plan(&plan).unwrap_err();
    assert!(errors.iter().any(|error| matches!(
        error,
        ValidationError::InvalidBoundaryDomain { boundary: 0, .. }
    )));
    assert!(errors.iter().any(|error| matches!(
        error,
        ValidationError::InvalidBoundaryLimit { boundary: 1, .. }
    )));
}

#[test]
fn rejects_invalid_and_noncanonical_boundary_resources() {
    use effinterp_proto::{ResourceExpr, ResourceIdentity};

    let mut invalid = load("symbolic-widened.json");
    invalid.boundaries[0].affected_resource = Some(ResourceExpr::Concrete {
        identity: ResourceIdentity::FsPath {
            path: String::new(),
        },
    });
    let errors = validate_plan(&invalid).unwrap_err();
    assert!(errors.iter().any(|error| matches!(
        error,
        ValidationError::InvalidBoundaryResource { boundary: 0 }
    )));

    invalid.boundaries[0].affected_resource = Some(ResourceExpr::Pattern {
        pattern: effinterp_proto::ResourcePattern::FsPath {
            glob: "/tmp/*/../x".into(),
        },
    });
    assert!(
        validate_plan(&invalid)
            .unwrap_err()
            .iter()
            .any(|error| matches!(
                error,
                ValidationError::InvalidBoundaryResource { boundary: 0 }
            ))
    );

    let mut noncanonical = load("symbolic-widened.json");
    noncanonical.boundaries[0].affected_resource = Some(ResourceExpr::Concrete {
        identity: ResourceIdentity::FsPath {
            path: "/a/../b".into(),
        },
    });
    let errors = validate_plan(&noncanonical).unwrap_err();
    assert!(errors.iter().any(|error| matches!(
        error,
        ValidationError::NonCanonicalBoundaryResource { boundary: 0 }
    )));
}

#[test]
fn rejects_empty_concrete_identity() {
    use effinterp_proto::{ResourceExpr, ResourceIdentity};
    let mut plan = load("exec-rm-recursive.json");
    plan.effects[1].resource = ResourceExpr::Concrete {
        identity: ResourceIdentity::FsPath {
            path: String::new(),
        },
    };
    plan.stamp_effect_ids().unwrap();
    let errors = validate_plan(&plan).unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, ValidationError::EmptyResourceIdentity { effect: 1 }))
    );
}

#[test]
fn accepts_a_canonical_windows_unc_resource() {
    use effinterp_proto::{ResourceExpr, ResourceIdentity};
    let mut plan = load("exec-rm-recursive.json");
    plan.effects[1].resource = ResourceExpr::Concrete {
        identity: ResourceIdentity::FsPath {
            path: "//server/share/data".into(),
        },
    };
    plan.stamp_effect_ids().unwrap();
    assert!(validate_plan(&plan).is_ok());
}

#[test]
fn rejects_incompatible_operation_resource_family() {
    use effinterp_proto::{Operation, ResourceExpr, ResourceIdentity};
    let mut plan = load("exec-rm-recursive.json");
    // filesystem.delete targeting a database table is incoherent.
    plan.effects[1].operation = Operation::new("filesystem.delete");
    plan.effects[1].resource = ResourceExpr::Concrete {
        identity: ResourceIdentity::DatabaseTable {
            server: None,
            database: None,
            schema: Some("public".into()),
            table: "users".into(),
        },
    };
    plan.stamp_effect_ids().unwrap();
    let errors = validate_plan(&plan).unwrap_err();
    assert!(errors.iter().any(|e| matches!(
        e,
        ValidationError::IncompatibleResourceFamily { effect: 1, .. }
    )));
}

#[test]
fn environment_and_git_roots_require_their_typed_identity() {
    let environment = ResourceExpr::Concrete {
        identity: ResourceIdentity::EnvironmentVariable {
            name: "HOME".into(),
        },
    };
    assert!(validate_plan(&plan_with_target("environment.read", environment)).is_ok());

    let git = ResourceExpr::Concrete {
        identity: ResourceIdentity::GitRepository {
            worktree: Some(Box::new(ResourceExpr::Parameter { name: "cwd".into() })),
            git_dir: None,
            pathspec: Some(Box::new(ResourceExpr::Pattern {
                pattern: effinterp_proto::ResourcePattern::FsPath {
                    glob: "src/*".into(),
                },
            })),
        },
    };
    assert!(validate_plan(&plan_with_target("git.read", git)).is_ok());

    let contradictory_git_scope = ResourceExpr::Concrete {
        identity: ResourceIdentity::GitRepository {
            worktree: Some(Box::new(ResourceExpr::Concrete {
                identity: ResourceIdentity::NetworkEndpoint {
                    host: "example.test".into(),
                    scheme: None,
                    port: None,
                    path: None,
                },
            })),
            git_dir: None,
            pathspec: None,
        },
    };
    let errors = validate_plan(&plan_with_target("git.read", contradictory_git_scope)).unwrap_err();
    assert!(errors.iter().any(|error| matches!(
        error,
        ValidationError::IncompatibleResourceFamily { effect: 1, .. }
    )));

    for (operation, resource) in [
        (
            "environment.read",
            ResourceExpr::Environment {
                name: "HOME".into(),
            },
        ),
        (
            "git.read",
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath {
                    path: "/repo".into(),
                },
            },
        ),
    ] {
        let errors = validate_plan(&plan_with_target(operation, resource)).unwrap_err();
        assert!(errors.iter().any(|error| matches!(
            error,
            ValidationError::IncompatibleResourceFamily { effect: 1, .. }
        )));
    }
}

#[test]
fn empty_environment_and_git_identities_fail() {
    for (operation, identity) in [
        (
            "environment.read",
            ResourceIdentity::EnvironmentVariable {
                name: String::new(),
            },
        ),
        (
            "git.read",
            ResourceIdentity::GitRepository {
                worktree: None,
                git_dir: None,
                pathspec: None,
            },
        ),
    ] {
        let errors = validate_plan(&plan_with_target(
            operation,
            ResourceExpr::Concrete { identity },
        ))
        .unwrap_err();
        assert!(
            errors
                .iter()
                .any(|error| matches!(error, ValidationError::EmptyResourceIdentity { effect: 1 }))
        );
    }
}

#[test]
fn declared_families_typed_children_and_unions_must_match_the_operation() {
    let incompatible = [
        ResourceExpr::Pattern {
            pattern: effinterp_proto::ResourcePattern::EnvironmentVariable {
                name_glob: "*".into(),
            },
        },
        ResourceExpr::Unresolved {
            family: ResourceFamily::new("network"),
        },
        ResourceExpr::Join {
            parts: vec![
                ResourceExpr::Parameter {
                    name: "root".into(),
                },
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::NetworkEndpoint {
                        host: "example.test".into(),
                        scheme: None,
                        port: None,
                        path: None,
                    },
                },
            ],
        },
        ResourceExpr::Union {
            alternatives: vec![
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path: "/a".into() },
                },
                ResourceExpr::Unresolved {
                    family: ResourceFamily::new("network"),
                },
            ],
        },
    ];
    for resource in incompatible {
        let errors = validate_plan(&plan_with_target("filesystem.read", resource)).unwrap_err();
        assert!(errors.iter().any(|error| matches!(
            error,
            ValidationError::IncompatibleResourceFamily { effect: 1, .. }
        )));
    }
}

#[test]
fn untyped_symbolic_filesystem_roots_remain_valid_and_unchanged() {
    let resources = [
        ResourceExpr::Environment {
            name: "FILE".into(),
        },
        ResourceExpr::Property {
            base: Box::new(ResourceExpr::Parameter {
                name: "config".into(),
            }),
            name: "cache_root".into(),
        },
        ResourceExpr::Join {
            parts: vec![
                ResourceExpr::Parameter {
                    name: "root".into(),
                },
                ResourceExpr::Literal {
                    value: "cache".into(),
                },
            ],
        },
    ];
    for resource in resources {
        let plan = plan_with_target("filesystem.read", resource.clone());
        assert!(validate_plan(&plan).is_ok(), "{resource:?}");
        assert_eq!(plan.effects[1].resource, resource);
    }
}

#[test]
fn rejects_dangling_provenance_ref() {
    let mut plan = load("exec-rm-recursive.json");
    plan.effects[0].provenance[0].0 = 99;
    let errors = validate_plan(&plan).unwrap_err();
    assert!(matches!(
        errors[0],
        ValidationError::DanglingProvenanceRef { index: 99, .. }
    ));
}

#[test]
fn rejects_forward_antecedent() {
    let mut plan = load("exec-rm-recursive.json");
    plan.provenance[0]
        .antecedents
        .push(effinterp_proto::ProvenanceRef(2));
    let errors = validate_plan(&plan).unwrap_err();
    assert!(matches!(
        errors[0],
        ValidationError::ForwardAntecedent {
            node: 0,
            antecedent: 2
        }
    ));
}

#[test]
fn rejects_effect_in_uncovered_domain() {
    let mut plan = load("exec-rm-recursive.json");
    plan.effects[1].operation = effinterp_proto::Operation::new("database.write");
    plan.stamp_effect_ids().unwrap();
    let errors = validate_plan(&plan).unwrap_err();
    assert!(matches!(
        errors[0],
        ValidationError::UncoveredDomain { effect: 1, .. }
    ));
}

#[test]
fn rejects_malformed_operation() {
    let mut plan = load("exec-rm-recursive.json");
    for bad in ["delete", "Filesystem.Delete", "filesystem..delete", ""] {
        plan.effects[1].operation = effinterp_proto::Operation::new(bad);
        plan.stamp_effect_ids().unwrap();
        let errors = validate_plan(&plan).unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ValidationError::MalformedOperation { effect: 1, .. })),
            "accepted malformed operation {bad:?}"
        );
    }
}

#[test]
fn rejects_dangling_boundary_ref() {
    let mut plan = load("shell-env-opaque-nested.json");
    plan.execution_graph.nodes[1].boundary = Some(effinterp_proto::BoundaryRef(7));
    let errors = validate_plan(&plan).unwrap_err();
    assert!(matches!(
        errors[0],
        ValidationError::DanglingBoundaryRef {
            node: 1,
            boundary: 7
        }
    ));
}

#[test]
fn rejects_dangling_effect_execution_ref() {
    let mut plan = load("exec-rm-recursive.json");
    plan.effects[0].execution = effinterp_proto::ExecutionNodeRef(99);
    let errors = validate_plan(&plan).unwrap_err();
    assert!(errors.iter().any(|error| matches!(
        error,
        ValidationError::DanglingExecutionRef { context, node: 99 }
            if context == "effects[0]"
    )));
}

#[test]
fn rejects_effect_realm_different_from_execution_node() {
    let mut plan = load("exec-rm-recursive.json");
    plan.effects[0].realm = effinterp_proto::ExecutionRealm::Container {
        runtime: "docker".to_string(),
        name: "worker".to_string(),
    };
    plan.stamp_effect_ids().unwrap();
    let errors = validate_plan(&plan).unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| matches!(error, ValidationError::EffectRealmMismatch { effect: 0 }))
    );
}

fn occurrence(id: &str, order: u32) -> effinterp_proto::OccurrenceNode {
    effinterp_proto::OccurrenceNode {
        id: effinterp_proto::OccurrenceId(id.to_string()),
        occurrence: effinterp_proto::OccurrenceKind::Port {
            port: effinterp_proto::Port::Value,
        },
        execution: Some(effinterp_proto::ExecutionNodeRef(0)),
        realm: effinterp_proto::ExecutionRealm::Host,
        modality: effinterp_proto::Modality::May,
        condition: None,
        order,
        cardinality: effinterp_proto::CausalCardinality::MAYBE_ONCE,
        provenance: Vec::new(),
    }
}

fn causal_edge(from: &str, to: &str, order: u32) -> effinterp_proto::CausalEdge {
    effinterp_proto::CausalEdge {
        from: effinterp_proto::OccurrenceId(from.to_string()),
        to: effinterp_proto::OccurrenceId(to.to_string()),
        reason: effinterp_proto::CausalReason::ValueDependency,
        assurance: effinterp_proto::CausalAssurance::Conservative,
        modality: effinterp_proto::Modality::May,
        condition: None,
        order,
        cardinality: effinterp_proto::CausalCardinality::MAYBE_ONCE,
        provenance: Vec::new(),
    }
}

fn with_causality(
    edges: Vec<effinterp_proto::CausalEdge>,
    nodes: Vec<effinterp_proto::OccurrenceNode>,
) -> Plan {
    let mut plan = load("exec-rm-recursive.json");
    plan.causality = effinterp_proto::Causality {
        graph: Some(effinterp_proto::CausalityGraph { nodes, edges }),
        coverage: effinterp_proto::CoverageClaim {
            level: CoverageLevel::Full,
            gaps: Vec::new(),
        },
    };
    plan
}

#[test]
fn accepts_a_well_formed_causality_graph() {
    let plan = with_causality(
        vec![causal_edge("occurrence:a", "occurrence:b", 0)],
        vec![occurrence("occurrence:a", 0), occurrence("occurrence:b", 1)],
    );
    assert!(validate_plan(&plan).is_ok());
}

#[test]
fn rejects_cardinality_that_contradicts_modality() {
    let mut maybe = occurrence("occurrence:a", 0);
    maybe.cardinality = effinterp_proto::CausalCardinality::EXACTLY_ONCE;
    let errors = validate_plan(&with_causality(Vec::new(), vec![maybe])).unwrap_err();
    assert!(errors.iter().any(|error| matches!(
        error,
        ValidationError::InvalidCausalCardinality { context }
            if context == "causality.nodes[0]"
    )));

    let mut edge = causal_edge("occurrence:a", "occurrence:b", 0);
    edge.modality = effinterp_proto::Modality::MustOnSuccess;
    let errors = validate_plan(&with_causality(
        vec![edge],
        vec![occurrence("occurrence:a", 0), occurrence("occurrence:b", 1)],
    ))
    .unwrap_err();
    assert!(errors.iter().any(|error| matches!(
        error,
        ValidationError::InvalidCausalCardinality { context }
            if context == "causality.edges[0]"
    )));
}

#[test]
fn rejects_occurrence_in_a_different_execution_realm() {
    let mut node = occurrence("occurrence:a", 0);
    node.realm = effinterp_proto::ExecutionRealm::Container {
        runtime: "docker".into(),
        name: "worker".into(),
    };
    let errors = validate_plan(&with_causality(Vec::new(), vec![node])).unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| matches!(error, ValidationError::CausalRealmMismatch { node: 0 }))
    );
}

#[test]
fn exact_cycles_are_retained() {
    let plan = with_causality(
        vec![
            causal_edge("occurrence:a", "occurrence:b", 0),
            causal_edge("occurrence:b", "occurrence:a", 1),
        ],
        vec![occurrence("occurrence:a", 0), occurrence("occurrence:b", 1)],
    );
    assert!(validate_plan(&plan).is_ok());
}

#[test]
fn rejects_edge_to_missing_occurrence() {
    let plan = with_causality(
        vec![causal_edge("occurrence:a", "occurrence:missing", 0)],
        vec![occurrence("occurrence:a", 0)],
    );
    let errors = validate_plan(&plan).unwrap_err();
    assert!(errors.iter().any(|error| matches!(
        error,
        ValidationError::CausalDanglingOccurrence { edge: 0, id }
            if id == "occurrence:missing"
    )));
}

#[test]
fn rejects_duplicate_occurrence_identity() {
    let plan = with_causality(
        Vec::new(),
        vec![occurrence("occurrence:a", 0), occurrence("occurrence:a", 1)],
    );
    let errors = validate_plan(&plan).unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, ValidationError::DuplicateOccurrenceId { node: 1, .. }))
    );
}

#[test]
fn causal_reason_and_assurance_are_required_and_retained() {
    let mut edge = causal_edge("occurrence:a", "occurrence:b", 0);
    edge.reason = effinterp_proto::CausalReason::Alias;
    edge.assurance = effinterp_proto::CausalAssurance::Exact;
    let plan = with_causality(
        vec![edge],
        vec![occurrence("occurrence:a", 0), occurrence("occurrence:b", 1)],
    );
    assert!(validate_plan(&plan).is_ok());
    let reparsed = from_plan_json(&canonical_json(&plan)).unwrap();
    assert_eq!(
        reparsed
            .causality
            .graph
            .as_ref()
            .expect("causality detail required")
            .edges[0]
            .reason,
        effinterp_proto::CausalReason::Alias
    );
    let edge = &reparsed.causality.graph.as_ref().unwrap().edges[0];
    assert_eq!(edge.assurance, effinterp_proto::CausalAssurance::Exact);
    assert_eq!(edge.modality, effinterp_proto::Modality::May);
    let redacted = effinterp_proto::redact_plan(&plan);
    effinterp_proto::validate_redacted(&redacted).unwrap();
    assert_eq!(redacted.causality.graph.as_ref().unwrap().edges[0], *edge);
    let mut json = serde_json::to_value(&plan).unwrap();
    json["causality"]["graph"]["edges"][0]
        .as_object_mut()
        .unwrap()
        .remove("assurance");
    assert!(serde_json::from_value::<Plan>(json).is_err());

    for endpoint in [false, true] {
        let mut widened = plan.clone();
        let graph = widened.causality.graph.as_mut().unwrap();
        if endpoint {
            graph.nodes[0].condition = Some(effinterp_proto::Condition::Widened);
        } else {
            graph.edges[0].condition = Some(effinterp_proto::Condition::Widened);
        }
        assert!(validate_plan(&widened).is_err());
        assert!(
            effinterp_proto::validate_redacted(&effinterp_proto::redact_plan(&widened)).is_err()
        );
        widened.causality.graph.as_mut().unwrap().edges[0].assurance =
            effinterp_proto::CausalAssurance::Conservative;
        validate_plan(&widened).unwrap();
        effinterp_proto::validate_redacted(&effinterp_proto::redact_plan(&widened)).unwrap();
    }
}

/// A transfer edge names the two endpoints of one modeled movement. Anything
/// but a resource interaction at either end is corrupt transport, so the plan
/// is rejected rather than read as a weaker claim.
#[test]
fn rejects_transfer_edge_without_resource_interaction_endpoints() {
    let mut edge = causal_edge("occurrence:a", "occurrence:b", 0);
    edge.reason = effinterp_proto::CausalReason::ResourceTransfer;
    let mut source = occurrence("occurrence:a", 0);
    source.occurrence = effinterp_proto::OccurrenceKind::ResourceInteraction {
        operation: effinterp_proto::Operation::new("filesystem.read"),
        resource: ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath {
                path: "/w/a.txt".into(),
            },
        },
        attributes: Default::default(),
    };
    let port = occurrence("occurrence:b", 1);
    let plan = with_causality(vec![edge.clone()], vec![source.clone(), port]);
    let errors = validate_plan(&plan).unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, ValidationError::CausalTransferEndpoint { edge: 0 }))
    );

    let mut destination = source.clone();
    destination.id = effinterp_proto::OccurrenceId("occurrence:b".to_string());
    destination.order = 1;
    destination.occurrence = effinterp_proto::OccurrenceKind::ResourceInteraction {
        operation: effinterp_proto::Operation::new("filesystem.write"),
        resource: ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath {
                path: "/w/b.txt".into(),
            },
        },
        attributes: Default::default(),
    };
    assert!(validate_plan(&with_causality(vec![edge], vec![source, destination])).is_ok());
}

#[test]
fn unknown_operations_are_retained() {
    let mut plan = load("exec-rm-recursive.json");
    plan.effects[1].operation = effinterp_proto::Operation::new("filesystem.future_op");
    plan.effects[1].resource = ResourceExpr::Concrete {
        identity: ResourceIdentity::EnvironmentVariable {
            name: "FUTURE".into(),
        },
    };
    plan.stamp_effect_ids().unwrap();
    assert!(validate_plan(&plan).is_ok());
    let reparsed = from_plan_json(&canonical_json(&plan)).unwrap();
    assert_eq!(reparsed.effects[1].operation.0, "filesystem.future_op");
}

#[test]
fn system_identity_operations_validate_without_accepting_other_families() {
    for (identity, operation, name) in [
        (
            ResourceIdentity::ServiceUnit {
                manager: "systemd".into(),
                name: "nginx".into(),
            },
            "system.service_stop",
            "service-unit",
        ),
        (
            ResourceIdentity::ScheduledJob {
                scheduler: "cron".into(),
                owner: None,
            },
            "system.scheduled_job_delete",
            "scheduled-job",
        ),
        (
            ResourceIdentity::StorageVolume {
                manager: "lvm".into(),
                name: "vg/data".into(),
            },
            "system.storage_destroy",
            "storage-volume",
        ),
        (
            ResourceIdentity::BlockDevice {
                device: "/dev/sda".into(),
            },
            "system.storage_destroy",
            "block-device",
        ),
        (
            ResourceIdentity::HostSystem {},
            "system.power",
            "host-system",
        ),
    ] {
        let resource = ResourceExpr::Concrete { identity };
        assert!(effect_resource_errors(operation, resource.clone()).is_empty());
        assert!(effect_resource_errors("filesystem.read", resource.clone()).iter().any(|e| matches!(e, ValidationError::IncompatibleResourceFamily { identity, .. } if *identity == name)));
        if name == "service-unit" {
            assert!(!effect_resource_errors("system.kernel_trigger", resource).is_empty());
        }
    }
    assert!(
        effect_resource_errors(
            "system.kernel_trigger",
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath {
                    path: "/proc/sysrq-trigger".into()
                }
            }
        )
        .is_empty()
    );
    assert!(
        effect_resource_errors(
            "system.service_stop",
            ResourceExpr::Pattern {
                pattern: effinterp_proto::ResourcePattern::ServiceUnit {
                    manager: effinterp_proto::Field::Any,
                    name_glob: "*".into()
                }
            }
        )
        .is_empty()
    );
    assert!(
        effect_resource_errors(
            "system.storage_destroy",
            ResourceExpr::Unresolved {
                family: ResourceFamily::new("system")
            }
        )
        .is_empty()
    );
    assert!(Operation::new("system.storage_destroy").is_destructive());
    assert!(Operation::new("system.scheduled_job_delete").is_destructive());
    assert!(!Operation::new("system.service_stop").is_destructive());
}

#[test]
fn coverage_requires_explicit_nonempty_domain_requirements() {
    use effinterp_proto::{Coverage, CoverageClaim};
    let filesystem = Domain::new("filesystem");
    let network = Domain::new("network");
    let mut coverage = Coverage(Default::default());
    assert!(!coverage.covers_fully([]));
    assert!(!coverage.is_full(&filesystem));
    assert_eq!(coverage.level(&filesystem), None);
    assert!(coverage.gaps(&filesystem).is_empty());
    coverage.0.insert(
        filesystem.clone(),
        CoverageClaim {
            level: CoverageLevel::Full,
            gaps: vec![],
        },
    );
    assert!(coverage.covers_fully([&filesystem, &filesystem]));
    assert!(!coverage.covers_fully([&filesystem, &network]));
    for level in [CoverageLevel::Partial, CoverageLevel::None] {
        coverage.0.insert(
            network.clone(),
            CoverageClaim {
                level,
                gaps: vec![effinterp_proto::BoundaryRef(0)],
            },
        );
        assert!(!coverage.covers_fully([&filesystem, &network]));
        assert!(coverage.is_full(&filesystem));
    }
    let mut plan = load("exec-rm-recursive.json");
    plan.effects.clear();
    plan.causality
        .graph
        .as_mut()
        .expect("causality detail required")
        .nodes
        .clear();
    plan.causality
        .graph
        .as_mut()
        .expect("causality detail required")
        .edges
        .clear();
    validate_plan(&plan).unwrap();
    assert!(plan.coverage.is_full(&filesystem));
    plan.coverage.0.clear();
    validate_plan(&plan).unwrap();
    assert!(!plan.coverage.is_full(&filesystem));
}

#[test]
fn coverage_gaps_exactly_reference_each_domains_boundaries() {
    use effinterp_proto::{Boundary, BoundaryClass, BoundaryReason, BoundaryRef, CoverageClaim};
    let mut plan = load("exec-rm-recursive.json");
    let filesystem = Domain::new("filesystem");
    // Symbolic targets and may effects do not assert runtime occurrence.
    plan.effects[1].resource = ResourceExpr::Unresolved {
        family: ResourceFamily::new("filesystem"),
    };
    plan.effects[1].modality = effinterp_proto::Modality::May;
    let realm = effinterp_proto::ExecutionRealm::Remote {
        endpoint: "other-host".into(),
    };
    for effect in &mut plan.effects {
        effect.realm = realm.clone();
    }
    for node in &mut plan.execution_graph.nodes {
        node.realm = realm.clone();
    }
    for node in &mut plan
        .causality
        .graph
        .as_mut()
        .expect("causality detail required")
        .nodes
    {
        node.realm = realm.clone();
    }
    plan.stamp_effect_ids().unwrap();
    validate_plan(&plan).unwrap();
    for domain in ["network", "dataflow", "network"] {
        plan.boundaries.push(Boundary {
            reason: BoundaryReason::UNRESOLVED_CALL,
            class: BoundaryClass::Unresolved,
            scope: effinterp_proto::BoundaryScope::Invocation,
            domains: vec![Domain::new(domain)],
            affected_resource: None,
            callee: None,
            provenance: vec![],
            limit: None,
            detail: None,
        });
    }
    plan.boundaries[0].affected_resource = Some(ResourceExpr::Concrete {
        identity: ResourceIdentity::NetworkEndpoint {
            host: "other-host".into(),
            scheme: None,
            port: None,
            path: None,
        },
    });
    let network = Domain::new("network");
    plan.coverage.0.insert(
        network.clone(),
        CoverageClaim {
            level: CoverageLevel::Partial,
            gaps: vec![BoundaryRef(0), BoundaryRef(2)],
        },
    );
    plan.causality.coverage = CoverageClaim {
        level: CoverageLevel::Partial,
        gaps: vec![BoundaryRef(1)],
    };
    plan.stamp_effect_ids().unwrap();
    validate_plan(&plan).unwrap();
    assert!(plan.coverage.is_full(&filesystem));
    assert_eq!(from_plan_json(&canonical_json(&plan)).unwrap(), plan);
    for gaps in [
        vec![],
        vec![BoundaryRef(0)],
        vec![BoundaryRef(2), BoundaryRef(0)],
        vec![BoundaryRef(0), BoundaryRef(0), BoundaryRef(2)],
        vec![BoundaryRef(0), BoundaryRef(3)],
        vec![BoundaryRef(0), BoundaryRef(1)],
    ] {
        let mut invalid = plan.clone();
        invalid.coverage.0.get_mut(&network).unwrap().gaps = gaps;
        assert!(validate_plan(&invalid).unwrap_err().iter().any(
            |e| matches!(e, ValidationError::InvalidCoverageGaps { domain } if domain == "network")
        ));
    }
    let mut invalid = plan.clone();
    invalid.coverage.0.get_mut(&network).unwrap().level = CoverageLevel::Full;
    assert!(validate_plan(&invalid).is_err());
    invalid = plan.clone();
    invalid.coverage.0.remove(&network);
    assert!(
        validate_plan(&invalid)
            .unwrap_err()
            .iter()
            .any(|e| matches!(e, ValidationError::UnclaimedBoundaryDomain { .. }))
    );
    invalid = plan.clone();
    invalid.causality.coverage.gaps = vec![BoundaryRef(0)];
    assert!(validate_plan(&invalid).is_err());
    plan.coverage.0.get_mut(&network).unwrap().level = CoverageLevel::None;
    plan.stamp_effect_ids().unwrap();
    validate_plan(&plan).unwrap();
    assert!(serde_json::from_str::<CoverageClaim>(r#"{"level":"full","extra":true}"#).is_err());
    assert!(serde_json::from_str::<CoverageClaim>(r#""full""#).is_err());
    let stable: CoverageClaim<String> =
        serde_json::from_str(r#"{"level":"partial","gaps":["boundary-id"]}"#).unwrap();
    assert_eq!(stable.gaps, ["boundary-id"]);
}

#[test]
fn effect_identity_hashes_every_identity_field() {
    use effinterp_proto::{
        AttrValue, Condition, EffectId, EffectIdentity, EffectOccurrence, ExecutionRealm, Modality,
    };
    /// One mutation of an identity field, used to check that each field reaches the hash.
    type IdentityChange = Box<dyn Fn(&mut EffectIdentity)>;
    let plan = load("exec-rm-recursive.json");
    let effect = &plan.effects[1];
    let identity = EffectIdentity {
        request_assurance: effinterp_proto::RequestAssurance::Conservative,
        operation: effect.operation.clone(),
        resource: effect.resource.clone(),
        realm: effect.realm.clone(),
        modality: effect.modality,
        attributes: effect.attributes.clone(),
        condition: effect.condition.clone(),
        occurrence: EffectOccurrence {
            subject_digest: effinterp_proto::canonical_hash(
                &plan.execution_graph.nodes[effect.execution.0 as usize].subject,
            ),
            realm: ExecutionRealm::Host,
            ordinal: 0,
        },
    };
    let original = EffectId::derive(&identity);
    assert_eq!(original, effect.id);
    let changes: Vec<IdentityChange> = vec![
        Box::new(|i| i.request_assurance = effinterp_proto::RequestAssurance::Exact),
        Box::new(|i| i.operation = Operation::new("filesystem.read")),
        Box::new(|i| {
            i.resource = ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath {
                    path: "/different".into(),
                },
            }
        }),
        Box::new(|i| {
            i.realm = ExecutionRealm::Remote {
                endpoint: "server".into(),
            }
        }),
        Box::new(|i| i.modality = Modality::MustOnSuccess),
        Box::new(|i| {
            i.attributes.insert("changed".into(), AttrValue::Bool(true));
        }),
        Box::new(|i| i.condition = Some(Condition::Widened)),
        Box::new(|i| {
            i.occurrence.subject_digest = effinterp_proto::canonical_hash(&"changed subject")
        }),
        Box::new(|i| {
            i.occurrence.realm = ExecutionRealm::Remote {
                endpoint: "server".into(),
            }
        }),
        Box::new(|i| i.occurrence.ordinal += 1),
    ];
    for change in changes {
        let mut changed = identity.clone();
        change(&mut changed);
        assert_ne!(EffectId::derive(&changed), original);
    }
    let mut normalized = identity.clone();
    if let ResourceExpr::Concrete {
        identity: ResourceIdentity::FsPath { path },
    } = &mut normalized.resource
    {
        *path = format!("{path}/./");
    } else {
        panic!("fixture has a filesystem path");
    }
    assert_eq!(EffectId::derive(&normalized), original);
}

#[test]
fn effect_ids_ignore_metadata_and_numbering_but_hash_launching_subjects() {
    let mut plan = load("exec-rm-recursive.json");
    let original = plan.expected_effect_ids().unwrap();
    plan.analysis.engine_version = "changed".into();
    plan.analysis.model_set = "changed".into();
    plan.analysis.limits.insert("max_effects".into(), 9999);
    plan.effects.reverse();
    plan.provenance.reverse();
    for effect in &mut plan.effects {
        for reference in &mut effect.provenance {
            reference.0 = plan.provenance.len() as u32 - 1 - reference.0;
        }
    }
    // A new node number for the same subject must not change identity.
    let node = plan.execution_graph.nodes[0].clone();
    plan.execution_graph.nodes.insert(0, node);
    for effect in &mut plan.effects {
        effect.execution.0 += 1;
    }
    assert_eq!(
        plan.expected_effect_ids().unwrap(),
        original.iter().rev().cloned().collect::<Vec<_>>()
    );
    let mut unrelated = plan.effects[0].clone();
    unrelated.operation = Operation::new("filesystem.read");
    plan.effects.insert(0, unrelated);
    assert_eq!(
        &plan.expected_effect_ids().unwrap()[1..],
        original.iter().rev().cloned().collect::<Vec<_>>()
    );
    let node = &mut plan.execution_graph.nodes[1];
    if let effinterp_proto::Subject::Exec { argv, .. } = &mut node.subject {
        argv.push("another-path".into());
    }
    assert!(
        plan.expected_effect_ids().unwrap()[1..]
            .iter()
            .zip(original.iter().rev())
            .all(|(a, b)| a != b)
    );
}

#[test]
fn effect_ids_reject_tampering_and_assign_duplicate_ordinals_across_nodes() {
    use effinterp_proto::{EffectId, ExecutionNodeRef};
    let mut plan = load("exec-rm-recursive.json");
    let original = plan.effects[1].clone();
    plan.effects.push(original.clone());
    let mut nested = original.clone();
    nested.execution = ExecutionNodeRef(plan.execution_graph.nodes.len() as u32);
    plan.execution_graph
        .nodes
        .push(plan.execution_graph.nodes[original.execution.0 as usize].clone());
    plan.effects.push(nested);
    let ids = plan.expected_effect_ids().unwrap();
    assert_eq!(
        ids.iter().collect::<std::collections::BTreeSet<_>>().len(),
        plan.effects.len()
    );
    // Moving the third duplicate into the first node leaves its ordinal unchanged.
    plan.effects.last_mut().unwrap().execution = original.execution;
    assert_eq!(plan.expected_effect_ids().unwrap(), ids);
    plan.stamp_effect_ids().unwrap();
    plan.effects[0].id = plan.effects[1].id.clone();
    let errors = validate_plan(&plan).unwrap_err();
    assert!(errors.contains(&ValidationError::InvalidEffectId { effect: 0 }));
    assert!(errors.contains(&ValidationError::DuplicateEffectId { effect: 1 }));
    for invalid in [
        "",
        "effect:blake3:123",
        &format!("effect:blake3:{}", "A".repeat(64)),
    ] {
        plan.effects[0].id = EffectId(invalid.into());
        assert!(
            validate_plan(&plan)
                .unwrap_err()
                .contains(&ValidationError::InvalidEffectId { effect: 0 })
        );
    }
    let mut wire = serde_json::to_value(load("exec-rm-recursive.json")).unwrap();
    wire["effects"][0].as_object_mut().unwrap().remove("id");
    assert!(serde_json::from_value::<Plan>(wire).is_err());
    plan.effects[0].execution = ExecutionNodeRef(u32::MAX);
    assert!(plan.stamp_effect_ids().is_err());
    assert!(
        validate_plan(&plan)
            .unwrap_err()
            .iter()
            .any(|e| matches!(e, ValidationError::DanglingExecutionRef { .. }))
    );
}

#[test]
fn credential_identities_validate_and_keep_verbatim_store_paths() {
    for (store, path, provider, rendered) in [
        (Some("secret"), Some("x"), "vault", "cred:vault/secret/x"),
        (
            None,
            Some("/service/api"),
            "aws-ssm",
            "cred:aws-ssm//service/api",
        ),
        (Some("service"), None, "doppler", "cred:doppler/service"),
    ] {
        let resource = ResourceExpr::Concrete {
            identity: ResourceIdentity::CredentialStore {
                provider: provider.into(),
                store: store.map(str::to_owned),
                path: path.map(str::to_owned),
            },
        };
        assert!(effect_resource_errors("credential.read", resource.clone()).is_empty());
        assert_eq!(effinterp_proto::display_resource(&resource), rendered);
        assert!(
            effect_resource_errors("cloud.resource.delete", resource)
                .iter()
                .any(|error| matches!(
                    error,
                    ValidationError::IncompatibleResourceFamily {
                        identity: "credential-store",
                        ..
                    }
                ))
        );
    }
    let cloud = ResourceExpr::Concrete {
        identity: ResourceIdentity::CloudResource {
            provider: Some("aws".into()),
            scope: Box::new(effinterp_proto::cloud_scope(Some("aws"), "secrets", "path")),
            service: "secrets".into(),
            kind: "path".into(),
            id: Some("x".into()),
        },
    };
    assert!(
        effect_resource_errors("credential.read", cloud)
            .iter()
            .any(|error| matches!(error, ValidationError::IncompatibleResourceFamily { .. }))
    );
    assert!(matches!(
        effect_resource_errors(
            "credential.read",
            ResourceExpr::Concrete {
                identity: ResourceIdentity::CredentialStore {
                    provider: String::new(),
                    store: None,
                    path: None,
                }
            }
        )
        .as_slice(),
        [ValidationError::EmptyResourceIdentity { effect: 0 }]
    ));
    assert!(
        effect_resource_errors(
            "credential.read",
            ResourceExpr::Unresolved {
                family: ResourceFamily::new("credential")
            }
        )
        .is_empty()
    );
    assert!(Operation::new("credential.delete").is_destructive());
    assert!(!Operation::new("credential.read").is_destructive());
}

#[test]
fn source_language_and_dialect_are_validated() {
    use effinterp_proto::{SourceDialect, Subject};
    for (language, dialect, valid) in [
        ("python", None, true),
        ("python", Some(SourceDialect::Ipython), true),
        ("python", Some(SourceDialect::Js), false),
        ("js", None, false),
        ("js", Some(SourceDialect::Js), true),
        ("js", Some(SourceDialect::Ts), true),
        ("js", Some(SourceDialect::Ipython), false),
        ("py", None, false),
        ("javascript", Some(SourceDialect::Js), false),
        ("ts", Some(SourceDialect::Ts), false),
        ("unknown", None, false),
    ] {
        let subject = Subject::Source {
            language: language.into(),
            dialect,
            source: String::new(),
            cwd: None,
            context: Default::default(),
        };
        assert_eq!(
            effinterp_proto::validate_subject(&subject).is_ok(),
            valid,
            "{language} {dialect:?}"
        );
    }
}

#[test]
fn compact_and_present_empty_causality_round_trip_distinctly() {
    let mut plan = with_causality(Vec::new(), Vec::new());
    validate_plan(&plan).unwrap();
    let detailed = effinterp_proto::canonical_json(&plan);
    plan.causality.graph = None;
    validate_plan(&plan).unwrap();
    let compact = effinterp_proto::canonical_json(&plan);
    assert_ne!(compact, detailed);
    assert!(!compact.contains("\"graph\""));
    assert_eq!(effinterp_proto::from_plan_json(&compact).unwrap(), plan);
    plan.causality
        .coverage
        .gaps
        .push(effinterp_proto::BoundaryRef(999));
    assert!(validate_plan(&plan).is_err());
    let mut obsolete: serde_json::Value = serde_json::from_str(&detailed).unwrap();
    let graph = obsolete["causality"]
        .as_object_mut()
        .unwrap()
        .remove("graph")
        .unwrap();
    obsolete["causality"]["nodes"] = graph["nodes"].clone();
    obsolete["causality"]["edges"] = graph["edges"].clone();
    assert!(effinterp_proto::from_plan_json(&obsolete.to_string()).is_err());
}
