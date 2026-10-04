// The fixture loader reads frozen documents from disk; the crate itself stays pure.
#![allow(clippy::disallowed_methods)]

use effinterp_proto::*;

#[test]
fn satisfies_conformance_replay() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/satisfies-v1");
    for directory in ["valid", "invalid"] {
        for entry in std::fs::read_dir(root.join(directory)).unwrap() {
            let path = entry.unwrap().path();
            let input = std::fs::read_to_string(&path).unwrap();
            let result = SatisfiesCase::from_canonical_json(&input);
            assert_eq!(
                result.is_ok(),
                directory == "valid",
                "{}: {result:?}",
                path.display()
            );
        }
    }
}

#[test]
fn direct_relation_limits_are_deterministic() {
    let point = QualifiedIdentity {
        realm: ExecutionRealm::Host,
        identity: ResourceIdentity::FsPath { path: "/x".into() },
    };
    let bindings = Bindings::none(PathPlatform::Posix);
    let mut deep = ResourceExpr::Literal { value: "/x".into() };
    for _ in 0..RELATION_DEPTH_LIMIT {
        deep = ResourceExpr::Join { parts: vec![deep] };
    }
    let artifact = ResourceExpr::Concrete {
        identity: ResourceIdentity::Artifact {
            ecosystem: ArtifactEcosystem::Oci,
            endpoint: Box::new(ResourceExpr::Literal {
                value: "registry.example".into(),
            }),
            name: Box::new(ResourceExpr::Literal {
                value: "app".into(),
            }),
            reference: Box::new(ArtifactReference::Tag {
                value: deep.clone(),
            }),
        },
    };
    let infrastructure = ResourceExpr::Concrete {
        identity: ResourceIdentity::ManagedInfrastructure {
            tool: "terraform".into(),
            configuration_root: Box::new(deep.clone()),
            workspace: Box::new(ResourceExpr::Literal {
                value: "default".into(),
            }),
            resource_type: None,
            address: None,
            instance: Box::new(ResourceExpr::Literal {
                value: "one".into(),
            }),
        },
    };
    let expressions = [
        infrastructure,
        artifact,
        ResourceExpr::Pattern {
            pattern: ResourcePattern::ArtifactField {
                glob: "?".repeat(RELATION_BYTE_LIMIT),
            },
        },
        deep,
        ResourceExpr::Union {
            alternatives: vec![ResourceExpr::Literal { value: "/x".into() }; 100_000],
        },
        ResourceExpr::Pattern {
            pattern: ResourcePattern::FsPath {
                glob: "?".repeat(RELATION_BYTE_LIMIT),
                narrowing: Default::default(),
            },
        },
    ];
    for expr in expressions {
        let point = if let ResourceExpr::Concrete {
            identity: identity @ ResourceIdentity::ManagedInfrastructure { .. },
        } = &expr
        {
            QualifiedIdentity {
                realm: ExecutionRealm::Host,
                identity: identity.clone(),
            }
        } else if resource_domain(&expr) == Some("artifact") {
            QualifiedIdentity {
                realm: ExecutionRealm::Host,
                identity: ResourceIdentity::Artifact {
                    ecosystem: ArtifactEcosystem::Oci,
                    endpoint: Box::new(ResourceExpr::Literal {
                        value: "registry.example".into(),
                    }),
                    name: Box::new(ResourceExpr::Literal {
                        value: "app".into(),
                    }),
                    reference: Box::new(ArtifactReference::Tag {
                        value: ResourceExpr::Literal { value: "v2".into() },
                    }),
                },
            }
        } else {
            point.clone()
        };
        let expr = QualifiedExpr {
            realm: ExecutionRealm::Host,
            expr,
        };
        for _ in 0..2 {
            assert_eq!(
                satisfies(&point, &expr, &bindings),
                Match::Indeterminate {
                    reason: MatchReason::Limit
                }
            );
        }
    }
    let mut bindings = bindings;
    bindings.env.insert(
        "DIR".into(),
        Binding {
            value: format!("/{}", "x".repeat(8192)),
            source: BindingSource::Declared,
        },
    );
    let expr = QualifiedExpr {
        realm: ExecutionRealm::Host,
        expr: ResourceExpr::Union {
            alternatives: vec![ResourceExpr::Environment { name: "DIR".into() }; 100],
        },
    };
    for _ in 0..2 {
        assert_eq!(
            satisfies(&point, &expr, &bindings),
            Match::Indeterminate {
                reason: MatchReason::Limit
            }
        );
    }
}

#[test]
fn nested_identity_depth_and_glob_work_share_relation_limits() {
    let bindings = Bindings::none(PathPlatform::Posix);
    let mut nested = ResourceExpr::Literal {
        value: "/work".into(),
    };
    for _ in 0..RELATION_DEPTH_LIMIT {
        nested = ResourceExpr::Concrete {
            identity: ResourceIdentity::Process {
                executable: "p".into(),
                path: None,
                argv: vec![],
                cwd: Some(Box::new(nested)),
            },
        };
    }
    let point = QualifiedIdentity {
        realm: ExecutionRealm::Host,
        identity: ResourceIdentity::Process {
            executable: "p".into(),
            path: None,
            argv: vec![],
            cwd: None,
        },
    };
    let expr = QualifiedExpr {
        realm: ExecutionRealm::Host,
        expr: nested,
    };
    assert_eq!(
        satisfies(&point, &expr, &bindings),
        Match::Indeterminate {
            reason: MatchReason::Limit
        }
    );
    let point = QualifiedIdentity {
        realm: ExecutionRealm::Host,
        identity: ResourceIdentity::FsPath {
            path: format!("/{}", "x".repeat(1100)),
        },
    };
    let expr = QualifiedExpr {
        realm: ExecutionRealm::Host,
        expr: ResourceExpr::Pattern {
            pattern: ResourcePattern::FsPath {
                glob: format!("/{}", "?".repeat(1100)),
                narrowing: Default::default(),
            },
        },
    };
    for _ in 0..2 {
        assert_eq!(
            satisfies(&point, &expr, &bindings),
            Match::Indeterminate {
                reason: MatchReason::Limit
            }
        );
    }
}
