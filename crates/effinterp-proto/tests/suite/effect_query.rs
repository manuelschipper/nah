use effinterp_proto::*;
use std::collections::BTreeMap;

fn effect_target(
    operation: &Operation,
    resource: &ResourceExpr,
    attributes: &BTreeMap<String, AttrValue>,
    realm: &ExecutionRealm,
) -> Effect {
    Effect {
        id: EffectId::default(),
        operation: operation.clone(),
        resource: resource.clone(),
        attributes: attributes.clone(),
        modality: Modality::May,
        request_assurance: RequestAssurance::Conservative,
        condition: None,
        realm: realm.clone(),
        execution: ExecutionNodeRef::default(),
        provenance: Vec::new(),
    }
}

#[test]
fn recursive_effect_extent_is_root_inclusive_bounded_and_realm_qualified() {
    let operation = Operation::new("filesystem.delete");
    let mut attrs = BTreeMap::from([("recursive".into(), AttrValue::Bool(true))]);
    let host = ExecutionRealm::Host;
    let bindings = Bindings::none(PathPlatform::Posix);
    let member = |path: &str| EffectQuery::Satisfies {
        concrete: QualifiedIdentity {
            realm: host.clone(),
            identity: ResourceIdentity::FsPath { path: path.into() },
        },
    };
    let contains = |root: &str| EffectQuery::Contains {
        scope: Scope {
            realm: Some(host.clone()),
            set: ScopeSet::FsSubtree { root: root.into() },
        },
    };
    for root in ["/tmp/out", "/tmp/[out]*", "/"] {
        let resource = ResourceExpr::Literal { value: root.into() };
        let target = effect_target(&operation, &resource, &attrs, &host);
        for path in [
            root.to_string(),
            format!("{}/.hidden/nested", root.trim_end_matches('/')),
        ] {
            assert!(matches!(
                member(&path).evaluate((&target).into(), &bindings),
                Match::Satisfied { .. }
            ));
        }
        assert!(matches!(
            contains(root).evaluate((&target).into(), &bindings),
            Match::Satisfied { .. }
        ));
        let exact = EffectQuery::Contains {
            scope: Scope {
                realm: Some(host.clone()),
                set: ScopeSet::Exact {
                    identity: ResourceIdentity::FsPath { path: root.into() },
                },
            },
        };
        assert_eq!(
            exact.evaluate((&target).into(), &bindings),
            Match::NotSatisfied
        );
    }
    let resource = ResourceExpr::Environment {
        name: "OUTPUT_DIR".into(),
    };
    let target = effect_target(&operation, &resource, &attrs, &host);
    assert_eq!(
        contains("/tmp").evaluate((&target).into(), &bindings),
        Match::Indeterminate {
            reason: MatchReason::Unbound {
                names: vec!["OUTPUT_DIR".into()]
            }
        }
    );
    let mut bound = bindings.clone();
    bound.env.insert(
        "OUTPUT_DIR".into(),
        Binding {
            value: "/tmp/out".into(),
            source: BindingSource::Observed,
        },
    );
    let result = contains("/tmp").evaluate((&target).into(), &bound);
    assert!(
        matches!(&result, Match::Satisfied { proof } if proof.steps.contains(&ProofStep::RecursiveExtent) && proof.steps.contains(&ProofStep::Binding { name: "OUTPUT_DIR".into(), source: BindingSource::Observed }))
    );
    assert!(!canonical_json(&result).contains("/tmp/out"));
    let foreign = ExecutionRealm::Container {
        runtime: "docker".into(),
        name: "c".into(),
    };
    assert_eq!(
        contains("/tmp").evaluate(
            (&Effect {
                realm: foreign,
                ..target.clone()
            })
                .into(),
            &bound
        ),
        Match::NotSatisfied
    );
    attrs.insert("recursive".into(), AttrValue::Bool(false));
    let resource = ResourceExpr::Literal {
        value: "/tmp/out".into(),
    };
    let target = effect_target(&operation, &resource, &attrs, &host);
    assert_eq!(
        member("/tmp/out/child").evaluate((&target).into(), &bindings),
        Match::NotSatisfied
    );
}

#[test]
fn recursive_unions_platform_roots_and_limits_preserve_three_valued_truth() {
    let operation = Operation::new("filesystem.delete");
    let attrs = BTreeMap::from([("recursive".into(), AttrValue::Bool(true))]);
    let realm = ExecutionRealm::Host;
    let bindings = Bindings::none(PathPlatform::Posix);
    let literal = |value: &str| ResourceExpr::Literal {
        value: value.into(),
    };
    let scope = Scope {
        realm: None,
        set: ScopeSet::FsSubtree {
            root: "/tmp".into(),
        },
    };
    let contains = EffectQuery::Contains {
        scope: scope.clone(),
    };
    let intersects = EffectQuery::Intersects { scope };
    let unresolved = ResourceExpr::Environment {
        name: "OUTPUT_DIR".into(),
    };
    for (alternatives, expected_contains, expected_intersects) in [
        (
            vec![literal("/tmp/a"), literal("/tmp/b")],
            "satisfied",
            "satisfied",
        ),
        (
            vec![literal("/outside"), literal("/tmp/a")],
            "not_satisfied",
            "satisfied",
        ),
        (
            vec![unresolved.clone(), literal("/tmp/a")],
            "indeterminate",
            "satisfied",
        ),
        (
            vec![unresolved.clone(), literal("/outside")],
            "not_satisfied",
            "indeterminate",
        ),
    ] {
        let resource = ResourceExpr::Union { alternatives };
        let target = effect_target(&operation, &resource, &attrs, &realm);
        assert_eq!(
            serde_json::to_value(contains.evaluate((&target).into(), &bindings)).unwrap()["kind"],
            expected_contains
        );
        let answer = intersects.evaluate((&target).into(), &bindings);
        assert_eq!(
            serde_json::to_value(&answer).unwrap()["kind"],
            expected_intersects
        );
        if let Match::Satisfied { proof } = answer {
            assert!(
                proof
                    .steps
                    .iter()
                    .any(|step| matches!(step, ProofStep::Alternative { .. }))
            );
        }
    }
    let patterned = ResourceExpr::Pattern {
        pattern: ResourcePattern::FsPath {
            glob: "/tmp/*".into(),
        },
    };
    let target = effect_target(&operation, &patterned, &attrs, &realm);
    assert!(matches!(
        contains.evaluate((&target).into(), &bindings),
        Match::Indeterminate {
            reason: MatchReason::UnsupportedShape
        }
    ));
    let malformed_extent = BTreeMap::from([("recursive".into(), AttrValue::String("true".into()))]);
    assert!(matches!(
        contains.evaluate(
            (&Effect {
                attributes: malformed_extent.clone(),
                ..target.clone()
            })
                .into(),
            &bindings
        ),
        Match::Indeterminate {
            reason: MatchReason::UnsupportedShape
        }
    ));
    let environment = Operation::new("environment.read");
    let variable = ResourceIdentity::EnvironmentVariable {
        name: "OUTPUT_DIR".into(),
    };
    let env_resource = ResourceExpr::Concrete {
        identity: variable.clone(),
    };
    let env_query = EffectQuery::Satisfies {
        concrete: QualifiedIdentity {
            realm: realm.clone(),
            identity: variable,
        },
    };
    assert!(matches!(
        env_query.evaluate(
            (&effect_target(&environment, &env_resource, &malformed_extent, &realm)).into(),
            &bindings
        ),
        Match::Satisfied { .. }
    ));
    let network = EffectQuery::Intersects {
        scope: Scope {
            realm: None,
            set: ScopeSet::Pattern {
                pattern: ResourcePattern::NetworkEndpoint {
                    host_glob: "*".into(),
                    scheme: Field::Any,
                    port: PortField::Any,
                    path_prefix: None,
                },
            },
        },
    };
    assert_eq!(
        network.evaluate(
            (&Effect {
                resource: unresolved.clone(),
                ..target.clone()
            })
                .into(),
            &bindings
        ),
        Match::NotSatisfied
    );
    let windows = Bindings::none(PathPlatform::Windows);
    for root in ["C:/", "//server/share/"] {
        let resource = literal(root);
        let query = EffectQuery::Satisfies {
            concrete: QualifiedIdentity {
                realm: realm.clone(),
                identity: ResourceIdentity::FsPath {
                    path: format!("{root}.hidden/deep"),
                },
            },
        };
        assert!(matches!(
            query.evaluate(
                (&Effect {
                    resource,
                    ..target.clone()
                })
                    .into(),
                &windows
            ),
            Match::Satisfied { .. }
        ));
    }
    let large = ResourceExpr::Union {
        alternatives: vec![literal("/tmp/a"); RELATION_BYTE_LIMIT / 64],
    };
    assert_eq!(
        contains.evaluate(
            (&Effect {
                resource: large,
                ..target.clone()
            })
                .into(),
            &bindings
        ),
        Match::Indeterminate {
            reason: MatchReason::Limit
        }
    );
    let mut deep = literal("/tmp/a");
    for _ in 0..RELATION_DEPTH_LIMIT {
        deep = ResourceExpr::Union {
            alternatives: vec![deep],
        };
    }
    assert_eq!(
        contains.evaluate(
            (&Effect {
                resource: deep,
                ..target.clone()
            })
                .into(),
            &bindings
        ),
        Match::Indeterminate {
            reason: MatchReason::Limit
        }
    );
}

// A relative selector must remain a valid effect check, with explicit cwd evidence.
#[test]
fn relative_effect_scopes_require_cwd_without_changing_resource_requests() {
    let operation = Operation::new("filesystem.delete");
    let attrs = BTreeMap::from([("recursive".into(), AttrValue::Bool(true))]);
    let resource = ResourceExpr::Literal {
        value: "/work/build/.hidden/nested".into(),
    };
    let host = ExecutionRealm::Host;
    let target = effect_target(&operation, &resource, &attrs, &host);
    let scope = Scope {
        realm: None,
        set: ScopeSet::FsSubtree {
            root: "build".into(),
        },
    };
    let unknown = Match::Indeterminate {
        reason: MatchReason::Unbound {
            names: vec!["cwd".into()],
        },
    };
    for query in [
        EffectQuery::Contains {
            scope: scope.clone(),
        },
        EffectQuery::Intersects {
            scope: scope.clone(),
        },
    ] {
        let mut bindings = Bindings::none(PathPlatform::Posix);
        assert_eq!(query.validate((&target).into(), &bindings), Ok(()));
        assert_eq!(query.evaluate((&target).into(), &bindings), unknown);
        for source in [BindingSource::Declared, BindingSource::Observed] {
            bindings.cwd = Some(Binding {
                value: "/work".into(),
                source: source.clone(),
            });
            let result = query.evaluate((&target).into(), &bindings);
            assert!(
                matches!(result, Match::Satisfied { proof } if proof.steps.contains(&ProofStep::Binding { name: "cwd".into(), source }))
            );
        }
        let foreign = ExecutionRealm::Container {
            runtime: "docker".into(),
            name: "c".into(),
        };
        assert_eq!(
            query.evaluate(
                (&Effect {
                    realm: foreign,
                    ..target.clone()
                })
                    .into(),
                &bindings
            ),
            unknown
        );
        let outside = ResourceExpr::Literal {
            value: "/outside".into(),
        };
        assert_eq!(
            query.evaluate(
                (&Effect {
                    resource: outside.clone(),
                    ..target.clone()
                })
                    .into(),
                &bindings
            ),
            Match::NotSatisfied
        );
        let other_operation = Operation::new("network.connect");
        assert_eq!(
            query.evaluate(
                (&Effect {
                    operation: other_operation,
                    ..target.clone()
                })
                    .into(),
                &Bindings::none(PathPlatform::Posix)
            ),
            Match::NotSatisfied
        );
    }
    assert_eq!(
        RelationRequest::Intersects {
            scope,
            expr: QualifiedExpr {
                realm: host,
                expr: resource
            },
            bindings: Bindings::none(PathPlatform::Posix)
        }
        .validate(),
        Err(MatchReason::InvalidInput)
    );
}
