use nah_proto::ctx::AbsolutePath;
use nah_proto::ctx::Ctx;
use nah_proto::ctx::Platform;
use nah_proto::ctx::SchemaVersion;
use nah_proto::ctx::ShippedGuardState;
use nah_proto::ctx::TrustProjection;
use nah_proto::ctx::derive_policy_ctx;
use nah_proto::observation::BindingError;
use nah_proto::observation::DescendantObservation;
use nah_proto::observation::EnvObservation;
use nah_proto::observation::MAX_DESCENDANT_PATH_BYTES;
use nah_proto::observation::MAX_DESCENDANT_PATHS;
use nah_proto::observation::Observation;
use nah_proto::observation::ObservationFact;
use nah_proto::observation::ObservationQuery;
use nah_proto::observation::ObservationRequest;
use nah_proto::observation::ObservationValue;
use nah_proto::observation::Observed;
use nah_proto::observation::PathKind;
use nah_proto::observation::PathObservation;
use nah_proto::observation::ProjectGuardDeclaration;
use nah_proto::observation::ProjectGuardObservation;
use nah_proto::observation::Root;
use nah_proto::observation::RootKind;
use nah_proto::observation::SymlinkTraversal;
use serde_json::json;

#[test]
fn observation_binding_is_exact_and_policy_projection_is_tighten_only() {
    let request = request();
    let present_observation = observation(ProjectGuardDeclaration::Present {
        names: vec!["unknown".into(), "secrets-env".into()],
    });
    present_observation.bind(&request).expect("exact binding");

    let ctx = Ctx::new(
        Platform::Linux,
        absolute("/home/test"),
        vec![
            ShippedGuardState::new("fs-system-tree", true).expect("shipped guard"),
            ShippedGuardState::new("secrets-env", false).expect("shipped guard"),
        ],
        Vec::new(),
        TrustProjection::new(Vec::new()).expect("trust"),
    )
    .expect("ctx");
    let derived = derive_policy_ctx(&ctx, &present_observation).expect("derive");
    assert_eq!(
        derived.policy_ctx().enabled_shipped_guards(),
        ["fs-system-tree", "secrets-env"]
    );
    assert_eq!(derived.unknown_declared_guards(), ["unknown"]);

    let explicitly_disabled = Ctx::new(
        Platform::Linux,
        absolute("/home/test"),
        vec![
            ShippedGuardState::new("fs-system-tree", true).unwrap(),
            ShippedGuardState::with_explicit_disable("secrets-env", false, true).unwrap(),
        ],
        Vec::new(),
        TrustProjection::new(Vec::new()).unwrap(),
    )
    .unwrap();
    let derived = derive_policy_ctx(&explicitly_disabled, &present_observation).unwrap();
    assert_eq!(
        derived.policy_ctx().enabled_shipped_guards(),
        ["fs-system-tree"]
    );
    assert_eq!(derived.unknown_declared_guards(), ["unknown"]);

    // A declaration nah cannot read or parse adds nothing; the globally
    // enabled guards still run.
    for declaration in [
        ProjectGuardDeclaration::ReadFailure,
        ProjectGuardDeclaration::Malformed,
        ProjectGuardDeclaration::Absent,
    ] {
        let derived =
            derive_policy_ctx(&ctx, &observation(declaration)).expect("derive declaration");
        assert_eq!(
            derived.policy_ctx().enabled_shipped_guards(),
            ["fs-system-tree"]
        );
        assert!(derived.unknown_declared_guards().is_empty());
    }
}

#[test]
fn observation_rejects_bad_typed_references_and_changed_facts() {
    let bad = ObservationRequest::new(
        SchemaVersion::V1,
        "r1",
        vec![
            ObservationQuery::Cwd {
                key: "cwd".into(),
                requested: absolute("/repo"),
            },
            ObservationQuery::Roots {
                key: "roots".into(),
                cwd_key: "wrong".into(),
            },
        ],
    );
    assert_eq!(
        bad.expect_err("invalid reference"),
        BindingError::InvalidReference
    );

    let internally_unbound = Observation::new(
        SchemaVersion::V1,
        "r1",
        vec![
            ObservationFact::new(
                ObservationQuery::Roots {
                    key: "roots".into(),
                    cwd_key: "missing".into(),
                },
                ObservationValue::Roots {
                    observed: Observed::Error {
                        error: nah_proto::observation::ObservationFailure::Unavailable,
                    },
                },
            )
            .unwrap(),
            ObservationFact::new(
                ObservationQuery::ProjectGuards {
                    key: "guards".into(),
                    roots_key: "roots".into(),
                },
                ObservationValue::ProjectGuards {
                    observation: ProjectGuardObservation::new(
                        None,
                        ProjectGuardDeclaration::ReadFailure,
                    )
                    .unwrap(),
                },
            )
            .unwrap(),
        ],
    );
    assert_eq!(internally_unbound, Err(BindingError::InvalidReference));

    let mut changed_queries = request().queries().to_vec();
    changed_queries.push(ObservationQuery::Env {
        key: "env".into(),
        name: "TOKEN".into(),
    });
    let changed = ObservationRequest::new(SchemaVersion::V1, "r1", changed_queries)
        .expect("valid changed request");
    assert_eq!(
        observation(ProjectGuardDeclaration::Absent)
            .bind(&changed)
            .expect_err("extra query must fail"),
        BindingError::RequestMismatch
    );
}

#[test]
fn env_only_request_and_observation_round_trip_and_bind_exactly() {
    let request = ObservationRequest::new(
        SchemaVersion::V1,
        "env-request",
        vec![
            ObservationQuery::Env {
                key: "token".into(),
                name: "TOKEN".into(),
            },
            ObservationQuery::Env {
                key: "optional".into(),
                name: "OPTIONAL".into(),
            },
        ],
    )
    .expect("env-only request");
    assert_eq!(
        serde_json::to_value(&request).unwrap(),
        json!({
            "v": 1,
            "request_id": "env-request",
            "queries": [
                {"kind":"env","key":"optional","name":"OPTIONAL"},
                {"kind":"env","key":"token","name":"TOKEN"}
            ]
        })
    );
    let observation = Observation::new(
        SchemaVersion::V1,
        "env-request",
        vec![
            ObservationFact::new(
                ObservationQuery::Env {
                    key: "token".into(),
                    name: "TOKEN".into(),
                },
                ObservationValue::Env {
                    observed: Observed::Ok {
                        value: EnvObservation::Value {
                            text: "secret".into(),
                        },
                    },
                },
            )
            .unwrap(),
            ObservationFact::new(
                ObservationQuery::Env {
                    key: "optional".into(),
                    name: "OPTIONAL".into(),
                },
                ObservationValue::Env {
                    observed: Observed::Ok {
                        value: EnvObservation::Unset,
                    },
                },
            )
            .unwrap(),
        ],
    )
    .expect("env-only observation");
    observation.bind(&request).expect("exact env binding");
    assert_eq!(
        serde_json::to_value(&observation).unwrap(),
        json!({
            "v": 1,
            "request_id": "env-request",
            "facts": [
                {
                    "query":{"kind":"env","key":"optional","name":"OPTIONAL"},
                    "value":{"kind":"env","status":"ok","value":{"kind":"unset"}}
                },
                {
                    "query":{"kind":"env","key":"token","name":"TOKEN"},
                    "value":{"kind":"env","status":"ok","value":{"kind":"value","text":"secret"}}
                }
            ]
        })
    );
    assert_eq!(
        serde_json::from_value::<ObservationRequest>(serde_json::to_value(&request).unwrap())
            .unwrap(),
        request
    );
    assert_eq!(
        serde_json::from_value::<Observation>(serde_json::to_value(&observation).unwrap()).unwrap(),
        observation
    );

    let changed = ObservationRequest::new(
        SchemaVersion::V1,
        "env-request",
        vec![
            ObservationQuery::Env {
                key: "optional".into(),
                name: "OPTIONAL".into(),
            },
            ObservationQuery::Env {
                key: "token".into(),
                name: "OTHER_TOKEN".into(),
            },
        ],
    )
    .unwrap();
    assert_eq!(
        observation.bind(&changed),
        Err(BindingError::RequestMismatch)
    );
}

#[test]
fn empty_and_partial_mixed_observation_shapes_remain_invalid() {
    assert_eq!(
        ObservationRequest::new(SchemaVersion::V1, "empty", vec![]),
        Err(BindingError::InvalidReference)
    );
    for queries in [
        vec![ObservationQuery::Cwd {
            key: "cwd".into(),
            requested: absolute("/repo"),
        }],
        vec![
            ObservationQuery::Env {
                key: "env".into(),
                name: "TOKEN".into(),
            },
            ObservationQuery::Cwd {
                key: "cwd".into(),
                requested: absolute("/repo"),
            },
        ],
        vec![
            ObservationQuery::Env {
                key: "env".into(),
                name: "TOKEN".into(),
            },
            ObservationQuery::Roots {
                key: "roots".into(),
                cwd_key: "missing".into(),
            },
        ],
    ] {
        assert_eq!(
            ObservationRequest::new(SchemaVersion::V1, "invalid", queries),
            Err(BindingError::InvalidReference)
        );
    }

    let mixed_observation = Observation::new(
        SchemaVersion::V1,
        "invalid",
        vec![
            ObservationFact::new(
                ObservationQuery::Env {
                    key: "env".into(),
                    name: "TOKEN".into(),
                },
                ObservationValue::Env {
                    observed: Observed::Ok {
                        value: EnvObservation::Unset,
                    },
                },
            )
            .unwrap(),
            ObservationFact::new(
                ObservationQuery::Cwd {
                    key: "cwd".into(),
                    requested: absolute("/repo"),
                },
                ObservationValue::Cwd {
                    observed: Observed::Ok {
                        value: absolute("/repo"),
                    },
                },
            )
            .unwrap(),
        ],
    );
    assert_eq!(mixed_observation, Err(BindingError::InvalidReference));
}

#[test]
fn observation_status_and_query_encodings_are_normative() {
    let query = ObservationQuery::Path {
        key: "p0".into(),
        requested: "src/lib.rs".into(),
        cwd_key: "cwd".into(),
        inspect_descendants: false,
        symlink_traversal: SymlinkTraversal::None,
    };
    assert_eq!(
        serde_json::to_string(&query).expect("query JSON"),
        r#"{"kind":"path","key":"p0","requested":"src/lib.rs","cwd_key":"cwd","inspect_descendants":false,"symlink_traversal":"none"}"#
    );
    let observed: Observed<AbsolutePath> = Observed::Ok {
        value: absolute("/repo"),
    };
    assert_eq!(
        serde_json::to_string(&observed).expect("status JSON"),
        r#"{"status":"ok","value":"/repo"}"#
    );
    assert_eq!(
        serde_json::to_value(ObservationValue::Env {
            observed: Observed::Ok {
                value: EnvObservation::Value {
                    text: "value".into(),
                },
            },
        })
        .unwrap(),
        json!({"kind":"env","status":"ok","value":{"kind":"value","text":"value"}})
    );
    assert_eq!(
        serde_json::to_value(ObservationValue::Path {
            observed: Observed::Ok {
                value: PathObservation::new(
                    absolute("/repo/link"),
                    Some(absolute("/repo/file")),
                    PathKind::Symlink,
                )
                .with_target_kind(PathKind::File),
            },
        })
        .unwrap(),
        json!({"kind":"path","status":"ok","value":{"resolved":"/repo/link","realpath":"/repo/file","kind":"symlink","target_kind":"file"}})
    );
}

#[test]
fn descendant_snapshots_are_bounded_and_exactly_requested() {
    let mut invalid_queries = request().queries().to_vec();
    invalid_queries.push(ObservationQuery::Path {
        key: "invalid".into(),
        requested: "src".into(),
        cwd_key: "cwd".into(),
        inspect_descendants: false,
        symlink_traversal: SymlinkTraversal::Root,
    });
    assert_eq!(
        ObservationRequest::new(SchemaVersion::V1, "r1", invalid_queries),
        Err(BindingError::InvalidReference)
    );

    let query = ObservationQuery::Path {
        key: "p0".into(),
        requested: "src".into(),
        cwd_key: "cwd".into(),
        inspect_descendants: true,
        symlink_traversal: SymlinkTraversal::None,
    };
    let absent = ObservationValue::Path {
        observed: Observed::Ok {
            value: PathObservation::new(
                absolute("/repo/src"),
                Some(absolute("/repo/src")),
                PathKind::Directory,
            ),
        },
    };
    assert_eq!(
        ObservationFact::new(query.clone(), absent),
        Err(BindingError::WrongValueKind)
    );

    let descendants =
        DescendantObservation::new(vec![absolute("/repo/src/z"), absolute("/repo/src/a")], true)
            .unwrap();
    assert_eq!(
        descendants.paths(),
        [absolute("/repo/src/a"), absolute("/repo/src/z")]
    );
    let value = ObservationValue::Path {
        observed: Observed::Ok {
            value: PathObservation::new(
                absolute("/repo/src"),
                Some(absolute("/repo/src")),
                PathKind::Directory,
            )
            .with_descendants(descendants),
        },
    };
    ObservationFact::new(query, value).expect("requested descendant fact");

    let too_many = (0..=MAX_DESCENDANT_PATHS)
        .map(|index| absolute(&format!("/repo/src/{index}")))
        .collect();
    assert_eq!(
        DescendantObservation::new(too_many, false),
        Err(BindingError::ExceedsLimit)
    );
    let long_name = "x".repeat((MAX_DESCENDANT_PATH_BYTES / MAX_DESCENDANT_PATHS) + 32);
    let too_wide = (0..MAX_DESCENDANT_PATHS)
        .map(|index| absolute(&format!("/repo/src/{index}/{long_name}")))
        .collect();
    assert_eq!(
        DescendantObservation::new(too_wide, false),
        Err(BindingError::ExceedsLimit)
    );
}

#[test]
fn observation_request_and_response_round_trip_canonically() {
    let request = request();
    let observation = observation(ProjectGuardDeclaration::Absent);
    assert_eq!(
        serde_json::to_value(&request).unwrap(),
        json!({
            "v": 1,
            "request_id": "r1",
            "queries": [
                {"kind":"cwd","key":"cwd","requested":"/repo"},
                {"kind":"project-guards","key":"guards","roots_key":"roots"},
                {"kind":"roots","key":"roots","cwd_key":"cwd"}
            ]
        })
    );
    assert_eq!(
        serde_json::to_value(&observation).unwrap(),
        json!({
            "v": 1,
            "request_id": "r1",
            "facts": [
                {
                    "query":{"kind":"cwd","key":"cwd","requested":"/repo"},
                    "value":{"kind":"cwd","status":"ok","value":"/repo"}
                },
                {
                    "query":{"kind":"project-guards","key":"guards","roots_key":"roots"},
                    "value":{"kind":"project-guards","root":{"kind":"project","path":"/repo"},"declaration":{"status":"absent"}}
                },
                {
                    "query":{"kind":"roots","key":"roots","cwd_key":"cwd"},
                    "value":{"kind":"roots","status":"ok","value":[{"kind":"project","path":"/repo"}]}
                }
            ]
        })
    );
    assert_eq!(
        serde_json::from_value::<ObservationRequest>(serde_json::to_value(&request).unwrap())
            .unwrap(),
        request
    );
    assert_eq!(
        serde_json::from_value::<Observation>(serde_json::to_value(&observation).unwrap()).unwrap(),
        observation
    );
}

fn request() -> ObservationRequest {
    ObservationRequest::new(
        SchemaVersion::V1,
        "r1",
        vec![
            ObservationQuery::ProjectGuards {
                key: "guards".into(),
                roots_key: "roots".into(),
            },
            ObservationQuery::Roots {
                key: "roots".into(),
                cwd_key: "cwd".into(),
            },
            ObservationQuery::Cwd {
                key: "cwd".into(),
                requested: absolute("/repo"),
            },
        ],
    )
    .expect("request")
}

fn observation(declaration: ProjectGuardDeclaration) -> Observation {
    let project = Root::new(RootKind::Project, absolute("/repo"));
    Observation::new(
        SchemaVersion::V1,
        "r1",
        vec![
            ObservationFact::new(
                ObservationQuery::ProjectGuards {
                    key: "guards".into(),
                    roots_key: "roots".into(),
                },
                ObservationValue::ProjectGuards {
                    observation: ProjectGuardObservation::new(Some(project.clone()), declaration)
                        .expect("guard observation"),
                },
            )
            .expect("guard fact"),
            ObservationFact::new(
                ObservationQuery::Roots {
                    key: "roots".into(),
                    cwd_key: "cwd".into(),
                },
                ObservationValue::Roots {
                    observed: Observed::Ok {
                        value: vec![project],
                    },
                },
            )
            .expect("roots fact"),
            ObservationFact::new(
                ObservationQuery::Cwd {
                    key: "cwd".into(),
                    requested: absolute("/repo"),
                },
                ObservationValue::Cwd {
                    observed: Observed::Ok {
                        value: absolute("/repo"),
                    },
                },
            )
            .expect("cwd fact"),
        ],
    )
    .expect("observation")
}

fn absolute(path: &str) -> AbsolutePath {
    AbsolutePath::new(Platform::Linux, path).expect("absolute path")
}
