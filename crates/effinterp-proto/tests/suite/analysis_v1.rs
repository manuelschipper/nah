// The fixture loader reads frozen documents from disk; the crate itself stays pure.
#![allow(clippy::disallowed_methods)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use effinterp_proto::{
    AnalysisStatus, AttrValue, ByteSpan, Condition, DispatchIdentity, ExecutionRealm, FactId,
    FactIdentity, HostContext, Modality, OccurrenceDescriptor, OccurrenceId, Operation,
    PartialReason, PathPlatform, ProtocolProvenanceKind, RepoQueryEnvelope, RepoQueryParseError,
    RepoQueryValidationError, ResourceExpr, ResourceIdentity, StaleReason, from_repo_query_json,
    stable_hash, validate_repo_query,
};
use serde_json::{Value, json};

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/analysis-v1")
}

fn fixture_paths() -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = fs::read_dir(fixture_dir().join("valid"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    paths.sort();
    paths
}

fn load(name: &str) -> RepoQueryEnvelope {
    from_repo_query_json(
        &fs::read_to_string(fixture_dir().join("valid").join(name))
            .expect("fixture must be readable"),
    )
    .expect("fixture must parse and validate")
}

fn reseal(value: Value) -> RepoQueryEnvelope {
    let mut envelope: RepoQueryEnvelope = serde_json::from_value(value).unwrap();
    envelope.reseal();
    envelope
}

#[test]
fn schema_and_rust_validator_accept_every_canonical_fixture() {
    let schema: Value = serde_json::from_str(
        &fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("analysis-v1.schema.json"))
            .unwrap(),
    )
    .unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let paths = fixture_paths();
    assert_eq!(paths.len(), 7);
    let mut payload_kinds = std::collections::BTreeSet::new();
    for path in paths {
        let text = fs::read_to_string(&path).unwrap();
        assert!(
            text.ends_with('\n'),
            "{} lacks its trailing LF",
            path.display()
        );
        let value: Value = serde_json::from_str(&text).unwrap();
        if let Err(error) = validator.validate(&value) {
            panic!("{} fails JSON Schema: {error}", path.display());
        }
        let envelope: RepoQueryEnvelope = from_repo_query_json(&text)
            .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        payload_kinds.insert(serde_json::to_string(&envelope.payload_kind).unwrap());
        match envelope.payload_kind {
            effinterp_proto::PayloadKind::Reach => {
                assert!(
                    value["payload"]["indeterminate"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|row| row["row_kind"] == "effect")
                );
                assert!(
                    !value["payload"]["indeterminate"]
                        .as_array()
                        .unwrap()
                        .is_empty()
                );
            }
            effinterp_proto::PayloadKind::Effects => {}
        }
        assert_eq!(envelope.to_canonical_json(), text, "{}", path.display());
    }
    assert_eq!(payload_kinds.len(), 2);
    for name in [
        "payload_entrypoint_type.json",
        "payload_unknown_field.json",
        "payload_boundary_type.json",
        "payload_duplicate.json",
        "payload_kind.json",
        "payload_operation_filter.json",
        "payload_provenance_type.json",
        "payload_realm_shape.json",
        "payload_resource_shape.json",
        "legacy_row_shape.json",
        "payload_selector.json",
    ] {
        let value: Value = serde_json::from_str(
            &fs::read_to_string(fixture_dir().join("invalid").join(name)).unwrap(),
        )
        .unwrap();
        assert!(validator.validate(&value).is_err(), "{name}");
    }
}

#[test]
fn source_subject_schema_keeps_language_dialects_closed() {
    let schema: Value = serde_json::from_str(
        &fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("analysis-v1.schema.json"))
            .unwrap(),
    )
    .unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let mut envelope = load("minimal.json");
    let effinterp_proto::Subject::Source {
        context,
        dialect,
        language,
        ..
    } = &mut envelope.subjects[0].subject
    else {
        panic!("minimal fixture must use a source subject");
    };
    *context = HostContext {
        env: BTreeMap::from([("HOME".to_string(), "/home/test".to_string())]),
        env_unset: ["XDG_CONFIG_HOME".to_owned()].into_iter().collect(),
        ..Default::default()
    };
    *dialect = Some(effinterp_proto::SourceDialect::Ipython);
    *language = "python".to_string();
    envelope.subjects[0].subject_digest = stable_hash(
        "effinterp/analysis-subject/v1",
        &envelope.subjects[0].subject,
    );
    envelope.reseal();

    validate_repo_query(&envelope).unwrap();
    validator
        .validate(&serde_json::to_value(&envelope).unwrap())
        .unwrap();

    for (language, dialect, valid) in [
        ("python", None, true),
        ("python", Some("ipython"), true),
        ("python", Some("prime_agent"), true),
        ("python", Some("js"), false),
        ("js", None, false),
        ("js", Some("js"), true),
        ("js", Some("ipython"), false),
        ("ruby", None, true),
        ("ruby", Some("ipython"), false),
    ] {
        let mut value = serde_json::to_value(&envelope).unwrap();
        value["subjects"][0]["subject"]["language"] = json!(language);
        let subject = value["subjects"][0]["subject"].as_object_mut().unwrap();
        if let Some(dialect) = dialect {
            subject.insert("dialect".to_string(), json!(dialect));
        } else {
            subject.remove("dialect");
        }
        assert_eq!(
            validator.validate(&value).is_ok(),
            valid,
            "{language:?} {dialect:?}"
        );
    }
}

#[test]
fn sql_subject_schema_accepts_every_serialized_dialect() {
    use effinterp_proto::{SqlConnection, SqlDialect, Subject};

    let schema: Value = serde_json::from_str(
        &fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("analysis-v1.schema.json"))
            .unwrap(),
    )
    .unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    for dialect in [
        SqlDialect::Postgres,
        SqlDialect::Mysql,
        SqlDialect::Sqlite,
        SqlDialect::Generic,
        SqlDialect::TSql,
        SqlDialect::Snowflake,
        SqlDialect::BigQuery,
        SqlDialect::ClickHouse,
        SqlDialect::Cql,
    ] {
        let mut envelope = load("minimal.json");
        envelope.subjects[0].subject = Subject::Sql {
            source: "DROP TABLE users".to_string(),
            dialect,
            connection: SqlConnection::default(),
        };
        envelope.subjects[0].subject_digest = stable_hash(
            "effinterp/analysis-subject/v1",
            &envelope.subjects[0].subject,
        );
        envelope.reseal();

        validate_repo_query(&envelope).unwrap();
        let value = serde_json::to_value(&envelope).unwrap();
        validator
            .validate(&value)
            .unwrap_or_else(|error| panic!("{dialect:?} fails JSON Schema: {error}"));
        let decoded: Subject =
            serde_json::from_value(value["subjects"][0]["subject"].clone()).unwrap();
        assert_eq!(decoded, envelope.subjects[0].subject);
    }
}

#[test]
fn rust_decoder_rejects_every_invalid_single_fault_fixture() {
    let mut paths: Vec<PathBuf> = fs::read_dir(fixture_dir().join("invalid"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    paths.sort();
    assert_eq!(paths.len(), 41);
    for path in paths {
        let text = fs::read_to_string(&path).unwrap();
        assert!(
            from_repo_query_json(&text).is_err(),
            "{} was accepted",
            path.display()
        );
    }
}

#[test]
fn fixtures_cover_status_and_provenance_vocabularies() {
    let partial = load("partial.json");
    let AnalysisStatus::Partial { reasons } = partial.status else {
        panic!("partial fixture must be partial");
    };
    assert!(
        reasons
            .iter()
            .any(|reason| matches!(reason, PartialReason::UnsupportedEvidence { .. }))
    );
    assert!(
        reasons
            .iter()
            .any(|reason| matches!(reason, PartialReason::UnanalyzedInput { .. }))
    );
    assert!(
        reasons
            .iter()
            .any(|reason| matches!(reason, PartialReason::AnalysisFailure { .. }))
    );
    assert!(
        reasons
            .iter()
            .any(|reason| matches!(reason, PartialReason::LimitReached { .. }))
    );
    assert!(
        reasons
            .iter()
            .any(|reason| matches!(reason, PartialReason::Truncated { .. }))
    );
    assert!(reasons.windows(2).any(|pair| matches!(
        pair,
        [
            PartialReason::AnalysisFailure {
                entrypoint: first_entrypoint,
                scope: first_scope,
            },
            PartialReason::AnalysisFailure {
                entrypoint: second_entrypoint,
                scope: second_scope,
            },
        ] if first_entrypoint == second_entrypoint
            && first_scope.graphs.len() > second_scope.graphs.len()
            && first_scope.graphs.starts_with(&second_scope.graphs)
    )));

    let stale = load("stale.json");
    let AnalysisStatus::Stale { reasons } = stale.status else {
        panic!("stale fixture must be stale");
    };
    assert!(
        reasons
            .iter()
            .any(|reason| matches!(reason, StaleReason::SnapshotSuperseded { .. }))
    );
    assert!(
        reasons
            .iter()
            .any(|reason| matches!(reason, StaleReason::InputChanged { .. }))
    );
    assert!(
        reasons
            .iter()
            .any(|reason| matches!(reason, StaleReason::AnalyzerChanged { .. }))
    );
    assert!(
        reasons
            .iter()
            .any(|reason| matches!(reason, StaleReason::ModelSetChanged { .. }))
    );

    let lifecycle = load("cross-runtime.json");
    for kind in [
        "entrypoint",
        "argument",
        "execution",
        "cross_file_call",
        "dispatch",
    ] {
        assert!(
            lifecycle
                .provenance
                .nodes
                .iter()
                .any(|node| node.occurrence.semantic_kind == kind)
        );
    }
    assert!(
        lifecycle
            .provenance
            .nodes
            .iter()
            .any(|node| { matches!(node.evidence, ProtocolProvenanceKind::Dispatch { .. }) })
    );

    // One typed resource per fact: already normalized, with no display or
    // expression twin beside it.
    let complete = load("minimal.json");
    let value = serde_json::to_value(&complete.payload).unwrap();
    let fact = value["effects"][0].as_object().unwrap();
    let resource: ResourceExpr = serde_json::from_value(fact["resource"].clone()).unwrap();
    assert_eq!(
        effinterp_proto::normalize_resource(resource.clone(), PathPlatform::Posix),
        resource
    );
    assert!(
        fact.keys()
            .all(|key| !key.starts_with("resource") || key == "resource")
    );
}

#[test]
fn status_evidence_hashes_and_provenance_fail_closed() {
    let partial = load("partial.json");
    let mut missing_reasons = serde_json::to_value(&partial).unwrap();
    missing_reasons["status"]
        .as_object_mut()
        .unwrap()
        .remove("reasons");
    assert!(matches!(
        from_repo_query_json(&serde_json::to_string(&missing_reasons).unwrap()),
        Err(RepoQueryParseError::Json(_))
    ));

    let mut bad_hash = load("minimal.json");
    bad_hash.content_hash = format!("blake3:{}", '0'.to_string().repeat(64));
    assert!(matches!(
        validate_repo_query(&bad_hash).unwrap_err().as_slice(),
        [RepoQueryValidationError::ContentHashMismatch { .. }]
    ));

    let mut dangling = serde_json::to_value(load("minimal.json")).unwrap();
    dangling["payload"]["effects"][0]["provenance_roots"] =
        json!([format!("occurrence:blake3:{}", '0'.to_string().repeat(64))]);
    assert!(probe(dangling).validate_err(|error| matches!(
        error,
        RepoQueryValidationError::DanglingProvenanceRef { .. }
    )));

    let mut dangling_occurrence = serde_json::to_value(load("minimal.json")).unwrap();
    dangling_occurrence["payload"]["effects"][0]["occurrence_id"] =
        json!(format!("occurrence:blake3:{}", '0'.to_string().repeat(64)));
    assert!(
        probe(dangling_occurrence)
            .validate_err(|error| matches!(error, RepoQueryValidationError::InvalidPayload { .. }))
    );

    let mut changed_boundary = serde_json::to_value(load("partial.json")).unwrap();
    changed_boundary["boundaries"][0]["detail"] = json!("different unresolved call");
    assert!(
        probe(changed_boundary).validate_err(|error| matches!(
            error,
            RepoQueryValidationError::InvalidBoundary { .. }
        ))
    );

    let mut cyclic = serde_json::to_value(load("cross-runtime.json")).unwrap();
    let existing = cyclic["provenance"]["edges"][0].clone();
    cyclic["provenance"]["edges"]
        .as_array_mut()
        .unwrap()
        .push(json!({"from": existing["to"], "kind": "supports", "to": existing["from"]}));
    assert!(
        probe(cyclic)
            .validate_err(|error| matches!(error, RepoQueryValidationError::CyclicProvenance))
    );
}

trait ValidationProbe {
    fn validate_err(&self, predicate: impl Fn(&RepoQueryValidationError) -> bool) -> bool;
}

fn probe(value: Value) -> Vec<RepoQueryValidationError> {
    match serde_json::from_value::<RepoQueryEnvelope>(value.clone()) {
        Ok(mut envelope) => {
            envelope.reseal();
            validate_repo_query(&envelope).unwrap_err()
        }
        Err(_) => match from_repo_query_json(&value.to_string()).unwrap_err() {
            RepoQueryParseError::Validation(errors) => errors,
            error => panic!("expected payload validation error: {error}"),
        },
    }
}

impl ValidationProbe for Vec<RepoQueryValidationError> {
    fn validate_err(&self, predicate: impl Fn(&RepoQueryValidationError) -> bool) -> bool {
        assert!(!self.is_empty());
        self.iter().any(predicate)
    }
}

impl ValidationProbe for RepoQueryEnvelope {
    fn validate_err(&self, predicate: impl Fn(&RepoQueryValidationError) -> bool) -> bool {
        validate_repo_query(self).unwrap_err().iter().any(predicate)
    }
}

#[test]
fn rejects_absolute_identity_invalid_facts_and_unreported_truncation() {
    let mut absolute = serde_json::to_value(load("minimal.json")).unwrap();
    absolute["provenance"]["nodes"][0]["occurrence"]["origin"] = json!("/src/main.rs");
    assert!(
        probe(absolute)
            .validate_err(|error| matches!(error, RepoQueryValidationError::AbsoluteOrigin { .. }))
    );

    let mut bad_operation = serde_json::to_value(load("minimal.json")).unwrap();
    bad_operation["payload"]["effects"][0]["operation"] = json!("DELETE");
    assert!(probe(bad_operation).validate_err(|error| matches!(
        error,
        RepoQueryValidationError::InvalidPayload { path } if path.ends_with(".operation")
    )));

    let mut bad_resource = serde_json::to_value(load("minimal.json")).unwrap();
    bad_resource["payload"]["effects"][0]["resource"] =
        json!({"expr": "union", "alternatives": []});
    assert!(probe(bad_resource).validate_err(|error| matches!(
        error,
        RepoQueryValidationError::InvalidPayload { path }
            if path.contains(".resource")
    )));

    let mut incomplete_fact = serde_json::to_value(load("minimal.json")).unwrap();
    incomplete_fact["payload"]["effects"][0]
        .as_object_mut()
        .unwrap()
        .remove("realm");
    assert!(probe(incomplete_fact).validate_err(|error| matches!(
        error,
        RepoQueryValidationError::InvalidPayload { path } if path.starts_with("payload.effects[0]")
    )));

    // One typed resource: a display string or a missing resource is not a
    // second accepted spelling of it.
    let mut display_resource = serde_json::to_value(load("minimal.json")).unwrap();
    display_resource["payload"]["effects"][0]["resource"] = json!("fs:/etc/shadow-LIE");
    assert!(probe(display_resource).validate_err(|error| matches!(
        error,
        RepoQueryValidationError::InvalidPayload { path } if path.starts_with("payload.effects[0]")
    )));

    let mut missing_resource = serde_json::to_value(load("minimal.json")).unwrap();
    missing_resource["payload"]["effects"][0]
        .as_object_mut()
        .unwrap()
        .remove("resource");
    assert!(probe(missing_resource).validate_err(|error| matches!(
        error,
        RepoQueryValidationError::InvalidPayload { path } if path.starts_with("payload.effects[0]")
    )));

    let mut incomplete_complete = serde_json::to_value(load("minimal.json")).unwrap();
    incomplete_complete["coverage"]["domains"]["filesystem"] = json!({"level": "partial"});
    assert!(probe(incomplete_complete).validate_err(|error| matches!(
        error,
        RepoQueryValidationError::InvalidPayload { path } if path == "coverage.filesystem"
    )));

    let mut truncated = serde_json::to_value(load("minimal.json")).unwrap();
    truncated["payload"]["truncated"] = json!(true);
    assert!(probe(truncated).validate_err(|error| matches!(
        error,
        RepoQueryValidationError::InvalidPayload { path } if path.starts_with("payload")
    )));
}

#[test]
fn payload_reference_types_and_identity_shapes_fail_closed() {
    // The retired row-level occurrence alias must not be readable again.
    let mut occurrence = serde_json::to_value(load("minimal.json")).unwrap();
    occurrence["payload"]["effects"][0]["occurrence_id"] =
        occurrence["payload"]["effects"][0]["provenance_roots"][0].clone();
    assert!(probe(occurrence).validate_err(|error| matches!(
        error,
        RepoQueryValidationError::InvalidPayload { path } if path.starts_with("payload.effects[0]")
    )));

    let mut boundary = serde_json::to_value(load("partial.json")).unwrap();
    boundary["payload"]["boundaries"][0]["boundary_id"] = Value::Null;
    assert!(probe(boundary).validate_err(|error| matches!(
        error,
        RepoQueryValidationError::InvalidPayload { path } if path.ends_with(".boundary_id")
    )));

    let mut roots = serde_json::to_value(load("minimal.json")).unwrap();
    roots["payload"]["effects"][0]["provenance_roots"] = Value::Null;
    assert!(probe(roots).validate_err(|error| matches!(
        error,
        RepoQueryValidationError::InvalidPayload { path }
            if path.ends_with(".provenance_roots")
    )));

    let mut realm = serde_json::to_value(load("minimal.json")).unwrap();
    realm["payload"]["effects"][0]["realm"]["unknown"] = json!(true);
    assert!(probe(realm).validate_err(|error| matches!(
        error,
        RepoQueryValidationError::InvalidPayload { path }
            if path.contains(".realm") || path.starts_with("payload.effects[0]")
    )));

    let mut resource = serde_json::to_value(load("minimal.json")).unwrap();
    resource["payload"]["effects"][0]["resource"]["identity"]["unknown"] = json!(true);
    assert!(probe(resource).validate_err(|error| matches!(
        error,
        RepoQueryValidationError::InvalidPayload { path }
            if path.contains(".resource") || path.starts_with("payload.effects[0]")
    )));
}

#[test]
fn typed_payload_selectors_filters_and_retired_origin_alias_fail_closed() {
    let mut selector = serde_json::to_value(load("reach.json")).unwrap();
    selector["payload"]["selector"] = json!("");
    assert!(probe(selector).validate_err(|error| matches!(
        error,
        RepoQueryValidationError::InvalidPayload { path } if path == "payload.selector"
    )));

    let mut filter = serde_json::to_value(load("reach.json")).unwrap();
    filter["payload"]["operation"] = json!("");
    assert!(probe(filter).validate_err(|error| matches!(
        error,
        RepoQueryValidationError::InvalidPayload { path } if path == "payload.selector"
    )));

    // The retired row-level `origin_file` alias must not be readable again;
    // its successor is `origin.source_file`. Source-dependency membership is
    // covered by the `invalid/payload_source_dependency.json` fixture.
    let mut source = serde_json::to_value(load("minimal.json")).unwrap();
    source["payload"]["effects"][0]["origin_file"] = json!("src/undeclared.rs");
    assert!(probe(source).validate_err(|error| matches!(
        error,
        RepoQueryValidationError::InvalidPayload { path } if path.ends_with(".origin_file")
    )));
}

#[test]
fn rust_validator_rejects_payload_values_outside_the_frozen_domains() {
    let cases = [(
        "minimal.json",
        "/payload/coverage/filesystem",
        json!("fullX"),
    )];
    for (fixture, pointer, replacement) in cases {
        let mut value = serde_json::to_value(load(fixture)).unwrap();
        *value.pointer_mut(pointer).unwrap() = replacement;
        assert!(!probe(value).is_empty(), "{fixture} {pointer}");
    }

    let mut mismatch = load("minimal.json");
    let effinterp_proto::Payload::Effects(payload) = &mut mismatch.payload else {
        panic!("effects fixture");
    };
    payload.coverage.get_mut("filesystem").unwrap().level = effinterp_proto::CoverageLevel::Partial;
    mismatch.reseal();
    assert!(validate_repo_query(&mismatch)
        .unwrap_err()
        .iter()
        .any(|error| matches!(error, RepoQueryValidationError::InvalidPayload { path } if path == "payload.coverage")));
}

#[test]
fn occurrence_fact_and_envelope_identity_are_deterministic_and_semantic() {
    let descriptor = OccurrenceDescriptor {
        input_digest: "input-digest".to_string(),
        origin: "src/main.rs".to_string(),
        span: ByteSpan { start: 1, end: 8 },
        semantic_kind: "call".to_string(),
        local_ordinal: 0,
    };
    assert_eq!(
        OccurrenceId::derive(&descriptor),
        OccurrenceId::derive(&descriptor)
    );
    let mut moved = descriptor.clone();
    moved.span.end += 1;
    assert_ne!(
        OccurrenceId::derive(&descriptor),
        OccurrenceId::derive(&moved)
    );

    let root = OccurrenceId::derive(&descriptor);
    let identity = FactIdentity {
        request_assurance: effinterp_proto::RequestAssurance::Conservative,
        operation: Operation::new("filesystem.write"),
        resource: ResourceExpr::Union {
            alternatives: vec![
                ResourceExpr::Literal {
                    value: "b".to_string(),
                },
                ResourceExpr::Literal {
                    value: "a".to_string(),
                },
            ],
        },
        realm: ExecutionRealm::Host,
        modality: Modality::May,
        attributes: BTreeMap::<String, AttrValue>::new(),
        condition: Some(Condition::Widened),
        provenance_roots: vec![root.clone()],
        dispatch: Some(DispatchIdentity {
            model: "fixture".to_string(),
            registration_roots: vec![root.clone()],
            dispatch_roots: vec![root],
        }),
    };
    let normalized = FactIdentity {
        resource: effinterp_proto::normalize_resource(
            identity.resource.clone(),
            PathPlatform::Posix,
        ),
        ..identity.clone()
    };
    assert_eq!(FactId::derive(&identity), FactId::derive(&normalized));
    let changed = FactIdentity {
        resource: ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath {
                path: "different".to_string(),
            },
        },
        ..identity
    };
    assert_ne!(FactId::derive(&normalized), FactId::derive(&changed));

    let envelope = load("minimal.json");
    assert_eq!(envelope.expected_content_hash(), envelope.content_hash);
    let mut changed = envelope.clone();
    let effinterp_proto::Payload::Effects(payload) = &mut changed.payload else {
        panic!("effects fixture");
    };
    payload.entrypoint = "src/changed.rs".into();
    changed.reseal();
    assert_ne!(changed.content_hash, envelope.content_hash);
}

#[test]
fn a_boundary_that_declares_a_domain_accounts_for_its_partial_coverage() {
    let mut value: Value = serde_json::from_str(
        &fs::read_to_string(fixture_dir().join("valid").join("partial.json")).unwrap(),
    )
    .unwrap();
    validate_repo_query(&reseal(value.clone())).expect("the boundary declares the partial domain");

    // Move the boundary off that domain and nothing explains the loss.
    value["boundaries"][0]["domains"] = json!(["network"]);
    assert!(validate_repo_query(&reseal(value)).is_err());
}

/// An effects payload repeats the envelope's domain coverage, so a coverage
/// edit must reach both before resealing.
fn mirror_payload_coverage(envelope: &mut RepoQueryEnvelope) {
    let effinterp_proto::Payload::Effects(payload) = &mut envelope.payload else {
        panic!("effects fixture");
    };
    payload.coverage = envelope.coverage.domains.clone();
    envelope.reseal();
}

#[test]
fn repository_claims_require_exact_stable_domain_gaps_and_boundary_classes() {
    let envelope = load("partial.json");
    let domain = envelope.boundaries[0].domains[0].clone();
    let original = serde_json::to_value(&envelope).unwrap();
    let gap = envelope.boundaries[0].id.clone();
    for gaps in [
        json!([]),
        json!([0]),
        json!([gap, gap]),
        json!(["boundary:blake3:deadbeef"]),
    ] {
        let mut value = original.clone();
        value["coverage"]["domains"][&domain]["gaps"] = gaps.clone();
        value["payload"]["coverage"][&domain]["gaps"] = gaps;
        match serde_json::from_value::<RepoQueryEnvelope>(value) {
            Err(_) => {}
            Ok(mut parsed) => {
                parsed.reseal();
                assert!(validate_repo_query(&parsed).is_err());
            }
        }
    }
    let mut multiple = envelope.clone();
    let mut extra = multiple.boundaries[0].clone();
    extra.detail = Some("a second contributing scope".to_string());
    extra.id = extra.expected_id();
    multiple.boundaries.push(extra.clone());
    multiple.boundaries.sort_by(|a, b| a.id.cmp(&b.id));
    multiple.coverage.domains.get_mut(&domain).unwrap().gaps = multiple
        .boundaries
        .iter()
        .map(|boundary| boundary.id.clone())
        .collect();
    let AnalysisStatus::Partial { reasons } = &mut multiple.status else {
        unreachable!()
    };
    reasons.push(PartialReason::UnsupportedEvidence {
        boundary_id: extra.id.clone(),
        scope: effinterp_proto::AffectedScope::all(vec![effinterp_proto::AnalysisGraph::Effects]),
    });
    reasons.sort_by_key(|reason| serde_json::to_string(reason).unwrap());
    mirror_payload_coverage(&mut multiple);
    validate_repo_query(&multiple).unwrap();
    multiple
        .coverage
        .domains
        .get_mut(&domain)
        .unwrap()
        .gaps
        .reverse();
    mirror_payload_coverage(&mut multiple);
    assert!(validate_repo_query(&multiple).is_err());

    let mut foreign = envelope.clone();
    extra.domains = vec!["network".to_string()];
    extra.affected_resource = None;
    extra.id = extra.expected_id();
    foreign.boundaries.push(extra.clone());
    foreign.boundaries.sort_by(|a, b| a.id.cmp(&b.id));
    foreign.coverage.domains.insert(
        "network".to_string(),
        effinterp_proto::CoverageClaim {
            level: effinterp_proto::CoverageLevel::Partial,
            gaps: vec![extra.id.clone()],
        },
    );
    let AnalysisStatus::Partial { reasons } = &mut foreign.status else {
        unreachable!()
    };
    reasons.push(PartialReason::UnsupportedEvidence {
        boundary_id: extra.id.clone(),
        scope: effinterp_proto::AffectedScope::all(vec![effinterp_proto::AnalysisGraph::Effects]),
    });
    reasons.sort_by_key(|reason| serde_json::to_string(reason).unwrap());
    mirror_payload_coverage(&mut foreign);
    validate_repo_query(&foreign).unwrap();
    foreign.coverage.domains.get_mut(&domain).unwrap().gaps = vec![extra.id];
    mirror_payload_coverage(&mut foreign);
    assert!(validate_repo_query(&foreign).is_err());

    let mut missing_claim = load("minimal.json");
    missing_claim.coverage.domains.clear();
    let effinterp_proto::Payload::Effects(payload) = &mut missing_claim.payload else {
        panic!("effects fixture");
    };
    payload.coverage.clear();
    missing_claim.reseal();
    assert!(validate_repo_query(&missing_claim).is_err());

    let mut changed_class = envelope.clone();
    changed_class.boundaries[0].class = effinterp_proto::BoundaryClass::Unsupported;
    changed_class.reseal();
    assert!(
        validate_repo_query(&changed_class)
            .unwrap_err()
            .iter()
            .any(|error| matches!(error, RepoQueryValidationError::InvalidBoundary { .. }))
    );
    for class in [None, Some(json!("guessed"))] {
        let mut value = original.clone();
        match class {
            Some(class) => value["boundaries"][0]["class"] = class,
            None => {
                value["boundaries"][0]
                    .as_object_mut()
                    .unwrap()
                    .remove("class");
            }
        }
        assert!(serde_json::from_value::<RepoQueryEnvelope>(value).is_err());
    }
    let mut old = envelope;
    old.schema = "effinterp/analysis/v1".to_string();
    old.reseal();
    assert!(from_repo_query_json(&old.to_canonical_json()).is_err());
}

#[test]
fn reach_row_order_preserves_provenance_distinct_facts() {
    let envelope = load("reach.json");
    let rows = &envelope.payload.as_reach().unwrap().matches;
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].fact.entrypoint, rows[1].fact.entrypoint);
    assert_eq!(rows[0].fact.operation, rows[1].fact.operation);
    assert_eq!(rows[0].fact.resource, rows[1].fact.resource);
    assert_eq!(rows[0].fact.realm, rows[1].fact.realm);
    assert_ne!(rows[0].fact.provenance_roots, rows[1].fact.provenance_roots);
    assert!(rows[0].fact.fact_id < rows[1].fact.fact_id);
    let invalid = fs::read_to_string(fixture_dir().join("invalid/reach_row_order.json")).unwrap();
    assert!(matches!(
        from_repo_query_json(&invalid),
        Err(RepoQueryParseError::Validation(errors))
            if errors == vec![RepoQueryValidationError::InvalidPayload {
                path: "payload.matches".into()
            }]
    ));
}
