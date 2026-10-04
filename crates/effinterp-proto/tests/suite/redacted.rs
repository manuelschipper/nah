// The fixture loader reads frozen documents from disk; the crate itself stays pure.
#![allow(clippy::disallowed_methods)]

use effinterp_proto::*;
use serde_json::{Value, json};
use std::{fs, path::PathBuf};

fn fixtures(directory: &str) -> Vec<PathBuf> {
    let mut paths: Vec<_> = fs::read_dir(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures")
            .join(directory),
    )
    .unwrap()
    .map(|p| p.unwrap().path())
    .filter(|p| p.extension().is_some_and(|ext| ext == "json"))
    .collect();
    paths.sort();
    assert!(!paths.is_empty());
    paths
}
fn plan() -> Plan {
    from_plan_json(
        &fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/exec-rm-recursive.json"),
        )
        .unwrap(),
    )
    .unwrap()
}

#[test]
fn redact_is_deterministic() {
    for path in fixtures("") {
        let plan = from_plan_json(&fs::read_to_string(path).unwrap()).unwrap();
        assert_eq!(redact_plan(&plan), redact_plan(&plan));
        assert_eq!(
            canonical_json(&redact_plan(&plan)),
            canonical_json(&redact_plan(&plan))
        );
    }
}
#[test]
fn every_plan_fixture_redacts_and_validates() {
    for path in fixtures("") {
        let plan = from_plan_json(&fs::read_to_string(path).unwrap()).unwrap();
        let view = redact_plan(&plan);
        validate_redacted(&view).unwrap();
        assert_eq!(
            serde_json::from_str::<RedactedPlan>(&canonical_json(&view)).unwrap(),
            view
        );
    }
}
#[test]
fn digest_correlates_equal_literals() {
    let shape = |value: &str| {
        let mut plan = plan();
        plan.effects[0].resource = ResourceExpr::Literal {
            value: value.into(),
        };
        redact_plan(&plan).effects.remove(0).resource
    };
    assert_eq!(shape("secret"), shape("secret"));
    assert_ne!(shape("secret"), shape("different"));
    for value in ["secret", ""] {
        let ResourceShape::Literal { digest } = shape(value) else {
            panic!()
        };
        assert_eq!(
            digest,
            stable_hash(REDACTED_LITERAL_HASH_DOMAIN, &value)[..23]
        );
    }
    let shape = |executable| {
        let mut plan = plan();
        plan.effects[0].resource = ResourceExpr::Pattern {
            pattern: ResourcePattern::Process {
                executable,
                argv_prefix: vec![ResourceExpr::Pattern {
                    pattern: ResourcePattern::FsPath {
                        glob: "/secret/*".into(),
                        narrowing: Default::default(),
                    },
                }],
            },
        };
        redact_plan(&plan).effects.remove(0).resource
    };
    let any = shape(TextField::Any);
    assert_eq!(any, shape(TextField::Any));
    assert_ne!(
        any,
        shape(TextField::Exact {
            value: "secret".into()
        })
    );
    assert!(!canonical_json(&any).contains("secret"));
}
#[test]
fn validate_redacted_rejects() {
    let mut plan = plan();
    plan.effects[0].attributes.insert(
        "selections".into(),
        AttrValue::List(vec![AttrValue::String("/SECRET_PATH".into())]),
    );
    plan.stamp_effect_ids().unwrap();
    let view = redact_plan(&plan);
    validate_redacted(&view).unwrap();
    assert!(!canonical_json(&view).contains("SECRET_PATH"));
    let raw = serde_json::to_value(&view).unwrap();
    let malformed: Vec<(&str, Value)> = vec![
        ("/schema", json!("wrong")),
        ("/execution_graph/entry", json!(999999)),
        ("/effects/0/execution", json!(999999)),
        ("/effects/0/provenance", json!([999999])),
        ("/execution_graph/nodes/0/boundary", json!(999999)),
        (
            "/effects/0/resource",
            json!({"expr":"concrete","identity":{"family":"fs_path","digest":"blake3:ab"}}),
        ),
        ("/effects/0/attributes", json!({"secret":"literal"})),
        ("/effects/0/attributes", json!({"secret":["literal"]})),
        (
            "/effects/0/condition",
            json!({"expression":"shell:/private"}),
        ),
        (
            "/causality/graph/nodes/0/condition",
            json!({"expression":"secret/path"}),
        ),
        (
            "/causality/graph/edges/0/condition",
            json!({"expression":"secret/path"}),
        ),
        // A transfer relates two resource interactions; relabeling any other
        // edge as one is corrupt transport, not a weaker claim.
        (
            "/causality/graph/edges/0/reason",
            json!("resource_transfer"),
        ),
        ("/effects/0/id", json!("effect:bad")),
        ("/effects/1/id", raw["effects"][0]["id"].clone()),
    ];
    for (path, value) in malformed {
        let mut changed = raw.clone();
        let (parent, field) = path.rsplit_once('/').unwrap();
        changed
            .pointer_mut(parent)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert(field.into(), value);
        if let Ok(changed) = serde_json::from_value::<RedactedPlan>(changed) {
            assert!(validate_redacted(&changed).is_err(), "accepted {path}");
        }
    }
    // Deserialization must reject literal-bearing additions even in flattened nodes.
    for path in [
        "/subject",
        "/effects/0",
        "/execution_graph/nodes/0",
        "/provenance/0",
        "/causality/graph/nodes/0",
    ] {
        let mut changed = raw.clone();
        changed
            .pointer_mut(path)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("source".into(), json!("SECRET"));
        assert!(
            serde_json::from_value::<RedactedPlan>(changed).is_err(),
            "accepted unknown field at {path}"
        );
    }
}
// A condition copied at any of these three sites can expose foreign-producer literals.
#[test]
fn condition_source_evidence_is_always_digested() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/symbolic-widened.json");
    let mut plan = from_plan_json(&fs::read_to_string(path).unwrap()).unwrap();
    let mut condition = Condition::from_source(
        "SECRET_PREDICATE",
        ByteSpan { start: 0, end: 16 },
        ConditionKind::Branch,
        0,
        2,
        true,
        true,
    );
    if let Condition::Atom { atom } = &mut condition {
        atom.evidence = ConditionEvidence::Source {
            path: Some("/SECRET_PATH/file.py".into()),
            excerpt: Some("SECRET_PREDICATE".into()),
        };
    }
    plan.effects[0].condition = Some(condition.clone());
    plan.causality
        .graph
        .as_mut()
        .expect("causality detail required")
        .nodes[1]
        .condition = Some(condition.clone());
    plan.causality
        .graph
        .as_mut()
        .expect("causality detail required")
        .edges[0]
        .condition = Some(condition.clone());
    plan.stamp_effect_ids().unwrap();
    let view = redact_plan(&plan);
    validate_redacted(&view).unwrap();
    let redacted = view.effects[0].condition.as_ref().unwrap();
    assert!(redacted.is_redacted());
    assert_eq!(redacted.identity(), condition.identity());
    let bytes = canonical_json(&view);
    assert!(!bytes.contains("SECRET_PREDICATE"));
    assert!(!bytes.contains("SECRET_PATH"));
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
    let minimal = redact_plan(&plan);
    validate_redacted(&minimal).unwrap();
    assert_eq!(
        minimal.effects[0].condition.as_ref().unwrap().identity(),
        condition.identity()
    );
}

#[test]
fn conformance_vectors_replay() {
    for directory in ["valid", "invalid"] {
        for path in fixtures(&format!("redacted-v1/{directory}")) {
            let case: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
            let plan = from_plan_json(&case["plan"].to_string()).unwrap();
            validate_plan(&plan).unwrap();
            let accepted = serde_json::from_value::<RedactedPlan>(case["expected"].clone())
                .is_ok_and(|expected| {
                    validate_redacted(&expected).is_ok() && expected == redact_plan(&plan)
                });
            assert_eq!(accepted, directory == "valid", "{}", path.display());
        }
    }
}

// New infrastructure identities and supporting-input provenance must not expose
// admitted paths, namespace names, or configuration addresses in audit records.
#[test]
fn infrastructure_and_source_input_redact_and_validate() {
    let literal = |value: &str| {
        Box::new(ResourceExpr::Literal {
            value: value.into(),
        })
    };
    let namespace = literal("private-namespace");
    let namespaces = [
        KubernetesNamespace::Cluster,
        KubernetesNamespace::Namespaced {
            namespace: namespace.clone(),
        },
        KubernetesNamespace::Unknown { namespace },
    ];
    let mut identities: Vec<_> = namespaces
        .into_iter()
        .map(|namespace| ResourceIdentity::KubernetesResource {
            api_group: "apps".into(),
            kind: "Deployment".into(),
            name: literal("private-deployment"),
            namespace,
            server: literal("https://private-cluster"),
            context: literal("private-context"),
        })
        .collect();
    identities.push(ResourceIdentity::ManagedInfrastructure {
        tool: "terraform".into(),
        configuration_root: literal("/private/configuration"),
        workspace: literal("private-workspace"),
        resource_type: Some("aws_instance".into()),
        address: Some("aws_instance.private_address".into()),
        instance: literal("private-instance"),
    });
    for identity in identities {
        let mut plan = plan();
        plan.effects[0].resource = ResourceExpr::Concrete { identity };
        let content_digest = canonical_hash(&"private-content");
        plan.provenance.push(ProvenanceNode {
            kind: ProvenanceKind::SourceInput {
                path: "/private/input.yaml".into(),
                digest: content_digest.clone(),
            },
            antecedents: vec![],
        });
        let view = redact_plan(&plan);
        validate_redacted(&view).unwrap();
        let json = canonical_json(&view);
        assert!(!json.contains("private"));
        assert_eq!(serde_json::from_str::<RedactedPlan>(&json).unwrap(), view);
        let raw = serde_json::to_value(&view).unwrap();
        let provenance = view.provenance.len() - 1;
        assert_eq!(raw["provenance"][provenance]["digest"], content_digest);
        let mut paths = vec![
            format!("/provenance/{provenance}/path"),
            format!("/provenance/{provenance}/digest"),
        ];
        match &view.effects[0].resource {
            ResourceShape::Concrete {
                identity: ResourceShapeIdentity::KubernetesResource { namespace, .. },
            } => {
                for field in ["name", "server", "context"] {
                    paths.push(format!("/effects/0/resource/identity/{field}/digest"));
                }
                if !matches!(namespace, RedactedKubernetesNamespace::Cluster) {
                    paths.push("/effects/0/resource/identity/namespace/namespace/digest".into());
                }
            }
            _ => {
                for field in ["configuration_root", "workspace", "instance"] {
                    paths.push(format!("/effects/0/resource/identity/{field}/digest"));
                }
                paths.push("/effects/0/resource/identity/address".into());
            }
        }
        for path in paths {
            let mut changed = raw.clone();
            *changed.pointer_mut(&path).unwrap() = json!("private-literal");
            let changed = serde_json::from_value::<RedactedPlan>(changed).unwrap();
            assert!(validate_redacted(&changed).is_err(), "accepted {path}");
        }
    }
}
