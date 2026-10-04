//! Resource predicates: rendered text, attributes, list elements, typed fields
//! and shapes, realms and selections.

use std::collections::BTreeMap;

use effinterp_proto::{
    AttrValue, EffectQuery, ExecutionRealm, KubernetesNamespace, MatchReason, ResourceExpr,
    ResourceFamily, ResourceIdentity, Scope, ScopeSet,
};

use super::{evaluate, exists, plan, rendered, selector};
use crate::{
    Assertion, AttributePredicate, AttributeTest, ElementTest, KubernetesNamespacePredicate,
    OperationMatch, Outcome, Projection, Query, RealmPredicate, Refusal, ResourceField,
    ResourcePredicate, ResourceVariant, SelectionShape, TextPredicate, Truth, Unknown, Witness,
};

#[test]
fn operations_and_rendered_text_are_never_unknown() {
    let family = OperationMatch::Family("filesystem".into());
    assert!(family.matches("filesystem") && family.matches("filesystem.read"));
    assert!(!family.matches("filesystemx.read"));
    assert!(!OperationMatch::Family("filesyst".into()).matches("filesystem.read"));
    assert!(!OperationMatch::Exact("filesystem".into()).matches("filesystem.read"));
    for (predicate, expected) in [
        (TextPredicate::Equals("/work/secret.key".into()), true),
        (TextPredicate::Equals("/work".into()), false),
        (TextPredicate::StartsWith("/work/".into()), true),
        (TextPredicate::StartsWith("secret".into()), false),
        (TextPredicate::Contains("secret".into()), true),
        (
            TextPredicate::ContainsAsciiCaseInsensitive("SECRET".into()),
            true,
        ),
        (TextPredicate::Any, true),
    ] {
        assert_eq!(
            predicate.matches("/work/secret.key"),
            expected,
            "{predicate:?}"
        );
    }

    // The realm-scoped projection prefixes a non-host realm; the resource
    // projection does not. Either is a plain text test, never unknown.
    let mut plan = plan();
    plan.effects[1].realm = ExecutionRealm::Container {
        runtime: "docker".into(),
        name: "c".into(),
    };
    let path = TextPredicate::Equals("/work/secret.key".into());
    let scoped = rendered(Projection::RealmScoped, path.clone());
    assert_eq!(
        evaluate(&plan, exists(selector("filesystem", scoped))),
        Outcome::NoMatch
    );
    let scoped = rendered(
        Projection::RealmScoped,
        TextPredicate::Equals("docker:c!/work/secret.key".into()),
    );
    assert!(matches!(
        evaluate(&plan, exists(selector("filesystem", scoped))),
        Outcome::Match(Witness::Effect { effect }) if effect == plan.effects[1].id
    ));
    let unscoped = rendered(Projection::Resource, path);
    assert!(matches!(
        evaluate(&plan, exists(selector("filesystem", unscoped))),
        Outcome::Match(_)
    ));
}

#[test]
fn string_attribute_predicates_keep_missing_and_nontext_distinct() {
    let attributes = BTreeMap::from([(
        "query".to_string(),
        AttrValue::String("(?i)token=Ghp_Example".into()),
    )]);
    let predicate = |text| AttributePredicate {
        name: "query".into(),
        test: AttributeTest::Text(text),
    };
    assert_eq!(
        predicate(TextPredicate::ContainsAsciiCaseInsensitive("ghp_".into())).test(&attributes),
        Truth::True
    );
    assert_eq!(
        predicate(TextPredicate::Contains("GITHUB_PAT_".into())).test(&attributes),
        Truth::False
    );
    assert_eq!(
        predicate(TextPredicate::Contains("ghp_".into())).test(&BTreeMap::new()),
        Truth::Unknown(vec![Unknown::AttributeAbsent {
            name: "query".into(),
        }])
    );
    assert_eq!(
        predicate(TextPredicate::Any)
            .test(&BTreeMap::from([("query".into(), AttrValue::Bool(true))])),
        Truth::False
    );

    let mut selector = selector("filesystem.read", ResourcePredicate::Any);
    selector.attributes.push(predicate(TextPredicate::Any));
    let schema_two = Query {
        schema_version: 2,
        assertion: exists(selector),
    };
    assert!(matches!(
        schema_two.validate(),
        Err(Refusal::InvalidInput(_))
    ));
}

#[test]
fn list_element_predicates_keep_missing_scalar_and_empty_distinct() {
    let branch = |name: &str| AttrValue::String(name.into());
    let attributes = BTreeMap::from([
        (
            "destinations".to_string(),
            AttrValue::List(vec![branch("refs/heads/main"), branch("refs/heads/topic")]),
        ),
        ("remote".to_string(), branch("origin")),
        ("sources".to_string(), AttrValue::List(Vec::new())),
    ]);
    let test = |name: &str, test| {
        AttributePredicate {
            name: name.into(),
            test,
        }
        .test(&attributes)
    };
    let main = ElementTest::Equals(branch("refs/heads/main"));
    let heads = ElementTest::Text(TextPredicate::StartsWith("refs/heads/".into()));
    assert_eq!(
        test("destinations", AttributeTest::AnyElement(main.clone())),
        Truth::True
    );
    assert_eq!(
        test("destinations", AttributeTest::AllElements(main.clone())),
        Truth::False
    );
    assert_eq!(
        test("destinations", AttributeTest::AllElements(heads.clone())),
        Truth::True
    );
    assert_eq!(
        test("sources", AttributeTest::AnyElement(heads.clone())),
        Truth::False
    );
    assert_eq!(
        test("sources", AttributeTest::AllElements(heads)),
        Truth::True
    );
    assert_eq!(
        test("remote", AttributeTest::AnyElement(main.clone())),
        Truth::False
    );
    assert_eq!(
        test("lease_targets", AttributeTest::AnyElement(main)),
        Truth::Unknown(vec![Unknown::AttributeAbsent {
            name: "lease_targets".into()
        }])
    );

    let mut nested = selector("git.push_request", ResourcePredicate::Any);
    nested.attributes.push(AttributePredicate {
        name: "destinations".into(),
        test: AttributeTest::AnyElement(ElementTest::Equals(AttrValue::List(Vec::new()))),
    });
    assert!(matches!(
        Query::new(exists(nested)).validate(),
        Err(Refusal::InvalidInput(_))
    ));
}

#[test]
fn attribute_equality_keeps_absent_distinct_from_unequal() {
    let attributes = BTreeMap::from([("method".to_string(), AttrValue::String("DELETE".into()))]);
    let test = |name: &str, test| AttributePredicate {
        name: name.into(),
        test,
    };
    let delete = AttributeTest::Equals(AttrValue::String("DELETE".into()));
    assert_eq!(
        test("method", delete.clone()).test(&attributes),
        Truth::True
    );
    assert_eq!(
        test(
            "method",
            AttributeTest::Equals(AttrValue::String("GET".into()))
        )
        .test(&attributes),
        Truth::False
    );
    assert_eq!(
        test("mode", delete.clone()).test(&attributes),
        Truth::Unknown(vec![Unknown::AttributeAbsent {
            name: "mode".into()
        }])
    );
    assert_eq!(
        test("mode", AttributeTest::Present).test(&attributes),
        Truth::False
    );
    assert_eq!(
        test("mode", AttributeTest::RequiredPresent).test(&attributes),
        Truth::Unknown(vec![Unknown::AttributeAbsent {
            name: "mode".into()
        }])
    );
    assert_eq!(
        test(
            "method",
            AttributeTest::OneOf(vec![
                AttrValue::String("POST".into()),
                AttrValue::String("DELETE".into()),
            ])
        )
        .test(&attributes),
        Truth::True
    );

    // An unknown conjunct leaves the effect undecided, but a false
    // presence conjunct beside it disproves the effect.
    let plan = plan();
    let mut upload = selector(
        "network.upload",
        rendered(Projection::Resource, TextPredicate::Any),
    );
    upload.attributes = vec![test("method", delete)];
    assert_eq!(
        evaluate(&plan, exists(upload.clone())),
        Outcome::Indeterminate(vec![Unknown::AttributeAbsent {
            name: "method".into()
        }])
    );
    upload
        .attributes
        .insert(0, test("method", AttributeTest::Present));
    assert_eq!(evaluate(&plan, exists(upload)), Outcome::NoMatch);
}

#[test]
fn typed_relations_come_from_the_resource_algebra() {
    let contains = |root: &str| {
        ResourcePredicate::Relation(Box::new(EffectQuery::Contains {
            scope: Scope {
                realm: Some(ExecutionRealm::Host),
                set: ScopeSet::FsSubtree { root: root.into() },
            },
        }))
    };
    let mut plan = plan();
    assert!(matches!(
        evaluate(
            &plan,
            exists(selector("filesystem.read", contains("/work")))
        ),
        Outcome::Match(_)
    ));
    assert_eq!(
        evaluate(
            &plan,
            exists(selector("filesystem.read", contains("/other")))
        ),
        Outcome::NoMatch
    );
    plan.effects[1].resource = ResourceExpr::Join {
        parts: vec![
            ResourceExpr::Environment {
                name: "HOME".into(),
            },
            ResourceExpr::Literal {
                value: "/secret.key".into(),
            },
        ],
    };
    assert!(matches!(
        evaluate(&plan, exists(selector("filesystem.read", contains("/work")))),
        Outcome::Indeterminate(unknowns)
            if matches!(unknowns[..], [Unknown::Relation(MatchReason::Unbound { .. })])
    ));
}

#[test]
fn typed_resource_fields_never_use_rendered_identity() {
    let mut plan = plan();
    let effect = plan
        .effects
        .iter()
        .position(|effect| effect.operation.as_str() == "filesystem.read")
        .unwrap();
    plan.effects[effect].operation = effinterp_proto::Operation::new("system.storage_destroy");
    plan.effects[effect].resource = ResourceExpr::Concrete {
        identity: ResourceIdentity::StorageVolume {
            manager: "zfs".into(),
            name: "pool@snapshot".into(),
        },
    };
    let storage = ResourcePredicate::StorageVolume {
        manager: Some(TextPredicate::Equals("zfs".into())),
        name: Some(TextPredicate::Contains("@".into())),
    };
    assert!(matches!(
        evaluate(
            &plan,
            exists(selector("system.storage_destroy", storage.clone()))
        ),
        Outcome::Match(_)
    ));
    assert!(matches!(
        evaluate(
            &plan,
            exists(selector(
                "system.storage_destroy",
                ResourcePredicate::Family {
                    family: "vol".into(),
                },
            ))
        ),
        Outcome::Match(_)
    ));
    assert_eq!(
        evaluate(
            &plan,
            exists(selector(
                "system.storage_destroy",
                ResourcePredicate::Family {
                    family: "host".into(),
                },
            ))
        ),
        Outcome::NoMatch
    );

    plan.effects[effect].resource = ResourceExpr::Literal {
        value: "vol:zfs/pool@snapshot".into(),
    };
    assert!(matches!(
        evaluate(
            &plan,
            exists(selector("system.storage_destroy", storage))
        ),
        Outcome::Indeterminate(unknowns)
            if unknowns == [Unknown::ResourceIdentityUnavailable {
                variant: ResourceVariant::StorageVolume,
            }]
    ));
    assert!(matches!(
        evaluate(
            &plan,
            exists(selector("system.storage_destroy", ResourcePredicate::Any))
        ),
        Outcome::Match(_)
    ));
}

#[test]
fn credential_and_environment_identity_use_exact_typed_fields() {
    let mut plan = plan();
    let effect = plan
        .effects
        .iter()
        .position(|effect| effect.operation.as_str() == "filesystem.read")
        .unwrap();
    plan.effects[effect].operation = effinterp_proto::Operation::new("credential.read");
    plan.effects[effect].resource = ResourceExpr::Concrete {
        identity: ResourceIdentity::CredentialStore {
            provider: "macos-keychain".into(),
            store: None,
            path: None,
        },
    };
    let credential = |provider: &str| {
        exists(selector(
            "credential.read",
            ResourcePredicate::Variant {
                variant: ResourceVariant::CredentialStore {
                    provider: provider.into(),
                },
            },
        ))
    };
    assert!(matches!(
        evaluate(&plan, credential("macos-keychain")),
        Outcome::Match(_)
    ));
    assert_eq!(evaluate(&plan, credential("pass")), Outcome::NoMatch);
    plan.effects[effect].resource = ResourceExpr::Unresolved {
        family: ResourceFamily::new("cred"),
    };
    assert_eq!(
        evaluate(&plan, credential("macos-keychain")),
        Outcome::Indeterminate(vec![Unknown::ResourceIdentityUnavailable {
            variant: ResourceVariant::CredentialStore {
                provider: "macos-keychain".into(),
            },
        }])
    );

    plan.effects[effect].operation = effinterp_proto::Operation::new("environment.read");
    plan.effects[effect].resource = ResourceExpr::Concrete {
        identity: ResourceIdentity::EnvironmentVariable {
            name: "GITHUB_TOKEN".into(),
        },
    };
    let environment = |name: &str| {
        exists(selector(
            "environment.read",
            ResourcePredicate::Variant {
                variant: ResourceVariant::EnvironmentVariable { name: name.into() },
            },
        ))
    };
    assert!(matches!(
        evaluate(&plan, environment("GITHUB_TOKEN")),
        Outcome::Match(_)
    ));
    assert_eq!(evaluate(&plan, environment("TOKEN")), Outcome::NoMatch);
    plan.effects[effect].resource = ResourceExpr::Unresolved {
        family: ResourceFamily::new("env"),
    };
    assert_eq!(
        evaluate(&plan, environment("GITHUB_TOKEN")),
        Outcome::Indeterminate(vec![Unknown::ResourceIdentityUnavailable {
            variant: ResourceVariant::EnvironmentVariable {
                name: "GITHUB_TOKEN".into(),
            },
        }])
    );

    let mut schema_two = Query {
        schema_version: 2,
        assertion: credential("macos-keychain"),
    };
    assert!(matches!(
        schema_two.validate(),
        Err(Refusal::InvalidInput(_))
    ));
    schema_two.schema_version = 3;
    let Assertion::Effect { selector, .. } = &mut schema_two.assertion else {
        unreachable!()
    };
    selector.resource = ResourcePredicate::Variant {
        variant: ResourceVariant::EnvironmentVariable {
            name: String::new(),
        },
    };
    assert!(matches!(
        schema_two.validate(),
        Err(Refusal::InvalidInput(_))
    ));
}

#[test]
fn typed_resource_shapes_keep_missing_fields_unknown() {
    let mut plan = plan();
    let effect = plan
        .effects
        .iter()
        .position(|effect| effect.operation.as_str() == "filesystem.read")
        .unwrap();
    plan.effects[effect].operation = effinterp_proto::Operation::new("container.resource.delete");
    plan.effects[effect].resource = ResourceExpr::Concrete {
        identity: ResourceIdentity::KubernetesResource {
            api_group: "apps".into(),
            kind: "Deployment".into(),
            name: Box::new(ResourceExpr::Unresolved {
                family: ResourceFamily::new("container"),
            }),
            namespace: KubernetesNamespace::Unknown {
                namespace: Box::new(ResourceExpr::Parameter { name: "ns".into() }),
            },
            server: Box::new(ResourceExpr::Parameter {
                name: "server".into(),
            }),
            context: Box::new(ResourceExpr::Parameter {
                name: "context".into(),
            }),
        },
    };
    plan.effects[effect]
        .attributes
        .insert("selection".into(), AttrValue::String("pattern".into()));
    let kubernetes = ResourcePredicate::KubernetesResource {
        namespace: Some(KubernetesNamespacePredicate::Namespaced),
        selection: Some(SelectionShape::Pattern),
    };
    assert!(matches!(
        evaluate(
            &plan,
            exists(selector("container.resource.delete", kubernetes.clone()))
        ),
        Outcome::Indeterminate(unknowns)
            if unknowns == [Unknown::ResourceFieldUnavailable {
                field: ResourceField::KubernetesNamespace,
            }]
    ));
    let ResourceExpr::Concrete {
        identity: ResourceIdentity::KubernetesResource { namespace, .. },
    } = &mut plan.effects[effect].resource
    else {
        unreachable!()
    };
    *namespace = KubernetesNamespace::Namespaced {
        namespace: Box::new(ResourceExpr::Literal {
            value: "prod".into(),
        }),
    };
    assert!(matches!(
        evaluate(
            &plan,
            exists(selector("container.resource.delete", kubernetes.clone()))
        ),
        Outcome::Match(_)
    ));
    plan.effects[effect].attributes.remove("selection");
    assert!(matches!(
        evaluate(
            &plan,
            exists(selector("container.resource.delete", kubernetes))
        ),
        Outcome::Indeterminate(unknowns)
            if unknowns == [Unknown::ResourceFieldUnavailable {
                field: ResourceField::KubernetesSelection,
            }]
    ));

    plan.effects[effect].operation = effinterp_proto::Operation::new("cloud.resource.delete");
    plan.effects[effect].resource = ResourceExpr::Concrete {
        identity: ResourceIdentity::ManagedInfrastructure {
            tool: "terraform".into(),
            configuration_root: Box::new(ResourceExpr::Literal { value: "/w".into() }),
            workspace: Box::new(ResourceExpr::Literal {
                value: "default".into(),
            }),
            resource_type: None,
            address: None,
            instance: Box::new(ResourceExpr::Unresolved {
                family: ResourceFamily::new("cloud"),
            }),
        },
    };
    let whole = ResourcePredicate::ManagedInfrastructure { whole_stack: true };
    assert!(matches!(
        evaluate(
            &plan,
            exists(selector("cloud.resource.delete", whole.clone()))
        ),
        Outcome::Indeterminate(_)
    ));
    plan.effects[effect]
        .attributes
        .insert("whole_stack".into(), AttrValue::Bool(true));
    assert!(matches!(
        evaluate(&plan, exists(selector("cloud.resource.delete", whole))),
        Outcome::Match(_)
    ));

    plan.effects[effect].resource = ResourceExpr::Concrete {
        identity: ResourceIdentity::CloudResource {
            scope: Box::new(effinterp_proto::cloud_scope(Some("gcp"), "compute", "disk")),
            provider: Some("gcp".into()),
            service: "compute".into(),
            kind: "disk".into(),
            id: Some("data".into()),
        },
    };
    let cloud = ResourcePredicate::CloudResource {
        provider: Some(TextPredicate::Equals("gcp".into())),
        service: None,
        kind: Some(TextPredicate::Equals("disk".into())),
    };
    assert!(matches!(
        evaluate(
            &plan,
            exists(selector("cloud.resource.delete", cloud.clone()))
        ),
        Outcome::Match(_)
    ));
    let ResourceExpr::Concrete {
        identity: ResourceIdentity::CloudResource { provider, .. },
    } = &mut plan.effects[effect].resource
    else {
        unreachable!()
    };
    *provider = None;
    assert!(matches!(
        evaluate(
            &plan,
            exists(selector("cloud.resource.delete", cloud))
        ),
        Outcome::Indeterminate(unknowns)
            if unknowns == [Unknown::ResourceFieldUnavailable {
                field: ResourceField::CloudProvider,
            }]
    ));
}

#[test]
fn realm_and_selection_predicates_are_typed_and_target_local() {
    let mut plan = plan();
    let effect = plan
        .effects
        .iter()
        .position(|effect| effect.operation.as_str() == "filesystem.read")
        .unwrap();
    let realms = [
        (RealmPredicate::Host, ExecutionRealm::Host),
        (
            RealmPredicate::Container,
            ExecutionRealm::Container {
                runtime: "docker".into(),
                name: "build".into(),
            },
        ),
        (
            RealmPredicate::Kubernetes,
            ExecutionRealm::Kubernetes {
                namespace: Some("prod".into()),
                pod: "worker".into(),
                container: Some("app".into()),
            },
        ),
        (
            RealmPredicate::Chroot,
            ExecutionRealm::Chroot {
                host_root: Some("/srv/root".into()),
            },
        ),
        (
            RealmPredicate::Remote,
            ExecutionRealm::Remote {
                endpoint: "host".into(),
            },
        ),
    ];
    for (expected, actual) in &realms {
        plan.effects[effect].realm = actual.clone();
        for (predicate, _) in &realms {
            let mut selector = selector("filesystem.read", ResourcePredicate::Any);
            selector.realm = Some(*predicate);
            assert_eq!(
                matches!(evaluate(&plan, exists(selector)), Outcome::Match(_)),
                predicate == expected
            );
        }
    }

    plan.effects[effect].realm = ExecutionRealm::Remote {
        endpoint: "host".into(),
    };
    let mut remote = selector("filesystem.read", ResourcePredicate::Any);
    remote.realm = Some(RealmPredicate::Remote);
    assert!(matches!(
        evaluate(&plan, exists(remote.clone())),
        Outcome::Match(_)
    ));

    plan.effects[effect].resource = ResourceExpr::Pattern {
        pattern: effinterp_proto::ResourcePattern::FsPath {
            glob: "/tmp/*".into(),
            narrowing: Default::default(),
        },
    };
    remote.resource = ResourcePredicate::Not {
        predicate: Box::new(ResourcePredicate::Selection {
            shape: SelectionShape::Pattern,
        }),
    };
    assert_eq!(evaluate(&plan, exists(remote.clone())), Outcome::NoMatch);
    plan.effects[effect].resource = ResourceExpr::Concrete {
        identity: ResourceIdentity::FsPath {
            path: "/tmp/file".into(),
        },
    };
    assert!(matches!(evaluate(&plan, exists(remote)), Outcome::Match(_)));
}
