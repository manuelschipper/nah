//! Labels and observed path kinds supplied by the consumer's label provider.

use std::collections::BTreeMap;

use effinterp_proto::{
    AttrValue, Bindings, ExecutionNodeRef, PathPlatform, Plan, ResourceExpr, ResourceFamily,
    ResourceIdentity, ResourcePattern, filesystem_path,
};

use super::{TestLabels, evaluate_with_labels, exists, label, plan, selector};
use crate::{
    Assertion, Closure, Evaluator, ObservationBinding, ObservedPathKind, Outcome, Query,
    QueryLimits, Refusal, ResourcePredicate, ResourceVariant, Unknown,
};

#[test]
fn nah_labels_are_typed_observation_bound_and_three_valued() {
    let plan = plan();
    let labeled = |label, observation: &str| {
        exists(selector(
            "filesystem.read",
            ResourcePredicate::Label {
                label,
                observation: ObservationBinding(observation.into()),
            },
        ))
    };
    let provider = TestLabels { available: true };
    assert!(matches!(
        evaluate_with_labels(
            &plan,
            labeled(label("credential-secret"), "policy"),
            &provider,
        ),
        Outcome::Match(_)
    ));
    assert_eq!(
        evaluate_with_labels(
            &plan,
            labeled(label("environment-secret"), "policy"),
            &provider,
        ),
        Outcome::NoMatch
    );
    assert_eq!(
        evaluate_with_labels(
            &plan,
            labeled(label("selects-home"), "policy"),
            &TestLabels { available: false },
        ),
        Outcome::Indeterminate(vec![Unknown::LabelObservationUnavailable {
            observation: ObservationBinding("policy".into()),
        }])
    );

    let mut schema_two = Query {
        schema_version: 2,
        assertion: labeled(label("selects-root"), "policy"),
    };
    assert!(matches!(
        schema_two.validate(),
        Err(Refusal::InvalidInput(_))
    ));
    schema_two.schema_version = 3;
    let Assertion::Effect { selector, .. } = &mut schema_two.assertion else {
        unreachable!()
    };
    selector.resource = ResourcePredicate::Label {
        label: label("system-scope"),
        observation: ObservationBinding(String::new()),
    };
    assert!(matches!(
        schema_two.validate(),
        Err(Refusal::InvalidInput(_))
    ));
}

#[test]
fn filesystem_descendants_inherit_observed_directory_labels() {
    let mut plan = plan();
    let read = plan
        .effects
        .iter_mut()
        .find(|effect| effect.operation.as_str() == "filesystem.read")
        .unwrap();
    read.resource = filesystem_path("/work/nested/key", None, PathPlatform::Posix);
    let label = label("credential-secret");
    let inherited = exists(selector(
        "filesystem.read",
        ResourcePredicate::InheritedLabel {
            label: label.clone(),
            observation: ObservationBinding("policy".into()),
        },
    ));
    let direct = exists(selector(
        "filesystem.read",
        ResourcePredicate::Label {
            label,
            observation: ObservationBinding("policy".into()),
        },
    ));
    assert!(matches!(
        evaluate_with_labels(&plan, inherited.clone(), &TestLabels { available: true }),
        Outcome::Match(_)
    ));
    assert_eq!(
        evaluate_with_labels(&plan, direct, &TestLabels { available: true }),
        Outcome::NoMatch
    );
    assert_eq!(
        evaluate_with_labels(&plan, inherited, &TestLabels { available: false }),
        Outcome::Indeterminate(vec![Unknown::LabelObservationUnavailable {
            observation: ObservationBinding("policy".into()),
        }])
    );
}

#[test]
fn labels_reach_pattern_and_union_selections_through_the_provider() {
    let mut plan = plan();
    let read = plan
        .effects
        .iter()
        .position(|effect| effect.operation.as_str() == "filesystem.read")
        .unwrap();
    plan.effects[read].resource = ResourceExpr::Pattern {
        pattern: ResourcePattern::FsPath {
            glob: "/work/*.key".into(),
            narrowing: Default::default(),
        },
    };
    let labeled = |label, inherited| {
        let observation = ObservationBinding("policy".into());
        exists(selector(
            "filesystem.read",
            if inherited {
                ResourcePredicate::InheritedLabel { label, observation }
            } else {
                ResourcePredicate::Label { label, observation }
            },
        ))
    };
    let credential = label("credential-secret");
    let environment = label("environment-secret");
    let available = TestLabels { available: true };
    assert!(matches!(
        evaluate_with_labels(&plan, labeled(credential.clone(), false), &available),
        Outcome::Match(_)
    ));
    assert_eq!(
        evaluate_with_labels(&plan, labeled(environment.clone(), false), &available),
        Outcome::NoMatch
    );
    let unavailable = Outcome::Indeterminate(vec![Unknown::LabelObservationUnavailable {
        observation: ObservationBinding("policy".into()),
    }]);
    assert_eq!(
        evaluate_with_labels(
            &plan,
            labeled(credential.clone(), false),
            &TestLabels { available: false },
        ),
        unavailable
    );
    // Schema 3 keeps its meaning: the provider is never asked.
    let schema_three = Query {
        schema_version: 3,
        assertion: labeled(credential.clone(), false),
    };
    let bindings = Bindings::from_subject(&plan.subject);
    assert_eq!(
        Evaluator::new(
            &plan,
            BTreeMap::from([(ExecutionNodeRef(0), bindings)]),
            &available,
            QueryLimits::default(),
        )
        .evaluate(&schema_three),
        Outcome::Indeterminate(vec![Unknown::ResourceIdentityUnavailable {
            variant: ResourceVariant::FsPath,
        }])
    );

    // A subtree is a directory paired with its descendants' pattern; the
    // provider receives it whole and says how it inherits.
    plan.effects[read].resource = ResourceExpr::Union {
        alternatives: vec![
            filesystem_path("/work/generated", None, PathPlatform::Posix),
            ResourceExpr::Pattern {
                pattern: ResourcePattern::FsPath {
                    glob: "/work/generated/**".into(),
                    narrowing: Default::default(),
                },
            },
        ],
    };
    assert!(matches!(
        evaluate_with_labels(&plan, labeled(environment.clone(), true), &available),
        Outcome::Match(_)
    ));
    assert_eq!(
        evaluate_with_labels(&plan, labeled(environment.clone(), false), &available),
        Outcome::NoMatch
    );
    assert_eq!(
        evaluate_with_labels(
            &plan,
            labeled(environment, true),
            &TestLabels { available: false },
        ),
        unavailable
    );
}

#[test]
fn observed_path_kinds_and_home_scope_come_from_the_provider() {
    // `mv /run/.env /backup`: the moved path and its destination are typed
    // by what the observation found there, never by their spelling.
    let mut plan = plan();
    let read = plan
        .effects
        .iter()
        .position(|effect| effect.operation.as_str() == "filesystem.read")
        .unwrap();
    let observed = |plan: &Plan, kind| {
        evaluate_with_labels(
            plan,
            Assertion::Effect {
                selector: selector(
                    "filesystem.read",
                    ResourcePredicate::ObservedPath {
                        kind,
                        observation: ObservationBinding("policy".into()),
                    },
                ),
                closure: Some(Closure::DomainFullOrBoundaryFree {
                    domain: "filesystem".into(),
                }),
            },
            &TestLabels { available: true },
        )
    };
    let at = |plan: &mut Plan, path: &str| {
        plan.effects[read].resource = filesystem_path(path, None, PathPlatform::Posix);
    };
    // `/work/secret.key` is a file, so it is neither a directory nor missing.
    assert!(matches!(
        observed(&plan, ObservedPathKind::File),
        Outcome::Match(_)
    ));
    assert_eq!(
        observed(&plan, ObservedPathKind::Directory),
        Outcome::NoMatch
    );
    at(&mut plan, "/backup");
    assert!(matches!(
        observed(&plan, ObservedPathKind::Directory),
        Outcome::Match(_)
    ));
    at(&mut plan, "/gone");
    assert!(matches!(
        observed(&plan, ObservedPathKind::Missing),
        Outcome::Match(_)
    ));
    // A symbolic link is none of the kinds; an unobserved path is unknown.
    at(&mut plan, "/work/link");
    assert_eq!(
        observed(&plan, ObservedPathKind::Directory),
        Outcome::NoMatch
    );
    at(&mut plan, "/elsewhere");
    assert!(matches!(
        observed(&plan, ObservedPathKind::Directory),
        Outcome::Indeterminate(unknowns)
            if unknowns == [Unknown::LabelObservationUnavailable {
                observation: ObservationBinding("policy".into()),
            }]
    ));
    // A pattern is typed by the directory that bounds it.
    plan.effects[read].resource = ResourceExpr::Pattern {
        pattern: ResourcePattern::FsPath {
            glob: "/backup/*".into(),
            narrowing: Default::default(),
        },
    };
    assert!(matches!(
        observed(&plan, ObservedPathKind::Directory),
        Outcome::Match(_)
    ));
    plan.effects[read].resource = ResourceExpr::Pattern {
        pattern: ResourcePattern::FsPath {
            glob: "/work/*".into(),
            narrowing: Default::default(),
        },
    };
    assert!(matches!(
        observed(&plan, ObservedPathKind::Directory),
        Outcome::Indeterminate(_)
    ));

    // The home-scope label is a label like any other.
    let plan = self::plan();
    let home = |label| {
        evaluate_with_labels(
            &plan,
            Assertion::Effect {
                selector: selector(
                    "filesystem.read",
                    ResourcePredicate::Label {
                        label,
                        observation: ObservationBinding("policy".into()),
                    },
                ),
                closure: Some(Closure::DomainFullOrBoundaryFree {
                    domain: "filesystem".into(),
                }),
            },
            &TestLabels { available: true },
        )
    };
    assert!(matches!(home(label("home-scope")), Outcome::Match(_)));
    assert_eq!(home(label("selects-home")), Outcome::NoMatch);

    // An observed path kind needs schema 6. A label id is the consumer's
    // name, so the matcher gates no label on the schema version.
    let assertion = Assertion::Effect {
        selector: selector(
            "filesystem.read",
            ResourcePredicate::ObservedPath {
                kind: ObservedPathKind::Directory,
                observation: ObservationBinding("policy".into()),
            },
        ),
        closure: Some(Closure::DomainFullOrBoundaryFree {
            domain: "filesystem".into(),
        }),
    };
    assert_eq!(Query::new(assertion.clone()).validate(), Ok(()));
    let schema_six = Query {
        schema_version: 6,
        assertion: assertion.clone(),
    };
    assert_eq!(schema_six.validate(), Ok(()));
    let schema_five = Query {
        schema_version: 5,
        assertion,
    };
    assert!(matches!(
        schema_five.validate(),
        Err(Refusal::InvalidInput(_))
    ));
}

#[test]
fn git_tree_path_labels_select_the_read_path_of_the_repository() {
    let mut plan = plan();
    let read = plan
        .effects
        .iter()
        .position(|effect| effect.operation.as_str() == "filesystem.read")
        .unwrap();
    plan.effects[read].operation = effinterp_proto::Operation::new("git.read");
    plan.effects[read].resource = ResourceExpr::Concrete {
        identity: ResourceIdentity::GitRepository {
            worktree: Some(Box::new(filesystem_path(
                "/work",
                None,
                PathPlatform::Posix,
            ))),
            git_dir: None,
            pathspec: None,
        },
    };
    plan.effects[read]
        .attributes
        .insert("path".into(), AttrValue::String(".env".into()));
    let labeled = |label| {
        exists(selector(
            "git.read",
            ResourcePredicate::GitTreePathLabel {
                label,
                observation: ObservationBinding("policy".into()),
            },
        ))
    };
    let environment = label("environment-secret");
    let credential = label("credential-secret");
    let available = TestLabels { available: true };
    assert!(matches!(
        evaluate_with_labels(&plan, labeled(environment.clone()), &available),
        Outcome::Match(_)
    ));
    assert_eq!(
        evaluate_with_labels(&plan, labeled(credential.clone()), &available),
        Outcome::NoMatch
    );
    assert_eq!(
        evaluate_with_labels(
            &plan,
            labeled(environment.clone()),
            &TestLabels { available: false },
        ),
        Outcome::Indeterminate(vec![Unknown::LabelObservationUnavailable {
            observation: ObservationBinding("policy".into()),
        }])
    );
    plan.effects[read].attributes.remove("path");
    assert_eq!(
        evaluate_with_labels(&plan, labeled(environment.clone()), &available),
        Outcome::Indeterminate(vec![Unknown::AttributeAbsent {
            name: "path".into(),
        }])
    );
    plan.effects[read].resource = ResourceExpr::Unresolved {
        family: ResourceFamily::new("git"),
    };
    assert_eq!(
        evaluate_with_labels(&plan, labeled(environment.clone()), &available),
        Outcome::Indeterminate(vec![Unknown::GitRepositoryUnavailable])
    );

    let schema_three = Query {
        schema_version: 3,
        assertion: labeled(environment),
    };
    assert!(matches!(
        schema_three.validate(),
        Err(Refusal::InvalidInput(_))
    ));
}

#[test]
fn whole_environment_labels_come_from_the_provider() {
    let mut plan = plan();
    let read = plan
        .effects
        .iter()
        .position(|effect| effect.operation.as_str() == "filesystem.read")
        .unwrap();
    plan.effects[read].operation = effinterp_proto::Operation::new("environment.read");
    plan.effects[read].resource = ResourceExpr::Pattern {
        pattern: ResourcePattern::EnvironmentVariable {
            name_glob: "*".into(),
        },
    };
    let labeled = |label| {
        exists(selector(
            "environment.read",
            ResourcePredicate::Label {
                label,
                observation: ObservationBinding("policy".into()),
            },
        ))
    };
    let environment = label("environment-secret");
    let available = TestLabels { available: true };
    assert!(matches!(
        evaluate_with_labels(&plan, labeled(environment.clone()), &available),
        Outcome::Match(_)
    ));
    assert_eq!(
        evaluate_with_labels(&plan, labeled(label("credential-secret")), &available,),
        Outcome::NoMatch
    );
    assert_eq!(
        evaluate_with_labels(
            &plan,
            labeled(environment.clone()),
            &TestLabels { available: false },
        ),
        Outcome::Indeterminate(vec![Unknown::LabelObservationUnavailable {
            observation: ObservationBinding("policy".into()),
        }])
    );
    // A narrower name pattern is not the whole environment and keeps
    // its schema-3 meaning.
    plan.effects[read].resource = ResourceExpr::Pattern {
        pattern: ResourcePattern::EnvironmentVariable {
            name_glob: "AWS_*".into(),
        },
    };
    assert_eq!(
        evaluate_with_labels(&plan, labeled(environment), &available),
        Outcome::NoMatch
    );
}
