//! Related effects: bindings, same-resource and plan-order relationships, and
//! scoped effects.

use std::collections::BTreeMap;

use effinterp_proto::{
    Bindings, Condition, ConditionKind, EffectId, EffectQuery, ExecutionAssurance,
    ExecutionNodeRef, ExecutionRealm, Modality, PathPlatform, RequestAssurance, ResourceExpr,
    ResourceIdentity, ResourcePattern, Scope, ScopeSet, filesystem_path,
};

use super::{condition, evaluate, exists, plan, relation_bindings, rendered, selector};
use crate::{
    Absence, Assertion, Closure, ConditionPredicate, EffectRelation, EffectRelationship, Evaluator,
    NO_LABELS, Outcome, Projection, Query, QueryLimits, Refusal, ResourcePredicate, SCHEMA_VERSION,
    TextPredicate, Unknown, Witness,
};

#[test]
fn effect_proof_dimensions_and_owning_bindings_stay_distinct() {
    let mut proof_plan = plan();
    let upload = proof_plan
        .effects
        .iter()
        .position(|effect| effect.operation.as_str() == "network.upload")
        .unwrap();
    proof_plan.effects[upload].request_assurance = RequestAssurance::Exact;
    let mut exact = selector(
        "network.upload",
        rendered(Projection::Resource, TextPredicate::Any),
    );
    exact.request_assurance = Some(RequestAssurance::Exact);
    exact.condition = Some(ConditionPredicate::Unconditional);
    exact.modality = Some(Modality::May);
    exact.execution_assurance = Some(ExecutionAssurance::Exact);
    assert!(matches!(
        evaluate(&proof_plan, exists(exact.clone())),
        Outcome::Match(_)
    ));

    proof_plan.effects[upload].condition = Some(Condition::Widened);
    assert_eq!(
        evaluate(&proof_plan, exists(exact.clone())),
        Outcome::NoMatch
    );
    proof_plan.effects[upload].condition = None;
    proof_plan.execution_graph.nodes[0].assurance = ExecutionAssurance::Alternatives;
    assert_eq!(evaluate(&proof_plan, exists(exact)), Outcome::NoMatch);

    let mut plan = plan();
    plan.execution_graph
        .nodes
        .push(plan.execution_graph.nodes[0].clone());
    let read = plan
        .effects
        .iter_mut()
        .find(|effect| effect.operation.as_str() == "filesystem.read")
        .unwrap();
    read.execution = ExecutionNodeRef(1);
    read.resource = filesystem_path("secret.key", None, PathPlatform::Posix);
    let contains = ResourcePredicate::Relation(Box::new(EffectQuery::Contains {
        scope: Scope {
            realm: Some(ExecutionRealm::Host),
            set: ScopeSet::FsSubtree {
                root: "/right".into(),
            },
        },
    }));
    let bindings = BTreeMap::from([
        (ExecutionNodeRef(0), relation_bindings("/wrong")),
        (ExecutionNodeRef(1), relation_bindings("/right")),
    ]);
    let evaluator = Evaluator::new(&plan, bindings, &NO_LABELS, QueryLimits::default());
    assert!(matches!(
        evaluator.evaluate(&Query::new(exists(selector("filesystem.read", contains)))),
        Outcome::Match(_)
    ));
}

#[test]
fn same_resource_relates_equal_concrete_identities_in_one_realm() {
    let mut plan = plan();
    let mut moved = plan
        .effects
        .iter()
        .find(|effect| effect.operation.as_str() == "filesystem.read")
        .unwrap()
        .clone();
    moved.id = EffectId("move".into());
    moved.operation = effinterp_proto::Operation::new("filesystem.move");
    plan.effects.push(moved);
    let relationship = EffectRelationship {
        same_execution: true,
        same_realm: false,
        same_resource: true,
        after: false,
    };
    let query = |relationship| Assertion::BindEffect {
        name: "read".into(),
        related: None,
        selector: selector("filesystem.read", ResourcePredicate::Any),
        closure: Some(Closure::DomainFullOrBoundaryFree {
            domain: "filesystem".into(),
        }),
        assertion: Box::new(Assertion::RelatedEffect {
            binding: "read".into(),
            relationship,
            selector: selector("filesystem.move", ResourcePredicate::Any),
            closure: Some(Closure::DomainFullOrBoundaryFree {
                domain: "filesystem".into(),
            }),
        }),
    };
    assert!(matches!(
        evaluate(&plan, query(relationship)),
        Outcome::Match(_)
    ));

    plan.effects.last_mut().unwrap().resource =
        filesystem_path("/work/backup", None, PathPlatform::Posix);
    assert_eq!(evaluate(&plan, query(relationship)), Outcome::NoMatch);
    plan.effects.last_mut().unwrap().resource = ResourceExpr::Pattern {
        pattern: ResourcePattern::FsPath {
            glob: "/work/*.key".into(),
            narrowing: Default::default(),
        },
    };
    assert_eq!(
        evaluate(&plan, query(relationship)),
        Outcome::Indeterminate(vec![Unknown::SameResourceUnavailable {
            effect: EffectId("move".into()),
        }])
    );
    // Two cloud resources of one kind whose IDs are unstated may differ.
    let unstated = ResourceExpr::Concrete {
        identity: ResourceIdentity::CloudResource {
            scope: Box::new(effinterp_proto::cloud_scope(
                Some("aws"),
                "dynamodb",
                "table",
            )),
            provider: Some("aws".into()),
            service: "dynamodb".into(),
            kind: "table".into(),
            id: None,
        },
    };
    let mut cloud = plan.clone();
    for effect in cloud.effects.iter_mut().filter(|effect| {
        matches!(
            effect.operation.as_str(),
            "filesystem.read" | "filesystem.move"
        )
    }) {
        effect.resource = unstated.clone();
    }
    assert_eq!(
        evaluate(&cloud, query(relationship)),
        Outcome::Indeterminate(vec![Unknown::SameResourceUnavailable {
            effect: EffectId("move".into()),
        }])
    );
    plan.effects.last_mut().unwrap().realm = ExecutionRealm::Remote {
        endpoint: "other".into(),
    };
    assert_eq!(evaluate(&plan, query(relationship)), Outcome::NoMatch);

    let schema_three = Query {
        schema_version: 3,
        assertion: query(relationship),
    };
    assert!(matches!(
        schema_three.validate(),
        Err(Refusal::InvalidInput(_))
    ));
    let empty = Query::new(query(EffectRelationship {
        same_execution: false,
        same_realm: false,
        same_resource: false,
        after: false,
    }));
    assert!(matches!(empty.validate(), Err(Refusal::InvalidInput(_))));
    // A schema-3 relationship without the field keeps deserializing.
    let json = r#"{"same_execution":true,"same_realm":true}"#;
    let relationship = serde_json::from_str::<EffectRelationship>(json).unwrap();
    assert!(!relationship.same_resource && !relationship.after);
}

#[test]
fn plan_order_relates_a_bound_move_to_the_reads_that_follow_it() {
    // `mv secret.key /tmp/k || cat secret.key`: the move's own source read,
    // the move, then a fallback read of the moved path in another call.
    let read = plan()
        .effects
        .into_iter()
        .find(|effect| effect.operation.as_str() == "filesystem.read")
        .unwrap();
    let effect = |id: &str, operation: &str| {
        let mut effect = read.clone();
        effect.id = EffectId(id.into());
        effect.operation = effinterp_proto::Operation::new(operation);
        effect
    };
    let mut fallback = effect("fallback", "filesystem.read");
    fallback.execution = ExecutionNodeRef(1);
    fallback.condition = Some(condition(ConditionKind::ShortCircuit, 0, Some(false)));
    let closure = || {
        Some(Closure::DomainFullOrBoundaryFree {
            domain: "filesystem".into(),
        })
    };
    let later = EffectRelationship {
        same_execution: false,
        same_realm: false,
        same_resource: true,
        after: true,
    };
    let query = |later| Assertion::BindEffect {
        name: "read".into(),
        related: None,
        selector: selector("filesystem.read", ResourcePredicate::Any),
        closure: closure(),
        assertion: Box::new(Assertion::BindEffect {
            name: "move".into(),
            related: Some(EffectRelation {
                binding: "read".into(),
                relationship: EffectRelationship {
                    same_execution: true,
                    same_realm: true,
                    same_resource: true,
                    after: false,
                },
            }),
            selector: selector("filesystem.move", ResourcePredicate::Any),
            closure: closure(),
            assertion: Box::new(Assertion::RelatedEffect {
                binding: "move".into(),
                relationship: later,
                selector: selector("filesystem.read", ResourcePredicate::Any),
                closure: closure(),
            }),
        }),
    };
    let related = |effects: Vec<effinterp_proto::Effect>| {
        let mut plan = plan();
        plan.effects = effects;
        match evaluate(&plan, query(later)) {
            Outcome::Match(Witness::BindEffect { witness, .. }) => match *witness {
                Witness::BindEffect { witness, .. } => match *witness {
                    Witness::RelatedEffect { effect } => Some(effect.0),
                    witness => panic!("{witness:?}"),
                },
                witness => panic!("{witness:?}"),
            },
            Outcome::NoMatch => None,
            outcome => panic!("{outcome:?}"),
        }
    };
    let (source, moved) = (
        effect("read", "filesystem.read"),
        effect("move", "filesystem.move"),
    );
    // A read after the move relates whatever its call or condition.
    assert_eq!(
        related(vec![source.clone(), moved.clone(), fallback.clone()]).as_deref(),
        Some("fallback")
    );
    // The move's own earlier source read never follows it.
    assert_eq!(related(vec![source.clone(), moved.clone()]), None);
    assert_eq!(
        related(vec![fallback.clone(), source.clone(), moved.clone()]),
        None
    );
    // A model that states the move first: its source read is the later read.
    assert_eq!(
        related(vec![moved.clone(), source.clone()]).as_deref(),
        Some("read")
    );
    // A related binding whose relation is unknown stays unknown.
    let mut pattern = moved.clone();
    pattern.resource = ResourceExpr::Pattern {
        pattern: ResourcePattern::FsPath {
            glob: "/work/*.key".into(),
            narrowing: Default::default(),
        },
    };
    let mut plan = plan();
    plan.effects = vec![source, pattern, fallback];
    assert_eq!(
        evaluate(&plan, query(later)),
        Outcome::Indeterminate(
            ["move", "fallback"]
                .map(|effect| Unknown::SameResourceUnavailable {
                    effect: EffectId(effect.into()),
                })
                .to_vec()
        )
    );

    // From schema 6 a move and read of one pattern spelled alike name one
    // resource; a schema-5 query keeps the concrete-only answer.
    let mut pattern_read = plan.effects[0].clone();
    pattern_read.resource = plan.effects[1].resource.clone();
    plan.effects = vec![pattern_read, plan.effects[1].clone()];
    let same = |schema_version| {
        let query = Query {
            schema_version,
            assertion: Assertion::BindEffect {
                name: "read".into(),
                related: None,
                selector: selector("filesystem.read", ResourcePredicate::Any),
                closure: closure(),
                assertion: Box::new(same_path_move(closure())),
            },
        };
        let bindings = Bindings::from_subject(&plan.subject);
        Evaluator::new(
            &plan,
            [(ExecutionNodeRef(0), bindings)].into(),
            &NO_LABELS,
            QueryLimits::default(),
        )
        .evaluate(&query)
    };
    assert!(matches!(same(SCHEMA_VERSION), Outcome::Match(_)));
    assert_eq!(
        same(5),
        Outcome::Indeterminate(vec![Unknown::SameResourceUnavailable {
            effect: EffectId("move".into()),
        }])
    );

    // Plan order alone is a relationship, and both forms need schema 5.
    let order = EffectRelationship {
        same_resource: false,
        ..later
    };
    assert_eq!(Query::new(query(order)).validate(), Ok(()));
    for relationship in [order, later] {
        let schema_four = Query {
            schema_version: 4,
            assertion: query(relationship),
        };
        assert!(matches!(
            schema_four.validate(),
            Err(Refusal::InvalidInput(_))
        ));
    }
    let Assertion::BindEffect { assertion, .. } = query(later) else {
        unreachable!()
    };
    let Assertion::BindEffect { related, .. } = *assertion.clone() else {
        unreachable!()
    };
    let schema_four = Query {
        schema_version: 4,
        assertion: Assertion::BindEffect {
            name: "read".into(),
            related: None,
            selector: selector("filesystem.read", ResourcePredicate::Any),
            closure: closure(),
            assertion: Box::new(Assertion::BindEffect {
                name: "move".into(),
                related: related.clone(),
                selector: selector("filesystem.move", ResourcePredicate::Any),
                closure: closure(),
                assertion: Box::new(Assertion::Effect {
                    selector: selector("filesystem.read", ResourcePredicate::Any),
                    closure: closure(),
                }),
            }),
        },
    };
    assert!(matches!(
        schema_four.validate(),
        Err(Refusal::InvalidInput(_))
    ));
    // A related binding must name an enclosing binding.
    let unbound = Query::new(*assertion);
    assert!(matches!(unbound.validate(), Err(Refusal::InvalidInput(_))));
}

fn same_path_move(closure: Option<Closure>) -> Assertion {
    Assertion::RelatedEffect {
        binding: "read".into(),
        relationship: EffectRelationship {
            same_execution: true,
            same_realm: true,
            same_resource: true,
            after: false,
        },
        selector: selector("filesystem.move", ResourcePredicate::Any),
        closure,
    }
}

#[test]
fn scoped_effects_can_be_related_but_never_selected_or_bound() {
    // `mv /repo/.env /tmp/e || /opt/tools/cat /repo/.env`: Nah never binds
    // the untrusted tool's read, but it is still a later read of the path.
    let mut plan = plan();
    let read = plan
        .effects
        .iter()
        .position(|effect| effect.operation.as_str() == "filesystem.read")
        .unwrap();
    let mut moved = plan.effects[read].clone();
    moved.id = EffectId("move".into());
    moved.operation = effinterp_proto::Operation::new("filesystem.move");
    let mut later = plan.effects[read].clone();
    later.id = EffectId("later".into());
    plan.effects = vec![moved, later];
    let bindings = Bindings::from_subject(&plan.subject);
    let evaluator = Evaluator::new(
        &plan,
        [(ExecutionNodeRef(0), bindings)].into(),
        &NO_LABELS,
        QueryLimits::default(),
    );
    let evaluate =
        |query: &Query, scope: &[usize]| evaluator.evaluate_in(query, scope, Absence::Conclusive);
    let related = Query::new(Assertion::BindEffect {
        name: "moved".into(),
        related: None,
        selector: selector("filesystem.move", ResourcePredicate::Any),
        closure: None,
        assertion: Box::new(Assertion::RelatedEffect {
            binding: "moved".into(),
            relationship: EffectRelationship {
                same_execution: false,
                same_realm: false,
                same_resource: true,
                after: true,
            },
            selector: selector("filesystem.read", ResourcePredicate::Any),
            closure: None,
        }),
    });
    assert!(matches!(evaluate(&related, &[0]), Outcome::Match(_)));
    let direct = Query::new(Assertion::Effect {
        selector: selector("filesystem.read", ResourcePredicate::Any),
        closure: None,
    });
    assert_eq!(evaluate(&direct, &[0]), Outcome::NoMatch);
    assert!(matches!(evaluate(&direct, &[0, 1]), Outcome::Match(_)));
    // A clause that binds nothing is answered per candidate effect: its
    // negation sees only the candidate, never the read beside it.
    let alone = Query::new(Assertion::All {
        assertions: vec![
            Assertion::Effect {
                selector: selector("filesystem.move", ResourcePredicate::Any),
                closure: None,
            },
            Assertion::Not {
                assertion: Box::new(direct.assertion.clone()),
            },
        ],
    });
    assert_eq!(evaluator.candidate_effects(&alone), vec![0, 1]);
    assert!(matches!(evaluate(&alone, &[0]), Outcome::Match(_)));
    assert_eq!(evaluate(&alone, &[0, 1]), Outcome::NoMatch);
    // The move itself left out: nothing binds it, so nothing relates to it.
    assert_eq!(evaluate(&related, &[1]), Outcome::NoMatch);
}
