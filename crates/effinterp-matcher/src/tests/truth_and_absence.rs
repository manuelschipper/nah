//! Three-valued truth: boolean composition, absence under a closure, coverage,
//! subject kinds, boundary evidence and refusals.

use std::collections::BTreeMap;

use effinterp_proto::{
    AttrValue, Bindings, BoundaryClass, BoundaryRef, CausalAssurance, CausalReason, Condition,
    ConditionKind, CoverageLevel, Domain, ExecutionNodeRef, OccurrenceId, Plan, Subject, ToolCall,
};

use super::{all_byte_edges, boundary, condition, evaluate, exists, plan, rendered, selector};
use crate::{
    Absence, Assertion, AttributePredicate, AttributeTest, BoundaryDomainsPredicate,
    BoundaryProvenancePredicate, ByteFlowAssurance, ConditionPredicate, Endpoint, Evaluator,
    NO_LABELS, NativeTool, Outcome, Projection, Query, QueryLimits, Refusal, ResourcePredicate,
    RouteProvenance, SCHEMA_VERSION, SubjectKind, TextPredicate, Traversal, Unknown, Witness,
};

#[test]
fn boolean_assertions_preserve_three_valued_logic() {
    let plan = plan();
    let mut undecided = selector(
        "network.upload",
        rendered(Projection::Resource, TextPredicate::Any),
    );
    undecided.attributes.push(AttributePredicate {
        name: "missing".into(),
        test: AttributeTest::Equals(AttrValue::Bool(true)),
    });
    let undecided = exists(undecided);
    let disproved = exists(selector(
        "filesystem.delete",
        rendered(Projection::Resource, TextPredicate::Any),
    ));
    let matched = exists(selector(
        "network.upload",
        rendered(Projection::Resource, TextPredicate::Any),
    ));

    assert_eq!(
        evaluate(
            &plan,
            Assertion::All {
                assertions: vec![undecided.clone(), disproved.clone()],
            }
        ),
        Outcome::NoMatch
    );
    assert!(matches!(
        evaluate(
            &plan,
            Assertion::Any {
                assertions: vec![undecided.clone(), matched],
            }
        ),
        Outcome::Match(Witness::Any { index: 1, .. })
    ));
    assert!(matches!(
        evaluate(
            &plan,
            Assertion::Not {
                assertion: Box::new(undecided),
            }
        ),
        Outcome::Indeterminate(_)
    ));
    assert_eq!(
        evaluate(
            &plan,
            Assertion::Not {
                assertion: Box::new(disproved),
            }
        ),
        Outcome::Match(Witness::Not)
    );
}

#[test]
fn success_path_requires_complete_positive_short_circuits() {
    let mut plan = plan();
    let upload = plan
        .effects
        .iter()
        .position(|effect| effect.operation.as_str() == "network.upload")
        .unwrap();
    let mut selector = selector("network.upload", ResourcePredicate::Any);
    selector.condition = Some(ConditionPredicate::SuccessPath);
    let assertion = || exists(selector.clone());

    assert!(matches!(evaluate(&plan, assertion()), Outcome::Match(_)));
    let positive = || condition(ConditionKind::ShortCircuit, 0, Some(true));
    plan.effects[upload].condition = Some(positive());
    assert!(matches!(evaluate(&plan, assertion()), Outcome::Match(_)));

    for composite in [
        Condition::All {
            conditions: vec![positive(), positive()],
        },
        Condition::Any {
            conditions: vec![positive(), positive()],
        },
    ] {
        plan.effects[upload].condition = Some(composite);
        assert!(matches!(evaluate(&plan, assertion()), Outcome::Match(_)));
    }

    for condition in [
        condition(ConditionKind::ShortCircuit, 0, Some(false)),
        condition(ConditionKind::ShortCircuit, 0, None),
        condition(ConditionKind::Branch, 0, Some(true)),
    ] {
        plan.effects[upload].condition = Some(condition);
        assert_eq!(evaluate(&plan, assertion()), Outcome::NoMatch);
    }

    plan.effects[upload].condition = Some(Condition::All {
        conditions: vec![positive(), Condition::Widened],
    });
    assert_eq!(
        evaluate(&plan, assertion()),
        Outcome::Indeterminate(vec![Unknown::ConditionIncomplete])
    );
    plan.effects[upload].condition = Some(Condition::Any {
        conditions: vec![
            Condition::Widened,
            condition(ConditionKind::ShortCircuit, 0, Some(false)),
        ],
    });
    assert_eq!(evaluate(&plan, assertion()), Outcome::NoMatch);

    let bindings = Bindings::from_subject(&plan.subject);
    let bounded = Evaluator::new(
        &plan,
        plan.execution_graph
            .nodes
            .iter()
            .enumerate()
            .map(|(index, _)| (ExecutionNodeRef(index as u32), bindings.clone()))
            .collect(),
        &NO_LABELS,
        QueryLimits {
            max_condition_depth: 0,
            ..QueryLimits::default()
        },
    );
    assert_eq!(
        bounded.evaluate(&Query::new(assertion())),
        Outcome::Refused(Refusal::WorkLimit)
    );
    // A complete condition admits either branch arm; the host decides whether
    // that arm is satisfiable.
    selector.condition = Some(ConditionPredicate::Complete);
    let assertion = || exists(selector.clone());
    for polarity in [true, false] {
        plan.effects[upload].condition = Some(condition(ConditionKind::Branch, 0, Some(polarity)));
        assert!(matches!(evaluate(&plan, assertion()), Outcome::Match(_)));
    }
    plan.effects[upload].condition = Some(Condition::All {
        conditions: vec![positive(), Condition::Widened],
    });
    assert_eq!(
        evaluate(&plan, assertion()),
        Outcome::Indeterminate(vec![Unknown::ConditionIncomplete])
    );
    let schema_six = Query {
        schema_version: 6,
        assertion: assertion(),
    };
    assert!(matches!(
        schema_six.validate(),
        Err(Refusal::InvalidInput(_))
    ));
}

#[test]
fn effect_absence_is_conclusive_only_under_its_closure() {
    let mut plan = plan();
    let delete = || {
        exists(selector(
            "filesystem.delete",
            rendered(Projection::RealmScoped, TextPredicate::Any),
        ))
    };
    assert_eq!(evaluate(&plan, delete()), Outcome::NoMatch);
    let filesystem = Domain("filesystem".into());
    plan.coverage.0.get_mut(&filesystem).unwrap().level = CoverageLevel::Partial;
    // A boundary-free plan's silence still counts under this closure.
    assert_eq!(evaluate(&plan, delete()), Outcome::NoMatch);
    plan.boundaries.push(boundary("unrelated", Vec::new()));
    assert_eq!(
        evaluate(&plan, delete()),
        Outcome::Indeterminate(vec![Unknown::DomainNotClosed {
            domain: "filesystem".into()
        }])
    );
    // Under conclusive absence the caller accounts for gaps: neither the
    // boundary nor Partial coverage is consulted, and a closure is refused
    // rather than silently ignored.
    let Assertion::Effect { selector, .. } = delete() else {
        unreachable!()
    };
    let conclusive = Query::new(Assertion::Effect {
        selector,
        closure: None,
    });
    let evaluator = Evaluator::new(&plan, BTreeMap::new(), &NO_LABELS, QueryLimits::default());
    let all = (0..plan.effects.len()).collect::<Vec<_>>();
    assert_eq!(
        evaluator.evaluate_in(&conclusive, &all, Absence::Conclusive),
        Outcome::NoMatch
    );
    assert!(matches!(
        evaluator.evaluate(&conclusive),
        Outcome::Refused(Refusal::InvalidInput(_))
    ));
    assert!(matches!(
        evaluator.evaluate_in(&Query::new(delete()), &all, Absence::Conclusive),
        Outcome::Refused(Refusal::InvalidInput(_))
    ));
    plan.coverage.0.get_mut(&filesystem).unwrap().level = CoverageLevel::Full;
    assert_eq!(evaluate(&plan, delete()), Outcome::NoMatch);
}

#[test]
fn subject_kinds_are_typed_and_an_untyped_tool_is_unknown() {
    let mut plan = plan();
    let subject = |kinds: Vec<SubjectKind>| Assertion::SubjectKind { kinds };
    let file_read = SubjectKind::NativeTool(NativeTool::FileRead);
    let fs_glob = SubjectKind::NativeTool(NativeTool::FsGlob);
    assert!(matches!(
        evaluate(&plan, subject(vec![SubjectKind::Exec])),
        Outcome::Match(_)
    ));
    assert_eq!(evaluate(&plan, subject(vec![file_read])), Outcome::NoMatch);

    plan.subject = Subject::ToolCall {
        call: ToolCall::FileRead(effinterp_proto::FileReadArgs {
            path: "/work/.env".into(),
            range: None,
        }),
        cwd: None,
        context: Default::default(),
    };
    assert_eq!(
        evaluate(&plan, subject(vec![fs_glob, file_read])),
        Outcome::Match(Witness::SubjectKind { kind: file_read })
    );
    assert_eq!(
        evaluate(&plan, subject(vec![SubjectKind::ShellCommand])),
        Outcome::NoMatch
    );

    plan.subject = Subject::ToolCall {
        call: ToolCall::Unknown(effinterp_proto::UnknownToolArgs {
            name: "Read".into(),
            args: serde_json::Value::Null,
        }),
        cwd: None,
        context: Default::default(),
    };
    assert_eq!(
        evaluate(&plan, subject(vec![file_read])),
        Outcome::Indeterminate(vec![Unknown::SubjectToolUnavailable])
    );
    assert_eq!(
        evaluate(&plan, subject(vec![SubjectKind::ShellCommand])),
        Outcome::NoMatch
    );

    for invalid in [
        Query {
            schema_version: 3,
            assertion: subject(vec![file_read]),
        },
        Query::new(subject(Vec::new())),
        Query::new(subject(vec![file_read, file_read])),
    ] {
        assert!(matches!(invalid.validate(), Err(Refusal::InvalidInput(_))));
    }
}

#[test]
fn coverage_holds_only_for_a_full_claim_without_gaps() {
    // `mv /run/.env /backup` decides on the engine's own filesystem claim.
    let full = |plan: &Plan| {
        evaluate(
            plan,
            Assertion::Coverage {
                domain: "filesystem".into(),
            },
        )
    };
    let mut plan = plan();
    assert_eq!(
        full(&plan),
        Outcome::Match(Witness::Coverage {
            domain: "filesystem".into()
        })
    );
    let claim = plan
        .coverage
        .0
        .get_mut(&Domain("filesystem".into()))
        .unwrap();
    claim.gaps.push(BoundaryRef(0));
    assert_eq!(full(&plan), Outcome::NoMatch);
    let claim = plan
        .coverage
        .0
        .get_mut(&Domain("filesystem".into()))
        .unwrap();
    claim.gaps.clear();
    claim.level = CoverageLevel::Partial;
    assert_eq!(full(&plan), Outcome::NoMatch);
    plan.coverage.0.remove(&Domain("filesystem".into()));
    assert_eq!(full(&plan), Outcome::NoMatch);

    let assertion = Assertion::Coverage {
        domain: "filesystem".into(),
    };
    let schema_five = Query {
        schema_version: 5,
        assertion,
    };
    assert!(matches!(
        schema_five.validate(),
        Err(Refusal::InvalidInput(_))
    ));
    assert!(matches!(
        Query::new(Assertion::Coverage { domain: "".into() }).validate(),
        Err(Refusal::InvalidInput(_))
    ));
}

#[test]
fn boundary_selectors_preserve_missing_evidence_as_unknown() {
    let mut plan = plan();
    let assertion = |domains, detail, provenance| Assertion::Boundary {
        reason: "dynamic_call".into(),
        class: Some(BoundaryClass::Unresolved),
        domains: Some(domains),
        detail,
        provenance,
    };
    let mut candidate = boundary("eval \"$x\"", Vec::new());
    candidate.domains = vec![Domain::new("process")];
    plan.boundaries.push(candidate);

    let any_domain =
        BoundaryDomainsPredicate::AnyOf(vec![Domain::new("filesystem"), Domain::new("process")]);
    assert_eq!(
        evaluate(&plan, assertion(any_domain, None, None)),
        Outcome::Match(Witness::Boundary {
            boundary: BoundaryRef(0)
        })
    );

    let all_domains =
        BoundaryDomainsPredicate::AllOf(vec![Domain::new("filesystem"), Domain::new("process")]);
    assert_eq!(
        evaluate(&plan, assertion(all_domains, None, None)),
        Outcome::NoMatch
    );

    let process = || BoundaryDomainsPredicate::AllOf(vec![Domain::new("process")]);
    assert_eq!(
        evaluate(
            &plan,
            assertion(
                process(),
                Some(TextPredicate::Contains("eval".into())),
                Some(BoundaryProvenancePredicate::Nonempty),
            ),
        ),
        Outcome::Indeterminate(vec![Unknown::BoundaryProvenanceUnavailable])
    );

    plan.boundaries[0].detail = None;
    assert_eq!(
        evaluate(
            &plan,
            assertion(
                process(),
                Some(TextPredicate::Contains("eval".into())),
                None,
            ),
        ),
        Outcome::Indeterminate(vec![Unknown::BoundaryDetailUnavailable])
    );
}

#[test]
fn invalid_queries_and_exhausted_work_are_refused() {
    let plan = plan();
    let upload = exists(selector(
        "network.upload",
        rendered(Projection::Resource, TextPredicate::Any),
    ));
    let query = Query::new(upload.clone());
    let json = serde_json::to_string(&query).unwrap();
    assert_eq!(serde_json::from_str::<Query>(&json).unwrap(), query);

    // The upload is the third effect; one step examines only the first.
    let bounded = Evaluator::new(
        &plan,
        BTreeMap::from([(ExecutionNodeRef(0), Bindings::from_subject(&plan.subject))]),
        &NO_LABELS,
        QueryLimits {
            max_steps: 1,
            ..QueryLimits::default()
        },
    );
    assert_eq!(
        bounded.evaluate(&query),
        Outcome::Refused(Refusal::WorkLimit)
    );
    // Evaluating the query takes one step. Evaluations of one evaluator
    // share the steps beyond their own: the first spends the one shared
    // step and refuses the second, while an own step serves every one.
    for (own_steps, shared_steps, second) in [(0, 1, false), (1, 0, true)] {
        let shared = Evaluator::new(
            &plan,
            BTreeMap::from([(ExecutionNodeRef(0), Bindings::from_subject(&plan.subject))]),
            &NO_LABELS,
            QueryLimits {
                own_steps,
                shared_steps,
                ..QueryLimits::default()
            },
        );
        assert!(matches!(shared.evaluate(&query), Outcome::Match(_)));
        assert_eq!(matches!(shared.evaluate(&query), Outcome::Match(_)), second);
    }

    // Reads chained by exact value dependencies reach nothing a listen
    // could be: with no destination, the byte flow searches no route and
    // spends nothing on the chain.
    let mut chained = plan.clone();
    let graph = chained.causality.graph.as_mut().unwrap();
    let read = graph.nodes[10].clone();
    let mut previous = read.id.clone();
    for index in 0..1_500 {
        let mut node = read.clone();
        node.id = OccurrenceId(format!("{}-{index}", read.id.0));
        let mut edge = graph.edges[0].clone();
        edge.from = previous;
        edge.to = node.id.clone();
        edge.reason = CausalReason::ValueDependency;
        edge.assurance = CausalAssurance::Exact;
        previous = node.id.clone();
        graph.nodes.push(node);
        graph.edges.push(edge);
    }
    let listen = Query::new(Assertion::Flow {
        source: Endpoint::Interaction(selector("filesystem.read", ResourcePredicate::Any)),
        destination: Endpoint::Interaction(selector("network.listen", ResourcePredicate::Any)),
        traversal: Traversal::ByteFlow {
            assurance: ByteFlowAssurance::Exact,
            edges: all_byte_edges(),
        },
        provenance: RouteProvenance::Any,
    });
    assert_eq!(
        Evaluator::new(
            &chained,
            BTreeMap::from([(ExecutionNodeRef(0), Bindings::from_subject(&plan.subject))]),
            &NO_LABELS,
            QueryLimits::default(),
        )
        .evaluate(&listen),
        Outcome::NoMatch
    );

    let evaluator = Evaluator::new(
        &plan,
        BTreeMap::from([(ExecutionNodeRef(0), Bindings::from_subject(&plan.subject))]),
        &NO_LABELS,
        QueryLimits::default(),
    );
    let future = Query {
        schema_version: SCHEMA_VERSION + 1,
        assertion: upload.clone(),
    };
    assert_eq!(
        evaluator.evaluate(&future),
        Outcome::Refused(Refusal::UnsupportedVersion(SCHEMA_VERSION + 1))
    );
    let values = Query::new(Assertion::Flow {
        source: Endpoint::Value(TextPredicate::Any),
        destination: Endpoint::Value(TextPredicate::Any),
        traversal: Traversal::ResourcePairs,
        provenance: RouteProvenance::Any,
    });
    assert!(matches!(
        evaluator.evaluate(&values),
        Outcome::Refused(Refusal::InvalidInput(_))
    ));

    let empty = Query::new(Assertion::All {
        assertions: Vec::new(),
    });
    assert!(matches!(
        evaluator.evaluate(&empty),
        Outcome::Refused(Refusal::InvalidInput(_))
    ));
    let nested = Query::new(Assertion::Not {
        assertion: Box::new(Assertion::Not {
            assertion: Box::new(upload),
        }),
    });
    assert!(matches!(
        nested.validate_with_limits(QueryLimits {
            max_assertion_depth: 1,
            ..QueryLimits::default()
        }),
        Err(Refusal::InvalidInput(_))
    ));

    let resource = Query::new(exists(selector(
        "network.upload",
        ResourcePredicate::Not {
            predicate: Box::new(ResourcePredicate::Any),
        },
    )));
    assert!(matches!(
        resource.validate_with_limits(QueryLimits {
            max_resource_depth: 0,
            ..QueryLimits::default()
        }),
        Err(Refusal::InvalidInput(_))
    ));
    let empty_resource = Query::new(exists(selector(
        "network.upload",
        ResourcePredicate::AnyOf {
            predicates: Vec::new(),
        },
    )));
    assert!(matches!(
        evaluator.evaluate(&empty_resource),
        Outcome::Refused(Refusal::InvalidInput(_))
    ));

    for domains in [
        BoundaryDomainsPredicate::AllOf(Vec::new()),
        BoundaryDomainsPredicate::AnyOf(vec![Domain::new("")]),
        BoundaryDomainsPredicate::AllOf(vec![Domain::new("process"), Domain::new("process")]),
    ] {
        let boundary = Query::new(Assertion::Boundary {
            reason: "dynamic_call".into(),
            class: None,
            domains: Some(domains),
            detail: None,
            provenance: None,
        });
        assert!(matches!(
            evaluator.evaluate(&boundary),
            Outcome::Refused(Refusal::InvalidInput(_))
        ));
    }
}
