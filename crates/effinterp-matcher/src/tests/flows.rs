//! Flow assertions: routes, byte flow, flow endpoints, ports and transfer
//! destinations.

use std::collections::BTreeMap;

use effinterp_proto::{
    AttrValue, CausalAssurance, CausalReason, Condition, ConditionKind, CoverageLevel, EffectId,
    ExecutionNodeRef, ExecutionRealm, OccurrenceId, OccurrenceKind, PathPlatform, Plan, Port,
    filesystem_path,
};

use super::{
    TestLabels, all_byte_edges, condition, evaluate, evaluate_with_labels, plan, rendered, selector,
};
use crate::{
    Assertion, ByteFlowAssurance, ByteFlowEdgeKind, Closure, EffectRelationship, Endpoint,
    Evaluator, NO_LABELS, ObservationBinding, ObservedPathKind, Outcome, PortKind, PortScope,
    Projection, Query, QueryLimits, Refusal, ResourcePredicate, RouteProvenance, TextPredicate,
    Traversal, Unknown, Witness,
};

#[test]
fn flows_return_routes_and_prove_absence_only_when_complete() {
    let mut plan = plan();
    let read = || {
        Endpoint::Interaction(selector(
            "filesystem.read",
            rendered(Projection::Resource, TextPredicate::Any),
        ))
    };
    let upload = || {
        Endpoint::Interaction(selector(
            "network.upload",
            rendered(Projection::Resource, TextPredicate::Any),
        ))
    };
    let flow = |source, traversal, provenance| Assertion::Flow {
        source,
        destination: upload(),
        traversal,
        provenance,
    };
    let host = || Endpoint::Value(TextPredicate::Equals("evil.example".into()));

    // The literal host reaches the upload through two unprovenanced ports.
    let Outcome::Match(Witness::Flow { route, .. }) = evaluate(
        &plan,
        flow(host(), Traversal::OccurrencePath, RouteProvenance::Any),
    ) else {
        panic!("the host value reaches the upload")
    };
    assert_eq!(route.len(), 4);
    let provenanced = RouteProvenance::NonemptyOnEveryOccurrence;
    assert_eq!(
        evaluate(&plan, flow(host(), Traversal::OccurrencePath, provenanced)),
        Outcome::NoMatch
    );

    // No resource interaction reaches another until an edge carries the
    // read's bytes into the upload's input port.
    let pairs = || flow(read(), Traversal::ResourcePairs, RouteProvenance::Any);
    assert_eq!(evaluate(&plan, pairs()), Outcome::NoMatch);
    let graph = plan.causality.graph.as_mut().unwrap();
    let read_id = graph.nodes[10].id.clone();
    let mut edge = graph.edges.last().unwrap().clone();
    edge.from = read_id.clone();
    edge.to = graph.nodes[12].id.clone();
    graph.edges.push(edge);
    assert!(matches!(
        evaluate(&plan, pairs()),
        Outcome::Match(Witness::Flow { source, .. }) if source == read_id
    ));

    // A capped traversal cannot prove absence from the truncated source.
    plan.analysis.limits.insert("max_causal_pairs".into(), 0);
    assert_eq!(
        evaluate(&plan, pairs()),
        Outcome::Indeterminate(vec![Unknown::TraversalIncomplete {
            sources: vec![read_id]
        }])
    );
    plan.causality.coverage.level = CoverageLevel::Partial;
    assert!(matches!(
        evaluate(&plan, flow(host(), Traversal::OccurrencePath, provenanced)),
        Outcome::Indeterminate(unknowns) if unknowns == [Unknown::CausalCoverageNotFull]
    ));
    plan.causality.graph = None;
    assert_eq!(
        evaluate(&plan, pairs()),
        Outcome::Indeterminate(vec![Unknown::CausalDetailUnavailable])
    );
}

#[test]
fn byte_flow_enforces_edge_assurance_realm_and_success_path() {
    let mut plan = plan();
    let read = Endpoint::Interaction(selector("filesystem.read", ResourcePredicate::Any));
    let upload = Endpoint::Interaction(selector("network.upload", ResourcePredicate::Any));
    let flow = |traversal| Assertion::Flow {
        source: read.clone(),
        destination: upload.clone(),
        traversal,
        provenance: RouteProvenance::Any,
    };
    let graph = plan.causality.graph.as_mut().unwrap();
    let read_id = graph.nodes[10].id.clone();
    let upload_id = graph.nodes[11].id.clone();
    let mut edge = graph.edges[0].clone();
    edge.from = read_id;
    edge.to = upload_id;
    edge.reason = CausalReason::ControlDependency;
    edge.assurance = CausalAssurance::Conservative;
    edge.condition = None;
    graph.edges.push(edge);

    assert!(matches!(
        evaluate(&plan, flow(Traversal::OccurrencePath)),
        Outcome::Match(_)
    ));
    let exact = Traversal::ByteFlow {
        assurance: ByteFlowAssurance::Exact,
        edges: all_byte_edges(),
    };
    let conservative = Traversal::ByteFlow {
        assurance: ByteFlowAssurance::Conservative,
        edges: all_byte_edges(),
    };
    assert_eq!(evaluate(&plan, flow(exact.clone())), Outcome::NoMatch);

    let edge = plan
        .causality
        .graph
        .as_mut()
        .unwrap()
        .edges
        .last_mut()
        .unwrap();
    edge.reason = CausalReason::ValueDependency;
    assert_eq!(evaluate(&plan, flow(exact.clone())), Outcome::NoMatch);
    assert!(matches!(
        evaluate(&plan, flow(conservative.clone())),
        Outcome::Match(_)
    ));

    let edge = plan
        .causality
        .graph
        .as_mut()
        .unwrap()
        .edges
        .last_mut()
        .unwrap();
    edge.assurance = CausalAssurance::Exact;
    assert!(matches!(
        evaluate(&plan, flow(exact.clone())),
        Outcome::Match(_)
    ));

    plan.causality
        .graph
        .as_mut()
        .unwrap()
        .edges
        .last_mut()
        .unwrap()
        .condition = Some(Condition::Widened);
    assert_eq!(
        evaluate(&plan, flow(exact.clone())),
        Outcome::Indeterminate(vec![Unknown::ConditionIncomplete])
    );
    let upload_id = {
        let edge = plan
            .causality
            .graph
            .as_mut()
            .unwrap()
            .edges
            .last_mut()
            .unwrap();
        edge.condition = None;
        edge.reason = CausalReason::ResourceTransfer;
        edge.assurance = CausalAssurance::Conservative;
        edge.to.clone()
    };
    assert!(matches!(
        evaluate(&plan, flow(exact.clone())),
        Outcome::Match(_)
    ));
    let transfer_only = Traversal::ByteFlow {
        assurance: ByteFlowAssurance::Conservative,
        edges: vec![ByteFlowEdgeKind::ContentPreservingTransfer],
    };
    assert!(matches!(
        evaluate(&plan, flow(transfer_only.clone())),
        Outcome::Match(_)
    ));
    plan.causality
        .graph
        .as_mut()
        .unwrap()
        .edges
        .last_mut()
        .unwrap()
        .reason = CausalReason::ValueDependency;
    assert_eq!(
        evaluate(&plan, flow(transfer_only.clone())),
        Outcome::NoMatch
    );
    plan.causality
        .graph
        .as_mut()
        .unwrap()
        .edges
        .last_mut()
        .unwrap()
        .reason = CausalReason::ResourceTransfer;

    // A route may stay within its source's branch arm, never join two arms.
    let arm = |polarity| Some(condition(ConditionKind::Branch, 0, Some(polarity)));
    let conditions = |plan: &mut Plan, read: Option<Condition>, upload: Option<Condition>| {
        let graph = plan.causality.graph.as_mut().unwrap();
        let edge = graph.edges.last_mut().unwrap();
        edge.condition = upload.clone();
        let read_id = edge.from.clone();
        for node in &mut graph.nodes {
            if node.id == read_id {
                node.condition = read.clone();
            } else if node.id == upload_id {
                node.condition = upload.clone();
            }
        }
    };
    conditions(&mut plan, arm(false), arm(false));
    assert!(matches!(
        evaluate(&plan, flow(exact.clone())),
        Outcome::Match(_)
    ));
    let schema_six = Query {
        schema_version: 6,
        assertion: flow(exact.clone()),
    };
    assert_eq!(
        Evaluator::new(&plan, BTreeMap::new(), &NO_LABELS, QueryLimits::default())
            .evaluate(&schema_six),
        Outcome::NoMatch
    );
    conditions(&mut plan, arm(true), arm(false));
    assert_eq!(evaluate(&plan, flow(exact.clone())), Outcome::NoMatch);
    conditions(&mut plan, None, None);

    plan.causality
        .graph
        .as_mut()
        .unwrap()
        .nodes
        .iter_mut()
        .find(|node| node.id == upload_id)
        .unwrap()
        .realm = ExecutionRealm::Remote {
        endpoint: "remote".into(),
    };
    assert_eq!(evaluate(&plan, flow(exact.clone())), Outcome::NoMatch);

    let mut schema_two = Query {
        schema_version: 2,
        assertion: flow(exact),
    };
    assert!(matches!(
        schema_two.validate(),
        Err(Refusal::InvalidInput(_))
    ));
    schema_two.assertion = flow(Traversal::OccurrencePath);
    assert!(schema_two.validate().is_ok());

    for edges in [
        vec![],
        vec![
            ByteFlowEdgeKind::ValueDependency,
            ByteFlowEdgeKind::ValueDependency,
        ],
    ] {
        let invalid = Query::new(flow(Traversal::ByteFlow {
            assurance: ByteFlowAssurance::Exact,
            edges,
        }));
        assert!(matches!(invalid.validate(), Err(Refusal::InvalidInput(_))));
    }
}

#[test]
fn byte_flow_qualifies_state_transitions_and_exact_aliases() {
    let mut plan = plan();
    let graph = plan.causality.graph.as_mut().unwrap();
    let mut source = graph.nodes[10].clone();
    source.id = OccurrenceId("state-source".into());
    let OccurrenceKind::ResourceInteraction {
        operation,
        resource,
        ..
    } = &mut source.occurrence
    else {
        unreachable!()
    };
    *operation = effinterp_proto::Operation::new("filesystem.write");
    *resource = filesystem_path("/work/staged", None, PathPlatform::Posix);
    let mut destination = source.clone();
    destination.id = OccurrenceId("state-destination".into());
    let OccurrenceKind::ResourceInteraction { operation, .. } = &mut destination.occurrence else {
        unreachable!()
    };
    *operation = effinterp_proto::Operation::new("filesystem.read");
    graph.nodes.extend([source.clone(), destination.clone()]);
    let mut transition = graph.edges[0].clone();
    transition.from = source.id.clone();
    transition.to = destination.id.clone();
    transition.reason = CausalReason::ResourceTransition;
    transition.assurance = CausalAssurance::Conservative;
    transition.condition = None;
    graph.edges.push(transition);

    let flow = |source: &str, destination: &str| Assertion::Flow {
        source: Endpoint::Interaction(selector(source, ResourcePredicate::Any)),
        destination: Endpoint::Interaction(selector(destination, ResourcePredicate::Any)),
        traversal: Traversal::ByteFlow {
            assurance: ByteFlowAssurance::Exact,
            edges: all_byte_edges(),
        },
        provenance: RouteProvenance::Any,
    };
    assert!(matches!(
        evaluate(&plan, flow("filesystem.write", "filesystem.read")),
        Outcome::Match(_)
    ));

    plan.causality
        .graph
        .as_mut()
        .unwrap()
        .edges
        .last_mut()
        .unwrap()
        .reason = CausalReason::Alias;
    assert_eq!(
        evaluate(&plan, flow("filesystem.write", "filesystem.read")),
        Outcome::NoMatch
    );
    plan.causality
        .graph
        .as_mut()
        .unwrap()
        .edges
        .last_mut()
        .unwrap()
        .assurance = CausalAssurance::Exact;
    assert!(matches!(
        evaluate(&plan, flow("filesystem.write", "filesystem.read")),
        Outcome::Match(_)
    ));

    let graph = plan.causality.graph.as_mut().unwrap();
    let source = graph
        .nodes
        .iter_mut()
        .find(|node| node.id == OccurrenceId("state-source".into()))
        .unwrap();
    let OccurrenceKind::ResourceInteraction { operation, .. } = &mut source.occurrence else {
        unreachable!()
    };
    *operation = effinterp_proto::Operation::new("filesystem.delete");
    graph.edges.last_mut().unwrap().reason = CausalReason::ResourceTransition;
    assert_eq!(
        evaluate(&plan, flow("filesystem.delete", "filesystem.read")),
        Outcome::NoMatch
    );

    let graph = plan.causality.graph.as_mut().unwrap();
    let source = graph
        .nodes
        .iter_mut()
        .find(|node| node.id == OccurrenceId("state-source".into()))
        .unwrap();
    let OccurrenceKind::ResourceInteraction {
        operation,
        resource,
        ..
    } = &mut source.occurrence
    else {
        unreachable!()
    };
    *operation = effinterp_proto::Operation::new("filesystem.write");
    *resource = filesystem_path("/work/staged/secret", None, PathPlatform::Posix);
    let destination = graph
        .nodes
        .iter_mut()
        .find(|node| node.id == OccurrenceId("state-destination".into()))
        .unwrap();
    let OccurrenceKind::ResourceInteraction { resource, .. } = &mut destination.occurrence else {
        unreachable!()
    };
    *resource = filesystem_path("/work/staged", None, PathPlatform::Posix);
    assert!(matches!(
        evaluate(&plan, flow("filesystem.write", "filesystem.read")),
        Outcome::Match(_)
    ));
}

#[test]
fn effect_bindings_join_flow_endpoints_and_related_effects() {
    let mut plan = plan();
    let graph = plan.causality.graph.as_mut().unwrap();
    let mut edge = graph.edges[0].clone();
    edge.from = graph.nodes[10].id.clone();
    edge.to = graph.nodes[11].id.clone();
    edge.reason = CausalReason::ResourceTransfer;
    edge.assurance = CausalAssurance::Conservative;
    edge.condition = None;
    graph.edges.push(edge);

    let relationship = EffectRelationship {
        same_execution: true,
        same_realm: true,
        same_resource: false,
        after: false,
    };
    let query = || Assertion::BindEffect {
        name: "source".into(),
        related: None,
        selector: selector("filesystem.read", ResourcePredicate::Any),
        closure: Some(Closure::DomainFullOrBoundaryFree {
            domain: "filesystem".into(),
        }),
        assertion: Box::new(Assertion::All {
            assertions: vec![
                Assertion::Flow {
                    source: Endpoint::EffectBinding {
                        name: "source".into(),
                    },
                    destination: Endpoint::Interaction(selector(
                        "network.upload",
                        ResourcePredicate::Any,
                    )),
                    traversal: Traversal::ByteFlow {
                        assurance: ByteFlowAssurance::Conservative,
                        edges: all_byte_edges(),
                    },
                    provenance: RouteProvenance::Any,
                },
                Assertion::Not {
                    assertion: Box::new(Assertion::RelatedEffect {
                        binding: "source".into(),
                        relationship,
                        selector: selector("network.listen", ResourcePredicate::Any),
                        closure: Some(Closure::DomainFullOrBoundaryFree {
                            domain: "network".into(),
                        }),
                    }),
                },
            ],
        }),
    };
    assert!(matches!(evaluate(&plan, query()), Outcome::Match(_)));

    let mut listener = plan
        .effects
        .iter()
        .find(|effect| effect.operation.as_str() == "network.upload")
        .unwrap()
        .clone();
    listener.id = EffectId("listener".into());
    listener.operation = effinterp_proto::Operation::new("network.listen");
    plan.effects.push(listener.clone());
    assert_eq!(evaluate(&plan, query()), Outcome::NoMatch);

    plan.effects.last_mut().unwrap().execution = ExecutionNodeRef(1);
    assert!(matches!(evaluate(&plan, query()), Outcome::Match(_)));
    plan.effects.last_mut().unwrap().execution = listener.execution;
    plan.effects.last_mut().unwrap().realm = ExecutionRealm::Remote {
        endpoint: "other".into(),
    };
    assert!(matches!(evaluate(&plan, query()), Outcome::Match(_)));
    plan.effects.pop();

    plan.causality.graph.as_mut().unwrap().nodes[10]
        .provenance
        .clear();
    let read = plan
        .effects
        .iter()
        .find(|effect| effect.operation.as_str() == "filesystem.read")
        .unwrap();
    assert_eq!(
        evaluate(&plan, query()),
        Outcome::Indeterminate(vec![Unknown::EffectOccurrenceUnavailable {
            effect: read.id.clone(),
        }])
    );

    let invalid = Query::new(Assertion::Flow {
        source: Endpoint::EffectBinding {
            name: "missing".into(),
        },
        destination: Endpoint::Value(TextPredicate::Any),
        traversal: Traversal::OccurrencePath,
        provenance: RouteProvenance::Any,
    });
    assert!(matches!(invalid.validate(), Err(Refusal::InvalidInput(_))));
}

#[test]
fn port_endpoints_select_typed_ports_of_the_bound_call() {
    let mut plan = plan();
    // The read's bytes reach curl's request body exactly.
    let graph = plan.causality.graph.as_mut().unwrap();
    let mut edge = graph.edges[0].clone();
    edge.from = graph.nodes[10].id.clone();
    edge.to = graph.nodes[12].id.clone();
    edge.reason = CausalReason::ValueDependency;
    edge.assurance = CausalAssurance::Exact;
    edge.condition = None;
    graph.edges.push(edge);
    let query = |kind, scope| Assertion::BindEffect {
        name: "read".into(),
        related: None,
        selector: selector("filesystem.read", ResourcePredicate::Any),
        closure: Some(Closure::DomainFullOrBoundaryFree {
            domain: "filesystem".into(),
        }),
        assertion: Box::new(Assertion::Flow {
            source: Endpoint::EffectBinding {
                name: "read".into(),
            },
            destination: Endpoint::Port { kind, scope },
            traversal: Traversal::ByteFlow {
                assurance: ByteFlowAssurance::Exact,
                edges: all_byte_edges(),
            },
            provenance: RouteProvenance::Any,
        }),
    };
    let same = || PortScope::SameExecution {
        binding: "read".into(),
    };
    assert!(matches!(
        evaluate(&plan, query(PortKind::NetworkRequest, same())),
        Outcome::Match(_)
    ));
    assert_eq!(
        evaluate(&plan, query(PortKind::Stdout, same())),
        Outcome::NoMatch
    );

    let request = plan.causality.graph.as_ref().unwrap().nodes[12].id.clone();
    plan.causality.graph.as_mut().unwrap().nodes[12].execution = Some(ExecutionNodeRef(1));
    assert_eq!(
        evaluate(&plan, query(PortKind::NetworkRequest, same())),
        Outcome::NoMatch
    );
    assert!(matches!(
        evaluate(
            &plan,
            query(PortKind::NetworkRequest, PortScope::AnyExecution)
        ),
        Outcome::Match(_)
    ));
    plan.causality.graph.as_mut().unwrap().nodes[12].execution = None;
    assert_eq!(
        evaluate(&plan, query(PortKind::NetworkRequest, same())),
        Outcome::Indeterminate(vec![Unknown::PortExecutionUnavailable {
            occurrence: request.clone(),
        }])
    );

    // Stdin is consumed only when its call evaluates stdin as code.
    let graph = plan.causality.graph.as_mut().unwrap();
    graph.nodes[12].execution = Some(ExecutionNodeRef(0));
    graph.nodes[12].occurrence = OccurrenceKind::Port { port: Port::Stdin };
    assert_eq!(
        evaluate(&plan, query(PortKind::ConsumedStdin, same())),
        Outcome::NoMatch
    );
    let mut execution = plan.effects[0].clone();
    execution.id = EffectId("code".into());
    execution.operation = effinterp_proto::Operation::new("process.code_execution");
    plan.effects.push(execution);
    assert_eq!(
        evaluate(&plan, query(PortKind::ConsumedStdin, same())),
        Outcome::Indeterminate(vec![Unknown::AttributeAbsent {
            name: "source".into(),
        }])
    );
    plan.effects
        .last_mut()
        .unwrap()
        .attributes
        .insert("source".into(), AttrValue::String("stdin".into()));
    assert!(matches!(
        evaluate(&plan, query(PortKind::ConsumedStdin, same())),
        Outcome::Match(_)
    ));

    let schema_three = Query {
        schema_version: 3,
        assertion: query(PortKind::Stdout, same()),
    };
    assert!(matches!(
        schema_three.validate(),
        Err(Refusal::InvalidInput(_))
    ));
    let unbound = Query::new(query(
        PortKind::Stdout,
        PortScope::SameExecution {
            binding: "missing".into(),
        },
    ));
    assert!(matches!(unbound.validate(), Err(Refusal::InvalidInput(_))));
    let outside_byte_flow = Query::new(Assertion::Flow {
        source: Endpoint::Port {
            kind: PortKind::Stdout,
            scope: PortScope::AnyExecution,
        },
        destination: Endpoint::Value(TextPredicate::Any),
        traversal: Traversal::OccurrencePath,
        provenance: RouteProvenance::Any,
    });
    assert!(matches!(
        outside_byte_flow.validate(),
        Err(Refusal::InvalidInput(_))
    ));
}

#[test]
fn transfer_destinations_count_where_a_bound_move_sends_its_content() {
    // `mv /work/secret.key /backup`: the move's transfer lands in one
    // directory; `mv` may state it on the source's deletion instead.
    let mut plan = plan();
    let moved = plan
        .effects
        .iter()
        .position(|effect| effect.operation.as_str() == "filesystem.read")
        .unwrap();
    plan.effects[moved].operation = effinterp_proto::Operation::new("filesystem.move");
    let graph = plan.causality.graph.as_mut().unwrap();
    let node_of = |graph: &effinterp_proto::CausalityGraph, operation: &str| {
        graph
            .nodes
            .iter()
            .position(|node| {
                matches!(&node.occurrence, OccurrenceKind::ResourceInteraction {
                    operation: actual, ..
                } if actual.as_str() == operation)
            })
            .unwrap()
    };
    let source = node_of(graph, "filesystem.read");
    let OccurrenceKind::ResourceInteraction { operation, .. } = &mut graph.nodes[source].occurrence
    else {
        unreachable!()
    };
    *operation = effinterp_proto::Operation::new("filesystem.move");
    // The move's source-side deletion carries the transfer.
    let mut deletion = graph.nodes[source].clone();
    deletion.id = OccurrenceId("delete".into());
    let OccurrenceKind::ResourceInteraction { operation, .. } = &mut deletion.occurrence else {
        unreachable!()
    };
    *operation = effinterp_proto::Operation::new("filesystem.delete");
    let mut destination = graph.nodes[node_of(graph, "network.upload")].clone();
    destination.id = OccurrenceId("backup".into());
    destination.occurrence = OccurrenceKind::ResourceInteraction {
        operation: effinterp_proto::Operation::new("filesystem.write"),
        resource: filesystem_path("/backup", None, PathPlatform::Posix),
        attributes: BTreeMap::new(),
    };
    let mut transfer = graph.edges[0].clone();
    transfer.from = deletion.id.clone();
    transfer.to = destination.id.clone();
    transfer.reason = CausalReason::ResourceTransfer;
    transfer.assurance = CausalAssurance::Exact;
    graph.nodes.push(deletion);
    graph.nodes.push(destination.clone());
    graph.edges.push(transfer.clone());

    let query = |count, destination| Assertion::BindEffect {
        name: "moved".into(),
        related: None,
        selector: selector("filesystem.move", ResourcePredicate::Any),
        closure: Some(Closure::DomainFullOrBoundaryFree {
            domain: "filesystem".into(),
        }),
        assertion: Box::new(Assertion::TransferDestinations {
            binding: "moved".into(),
            count,
            destination,
        }),
    };
    let directory = || ResourcePredicate::ObservedPath {
        kind: ObservedPathKind::Directory,
        observation: ObservationBinding("policy".into()),
    };
    let destinations = |plan: &Plan, count, destination| match evaluate_with_labels(
        plan,
        query(count, destination),
        &TestLabels { available: true },
    ) {
        Outcome::Match(Witness::BindEffect { witness, .. }) => match *witness {
            Witness::TransferDestinations { destinations } => Some(destinations),
            witness => panic!("{witness:?}"),
        },
        Outcome::NoMatch => None,
        outcome => panic!("{outcome:?}"),
    };
    assert_eq!(
        destinations(&plan, 1, directory()),
        Some(vec![OccurrenceId("backup".into())])
    );
    assert_eq!(
        destinations(&plan, 1, ResourcePredicate::Any).map(|d| d.len()),
        Some(1)
    );
    assert_eq!(destinations(&plan, 2, ResourcePredicate::Any), None);
    // A destination that is a file is not the directory the query asks for.
    let file = ResourcePredicate::ObservedPath {
        kind: ObservedPathKind::File,
        observation: ObservationBinding("policy".into()),
    };
    assert_eq!(destinations(&plan, 1, file), None);

    // A second destination makes two, and a transfer under another
    // condition than the move's is not the move's.
    let mut second = plan.clone();
    let graph = second.causality.graph.as_mut().unwrap();
    let mut other = destination.clone();
    other.id = OccurrenceId("elsewhere".into());
    other.occurrence = OccurrenceKind::ResourceInteraction {
        operation: effinterp_proto::Operation::new("filesystem.write"),
        resource: filesystem_path("/elsewhere", None, PathPlatform::Posix),
        attributes: BTreeMap::new(),
    };
    let mut again = transfer.clone();
    again.to = other.id.clone();
    graph.nodes.push(other);
    graph.edges.push(again.clone());
    assert_eq!(destinations(&second, 1, ResourcePredicate::Any), None);
    assert!(matches!(
        evaluate_with_labels(&second, query(2, directory()), &TestLabels { available: true }),
        Outcome::Indeterminate(unknowns)
            if unknowns == [Unknown::LabelObservationUnavailable {
                observation: ObservationBinding("policy".into()),
            }]
    ));
    let graph = second.causality.graph.as_mut().unwrap();
    graph.edges.last_mut().unwrap().condition =
        Some(condition(ConditionKind::ShortCircuit, 0, Some(false)));
    assert_eq!(
        destinations(&second, 1, directory()).map(|d| d.len()),
        Some(1)
    );

    let assertion = query(1, directory());
    let schema_five = Query {
        schema_version: 5,
        assertion,
    };
    assert!(matches!(
        schema_five.validate(),
        Err(Refusal::InvalidInput(_))
    ));
    let unbound = Query::new(Assertion::TransferDestinations {
        binding: "moved".into(),
        count: 1,
        destination: ResourcePredicate::Any,
    });
    assert!(matches!(unbound.validate(), Err(Refusal::InvalidInput(_))));
}
