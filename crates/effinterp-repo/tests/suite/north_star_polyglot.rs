#![allow(clippy::disallowed_methods)]

use std::path::{Path, PathBuf};

use effinterp_proto::{
    ContainerStorage, ExecutionAssurance, ExecutionEdgeKind, ExecutionNode, ExecutionRealm,
    ProvenanceKind, ResourceExpr, ResourceIdentity, Subject,
};
use effinterp_repo::{EntrypointKind, IndexLimits, RepoIndex, build_index, save_index};

use super::plan_execution;
use crate::support::literal;

const PACKAGE_JSON: &str = include_str!("../fixtures/north-star-polyglot/package.json");
const PACKAGE_SCRIPT: &str = "./src/launcher.ts";
const LAUNCHER: &str = include_str!("../fixtures/north-star-polyglot/src/launcher.ts");
const HELPER: &str = include_str!("../fixtures/north-star-polyglot/helper.py");
const RUN_SH: &str = include_str!("../fixtures/north-star-polyglot/scripts/run.sh");

const EDGE_KINDS: [ExecutionEdgeKind; 9] = [
    ExecutionEdgeKind::Launch,
    ExecutionEdgeKind::Interpreter,
    ExecutionEdgeKind::Launch,
    ExecutionEdgeKind::Interpreter,
    ExecutionEdgeKind::Launch,
    ExecutionEdgeKind::ContainerRealm,
    ExecutionEdgeKind::Script,
    ExecutionEdgeKind::Launch,
    ExecutionEdgeKind::DatabaseClient,
];

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/north-star-polyglot")
}

fn argv(node: &ExecutionNode) -> Vec<&str> {
    node.argv
        .iter()
        .map(|arg| literal(arg).expect("exact literal argv"))
        .collect()
}

fn cwd(node: &ExecutionNode) -> Option<&str> {
    match node.cwd.as_ref() {
        Some(ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        }) => Some(path),
        None => None,
        other => panic!("unexpected cwd {other:?}"),
    }
}

fn span_text<'a>(node: &ExecutionNode, source: &'a str) -> &'a str {
    let span = node.source_span.expect("source span");
    &source[span.start as usize..span.end as usize]
}

fn assert_mount(node: &ExecutionNode) {
    assert!(matches!(
        node.mounts.as_slice(),
        [ContainerStorage::BindMount {
            host_path: ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path: host }
            },
            container_path: ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path: container }
            },
            read_only: false,
        }] if host == "scripts" && container == "/workspace"
    ));
}

fn build_fixture() -> RepoIndex {
    build_index(&fixture_root(), IndexLimits::default())
}

#[test]
fn package_script_reaches_exact_sql_table_through_every_runtime() {
    let index = build_fixture();
    let analyzed = index.find("package.json:scripts.northstar").unwrap();
    assert_eq!(
        analyzed.entrypoint.evidence.kind,
        EntrypointKind::PackageScript
    );
    assert_eq!(analyzed.entrypoint.evidence.file, "package.json");

    let report = plan_execution(&index, "package.json:scripts.northstar").unwrap();
    assert_eq!(
        report
            .boundaries
            .iter()
            .filter(|boundary| boundary.reason.as_str() == "daemon_transport"
                && boundary.domains == ["network"])
            .count(),
        1
    );

    assert!(
        report.boundaries.iter().all(|boundary| {
            matches!(
                boundary.reason.as_str(),
                "frontend_partial" | "unrecoverable_source"
            ) || (boundary.reason.as_str() == "environment_configuration"
                && boundary.domains == ["environment"])
                || (boundary.reason.as_str() == "daemon_transport"
                    && boundary.domains == ["network"])
        }),
        "{:?}",
        report.boundaries
    );
    let graph = &report.graph;
    let node_refs: Vec<_> = graph
        .nodes
        .iter()
        .enumerate()
        .filter_map(|(index, node)| {
            (node.input.is_none() || node.boundary.is_none()).then_some(index)
        })
        .collect();
    let nodes: Vec<_> = node_refs.iter().map(|index| &graph.nodes[*index]).collect();
    let edges: Vec<_> = graph
        .edges
        .iter()
        .filter(|edge| node_refs.contains(&(edge.to.0 as usize)))
        .collect();
    assert_eq!(nodes.len(), 10, "{:#?}", nodes);
    assert_eq!(
        edges.iter().map(|edge| edge.kind).collect::<Vec<_>>(),
        EDGE_KINDS
    );
    for (index, edge) in edges.iter().enumerate() {
        assert_eq!(edge.from.0 as usize, node_refs[index]);
        assert_eq!(edge.to.0 as usize, node_refs[index + 1]);
        assert!(!edge.evidence.is_empty());
        assert_eq!(edge.evidence, nodes[index + 1].evidence);
    }
    assert!(
        nodes
            .iter()
            .all(|node| node.assurance == ExecutionAssurance::Exact)
    );
    assert!(nodes[0].evidence.is_empty());
    assert!(nodes[1..].iter().all(|node| !node.evidence.is_empty()));

    let subjects: Vec<&str> = nodes
        .iter()
        .enumerate()
        .map(|(index, node)| match &node.subject {
            Subject::Shell { .. } if index == graph.entry.0 as usize => "package-script",
            Subject::Source { language, .. } if language == "js" => "typescript",
            Subject::Source { language, .. } if language == "python" => "python",
            Subject::Shell { .. } => "shell",
            Subject::Sql { .. } => "sql",
            Subject::Exec { argv, .. } => argv[0].as_str(),
            Subject::Source { language, .. } => language,
            Subject::ToolCall { .. } => "tool",
        })
        .collect();
    assert_eq!(
        subjects,
        [
            "package-script",
            "./src/launcher.ts",
            "typescript",
            "python3",
            "python",
            "docker",
            "sh",
            "shell",
            "psql",
            "sql",
        ]
    );
    assert_eq!(
        nodes
            .iter()
            .map(|node| node.selected_source_path())
            .collect::<Vec<_>>(),
        [
            None,
            None,
            Some("src/launcher.ts"),
            None,
            Some("helper.py"),
            None,
            None,
            Some("scripts/run.sh"),
            None,
            None,
        ]
    );

    assert_eq!(argv(nodes[1]), ["./src/launcher.ts"]);
    assert_eq!(argv(nodes[3]), ["python3", "helper.py", "--tenant", "acme"]);
    assert_eq!(
        argv(nodes[5]),
        [
            "docker",
            "run",
            "--name",
            "worker",
            "-v",
            "./scripts:/workspace",
            "-w",
            "/workspace",
            "-e",
            "TENANT=acme",
            "postgres:16",
            "sh",
            "/workspace/run.sh",
        ]
    );
    assert_eq!(argv(nodes[6]), ["sh", "/workspace/run.sh"]);
    assert_eq!(
        argv(nodes[8]),
        [
            "psql",
            "-h",
            "db",
            "-d",
            "app",
            "-c",
            "UPDATE audit.events SET seen=true",
        ]
    );

    let container = ExecutionRealm::Container {
        runtime: "docker".to_string(),
        name: "postgres:16".to_string(),
    };
    assert!(
        nodes[..6]
            .iter()
            .all(|node| node.realm == ExecutionRealm::Host)
    );
    for node in &nodes[6..] {
        assert_eq!(node.realm, container);
        assert_eq!(cwd(node), Some("/workspace"));
        assert_eq!(
            node.environment
                .get("TENANT")
                .and_then(Option::as_ref)
                .and_then(literal),
            Some("acme")
        );
        assert_mount(node);
    }
    assert!(nodes[..6].iter().all(|node| cwd(node) == Some(".")));

    assert_eq!(span_text(nodes[1], PACKAGE_SCRIPT), PACKAGE_SCRIPT);
    assert_eq!(span_text(nodes[2], PACKAGE_SCRIPT), PACKAGE_SCRIPT);
    let launcher_call = "spawnSync(\"python3\", [\"helper.py\", \"--tenant\", \"acme\"])";
    assert_eq!(span_text(nodes[3], LAUNCHER), launcher_call);
    assert_eq!(span_text(nodes[4], LAUNCHER), launcher_call);
    let helper_call = HELPER.strip_prefix("import subprocess\n\n").unwrap().trim();
    assert_eq!(span_text(nodes[5], HELPER), helper_call);
    assert_eq!(span_text(nodes[6], HELPER), helper_call);
    assert_eq!(span_text(nodes[7], HELPER), helper_call);
    let shell_call = RUN_SH.strip_prefix("#!/bin/sh\n").unwrap().trim();
    assert_eq!(span_text(nodes[8], RUN_SH), shell_call);
    assert_eq!(span_text(nodes[9], RUN_SH), shell_call);
    assert!(analyzed.plan().unwrap().provenance.iter().any(|node| {
        matches!(
            node.kind,
            ProvenanceKind::SourceSpan { start, end }
                if &PACKAGE_JSON[start as usize..end as usize] == PACKAGE_SCRIPT
        )
    }));

    let table = report
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "database.write")
        .expect("database.write on the final SQL execution");
    assert_eq!(table.execution.0 as usize, node_refs[9]);
    assert_eq!(table.realm, container);
    assert!(matches!(
        &table.resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::DatabaseTable {
                server: Some(server),
                database: Some(database),
                schema: Some(schema),
                table,
            }
        } if server == "db" && database == "app" && schema == "audit" && table == "events"
    ));
}

#[test]
fn repeated_indexing_and_querying_are_byte_identical() {
    let first = build_fixture();
    let second = build_fixture();
    assert_eq!(save_index(&first), save_index(&second));
    let first = plan_execution(&first, "package.json:scripts.northstar").unwrap();
    let second = plan_execution(&second, "package.json:scripts.northstar").unwrap();
    assert_eq!(first.graph, second.graph);
    assert_eq!(first.effects, second.effects);
}

fn variant_fixture(
    tag: &str,
    package_json: &str,
    launcher: &str,
    helper: &str,
    run_sh: &str,
) -> PathBuf {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("north-star-{tag}"));
    let _ = std::fs::remove_dir_all(&root);
    for (path, source) in [
        ("package.json", package_json),
        ("src/launcher.ts", launcher),
        ("helper.py", helper),
        ("scripts/run.sh", run_sh),
    ] {
        let path = root.join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, source).unwrap();
    }
    root
}

#[test]
fn broken_links_remove_only_the_unsupported_suffix() {
    let cases = [
        (
            "typescript",
            PACKAGE_JSON.replace("src/launcher.ts", "src/missing.ts"),
            LAUNCHER.to_string(),
            HELPER.to_string(),
            RUN_SH.to_string(),
            1,
        ),
        (
            "python",
            PACKAGE_JSON.to_string(),
            LAUNCHER.replace("helper.py", "missing.py"),
            HELPER.to_string(),
            RUN_SH.to_string(),
            3,
        ),
        (
            "mount",
            PACKAGE_JSON.to_string(),
            LAUNCHER.to_string(),
            HELPER.replace("./scripts:/workspace", "./scripts:/elsewhere"),
            RUN_SH.to_string(),
            6,
        ),
        (
            "shell",
            PACKAGE_JSON.to_string(),
            LAUNCHER.to_string(),
            HELPER.replace("/workspace/run.sh", "/workspace/missing.sh"),
            RUN_SH.to_string(),
            6,
        ),
        (
            "sql",
            PACKAGE_JSON.to_string(),
            LAUNCHER.to_string(),
            HELPER.to_string(),
            "#!/bin/sh\npsql -h db -d app -c \"$MIGRATION_SQL\"\n".to_string(),
            8,
        ),
    ];

    for (tag, package_json, launcher, helper, run_sh, retained_edges) in cases {
        let root = variant_fixture(tag, &package_json, &launcher, &helper, &run_sh);
        let index = build_index(&root, IndexLimits::default());
        let report = plan_execution(&index, "package.json:scripts.northstar").unwrap();
        let graph = &report.graph;
        assert_eq!(
            graph
                .edges
                .iter()
                .filter(|edge| {
                    let node = &graph.nodes[edge.to.0 as usize];
                    node.input.is_none() || node.boundary.is_none()
                })
                .map(|edge| edge.kind)
                .collect::<Vec<_>>(),
            EDGE_KINDS[..retained_edges],
            "{tag}: {:#?}",
            graph.edges
        );
        assert_eq!(
            graph
                .nodes
                .iter()
                .filter(|node| node.input.is_none() || node.boundary.is_none())
                .count(),
            retained_edges + 1,
            "{tag}"
        );
        assert!(
            !report.boundaries.is_empty(),
            "{tag} must retain a typed boundary"
        );
        assert!(
            !report.effects.iter().any(|effect| {
                effect.operation.0 == "database.write"
                    && matches!(
                        &effect.resource,
                        ResourceExpr::Concrete {
                            identity: ResourceIdentity::DatabaseTable {
                                schema: Some(schema),
                                table,
                                ..
                            }
                        } if schema == "audit" && table == "events"
                    )
            }),
            "{tag} retained the unsupported table mutation"
        );
    }
}
