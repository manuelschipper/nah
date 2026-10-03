//! Execution-reachability contract: an entrypoint's effect surface reflects
//! what it actually executes, not what any function in its source could do.
//! A cross-file effect reachable only through an uncalled function must not be
//! attributed to the entrypoint; adding a real call makes it appear.
#![allow(clippy::disallowed_methods)]

use std::path::Path;

use effinterp_proto::{
    CausalReason, ContainerStorage, ExecutionAssurance, ExecutionEdgeKind, ExecutionRealm,
    OccurrenceKind, ResourceExpr, ResourceIdentity, Subject,
};
use effinterp_repo::{IndexLimits, ResourceSelector, build_index, effects_of, reach};
use effinterp_testkit::repo_fixture::repo_test_fixture;

use crate::{causal_path, plan_causality, plan_execution};

fn deletes_important(root: &Path) -> bool {
    let idx = build_index(root, IndexLimits::default());
    reach(
        &idx,
        &ResourceSelector::parse("fs:/important").unwrap(),
        None,
    )
    .payload
    .as_reach()
    .unwrap()
    .matches
    .iter()
    .any(|h| h.fact.operation.0 == "filesystem.delete")
}

fn display(effect: &effinterp_proto::EffectFact) -> String {
    effinterp_proto::display_resource(&effect.resource)
}

fn originates(effect: &effinterp_proto::EffectFact, source_file: &str) -> bool {
    effect
        .origin
        .as_ref()
        .is_some_and(|origin| origin.source_file == source_file)
}

/// Every occurrence a set of roots derives from, walking the envelope graph
/// backwards the way explanation does.
fn antecedents(
    dag: &effinterp_proto::ProvenanceDag,
    roots: &[effinterp_proto::OccurrenceId],
) -> std::collections::BTreeSet<effinterp_proto::OccurrenceId> {
    let mut seen: std::collections::BTreeSet<_> = roots.iter().cloned().collect();
    let mut pending: Vec<_> = roots.to_vec();
    while let Some(id) = pending.pop() {
        for edge in dag.edges.iter().filter(|edge| edge.to == id) {
            if seen.insert(edge.from.clone()) {
                pending.push(edge.from.clone());
            }
        }
    }
    seen
}

#[test]
fn python_uncalled_import_is_not_attributed() {
    let uncalled = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "er-py-uncalled",
        &[
            (
                "app.py",
                "from util import wipe\n\ndef never_called():\n    wipe(\"/important\")\n\nif __name__ == \"__main__\":\n    print(\"safe\")\n",
            ),
            ("util.py", "import os\n\ndef wipe(p):\n    os.remove(p)\n"),
        ],
    );
    assert!(
        !deletes_important(&uncalled),
        "an uncalled function's cross-file delete must not reach the surface"
    );
}

#[test]
fn python_reachable_import_is_attributed() {
    // Transitively reached through a called local function.
    let called = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "er-py-called",
        &[
            (
                "app.py",
                "from util import wipe\n\ndef used():\n    wipe(\"/important\")\n\nif __name__ == \"__main__\":\n    used()\n",
            ),
            ("util.py", "import os\n\ndef wipe(p):\n    os.remove(p)\n"),
        ],
    );
    assert!(
        deletes_important(&called),
        "a function reached from execution must contribute its cross-file delete"
    );
}

#[test]
fn javascript_uncalled_import_is_not_attributed() {
    let uncalled = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "er-js-uncalled",
        &[
            (
                "app.js",
                "import { wipe } from './util.js';\nfunction neverCalled() { wipe('/important'); }\nconsole.log('safe');\n",
            ),
            (
                "util.js",
                "import fs from 'fs';\nexport function wipe(p) { fs.unlinkSync(p); }\n",
            ),
        ],
    );
    assert!(
        !deletes_important(&uncalled),
        "an uncalled JS function's cross-file delete must not reach the surface"
    );
}

#[test]
fn javascript_reachable_import_is_attributed() {
    let called = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "er-js-called",
        &[
            (
                "app.js",
                "import { wipe } from './util.js';\nfunction used() { wipe('/important'); }\nused();\n",
            ),
            (
                "util.js",
                "import fs from 'fs';\nexport function wipe(p) { fs.unlinkSync(p); }\n",
            ),
        ],
    );
    assert!(
        deletes_important(&called),
        "a reached JS function's cross-file delete must be attributed"
    );
}

fn north_star_files<'a>(
    launcher: &'a str,
    helper: &'a str,
    shell: &'a str,
) -> [(&'static str, &'a str); 4] {
    [
        ("package.json", r#"{"scripts":{"run":"./launcher"}}"#),
        ("launcher", launcher),
        ("helper.py", helper),
        ("scripts/run.sh", shell),
    ]
}

const LAUNCHER: &str = "#!/usr/bin/env tsx\nconst { spawnSync } = require('child_process');\nspawnSync('python3', ['helper.py', '--tenant', 'acme']);\n";
const LAUNCHER_WITH_DECOY: &str = "#!/usr/bin/env tsx\nconst { spawnSync } = require('child_process');\nspawnSync('python3', ['helper.py', '--tenant', 'acme']);\nspawnSync('echo', ['TENANT=decoy']);\n";
const HELPER: &str = "import subprocess\nsubprocess.run(['docker', 'run', '--name', 'worker', '-v', './scripts:/workspace', '-w', '/workspace', '-e', 'TENANT=acme', 'postgres:16', 'sh', '/workspace/run.sh'])\n";
const SHELL: &str = "#!/bin/sh\npsql -h db -d app -c 'UPDATE audit.events SET seen=true'\n";
// The discovered launcher has no runtime-cwd evidence; every contextual graph query uses this.
const NORTH_STAR_ENTRYPOINT: &str = "package.json:scripts.run";
const NORTH_STAR_SQL_EXECUTION: u32 = 9;
const NORTH_STAR_DECOY_EXECUTION: usize = 10;

fn literal(expr: &ResourceExpr) -> Option<&str> {
    match expr {
        ResourceExpr::Literal { value } => Some(value),
        _ => None,
    }
}

fn cwd(expr: Option<&ResourceExpr>) -> Option<&str> {
    match expr {
        Some(ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        }) => Some(path),
        _ => None,
    }
}

#[test]
fn universal_execution_graph_reaches_exact_sql_table() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "execution-graph-north-star",
        &north_star_files(LAUNCHER_WITH_DECOY, HELPER, SHELL),
    );
    let index = build_index(&root, IndexLimits::default());
    let report =
        plan_execution(&index, NORTH_STAR_ENTRYPOINT).expect("repository-root package launch");
    let graph = &report.graph;
    // Dependency requests are terminal evidence alongside the direct execution chain.
    let nodes: Vec<_> = graph
        .nodes
        .iter()
        .filter(|node| node.input.is_none() || node.boundary.is_none())
        .collect();
    let edges: Vec<_> = graph
        .edges
        .iter()
        .filter(|edge| {
            let target = &graph.nodes[edge.to.0 as usize];
            target.input.is_none() || target.boundary.is_none()
        })
        .collect();
    let direct = plan_execution(&index, "launcher").expect("direct TypeScript entrypoint");
    assert!(
        direct
            .graph
            .nodes
            .iter()
            .all(|node| node.selected_source_path() != Some("helper.py")),
        "a cwd-unknown source entrypoint must not resolve a repository-root helper"
    );

    assert_eq!(nodes.len(), NORTH_STAR_DECOY_EXECUTION + 1, "{:#?}", nodes);
    let launchers: Vec<&str> = nodes
        .iter()
        .map(|node| match &node.subject {
            Subject::Source { language, .. } if language == "js" => "typescript",
            Subject::Source { language, .. } if language == "python" => "python-source",
            Subject::Shell { .. } => "shell-source",
            Subject::Sql { .. } => "sql",
            Subject::Exec { argv, .. } => argv.first().map(String::as_str).unwrap_or("exec"),
            Subject::Source { language, .. } => language,
            Subject::ToolCall { .. } => "tool",
        })
        .collect();
    assert_eq!(
        launchers,
        [
            "shell-source",
            "./launcher",
            "typescript",
            "python3",
            "python-source",
            "docker",
            "sh",
            "shell-source",
            "psql",
            "sql",
            "echo",
        ]
    );
    assert_eq!(
        edges.iter().map(|edge| edge.kind).collect::<Vec<_>>(),
        [
            ExecutionEdgeKind::Launch,
            ExecutionEdgeKind::Interpreter,
            ExecutionEdgeKind::Launch,
            ExecutionEdgeKind::Launch,
            ExecutionEdgeKind::Interpreter,
            ExecutionEdgeKind::Launch,
            ExecutionEdgeKind::ContainerRealm,
            ExecutionEdgeKind::Script,
            ExecutionEdgeKind::Launch,
            ExecutionEdgeKind::DatabaseClient,
        ]
    );
    assert!(
        nodes
            .iter()
            .all(|node| node.assurance == ExecutionAssurance::Exact)
    );
    assert!(nodes[0].input.is_none());
    assert_eq!(nodes[2].selected_source_path(), Some("launcher"));
    assert_eq!(nodes[4].selected_source_path(), Some("helper.py"));
    assert_eq!(nodes[7].selected_source_path(), Some("scripts/run.sh"));
    assert_eq!(literal(&nodes[3].argv[1]), Some("helper.py"));
    assert_eq!(literal(&nodes[6].argv[1]), Some("/workspace/run.sh"));
    assert_eq!(literal(&nodes[8].argv[0]), Some("psql"));

    let container = ExecutionRealm::Container {
        runtime: "docker".to_string(),
        name: "postgres:16".to_string(),
    };
    for node in &nodes[6..NORTH_STAR_DECOY_EXECUTION] {
        assert_eq!(node.realm, container);
        assert_eq!(cwd(node.cwd.as_ref()), Some("/workspace"));
        assert_eq!(
            node.environment
                .get("TENANT")
                .and_then(Option::as_ref)
                .and_then(literal),
            Some("acme")
        );
        assert!(matches!(
            node.mounts.as_slice(),
            [ContainerStorage::BindMount {
                host_path: ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path: host }
                },
                container_path: ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path: guest }
                },
                read_only: false,
            }] if host == "scripts" && guest == "/workspace"
        ));
    }
    assert_eq!(
        nodes[NORTH_STAR_DECOY_EXECUTION].realm,
        ExecutionRealm::Host
    );

    let table_effect = report.effects.iter().find(|effect| {
        effect.operation.0 == "database.write"
            && matches!(
                &effect.resource,
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::DatabaseTable { schema, table, .. }
                } if schema.as_deref() == Some("audit") && table == "events"
            )
    });
    let table_effect = table_effect.expect("exact SQL table effect");
    assert_eq!(table_effect.execution.0, NORTH_STAR_SQL_EXECUTION);
    assert_eq!(table_effect.realm, container);
    let causality = plan_causality(&index, NORTH_STAR_ENTRYPOINT).unwrap();
    let tenant = causality
        .nodes
        .iter()
        .find(|node| {
            matches!(
                &node.occurrence,
                OccurrenceKind::Value {
                    value: ResourceExpr::Literal { value }
                } if value == "TENANT=acme"
            )
        })
        .expect("container environment argument occurrence");
    let table = causality
        .nodes
        .iter()
        .find(|node| {
            node.execution.map(|execution| execution.0) == Some(NORTH_STAR_SQL_EXECUTION)
                && matches!(
                    &node.occurrence,
                    OccurrenceKind::ResourceInteraction { operation, resource, .. }
                        if operation.0 == "database.write"
                            && matches!(resource, ResourceExpr::Concrete {
                                identity: ResourceIdentity::DatabaseTable { schema, table, .. }
                            } if schema.as_deref() == Some("audit") && table == "events")
                )
        })
        .expect("exact SQL table transition occurrence");
    let path = causal_path(causality, &tenant.id, &table.id)
        .expect("config value reaches the exact table transition");
    assert_eq!(path.first(), Some(&tenant.id));
    assert_eq!(path.last(), Some(&table.id));
    let reasons: Vec<_> = path
        .windows(2)
        .map(|pair| {
            causality
                .edges
                .iter()
                .find(|edge| edge.from == pair[0] && edge.to == pair[1])
                .expect("every path step names a causal edge")
                .reason
        })
        .collect();
    assert_eq!(
        reasons,
        [
            CausalReason::Containment,
            CausalReason::ValueDependency,
            CausalReason::Launch,
            CausalReason::Launch,
            CausalReason::Launch,
            CausalReason::Launch,
            CausalReason::ControlDependency,
        ]
    );

    let decoy = causality
        .nodes
        .iter()
        .find(|node| {
            matches!(
                &node.occurrence,
                OccurrenceKind::Value {
                    value: ResourceExpr::Literal { value }
                } if value == "TENANT=decoy"
            )
        })
        .expect("disconnected decoy argument occurrence");
    assert!(
        causal_path(causality, &decoy.id, &table.id,).is_none(),
        "an unrelated execution branch must not reach the table"
    );
    assert!(
        direct
            .effects
            .iter()
            .all(|effect| effect.operation.0 != "database.write"),
        "a cwd-unknown source entrypoint must not inherit the package launch's SQL effect"
    );
}

#[test]
fn broken_execution_evidence_removes_only_the_downstream_sql_path() {
    let cases = [
        (
            "missing-python",
            LAUNCHER.replace("helper.py", "missing.py"),
            HELPER.to_string(),
            SHELL.to_string(),
        ),
        (
            "missing-mount",
            LAUNCHER.to_string(),
            HELPER.replace("'-v', './scripts:/workspace', ", ""),
            SHELL.to_string(),
        ),
        (
            "missing-shell",
            LAUNCHER.to_string(),
            HELPER.replace("/workspace/run.sh", "/workspace/missing.sh"),
            SHELL.to_string(),
        ),
        (
            "dynamic-sql",
            LAUNCHER.to_string(),
            HELPER.to_string(),
            "#!/bin/sh\npsql -h db -d app -c \"$MIGRATION_SQL\"\n".to_string(),
        ),
    ];
    for (tag, launcher, helper, shell) in cases {
        let files = north_star_files(&launcher, &helper, &shell);
        let root = repo_test_fixture(Path::new(env!("CARGO_TARGET_TMPDIR")), tag, &files);
        let index = build_index(&root, IndexLimits::default());
        let report = plan_execution(&index, NORTH_STAR_ENTRYPOINT)
            .expect("package launch remains supported");
        assert!(
            !report.effects.iter().any(|effect| {
                matches!(
                    &effect.resource,
                    ResourceExpr::Concrete {
                        identity: ResourceIdentity::DatabaseTable { schema, table, .. }
                    } if schema.as_deref() == Some("audit") && table == "events"
                )
            }),
            "{tag} retained unsupported downstream SQL"
        );
        assert!(
            !report.boundaries.is_empty(),
            "{tag} must retain an explicit boundary"
        );
    }

    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "broken-shebang",
        &north_star_files(
            &LAUNCHER.replacen("#!/usr/bin/env tsx", "#!/usr/bin/env unknown", 1),
            HELPER,
            SHELL,
        ),
    );
    let index = build_index(&root, IndexLimits::default());
    let report = plan_execution(&index, NORTH_STAR_ENTRYPOINT).unwrap();
    assert!(
        !report.graph.nodes.iter().any(
            |node| matches!(&node.subject, Subject::Source { language, .. } if language == "js")
        )
    );
}

#[test]
fn repository_evidence_drives_package_build_ci_and_shell_edges() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "execution-graph-repository-layers",
        &[
            (
                "main.sh",
                "#!/bin/sh\nnpm run build\nmake deploy\njust ship\ntask clean\ncargo run\ngo run ./cmd/app\nmvn exec:java\ngradle run\n./local\n",
            ),
            (
                "package.json",
                r#"{"scripts":{"all":"./main.sh","build":"rm -rf /package-output"}}"#,
            ),
            ("Makefile", "deploy:\n\trm -rf /build-output\n"),
            ("justfile", "ship:\n  rm -rf /just-output\n"),
            (
                "Taskfile.yml",
                "version: '3'\ntasks:\n  clean:\n    cmds:\n      - rm -rf /task-output\n",
            ),
            (
                "Cargo.toml",
                "[package]\nname = \"app\"\nversion = \"0.1.0\"\n",
            ),
            (
                "src/main.rs",
                "fn main() { std::fs::remove_file(\"/cargo-output\"); }\n",
            ),
            (
                "cmd/app/main.go",
                "package main\nimport \"os\"\nfunc main() { os.RemoveAll(\"/go-output\") }\n",
            ),
            (
                "pom.xml",
                "<project><build><plugins><plugin><artifactId>exec-maven-plugin</artifactId><configuration><mainClass>com.acme.Main</mainClass></configuration></plugin></plugins></build></project>",
            ),
            (
                "build.gradle",
                "plugins { id 'application' }\nmainClass = 'com.acme.Main'\n",
            ),
            (
                "src/main/java/com/acme/Main.java",
                "import java.nio.file.Files; import java.nio.file.Path; public class Main { public static void main(String[] args) throws Exception { Files.delete(Path.of(\"/java-output\")); } }",
            ),
            ("local", "#!/bin/sh\nrm -rf /local-output\n"),
            (
                ".github/workflows/check.yml",
                "name: check\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: rm -rf /ci-output\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());

    let main = plan_execution(&index, "package.json:scripts.all").unwrap();
    let main_kinds: Vec<_> = main.graph.edges.iter().map(|edge| edge.kind).collect();
    assert!(main_kinds.contains(&ExecutionEdgeKind::PackageScript));
    assert!(main_kinds.contains(&ExecutionEdgeKind::BuildTarget));
    assert!(main_kinds.contains(&ExecutionEdgeKind::Script));
    for path in [
        "/package-output",
        "/build-output",
        "/just-output",
        "/task-output",
        "/cargo-output",
        "/go-output",
        "/java-output",
        "/local-output",
    ] {
        assert!(main.effects.iter().any(|effect| {
            matches!(
                &effect.resource,
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path: actual }
                } if actual == path
            )
        }));
    }

    let ci = plan_execution(&index, ".github/workflows/check.yml:run.1").unwrap();
    assert!(
        ci.graph
            .edges
            .iter()
            .any(|edge| edge.kind == ExecutionEdgeKind::CiRealm)
    );
    let ci_effect = ci
        .effects
        .iter()
        .find(|effect| {
            matches!(
                &effect.resource,
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path }
                } if path == "/ci-output"
            )
        })
        .unwrap();
    assert_eq!(
        ci_effect.realm,
        ExecutionRealm::Remote {
            endpoint: "github-actions".to_string()
        }
    );
}

#[test]
fn go_package_with_sibling_sources_retains_a_boundary() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "execution-go-package-siblings",
        &[
            ("package.json", r#"{"scripts":{"run":"go run ./cmd/app"}}"#),
            (
                "cmd/app/main.go",
                "package main\nfunc main() { helper() }\n",
            ),
            (
                "cmd/app/helper.go",
                "package main\nimport \"os\"\nfunc helper() { os.RemoveAll(\"/go-helper-output\") }\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let report = plan_execution(&index, "package.json:scripts.run").unwrap();

    assert!(!report.effects.iter().any(|effect| {
        matches!(
            &effect.resource,
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path }
            } if path == "/go-helper-output"
        )
    }));
    assert!(report.boundaries.iter().any(|boundary| {
        boundary.reason == "unrecoverable_source"
            && boundary
                .detail
                .as_deref()
                .is_some_and(|detail| detail.contains("sibling Go sources"))
    }));
    assert!(!report.graph.edges.iter().any(|edge| {
        edge.kind == ExecutionEdgeKind::BuildTarget
            && report.graph.nodes[edge.to.0 as usize].selected_source_path()
                == Some("cmd/app/main.go")
    }));
}

#[test]
fn github_actions_only_accepts_direct_step_run_keys() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "execution-graph-ci-step-nesting",
        &[(
            ".github/workflows/check.yml",
            "name: check\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: vendor/action@v1\n        with:\n          run: rm -rf /from-input\n      - run: rm -rf /from-step\n",
        )],
    );
    let index = build_index(&root, IndexLimits::default());
    assert!(
        index
            .entrypoints
            .iter()
            .any(|entry| entry.entrypoint.id == ".github/workflows/check.yml:run.1")
    );
    assert!(
        !index
            .entrypoints
            .iter()
            .any(|entry| { entry.entrypoint.id == ".github/workflows/check.yml:run.2" })
    );

    let report = plan_execution(&index, ".github/workflows/check.yml:run.1").unwrap();
    assert!(report.effects.iter().any(|effect| {
        matches!(
            &effect.resource,
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path }
            } if path == "/from-step"
        )
    }));
    assert!(!report.effects.iter().any(|effect| {
        matches!(
            &effect.resource,
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path }
            } if path == "/from-input"
        ) || matches!(
            &effect.resource,
            ResourceExpr::Concrete {
                identity: ResourceIdentity::Process { executable, .. }
            } if executable == "github-actions"
        )
    }));
}

#[test]
fn github_actions_respects_declared_shells() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "execution-graph-ci-shells",
        &[(
            ".github/workflows/check.yml",
            "jobs:\n  test:\n    defaults:\n      run:\n        shell: python\n    steps:\n      - run: |\n          import os\n          os.remove(\"/default-python\")\n      - shell: bash\n        run: rm -rf /bash-step\n      - shell: python\n        run: os.remove(\"/step-python\")\n",
        )],
    );
    let index = build_index(&root, IndexLimits::default());

    for entrypoint in [
        ".github/workflows/check.yml:run.1",
        ".github/workflows/check.yml:run.3",
    ] {
        let report = plan_execution(&index, entrypoint).unwrap();
        assert!(
            report
                .boundaries
                .iter()
                .any(|boundary| boundary.reason == "unresolved_ci_step")
        );
        assert!(!report.effects.iter().any(|effect| {
            matches!(
                &effect.resource,
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::Process { executable, .. }
                } if executable == "import" || executable == "os.remove"
            )
        }));
    }

    let bash = plan_execution(&index, ".github/workflows/check.yml:run.2").unwrap();
    assert!(bash.effects.iter().any(|effect| {
        matches!(
            &effect.resource,
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path }
            } if path == "/bash-step"
        )
    }));
}

#[test]
fn github_actions_respects_workflow_default_shell() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "execution-graph-ci-workflow-shell",
        &[(
            ".github/workflows/check.yml",
            "defaults:\n  run:\n    shell: python\njobs:\n  test:\n    steps:\n      - run: |\n          import os\n          os.remove(\"/workflow-python\")\n",
        )],
    );
    let index = build_index(&root, IndexLimits::default());
    let report = plan_execution(&index, ".github/workflows/check.yml:run.1").unwrap();

    assert!(
        report
            .boundaries
            .iter()
            .any(|boundary| boundary.reason == "unresolved_ci_step")
    );
    assert!(!report.effects.iter().any(|effect| {
        matches!(
            &effect.resource,
            ResourceExpr::Concrete {
                identity: ResourceIdentity::Process { executable, .. }
            } if executable == "import" || executable == "os.remove"
        )
    }));
}

#[test]
fn github_actions_propagates_default_working_directories() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "execution-graph-ci-default-cwd",
        &[(
            ".github/workflows/check.yml",
            "defaults:\n  run:\n    working-directory: workflow\njobs:\n  workflow:\n    runs-on: ubuntu-latest\n    steps:\n      - run: rm -rf out\n  job:\n    runs-on: ubuntu-latest\n    defaults:\n      run:\n        working-directory: job\n    steps:\n      - run: rm -rf out\n",
        )],
    );
    let index = build_index(&root, IndexLimits::default());

    for (entrypoint, expected) in [
        (".github/workflows/check.yml:run.1", "workflow/out"),
        (".github/workflows/check.yml:run.2", "job/out"),
    ] {
        let report = plan_execution(&index, entrypoint).unwrap();
        assert!(report.effects.iter().any(|effect| {
            effect.operation.0 == "filesystem.delete"
                && matches!(
                    &effect.resource,
                    ResourceExpr::Concrete {
                        identity: ResourceIdentity::FsPath { path }
                    } if path == expected
                )
        }));
    }
}

#[test]
fn github_actions_propagates_step_cwd_and_environment() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "execution-graph-ci-context",
        &[(
            ".github/workflows/check.yml",
            "jobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - working-directory: sub\n        env:\n          TARGET: out\n        run: rm -rf \"$TARGET\"\n",
        )],
    );
    let index = build_index(&root, IndexLimits::default());
    let report = plan_execution(&index, ".github/workflows/check.yml:run.1").unwrap();

    let ci_node = report
        .graph
        .nodes
        .iter()
        .find(|node| matches!(node.subject, Subject::Shell { .. }))
        .unwrap();
    assert_eq!(cwd(ci_node.cwd.as_ref()), Some("sub"));
    assert_eq!(
        ci_node.environment.get("TARGET"),
        Some(&Some(ResourceExpr::Literal {
            value: "out".to_string()
        }))
    );
    assert!(
        report.effects.iter().any(|effect| {
            effect.operation.0 == "filesystem.delete"
                && matches!(
                    &effect.resource,
                    ResourceExpr::Concrete {
                        identity: ResourceIdentity::FsPath { path }
                    } if path == "sub/out"
                )
                && effect.realm
                    == ExecutionRealm::Remote {
                        endpoint: "github-actions".to_string(),
                    }
        }),
        "{:#?}",
        report.effects
    );
}

#[test]
fn github_actions_rejects_unsafe_context_scalars() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "execution-graph-ci-context-scalars",
        &[(
            ".github/workflows/check.yml",
            "jobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - env:\n          TARGET: |\n            real/path\n        run: rm -rf \"$TARGET\"\n      - env:\n          TARGET: real   # deploy dir\n        run: rm -rf \"$TARGET\"\n      - working-directory: sub   # build dir\n        run: rm -rf out\n      - working-directory: >\n          sub\n        run: rm -rf out\n",
        )],
    );
    let index = build_index(&root, IndexLimits::default());

    for entrypoint in [
        ".github/workflows/check.yml:run.1",
        ".github/workflows/check.yml:run.4",
    ] {
        let report = plan_execution(&index, entrypoint).unwrap();
        assert!(
            report
                .boundaries
                .iter()
                .any(|boundary| boundary.reason == "unresolved_ci_step")
        );
        assert!(
            !report
                .effects
                .iter()
                .any(|effect| effect.operation.0 == "filesystem.delete")
        );
    }

    let environment = plan_execution(&index, ".github/workflows/check.yml:run.2").unwrap();
    assert!(environment.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.delete"
            && matches!(
                &effect.resource,
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path }
                } if path == "real"
            )
    }));
    let working_directory = plan_execution(&index, ".github/workflows/check.yml:run.3").unwrap();
    assert!(working_directory.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.delete"
            && matches!(
                &effect.resource,
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path }
                } if path == "sub/out"
            )
    }));
}

#[test]
fn github_actions_rejects_unsupported_run_scalars() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "execution-graph-ci-run-scalars",
        &[(
            ".github/workflows/check.yml",
            "jobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: >\n          rm -rf\n          /folded-target\n      - run: |2\n          rm -rf /indicator-target\n      - run: rm -rf\n          /plain-target\n      - run: \"rm -rf /quoted-target\" # cleanup\n      - run: \"rm -rf /a\\tb\"\n      - run: |\n          rm -rf /literal-target\n",
        )],
    );
    let index = build_index(&root, IndexLimits::default());

    for step in 1..=5 {
        let report =
            plan_execution(&index, &format!(".github/workflows/check.yml:run.{step}")).unwrap();
        assert!(
            report
                .boundaries
                .iter()
                .any(|boundary| boundary.reason == "unresolved_ci_step")
        );
        assert!(report.effects.is_empty());
    }

    let literal = plan_execution(&index, ".github/workflows/check.yml:run.6").unwrap();
    assert!(literal.effects.iter().any(|effect| {
        matches!(
            &effect.resource,
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path }
            } if path == "/literal-target"
        )
    }));
}

#[test]
fn source_imports_and_runtime_cwds_stay_distinct_across_launch_contexts() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p14j-source-runtime-cwds",
        &[
            (
                "package.json",
                r#"{"scripts":{"root":"python3 scripts/task.py","changed":"cd build && python3 ../scripts/task.py"}}"#,
            ),
            (
                "nested/package.json",
                r#"{"scripts":{"run":"python3 ../scripts/task.py"}}"#,
            ),
            (
                "scripts/task.py",
                "import os\nfrom helper import imported\nif __name__ == '__main__':\n    imported()\n    os.remove('victim.txt')\n",
            ),
            (
                "scripts/helper.py",
                "import os\ndef imported():\n    os.remove('/p14j/source-relative-import')\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());

    for (entrypoint, resource, runtime_cwd) in [
        ("package.json:scripts.root", "fs:victim.txt", "."),
        (
            "nested/package.json:scripts.run",
            "fs:nested/victim.txt",
            "nested",
        ),
        (
            "package.json:scripts.changed",
            "fs:build/victim.txt",
            "build",
        ),
    ] {
        let effects = effects_of(&index, entrypoint)
            .unwrap()
            .payload
            .into_effects()
            .unwrap()
            .effects;
        assert!(
            effects.iter().any(|effect| {
                effect.operation.0 == "filesystem.delete"
                    && originates(effect, "scripts/task.py")
                    && display(effect) == resource
            }),
            "{entrypoint}: {effects:?}"
        );
        assert!(
            effects.iter().any(|effect| {
                effect.operation.0 == "filesystem.delete"
                    && originates(effect, "scripts/helper.py")
                    && display(effect) == "fs:/p14j/source-relative-import"
            }),
            "{entrypoint}: {effects:?}"
        );

        let execution = plan_execution(&index, entrypoint).unwrap();
        assert!(
            execution.graph.nodes.iter().any(|node| {
                matches!(&node.subject, Subject::Source { language, .. } if language == "python")
                    && node.selected_source_path() == Some("scripts/task.py")
                    && cwd(node.cwd.as_ref()) == Some(runtime_cwd)
            }),
            "{entrypoint}: {:#?}",
            execution.graph.nodes
        );
    }

    let direct = effects_of(&index, "scripts/task.py")
        .unwrap()
        .payload
        .into_effects()
        .unwrap()
        .effects;
    assert!(
        direct.iter().any(|effect| {
            effect.operation.0 == "filesystem.delete"
                && originates(effect, "scripts/task.py")
                && display(effect).contains("<cwd>")
        }),
        "{direct:?}"
    );
}

#[test]
fn source_relative_javascript_and_php_constructs_do_not_supply_runtime_cwd() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p14j-source-relative-language-constructs",
        &[
            (
                "package.json",
                r#"{"scripts":{"js":"node scripts/task.mjs","php":"php scripts/task.php"}}"#,
            ),
            ("config.json", "{}"),
            (
                "scripts/task.mjs",
                "import fs from 'fs';\nfs.readFileSync(new URL('../config.json', import.meta.url));\nfs.writeFileSync('output.txt', '');\n",
            ),
            (
                "scripts/task.php",
                "#!/usr/bin/env php\n<?php require __DIR__ . '/lib.php'; unlink('victim.txt');\n",
            ),
            ("scripts/lib.php", "<?php unlink('/p14j/php-source');\n"),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    for entrypoint in ["scripts/task.mjs", "package.json:scripts.js"] {
        let effects = effects_of(&index, entrypoint)
            .unwrap()
            .payload
            .into_effects()
            .unwrap()
            .effects;
        assert!(
            effects.iter().any(|effect| {
                effect.operation.0 == "filesystem.read" && display(effect) == "fs:config.json"
            }),
            "{entrypoint}: {effects:?}"
        );
        let output = effects
            .iter()
            .find(|effect| effect.operation.0 == "filesystem.write")
            .unwrap();
        if entrypoint == "scripts/task.mjs" {
            assert!(
                display(output).contains("<cwd>"),
                "{entrypoint}: {effects:?}"
            );
        } else {
            assert_eq!(
                display(output),
                "fs:output.txt",
                "{entrypoint}: {effects:?}"
            );
        }
    }

    for entrypoint in ["scripts/task.php", "package.json:scripts.php"] {
        let effects = effects_of(&index, entrypoint)
            .unwrap()
            .payload
            .into_effects()
            .unwrap()
            .effects;
        assert!(
            effects.iter().any(|effect| {
                effect.operation.0 == "filesystem.delete"
                    && originates(effect, "scripts/lib.php")
                    && display(effect) == "fs:/p14j/php-source"
            }),
            "{entrypoint}: {effects:?}"
        );
        let victim = effects
            .iter()
            .find(|effect| {
                effect.operation.0 == "filesystem.delete" && originates(effect, "scripts/task.php")
            })
            .unwrap();
        if entrypoint == "scripts/task.php" {
            assert!(
                display(victim).contains("<cwd>"),
                "{entrypoint}: {effects:?}"
            );
        } else {
            assert_eq!(
                display(victim),
                "fs:victim.txt",
                "{entrypoint}: {effects:?}"
            );
        }
    }
}

#[test]
fn direct_scripts_keep_the_repository_execution_depth() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "p14j-direct-repository-depth",
        &[(
            "scripts/deep.sh",
            "#!/bin/sh\nf1() { f2; }\nf2() { f3; }\nf3() { f4; }\nf4() { f5; }\nf5() { f6; }\nf6() { f7; }\nf7() { rm /p14j/deep-direct; }\nf1\n",
        )],
    );
    let effects = effects_of(
        &build_index(&root, IndexLimits::default()),
        "scripts/deep.sh",
    )
    .unwrap()
    .payload
    .into_effects()
    .unwrap()
    .effects;
    assert!(
        effects.iter().any(|effect| {
            effect.operation.0 == "filesystem.delete" && display(effect) == "fs:/p14j/deep-direct"
        }),
        "{effects:?}"
    );
}

#[test]
fn github_actions_requires_evidence_for_the_default_shell() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "execution-graph-ci-runner-shell",
        &[(
            ".github/workflows/check.yml",
            "jobs:\n  linux:\n    runs-on: ubuntu-latest\n    steps:\n      - run: rm -rf /linux-target\n  windows:\n    runs-on: windows-latest\n    steps:\n      - run: rm -rf /windows-target\n      - shell: bash\n        run: rm -rf /windows-bash-target\n  matrix:\n    runs-on: ${{ matrix.os }}\n    steps:\n      - run: rm -rf /matrix-target\n  unknown:\n    steps:\n      - run: rm -rf /unknown-target\n",
        )],
    );
    let index = build_index(&root, IndexLimits::default());

    for (step, path) in [
        (2, "/windows-target"),
        (4, "/matrix-target"),
        (5, "/unknown-target"),
    ] {
        let report =
            plan_execution(&index, &format!(".github/workflows/check.yml:run.{step}")).unwrap();
        assert!(
            report
                .boundaries
                .iter()
                .any(|boundary| boundary.reason == "unresolved_ci_step")
        );
        assert!(!report.effects.iter().any(|effect| {
            matches!(
                &effect.resource,
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path: actual }
                } if actual == path
            )
        }));
    }

    for (step, path) in [(1, "/linux-target"), (3, "/windows-bash-target")] {
        let report =
            plan_execution(&index, &format!(".github/workflows/check.yml:run.{step}")).unwrap();
        assert!(report.effects.iter().any(|effect| {
            matches!(
                &effect.resource,
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path: actual }
                } if actual == path
            )
        }));
    }
}

#[test]
fn github_actions_accepts_indentationless_step_sequences() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "execution-graph-ci-indentationless-steps",
        &[(
            ".github/workflows/check.yml",
            "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n    - name: cleanup\n      run: rm -rf /flat-step-target\n",
        )],
    );
    let index = build_index(&root, IndexLimits::default());
    let report = plan_execution(&index, ".github/workflows/check.yml:run.1").unwrap();

    assert!(report.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.delete"
            && matches!(&effect.resource, ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path }
            } if path == "/flat-step-target")
    }));
}

#[test]
fn github_actions_container_jobs_preserve_the_container_realm() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "execution-graph-ci-job-container",
        &[(
            ".github/workflows/check.yml",
            "jobs:\n  build:\n    runs-on: ubuntu-latest\n    container:\n      image: alpine:3\n    steps:\n      - run: rm -rf /etc/passwd\n",
        )],
    );
    let index = build_index(&root, IndexLimits::default());
    let report = plan_execution(&index, ".github/workflows/check.yml:run.1").unwrap();
    let realm = ExecutionRealm::Container {
        runtime: "github-actions".to_string(),
        name: "alpine:3".to_string(),
    };

    assert!(
        report
            .graph
            .edges
            .iter()
            .any(|edge| edge.kind == ExecutionEdgeKind::CiRealm)
    );
    assert!(
        report
            .graph
            .edges
            .iter()
            .any(|edge| edge.kind == ExecutionEdgeKind::ContainerRealm)
    );
    assert!(report.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.delete"
            && effect.realm == realm
            && matches!(&effect.resource, ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path }
            } if path == "/etc/passwd")
    }));
    assert!(!report.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.delete"
            && matches!(
                effect.realm,
                ExecutionRealm::Host | ExecutionRealm::Remote { .. }
            )
    }));
}

#[test]
fn makefile_entrypoints_use_the_engine_make_model() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "execution-graph-makefile-entrypoints",
        &[
            (
                "isolated/Makefile",
                "all:\n\tcd /tmp/stage\n\trm -rf victim\n",
            ),
            (
                "shell/Makefile",
                "SHELL := /usr/bin/python3\n.SHELLFLAGS := -c\nall:\n\tos.remove(\"/wrong\")\n",
            ),
            (
                "deps/Makefile",
                "all: dep\n\trm -rf /all\ndep:\n\ttouch /dep\n",
            ),
            ("inline/Makefile", "all: ; rm -rf /inline\n"),
            (
                "selection/Makefile",
                "DIR := /tmp/build\nclean:\n\trm -rf /clean\ninstall: clean\n%.o: %.c\n",
            ),
            ("span/Makefile", "clean:\n\trm -rf /tmp/junk\n"),
        ],
    );
    let index = build_index(&root, IndexLimits::default());

    let ids: Vec<_> = index
        .entrypoints
        .iter()
        .map(|entrypoint| entrypoint.entrypoint.id.as_str())
        .collect();
    assert!(ids.contains(&"selection/Makefile:clean"));
    assert!(ids.contains(&"selection/Makefile:install"));
    assert!(!ids.contains(&"selection/Makefile:DIR"));
    assert!(!ids.contains(&"selection/Makefile:%.o"));

    let isolated = plan_execution(&index, "isolated/Makefile:all").unwrap();
    assert!(
        isolated
            .graph
            .edges
            .iter()
            .any(|edge| edge.kind == ExecutionEdgeKind::BuildTarget)
    );
    assert!(isolated.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.delete"
            && !matches!(&effect.resource, ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path }
            } if path.starts_with("/tmp/stage"))
    }));

    for entrypoint in [
        "shell/Makefile:all",
        "deps/Makefile:all",
        "inline/Makefile:all",
    ] {
        let report = plan_execution(&index, entrypoint).unwrap();
        assert!(
            report
                .boundaries
                .iter()
                .any(|boundary| boundary.reason == "unresolved_build_target")
        );
    }

    let spans = effects_of(&index, "span/Makefile:clean").unwrap();
    let delete = spans
        .payload
        .as_effects()
        .unwrap()
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "filesystem.delete")
        .unwrap();
    // The row keeps only terminal roots; the recipe span is reached by walking
    // the envelope graph back from them, the way explanation does.
    assert!(
        antecedents(&spans.provenance, &delete.provenance_roots)
            .iter()
            .any(|id| spans.provenance.nodes.iter().any(|node| &node.id == id
                && node.occurrence.origin == "span/Makefile"
                && node.occurrence.span.start == 8
                && node.occurrence.span.end == 24))
    );
}

#[test]
fn removing_local_shell_shebang_removes_only_its_downstream_path() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "execution-graph-local-shell-no-shebang",
        &[
            ("main.sh", "#!/bin/sh\n./local.sh\nrm -rf /retained\n"),
            ("local.sh", "rm -rf /unsupported\n"),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let report = plan_execution(&index, "main.sh").unwrap();
    assert!(report.effects.iter().any(|effect| {
        matches!(
            &effect.resource,
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path }
            } if path == "/retained"
        )
    }));
    assert!(!report.effects.iter().any(|effect| {
        matches!(
            &effect.resource,
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path }
            } if path == "/unsupported"
        )
    }));
    assert!(!report.boundaries.is_empty());
}
